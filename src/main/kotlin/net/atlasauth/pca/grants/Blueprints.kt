package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Attest
import net.atlasauth.pca.verifier.Blueprint
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import java.util.concurrent.ConcurrentHashMap

/**
 * Operator-side blueprint operations and attestation-gated admission. Record verification, the registry and the chain gate are
 * [Blueprint]; signing is [GrantSigning.signBlueprint]. A blueprint with `runtime_pins` admits an instance key only after evidence for
 * that key was verified and the MEASURED identity matched a pin; anything unverifiable is a deny.
 */
object Blueprints {
    /** Anything with a revoke for an issuer key (a revocation registry). */
    fun interface IssuerRevoker {
        @Throws(Exception::class)
        fun revokeIssuer(value: String, reason: String, revokedAt: Long)
    }

    /** Group kill: sign the blueprint as `disabled` at the next epoch, accept it, revoke the key as an issuer and advance the freshness epoch. */
    @JvmStatic
    @JvmOverloads
    fun groupKill(secret: Keys.EdKey, registry: Blueprint.Registry, key: String, now: Long, reason: String? = null, revocation: IssuerRevoker? = null, freshAt: FreshAt.Issuer? = null): Map<String, Any?> {
        val cur = GrantSigning.blueprintGet(registry, key) ?: return fail("unknown_blueprint")
        val rest = LinkedHashMap<String, Any?>(cur)
        rest.remove("sig")
        rest.remove("operator")
        rest.remove("v")
        rest["status"] = "disabled"
        rest["epoch"] = Json.asLong(cur["epoch"]) + 1
        rest["issued_at"] = now
        val record = GrantSigning.signBlueprint(secret, rest)
        val r = registry.accept(record)
        if (r.code != null) return fail(r.code)
        revocation?.revokeIssuer(key, reason ?: "blueprint disabled (group kill)", now)
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = true
        out["record"] = record
        if (freshAt != null) {
            val patch = LinkedHashMap<String, Any?>()
            patch["revocation_epoch"] = record["epoch"]
            out["freshAt"] = freshAt.advance(patch, now)
        }
        return out
    }

    private fun fail(code: String): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = false
        m["code"] = code
        return m
    }

    private fun deny(code: String, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["admitted"] = false
        m["code"] = code
        if (reason != null) m["reason"] = reason
        return m
    }

    private fun pinMatches(pin: Map<String, Any?>, id: Map<String, Any?>): Boolean {
        if (pin.isEmpty()) return false
        for ((k, v) in pin) if (v == null || id[k] != v) return false
        return true
    }

    /**
     * Admit from adapter evidence: a parsed `{ok, bound, identity?, reason?}`. `ok` and `bound` must both be exactly true; `identity` is
     * what the adapter established, never what the instance claims. A thrown error or malformed result denies.
     * Returns `{admitted:true, identity, pin}` or `{admitted:false, code, reason?}`.
     */
    @JvmStatic
    fun admitWithEvidence(blueprint: Map<String, Any?>, getEvidence: () -> Any?): Map<String, Any?> {
        val pins = K3Sig.list(blueprint["runtime_pins"])
        if (pins == null || pins.isEmpty()) return deny("no_pins", null)
        val r = try {
            getEvidence()
        } catch (e: Exception) {
            // the reference reports the thrown error's name: a failed type access or cast is a TypeError, a range failure a RangeError
            val name = when (e) {
                is NullPointerException, is ClassCastException, is UnsupportedOperationException -> "TypeError"
                is IndexOutOfBoundsException, is NegativeArraySizeException -> "RangeError"
                else -> "Error"
            }
            return deny("verifier_error", name)
        }
        val ev = K3Sig.map(r)
        if (ev == null || ev["ok"] != true) return deny("not_ok", ev?.get("reason") as? String)
        if (ev["bound"] != true) return deny("not_bound", null)
        if (ev["identity"] is List<*>) return deny("no_matching_pin", null) // the reference's typeof check passes an array; no pin key is ever a member of one
        val id = K3Sig.map(ev["identity"]) ?: return deny("no_identity", null)
        for (p in pins) {
            val pin = K3Sig.map(p)
            if (pin != null && pinMatches(pin, id)) {
                val ok = LinkedHashMap<String, Any?>()
                ok["admitted"] = true
                ok["identity"] = id
                ok["pin"] = pin
                return ok
            }
        }
        return deny("no_matching_pin", null)
    }

    /**
     * Admit through a hardware attestation verifier already bound to the document, context and expected binding ([verify]).
     * [hasDocument] false is a deny (no evidence).
     */
    @JvmStatic
    fun admitBlueprintInstance(blueprint: Map<String, Any?>, hasDocument: Boolean, verify: () -> Attest.Result?): Map<String, Any?> {
        val pins = K3Sig.list(blueprint["runtime_pins"])
        if (pins == null || pins.isEmpty()) return deny("no_pins", null)
        if (!hasDocument) return deny("not_ok", "no evidence")
        return admitWithEvidence(blueprint) {
            val h = verify()
            val ev = LinkedHashMap<String, Any?>()
            ev["ok"] = h != null && h.ok
            ev["bound"] = h != null && h.bound
            if (h?.measured != null) ev["identity"] = h.measured
            if (h != null) ev["reason"] = h.reason
            ev
        }
    }

    /** Holds admissions; plug [checker] into `Blueprint.check`. */
    class AdmissionRegistry {
        private val m = ConcurrentHashMap<String, LongArray>()

        private fun k(bpKey: String, instanceKey: String) = bpKey + "\u0000" + instanceKey

        /** Record an admission made under [bp] (its epoch), valid until [until] (epoch ms). */
        fun admit(instanceKey: String, bp: Map<String, Any?>, until: Long) {
            m[k(bp["key"] as String, instanceKey)] = longArrayOf(Json.asLong(bp["epoch"]), until)
        }

        fun revoke(instanceKey: String, bpKey: String): Boolean = m.remove(k(bpKey, instanceKey)) != null

        /** True only for an unexpired admission made under the record's current epoch. */
        fun checker(now: Long): (String, Map<String, Any?>) -> Boolean = { instanceKey, bp ->
            val a = m[k(bp["key"] as String, instanceKey)]
            a != null && a[0] == Json.asLong(bp["epoch"]) && now < a[1]
        }
    }
}
