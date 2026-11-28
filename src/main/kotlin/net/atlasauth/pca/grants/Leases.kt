package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Lease

/** Authority-side lease operations. Verification, the registry and the live check are [Lease]; signing is [GrantSigning.signLease]. */
object Leases {
    /** Renewal options. [veto] can only REFUSE a renewal, never lengthen the lease. Null members are absent. */
    class RenewOptions {
        var now: Any? = null

        /** Advisory increment from now; the new expiry is capped at issued_at + max_ttl. */
        var increment: Any? = null
        var justificationDigest: String? = null
        var approvers: List<Any?>? = null
        var veto: ((Map<String, Any?>) -> Boolean)? = null
        var chain: List<String>? = null
    }

    private fun res(ok: Boolean, code: String?, record: Map<String, Any?>?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (ok) m["record"] = record else m["code"] = code
        return m
    }

    /** Sign and register the next record of a lease. Returns `{ok:true, record}` or `{ok:false, code}`. */
    @JvmStatic
    fun renewLease(secret: Keys.EdKey, registry: Lease.Registry, id: String, o: RenewOptions): Map<String, Any?> {
        if (!K3Sig.isSafeInt(o.now) || !K3Sig.isSafeInt(o.increment) || Json.asLong(o.increment) < 1) return res(false, "bad_input", null)
        val cur = registry.get(id) ?: return res(false, "unknown_lease", null)
        val veto = o.veto
        if (veto != null && veto(cur)) return res(false, "vetoed", null)
        val now = Json.asLong(o.now)
        val cap = Json.asLong(cur["issued_at"]) + Json.asLong(cur["max_ttl"])
        val expires = minOf(now + Json.asLong(o.increment), cap)
        val rest = LinkedHashMap<String, Any?>(cur)
        rest.remove("v")
        rest.remove("sig")
        rest.remove("authority")
        rest["seq"] = Json.asLong(cur["seq"]) + 1
        rest["renewed_at"] = now
        rest["expires_at"] = expires
        rest["justification_digest"] = o.justificationDigest
        rest["approvers"] = o.approvers ?: cur["approvers"]
        val record = try {
            GrantSigning.signLease(secret, rest)
        } catch (e: RuntimeException) {
            return res(false, if (expires <= now) "expired_lease" else "bad_input", null)
        }
        val r = registry.accept(record, o.chain ?: emptyList())
        return if (r.code == null) res(true, null, record) else res(false, r.code, null)
    }
}
