package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentRevocation
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates

/**
 * Portable, revocable intent profiles (`pca-intent-profile` v1): the principal's signed, versioned, append-only record of
 * standing rules (deny wins; permit is explicit, scoped and expiring) and prior answers (negative answers become vetoes, positive
 * ones never feed the learner). Profiles, scopes, rules and uses are JSON trees (Map / List / String / Json.Num / Boolean / null).
 * Verification honours every suite the SDK implements.
 */
object IntentProfile {
    const val INTENT_PROFILE_KIND = "pca-intent-profile"
    const val INTENT_PROFILE_SIG_DOMAIN = "atlas-pca/intent-profile/v1\u0000"
    const val INTENT_PROFILE_REF_DOMAIN = "atlas-pca/intent-profile-ref/v1"
    const val MAX_PROFILE_RULES = 256
    const val MAX_PROFILE_OBSERVATIONS = 2000

    private val KEYS = listOf("v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig")
    private val BODY_KEYS = listOf("v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev")
    private val ID_RE = Regex("[A-Za-z0-9_.-]{1,128}")

    private fun m(v: Any?): Map<*, *> = v as Map<*, *>
    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null
    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    private fun isInt(v: Any?): Boolean = IntentKit.isInt(v)
    private fun dbl(v: Any?): Double = IntentKit.num(v) ?: Double.NaN
    private fun b32(v: Any?): Boolean = Pca.decodeB64uStrict(v, 32) != null

    private fun strList(v: Any?): Boolean = v is List<*> && v.size <= 256 && v.all { it is String && it.isNotEmpty() }

    private fun predOk(p: Any?): Boolean {
        if (p !is Map<*, *>) return false
        val verb = p["verb"]
        if (verb is String) return true
        return verb is List<*> && verb.all { it is String }
    }

    private fun sortedKeys(o: Any?): String = TreeSet(m(o).keys.map { it as String }).joinToString(",")

    /** The first reason a profile is malformed, or null. `signed = false` skips the suite / signature members. */
    @JvmOverloads
    fun intentProfileShapeError(p: Any?, signed: Boolean = true): String? {
        try {
            if (p !is Map<*, *>) return "profile is not an object"
            for (k in p.keys) if (!KEYS.contains(k)) return "profile: unknown member '$k'"
            if (!(IntentKit.num(get(p, "v")) != null && dbl(get(p, "v")) == 1.0) || INTENT_PROFILE_KIND != get(p, "kind")) return "not a pca-intent-profile v1"
            val pid = get(p, "profile_id")
            if (pid !is String || !ID_RE.matches(pid)) return "profile_id must match [A-Za-z0-9_.-]{1,128}"
            if (!(isInt(get(p, "version")) && dbl(get(p, "version")) >= 1)) return "version must be a safe integer >= 1"
            if (Pca.decodeB64uStrict(get(p, "owner"), 32) == null) return "owner must be canonical base64url (32 bytes)"
            val scope = get(p, "scope")
            if (scope !is Map<*, *>) return "scope must be {sites?, verbs?, semantic_types?}"
            for (k in scope.keys) if (!listOf("sites", "verbs", "semantic_types").contains(k)) return "scope must be {sites?, verbs?, semantic_types?}"
            for (k in arrayOf("sites", "verbs", "semantic_types")) if (has(scope, k) && !strList(get(scope, k))) return "scope.$k must be a list of strings"
            val standing = get(p, "standing")
            if (standing !is Map<*, *> || sortedKeys(standing) != "deny,permit") return "standing must be {deny, permit}"
            for (k in arrayOf("deny", "permit")) {
                val r = get(standing, k)
                if (r !is List<*> || r.size > MAX_PROFILE_RULES) return "standing.$k must be at most $MAX_PROFILE_RULES predicates"
                for (x in r) if (!predOk(x)) return "standing.$k must be at most $MAX_PROFILE_RULES predicates"
            }
            val prior = get(p, "prior")
            if (prior !is Map<*, *> || sortedKeys(prior) != "maps,observations") return "prior must be {observations, maps}"
            val obs = get(prior, "observations")
            if (obs !is List<*> || obs.size > MAX_PROFILE_OBSERVATIONS) return "prior.observations must be at most $MAX_PROFILE_OBSERVATIONS"
            for (o in obs) {
                val y = get(o, "y")
                val yOk = IntentKit.num(y) != null && (dbl(y) == 0.0 || dbl(y) == 1.0)
                if (o !is Map<*, *> || sortedKeys(o) != "at,values,verb,y" || get(o, "verb") !is String || get(o, "values") !is Map<*, *> || !yOk || !(isInt(get(o, "at")) && dbl(get(o, "at")) >= 0))
                    return "prior.observations entries are {verb, values, y, at}"
            }
            val maps = get(prior, "maps")
            if (maps !is List<*>) return "prior.maps must be 32-byte digests"
            for (x in maps) if (!b32(x)) return "prior.maps must be 32-byte digests"
            if (!(isInt(get(p, "expires_at")) && dbl(get(p, "expires_at")) >= 0)) return "expires_at must be a non-negative safe integer"
            val rev = get(p, "revocation")
            if (rev !is Map<*, *>) return "revocation must be {epoch_uri, key?}"
            for (k in rev.keys) if (k != "epoch_uri" && k != "key") return "revocation must be {epoch_uri, key?}"
            val eu = get(rev, "epoch_uri")
            if (eu !is String || eu.isEmpty()) return "revocation must be {epoch_uri, key?}"
            if (has(rev, "key") && !b32(get(rev, "key"))) return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)"
            val v1 = dbl(get(p, "version")) == 1.0
            if (v1 != !has(p, "prev")) return "prev is required exactly when version > 1"
            if (has(p, "prev") && !b32(get(p, "prev"))) return "prev must be canonical base64url (32 bytes)"
            if (signed) {
                if (has(p, "alg") && get(p, "alg") !is String) return "alg must be a string"
                val suite = IntentKit.suiteName(get(p, "alg"), has(p, "alg")) ?: return "alg: unsupported_suite: '" + get(p, "alg") + "'"
                if (suite == "ed25519" && (has(p, "pq_pk") || has(p, "pq_sig"))) return "an ed25519 profile must not carry pq_pk / pq_sig"
                if (get(p, "sig") !is String) return "sig must be a string"
            }
            Json.canonicalizeStrict(profileBody(p))
            return null
        } catch (e: RuntimeException) {
            return "malformed profile: " + e.message
        }
    }

    private fun profileBody(p: Map<*, *>): MutableMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) if (p.containsKey(k)) b[k] = p[k]
        return b
    }

    private fun message(body: Map<String, Any?>): ByteArray = IntentKit.message(INTENT_PROFILE_SIG_DOMAIN, body)

    /** Sign a profile version as its owner with the owner's Ed25519 seed (the owner identity must be the signer's key). */
    fun signIntentProfile(body: Map<String, Any?>, ownerSeed: ByteArray): MutableMap<String, Any?> = signIntentProfile(body, Keys.ed25519(Keys.edFromSeed(ownerSeed)))

    /** Sign under any registry suite (ML-DSA, hybrid, ...): `alg` and `pq_pk` are signed into the profile. */
    fun signIntentProfile(body: Map<String, Any?>, key: Keys.SuiteKey): MutableMap<String, Any?> {
        val ed = key.ed ?: throw IllegalArgumentException("signIntentProfile: signer needs an Ed25519 identity key")
        val owner = ed.id()
        if (body.containsKey("owner") && owner != body["owner"]) throw IllegalArgumentException("signIntentProfile: owner does not match the signing key")
        val withOwner = LinkedHashMap(body)
        withOwner["owner"] = owner
        val b = profileBody(withOwner)
        val bad = intentProfileShapeError(b, false)
        if (bad != null) throw IllegalArgumentException("signIntentProfile: $bad")
        return IntentKit.signSuite(b, key) { message(it) }
    }

    private fun result(reason: String?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = reason == null
        if (reason != null) r["reason"] = reason
        return r
    }

    /** {ok: true} or {ok: false, reason}; [pin] maps an identity to the PQ key the verifier pins for it. Never throws. */
    @JvmOverloads
    fun verifyIntentProfile(p: Any?, pin: Map<String, Any?>? = null): MutableMap<String, Any?> {
        try {
            val bad = intentProfileShapeError(p)
            if (bad != null) return result(bad)
            val r = m(p)
            val body = IntentKit.bindSuiteFields(profileBody(r), r["alg"], r.containsKey("alg"), r["pq_pk"], r.containsKey("pq_pk"))
            if (!IntentKit.verifyPinnedSuite(r["alg"], r.containsKey("alg"), r["owner"] as String, r["pq_pk"], message(body), r["sig"], r["pq_sig"], pin))
                return result("profile signature invalid")
            return result(null)
        } catch (e: RuntimeException) {
            return result("malformed profile: " + e.message)
        }
    }

    /** The content address of a signed profile version. */
    fun intentProfileDigest(p: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_PROFILE_REF_DOMAIN, "p" to p))

    /** Append-only succession: same id and owner, version + 1, `prev` = digest(previous). */
    fun verifyProfileSuccession(prev: Any?, next: Any?): MutableMap<String, Any?> {
        val both = arrayOf(prev, next)
        val names = arrayOf("previous", "next")
        for (i in 0..1) {
            val v = verifyIntentProfile(both[i])
            if (true != v["ok"]) return result(names[i] + " version: " + v["reason"])
        }
        if (get(next, "profile_id") != get(prev, "profile_id") || get(next, "owner") != get(prev, "owner")) return result("a profile version cannot change its id or owner")
        if (!(dbl(get(next, "version")) == dbl(get(prev, "version")) + 1)) return result("versions are append-only: next.version must be previous + 1")
        if (intentProfileDigest(prev) != get(next, "prev")) return result("next.prev is not the digest of the previous version")
        return result(null)
    }

    private fun includes(list: Any?, x: Any?): Boolean = (list as List<*>).any { it != null && it == x }

    /** Is the profile in scope (and unexpired) for this use ({aud, verb, now, semantics?})? */
    fun profileApplies(p: Map<String, Any?>, u: Map<String, Any?>): Boolean {
        if (!(dbl(u["now"]).isFinite() && dbl(p["expires_at"]).isFinite() && dbl(u["now"]) < dbl(p["expires_at"]))) return false
        val scope = p["scope"]
        if (get(scope, "sites") != null && !includes(get(scope, "sites"), u["aud"])) return false
        if (get(scope, "verbs") != null && !includes(get(scope, "verbs"), u["verb"])) return false
        if (get(scope, "semantic_types") != null) {
            var any = false
            if (u["semantics"] != null) for (s in u["semantics"] as List<*>) if (includes(get(scope, "semantic_types"), s)) any = true
            if (!any) return false
        }
        return true
    }

    @Suppress("UNCHECKED_CAST")
    private fun anyRuleMatches(rules: Any?, action: Map<String, Any?>): Boolean = (rules as List<*>).any { Predicates.predicateMatches(it, action) }

    /** G^std membership: an in-scope action is OUTSIDE the standing layer iff a deny rule matches it (deny wins). */
    fun standingAdmits(p: Map<String, Any?>, u: Map<String, Any?>, action: Map<String, Any?>): Boolean {
        if (!profileApplies(p, u)) return true
        return !anyRuleMatches(get(p["standing"], "deny"), action)
    }

    /** The explicit standing-permission layer: true iff an in-scope permit rule matches. */
    fun standingPermits(p: Map<String, Any?>, u: Map<String, Any?>, action: Map<String, Any?>): Boolean =
        profileApplies(p, u) && anyRuleMatches(get(p["standing"], "permit"), action)

    /** The cells that the profile's negative observations veto: [{verb, cell}], de-duplicated in order. */
    fun profileVetoCells(p: Map<String, Any?>, omega: Omega): List<MutableMap<String, Any?>> {
        val out = ArrayList<MutableMap<String, Any?>>()
        val seen = HashSet<String>()
        for (o in get(p["prior"], "observations") as List<*>) {
            if (dbl(get(o, "y")) != 0.0) continue
            val verb = get(o, "verb") as String
            val vs = IntentOmega.verbSpace(omega, verb) ?: continue
            val vals = LinkedHashMap<String, Any?>()
            for ((k, v) in m(get(o, "values"))) vals[k as String] = if (IntentOmega.isNumber(v)) IntentOmega.dbl(v) else v
            val cell = IntentOmega.cellOf(vs, Outcome(verb, vals)) ?: continue
            if (seen.add(verb + "|" + cell.joinToString(","))) out.add(linkedMapOf("verb" to verb, "cell" to cell.toMutableList()))
        }
        return out
    }

    /** A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes. */
    fun profileCeiling(p: Map<String, Any?>, u: Map<String, Any?>): (VerbSpace, Outcome) -> Boolean = { vs, o ->
        val a = IntentPolicy.outcomeToAction(vs, o)
        val ctx = LinkedHashMap<String, Any?>()
        ctx["action"] = linkedMapOf<String, Any?>("verb" to a["verb"], "resource" to a["resource"], "params" to a["params"])
        if (a.containsKey("env")) ctx["env"] = a["env"]
        if (a.containsKey("subject")) ctx["subject"] = a["subject"]
        val use = LinkedHashMap(u)
        use["verb"] = o.verb
        standingAdmits(p, use, ctx)
    }

    /**
     * Is this profile version usable now: signed, unexpired and not revoked per a fresh epoch of its revocation authority?
     * [c] members: now, maxAgeMs, revocation?, last?, pin?.
     */
    fun profileUsable(p: Map<String, Any?>, c: Map<String, Any?>): MutableMap<String, Any?> {
        val pin = if (c["pin"] is Map<*, *>) IntentOmega.obj(c["pin"]) else null
        val v = verifyIntentProfile(p, pin)
        if (true != v["ok"]) return v
        if (!(dbl(c["now"]).isFinite() && dbl(p["expires_at"]).isFinite() && dbl(c["now"]) < dbl(p["expires_at"]))) return result("the profile has expired")
        val id = p["profile_id"] as String
        val revKey = get(p["revocation"], "key")
        val authority = revKey ?: p["owner"]
        val ids = listOf<Any?>(IntentRevocation.profileRevocationId(id, AttestUtil.jsNumString(dbl(p["version"]))))
        val r = IntentRevocation.checkSessionRevocation(c["revocation"], id, authority, ids, dbl(c["now"]), dbl(c["maxAgeMs"]),
            "pca-intent-profile:$id", pin, c["last"] != null, c["last"])
        return if (r == null) result(null) else result("profile revocation: $r")
    }
}
