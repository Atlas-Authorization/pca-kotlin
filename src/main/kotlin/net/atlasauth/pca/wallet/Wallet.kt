package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.SignersMore

/**
 * The wallet side of the PCA Intent Layer v2: the wire formats of the trusted question channel (the principal-signed answer),
 * friction tiers scaled by harm, and the helpers the rest of the package shares. Values are the parsed-JSON tree
 * (Map, List, String, Boolean, [Json.Num], null) so a result compares with the reference as JSON.
 */
@Suppress("UNCHECKED_CAST")
object Wallet {
    const val INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\u0000"
    const val INTENT_ANSWER_REF_DOMAIN = "atlas-pca/intent-answer-ref/v1"
    const val INTENT_TYPED_DOMAIN = "atlas-pca/intent-typed/v1"
    const val INTENT_DEVICE_CHALLENGE_DOMAIN = "atlas-pca/intent-device/v1"
    const val INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"
    const val MIN_HOLD_MS = 2000L

    // ---- friction tiers ----

    @JvmField val FRICTION_ORDER: List<String> = listOf("tap", "hold", "typed", "device")

    fun isFrictionTier(x: Any?): Boolean = x is String && FRICTION_ORDER.contains(x)

    /** Index in tap < hold < typed < device; -1 for anything else (as Array.indexOf). */
    fun frictionRank(t: Any?): Int = if (t is String) FRICTION_ORDER.indexOf(t) else -1

    fun maxFriction(ts: List<*>): String {
        var best = "tap"
        for (t in ts) if (frictionRank(t) > frictionRank(best)) best = t as String
        return best
    }

    // ---- shared helpers ----

    /** Is the key present (the reference's "!== undefined" for JSON-sourced input; a JSON null is defined). */
    internal fun defined(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    internal fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    fun isObj(v: Any?): Boolean = v is Map<*, *>

    fun isB64u32(v: Any?): Boolean = Pca.decodeB64uStrict(v, 32) != null

    /** Number.isSafeInteger and not -0. */
    internal fun isInt(v: Any?): Boolean = isSafeInteger(v) && !Js.isNegZero(v)

    internal fun isSafeInteger(v: Any?): Boolean {
        val d = Js.num(v) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    internal fun isFinite(v: Any?): Boolean = Js.isFinite(v)

    /** The number value of a number, else NaN (a comparison with it is false, as in JavaScript). */
    internal fun nv(v: Any?): Double = Js.num(v) ?: Double.NaN

    internal fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    internal fun utf8(s: String): ByteArray = Json.utf8(s)

    internal fun domainMessage(domain: String, body: Any?): ByteArray = IntentJs.message(domain, body)

    /** Coordinates as the core validates them (shared with intent_required). */
    fun coordsError(c: Any?): String? = SignersMore.cellCoordsError(c)

    /** `JSON.parse(JSON.stringify(v))`: a deep copy where -0 becomes 0 and every number is spelled as JavaScript prints it. */
    internal fun plain(v: Any?): Any? {
        if (v is Map<*, *>) {
            val m = LinkedHashMap<String, Any?>()
            for ((k, x) in v) m[k as String] = plain(x)
            return m
        }
        if (v is List<*>) return v.map { plain(it) }
        if (Js.isNumber(v)) return if (Js.isNegZero(v)) Json.Num("0") else IntentJs.normalize(if (v is Json.Num) v else Json.Num(v.toString()))
        return v
    }

    /** The first member of [o] that is not in [allowed], as the reference's message; null when none. */
    internal fun onlyKeys(o: Any?, allowed: List<String>): String? {
        for (k in (o as Map<*, *>).keys) if (!allowed.contains(k)) return "unknown member \"$k\""
        return null
    }

    // ---- the action and its digest ----

    /** The V3 action digest of an attempted action (what intent_required.action_digest and a JIT consent bind to). */
    fun pcaActionDigest(a: Map<String, Any?>): String {
        val params = a["params"]
        for (k in listOf("verb", "resource", "reversibility_class")) if (!a.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        val action = obj("verb", a["verb"], "resource", a["resource"], "params_digest", Pca.paramsDigest(params), "reversibility_class", a["reversibility_class"])
        return Pca.hashCanonical(obj("d", INTENT_ACTION_DOMAIN, "action", action))
    }

    private val NULL = Any()

    /**
     * The default projection of an attempted action onto the outcome-space paths: action.resource and every scalar param as
     * action.params.NAME. Returns {verb, values}.
     */
    fun actionValuesOf(a: Map<String, Any?>): Map<String, Any?> {
        val values = LinkedHashMap<String, Any?>()
        if (a.containsKey("resource")) values["action.resource"] = a["resource"]
        val ps = a["params"] ?: throw IllegalArgumentException("Cannot convert undefined or null to object")
        val entries = ArrayList<Pair<String, Any?>>()
        if (ps is Map<*, *>) {
            for ((k, v) in ps) entries.add(Pair(k as String, v ?: NULL))
        } else if (ps is List<*>) {
            for (i in ps.indices) entries.add(Pair(i.toString(), ps[i] ?: NULL))
        } else if (ps is String) {
            for (i in ps.indices) entries.add(Pair(i.toString(), ps[i].toString()))
        }
        for ((k, v) in entries) {
            if (v is String || (Js.isNumber(v) && isFinite(v))) values["action.params.$k"] = v
        }
        val out = LinkedHashMap<String, Any?>()
        if (a.containsKey("verb")) out["verb"] = a["verb"]
        out["values"] = values
        return out
    }

    // ---- M6: the signed answer ----

    private val QID_RE = Regex("[A-Za-z0-9_-]{1,64}")
    private val ANS_KEYS = listOf("v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig")
    private val UX_KEYS = listOf("tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action")
    private val WA_KEYS = listOf("credential_id", "authenticator_data", "client_data_json", "signature")

    private fun strEq(v: Any?, s: String): Boolean = s == v

    private fun numEq(v: Any?, d: Double): Boolean = Js.isNumber(v) && Js.num(v) == d

    private fun allInts(v: Any?): Boolean = v is List<*> && v.all { isInt(it) }

    private fun allNonEmptyStrings(v: Any?): Boolean = v is List<*> && v.all { it is String && it.isNotEmpty() }

    /** The reference's partialError: null when the "Partly..." spec is structurally valid. */
    fun partialShapeError(p: Any?): String? {
        val path = get(p, "path")
        if (!isObj(p) || path !is String || path.isEmpty()) return "partial.path must be a non-empty string"
        val keys = (p as Map<*, *>).keys.filter { it != "path" }.map { it as String }
        if (keys.size != 1) return "partial must carry exactly one of upTo / from / except / notFor"
        val k = keys[0]
        val v = p[k]
        if ((k == "upTo" || k == "from") && !isInt(v)) return "partial.$k must be an integer"
        if (k == "except" && !(v is List<*> && v.isNotEmpty() && allInts(v))) return "partial.except must be a non-empty integer array"
        if (k == "notFor" && !(v is List<*> && v.isNotEmpty() && allNonEmptyStrings(v))) return "partial.notFor must be a non-empty string array"
        if (!listOf("upTo", "from", "except", "notFor").contains(k)) return "unknown partial member \"$k\""
        return null
    }

    /** The reference's answerShapeError: null when the (unsigned or signed) answer is well formed. */
    fun answerShapeError(a: Any?): String? {
        if (!isObj(a)) return "not an object"
        val extra = onlyKeys(a, ANS_KEYS)
        if (extra != null) return extra
        if (!numEq(get(a, "v"), 2.0) || !strEq(get(a, "kind"), "pca-intent-observation")) return "not a pca-intent-observation v2"
        for (k in listOf("map_digest", "session", "signer")) if (!isB64u32(get(a, k))) return "$k is not canonical base64url (32 bytes)"
        val qid = get(a, "question_id")
        if (qid !is String || !QID_RE.matches(qid)) return "question_id must match [A-Za-z0-9_-]{1,64}"
        val verb = get(a, "verb")
        if (verb !is String || verb.isEmpty()) return "verb must be a non-empty string"
        val ce = coordsError(get(a, "cell"))
        if (ce != null) return "cell: $ce"
        val y = get(a, "y")
        if (!numEq(y, 0.0) && !numEq(y, 1.0)) return "y must be 0 or 1"
        if (defined(a, "partial")) {
            val pe = partialShapeError(get(a, "partial"))
            if (pe != null) return pe
            if (!numEq(y, 1.0)) return "a partial answer carries y = 1 (yes for the part)"
        }
        val source = get(a, "source")
        if (!strEq(source, "elicitation") && !strEq(source, "clarification")) return "source must be elicitation or clarification"
        val obs = get(a, "observed_at")
        if (!(isInt(obs) && nv(obs) >= 0)) return "observed_at must be a non-negative safe integer"
        if (!strEq(get(a, "alg"), "ed25519")) return "alg must be ed25519"
        val ux = get(a, "ux")
        if (!isObj(ux)) return "ux must be an object"
        val ue = onlyKeys(ux, UX_KEYS)
        if (ue != null) return "ux: $ue"
        if (!isFrictionTier(get(ux, "tier"))) return "ux.tier is not a friction tier"
        if (!isB64u32(get(ux, "rendered_digest"))) return "ux.rendered_digest is not canonical base64url (32 bytes)"
        if (get(ux, "canary") !is Boolean) return "ux.canary must be a boolean"
        if (defined(ux, "typed_digest") && !isB64u32(get(ux, "typed_digest"))) return "ux.typed_digest is not canonical base64url (32 bytes)"
        if (defined(ux, "hold_ms") && !(isInt(get(ux, "hold_ms")) && nv(get(ux, "hold_ms")) >= 0)) return "ux.hold_ms must be a non-negative integer"
        if (defined(ux, "action_digest") && !isB64u32(get(ux, "action_digest"))) return "ux.action_digest is not canonical base64url (32 bytes)"
        if (defined(ux, "consent_for_action") && get(ux, "consent_for_action") !is Boolean) return "ux.consent_for_action must be a boolean"
        val consent = get(ux, "consent_for_action") == true
        if (consent && (!defined(ux, "action_digest") || !numEq(y, 1.0) || defined(a, "partial"))) return "consent_for_action needs action_digest and a plain yes"
        if (consent && get(ux, "canary") == true) return "a canary never consents to an action"
        if (defined(ux, "webauthn")) {
            val wa = get(ux, "webauthn")
            var bad = !isObj(wa) || onlyKeys(wa, WA_KEYS) != null
            if (!bad) for (k in WA_KEYS) if (get(wa, k) !is String) bad = true
            if (bad) return "ux.webauthn is malformed"
        }
        // The tier's own evidence must be present (a "yes" only: a "no" needs no friction).
        if (numEq(y, 1.0) && get(ux, "canary") != true) {
            val tier = get(ux, "tier")
            if ("hold" == tier && !(isInt(get(ux, "hold_ms")) && nv(get(ux, "hold_ms")) >= MIN_HOLD_MS)) return "hold tier needs hold_ms >= $MIN_HOLD_MS"
            if ("typed" == tier && !defined(ux, "typed_digest")) return "typed tier needs typed_digest"
            if ("device" == tier && !defined(ux, "webauthn")) return "device tier needs a WebAuthn assertion"
        }
        return null
    }

    private fun answerBody(a: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg"))
            if (a.containsKey(k)) m[k] = a[k]
        return plain(m) as Map<String, Any?>
    }

    /**
     * Wallet side: sign the principal's answer. [a] is the answer without v / kind / signer / alg; [principalSeed] is the 32-byte
     * Ed25519 seed of the principal key. Throws when the answer is malformed.
     */
    fun signIntentAnswer(a: Map<String, Any?>, principalSeed: ByteArray): Map<String, Any?> {
        val key = Keys.edFromSeed(principalSeed)
        val inp = LinkedHashMap(a)
        inp["v"] = Js.n(2)
        inp["kind"] = "pca-intent-observation"
        inp["signer"] = key.id()
        inp["alg"] = "ed25519"
        val body = answerBody(inp)
        val bad = answerShapeError(body)
        if (bad != null) throw IllegalArgumentException("signIntentAnswer: $bad")
        val out = LinkedHashMap(body)
        out["sig"] = Keys.b64u(key.sign(domainMessage(INTENT_ANSWER_SIG_DOMAIN, body)))
        return out
    }

    /** Verify a signed answer; [principals] (nullable) restricts the signer. Never throws: {ok:true} or {ok:false, reason}. */
    fun verifyIntentAnswer(a: Any?, principals: Any?): Map<String, Any?> {
        try {
            val bad = answerShapeError(a)
            if (bad != null) return obj("ok", false, "reason", bad)
            val ans = a as Map<String, Any?>
            // a non-array (e.g. a string, whose includes() is a substring match) restricts to nobody
            if (principals != null && (principals !is List<*> || !principals.contains(ans["signer"]))) return obj("ok", false, "reason", "signer is not a principal of the session")
            val sig = ans["sig"]
            if (sig !is String || !Pca.verifyB64u(ans["signer"] as String, domainMessage(INTENT_ANSWER_SIG_DOMAIN, answerBody(ans)), sig)) return obj("ok", false, "reason", "bad signature")
            return obj("ok", true)
        } catch (e: RuntimeException) {
            return obj("ok", false, "reason", "malformed answer: " + e.message)
        }
    }

    /** Content address of a signed answer. */
    fun answerRef(a: Any?): String = Pca.hashCanonical(obj("d", INTENT_ANSWER_REF_DOMAIN, "a", a))

    /** The typed-tier digest. */
    fun typedDigest(questionId: String, normalizedValue: String): String =
        Pca.hashCanonical(obj("d", INTENT_TYPED_DOMAIN, "q", questionId, "v", normalizedValue))

    /** The 32-byte WebAuthn challenge of a device-tier answer: {questionId, renderedDigest, y, actionDigest?}. */
    fun deviceChallenge(questionId: String, renderedDigest: String, y: Long, actionDigest: String?): String =
        Pca.hashCanonical(obj("d", INTENT_DEVICE_CHALLENGE_DOMAIN, "q", questionId, "r", renderedDigest, "y", Js.n(y), "a", actionDigest))

    // ---- friction scaled by harm ----

    @JvmField val PROVENANCE_ORDER: List<String> = listOf("trusted", "first_party", "tool", "web", "agent")

    fun isProvenanceLevel(x: Any?): Boolean = x is String && PROVENANCE_ORDER.contains(x)

    /** The highest (least trusted) level of a set; "agent" for an empty or unknown set (fail closed). */
    fun worstProvenance(levels: Any?): String {
        if (levels is String) return "agent" // iterating a string yields single characters, none a level
        if (levels !is List<*>) throw IllegalArgumentException("levels is not iterable")
        var best = -1
        for (l in levels) {
            if (!isProvenanceLevel(l)) return "agent"
            best = Math.max(best, PROVENANCE_ORDER.indexOf(l))
        }
        return if (best < 0) "agent" else PROVENANCE_ORDER[best]
    }

    /** {hTap: 5, hDevice: 100000}. */
    fun defaultFrictionThresholds(): Map<String, Any?> = obj("hTap", Js.n(5), "hDevice", Js.n(100_000))

    /**
     * The tier of a question as {tier, rules}: a pure function of the cell's reversibility, expected harm, provenance and the
     * site minimum. [inp] members: reversibility, expectedHarm, provenance?, widensCriticalIdentity?, singleSource?, siteMin?.
     */
    fun frictionFor(inp: Map<String, Any?>, th: Map<String, Any?> = defaultFrictionThresholds()): Map<String, Any?> {
        val eh = inp["expectedHarm"]
        if (!(isFinite(eh) && nv(eh) >= 0)) return obj("tier", "device", "rules", ArrayList<Any?>(listOf("harm-unknown")))
        val rules = ArrayList<Any?>()
        var tier = "tap"
        fun raise(t: Any?, why: String) {
            if (frictionRank(t) >= frictionRank(tier)) rules.add(why)
            tier = maxFriction(listOf(tier, t))
        }
        val rev = inp["reversibility"]
        val hTap = nv(th["hTap"])
        val hDevice = nv(th["hDevice"])
        if ("rate_limited" == rev) raise("hold", "rate-limited")
        if (nv(eh) >= hTap) raise("hold", "harm>=h_tap")
        if ("irreversible" == rev) raise("typed", "irreversible")
        var taintedCritical = false
        val prov = inp["provenance"]
        if (prov != null) {
            if (prov !is List<*>) throw IllegalArgumentException("provenance is not an array")
            for (p in prov) {
                if (p == null) throw IllegalArgumentException("provenance entry is null")
                if ("critical" == get(p, "sensitivity")) {
                    val w = worstProvenance(get(p, "levels"))
                    if (w == "web" || w == "agent") { taintedCritical = true; break }
                }
            }
        }
        if (taintedCritical) raise("typed", "tainted-critical")
        if (Js.truthy(inp["widensCriticalIdentity"]) && "irreversible" == rev) raise("device", "critical-irreversible")
        if (nv(eh) >= hDevice) raise("device", "harm>=h_device")
        if (Js.truthy(inp["singleSource"])) raise(FRICTION_ORDER[Math.min(FRICTION_ORDER.size - 1, frictionRank(tier) + 1)], "single-source")
        if (defined(inp, "siteMin")) raise(inp["siteMin"], "site-minimum")
        return obj("tier", tier, "rules", rules)
    }

    /** Does an answer given at tier [given] satisfy a requirement of tier [required]? */
    fun satisfiesTier(given: Any?, required: Any?): Boolean = frictionRank(given) >= frictionRank(required)
}
