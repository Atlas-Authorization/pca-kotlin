package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * Rule 13 step 7: session revocation (packages/pca/src/intent-revocation.ts `checkSessionRevocation`). Session ids, map
 * digests, delta-grant ids and profile versions are namespaced ids in the session's revocation set. ONE dedicated revocation
 * authority (`S.revocation.key`, never a principal) signs epochs that carry the FULL revoked list (sorted, distinct, its
 * revset root the signed `root`, its length `set_size == epoch`); the verifier needs an epoch at most `max_age` old that
 * lists none of the ids the action relies on and, when it tracks the last accepted epoch, extends it append-only.
 */
object IntentRevocation {
    const val REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\u0000"
    private val REVSET_PREFIX = "pca-revset/v1\u0000".toByteArray(StandardCharsets.UTF_8)

    fun sessionRevocationId(session: String): String = "pca-intent:session:$session"
    fun mapRevocationId(mapDigest: String): String = "pca-intent:map:$mapDigest"
    fun deltaRevocationId(grantId: String): String = "pca-intent:delta:$grantId"
    fun profileRevocationId(profile: String, version: String): String = "pca-intent:profile:$profile@$version"
    fun sessionRevocationScope(session: String?): String = "pca-intent-session:$session"

    /** JavaScript template-literal text of a JSON value (`${x}`). */
    internal fun jsText(x: Any?, present: Boolean): String {
        if (!present) return "undefined"
        if (x == null) return "null"
        if (x is Json.Num) return if (x.raw == "-0") "0" else x.raw
        if (x is List<*>) return x.joinToString(",") { if (it == null) "" else jsText(it, true) }
        if (x is Map<*, *>) return "[object Object]"
        return x.toString()
    }

    private fun bindRoot(size: Any?, treeRoot: String): String =
        Pca.b64(Pca.sha(REVSET_PREFIX, IntentJs.canonBytes(linkedMapOf<String, Any?>("size" to size, "tree" to treeRoot))))

    private val EMPTY_TREE = Pca.b64(Pca.sha(ByteArray(0)))

    /**
     * `revset_root(L)`: `base64url(SHA-256("pca-revset/v1\0" || canonical({size: |L|, tree})))` over the RFC 6962 Merkle root
     * of `L` in order (leaf `SHA-256(0x00 || canonical(id))`, node `SHA-256(0x01 || l || r)`), `tree = base64url(SHA-256(""))`
     * for the empty list.
     */
    internal fun revsetRoot(ids: List<String>): String =
        bindRoot(IntentJs.ofLong(ids.size.toLong()), if (ids.isEmpty()) EMPTY_TREE else Pca.merkleRoot(ArrayList<Any?>(ids)))

    /** JavaScript truthiness of a JSON value. */
    internal fun truthy(v: Any?): Boolean {
        if (v == null) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        val d = IntentJs.num(v)
        if (d != null) return d != 0.0 && !d.isNaN()
        return true
    }

    /**
     * The revoked list is well-formed and is exactly what the epoch signs: an array of strings strictly ascending in UTF-8
     * byte order, `length == set_size == epoch`, `revset_root(revoked) == root`. Null = ok.
     */
    internal fun revokedListError(ep: Map<String, Any?>, revoked: Any?): String? {
        if (revoked !is List<*> || !revoked.all { it is String }) return "revoked must be an array of ids"
        val r = revoked.map { it as String }
        for (i in 1 until r.size) if (Json.compareUtf8(r[i - 1], r[i]) >= 0) return "revoked must be sorted by UTF-8 bytes and distinct"
        if (r.size.toDouble() != IntentJs.num(ep["set_size"]) || IntentJs.num(ep["epoch"]) != IntentJs.num(ep["set_size"]))
            return "the epoch must be numbered by its set size and list exactly set_size ids"
        if (revsetRoot(r) != ep["root"]) return "the revoked list is not the signed set (root mismatch)"
        return null
    }

    /**
     * The revocation epoch, strictly typed before any comparison: `instance_id`, `grant_ref`, `root`, `guardian`, `sig`
     * strings; `epoch`, `set_size`, `issued_at`, `not_after` (and `guardian_epoch` when present) non-negative safe integers;
     * `alg` a suite this verifier implements; `pq_pk` / `pq_sig` strings when present. Null = well-formed.
     */
    internal fun revocationEpochShapeError(epO: Any?): String? {
        if (epO !is Map<*, *>) return "the revocation epoch must be an object"
        val ep = IntentJs.obj(epO)
        for (k in listOf("instance_id", "grant_ref", "root", "guardian", "sig")) if (ep[k] !is String) return "revocation epoch $k must be a string"
        for (k in listOf("epoch", "set_size", "issued_at", "not_after")) if (!IntentJs.isNonNeg(ep[k])) return "revocation epoch $k must be a non-negative safe integer"
        if (ep.containsKey("guardian_epoch") && !IntentJs.isNonNeg(ep["guardian_epoch"])) return "revocation epoch guardian_epoch must be a non-negative safe integer"
        val se = IntentJs.suiteError(ep["alg"], ep.containsKey("alg"))
        if (se != null) return "revocation epoch alg: $se"
        for (k in listOf("pq_pk", "pq_sig")) if (ep.containsKey(k) && ep[k] !is String) return "revocation epoch $k must be a string"
        return null
    }

    /**
     * The signed epoch (shape already checked): signature under the guardian (a PQ epoch only under the PQ key pinned for
     * it), grant binding, `now <= not_after`, issued at most 60 s ahead.
     */
    internal fun checkRevocationEpoch(ep: Map<String, Any?>, guardian: String, now: Double, grantRef: String, pqPins: Map<String, Any?>?): String? {
        try {
            if (guardian != ep["guardian"] || IntentJs.suiteOf(ep) == null) return "revocation epoch not signed by the pinned guardian"
            val body = LinkedHashMap<String, Any?>()
            for (k in listOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")) body[k] = ep[k]
            val msg = Pca.concat(
                REVEPOCH_DOMAIN.toByteArray(StandardCharsets.UTF_8),
                IntentJs.canonBytes(IntentJs.bindSuiteFields(body, ep["alg"], ep.containsKey("alg"), ep["pq_pk"], ep.containsKey("pq_pk"))),
            )
            if (!IntentJs.verifyPinnedSuite(ep["alg"], ep.containsKey("alg"), guardian, ep["pq_pk"], msg, ep["sig"], ep["pq_sig"], pqPins))
                return "revocation epoch signature invalid"
            if (grantRef != ep["grant_ref"]) return "revocation epoch is for a different grant"
            if (!(now <= IntentJs.num(ep["not_after"])!!)) return "revocation epoch expired (stale revocation root)"
            if (!(IntentJs.num(ep["issued_at"])!! <= now + 60_000)) return "revocation epoch issued in the future"
            return null
        } catch (e: RuntimeException) {
            return "revocation epoch check error"
        }
    }

    /**
     * The session revocation step (rule 13 step 7). First failure wins: a. `maxAgeMs` a safe integer >= 0, the clock a safe
     * integer, `ids` a list, the authority a string; b. the evidence an object with a well-formed epoch whose guardian is the
     * dedicated `authority`; c. the epoch verifies for the scope (PQ only under `pqPins`); d. it is at most `maxAgeMs` old;
     * e. `revoked` is the full signed set; f. APPEND-ONLY against the tracked `last` when present; g. no id of `ids` is
     * revoked. Null = ok.
     */
    fun checkSessionRevocation(
        ev: Any?, session: String?, authority: Any?, ids: List<*>?, now: Double, maxAgeMs: Double,
        scope: String?, pqPins: Map<String, Any?>?, lastPresent: Boolean, last: Any?,
    ): String? {
        try {
            if (!(maxAgeMs.isFinite() && maxAgeMs == Math.rint(maxAgeMs) && maxAgeMs <= IntentJs.MAX_SAFE && maxAgeMs >= 0 && !IntentJs.isNegZero(maxAgeMs)))
                return "revocation max age misconfigured (fail closed)"
            if (!(now.isFinite() && now == Math.rint(now) && Math.abs(now) <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(now))) return "the verifier clock is not a safe integer (fail closed)"
            if (ids == null || authority !is String) return "ids must be an array and the authority a key"
            if (ev !is Map<*, *>) return "no session revocation epoch supplied"
            closedEvidenceError(ev)?.let { return "the revocation evidence $it" }
            val epO = IntentJs.get(ev, "epoch")
            val shape = revocationEpochShapeError(epO)
            if (shape != null) return shape
            val ep = IntentJs.obj(epO)
            if (authority != ep["guardian"]) return "the revocation epoch is not signed by the session revocation authority"
            val r = checkRevocationEpoch(ep, authority, now, scope ?: sessionRevocationScope(session), pqPins)
            if (r != null) return r
            if (!(now - IntentJs.num(ep["issued_at"])!! <= maxAgeMs)) return "the session revocation epoch is older than ${maxAgeMs.toLong()} ms"
            val revoked = IntentJs.get(ev, "revoked")
            val le = revokedListError(ep, revoked)
            if (le != null) return le
            if (lastPresent) {
                val lep = IntentJs.get(last, "epoch")
                if (last !is Map<*, *> || closedEvidenceError(last) != null || revocationEpochShapeError(lep) != null || revokedListError(IntentJs.obj(lep), IntentJs.get(last, "revoked")) != null)
                    return "the tracked last epoch is malformed (fail closed)"
                if (IntentJs.num(ep["epoch"])!! < IntentJs.num(IntentJs.get(lep, "epoch"))!!) return "revocation epoch rollback (older than the last accepted)"
                val cur = HashSet(revoked as List<*>)
                for (id in IntentJs.get(last, "revoked") as List<*>)
                    if (id !in cur) return "the epoch drops '$id', revoked in the last accepted epoch (not append-only)"
                if (IntentJs.num(ep["epoch"]) == IntentJs.num(IntentJs.get(lep, "epoch")) && ep["root"] != IntentJs.get(lep, "root"))
                    return "two different revocation sets under one epoch number (equivocation)"
            }
            val rv = HashSet(revoked as List<*>)
            for (id in ids) if (id !is String || id in rv) return "'${jsText(id, true)}' is revoked"
            return null
        } catch (e: RuntimeException) {
            return "session revocation check error (fail closed): " + e.javaClass.simpleName
        }
    }

    /** The evidence is CLOSED: exactly the members `epoch` and `revoked` (an extra member is malformed). Null = ok. */
    internal fun closedEvidenceError(ev: Map<*, *>): String? {
        for (k in ev.keys) if (k != "epoch" && k != "revoked") return "has the unknown member '$k' (it is exactly {epoch, revoked})"
        return null
    }

    /** The parameters of `primitives.intent_revocation`; every other input member belongs to the (closed) evidence. */
    internal val PRIMITIVE_PARAMS = listOf("session", "scope", "authority", "ids", "now", "max_age_ms", "last")

    /**
     * The `primitives.intent_revocation` entry point: `{epoch, revoked, session, authority, ids, now, max_age_ms, last?}` with
     * the scope `"pca-intent-session:" + session`.
     */
    fun checkPrimitive(input: Any?): Boolean = primitiveReason(input) == null

    /** As [checkPrimitive], with the refusal reason (null = ok). */
    fun primitiveReason(input: Any?): String? {
        try {
            val inp = IntentJs.obj(IntentJs.normalize(input))
            val ev = LinkedHashMap(inp).also { m -> PRIMITIVE_PARAMS.forEach { m.remove(it) } }
            val maxAge = if (IntentJs.isInt(inp["max_age_ms"])) IntentJs.num(inp["max_age_ms"])!! else Double.NaN
            val now = if (IntentJs.isInt(inp["now"])) IntentJs.num(inp["now"])!! else Double.NaN
            return checkSessionRevocation(
                ev, inp["session"] as? String, inp["authority"], inp["ids"] as? List<*>, now, maxAge,
                null, null, inp.containsKey("last"), inp["last"],
            )
        } catch (e: RuntimeException) {
            return "session revocation check error (fail closed)"
        }
    }
}
