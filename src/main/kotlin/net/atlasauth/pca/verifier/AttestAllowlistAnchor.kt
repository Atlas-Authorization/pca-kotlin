package net.atlasauth.pca.verifier

/**
 * Transparency-anchored rollback detection for signed allowlist manifests. A fresh machine, or an attacker who deletes the local state, has no
 * `lastSeenVersion`, so an old but unexpired manifest (possibly allowlisting a since-revoked measurement) would verify. This moves "the highest version ever
 * issued" into an append-only Merkle log (RFC 6962 tree, RFC 9162 consistency, guardian-signed tree heads, optional witness cosignatures).
 *
 * OPERATOR: [anchorAllowlistHead] appends `{issuer, version, digest}` and re-signs the head; it refuses a version below one already anchored or a second digest
 * for an anchored version. VERIFIER: [verifyAllowlistAnchored] requires a head signed by the pinned log key (and the witness threshold when configured), fresh
 * (`maxHeadAgeMs`), extending the cached head by a valid consistency proof, a log content that reproduces the signed root exactly (nothing can be omitted), an
 * inclusion proof of THIS manifest, and a version at least the highest anchored for its issuer (equal only with the identical digest). It works with EMPTY
 * local state; a cached head only tightens it.
 *
 * Not guaranteed: a single operator that is also the attacker can serve a verifier with no cached head and no witness policy an old head within
 * `maxHeadAgeMs`; the log is only as honest as its witnesses. Freshness depends on the operator re-signing the head ([refreshAnchorHead]). An anchor binds
 * ordering, not truth.
 */
@Suppress("UNCHECKED_CAST")
object AttestAllowlistAnchor {
    const val DOMAIN = "pca-attest-allowlist-anchor/v1"
    private val B64U_DIGEST = Regex("[A-Za-z0-9_-]{43}")
    private const val MAX_FEED = 100_000
    private const val DAY = 86_400_000.0

    /** The leaf the log stores for an entry `{issuer, version, digest}`: deterministic and public. */
    @JvmStatic
    fun allowlistAnchorCommit(e: Map<String, Any?>): String =
        Pca.hashCanonical(IntentJs.normalize(linkedMapOf("domain" to DOMAIN, "issuer" to e["issuer"], "version" to e["version"], "digest" to e["digest"])))

    private fun validEntry(e: Any?): Boolean {
        if (e !is Map<*, *> || e.size != 3) return false
        val issuer = e["issuer"]
        return issuer is String && issuer.isNotEmpty() && issuer.length <= 200 && IntentJs.isSafeInteger(e["version"]) && IntentJs.num(e["version"])!! >= 1 &&
            e["digest"] is String && B64U_DIGEST.matches(e["digest"] as String)
    }

    private fun copyEntry(e: Map<*, *>): LinkedHashMap<String, Any?> = linkedMapOf("issuer" to e["issuer"], "version" to IntentJs.ofLong(IntentJs.lng(e["version"])), "digest" to e["digest"])

    /** The operator's anchor log: the Merkle log of commitments plus the plaintext entries behind them and the latest signed head. */
    class AnchorLog internal constructor(val instanceId: String, val principal: String) {
        internal val ledger = MerkleLog()
        internal val items = ArrayList<LinkedHashMap<String, Any?>>()
        internal var head: Map<String, Any?>? = null

        fun entries(): List<Map<String, Any?>> = items.map { LinkedHashMap(it) }

        /** The latest signed head, if anything was ever anchored. */
        fun latest(): Map<String, Any?>? = head
    }

    /** An empty anchor log. `principal` is the log id the verifier pins; `instanceId` the deployment. */
    @JvmStatic fun createAllowlistAnchorLog(instanceId: String, principal: String): AnchorLog = AnchorLog(instanceId, principal)

    private fun signHead(log: AnchorLog, guardian: Keys.SuiteKey, nowMs: Any?): Map<String, Any?> {
        val h = log.ledger.head()
        val sth = Ledger.signTreeHead(
            guardian,
            linkedMapOf(
                "instance_id" to log.instanceId, "principal" to log.principal, "size" to h["size"], "root" to h["root"],
                "prev_root" to ((log.head?.get("root")) ?: ""), "timestamp" to nowMs,
            ),
        )
        log.head = sth
        return sth
    }

    /**
     * Anchor a verified manifest (an `ok` result) or a bare entry `{issuer, version, digest}` and re-sign the head at `nowMs`. Throws when it would lower the
     * issuer's highest anchored version or give an anchored version a second digest; re-anchoring the identical entry is idempotent. Returns the evidence for
     * the entry's leaf: `{head, entries, proof}`.
     */
    @JvmStatic
    fun anchorAllowlistHead(log: AnchorLog, what: Any?, guardian: Keys.SuiteKey, nowMs: Any?): Map<String, Any?> {
        if (what !is Map<*, *>) throw IllegalArgumentException(if (what == null) "Cannot use 'in' operator" else "anchorAllowlistHead: malformed entry")
        val entry: Map<String, Any?> = if (what.containsKey("body")) linkedMapOf("issuer" to what["issuer"], "version" to what["version"], "digest" to what["digest"]) else LinkedHashMap(what as Map<String, Any?>)
        if (!validEntry(entry)) throw IllegalArgumentException("anchorAllowlistHead: malformed entry")
        val clean = copyEntry(entry)
        val ver = IntentJs.num(clean["version"])!!
        val same = log.items.indexOfFirst { it["issuer"] == clean["issuer"] && IntentJs.num(it["version"]) == ver }
        val index: Int
        if (same >= 0) {
            if (log.items[same]["digest"] != clean["digest"]) throw IllegalStateException("anchorAllowlistHead: this version is already anchored with a different digest")
            index = same
        } else {
            val max = log.items.filter { it["issuer"] == clean["issuer"] }.fold(0.0) { m, e -> Math.max(m, IntentJs.num(e["version"])!!) }
            if (ver < max) throw IllegalStateException("anchorAllowlistHead: version ${IntentJs.lng(clean["version"])} is lower than the anchored ${max.toLong()}")
            index = log.ledger.appendCommitment(allowlistAnchorCommit(clean))
            log.items.add(clean)
            signHead(log, guardian, nowMs)
        }
        if (log.head == null) signHead(log, guardian, nowMs)
        return evidenceFor(log, index.toLong(), null)
    }

    /** Re-sign the current head with a fresh timestamp (a liveness heartbeat, no new entry). Throws on an empty log. */
    @JvmStatic
    fun refreshAnchorHead(log: AnchorLog, guardian: Keys.SuiteKey, nowMs: Any?): Map<String, Any?> {
        if (log.ledger.size() == 0) throw IllegalStateException("refreshAnchorHead: nothing anchored yet")
        return signHead(log, guardian, nowMs)
    }

    /** Evidence for the leaf at `index` under the latest head; with `cachedSize` (the verifier's cached head size) it carries a consistency proof when smaller. */
    @JvmStatic @JvmOverloads
    fun evidenceFor(log: AnchorLog, index: Long, cachedSize: Long? = null): Map<String, Any?> {
        val latest = log.head ?: throw IllegalStateException("evidenceFor: log has no signed head")
        val out = linkedMapOf<String, Any?>("head" to latest, "entries" to log.entries(), "proof" to log.ledger.inclusionProof(index))
        val size = IntentJs.num(latest["size"])!!
        if (cachedSize != null && cachedSize > 0 && cachedSize < size) out["consistency"] = log.ledger.consistencyProof(cachedSize, size.toLong())
        return out
    }

    /** The anchor entry `{issuer, version, digest}` of a verified manifest. */
    @JvmStatic
    fun anchorEntryOf(v: Map<String, Any?>): Map<String, Any?> = linkedMapOf("issuer" to v["issuer"], "version" to v["version"], "digest" to v["digest"])

    private fun no(code: String, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "code" to code, "reason" to reason)

    /**
     * Check a signature-verified manifest `verified` (`{issuer, version, digest}`) against log `evidence` `{head, entries, proof, consistency?}`. `opts` is
     * `{trust: {logKey, instanceId, principal, witnesses?, pqPins?}, nowMs, maxHeadAgeMs?, clockSkewMs?, cachedHead?}`. Never throws: `{ok: true, issuer,
     * version, digest, highestAnchoredVersion, head}` or `{ok: false, code, reason}` (missing-proof, bad-head, stale-head, bad-cache, log-rollback,
     * split-view, inconsistent-with-cache, feed-mismatch, bad-proof, not-anchored, anchored-rollback, log-conflict). The cache, freshness and feed-scan
     * decisions follow the proved stages: cache (smaller head is a rollback, equal size with another root a split view, larger needs a consistency proof),
     * freshness (options validated first, so a NaN can never disable the window) and the feed scan (conflict, then rollback, then not anchored).
     */
    @JvmStatic
    fun verifyAllowlistAnchored(verified: Map<String, Any?>, evidence: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        try {
            if (evidence !is Map<*, *> || !evidence.containsKey("proof") || !evidence.containsKey("head") || evidence["entries"] !is List<*>) {
                return no("missing-proof", "no anchor evidence (head + entries + inclusion proof) supplied")
            }
            val trust = opts["trust"] as Map<String, Any?>
            val logKey = trust["logKey"] as String
            val witnesses = trust["witnesses"] as Map<String, Any?>?
            val pins = trust["pqPins"] as Map<String, Any?>?
            if (!IntentJs.isSafeInteger(opts["nowMs"])) return no("bad-head", "nowMs must be an integer")
            val nowMs = IntentJs.num(opts["nowMs"])!!
            val head = evidence["head"] as Map<String, Any?>
            if (!Ledger.verifyTreeHead(head, logKey, witnesses, pins)) return no("bad-head", "tree head is not signed by the pinned log key (or lacks the required witness cosignatures)")
            if (head["instance_id"] != trust["instanceId"] || head["principal"] != trust["principal"]) return no("bad-head", "tree head is for a different log")
            val skewOk = !opts.containsKey("clockSkewMs") || IntentJs.isFinite(opts["clockSkewMs"])
            val ageOk = !opts.containsKey("maxHeadAgeMs") || IntentJs.isFinite(opts["maxHeadAgeMs"])
            if (!(skewOk && ageOk)) return no("bad-head", if (skewOk) "maxHeadAgeMs must be a finite number" else "clockSkewMs must be a finite number")
            val skew = Math.max(0.0, if (opts.containsKey("clockSkewMs")) IntentJs.num(opts["clockSkewMs"])!! else 60_000.0)
            val maxAge = if (opts.containsKey("maxHeadAgeMs")) IntentJs.num(opts["maxHeadAgeMs"])!! else DAY
            val ts = IntentJs.num(head["timestamp"])
            if (!IntentJs.isSafeInteger(head["timestamp"])) return no("stale-head", "tree head is timestamped in the future")
            val ageInt = Math.abs(maxAge) < Math.pow(2.0, 52.0)
            if (ageInt) {
                if (!(ts!! <= nowMs + Math.floor(skew))) return no("stale-head", "tree head is timestamped in the future")
                if (!(nowMs - ts <= Math.floor(maxAge))) return no("stale-head", "tree head is older than maxHeadAgeMs")
            } else {
                if (!(ts!! <= nowMs + skew)) return no("stale-head", "tree head is timestamped in the future")
                if (!(nowMs - ts <= maxAge)) return no("stale-head", "tree head is older than maxHeadAgeMs")
            }
            val headSize = IntentJs.num(head["size"])!!

            if (opts.containsKey("cachedHead")) {
                val cached = opts["cachedHead"] as Map<String, Any?>?
                if (cached == null || !Ledger.verifyTreeHead(cached, logKey, witnesses, pins) || cached["instance_id"] != trust["instanceId"] || cached["principal"] != trust["principal"]) {
                    return no("bad-cache", "the cached head does not verify under the pinned log key")
                }
                val cachedSize = IntentJs.num(cached["size"])!!
                if (headSize < cachedSize) return no("log-rollback", "head size < cached: the log shrank")
                if (headSize == cachedSize && head["root"] != cached["root"]) return no("split-view", "two different roots at the same size: split view / fork")
                if (headSize > cachedSize) {
                    val c = if (evidence.containsKey("consistency")) evidence["consistency"] else null
                    if (c == null || !Ledger.verifyHeadConsistency(cached, head, c, logKey, witnesses, pins)) {
                        return no("inconsistent-with-cache", "no valid consistency proof from the cached head: forked or truncated log")
                    }
                }
            }

            val entries = evidence["entries"] as List<Any?>
            if (entries.size > MAX_FEED || entries.size.toDouble() != headSize || !entries.all { validEntry(it) }) return no("feed-mismatch", "entries do not match the signed tree size")
            val feed = entries.map { copyEntry(it as Map<*, *>) }
            if (Ledger.ledgerRootOf(feed.map { allowlistAnchorCommit(it) }) != head["root"]) return no("feed-mismatch", "entries do not reproduce the signed root")

            val issuer = verified["issuer"]
            val version = IntentJs.num(verified["version"])!!
            val digest = verified["digest"]
            val mine = linkedMapOf("issuer" to issuer, "version" to verified["version"], "digest" to digest)
            val mineEntries = feed.filter { it["issuer"] == issuer }
            var highest = 0.0
            val firstDigest = HashMap<Double, Any?>()
            var conflict = false
            for (e in mineEntries) {
                val ev = IntentJs.num(e["version"])!!
                if (ev > highest) highest = ev
                if (firstDigest.containsKey(ev)) { if (firstDigest[ev] != e["digest"]) conflict = true } else firstDigest[ev] = e["digest"]
            }
            if (conflict) return no("log-conflict", "log anchors two different digests for one version of '${ZkJs.string(issuer)}'")
            val proof = evidence["proof"] as Map<String, Any?>
            if (IntentJs.num(proof["size"]) != headSize) return no("bad-proof", "inclusion proof size does not match the signed head size")
            if (!Ledger.verifyInclusion(head["root"] as String, proof, allowlistAnchorCommit(mine))) return no("bad-proof", "inclusion proof does not place this manifest under the signed root")
            if (version < highest) return no("anchored-rollback", "manifest version ${version.toLong()} < highest anchored ${highest.toLong()}")
            if (mineEntries.none { IntentJs.num(it["version"]) == version && it["digest"] == digest }) return no("not-anchored", "this manifest digest is not the one anchored for its version")
            return linkedMapOf("ok" to true, "issuer" to issuer, "version" to verified["version"], "digest" to digest, "highestAnchoredVersion" to IntentJs.ofLong(highest.toLong()), "head" to head)
        } catch (e: RuntimeException) {
            return no("bad-head", e.message ?: "anchor verification error")
        }
    }
}
