package net.atlasauth.pca.verifier

/**
 * Signed policy bundles and decision records (packages/pca-grants/src/bundle.ts), VERIFICATION only. A bundle pins everything a decision
 * depends on under one monotone `revision`, signed k-of-n by pinned keys; every decision record is hash-chained, committed to a Merkle log
 * and cited by a signed log head. All signatures are Ed25519 over `domain || strictCanonical(body)` (see [K3Sig]). Total: malformed
 * input is the failure value, never an exception.
 */
object Bundle {
    const val BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\u0000"
    const val BUNDLE_REF_DOMAIN = "atlas-pca/policy-bundle-ref/v1"
    const val RECORD_DOMAIN = "atlas-pca/decision-record/v1"
    const val LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\u0000"

    private const val MAX_LIST = 4096
    private val VERSION_RE = Regex("[0-9]{1,6}(\\.[0-9]{1,6}){0,3}")

    /** The bundle without its signatures. */
    private fun bodyOf(b: Map<String, Any?>): Map<String, Any?> = K3Sig.without(b, "sigs")

    /** Content address of a bundle; the signatures are not part of it. */
    @JvmStatic
    fun digest(bundle: Any?): String = K3Sig.digestOf("d" to BUNDLE_REF_DOMAIN, "b" to bodyOf(K3Sig.map(bundle) ?: LinkedHashMap<String, Any?>()))

    /** `a` versus `b` as dotted numbers: -1, 0 or 1 (a missing component is 0). */
    @JvmStatic
    fun compareVersion(a: String, b: String): Int {
        val pa = a.split('.').map { numOf(it) }
        val pb = b.split('.').map { numOf(it) }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val d = (pa.getOrNull(i) ?: 0.0) - (pb.getOrNull(i) ?: 0.0)
            if (d != 0.0) return if (d < 0) -1 else 1
        }
        return 0
    }

    /** JavaScript `Number(s)` for the digit strings a version holds (empty is 0, anything else unparsable is NaN). */
    private fun numOf(s: String): Double = if (s.isEmpty()) 0.0 else s.toDoubleOrNull() ?: Double.NaN

    /** Why `b` is not a well-formed bundle, or null. */
    @JvmStatic
    fun shapeError(b: Any?): String? {
        val m = K3Sig.map(b)
        if (m == null || IntentJs.num(m["v"]) != 1.0 || m["kind"] != "pca-policy-bundle") return "not a policy bundle"
        if (!K3Sig.isSafeInt(m["revision"]) || IntentJs.num(m["revision"])!! < 1.0 || !K3Sig.isSafeInt(m["issued_at"])) return "bad revision or time"
        val first = IntentJs.num(m["revision"]) == 1.0
        if (if (first) m.containsKey("prev") else !K3Sig.isStr(m["prev"], 128)) return "prev must be absent at revision 1 and present after"
        val grants = K3Sig.list(m["grants"])
        if (grants == null || grants.size > MAX_LIST || !grants.all { K3Sig.isStr(it, 128) }) return "bad grants"
        val templates = K3Sig.list(m["template_digests"])
        if (templates == null || templates.size > MAX_LIST || !templates.all { K3Sig.isStr(it, 128) }) return "bad template_digests"
        for (k in listOf("schema_digest", "constitution_digest", "flow_rules_digest")) if (m.containsKey(k) && !K3Sig.isStr(m[k], 128)) return "bad $k"
        val ver = m["min_verifier_version"]
        if (ver !is String || !VERSION_RE.matches(ver)) return "bad min_verifier_version"
        return null
    }

    /** `ok`: [revision], [digest] and the pinned signers whose signature verified, in signature order. Otherwise [code] and [reason]. */
    class Verdict(
        val ok: Boolean,
        val revision: Long = 0,
        val digest: String = "",
        val signers: List<String> = emptyList(),
        val code: String = "",
        val reason: String = "",
    ) {
        /** The vector form. */
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) {
                m["revision"] = revision
                m["digest"] = digest
                m["signers"] = signers
            } else {
                m["code"] = code
                m["reason"] = reason
            }
            return m
        }
    }

    private fun fail(code: String, reason: String) = Verdict(false, code = code, reason = reason)

    /** The newest accepted revision and digest so far: a lower revision is a rollback, the next one must chain by `prev`. */
    class Last(val revision: Long, val digest: String)

    /**
     * Verify a bundle against the pinned `signers` (signatures by anyone else are ignored), `threshold` valid distinct signatures, this
     * verifier's own `verifierVersion` and the `last` accepted state. Check order: shape, sigs and threshold, signatures, verifier version,
     * rollback, same-revision content, chain.
     */
    @JvmStatic
    fun verify(b: Any?, signers: Collection<String>, threshold: Long, verifierVersion: String, last: Last? = null): Verdict {
        return try {
            val e = shapeError(b)
            if (e != null) return fail("malformed", e)
            val bundle = K3Sig.map(b)!!
            val sigs = K3Sig.list(bundle["sigs"])
            if (sigs == null || sigs.size > 64 || threshold < 1) return fail("malformed", "bad sigs or threshold")
            val pinned = HashSet(signers)
            val body = bodyOf(bundle)
            val good = LinkedHashSet<String>()
            for (s in sigs) {
                val sm = K3Sig.map(s) ?: continue
                val signer = sm["signer"]
                if (signer is String && pinned.contains(signer) && K3Sig.verifyBody(BUNDLE_DOMAIN, body, signer, sm["sig"])) good.add(signer)
            }
            if (good.size < threshold) return fail("below_threshold", "${good.size} valid pinned signature(s), need $threshold")
            val minVer = bundle["min_verifier_version"] as String
            if (!VERSION_RE.matches(verifierVersion) || compareVersion(verifierVersion, minVer) < 0) return fail("verifier_too_old", "needs verifier >= $minVer")
            val revision = IntentJs.lng(bundle["revision"])
            val dig = digest(bundle)
            if (last != null) {
                if (revision < last.revision) return fail("rollback", "revision $revision < accepted ${last.revision}")
                if (revision == last.revision && dig != last.digest) return fail("broken_chain", "same revision, different content")
                if (revision == last.revision + 1 && bundle["prev"] != last.digest) return fail("broken_chain", "prev does not chain to the accepted revision")
            }
            Verdict(true, revision, dig, good.toList())
        } catch (e: RuntimeException) {
            fail("malformed", "malformed bundle")
        }
    }

    /** The commit of a decision record (the Merkle leaf is this string). Throws only for an out-of-profile record. */
    @JvmStatic
    fun recordCommit(record: Any?): String = K3Sig.digestOf("d" to RECORD_DOMAIN, "r" to record)

    /** A signed log head: well formed and signed by `signer` over exactly its content. */
    @JvmStatic
    fun verifyLogHead(h: Any?, signer: String): Boolean {
        val m = K3Sig.map(h) ?: return false
        if (IntentJs.num(m["v"]) != 1.0 || m["signer"] != signer || !K3Sig.isSafeInt(m["size"]) || !K3Sig.isSafeInt(m["issued_at"]) || m["root"] !is String || m["last_commit"] !is String) return false
        return K3Sig.verifyBody(LOG_HEAD_DOMAIN, K3Sig.without(m, "sig"), signer, m["sig"])
    }

    /** Offline: this record is in the log the signed head commits to, and the head is by the pinned signer. */
    @JvmStatic
    fun verifyRecordInclusion(record: Any?, proof: Any?, head: Any?, signer: String): Boolean = try {
        verifyLogHead(head, signer) && Pca.verifyInclusion(K3Sig.map(head)!!["root"] as String, K3Sig.map(proof), recordCommit(record))
    } catch (e: RuntimeException) {
        false
    }

    /** `ok`: the new cursor [next] and [lastCommit]. Otherwise the [reason]. */
    class BatchVerdict(val ok: Boolean, val next: Long = 0, val lastCommit: String = "", val reason: String = "") {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) {
                m["next"] = next
                m["lastCommit"] = lastCommit
            } else m["reason"] = reason
            return m
        }
    }

    /**
     * Receiver side of the decision stream: contiguous sequence, intact hash chain from the receiver's state (`stateNext`,
     * `stateLastCommit`) and, when the batch reaches the head, the head's last commit and size match. Never throws.
     */
    @JvmStatic
    fun verifyBatch(batch: Any?, stateNext: Long, stateLastCommit: String, signer: String): BatchVerdict {
        try {
            val b = K3Sig.map(batch) ?: return BatchVerdict(false, reason = "malformed batch")
            if (IntentJs.num(b["from"]) != stateNext.toDouble()) {
                return BatchVerdict(false, reason = "gap or replay: batch starts at ${K3Sig.jsText(b["from"], b.containsKey("from"))}, expected $stateNext")
            }
            if (!verifyLogHead(b["head"], signer)) return BatchVerdict(false, reason = "head not signed by the pinned log signer")
            val head = K3Sig.map(b["head"])!!
            val records = K3Sig.list(b["records"]) ?: return BatchVerdict(false, reason = "malformed batch")
            var last = stateLastCommit
            var n = stateNext
            for (r in records) {
                val rm = K3Sig.map(r) ?: return BatchVerdict(false, reason = "malformed batch")
                if (IntentJs.num(rm["seq"]) != n.toDouble() || rm["prev"] != last) {
                    return BatchVerdict(false, reason = "chain broken at seq ${K3Sig.jsText(rm["seq"], rm.containsKey("seq"))}")
                }
                last = recordCommit(rm)
                n++
            }
            val size = IntentJs.lng(head["size"])
            if (n > size) return BatchVerdict(false, reason = "batch is longer than the signed head")
            if (n == size && last != head["last_commit"]) return BatchVerdict(false, reason = "batch end does not match the signed head")
            return BatchVerdict(true, next = n, lastCommit = last)
        } catch (e: RuntimeException) {
            return BatchVerdict(false, reason = "malformed batch")
        }
    }
}
