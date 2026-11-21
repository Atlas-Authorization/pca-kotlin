package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Bundle as BundleVerify

/**
 * Signed policy bundles and decision records: the signing, log and replay sides. Verification (verify, digest, compareVersion,
 * recordCommit, verifyLogHead, verifyRecordInclusion, verifyBatch) is [BundleVerify] in the verifier package.
 */
object Bundle {
    private fun bodyOf(b: Map<String, Any?>): LinkedHashMap<String, Any?> = K3Sig.without(b, "sigs")

    /** One signer's `{signer, sig}` over the bundle body. Collect k of them and call [assembleBundle]. Throws on a malformed body. */
    @JvmStatic
    fun signBundle(body: Map<String, Any?>, secret: Keys.EdKey): Map<String, Any?> {
        val e = BundleVerify.shapeError(body)
        require(e == null) { "signBundle: $e" }
        val s = LinkedHashMap<String, Any?>()
        s["signer"] = GrantSigning.signerOf(secret)
        s["sig"] = GrantSigning.signBody(BundleVerify.BUNDLE_DOMAIN, bodyOf(body), secret)
        return s
    }

    @JvmStatic
    fun assembleBundle(body: Map<String, Any?>, sigs: List<Any?>): Map<String, Any?> {
        val b = bodyOf(body)
        b["sigs"] = sigs
        return b
    }

    /** Mask by data CLASS: every detail field whose class is in [maskClasses] becomes a commitment. Returns the record itself when it has no detail or classes. */
    @JvmStatic
    fun maskRecord(r: Map<String, Any?>, maskClasses: List<String>): Map<String, Any?> {
        val detail = K3Sig.map(r["detail"])
        val classes = K3Sig.map(r["classes"])
        if (detail == null || classes == null) return r
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in detail) {
            val cls = classes[k]
            if (cls is String && cls in maskClasses) {
                val h = LinkedHashMap<String, Any?>()
                h["d"] = "atlas-pca/mask/v1"
                h["k"] = k
                h["v"] = v
                out[k] = "masked:" + cls + ":" + Pca.hashCanonical(h)
            } else {
                out[k] = v
            }
        }
        val res = LinkedHashMap<String, Any?>(r)
        res["detail"] = out
        return res
    }

    /** Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs. */
    class DecisionLog @JvmOverloads constructor(private val secret: Keys.EdKey, private val maskClasses: List<String> = emptyList()) {
        private val recs = ArrayList<Map<String, Any?>>()

        @Synchronized
        fun size(): Int = recs.size

        /** Mask, chain and store a record (without v, seq, prev); returns the stored record. */
        @Synchronized
        fun append(r: Map<String, Any?>): Map<String, Any?> {
            val masked = maskRecord(r, maskClasses)
            val rec = LinkedHashMap<String, Any?>()
            rec["v"] = 1L
            rec.putAll(masked)
            rec["seq"] = recs.size.toLong()
            rec["prev"] = if (recs.isEmpty()) "" else BundleVerify.recordCommit(recs[recs.size - 1])
            recs.add(rec)
            return rec
        }

        private fun commits(): List<Any?> {
            val c = ArrayList<Any?>()
            for (r in recs) c.add(BundleVerify.recordCommit(r))
            return c
        }

        @Synchronized
        fun head(now: Long): Map<String, Any?> {
            val base = LinkedHashMap<String, Any?>()
            base["v"] = 1L
            base["size"] = recs.size.toLong()
            base["root"] = Pca.merkleRoot(commits()) // throws on an empty log, like the reference
            base["last_commit"] = BundleVerify.recordCommit(recs[recs.size - 1])
            base["issued_at"] = now
            base["signer"] = GrantSigning.signerOf(secret)
            val out = LinkedHashMap<String, Any?>(base)
            out["sig"] = GrantSigning.signBody(BundleVerify.LOG_HEAD_DOMAIN, base, secret)
            return out
        }

        @Synchronized
        fun proof(seq: Int): Map<String, Any?> = GrantSigning.merkleProof(commits(), seq)

        /** Records [from, to) clamped to the log (JavaScript slice semantics for non-negative bounds). */
        @Synchronized
        fun slice(from: Int, to: Int): List<Any?> {
            val a = minOf(maxOf(from, 0), recs.size)
            val b = minOf(maxOf(to, a), recs.size)
            return ArrayList<Any?>(recs.subList(a, b))
        }
    }

    /** The next batch of at most [max] records from [from] with a freshly signed head: `{from, records, head}`. */
    @JvmStatic
    fun nextBatch(log: DecisionLog, from: Any?, max: Any?, now: Any?): Map<String, Any?> {
        require(K3Sig.isSafeInt(from) && Json.isSafeInt(max) && Json.asLong(max) >= 1) { "nextBatch: bad cursor or size" }
        val f = Json.asLong(from)
        val m = Json.asLong(max)
        val b = LinkedHashMap<String, Any?>()
        b["from"] = f
        b["records"] = log.slice(minOf(f, Int.MAX_VALUE.toLong()).toInt(), minOf(f + m, Int.MAX_VALUE.toLong()).toInt())
        b["head"] = log.head(Json.asLong(now))
        return b
    }

    private fun rank(k: String?): Int = when (k) { "deny" -> 0; "escalate" -> 1; "allow" -> 2; else -> -1 }

    /**
     * "What would have changed": re-run two pure decision functions over recorded traffic. [cases] are `{action_digest, input}`.
     * A change is `{action_digest, before, after, direction}`. Analysis tooling: it runs outside the trusted core.
     */
    @JvmStatic
    fun semanticDiff(cases: List<Any?>, oldDecide: (Any?) -> String?, newDecide: (Any?) -> String?): List<Any?> {
        val out = ArrayList<Any?>()
        for (co in cases) {
            val c = K3Sig.map(co)!!
            val before = oldDecide(c["input"])
            val after = newDecide(c["input"])
            if (before != after) {
                val ch = LinkedHashMap<String, Any?>()
                ch["action_digest"] = c["action_digest"]
                if (before != null) ch["before"] = before // an undefined decision is absent from the reference's JSON
                if (after != null) ch["after"] = after
                ch["direction"] = if (rank(after) >= 0 && rank(before) >= 0 && rank(after) > rank(before)) "widened" else "tightened"
                out.add(ch)
            }
        }
        return out
    }

    /** Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift). */
    @JvmStatic
    fun auditReplay(records: List<Any?>, cases: List<Any?>, decide: (Any?, Any?) -> String?): List<Any?> {
        val byAction = LinkedHashMap<Any?, Any?>()
        for (co in cases) byAction[K3Sig.map(co)!!["action_digest"]] = K3Sig.map(co)!!["input"]
        val out = ArrayList<Any?>()
        for (ro in records) {
            val r = K3Sig.map(ro)!!
            if (!byAction.containsKey(r["action_digest"])) continue
            val d = decide(byAction[r["action_digest"]], r["bundle_revision"])
            if (d != r["decision"]) out.add(ro)
        }
        return out
    }
}
