package net.atlasauth.pca.verifier

/**
 * Action receipts: the principal's own tamper-evident, hash-chained log of what their agents did and how each action was verified. Each
 * receipt commits to the previous one, so a dropped or altered entry is detectable. Pure (hashing only). A receipt is
 * `{seq, at, actionDigest, verb, resource, outcome: allow|deny, checks?, prev, hash}`.
 */
object Receipts {
    private fun body(r: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "d" to "atlas-pca/receipt/v1", "seq" to r["seq"], "at" to r["at"], "actionDigest" to r["actionDigest"], "verb" to r["verb"],
        "resource" to r["resource"], "outcome" to r["outcome"], "checks" to (if (r.containsKey("checks")) r["checks"] else null), "prev" to r["prev"],
    )

    /** The next receipt in a chain for a verified action; [checks] and [at] (default: the action's `iat`) are optional. */
    @JvmOverloads
    fun receiptFor(prevHash: String, seq: Long, pcactn: Map<String, Any?>, allow: Boolean, checks: Map<String, Any?>? = null, at: Long? = null): Map<String, Any?> {
        val action = Pca.asMap(pcactn["action"])
        val b = LinkedHashMap<String, Any?>()
        b["seq"] = seq
        b["at"] = at ?: pcactn["iat"]
        b["actionDigest"] = Pca.hashCanonical(pcactn)
        b["verb"] = action["verb"]
        b["resource"] = action["resource"]
        b["outcome"] = if (allow) "allow" else "deny"
        if (checks != null) b["checks"] = checks
        b["prev"] = prevHash
        val r = LinkedHashMap(b)
        r["hash"] = Pca.hashCanonical(body(b))
        return r
    }

    /** A copy of [log] with the verified action appended, chained to the last entry. */
    @JvmOverloads
    fun appendReceipt(log: List<Any?>, pcactn: Map<String, Any?>, allow: Boolean, checks: Map<String, Any?>? = null, at: Long? = null): List<Any?> {
        val last = if (log.isEmpty()) null else Pca.asMap(log[log.size - 1])
        val prev = last?.get("hash") as? String ?: ""
        val seq = if (last != null && last["seq"] != null) Json.asLong(last["seq"]) + 1 else 0L
        return log + listOf<Any?>(receiptFor(prev, seq, pcactn, allow, checks, at))
    }

    private fun broken(seq: Any?, has: Boolean, reason: String): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("ok" to false)
        if (has) m["brokenAt"] = seq
        m["reason"] = reason
        return m
    }

    /** Verify a receipt log is an intact hash chain: `{ok}` or `{ok: false, brokenAt, reason}` for the first broken link. */
    fun verifyReceiptChain(log: List<Any?>): Map<String, Any?> {
        var prev = ""
        for (i in log.indices) {
            val r = Pca.asMap(log[i])
            val seq = r["seq"]
            val has = r.containsKey("seq")
            val st = IntentRevocation.jsText(seq, has)
            if (!Ledger.same(seq, i.toLong())) return broken(seq, has, "seq $st out of order (expected $i)")
            if (!Ledger.same(r["prev"], prev)) return broken(seq, has, "prev link mismatch at seq $st")
            // the reference hashes strictly: a body member that is absent (undefined) throws instead of reading as null
            for (k in listOf("at", "actionDigest", "verb", "resource", "outcome")) if (!r.containsKey(k)) throw IllegalArgumentException("receipt member '$k' is undefined")
            if (!Ledger.same(Pca.hashCanonical(body(r)), r["hash"])) return broken(seq, has, "hash mismatch at seq $st (tampered body)")
            prev = r["hash"] as String
        }
        return linkedMapOf("ok" to true)
    }

    /** The head hash of a log: one value that commits to the entire history (`""` for an empty log). */
    fun receiptHead(log: List<Any?>): String = if (log.isEmpty()) "" else Pca.asMap(log[log.size - 1])["hash"] as? String ?: ""
}
