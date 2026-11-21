package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.BondSettlement
import net.atlasauth.pca.verifier.StoreJs

/**
 * Reputation from verifiable records: disputes are derived ONLY from guardian-signed settlement records (open, release, slash). A record
 * whose signature does not verify (or whose claim has no known subject) is counted in `rejected`, never as a dispute.
 */
@Suppress("UNCHECKED_CAST")
object ReputationEvidence {
    /**
     * `{disputes: [{id, subject, slashed, at, amount}], rejected}`. [subjectOf] maps a bond or claim handle to the subject it was posted for
     * (null = unknown, and the record is rejected); [pin] is the post-quantum pin policy for hybrid records (may be null).
     */
    @JvmStatic
    @JvmOverloads
    fun disputesFromSettlements(records: List<Any?>, guardianPublicKey: String, subjectOf: (String) -> String?, pin: Map<String, Any?>? = null): Map<String, Any?> {
        val disputes = ArrayList<Any?>()
        var rejected = 0L
        for (ro in records) {
            val r = ro as? Map<String, Any?>
            val subject = if (r != null && r["claimId"] is String) subjectOf(r["claimId"] as String) else null
            if (r == null || subject == null || !BondSettlement.verifySettlement(ro, guardianPublicKey, pin)) { rejected++; continue }
            if (r["action"] == "open") continue // an open bond is not an outcome
            val d = LinkedHashMap<String, Any?>()
            d["id"] = BondSettlement.settlementRecordDigest(r)
            d["subject"] = subject
            d["slashed"] = r["action"] == "slash"
            if (r.containsKey("at")) d["at"] = r["at"]
            if (r.containsKey("amount")) d["amount"] = r["amount"]
            disputes.add(d)
        }
        return linkedMapOf("disputes" to disputes, "rejected" to StoreJs.num(rejected))
    }
}
