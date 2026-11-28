package net.atlasauth.pca.verifier

import org.junit.Test

/**
 * Differential test of bond settlement against the TypeScript reference: the slash split and money arithmetic, bond sizing, evidence
 * digests, settlement records, claim / fraud-proof / dispute verdicts, and scripted op sequences over a [StoreBondLedger] on a memory store.
 */
@Suppress("UNCHECKED_CAST")
class CoreBondSettlementDiffTest {
    private val module = "ref-core-bond-settlement-java"

    private fun m(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun d(o: Any?): Double = IntentJs.num(o) ?: throw IllegalArgumentException("not a number")
    private fun dOrNull(o: Any?): Double? = IntentJs.num(o)

    private fun codeOf(t: Throwable): String = if (t is BondStoreError) t.code else if (t is IllegalArgumentException) "RangeError" else "Error"

    @Test fun computeSlashSplit() = OracleCases.each(module, "computeSlashSplit") { a -> BondSettlement.computeSlashSplit(d(a[0]), m(a[1]), m(a[2])!!).toJson() }

    @Test fun quantizeUp() = OracleCases.each(module, "quantizeUp") { a -> BondSettlement.quantizeUp(d(a[0])) }

    @Test fun toMicros() = OracleCases.each(module, "toMicros") { a ->
        val v = BondSettlement.toMicros(d(a[0]))
        if (v == null) null else linkedMapOf<String, Any?>("\$bigint" to v.toString())
    }

    @Test fun exactAdd() = OracleCases.each(module, "exactAdd") { a -> BondSettlement.exactAdd(d(a[0]), d(a[1]), d(a[2]).toInt()) }

    @Test fun applyBondMoves() = OracleCases.each(module, "applyBondMoves") { a ->
        val bal = m(a[0])!!
        LinkedHashMap<String, Any?>(BondDoc.applyBondMoves({ acct -> if (bal.containsKey(acct)) (IntentJs.num(bal[acct]) ?: 0.0) else 0.0 }, l(a[1])))
    }

    @Test fun bondAmount() = OracleCases.each(module, "bondAmount") { a -> BondSettlement.bondAmount(m(a[0])!!, d(a[1])) }

    @Test fun evidenceDigests() {
        OracleCases.each(module, "settlementEvidenceDigest") { a -> BondSettlement.settlementEvidenceDigest(m(a[0])!!, m(a[1])!!) }
        OracleCases.each(module, "revocationEvidenceDigest") { a -> BondSettlement.revocationEvidenceDigest(m(a[0])!!, a[1] as String) }
        OracleCases.each(module, "disputeEvidenceDigest") { a -> BondSettlement.disputeEvidenceDigest(m(a[0])!!, m(a[1])!!) }
    }

    @Test fun records() {
        OracleCases.each(module, "verifySettlement") { a -> BondSettlement.verifySettlement(a[0], a[1] as String, m(a[2])) }
        OracleCases.each(module, "settlementRecordDigest") { a -> BondSettlement.settlementRecordDigest(m(a[0])!!) }
        OracleCases.each(module, "settlementCommit") { a -> BondSettlement.settlementCommit(a[0] as String, m(a[1])!!) }
        OracleCases.each(module, "verifySettlementCommit") { a -> BondSettlement.verifySettlementCommit(a[0] as? String, a[1] as String, m(a[2])!!) }
    }

    private fun policyOf(o: Any?): Optimistic.ChallengeWindowPolicy? {
        val p = m(o) ?: return null
        return Optimistic.ChallengeWindowPolicy(d(p["minWindowMs"]), d(p["maxWindowMs"]), d(p["maxSkewMs"]))
    }

    @Test fun verifyClaim() = OracleCases.each(module, "verifyClaim") { a -> OptimisticAdjudication.verifyClaim(a[0], m(a[1]), a[2] as String, d(a[3]), policyOf(a[4])) }

    @Test fun verifyFraudProof() = OracleCases.each(module, "verifyFraudProof") { a -> OptimisticAdjudication.verifyFraudProof(m(a[0])!!, a[1], m(a[2]), a[3]) }

    private fun oracleOf(table: Any?): OptimisticAdjudication.ObjectiveOracle? {
        val t = m(table) ?: return null
        return OptimisticAdjudication.ObjectiveOracle { input, _ -> m(t[input]) }
    }

    @Test fun adjudicateDispute() = OracleCases.each(module, "adjudicateDispute") { a ->
        OptimisticAdjudication.adjudicateDispute(m(a[0])!!, a[1], m(a[2]), a[3], oracleOf(a[4]), dOrNull(a[5]))
    }

    // ---- scripted ledger sequences ----

    /** Replaces every "@name" string by a copy of the fixture (an unknown name is an absent value). */
    private fun resolve(fx: Map<String, Any?>, v: Any?): Any? = when {
        v is String && v.startsWith("@") -> StoreJs.deepCopy(fx[v.substring(1)])
        v is List<*> -> v.map { resolve(fx, it) }
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in m(v)!!) out[k] = resolve(fx, x) }
        else -> v
    }

    private fun params(fx: Map<String, Any?>, raw: Any?): Map<String, Any?> {
        val q = m(resolve(fx, raw)) as MutableMap<String, Any?>
        if (q.containsKey("oracleTable")) {
            val table = q.remove("oracleTable")
            q["oracle"] = oracleOf(table)
        }
        return q
    }

    private fun run(args: List<Any?>): List<Any?> {
        val fx = m(args[0])!!
        val cfg = m(args[1])!!
        val kv = MemoryAtomicKv()
        var clock = net.atlasauth.pca.verifier.BaseOracle.T0.toDouble()
        val o = StoreBondLedger.Options()
        o.store = KvBondStore(kv)
        o.guardianKey = Keys.edFromSeed(OracleCases.seed("bond/guardian"))
        o.clock = { clock }
        if (cfg.containsKey("epoch")) o.guardianEpoch = d(cfg["epoch"]).toLong()
        if (cfg.containsKey("escrow")) o.escrowAccount = cfg["escrow"] as String
        if (cfg.containsKey("bondPolicy")) o.bondPolicy = m(cfg["bondPolicy"])
        if (cfg.containsKey("splitPolicy")) o.slashSplitPolicy = m(cfg["splitPolicy"])
        if (cfg.containsKey("windowMs")) {
            val w = m(cfg["windowMs"])!!
            o.windowPolicy = Optimistic.ChallengeWindowPolicy(d(w["min"]), d(w["max"]), d(w["skew"]))
        }
        val ledger = StoreBondLedger(o)
        val out = ArrayList<Any?>()
        for (oo in l(args[2])) {
            val op = l(oo)
            try {
                val v: Any? = when (op[0] as String) {
                    "clock" -> { clock = dOrNull(op[1]) ?: Double.NaN; null }
                    "deposit" -> ledger.deposit(op[1] as String, d(op[2]))
                    "balance" -> ledger.balanceOf(op[1] as String)
                    "status" -> ledger.bondStatus(op[1] as String)
                    "bond" -> ledger.getBond(op[1] as String)
                    "challenge" -> ledger.challengeStatus(op[1] as String)
                    "pub" -> ledger.guardianPublicKey()
                    "openClaim" -> {
                        val p = params(fx, op[1])
                        ledger.openClaim(m(p["claim"]), m(p["pcactn"]), p["signerPublic"] as String, d(p["amount"]), p["depositor"] as String, dOrNull(p["exposure"]))
                    }
                    "openBond" -> {
                        val p = params(fx, op[1])
                        ledger.openBond(p["claimId"] as String, d(p["amount"]), p["depositor"] as String, dOrNull(p["exposure"]))
                    }
                    "release" -> ledger.release(op[1] as String)
                    "releaseUnreg" -> ledger.releaseUnregistered(op[1] as String)
                    "slash" -> ledger.slashBond(params(fx, op[1]))
                    "slashDispute" -> ledger.slashBondOnDispute(params(fx, op[1]))
                    "slashRevoke" -> ledger.slashBondOnRevocation(params(fx, op[1]))
                    "slashCounter" -> ledger.slashCounterBond(params(fx, op[1]))
                    "kvSet" -> { kv.set(KvBondStore.DOC_KEY, StoreJs.deepCopy(op[1])); null }
                    "kvGet" -> StoreJs.deepCopy(kv.get(KvBondStore.DOC_KEY))
                    else -> throw IllegalStateException("op")
                }
                out.add(v)
            } catch (t: Throwable) {
                out.add(linkedMapOf<String, Any?>("\$err" to codeOf(t)))
            }
        }
        return out
    }

    @Test fun ledger() = OracleCases.each(module, "ledger") { a -> run(a) }
}
