package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the reference over reputation and underwriting, the frontier signals, the autonomy forecast and the multi-agent budget algebra. */
@Suppress("UNCHECKED_CAST")
class CoreSweepReputationDiffTest {
    private val mod = "ref-core-sweep-java"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun mapOrNull(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("not an array")

    private fun num(o: Any?): Double = IntentJs.num(o) ?: throw IllegalArgumentException("not a number")

    private fun numOrNull(o: Any?): Double? = IntentJs.num(o)

    @Test fun reputationAndPricing() {
        OracleCases.each(mod, "reputation") { a -> Reputation.reputation(a[0]) }
        OracleCases.each(mod, "priceCoverage") { a -> Reputation.priceCoverage(a[0], num(a[1]), mapOrNull(a[2])) }
    }

    @Test fun quotes() {
        val uw = Keys.edFromSeed(OracleCases.seed("sweep/underwriter"))
        OracleCases.each(mod, "issueCoverageQuote") { a -> Reputation.issueCoverageQuote(map(a[0]), num(a[1]), uw, num(a[2]), num(a[3]), mapOrNull(a[4])) }
        OracleCases.each(mod, "verifyCoverageQuote") { a ->
            val u = if (a[1] == "@u") uw.id() else a[1]
            Reputation.verifyCoverageQuote(a[0], u, numOrNull(a[2]) ?: Double.NaN)
        }
    }

    @Test fun pool() = OracleCases.each(mod, "pool") { a ->
        var pool: InsuranceCapitalPool? = null
        val out = ArrayList<Any?>()
        for (oo in a[0] as List<*>) {
            val op = oo as List<*>
            try {
                var v: Any? = null
                when (op[0] as String) {
                    "new" -> { pool = InsuranceCapitalPool(num(op[1])); v = pool.state() }
                    "quote" -> v = Reputation.priceCoverage(map(op[1]), num(op[2]), mapOrNull(op[3]))
                    "collect" -> v = pool!!.collectPremium(Reputation.priceCoverage(map(op[1]), num(op[2]), mapOrNull(op[3])))
                    "canCover" -> v = pool!!.canCover(num(op[1]))
                    "pay" -> v = pool!!.payClaim(num(op[1]))
                    "state" -> v = pool!!.state()
                    else -> throw IllegalStateException("op")
                }
                out.add(v)
            } catch (t: Throwable) {
                out.add(linkedMapOf<String, Any?>("\$err" to "Error"))
            }
        }
        out
    }

    @Test fun frontierSignals() {
        OracleCases.each(mod, "semanticSignal") { a -> FrontierSignals.semanticSignal(a[0]) }
        OracleCases.each(mod, "progressSignal") { a -> FrontierSignals.progressSignal(a[0]) }
        OracleCases.each(mod, "objectiveSignal") { a -> FrontierSignals.objectiveSignal(a[0]) }
        OracleCases.each(mod, "tightenRiskInputs") { a -> FrontierSignals.tightenRiskInputs(map(a[0]), map(a[1])) }
    }

    @Test fun budgetForecast() {
        OracleCases.each(mod, "recommendPolicy") { a -> BudgetForecast.recommendPolicy(num(a[0]), num(a[1]), numOrNull(a[2])) }
        OracleCases.each(mod, "autonomyBoundOf") { a -> BudgetForecast.autonomyBoundOf(map(a[0])) }
    }

    @Test fun budgetAlgebra() {
        OracleCases.each(mod, "subBudget") { a -> RiskBudgets.subBudget(map(a[0]), num(a[1])) }
        OracleCases.each(mod, "debitConsolidated") { a -> RiskBudgets.debitConsolidated(map(a[0]), map(a[1]), num(a[2])) }
        OracleCases.each(mod, "debitConsolidatedPath") { a -> RiskBudgets.debitConsolidatedPath(list(a[0]), num(a[1])) }
        OracleCases.each(mod, "rechargeFull") { a -> RiskBudgets.rechargeFull(num(a[0]), num(a[1])) }
    }

    @Test fun approvals() {
        OracleCases.each(mod, "approveClass") { a -> Approvals.approveClass(list(a[0]).map { it as String }, num(a[1]), a[2] as String, num(a[3]), a[4] as String?) }
        OracleCases.each(mod, "classApprovalCovers") { a -> Approvals.classApprovalCovers(map(a[0]), a[1] as String, a[2] as String, num(a[3])) }
        OracleCases.each(mod, "coveredByAny") { a -> Approvals.coveredByAny(list(a[0]), a[1] as String, a[2] as String, num(a[3])) }
        OracleCases.each(mod, "recordDecision") { a -> Approvals.recordDecision(map(a[0]), a[1] as String, a[2] as String, num(a[3])) }
        OracleCases.each(mod, "pendingRequests") { a -> Approvals.pendingRequests(list(a[0])) }
        OracleCases.each(mod, "applyCosign") { a -> Approvals.applyCosign(map(a[0]), map(a[1]), num(a[2]), a[3] == true) }
    }

    private fun checksOf(v: Any?): Map<String, Any?>? = mapOrNull(v)?.let { mapOrNull(it["checks"]) }

    private fun allowOf(v: Any?): Boolean = map(v)["allow"] == true

    @Test fun receipts() {
        OracleCases.each(mod, "receiptFor") { a -> Receipts.receiptFor(a[0] as String, num(a[1]).toLong(), map(a[2]), allowOf(a[3]), checksOf(a[3]), numOrNull(a[4])?.toLong()) }
        OracleCases.each(mod, "receiptChain") { a ->
            var log: List<Any?> = ArrayList()
            val out = ArrayList<Any?>()
            for (oo in a[0] as List<*>) {
                val op = oo as List<*>
                try {
                    var v: Any? = null
                    when (op[0] as String) {
                        "append" -> { log = Receipts.appendReceipt(log, map(op[1]), allowOf(op[2]), checksOf(op[2]), numOrNull(op[3])?.toLong()); v = log[log.size - 1] }
                        "head" -> v = Receipts.receiptHead(log)
                        "verify" -> v = Receipts.verifyReceiptChain(log)
                        "set" -> log = list(StoreJs.deepCopy(op[1]))
                        "tamper" -> {
                            log = list(StoreJs.deepCopy(log))
                            val r = log[num(op[1]).toInt()] as MutableMap<String, Any?>
                            if (op[3] == "\$del") r.remove(op[2] as String) else r[op[2] as String] = op[3]
                        }
                        "swap" -> {
                            val l = ArrayList(list(StoreJs.deepCopy(log)))
                            val i = num(op[1]).toInt()
                            val j = num(op[2]).toInt()
                            val t = l[i]; l[i] = l[j]; l[j] = t
                            log = l
                        }
                        "drop" -> log = ArrayList(log).also { it.removeAt(num(op[1]).toInt()) }
                        "truncate" -> log = ArrayList(log.subList(0, num(op[1]).toInt()))
                        else -> throw IllegalStateException("op")
                    }
                    out.add(v)
                } catch (t: Throwable) {
                    out.add(linkedMapOf<String, Any?>("\$err" to "Error"))
                }
            }
            out
        }
    }

    /** The two sweep tests together replay every fn of the corpus and every case of it. */
    @Test fun theWholeSweepCorpusIsReplayed() {
        val fns = setOf(
            "hopsRoot", "compactChain", "hopLeaf", "compactChainShapeError", "chainMemo", // CoreSweepChainDiffTest
            "reputation", "priceCoverage", "issueCoverageQuote", "verifyCoverageQuote", "pool", "semanticSignal", "progressSignal", "objectiveSignal", "tightenRiskInputs",
            "recommendPolicy", "autonomyBoundOf", "subBudget", "debitConsolidated", "debitConsolidatedPath", "rechargeFull", "approveClass", "classApprovalCovers",
            "coveredByAny", "recordDecision", "pendingRequests", "applyCosign", "receiptFor", "receiptChain",
        )
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(2167, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
