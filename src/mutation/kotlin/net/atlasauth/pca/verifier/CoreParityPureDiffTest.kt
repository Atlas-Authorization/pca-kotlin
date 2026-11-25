package net.atlasauth.pca.verifier

import net.atlasauth.pca.dataflow.Detectors
import org.junit.Test

/** Replays the reference over the pure parity surface: hash agility, budgets, receipts, discovery, detector policy, cheap claims, obligations, layers. */
@Suppress("UNCHECKED_CAST")
class CoreParityPureDiffTest {
    private val m = "ref-core-parity-pure"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun budget(o: Any?): Risk.Budget {
        val b = map(o)!!
        return Risk.Budget(IntentJs.num(b["B"])!!, IntentJs.num(b["tau"])!!, b["asOf"]?.let { IntentJs.num(it) })
    }

    private fun budgetJson(b: Risk.Budget?): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>("B" to b!!.B, "tau" to b.tau)
        if (b.asOf != null) out["asOf"] = b.asOf
        return out
    }

    @Test fun hashCanonical() = OracleCases.each(m, "hashCanonical") { a -> Pca.hashCanonical(a[0], a[1] as String) }

    @Test fun b64uLen() = OracleCases.each(m, "b64uLen") { a -> Pca.b64uLen(IntentJs.lng(a[0]).toInt()) }

    @Test fun isHashSuite() = OracleCases.each(m, "isHashSuite") { a -> Pca.isHashSuite(a[0]) }

    @Test fun isCanonicalB64u() = OracleCases.each(m, "isCanonicalB64u") { a -> Pca.isCanonicalB64u(a[0], a[1]?.let { IntentJs.lng(it).toInt() } ?: -1) }

    @Test fun strictNumberError() = OracleCases.each(m, "strictNumberError") { a -> Pca.strictNumberError(IntentJs.num(a[0])!!) }

    @Test fun meetAll() = OracleCases.each(m, "meetAll") { a -> PcaDecision.meetAll((a[0] as List<*>).map { it as String }) }

    @Test fun isBudgetAllocCaveat() = OracleCases.each(m, "isBudgetAllocCaveat") { a -> Pca.isBudgetAllocCaveat(a[0]) }

    @Test fun subBudget() = OracleCases.each(m, "subBudget") { a ->
        val r = Risk.subBudget(budget(a[0]), IntentJs.num(a[1])!!)
        if (r.ok) linkedMapOf<String, Any?>("ok" to true, "sub" to budgetJson(r.sub)) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
    }

    @Test fun debitConsolidated() = OracleCases.each(m, "debitConsolidated") { a ->
        val r = Risk.debitConsolidated(budget(a[0]), budget(a[1]), IntentJs.num(a[2])!!)
        if (r.ok) linkedMapOf<String, Any?>("ok" to true, "parent" to budgetJson(r.parent), "sub" to budgetJson(r.sub)) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
    }

    @Test fun debitConsolidatedPath() = OracleCases.each(m, "debitConsolidatedPath") { a ->
        val r = Risk.debitConsolidatedPath((a[0] as List<*>).map { budget(it) }, IntentJs.num(a[1])!!)
        if (r.ok) linkedMapOf<String, Any?>("ok" to true, "nodes" to r.nodes!!.map { budgetJson(it) }) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
    }

    @Test fun recharge() = OracleCases.each(m, "recharge") { a -> budgetJson(Risk.recharge(budget(a[0]), IntentJs.num(a[1])!!, IntentJs.num(a[2])!!, IntentJs.num(a[3])!!)) }

    @Test fun rechargeFull() = OracleCases.each(m, "rechargeFull") { a -> budgetJson(Risk.rechargeFull(budget(a[0]), IntentJs.num(a[1])!!, IntentJs.num(a[2])!!)) }

    private fun allow(v: Any?) = map(v)!!["allow"] == true

    private fun checks(v: Any?) = map(map(v)!!["checks"])

    @Test fun receiptFor() = OracleCases.each(m, "receiptFor") { a ->
        Receipts.receiptFor(a[0] as String, IntentJs.lng(a[1]), map(a[2])!!, allow(a[3]), checks(a[3]), a[4]?.let { IntentJs.lng(it) })
    }

    @Test fun appendReceipt() = OracleCases.each(m, "appendReceipt") { a ->
        Receipts.appendReceipt(a[0] as List<Any?>, map(a[1])!!, allow(a[2]), checks(a[2]), a[3]?.let { IntentJs.lng(it) })
    }

    @Test fun verifyReceiptChain() = OracleCases.each(m, "verifyReceiptChain") { a -> Receipts.verifyReceiptChain(a[0] as List<Any?>) }

    @Test fun receiptHead() = OracleCases.each(m, "receiptHead") { a -> Receipts.receiptHead(a[0] as List<Any?>) }

    @Test fun parseDiscoveryDocument() = OracleCases.each(m, "parseDiscoveryDocument") { a -> Discovery.parseDiscoveryDocument(a[0]) }

    @Test fun parseDiscoveryIntent() = OracleCases.each(m, "parseDiscoveryIntent") { a -> Discovery.parseDiscoveryIntent(a[0]) }

    @Test fun acceptsSuite() = OracleCases.each(m, "acceptsSuite") { a -> Discovery.acceptsSuite(map(a[0])!!, a[1] as String) }

    @Test fun detectorPolicyError() = OracleCases.each(m, "detectorPolicyError") { a -> Detectors.detectorPolicyError(a[0]) }

    @Test fun detectorReceiptShapeError() = OracleCases.each(m, "detectorReceiptShapeError") { a -> Detectors.detectorReceiptShapeError(a[0]) }

    @Test fun pcactnCheapClaims() = OracleCases.each(m, "pcactnCheapClaims") { a ->
        val f = Pca.pcactnCheapClaims(map(a[0])!!, a[1] as String, IntentJs.num(a[2])!!)
        if (f == null) null else linkedMapOf<String, Any?>("check" to f.check, "reason" to f.reason)
    }

    @Test fun resolveReversibilityClass() = OracleCases.each(m, "resolveReversibilityClass") { a -> Decide.resolveReversibilityClass(a[0], a[1] as? List<*>, a[2]) }

    @Test fun agentCaveatContext() = OracleCases.each(m, "agentCaveatContext") { a -> Decide.agentCaveatContext(map(a[0])!!, a[1]) }

    @Test fun enforceRequired() = OracleCases.each(m, "enforceRequired") { a ->
        val v = map(a[0])!!
        val r = Authorize.enforceRequired(
            v["allow"] == true, (map(v["checks"])!!).mapValues { it.value as String }, (v["reasons"] as List<*>).map { it as String }, (a[1] as List<*>).map { it as String },
        )
        linkedMapOf<String, Any?>("allow" to r.allow, "checks" to r.checks, "reasons" to r.reasons)
    }

    @Test fun collectObligations() = OracleCases.each(m, "collectObligations") { a ->
        val r = Obligations.collectObligations(a[0], map(a[1]))
        if (r.ok) linkedMapOf<String, Any?>("ok" to true, "obligations" to r.obligations) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
    }

    @Test fun decideLayers() = OracleCases.each(m, "decideLayers") { a ->
        val d = LayerDecide.decideLayers(a[0], map(a[1]))
        val out = linkedMapOf<String, Any?>("decision" to d.decision)
        if (d.by != null) out["by"] = d.by
        if (d.layer != null) out["layer"] = d.layer
        out
    }

    @Test fun decideLayerCeilings() = OracleCases.each(m, "decideLayerCeilings") { a ->
        val r = LayerDecide.decideLayerCeilings(a[0], map(a[1]))
        if (r.pass) linkedMapOf<String, Any?>("status" to "pass") else linkedMapOf<String, Any?>("status" to "fail", "layer" to r.layer, "reason" to r.reason)
    }
}
