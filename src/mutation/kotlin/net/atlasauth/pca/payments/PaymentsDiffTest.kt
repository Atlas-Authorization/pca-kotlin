package net.atlasauth.pca.payments

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference vectors of the payments package through the native port, plus plain tests of the stateful parts. */
@Suppress("UNCHECKED_CAST")
class PaymentsDiffTest {
    private val module = "ref-payments"

    private fun m(o: Any?) = o as Map<String, Any?>

    /** A dereference the reference performs (a null here is a TypeError there). */
    private fun req(o: Any?): Map<String, Any?> = m(o ?: throw NullPointerException())

    private fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    private fun n(o: Any?): Double = num(o) ?: throw NullPointerException("not a number")

    private fun s(o: Any?): String? = o as? String

    @Test fun isPlainId() = OracleCases.each(module, "isPlainId") { a -> Payments.isPlainId(a[0]) }
    @Test fun isMinorUnits() = OracleCases.each(module, "isMinorUnits") { a -> Payments.isMinorUnits(a[0]) }
    @Test fun mandatePredicates() = OracleCases.each(module, "mandatePredicates") { a -> Payments.mandatePredicates(m(a[0])) }
    @Test fun mandateCaveats() = OracleCases.each(module, "mandateCaveats") { a -> Payments.mandateCaveats(if (a[0] is Map<*, *>) m(a[0]) else if (a[0] == null) throw NullPointerException() else emptyMap()) }
    @Test fun mandateRiskPolicy() = OracleCases.each(module, "mandateRiskPolicy") { a -> Payments.mandateRiskPolicy(m(a[0]), a[1]) }
    @Test fun autoSpendBound() = OracleCases.each(module, "autoSpendBound") { a -> Payments.autoSpendBound(m(a[0])) }
    @Test fun buildPaymentMandate() = OracleCases.each(module, "buildPaymentMandate") { a -> Payments.buildPaymentMandate(m(a[0])) }
    @Test fun chargeActionContext() = OracleCases.each(module, "chargeActionContext") { a -> Payments.chargeActionContext(m(a[0]), m(a[1])) }
    @Test fun chargeParams() = OracleCases.each(module, "chargeParams") { a -> Payments.chargeParams(m(a[0]), m(a[1])) }
    @Test fun chargePlanNode() = OracleCases.each(module, "chargePlanNode") { a -> Payments.chargePlanNode(m(a[0]), m(a[1]), a[2] as String) }
    @Test fun chargeToPCActn() = OracleCases.each(module, "chargeToPCActn") { a -> Payments.chargeToPCActn(m(a[0]), m(a[1]), m(a[2])) }
    @Test fun chargeDecideInput() = OracleCases.each(module, "chargeDecideInput") { a -> Payments.chargeDecideInput(m(a[0]), m(a[1]), n(a[2]), a[3]) }
    @Test fun authorizeCharge() = OracleCases.each(module, "authorizeCharge") { a -> Payments.authorizeCharge(m(a[0]), m(a[1]), a[2], Payments.Decider { a[3] as Map<String, Any?>? }) }
    @Test fun settleCharge() = OracleCases.each(module, "settleCharge") { a -> Payments.settleCharge(m(a[0]), m(a[1])) }

    @Test fun applyHumanCosign() = OracleCases.each(module, "applyHumanCosign") { a ->
        val full = req(a[2])["full"]
        val fn = num(full)
        val f = full != null && full != false && full != "" && !(fn != null && (fn == 0.0 || fn.isNaN()))
        Payments.applyHumanCosign(m(a[0]), n(a[1]), f)
    }

    @Test fun sharedPaymentTokenLimits() = OracleCases.each(module, "sharedPaymentTokenLimits") { a -> Rails.sharedPaymentTokenLimits(m(a[0]), n(a[1])) }
    @Test fun railLimits() = OracleCases.each(module, "railLimits") { a -> Rails.railLimits(m(a[0]), n(a[1]), req(a[2])) }
    @Test fun categoriesFromTraits() = OracleCases.each(module, "categoriesFromTraits") { a -> Rails.categoriesFromTraits(a[0] as List<*>) }
    @Test fun reconcileSettlement() = OracleCases.each(module, "reconcileSettlement") { a -> Rails.reconcileSettlement(m(a[0]), m(a[1])) }

    @Test fun verifyStripeSignature() = OracleCases.each(module, "verifyStripeSignature") { a ->
        if (a.size < 5 || a[4] == null) Rails.verifyStripeSignature(s(a[0]), s(a[1]), s(a[2]), n(a[3]))
        else Rails.verifyStripeSignature(s(a[0]), s(a[1]), s(a[2]), n(a[3]), n(a[4]))
    }

    @Test fun signStripePayload() = OracleCases.each(module, "signStripePayload") { a -> Rails.signStripePayload(a[0] as String, a[1] as String, n(a[2]).toLong()) }

    @Test fun stripeCardParams() = OracleCases.each(module, "stripeCardParams") { a ->
        val names = LinkedHashMap<String, String>()
        for ((k, v) in m(a[1])) names[k] = v as String
        var meta: LinkedHashMap<String, String>? = null
        if (a.size > 3 && a[3] != null) {
            meta = LinkedHashMap()
            for ((k, v) in m(a[3])) meta[k] = v as String
        }
        Rails.stripeCardParams(m(a[0]), names, a[2] as String, meta)
    }

    @Test fun stripeAuthorizationFromEvent() = OracleCases.each(module, "stripeAuthorizationFromEvent") { a -> Rails.stripeAuthorizationFromEvent(a[0]) }
    @Test fun stripeSettlementFromTransaction() = OracleCases.each(module, "stripeSettlementFromTransaction") { a -> Rails.stripeSettlementFromTransaction(a[0]) }

    @Test fun stripeIssuingWebhook() = OracleCases.each(module, "stripeIssuingWebhook") { a ->
        val approved = if (a.size > 4) a[4] else null
        val o = Rails.StripeWebhookOptions(a[2] as String?) { _ -> linkedMapOf<String, Any?>("approved" to approved) }
        val now = n(a[3])
        o.nowSec = { now }
        Rails.stripeIssuingWebhook(o, a[0] as String?, s(a[1]))
    }

    @Test fun looksLikePan() = OracleCases.each(module, "looksLikePan") { a -> NetworkToken.looksLikePan(a[0] as String) }
    @Test fun tokenRefError() = OracleCases.each(module, "tokenRefError") { a -> NetworkToken.tokenRefError(a[0]) }
    @Test fun bindingMessage() = OracleCases.each(module, "bindingMessage") { a -> NetworkToken.bindingMessage(m(a[0])) }
    @Test fun bindNetworkToken() = OracleCases.each(module, "bindNetworkToken") { a -> NetworkToken.bindNetworkToken(m(a[0])) }
    @Test fun verifyNetworkTokenBinding() = OracleCases.each(module, "verifyNetworkTokenBinding") { a -> NetworkToken.verifyNetworkTokenBinding(a[0], m(a[1])) }
    @Test fun controlsFromLimits() = OracleCases.each(module, "controlsFromLimits") { a -> NetworkToken.controlsFromLimits(m(a[0]), a[1]) }
    @Test fun settlementMetadata() = OracleCases.each(module, "settlementMetadata") { a -> NetworkToken.settlementMetadata(m(a[0]), a[1] as String) }
    @Test fun reconcileNetworkSettlement() = OracleCases.each(module, "reconcileNetworkSettlement") { a -> NetworkToken.reconcileNetworkSettlement(m(a[0]), if (a[1] == null) null else m(a[1])) }
    @Test fun chargeWithNetworkToken() = OracleCases.each(module, "chargeWithNetworkToken") { a -> NetworkToken.chargeWithNetworkToken(m(a[0]), m(a[1]), m(a[2]), m(a[3])) }

    // ---- stateful parts the oracle does not cover ----

    private fun mandate(): Map<String, Any?> {
        val seed = ByteArray(32).also { it[0] = 7 }
        val aseed = ByteArray(32).also { it[0] = 9 }
        val p = linkedMapOf<String, Any?>(
            "principalSecret" to linkedMapOf<String, Any?>("\$bytes" to Keys.b64u(seed)),
            "principalPublic" to Keys.edFromSeed(seed).id(),
            "agentPublic" to Keys.edFromSeed(aseed).id(),
            "merchants" to arrayListOf<Any?>("m1"),
            "currency" to "USD",
            "perTransactionCap" to Json.Num("500"),
            "autoApproveThreshold" to Json.Num("200"),
            "cumulativeCap" to Json.Num("1000"),
            "goalSalt" to "c2FsdA",
            "now" to Json.Num("1800000000000"),
        )
        return Payments.buildPaymentMandate(p)
    }

    private fun decision(admit: Boolean, release: Boolean, budget: Any?): Map<String, Any?> = linkedMapOf(
        "releaseGuardianShare" to release,
        "requiredThreshold" to linkedMapOf<String, Any?>("t" to Json.Num("1"), "proof" to "claim", "optimisticAllowed" to true),
        "r" to Json.Num("0.1"), "admit" to admit, "needStepUp" to !admit, "reasons" to arrayListOf<Any?>(), "budget" to budget,
    )

    private fun charge(amount: Long): Map<String, Any?> =
        linkedMapOf("merchant" to "m1", "amount" to Json.Num(amount.toString()), "currency" to "USD", "now" to Json.Num("1800000001000"))

    private val autoDecider = Payments.Decider { decision(true, true, it["budget"]) }

    @Test fun atomicChargeDebitsTheDurableBudgetOnce() {
        val mand = mandate()
        val store = MemoryChargeBudgetStore()
        val d1 = Payments.authorizeChargeAtomic(mand, charge(50), mand["grant"], store, null, autoDecider)
        assertEquals("auto", d1["outcome"])
        val d2 = Payments.authorizeChargeAtomic(mand, charge(50), mand["grant"], store, null, autoDecider)
        assertEquals("auto", d2["outcome"])
        // the second decision started from the stored (debited) budget, not the mandate's initial one
        assertEquals(950.0, n(m(d2["budgetBefore"])["B"]), 0.0)
        assertEquals(900.0, n(m(d2["budgetAfter"])["B"]), 0.0)
    }

    @Test fun atomicChargeConflictDenies() {
        val mand = mandate()
        val losing = object : ChargeBudgetStore {
            override fun get(key: String): ChargeBudgetStore.Record? = null
            override fun compareAndSet(key: String, expected: Any?, budget: Map<String, Any?>): Boolean = false
        }
        val d = Payments.authorizeChargeAtomic(mand, charge(50), mand["grant"], losing, null, autoDecider)
        assertEquals("deny", d["outcome"])
        assertEquals("budget_store_conflict", (d["reasons"] as List<*>)[0])
    }

    @Test fun malformedStoreRecordThrows() {
        val mand = mandate()
        val bad = object : ChargeBudgetStore {
            override fun get(key: String): ChargeBudgetStore.Record = ChargeBudgetStore.Record(LinkedHashMap<String, Any?>(), Json.Num("1"))
            override fun compareAndSet(key: String, expected: Any?, budget: Map<String, Any?>): Boolean = true
        }
        for (store in listOf<ChargeBudgetStore?>(bad, null)) {
            try {
                Payments.authorizeChargeAtomic(mand, charge(50), mand["grant"], store, null, autoDecider)
                fail("a bad store was accepted")
            } catch (e: ChargeStoreError) {
                // expected
            }
        }
    }

    @Test fun foreignGrantIsRefused() {
        val mand = mandate()
        for ((grant, code) in listOf(LinkedHashMap<String, Any?>() to "mandate_grant_mismatch", null to "verified_grant_required")) {
            try {
                Payments.authorizeCharge(mand, charge(50), grant, Payments.Decider { null })
                fail("a foreign grant was accepted")
            } catch (e: MandateGrantError) {
                assertEquals(code, e.code)
            }
        }
    }

    @Test fun cosignIsCommittedWithCompareAndSet() {
        val mand = mandate()
        val store = MemoryChargeBudgetStore()
        val next = Payments.applyHumanCosignAtomic(mand, mand["grant"], store, 1_800_000_002_000.0, true, null)
        assertEquals(1000.0, n(next["B"]), 0.0)
        assertNotNull(store.get(Pca.hashCanonical(mand["grant"])))
    }

    @Test fun railAuthorizerDeclinesEverythingButAuto() {
        val mand = mandate()
        val o = Rails.RailAuthorizerOptions({ id -> if (id == "ic_1") Rails.InstrumentBinding(mand, mand["grant"], null) else null }, MemoryChargeBudgetStore())
        o.decider = autoDecider
        o.now = { 1_800_000_001_000L }
        val authorize = Rails.createRailAuthorizer(o)
        val a = linkedMapOf<String, Any?>("id" to "auth_1", "instrumentId" to "ic_1", "amount" to Json.Num("50"), "currency" to "usd", "merchantId" to "m1")
        assertEquals(true, authorize(a)["approved"])
        a["instrumentId"] = "nope"
        assertEquals(listOf("instrument_unknown"), authorize(a)["reasons"])
        a["instrumentId"] = "ic_1"
        a["amount"] = Json.Num("0")
        assertEquals(listOf("amount_not_positive_minor_units"), authorize(a)["reasons"])
        o.decider = Payments.Decider { throw IllegalStateException("boom") }
        a["amount"] = Json.Num("50")
        assertFalse(authorize(a)["approved"] as Boolean)
        assertEquals(listOf("authorizer_error"), authorize(a)["reasons"])
    }

    @Test fun railAuthorizerTimesOut() {
        val mand = mandate()
        val o = Rails.RailAuthorizerOptions({ _ -> Rails.InstrumentBinding(mand, mand["grant"], null) }, MemoryChargeBudgetStore())
        o.latencyBudgetMs = 50.0
        o.decider = Payments.Decider {
            try { Thread.sleep(2000) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
            decision(true, true, it["budget"])
        }
        val a = linkedMapOf<String, Any?>("id" to "auth_1", "instrumentId" to "ic_1", "amount" to Json.Num("50"), "currency" to "USD", "merchantId" to "m1")
        val v = Rails.createRailAuthorizer(o)(a)
        assertEquals(false, v["approved"])
        assertEquals(listOf("latency_budget_exceeded"), v["reasons"])
        o.latencyBudgetMs = 0.0
        try {
            Rails.createRailAuthorizer(o)
            fail("a zero latency budget was accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test fun partnerAdapterIssuesAndSuspends() {
        val paths = ArrayList<String>()
        val t = NetworkToken.PartnerTransport { path, _ ->
            paths.add(path)
            linkedMapOf<String, Any?>("token_ref" to "tok_abcdef123456")
        }
        val p = NetworkToken.visaIntelligentCommerceAdapter(t)
        assertEquals("visa_ic", p.id())
        val controls = linkedMapOf<String, Any?>(
            "currency" to "USD", "perAuthorizationMax" to Json.Num("5"), "totalMax" to Json.Num("9"),
            "categories" to arrayListOf<Any?>(), "merchants" to arrayListOf<Any?>(), "metadata" to linkedMapOf<String, Any?>(),
        )
        assertEquals("tok_abcdef123456", p.issue(controls, "agent")["token_ref"])
        p.suspend("tok a/b", "grant_revoked")
        assertEquals(listOf("/tokens", "/tokens/tok%20a%2Fb/suspend"), paths)
        assertNull(NetworkToken.tokenRefError("tok_abcdef123456"))
        assertTrue(NetworkToken.looksLikePan("4111111111111111"))
    }
}
