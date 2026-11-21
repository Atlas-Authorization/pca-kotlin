package net.atlasauth.pca.verifier

import net.atlasauth.pca.acp.Acp
import net.atlasauth.pca.ap2.Constraints
import net.atlasauth.pca.dpop.Dpop
import net.atlasauth.pca.gateway.Gateway
import net.atlasauth.pca.mcp.Mcp
import net.atlasauth.pca.oidc.Oidc
import net.atlasauth.pca.oidc.OidcVerificationError
import net.atlasauth.pca.payments.ChargeBond
import net.atlasauth.pca.payments.Rails
import net.atlasauth.pca.research.Dlp
import net.atlasauth.pca.signals.Signals
import net.atlasauth.pca.signals.SsfStream
import net.atlasauth.pca.spiffe.Spiffe
import net.atlasauth.pca.spiffe.SpiffeError
import net.atlasauth.pca.storeconformance.Reference
import net.atlasauth.pca.txntokens.TxnTokens
import net.atlasauth.pca.wallet.WalletNoise
import net.atlasauth.pca.webbotauth.WebBotAuth
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** A clock, age, spend, remaining budget or timeout that is NaN, +Infinity or -Infinity refuses (or expires, or depletes) instead of admitting. */
class InfiniteClockKillTest {
    private val inf = Double.POSITIVE_INFINITY
    private val ninf = Double.NEGATIVE_INFINITY
    private val bad = listOf(Double.NaN, inf, ninf)

    @Test fun claimStatusRefusesANonFiniteClockOrWindow() {
        assertEquals("open", Optimistic.claimStatus(100.0, 50.0, 150.0))
        // the old code returned finalized for each of these, which opens settlement
        for (n in bad) try { Optimistic.claimStatus(100.0, 50.0, n); fail("now=$n") } catch (e: IllegalArgumentException) {}
        for (w in bad) try { Optimistic.claimStatus(100.0, w, 150.0); fail("window=$w") } catch (e: IllegalArgumentException) {}
        try { Optimistic.claimStatus(inf, 50.0, 150.0); fail("issuedAt=inf") } catch (e: IllegalArgumentException) {}
    }

    @Test fun aStandingApprovalNeedsAFiniteClock() {
        val a = Approvals.approveClass(listOf("v"), 1000.0, "by", 100.0)
        assertTrue(Approvals.classApprovalCovers(a, "v", "r", 150.0))
        // NaN compared false with both bounds, so the old window test never refused it
        for (n in bad) assertFalse("now=$n", Approvals.classApprovalCovers(a, "v", "r", n))
    }

    @Test fun anInfiniteClockNeverForgetsARecordedEvent() {
        val c = WalletNoise.SlidingWindowCounter(1000.0)
        assertTrue(c.tryAdd(10.0, 5.0))
        assertEquals(1, c.count(inf)) // +Infinity used to prune every event out of the window
        assertFalse(c.tryAdd(inf, 5.0)) // and was recorded as an event itself
        assertEquals(1, c.count(20.0))
    }

    @Test fun aNaNClockIsNotAnOrderedTimeForTheSlidingWindow() {
        val c = WalletNoise.SlidingWindowCounter(1000.0)
        assertTrue(c.tryAdd(10.0, 5.0))
        try {
            c.tryAdd(Double.NaN, 5.0) // `now < last` was false for NaN, so it was recorded
            fail("expected the time-went-backwards refusal")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("time went backwards"))
        }
    }

    @Test fun theDpopReplayStoreAdmitsNothingOnANonFiniteClock() {
        for (n in bad) {
            val s = Dpop.createInMemoryDpopReplayStore()
            assertTrue(s.addIfAbsent("k", 100.0, 10.0))
            assertFalse("now=$n", s.addIfAbsent("k", 200.0, n)) // +Infinity and NaN used to read the held entry as expired
            assertFalse("fresh key, now=$n", s.addIfAbsent("other", 200.0, n))
        }
    }

    @Test fun theSetReplayStoreAdmitsNothingOnANonFiniteClock() {
        for (n in bad) {
            val s = Signals.createInMemorySetReplayStore(null)
            assertTrue(s.addIfAbsent("j", 100.0, 10.0))
            assertFalse("now=$n", s.addIfAbsent("j", 200.0, n))
            assertFalse("fresh key, now=$n", s.addIfAbsent("other", 200.0, n))
        }
    }

    @Test fun theWebBotAuthReplayCacheRefusesInfiniteInputs() {
        for (n in bad) {
            val cache = WebBotAuth.memoryReplayCache()
            assertTrue(cache.claim("n", 100.0, 10.0))
            assertFalse("now=$n", cache.claim("n", 200.0, n))
            assertFalse("expiry=$n", cache.claim("m", n, 10.0))
        }
    }

    @Test fun aStripeSignatureNeedsAFiniteClockAndTolerance() {
        val secret = "whsec_test"
        val body = "{}"
        val t = 1_700_000_000L
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val sig = mac.doFinal("$t.$body".toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        val header = "t=$t,v1=$sig"
        assertTrue(Rails.verifyStripeSignature(body, header, secret, t.toDouble()))
        assertFalse(Rails.verifyStripeSignature(body, header, secret, Double.NaN)) // abs(NaN) > tolerance was false
        assertFalse(Rails.verifyStripeSignature(body, header, secret, t.toDouble() + 10_000))
        assertFalse(Rails.verifyStripeSignature(body, header, secret, t.toDouble() + 10_000, inf)) // an infinite tolerance accepts every age
    }

    @Test fun aChallengeWindowPolicyThatIsNotANumberRefuses() {
        val p = Optimistic.ChallengeWindowPolicy(1.0, 10.0, Double.NaN)
        assertNotNull(ChargeBond.validateWindow(5.0, 5.0, 5.0, p)) // the skew comparison was false for a NaN limit
        assertFalse(Optimistic.withinChallengeWindow(0.0, 10.0, inf))
        assertFalse(Optimistic.withinChallengeWindow(0.0, 10.0, Double.NaN))
    }

    @Test fun aBudgetThatIsNotFiniteCoversNothing() {
        val infBudget = Risk.Budget(inf, 0.0)
        val ok = Risk.Budget(5.0, 0.0)
        // a +Infinity parent was never "short": the allocation passed `alloc > parent.B` as false
        assertFalse(Risk.subBudget(infBudget, 1.0).ok)
        assertFalse(Risk.debitConsolidated(infBudget, ok, 1.0).ok)
        assertFalse(Risk.debitConsolidated(ok, infBudget, 1.0).ok)
        assertFalse(Risk.debitConsolidatedPath(listOf(ok, infBudget), 1.0).ok)
        assertTrue(Risk.debitConsolidated(ok, ok, 1.0).ok)
    }

    @Test fun anUnboundedCeilingDoesNotLetAnUnmeasurableTaintThrough() {
        val policy = linkedMapOf<String, Any?>("classes" to listOf<Any?>(), "defaultMaxTaintForAuto" to inf)
        for (n in bad) {
            val r = Dlp.evaluateDlp(policy, linkedMapOf("resource" to "x", "verb" to "v", "taint" to n))
            assertNotEquals("taint=$n", "allow", r["outcome"]) // Infinity > Infinity is false, so it used to allow
        }
        assertEquals("allow", Dlp.evaluateDlp(policy, linkedMapOf("resource" to "x", "verb" to "v", "taint" to 0.5))["outcome"])
    }

    @Test fun aStepUpWithAnAttemptCountThatIsNotFiniteGivesUp() {
        val header = "Bearer error=\"insufficient_scope\", scope=\"a\""
        for (n in listOf(Double.NaN, ninf)) {
            val state = linkedMapOf<String, Any?>("attempts" to n, "requested" to listOf<Any?>())
            val r = Mcp.planStepUp(403.0, header, state)
            assertEquals("attempts=$n", "give_up", r["action"]) // NaN >= max and -Infinity >= max were false: it retried forever
        }
    }

    @Test fun anInMemoryStoreRefusesANonFiniteHorizonInsteadOfSaturatingIt() {
        val client = Reference.inMemoryAdapter().open()
        for (n in bad) {
            try {
                client.consumeOnce("k$n", n, 10.0)
                fail("expected a refusal for retainUntil=$n")
            } catch (e: IllegalArgumentException) {
                // refused
            }
            try {
                client.consumeOnce("c$n", 20.0, n)
                fail("expected a refusal for now=$n")
            } catch (e: IllegalArgumentException) {
                // refused
            }
        }
    }

    @Test fun anAmountThatIsNotFiniteIsAViolationOfTheAmountRange() {
        val range = linkedMapOf<String, Any?>("type" to "payment.amount_range", "currency" to "USD", "min" to 0, "max" to 100)
        val open = linkedMapOf<String, Any?>("constraints" to listOf<Any?>(range))
        for (n in bad) {
            val closed = linkedMapOf<String, Any?>("payment_amount" to linkedMapOf("currency" to "USD", "amount" to n))
            val v = Constraints.checkPaymentConstraints(open, closed, Constraints.PaymentCheckOptions())
            assertTrue("amount=$n", v.isNotEmpty()) // NaN compared false with both bounds
        }
        val fine = linkedMapOf<String, Any?>("payment_amount" to linkedMapOf("currency" to "USD", "amount" to 50))
        assertTrue(Constraints.checkPaymentConstraints(open, fine, Constraints.PaymentCheckOptions()).isEmpty())
    }

    @Test fun aPeriodEndThatIsNotAFiniteTimeRefusesTheSharedPaymentTokenLimits() {
        fun mandate(periodEnd: Double) = linkedMapOf<String, Any?>(
            "terms" to linkedMapOf<String, Any?>("autoApproveThreshold" to 100.0, "currency" to "USD", "periodEnd" to periodEnd),
            "budget" to linkedMapOf<String, Any?>("B" to 500.0),
        )
        assertNotNull(Rails.sharedPaymentTokenLimits(mandate(2e12), 1e12))
        for (n in bad) {
            try {
                Rails.sharedPaymentTokenLimits(mandate(n), 1e12) // +Infinity used to emit an expiry that reads as none
                fail("expected a refusal for periodEnd=$n")
            } catch (e: IllegalArgumentException) {
                assertTrue("periodEnd=$n: ${e.message}", e.message!!.contains("periodEnd must be an epoch-ms time"))
            }
        }
    }

    @Test fun aPresentSpendCapThatIsNotANonNegativeSafeIntegerRefuses() {
        val request = linkedMapOf<String, Any?>("amount" to 5.0, "currency" to "USD", "merchant" to "m")
        for (cap in listOf<Any?>(Double.NaN, inf, ninf, -1.0, -0.0, 1.5, null, "10", true)) { // a present null or non-number cap refuses as well
            val r = Acp.checkPaymentAuthority(linkedMapOf<String, Any?>("currency" to "USD", "maxAmount" to cap), request)
            assertEquals("cap=$cap", false, r["ok"])
            assertEquals("cap=$cap", "authorized spend cap is not a non-negative integer (fail closed)", r["reason"])
        }
        assertEquals(true, Acp.checkPaymentAuthority(linkedMapOf<String, Any?>("currency" to "USD", "maxAmount" to 10.0), request)["ok"])
        assertEquals(true, Acp.checkPaymentAuthority(linkedMapOf<String, Any?>("currency" to "USD"), request)["ok"]) // an absent cap is unbounded
    }

    @Test fun anUnknownRecurrenceFrequencyIsAlwaysAViolation() {
        for (f in listOf("HOURLY", "", "daily")) {
            val rec = linkedMapOf<String, Any?>("type" to "payment.agent_recurrence", "frequency" to f)
            val open = linkedMapOf<String, Any?>("constraints" to listOf<Any?>(rec))
            val closed = linkedMapOf<String, Any?>()
            // with no context the old code answered "mandate context is required", and with one but no last-used date it found nothing
            assertTrue(f, Constraints.checkPaymentConstraints(open, closed, Constraints.PaymentCheckOptions()).contains("unknown recurrence frequency"))
            val ctx = linkedMapOf<String, Any?>("totalAmount" to 0, "totalUses" to 0)
            assertTrue(f, Constraints.checkPaymentConstraints(open, closed, Constraints.PaymentCheckOptions(null, ctx, 1.0)).contains("unknown recurrence frequency"))
        }
    }

    @Test fun aChallengeStatusOnANonFiniteClockRefusesInsteadOfFinalizing() {
        for (n in bad) {
            val o = StoreBondLedger.Options()
            o.store = KvBondStore(MemoryAtomicKv())
            o.guardianKey = Keys.edFromSeed(ByteArray(32) { 7 })
            o.clock = { n }
            try {
                StoreBondLedger(o).challengeStatus("c")
                fail("expected a refusal for clock=$n")
            } catch (e: BondStoreError) {
                assertEquals("clock=$n", "clock_invalid", e.code) // a bond with no claim would otherwise say unregistered, a late clock finalized
            }
        }
    }

    @Test fun aBalanceThatIsNotFiniteRefusesTheBondMoves() {
        for (n in bad) {
            for (op in listOf("credit", "debit")) {
                try {
                    BondDoc.applyBondMoves({ n }, listOf(linkedMapOf<String, Any?>("account" to "a", "op" to op, "amount" to 1.0))) // NaN failed the overdraft compare
                    fail("expected a refusal for balance=$n $op")
                } catch (e: IllegalStateException) {
                    assertTrue(e.message!!.contains("is not finite"))
                }
            }
        }
        assertEquals(4.0, BondDoc.applyBondMoves({ 5.0 }, listOf(linkedMapOf<String, Any?>("account" to "a", "op" to "debit", "amount" to 1.0)))["a"]!!, 0.0)
    }

    @Test fun aStreamHealthClockOrTimeoutThatIsNotFiniteNeverVerifiesOrFreshens() {
        val sh = SsfStream.StreamHealth(linkedMapOf<String, Any?>(), null)
        for (n in bad) assertNull("now=$n", sh.requestVerification(n))
        val state = sh.requestVerification(100.0)!!
        for (n in bad) assertFalse("ack now=$n", sh.ackVerification(state, n)) // +Infinity used to expire the request and count a failure
        assertTrue(sh.ackVerification(state, 101.0)) // the request survived the bad clocks
        assertTrue(sh.revocationFreshWithin(300.0, 150.0))
        for (n in bad) {
            assertFalse("fresh now=$n", sh.revocationFreshWithin(300.0, n)) // -Infinity - last verified is below any bound
            assertNotEquals("report now=$n", "healthy", sh.report(n)["state"])
        }
        for (t in bad) assertNull("timeout=$t", SsfStream.StreamHealth(linkedMapOf<String, Any?>(), linkedMapOf<String, Any?>("verifyTimeoutSec" to t)).requestVerification(1.0))
    }

    @Test fun theGatewayReplayGuardRefusesAClockOrExpiryThatIsNotFinite() {
        val g = Gateway.memoryReplayGuard(10)
        assertTrue(g.claim("k", 100.0, 10.0))
        for (n in bad) {
            try {
                g.claim("a$n", n, 10.0) // a NaN expiry used to be recorded and never expire
                fail("expected a refusal for expiry=$n")
            } catch (e: IllegalStateException) {
                // refused
            }
            try {
                g.claim("b$n", 100.0, n)
                fail("expected a refusal for now=$n")
            } catch (e: IllegalStateException) {
                // refused
            }
        }
    }

    @Test fun aVerifierToleranceThatIsNotFiniteIsAConfigurationError() {
        val base = linkedMapOf<String, Any?>("issuer" to "i", "audience" to "a")
        for (n in bad) {
            try {
                Oidc.verifyIdToken("t", LinkedHashMap(base).also { it["clockToleranceSec"] = n })
                fail("expected a refusal for clockToleranceSec=$n")
            } catch (e: OidcVerificationError) {
                assertEquals("config", e.code) // the old code went on to read the token
            }
            val so = Spiffe.VerifyJwtSvidOptions()
            so.trustDomain = "example.org"
            so.audience = listOf("a")
            so.clockTolerance = n
            try {
                Spiffe.verifyJwtSvid("t", so)
                fail("expected a refusal for clockTolerance=$n")
            } catch (e: SpiffeError) {
                assertTrue(e.message!!.contains("clockTolerance must be a finite number"))
            }
            try {
                TxnTokens.fromTransactionToken("t", ByteArray(32), linkedMapOf<String, Any?>("replayCheck" to "unchecked", "audience" to "a", "clockToleranceSec" to n))
                fail("expected a refusal for clockToleranceSec=$n")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains("clockToleranceSec must be a finite number"))
            }
        }
        for (n in listOf(Double.NaN, ninf, -1.0)) {
            try {
                Oidc.verifyIdToken("t", LinkedHashMap(base).also { it["maxTokenAgeSec"] = n })
                fail("expected a refusal for maxTokenAgeSec=$n")
            } catch (e: OidcVerificationError) {
                assertEquals("config", e.code)
            }
        }
        for (n in bad) {
            try {
                TxnTokens.fromTransactionToken("t", ByteArray(32), linkedMapOf<String, Any?>("replayCheck" to "unchecked", "audience" to "a", "now" to n))
                fail("expected a refusal for now=$n")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains("now must be a number or a Date"))
            }
        }
    }

    @Test fun aRevocationAgeOnAClockThatIsNotFiniteCannotBeAged() {
        for (n in bad) {
            val r = Revocation.checkAge(1000.0, n, 1e9)
            assertFalse("now=$n", r.ok)
            assertTrue("now=$n: ${r.reason}", r.reason!!.contains("cannot be aged"))
        }
    }

    @Test fun aBudgetMaxThatIsNotAFiniteWholeNumberOfMinorUnitsIsAViolation() {
        fun check(max: Double): List<String> {
            val budget = linkedMapOf<String, Any?>("type" to "payment.budget", "currency" to "USD", "max" to max)
            val open = linkedMapOf<String, Any?>("constraints" to listOf<Any?>(budget))
            val closed = linkedMapOf<String, Any?>("payment_amount" to linkedMapOf("currency" to "USD", "amount" to 5))
            return Constraints.checkPaymentConstraints(open, closed, Constraints.PaymentCheckOptions(null, Constraints.context(0.0, 0.0), 1.0))
        }
        assertTrue(check(10.0).isEmpty())
        for (n in listOf(inf, Double.NaN)) {
            assertTrue("max=$n", check(n).contains("budget.max is not a whole number of minor units")) // Infinity - Infinity is NaN, which compared false with the tolerance
        }
    }

    private fun operationAuthorization(exp: Double): Authorize.Result {
        val pc = linkedMapOf<String, Any?>("exp" to exp, "action" to linkedMapOf<String, Any?>("reversibility_class" to "irreversible"))
        val op = Authorize.AuthorizedOperation("payments.refund", "/orders/1", Pca.paramsDigest(null), "op-exp")
        return Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = op, pcactn = pc)
    }

    @Test fun anExecutionWhoseProofExpiryIsNotAFiniteTimeIsRefusedBeforeItRuns() {
        var calls = 0
        val run = { exp: Double ->
            Operations.executeAuthorized(operationAuthorization(exp), Operations.MemoryStore(), null, { _ -> Operations.Recheck.OK }, "irreversible", null, 300_000.0, { 1000L }) { calls++; "done" }
        }
        assertEquals("committed", run(2000.0).status)
        assertEquals(1, calls)
        for (n in listOf(inf, Double.NaN)) {
            val r = run(n)
            assertEquals("exp=$n", "aborted", r.status)
            assertTrue("exp=$n: ${r.reason}", r.reason!!.contains("expired"))
        }
        assertEquals(1, calls) // the old code ran the function for an infinite or NaN expiry
    }

    @Test fun aNegativeOrNonFiniteAgeNeverSettlesAnOpenOperationRecord() {
        fun settled(startedAt: Double, olderThanMs: Double): Any? {
            val store = Operations.MemoryStore()
            store.create(linkedMapOf<String, Any?>("id" to "a", "state" to "pending", "startedAt" to startedAt))
            return Operations.recoverOperation(store, "a", olderThanMs, { 1000L })!!["state"]
        }
        assertEquals("aborted", settled(0.0, 5.0))
        assertEquals("pending", settled(0.0, -1.0)) // a negative timeout aged every record
        assertEquals("pending", settled(ninf, 5.0)) // now minus -Infinity is +Infinity, older than any timeout
        assertEquals("pending", settled(inf, 5.0))
        assertEquals("pending", settled(Double.NaN, 5.0))
        assertEquals("pending", settled(0.0, inf)) // a +Infinity timeout is the never-settle cap
    }
}
