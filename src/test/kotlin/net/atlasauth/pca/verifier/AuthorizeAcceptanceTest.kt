package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The reviewer acceptance at function level (this package has no HTTP middleware): a route that maps the request to an
 * operation, runs `AuthorizeOptions.run` and executes its side effect only on `allow`. The side-effect spy must never run
 * on a denial.
 */
class AuthorizeAcceptanceTest {
    private class Route(
        cases: List<Map<String, Any?>>,
        private val mapping: (Map<String, Any?>) -> Authorize.Operation?,
        var revoked: Boolean = false,
    ) {
        val executed = ArrayList<Map<String, Any?>>()
        private val grants = cases.associate { grant(it)["id"] as String to grant(it) }
        private val options = Authorize.AuthorizeOptions(stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> revoked })
        var last: Authorize.Result? = null

        /** The handler: 200 after the side effect, else the denial status. */
        fun post(pcactn: Any?, body: Map<String, Any?>): Int {
            val op = mapping(body)
            val r = options.run(pcactn, op, AUD, { grants[it] }, now = NOW)
            last = r
            if (!r.allow || !Authorize.isAuthorizedFor(r, op)) return r.status
            executed.add(body)
            return 200
        }
    }

    private fun send(body: Map<String, Any?>) = Authorize.Operation("payments.send", "payments/acme", body)
    private fun refund(body: Map<String, Any?>) = Authorize.Operation("payments.refund", "payments/acme", body)
    private val usd50 = mapOf("amount" to 50, "currency" to "usd")
    private val usd400 = mapOf("amount" to 400, "currency" to "usd")

    @Test
    fun over400Under100() {
        val over = case("envelope-max-spend-400-refused")
        val route = Route(listOf(over), ::send)
        assertEquals(403, route.post(pcactn(over), usd400))
        assertEquals("policy: caveat(s) not satisfied: max_spend", route.last!!.reason)
        assertEquals("fail", route.last!!.checks["policy"])
        val pred = case("envelope-predicate-400-refused")
        val r2 = Route(listOf(pred), ::send)
        assertEquals(403, r2.post(pcactn(pred), usd400))
        assertEquals("policy: amount <= 100 not satisfied for payments.send on payments/acme", r2.last!!.reason)
        assertTrue(route.executed.isEmpty() && r2.executed.isEmpty())
    }

    @Test
    fun signed50With400Body() {
        val within = case("envelope-max-spend-within")
        val route = Route(listOf(within), ::send)
        assertEquals(403, route.post(pcactn(within), usd400))
        assertEquals("operation: the proof's params_digest does not match the params of this payments.send operation", route.last!!.reason)
        assertTrue(route.executed.isEmpty())
    }

    @Test
    fun proofForXOnARouteExecutingY() {
        val within = case("envelope-max-spend-within")
        val route = Route(listOf(within), ::refund)
        assertEquals(403, route.post(pcactn(within), usd50))
        assertEquals(
            "operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme",
            route.last!!.reason,
        )
        assertTrue(route.executed.isEmpty())
    }

    @Test
    fun replay() {
        val within = case("envelope-max-spend-within")
        val route = Route(listOf(within), ::send)
        assertEquals(200, route.post(pcactn(within), usd50))
        assertEquals("payments.send", route.last!!.operation!!.verb)
        assertEquals(403, route.post(pcactn(within), usd50))
        assertEquals("replay: 1 is not greater than last seen 1 (replay)", route.last!!.reason)
        assertEquals(listOf(usd50), route.executed)
    }

    @Test
    fun revoked() {
        val within = case("envelope-max-spend-within")
        val route = Route(listOf(within), ::send, revoked = true)
        assertEquals(403, route.post(pcactn(within), usd50))
        assertEquals("revocation: the grant is revoked", route.last!!.reason)
        assertTrue(route.executed.isEmpty())
        route.revoked = false // a denial did not consume the counter
        assertEquals(200, route.post(pcactn(within), usd50))
    }

    @Test
    fun missingOperationMapping() {
        val within = case("envelope-max-spend-within")
        val route = Route(listOf(within), { null })
        assertEquals(403, route.post(pcactn(within), usd50))
        assertEquals("operation: authorize needs the operation to execute (verb, resource, params) (fail closed)", route.last!!.reason)
        assertTrue(route.executed.isEmpty())
    }

    @Test
    fun missingComponentsAndWrongAudience() {
        val within = case("envelope-max-spend-within")
        val r = Authorize.AuthorizeOptions(stateStore = null, isRevoked = null).run(pcactn(within), send(usd50), AUD, { grant(within) }, now = NOW)
        assertEquals(403, r.status)
        assertEquals(listOf("stateStore", "isRevoked"), r.missing)
        val wrong = case("wrong-audience")
        val route = Route(listOf(wrong), ::send)
        assertEquals(401, route.post(pcactn(wrong), mapOf("amount" to 1, "currency" to "usd")))
        assertTrue(route.executed.isEmpty())
    }

    @Test
    fun withoutAuthorizeTheCoreVerdictIsUnchanged() {
        // the default path (no authorize): Pca.verifyPcactn still answers only the structural question
        val over = case("envelope-max-spend-400-refused")
        val v = Pca.verifyPcactn(pcactn(over), grant(over), NOW, Pca.Audience.Of(AUD))
        assertTrue(v.allow)
        assertEquals(listOf("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"), v.checks.keys.toList())
    }
}
