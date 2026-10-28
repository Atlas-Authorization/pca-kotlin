package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** `Authorize.Input.freshAt` / `freshAtHeader` reach the core `fresh_at` check (the operation binding itself is not under test). */
@Suppress("UNCHECKED_CAST")
class AuthorizeFreshAtTest {
    private fun vec(name: String): Map<String, Any?> =
        ((ParityVectors.load("fresh-at-vectors.json")["vectors"] as List<Any?>).first { (it as Map<String, Any?>)["name"] == name }) as Map<String, Any?>

    private fun run(name: String, usePolicy: Boolean = true, header: String? = null): Authorize.Result {
        val v = vec(name)
        val ctx = v["context"] as Map<String, Any?>
        val grant = v["grant"] as Map<String, Any?>
        val policy = if (usePolicy) FreshAt.Policy.fromJson((ctx["fresh_at"] as Map<String, Any?>?)?.filterKeys { it != "side_carried" }) else null
        val input = Authorize.Input(
            operation = Authorize.Operation("pay", "acct/1", linkedMapOf()), audience = ctx["aud"] as String,
            resolveGrant = { grant }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false },
            now = Json.asLong(ctx["now"]), freshAt = policy, freshAtHeader = header,
        )
        return Authorize.authorize(v["pcactn"], input)
    }

    @Test fun okMember() = assertEquals("pass", run("member-equal-state").checks["fresh_at"])

    @Test fun staleEscalates() {
        val r = run("member-stale-revocation_epoch")
        assertEquals("fail", r.checks["fresh_at"])
        assertTrue(r.reasons.toString(), r.reasons.any { it.startsWith("fresh_at: escalate: stale_state") })
        assertTrue(!r.allow)
    }

    @Test fun memberWithoutPolicyIsRefused() {
        val r = run("member-without-policy", usePolicy = false)
        assertEquals("fail", r.checks["fresh_at"])
        assertTrue(!r.allow)
    }

    @Test fun sideCarriedHeader() {
        val tok = Json.canonicalize((vec("side-carried-ok")["context"] as Map<String, Any?>).let { (it["fresh_at"] as Map<String, Any?>)["side_carried"] })
        assertEquals("pass", run("side-carried-ok", header = tok).checks["fresh_at"])
        assertEquals("fail", run("side-carried-ok", header = "{not json").checks["fresh_at"])
    }
}
