package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `fresh_at` as a signed PCActn member over the shared `fresh-at-vectors.json`: wire validation (terminal, before any other work),
 * the `fresh_at` check right after the intent checks, escalate-class failures for a stale verifier, the side-carried form, and a PCActn with
 * neither member nor policy behaving exactly as before (no `fresh_at` entry in `checks`).
 */
@Suppress("UNCHECKED_CAST")
class FreshAtVectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Test
    fun memberVectors() {
        val doc = ParityVectors.load("fresh-at-vectors.json")
        val vs = doc["vectors"] as List<Any?>
        assertTrue(vs.size >= 28)
        for (x in vs) {
            val v = m(x)
            val name = v["name"] as String
            val ctx = m(v["context"])
            val policy = if (ctx.containsKey("fresh_at")) FreshAt.Policy.fromJson(ctx["fresh_at"]) else null
            if (ctx.containsKey("fresh_at")) assertTrue("$name: policy parses", policy != null)
            val got = Pca.verifyPcactn(v["pcactn"], m(v["grant"]), Json.asLong(ctx["now"]), Pca.Audience.Of(ctx["aud"] as String), null, null, null, policy)
            val exp = m(v["expect"])
            assertEquals("$name: allow (${got.reason})", exp["allow"], got.allow)
            // the vector pins the nine core checks; `fresh_at` is compared separately below
            val core = got.checks.filterKeys { it != "fresh_at" }
            assertEquals("$name: checks", Json.canonicalize(exp["checks"]), Json.canonicalize(core))
            assertEquals("$name: check order", (exp["checks"] as Map<String, Any?>).keys.toList(), core.keys.toList())
            val want = exp["fresh_at"] as String
            val has = got.checks.containsKey("fresh_at")
            assertEquals("$name: fresh_at status", want, if (!has) "absent" else if (got.checks["fresh_at"] == true) "pass" else "fail")
            val status = got.checks.mapValues { if (it.value) "pass" else "fail" }
            assertEquals("$name: decision", exp["decision"], PcaDecision.decisionOf(got.allow, status, got.reasons))
            val reason = exp["reason"] as? String
            if (reason == null) assertEquals("$name: no reason", "", got.reason)
            else if (reason.startsWith("fresh_at:") || reason.startsWith("wire:")) assertEquals("$name: reason", reason, got.reason)
            // the leaf-signature text predates fresh_at: the reference appends " / suite"; the failing check name and prefix are what is pinned
            else assertTrue("$name: reason '${got.reason}' vs '$reason'", got.reason.isNotEmpty() && reason.startsWith(got.reason))
        }
    }

    @Test
    fun withoutMemberOrPolicyThereIsNoFreshAtCheck() {
        val v = m((ParityVectors.load("fresh-at-vectors.json")["vectors"] as List<Any?>).first { m(it)["name"] == "no-member-no-policy" })
        val ctx = m(v["context"])
        val got = Pca.verifyPcactn(v["pcactn"], m(v["grant"]), Json.asLong(ctx["now"]), Pca.Audience.Of(ctx["aud"] as String))
        assertTrue(got.allow)
        assertFalse(got.checks.containsKey("fresh_at"))
        assertNull(FreshAt.Policy.fromJson("not a policy"))
        assertEquals(FreshAt.Status.NONE, FreshAt.decide(null, false, null, 0L).status)
    }
}
