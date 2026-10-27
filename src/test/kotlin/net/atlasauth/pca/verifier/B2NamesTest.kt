package net.atlasauth.pca.verifier

import java.io.File
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.findUp
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.5 B6: the check names `counter_format` (core) and `replay` (authorize), and the limit-naming denial reasons. */
@Suppress("UNCHECKED_CAST")
class B2NamesTest {
    private val c = case("envelope-predicate-within")

    /** The re-signed negative-counter conformance vector: the first failing check is counter_format, with its reason. */
    @Test
    fun malformedCounterFailsCounterFormatWithItsReason() {
        val doc = Json.parseLenient(findUp("packages/pca/conformance/vectors.json")!!.readText(Charsets.UTF_8)) as Map<String, Any?>
        val v = (doc["vectors"] as List<Map<String, Any?>>).first { it["name"] == "invalid-counter" }
        val ctx = v["context"] as Map<String, Any?>
        val r = Pca.verifyPcactn(v["pcactn"], v["grant"] as Map<String, Any?>, Json.asLong(ctx["now"]), Pca.Audience.Of(ctx["aud"] as String))
        assertFalse(r.allow)
        assertEquals(false, r.checks["counter_format"])
        assertEquals(true, r.checks["leaf_signature"])
        assertFalse(r.checks.containsKey("counter"))
        assertEquals("counter_format: missing or not a non-negative safe integer", r.reason)
    }

    @Test
    fun coreVerifierReportsCounterFormatNotCounter() {
        val r = Pca.verifyPcactn(pcactn(c), AuthorizeTestKit.grant(c), AuthorizeTestKit.NOW, Pca.Audience.Of(AuthorizeTestKit.AUD))
        assertTrue(r.allow)
        assertEquals(true, r.checks["counter_format"])
        assertFalse(r.checks.containsKey("counter"))
    }

    @Test
    fun requiredListNamesCounterFormatAndReplay() {
        assertEquals(
            listOf("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy"),
            Authorize.DEFAULT_REQUIRED_CHECKS,
        )
    }

    @Test
    fun authorizeReportsReplayAndNeverCounter() {
        val store = Authorize.MemoryStateStore()
        val first = Authorize.authorize(pcactn(c), input(c, stateStore = store))
        assertTrue(first.allow)
        assertEquals("pass", first.checks["replay"])
        assertEquals("pass", first.checks["counter_format"])
        assertFalse(first.checks.containsKey("counter"))
        val again = Authorize.authorize(pcactn(c), input(c, stateStore = store))
        assertFalse(again.allow)
        assertEquals(listOf("replay"), again.checks.filterValues { it == "fail" }.keys.toList())
        assertTrue(again.reasons.toString(), again.reasons.contains("replay: 1 is not greater than last seen 1 (replay)"))
    }

    @Test
    fun alreadyClaimedReason() {
        val claimed = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = Authorize.ClaimResult(false, null)
        }
        val r = Authorize.authorize(pcactn(c), input(c, stateStore = claimed))
        assertTrue(r.reasons.toString(), r.reasons.contains("replay: 1 was already claimed (replay)"))
    }

    @Test
    fun requireCounterIsAnAliasOfReplay() {
        val r = Authorize.authorize(pcactn(c), input(c, require = listOf("counter")))
        assertTrue(r.reasons.toString(), r.allow)
        assertFalse(r.checks.containsKey("counter"))
    }

    /** Denial reasons of evaluatePredicates, byte-identical to the TypeScript reference (table recorded from it). */
    @Test
    fun predicateReasonTable() {
        val doc = Json.parseLenient(File("test-data/predicate-reasons.json").readText(Charsets.UTF_8)) as Map<String, Any?>
        val cases = doc["cases"] as List<Map<String, Any?>>
        assertTrue(cases.size >= 55)
        for (k in cases) {
            val action = LinkedHashMap(doc["action"] as Map<String, Any?>)
            action["params"] = k["params"]
            val ctx = linkedMapOf<String, Any?>("action" to action)
            if (k.containsKey("subject")) ctx["subject"] = k["subject"]
            if (k.containsKey("env")) ctx["env"] = k["env"]
            assertEquals(k["name"].toString(), k["reason"], Predicates.denialReason(k["predicates"], ctx))
        }
    }

    @Test
    fun allowedHasNoReason() {
        val ctx = mapOf("action" to mapOf("verb" to "pay", "resource" to "r", "params" to emptyMap<String, Any?>()))
        assertNull(Predicates.denialReason(Json.parseLenient("[{\"verb\":\"pay\"}]"), ctx))
    }
}
