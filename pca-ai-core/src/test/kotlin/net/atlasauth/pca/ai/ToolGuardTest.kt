package net.atlasauth.pca.ai

import net.atlasauth.pca.verifier.Agent
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.Keys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ToolGuardTest {
    /** A fake prover: records calls, refuses verbs listed in [deny]. */
    class Fake : Prover {
        val proved = ArrayList<String>()
        val recorded = ArrayList<String>()
        val deny = ArrayList<String>()
        override fun prove(verb: String, resource: String, params: Map<String, Any?>): Proof {
            if (verb in deny) throw PcaDenied("denied by policy", verb, resource)
            proved.add("$verb@$resource")
            return Proof(LinkedHashMap(), "enc-$verb", mapOf("PCA-Action" to "enc-$verb"))
        }
        override fun tool(name: String, output: Any?) { recorded.add("$name=$output") }
    }

    private val map = ToolGuard.ToolMapping { name, args -> if (name == "refund") ToolGuard.Action("stripe.refund", "charge:" + args["id"]) else null }

    @Test fun runsTheBodyUnderTheProofAndRecordsTheResult() {
        val f = Fake()
        val out = ToolGuard.runJson(f, map, "refund", "{\"id\":\"c1\"}") { _, p -> "ok:" + p.encoded }
        assertEquals("ok:enc-stripe.refund", out)
        assertEquals(listOf("stripe.refund@charge:c1"), f.proved)
        assertEquals(listOf("refund=ok:enc-stripe.refund"), f.recorded)
    }

    @Test fun anUnmappedToolIsRefusedAndNeverRuns() {
        var ran = 0
        assertThrows(PcaDenied::class.java) { ToolGuard.runJson(Fake(), map, "drop_tables", "{}") { _, _ -> ran++; "x" } }
        assertEquals(0, ran)
    }

    @Test fun aDeniedProofNeverRunsTheTool() {
        val f = Fake()
        f.deny.add("stripe.refund")
        var ran = 0
        val d = assertThrows(PcaDenied::class.java) { ToolGuard.runJson(f, map, "refund", "{\"id\":\"c1\"}") { _, _ -> ran++; "x" } }
        assertEquals("stripe.refund", d.verb)
        assertEquals(0, ran)
        assertTrue(f.recorded.isEmpty())
    }

    @Test fun aProverThatCrashesIsARefusal() {
        val boom = Prover { _, _, _ -> throw IllegalStateException("kaput") }
        assertThrows(PcaDenied::class.java) { ToolGuard.runJson(boom, map, "refund", "{\"id\":\"c1\"}") { _, _ -> "x" } }
    }

    @Test fun argumentsMustBeAJsonObject() {
        assertEquals(0, ToolGuard.parseArguments("  ").size)
        assertEquals(0, ToolGuard.parseArguments(null).size)
        assertThrows(PcaDenied::class.java) { ToolGuard.parseArguments("[1]") }
        assertThrows(PcaDenied::class.java) { ToolGuard.parseArguments("{nope") }
        assertThrows(PcaDenied::class.java) { ToolGuard.parseArguments("\"s\"") }
    }

    @Test fun aNullResultCarriesTheProof() {
        val p = Proof(LinkedHashMap(), "E", emptyMap())
        assertEquals("{\"pca\":\"E\"}", ToolGuard.content(null, p))
        assertEquals("{\"a\":1}", ToolGuard.content(mapOf("a" to 1L), p))
    }

    @Test fun theFacadeProverSignsInPolicyAndRefusesOutOfPolicy() {
        val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
        val holder = ByteArray(32).also { it[0] = 1 }
        val h = Agent.fromPrincipal(
            Facade.AgentOptions(principal, "refund order 1", mapOf("stripe" to listOf("refund")), holder = Keys.ed25519(Keys.edFromSeed(holder)), aud = "rs", now = System.currentTimeMillis()),
        )
        val p = Prover.of(h)
        val ok = p.prove("stripe.refund", "charge:ch_1", linkedMapOf("amount" to 5L))
        assertNotNull(ok.encoded)
        assertTrue(ok.headers.containsKey("PCA-Action"))
        assertThrows(PcaDenied::class.java) { p.prove("stripe.charge", "charge:ch_1", LinkedHashMap()) }
    }
}

class GuardedToolTest {
    private class Echo(var ran: Int = 0) : Tool<String> {
        override val metadata = ToolMetadata("refund", "refund a charge", mapOf("type" to "object"))
        override fun call(input: Map<String, Any?>): String { ran++; return "refunded " + input["id"] }
    }

    private val spec get() = GuardToolSpec("stripe.refund", resource = { a -> "charge:" + a["id"] }) // a trailing lambda would bind to onProof

    @Test fun runsTheToolUnderTheProofAndKeepsItsMetadata() {
        val f = ToolGuardTest.Fake()
        val seen = ArrayList<String>()
        val inner = Echo()
        val t = GuardedTool(inner, f, GuardToolSpec("stripe.refund", { a -> "charge:" + a["id"] }, { p, _ -> seen.add(p.encoded) }))
        assertEquals(inner.metadata, t.metadata)
        assertEquals("refunded c1", t.call(mapOf("id" to "c1")))
        assertEquals(listOf("stripe.refund@charge:c1"), f.proved)
        assertEquals(listOf("enc-stripe.refund"), seen)
        assertEquals(listOf("refund=refunded c1"), f.recorded)
    }

    @Test fun aDeniedProofNeverRunsTheTool() {
        val f = ToolGuardTest.Fake()
        f.deny.add("stripe.refund")
        val inner = Echo()
        assertThrows(PcaDenied::class.java) { GuardedTool(inner, f, spec).call(mapOf("id" to "c1")) }
        assertEquals(0, inner.ran)
    }

    @Test fun anUnmappedToolInAListIsRefused() {
        val inner = Echo()
        val t = GuardedTool.wrapAll(listOf<Tool<String>>(inner), ToolGuardTest.Fake(), emptyMap())[0]
        assertThrows(PcaDenied::class.java) { t.call(emptyMap()) }
        assertEquals(0, inner.ran)
    }
}

class AnthropicPcaTest {
    private val map = ToolGuard.ToolMapping { name, args -> if (name == "refund") ToolGuard.Action("stripe.refund", "charge:" + args["id"]) else null }
    private val handlers = mapOf<String, ToolGuard.Body<Any?>>(
        "refund" to ToolGuard.Body { a, p -> mapOf("refunded" to a["id"], "proof" to p.encoded) },
        "boom" to ToolGuard.Body { _, _ -> throw IllegalStateException("downstream failed") },
    )

    private fun use(name: String, id: String = "tu_1", input: Map<String, Any?> = mapOf("id" to "c1")): Map<String, Any?> =
        mapOf("type" to "tool_use", "id" to id, "name" to name, "input" to input)

    @Test fun aMappedToolRunsUnderTheProofAndRecordsItsResult() {
        val f = ToolGuardTest.Fake()
        val r = AnthropicPca.handleToolUse(f, use("refund"), map, handlers)
        assertEquals("tool_result", r["type"])
        assertEquals("tu_1", r["tool_use_id"])
        assertTrue((r["content"] as String).contains("enc-stripe.refund"))
        assertTrue(r["is_error"] == null)
        assertEquals(1, f.recorded.size)
    }

    @Test fun refusalsAreErrorShapedResultsAndTheHandlerNeverRunsWithoutAProof() {
        val f = ToolGuardTest.Fake()
        val unmapped = AnthropicPca.handleToolUse(f, use("drop"), map, handlers)
        assertEquals(true, unmapped["is_error"])
        assertEquals(0, f.proved.size)
        f.deny.add("stripe.refund")
        val denied = AnthropicPca.handleToolUse(f, use("refund"), map, handlers)
        assertEquals(true, denied["is_error"])
        assertEquals("denied by policy", denied["content"])
        val noHandler = AnthropicPca.handleToolUse(ToolGuardTest.Fake(), use("refund"), map, emptyMap())
        assertEquals(true, noHandler["is_error"])
    }

    @Test fun aThrowingHandlerIsAnErrorResultAndItsTextIsRecorded() {
        val f = ToolGuardTest.Fake()
        val m = ToolGuard.ToolMapping { _, _ -> ToolGuard.Action("stripe.refund", "charge:c1") }
        val r = AnthropicPca.handleToolUse(f, use("boom"), m, handlers)
        assertEquals(true, r["is_error"])
        assertEquals("downstream failed", r["content"])
        assertEquals(listOf("boom=downstream failed"), f.recorded)
    }

    @Test fun handleToolUsesKeepsOrderAndSkipsOtherBlocks() {
        val out = AnthropicPca.handleToolUses(ToolGuardTest.Fake(), listOf(mapOf("type" to "text", "text" to "hi"), use("refund", "a"), use("refund", "b")), map, handlers)
        assertEquals(listOf("a", "b"), out.map { it["tool_use_id"] })
        assertEquals(2, AnthropicPca.extractToolUses(listOf(use("x"), mapOf("type" to "text"), use("y"))).size)
    }
}
