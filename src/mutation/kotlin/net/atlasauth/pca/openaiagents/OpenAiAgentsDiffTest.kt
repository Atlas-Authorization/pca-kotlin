package net.atlasauth.pca.openaiagents

import net.atlasauth.pca.openaiagents.OpenAiAgentsGuard.AgentExecute
import net.atlasauth.pca.openaiagents.OpenAiAgentsGuard.PcaToolDenied
import net.atlasauth.pca.openaiagents.OpenAiAgentsGuard.VerifyOutcome
import net.atlasauth.pca.openaiagents.OpenAiAgentsGuard.WithPcaToolOptions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference's OpenAI Agents adapter logic: proof sources, the guard pipeline, per-tool option merging, guardrails and the
 * step-up helpers. Tools, verifiers and hooks are rebuilt from the corpus' declarative descriptors. Deliberate differences, not compared: a
 * tool is a function (no name / extra / needsApproval properties), a build error is any IllegalArgumentException (the reference splits
 * TypeError from Error and words the text differently), the audience is required (an absent one is replaced by a fixed id, which the stub
 * verifiers ignore), and full-mode components are checked per call, not when the tool is wrapped.
 */
@Suppress("UNCHECKED_CAST")
class OpenAiAgentsDiffTest {
    private val M = "ref-openai-agents"
    private val AUD = "rs"

    private fun m(o: Any?): Map<String, Any?> = (o as? Map<String, Any?>) ?: LinkedHashMap()
    private fun str(o: Any?): String? = o as? String
    private val DECODE = Regex("proof could not be decoded: [\\s\\S]*$")

    private fun norm(s: String): String = DECODE.replace(s, "proof could not be decoded: ")

    /** Every string cut like the reference's normaliser, and the tool properties a function cannot carry removed from the expectation. */
    private fun clean(v: Any?, strip: Set<String>?): Any? = when {
        v is Map<*, *> && strip != null && v["build"] == true -> linkedMapOf("err" to "Error", "calls" to v["calls"], "build" to true)
        v is Map<*, *> -> {
            val o = LinkedHashMap<String, Any?>()
            for ((k, x) in v) {
                if (strip != null && k in strip) continue
                o[k as String] = clean(x, strip)
            }
            o
        }
        v is List<*> -> v.map { clean(it, strip) }
        v is String -> norm(v)
        else -> v
    }

    private val TOOL_PROPS = setOf("name", "extra", "hasNeedsApproval", "hasExecute")

    private fun replay(fn: String, strip: Set<String>? = null, skip: (Map<String, Any?>) -> Boolean = { false }, f: (List<Any?>) -> Any?) {
        val bad = OracleCases.of(M, fn).filter { !skip(it) }.mapNotNull { c ->
            OracleCases.diff(c, clean(c["out"], strip)) { a -> clean(OracleCases.toJson(f(a)), null) }
        }
        assertTrue("${bad.size} divergent case(s) of $fn:\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    private val skipFullMode = { c: Map<String, Any?> ->
        val o = c["out"] as? Map<String, Any?>
        o != null && o["build"] == true && (o["message"] as? String)?.contains("full policy mode is missing") == true
    }

    // ---- proof sources ----
    @Test fun proofFromRunContext() = replay("proofFromRunContext") { a -> OpenAiAgentsGuard.proofFromRunContext(m(m(a[0])["input"]), m(m(a[0])["runContext"])) }

    @Test fun guardrailProof() = replay("guardrailProofFromContext") { a -> OpenAiAgentsGuard.guardrailProofFromContext(m(m(a[0])["args"])) }

    @Test fun provenance() = replay("provenanceFromRunContext") { a -> OpenAiAgentsGuard.provenanceFromRunContext(null, m(m(a[0])["runContext"])) }

    @Test fun inputHeaders() = replay("proofFromInputHeaders") { a ->
        val x = m(a[0])
        OpenAiAgentsGuard.proofFromInputHeaders(str(x["field"]) ?: "headers", str(x["header"]) ?: "PCA-Action").find(x["input"] as? Map<String, Any?>, LinkedHashMap())
    }

    // ---- descriptors -> native objects ----
    private fun stub(d: Map<String, Any?>, calls: MutableList<Any?>): (Map<String, Any?>) -> VerifyOutcome = { p ->
        calls.add(listOf("verify", d["stub"], (p["action"] as? Map<String, Any?>)?.get("verb")))
        if (d["throws"] is String) throw IllegalStateException(d["throws"] as String)
        val allow = d["allow"] == true
        VerifyOutcome(allow, if (d.containsKey("reason")) str(d["reason"]) else null, linkedMapOf("sig" to if (allow) "pass" else "fail"))
    }

    private fun requireOf(d: Map<String, Any?>): OpenAiAgentsGuard.ProofSource? {
        val r = d["require"] as? Map<String, Any?> ?: return null
        if (r.containsKey("headers")) {
            val h = r["headers"] as List<Any?>
            return OpenAiAgentsGuard.proofFromInputHeaders(if (h.isNotEmpty()) h[0] as String else "headers", if (h.size > 1) h[1] as String else "PCA-Action")
        }
        val c = r["const"]
        return OpenAiAgentsGuard.ProofSource { _, _ -> c }
    }

    private fun on(o: Any?) = o != null && o != false

    private fun opts(d: Map<String, Any?>, calls: MutableList<Any?>, shared: Boolean): WithPcaToolOptions {
        var o = WithPcaToolOptions(
            mode = str(d["mode"]), verb = str(d["verb"]), require = requireOf(d),
            audience = if (d.containsKey("audience")) str(d["audience"]) ?: (if (shared) AUD else null) else if (shared) AUD else null,
        )
        (d["verify"] as? Map<String, Any?>)?.let { o = o.copy(verifyFn = stub(it, calls)) }
        if (on(d["authorize"])) o = o.copy(authorize = OpenAiAgentsGuard.AuthorizeBuilder { _, _, _ -> throw IllegalStateException("not configured") })
        if (on(d["onDeny"])) o = o.copy(onDeny = { e, i -> calls.add(listOf("onDeny", e.kind, i)) })
        if (on(d["onVerified"])) o = o.copy(onVerified = { p, i -> calls.add(listOf("onVerified", true, (p["action"] as? Map<String, Any?>)?.get("verb"), i)) })
        if (on(d["recorder"])) o = o.copy(recorder = OpenAiAgentsGuard.ToolOutputRecorder { n, out -> calls.add(listOf("recorded", n, out)) })
        return o
    }

    private fun tool(td: Map<String, Any?>, calls: MutableList<Any?>): AgentExecute {
        val name = str(td["name"])
        if (td["noExecute"] == true) return AgentExecute { _, _ -> throw IllegalStateException("with_pca_tool: the wrapped tool has no execute()") }
        return AgentExecute { input, _ ->
            calls.add(listOf("exec", name, input))
            if (td["throws"] is String) throw IllegalStateException(td["throws"] as String)
            linkedMapOf("echo" to input, "tool" to name)
        }
    }

    private fun errOf(e: Throwable, calls: List<Any?>): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("err" to (if (e is PcaToolDenied) "PcaToolDenied" else "Error"), "message" to norm(e.message ?: ""), "calls" to calls)
        if (e is PcaToolDenied) {
            o["kind"] = e.kind
            o["verb"] = e.verb
            if (e.checks != null) o["checks"] = LinkedHashMap<String, Any?>(e.checks)
        }
        return o
    }

    private fun buildErr(calls: List<Any?>): Map<String, Any?> = linkedMapOf("err" to "Error", "calls" to calls, "build" to true)

    private fun outcome(t: AgentExecute, input: Any?, rc: Map<String, Any?>?, calls: List<Any?>): LinkedHashMap<String, Any?> = try {
        linkedMapOf("ok" to true, "out" to t.execute(m(input), rc), "calls" to calls)
    } catch (e: RuntimeException) {
        LinkedHashMap(errOf(e, calls))
    }

    @Test fun withPcaTool() = replay("withPcaTool", TOOL_PROPS, skipFullMode) { a ->
        val x = m(a[0])
        val calls = ArrayList<Any?>()
        val t = try {
            OpenAiAgentsGuard.withPcaTool(str(m(x["tool"])["name"]), tool(m(x["tool"]), calls), opts(m(x["options"]), calls, true))
        } catch (e: IllegalArgumentException) {
            return@replay buildErr(calls)
        }
        outcome(t, x["input"], if (x["noRunContext"] == true) null else m(x["runContext"]), calls)
    }

    @Test fun pcaTools() = replay("pcaTools", TOOL_PROPS, skipFullMode) { a ->
        val x = m(a[0])
        val calls = ArrayList<Any?>()
        val tools = LinkedHashMap<String, AgentExecute>()
        for ((k, v) in m(x["tools"])) tools[k] = tool(m(v), calls)
        val o = m(x["options"])
        val per = (o["per"] as? Map<String, Any?>)?.mapValues { opts(m(it.value), calls, false) }
        val only = (o["only"] as? List<Any?>)?.map { it as String }
        val g = try {
            OpenAiAgentsGuard.pcaTools(tools, opts(o, calls, true), per, only)
        } catch (e: IllegalArgumentException) {
            return@replay buildErr(calls)
        }
        val res = LinkedHashMap<String, Any?>()
        for ((k, t) in g) {
            val r = outcome(t, x["input"], m(x["runContext"]), calls)
            r["same"] = t === tools[k]
            res[k] = r
        }
        res
    }

    @Test fun guardrail() = replay("guardrail") { a ->
        val x = m(a[0])
        val calls = ArrayList<Any?>()
        val d = m(x["options"])
        val wo = opts(d, calls, true)
        val go = OpenAiAgentsGuard.PcaGuardrailOptions(
            require = wo.require?.let { r -> { args: Map<String, Any?> -> r.find(args, LinkedHashMap()) } },
            verifyFn = wo.verifyFn, audience = wo.audience, verb = wo.verb, name = str(d["name"]),
        )
        val g = if (x["kind"] == "input") OpenAiAgentsGuard.pcaInputGuardrail(go) else OpenAiAgentsGuard.pcaToolGuard(go)
        try {
            val r = g.execute(m(x["args"]))
            linkedMapOf("name" to g.name, "result" to linkedMapOf("tripwireTriggered" to r.tripwireTriggered, "outputInfo" to r.outputInfo), "calls" to calls)
        } catch (e: RuntimeException) {
            linkedMapOf("err" to "Error", "message" to norm(e.message ?: ""), "calls" to calls)
        }
    }

    // ---- step-up ----
    private fun recording(calls: MutableList<Any?>) = OpenAiAgentsGuard.ToolIntent { t, i -> calls.add(listOf("intent", t, i)); null }

    @Test fun reviewToolCall() = replay("reviewToolCall") { a ->
        val x = m(a[0])
        val calls = ArrayList<Any?>()
        val r = OpenAiAgentsGuard.reviewToolCall(x["tool"] as String, x["input"] as? Map<String, Any?>, OpenAiAgentsGuard.StepUpOptions(recording(calls)))
        linkedMapOf("r" to linkedMapOf("tool" to r.tool, "review" to r.review), "calls" to calls)
    }

    @Test fun pendingStepUps() = replay("pendingStepUps") { a ->
        OpenAiAgentsGuard.pendingStepUps((a[0] as List<Any?>).map { OpenAiAgentsGuard.ToolReview(m(it)["tool"] as String, m(m(it)["review"])) })
            .map { linkedMapOf("tool" to it.tool, "request" to it.request) }
    }

    @Test fun needsApproval() = replay("needsApproval", TOOL_PROPS) { a ->
        val x = m(a[0])
        val calls = ArrayList<Any?>()
        val o = OpenAiAgentsGuard.NeedsApprovalOptions(recording(calls), toolName = str(x["toolName"]))
        val f = if (x["via"] == "direct") OpenAiAgentsGuard.pcaNeedsApproval(o) else OpenAiAgentsGuard.withApproval(str(m(x["tool"])["name"]), o)
        val value = f(LinkedHashMap(), m(x["input"]))
        // the reference also reports properties of the wrapped tool object, which a function does not carry
        linkedMapOf("value" to value, "calls" to calls)
    }
}
