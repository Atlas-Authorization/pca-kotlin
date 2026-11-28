package net.atlasauth.pca.dataflow

import net.atlasauth.pca.dataflow.Dataflow.Capability
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the data-flow model, trace rules and detector adapters. */
@Suppress("UNCHECKED_CAST")
class DataflowDiffTest {
    private val m = "ref-dataflow"

    private fun map(o: Any?) = o as Map<String, Any?>
    private fun strs(o: Any?) = o as List<String>
    private fun num(o: Any?): Double? = (o as? Json.Num)?.raw?.toDouble()

    /** A capability spec as the reference's tag() accepts it; anything else is refused. */
    private fun cap(spec: Any?): Capability {
        val bad = "tag: a capability needs a set of sources and a boolean isTrusted"
        require(spec is Map<*, *>) { bad }
        val c = map(spec)
        require(c["sources"] is List<*> && c["isTrusted"] is Boolean) { bad }
        require(!c.containsKey("readers") || c["readers"] is List<*>) { "tag: readers must be a Set when given" }
        return Capability(strs(c["sources"]), c["isTrusted"] as Boolean, if (c.containsKey("readers")) strs(c["readers"]) else null)
    }

    /** A value spec: {"$raw": v} is v itself (untagged); {"$t": v, cap} is tagged; anything else is itself. */
    private fun v(spec: Any?): Any? {
        if (spec is Map<*, *> && spec.containsKey("\$raw")) return spec["\$raw"] ?: Any() // a null element would read as an explicit undefined
        if (spec is Map<*, *> && spec.containsKey("\$t")) return Dataflow.tag(spec["\$t"], cap(spec["cap"]))
        return spec
    }

    private fun capJson(c: Capability): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("sources" to ArrayList<Any?>(c.sources), "isTrusted" to c.isTrusted)
        c.readers?.let { o["readers"] = ArrayList<Any?>(it) }
        return o
    }

    private fun taggedJson(t: Any?): Map<String, Any?> {
        val tg = t as Dataflow.Tagged<*>
        return linkedMapOf("value" to tg.value, "cap" to capJson(tg.cap))
    }

    private fun sink(spec: Any?): Dataflow.Sink? {
        if (spec !is Map<*, *>) return null
        val a = spec["accepts"] as? Map<*, *>
        val p = a?.let {
            Dataflow.FlowPolicy(it["external"] as? Boolean, it["requireTrusted"] as? Boolean, it["allowedSources"] as? List<String>, it["deniedSources"] as? List<String>)
        }
        return Dataflow.Sink(spec["id"] as? String, p)
    }

    private fun decisionJson(d: Dataflow.FlowDecision): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("outcome" to d.outcome)
        d.reason?.let { o["reason"] = it }
        d.path?.let { o["path"] = ArrayList<Any?>(it) }
        return o
    }

    private fun combiner(name: String): (List<Any?>) -> Any? = when (name) {
        "count" -> ({ xs -> Json.Num(xs.size.toString()) })
        "pair" -> ({ xs -> xs })
        "first" -> ({ xs -> xs[0] })
        else -> ({ _ -> throw IllegalStateException("combiner failed") })
    }

    private fun readers(opts: Any?): List<String>? = (opts as? Map<*, *>)?.get("readers") as? List<String>

    // ---- data-flow ------------------------------------------------------------------------------------------------------------

    @Test fun tag() = OracleCases.each(m, "tag") { a -> taggedJson(Dataflow.tag(a[0], cap(a[1]))) }
    @Test fun fromTrustedQuery() = OracleCases.each(m, "fromTrustedQuery") { a -> taggedJson(Dataflow.fromTrustedQuery(a[0], readers(a.getOrNull(1)))) }
    @Test fun fromToolOutput() = OracleCases.each(m, "fromToolOutput") { a -> taggedJson(Dataflow.fromToolOutput(a[0] as String, a[1], readers(a.getOrNull(2)))) }

    @Test fun fromSource() = OracleCases.each(m, "fromSource") { a ->
        val t = (a.getOrNull(2) as? Map<*, *>)?.get("isTrusted")
        taggedJson(Dataflow.fromSource(a[0] as String, a[1], t == true, readers(a.getOrNull(2))))
    }

    private fun caps(o: Any?): List<Capability> = (o as List<*>).map { c ->
        val x = map(c)
        Capability(strs(x["sources"]), x["isTrusted"] == true, if (x.containsKey("readers")) strs(x["readers"]) else null)
    }

    @Test fun unionSources() = OracleCases.each(m, "unionSources") { a -> ArrayList<Any?>(Dataflow.unionSources(caps(a[0]))) }
    @Test fun combineCaps() = OracleCases.each(m, "combineCaps") { a -> capJson(Dataflow.combineCaps(caps(a[0]))) }
    @Test fun derive() = OracleCases.each(m, "derive") { a -> taggedJson(Dataflow.derive((a[0] as List<*>).map { v(it) }, combiner(a[1] as String))) }
    @Test fun classifyFlow() = OracleCases.each(m, "classifyFlow") { a -> decisionJson(Dataflow.classifyFlow(v(a[0]), sink(a.getOrNull(1)))) }

    @Test fun canFlow() = OracleCases.each(m, "canFlow") { a ->
        val c = Dataflow.canFlow(v(a[0]), sink(a.getOrNull(1)))
        val o = linkedMapOf<String, Any?>("ok" to c.ok)
        c.reason?.let { o["reason"] = it }
        o
    }

    @Test fun checkAction() = OracleCases.each(m, "checkAction") { a ->
        val act = map(a[0])
        val args = (a[1] as List<*>).map { s -> if (s == null) null else if (s is Map<*, *> && s["\$hole"] == true) Dataflow.HOLE else v(s) }
        val g = map(a[2])
        val gov = Dataflow.FlowGovernor {
            if (g["throws"] == true) throw IllegalStateException("governor failed")
            sink(g["sink"])
        }
        val op = map(a[3])
        val expected = if (op.containsKey("expectedArgs")) num(op["expectedArgs"]) else null
        val d = Dataflow.checkAction(Dataflow.PcaStyleAction(act["verb"] as String?, act["resource"] as String?), args, gov, expected)
        val o = linkedMapOf<String, Any?>("outcome" to d.outcome, "sink" to d.sink)
        d.reason?.let { o["reason"] = it }
        d.arg?.let { o["arg"] = Json.Num(it.toString()) }
        d.path?.let { o["path"] = ArrayList<Any?>(it) }
        o
    }

    @Test fun dualContext() = OracleCases.each(m, "dualContext") { a ->
        val spec = map(a[0])
        val plan: (Any?) -> Any? = when (spec["plan"]) {
            "identity" -> ({ q -> q })
            "wrap" -> ({ q -> linkedMapOf<String, Any?>("planned" to q) })
            else -> ({ _ -> throw IllegalStateException("planner failed") })
        }
        val quarantine: (Any?) -> Any? = when (spec["quarantine"]) {
            "tagged_untrusted" -> ({ p -> Dataflow.fromToolOutput("quarantine", p, null) })
            "trusted" -> ({ p -> Dataflow.fromTrustedQuery(p, null) })
            "raw" -> ({ _ -> Any() })
            else -> ({ _ -> throw IllegalStateException("q failed") })
        }
        val r = Dataflow.dualContext<Any?, Any?, Any?>(v(spec["query"]), plan, quarantine)
        linkedMapOf("plan" to r.plan, "result" to taggedJson(r.result))
    }

    private fun sinkJson(s: Dataflow.Sink): Map<String, Any?> {
        val acc = linkedMapOf<String, Any?>()
        s.accepts!!.external?.let { acc["external"] = it }
        s.accepts!!.requireTrusted?.let { acc["requireTrusted"] = it }
        return linkedMapOf("id" to s.id, "accepts" to acc)
    }

    @Test fun externalSendSink() = OracleCases.each(m, "externalSendSink") { a -> sinkJson(Dataflow.externalSendSink(a[0] as String)) }
    @Test fun sensitiveSink() = OracleCases.each(m, "sensitiveSink") { a -> sinkJson(Dataflow.sensitiveSink(a[0] as String)) }
    @Test fun levelOf() = OracleCases.each(m, "levelOf") { a -> Dataflow.levelOf(v(a[0])) }

    @Test fun consts() = OracleCases.each(m, "consts") {
        linkedMapOf<String, Any?>("TRUSTED_QUERY" to Dataflow.TRUSTED_QUERY, "tool" to Dataflow.toolProvenance("x"), "tool2" to Dataflow.toolProvenance(""))
    }

    // ---- trace rules (a TraceRuleError carries the reference's code) ----------------------------------------------------------

    @Test fun parseTraceRule() = OracleCases.each(m, "parseTraceRule") { a ->
        if (a.size > 2) TraceRules.parseTraceRule(a[0] as String, a[1] as String, a[2]) else TraceRules.parseTraceRule(a[0] as String, a[1] as String)
    }

    @Test fun parseInvariantRule() = OracleCases.each(m, "parseInvariantRule") { a -> TraceRules.parseInvariantRule(a[0] as String, a[1] as String, a.getOrNull(2) as? Map<String, Any?>) }
    @Test fun compileTraceRules() = OracleCases.each(m, "compileTraceRules") { a -> TraceRules.compileTraceRules(a[0], map(a[1])) }
    @Test fun lethalTrifecta() = OracleCases.each(m, "lethalTrifecta") { a -> TraceRules.lethalTrifecta(map(a[0]), a[1] as List<Any?>?, a.getOrNull(2) as? Map<String, Any?>) }

    @Test fun traceConsts() = OracleCases.each(m, "traceConsts") {
        linkedMapOf<String, Any?>("MAX_TRACE_CAVEATS" to TraceRules.MAX_TRACE_CAVEATS, "PRIVATE_READ_TRAITS" to TraceRules.PRIVATE_READ_TRAITS, "EXTERNAL_SEND_TRAITS" to TraceRules.EXTERNAL_SEND_TRAITS)
    }

    // ---- detectors ----------------------------------------------------------------------------------------------------------------

    private fun ctx(o: Any?): Map<String, Any?> {
        val c = LinkedHashMap(map(o))
        c["secretKey"] = Keys.unb64u(map(c["secretKey"])["\$bytes"] as String)
        return c
    }

    @Test fun categoryId() = OracleCases.each(m, "categoryId") { a -> Detectors.categoryId(a[0]) }
    @Test fun lakeraReceipt() = OracleCases.each(m, "lakeraReceipt") { a -> Detectors.lakeraReceipt(a[0], ctx(a[1])) }
    @Test fun promptSecurityReceipt() = OracleCases.each(m, "promptSecurityReceipt") { a -> Detectors.promptSecurityReceipt(a[0], ctx(a[1])) }
    @Test fun genericReceipt() = OracleCases.each(m, "genericReceipt") { a -> Detectors.genericReceipt(a[0], ctx(a[1])) }
}
