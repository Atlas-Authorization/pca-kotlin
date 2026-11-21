package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** The information-flow taint lattice, the trusted-input registry, ref classification and computeTaint against the reference corpus (ref-taint, 2344 cases). */
@Suppress("UNCHECKED_CAST")
class TaintRefDiffTest {
    private val mod = "ref-taint"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    /** A registry spec: records / throws / fixed / none (null). */
    private fun registry(rs: Any?): Taint.Registry? {
        val r = map(rs) ?: return null
        return when (r["mode"]) {
            "fixed" -> { val f = map(r["fixed"]); Taint.Registry { f } }
            "throws" -> Taint.Registry { throw RuntimeException("registry boom") }
            else -> Taint.InMemoryRegistry().also { reg -> for (rec in (r["records"] as List<Any?>?) ?: emptyList()) { val l = rec as List<Any?>; reg.record(l[0], l[1]) } }
        }
    }

    private fun graph(gs: Any?): Taint.ResourceGraph? {
        val g = map(gs) ?: return null
        return Taint.ResourceGraph { id ->
            if (g["throws"] == true) throw RuntimeException("graph boom")
            if ((g["nodes"] as List<Any?>).contains(id)) linkedMapOf("id" to id) else null
        }
    }

    private fun computed(c: Taint.Computed): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("taint" to c.taint, "label" to c.label, "refs" to c.refs, "valid" to c.valid)
        if (c.reason != null) m["reason"] = c.reason
        return m
    }

    @Test fun everyFunction() {
        OracleCases.each(mod, "constants") { _ -> linkedMapOf("TAINT_LEVELS" to Taint.LEVELS, "BOTTOM" to Taint.BOTTOM, "TOP" to Taint.TOP) }
        OracleCases.each(mod, "isTaintLevel") { x -> Taint.isTaintLevel(x[0]) }
        OracleCases.each(mod, "labelRank") { x -> Taint.labelRank(x[0]) }
        OracleCases.each(mod, "taintValue") { x -> Taint.taintValue(x[0]) }
        OracleCases.each(mod, "joinLabel") { x -> Taint.joinLabel(x[0], x[1]) }
        OracleCases.each(mod, "joinLabels") { x -> Taint.joinLabels(x[0] as List<Any?>) }
        OracleCases.each(mod, "registry") { x ->
            val reg = Taint.InMemoryRegistry()
            (x[0] as List<Any?>).map { o ->
                val op = o as List<Any?>
                when (op[0] as String) {
                    "lookup" -> reg.lookup(op[1] as String)
                    "size" -> reg.size
                    "emptyLookup" -> Taint.EMPTY_REGISTRY.lookup(op[1] as String)
                    "record" -> { reg.record(op[1], op[2]); null }
                    "recordTrusted" -> { reg.recordTrusted(op[1]); null }
                    "recordFirstParty" -> { reg.recordFirstParty(op[1]); null }
                    "recordTool" -> { reg.recordTool(op[1], op[2]); null }
                    "recordWeb" -> { reg.recordWeb(op[1]); null }
                    else -> throw IllegalArgumentException("bad op")
                }
            }
        }
        OracleCases.each(mod, "classifyRef") { x -> val c = map(x[1])!!; Taint.classifyRef(x[0], registry(c["registry"]), graph(c["graph"])) }
        OracleCases.each(mod, "computeTaint") { x -> val c = map(x[1])!!; computed(Taint.computeTaint(x[0], registry(c["registry"]), graph(c["graph"]))) }
        val fns = setOf("constants", "isTaintLevel", "labelRank", "taintValue", "joinLabel", "joinLabels", "registry", "classifyRef", "computeTaint")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(2344, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
