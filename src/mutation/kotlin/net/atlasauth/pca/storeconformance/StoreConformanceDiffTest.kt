package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracles for the store conformance kit: the history model, linearizability checker, parser and report folding, and the command line. */
@Suppress("UNCHECKED_CAST")
class StoreConformanceDiffTest {
    private val MODULE = "ref-store-conformance"
    private val CLI_MODULE = "ref-store-conformance-java"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun d(o: Any?): Double = Op.numOf(o)
    private fun ops(o: Any?): List<Op> = Kit.opsOf(o)
    private fun opsJson(ops: List<Op>): List<Any?> = ops.map { it.toJson() }
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test fun step() = OracleCases.each(MODULE, "step") { a -> Kit.step(d(a[0]), Op.fromJson(a[1])).map { Op.numJson(it) } }

    @Test fun overlappingTrues() = OracleCases.each(MODULE, "overlappingTrues") { a ->
        val p = Kit.overlappingTrues(ops(a[0]))
        if (p == null) null else opsJson(p)
    }

    @Test fun prune() = OracleCases.each(MODULE, "prune") { a -> opsJson(Kit.prune(ops(a[0]))) }
    @Test fun fastCheck() = OracleCases.each(MODULE, "fastCheck") { a -> Kit.fastCheck(ops(a[0])) }
    @Test fun search() = OracleCases.each(MODULE, "search") { a -> Kit.searchLinearizable(ops(a[0]), d(a[1])) }
    @Test fun decideKey() = OracleCases.each(MODULE, "decideKey") { a -> Kit.decideKey(ops(a[0]), d(a[1])).toJson() }

    @Test fun deletion() = OracleCases.each(MODULE, "deletion") { a ->
        val o = ops(a[0])
        opsJson(Kit.deletion(o, o[d(a[1]).toInt()]))
    }

    @Test fun minimize() = OracleCases.each(MODULE, "minimize") { a -> opsJson(Kit.minimize(ops(a[0]), d(a[1]))) }
    @Test fun checkKey() = OracleCases.each(MODULE, "checkKey") { a -> Kit.checkKey(ops(a[0]), Kit.CheckOptions.fromJson(a[1])).toJson() }
    @Test fun checkHistory() = OracleCases.each(MODULE, "checkHistory") { a -> Kit.checkHistory(ops(a[0]), Kit.CheckOptions.fromJson(a[1])).toJson() }
    @Test fun formatOps() = OracleCases.each(MODULE, "formatOps") { a -> ArrayList<Any?>(Kit.formatOps(ops(a[0]))) }
    @Test fun parseHistory() = OracleCases.each(MODULE, "parseHistory") { a -> Kit.parseHistory(a[0] as String).toJson() }

    @Test fun prng() = OracleCases.each(MODULE, "prng") { a ->
        val r = Kit.Prng(d(a[0]))
        l(a[1]).map { r.rand(d(it)) }
    }

    @Test fun overall() = OracleCases.each(MODULE, "overall") { a ->
        val x = a[0]
        if (x is List<*>) {
            val tests = ArrayList<Any?>()
            for (s in x) { val t = LinkedHashMap<String, Any?>(); t["status"] = s; tests.add(t) }
            Kit.overall(tests)
        } else {
            Kit.overall(l(m(x)["tests"]))
        }
    }

    @Test fun formatReport() = OracleCases.each(MODULE, "formatReport") { a -> Kit.formatReport(a[0], d(a[1])) }
    @Test fun reportJson() = OracleCases.each(MODULE, "reportJson") { a -> Kit.reportJson(a[0]) }

    @Test fun cliConsts() = OracleCases.each(CLI_MODULE, "consts") { _ ->
        val o = LinkedHashMap<String, Any?>()
        o["DEFAULT_SEARCH_BUDGET"] = Kit.DEFAULT_SEARCH_BUDGET
        o["ALL_TESTS"] = ArrayList<Any?>(Kit.ALL_TESTS)
        o["USAGE"] = Cli.USAGE
        o
    }

    @Test fun parseCli() = OracleCases.each(CLI_MODULE, "parseCli") { a -> Cli.parseCli(strs(a[0])) }

    @Test fun cliMain() = OracleCases.each(CLI_MODULE, "main") { a ->
        val out = ArrayList<Any?>()
        val err = ArrayList<Any?>()
        val code = Cli.main(strs(a[0]), { out.add(it) }, { err.add(it) })
        val r = LinkedHashMap<String, Any?>()
        r["code"] = code
        r["out"] = out
        r["err"] = err
        r
    }
}
