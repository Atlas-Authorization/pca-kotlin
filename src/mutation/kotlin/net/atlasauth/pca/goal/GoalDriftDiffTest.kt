package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal drift monitor and the conformal risk control numerics. */
@Suppress("UNCHECKED_CAST")
class GoalDriftDiffTest {
    private val M = "ref-goal-drift"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun copy(o: Any?): Any? = when (o) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { r -> for ((k, v) in o) r[k as String] = copy(v) }
        is List<*> -> ArrayList<Any?>().also { r -> for (x in o) r.add(copy(x)) }
        else -> o
    }

    private fun key(b64: Any?): ByteArray {
        val s = b64 as String
        return if (s.isEmpty()) ByteArray(0) else Keys.unb64u(s)
    }

    @Test fun flow() = OracleCases.each(M, "flow") { a ->
        val goal = m(a[0])!!
        val opts = m(a[1])
        var mon = GoalDrift.Monitor(goal, opts)
        var last: Map<String, Any?>? = null
        val out = ArrayList<Any?>()
        for (so in l(a[2])) {
            val s = m(so)!!
            when (s["op"] as String) {
                "observe" -> out.add(mon.observe(m(s["act"])!!, s["t"]))
                "state" -> out.add(copy(mon.state()))
                "seal" -> {
                    last = m(copy(mon.seal(key(s["key"]))))
                    out.add(copy(last))
                }
                "restoreLast" -> {
                    val sealed = m(copy(last))!! as MutableMap<String, Any?>
                    val mode = s["mode"] as String
                    if (mode == "state") {
                        val st = LinkedHashMap(m(sealed["state"])!!)
                        st["strikes"] = Json.Num("0")
                        sealed["state"] = st
                    }
                    if (mode == "mac") {
                        val mac = sealed["mac"] as String
                        sealed["mac"] = (if (mac[0] == '0') "1" else "0") + mac.substring(1)
                    }
                    if (mode == "badmac") sealed["mac"] = "zz"
                    mon = GoalDrift.Monitor.restore(goal, sealed, key(s["key"]), opts)
                    out.add(copy(mon.state()))
                }
                else -> out.add(copy(GoalDrift.guardedDecide(goal, m(s["ont"])!!, mon, m(s["case"])!!, s["t"])))
            }
        }
        out
    }

    @Test fun applyDrift() = OracleCases.each(M, "applyDrift") { a -> GoalDrift.applyDrift(a[0] as String, m(a[1])!!) }
    @Test fun alphaOf() = OracleCases.each(M, "alphaOf") { a -> GoalCrc.alphaOf(a[0].toString().toDouble()) }

    @Test fun calibrate() = OracleCases.each(M, "calibrate") { a ->
        val gate = a[2] as String
        val cap = if (gate == "none") 0.0 else gate.substring(2).toDouble() / 1e5
        GoalCrc.calibrate(l(a[0]), m(a[1])!!, if (gate == "none") null else { k: Long, n: Long -> GoalCrc.cpUpper95(k, n) <= cap })
    }

    @Test fun assertMonotone() = OracleCases.each(M, "assertMonotone") { a ->
        GoalCrc.assertMonotone(l(a[0]))
        null
    }

    @Test fun cpUpper95() = OracleCases.each(M, "cpUpper95") { a -> GoalCrc.cpUpper95(a[0].toString().toLong(), a[1].toString().toLong()) }

    @Test fun renderReportMarkdown() = OracleCases.each(M, "renderReportMarkdown") { a ->
        GoalCrc.renderReportMarkdown(l(a[0]), m(a[1])!!["source"] as String, m(a[1])!!["modelSet"] as String)
    }
}
