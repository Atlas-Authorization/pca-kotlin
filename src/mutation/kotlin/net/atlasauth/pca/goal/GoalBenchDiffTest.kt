package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the benchmark: seeded cases, simulated model fixtures, the four-level evaluation and the calibration report. */
@Suppress("UNCHECKED_CAST")
class GoalBenchDiffTest {
    private val M = "ref-goal-bench"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    private fun cases(o: Any?): List<Map<String, Any?>> {
        val r = ArrayList<Map<String, Any?>>()
        for (c in o as List<*>) r.add(m(c)!!)
        return r
    }

    private fun lng(o: Any?): Long = (o as Json.Num).raw.toDouble().toLong()

    @Test fun rngSeq() = OracleCases.each(M, "rngSeq") { a ->
        val r = GoalBench.rng(lng(a[0]))
        val out = ArrayList<Any?>()
        var i = 0L
        val n = lng(a[1])
        while (i < n) {
            out.add(r.next())
            i++
        }
        out
    }

    @Test fun generateCases() = OracleCases.each(M, "generateCases") { a ->
        GoalBench.generateCases(a[0] as String, lng(a[1]).toInt(), lng(a[2]), if (a[3] == null) null else lng(a[3]).toInt(), a[4] == true)
    }

    @Test fun truthGoalOf() = OracleCases.each(M, "truthGoalOf") { a -> GoalBench.truthGoal(m(a[0])!!) }

    @Test fun simulateOutputOf() = OracleCases.each(M, "simulateOutputOf") { a ->
        var spec: Array<Any>? = null
        for (s in GoalBench.SIM_SPECS) if (s[0] == a[1]) spec = s
        GoalBench.simulateOutput(m(a[0])!!, spec!![0] as String, spec[1] as Double, spec[2] as Double)
    }

    @Test fun recordFixturesOf() = OracleCases.each(M, "recordFixturesOf") { a -> GoalBench.recordFixtures(cases(a[0])) }
    @Test fun caseSetDigest() = OracleCases.each(M, "caseSetDigest") { a -> GoalBench.caseSetDigest(cases(a[0])) }

    @Test fun evalCaseOf() = OracleCases.each(M, "evalCaseOf") { a ->
        val c = m(a[0])!!
        GoalBench.evalCase(c, GoalBench.completionsFrom(GoalBench.recordFixtures(listOf(c))), null, false, null)
    }

    @Test fun compileWideningOf() = OracleCases.each(M, "compileWideningOf") { a ->
        val items = ArrayList<Array<Map<String, Any?>>>()
        for (c in cases(a[0])) {
            val goal = GoalBench.truthGoal(c)
            items.add(arrayOf(goal, GoalBench.truthOnt(c, goal)))
        }
        GoalBench.compileWideningCount(items, null)
    }

    @Test fun summarizeOf() = OracleCases.each(M, "summarizeOf") { a -> GoalBench.summarize(a[0] as String, cases(a[1]), a[2] as String, m(a[3])) }

    @Test fun runDomainOf() = OracleCases.each(M, "runDomainOf") { a ->
        val cs = cases(a[1])
        GoalBench.runDomain(a[0] as String, cs, GoalBench.recordFixtures(cs), null, false)
    }
}
