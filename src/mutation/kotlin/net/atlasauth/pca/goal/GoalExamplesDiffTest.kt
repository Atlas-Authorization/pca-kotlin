package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal examples: decision cells, boundary examples, goal tests, policy pin. */
@Suppress("UNCHECKED_CAST")
class GoalExamplesDiffTest {
    private val M = "ref-goal-examples"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun maps(o: Any?): List<Map<String, Any?>>? {
        if (o == null) return null
        val out = ArrayList<Map<String, Any?>>()
        for (x in l(o)) out.add(m(x)!!)
        return out
    }

    private fun strs(o: Any?): List<String>? {
        if (o == null) return null
        val out = ArrayList<String>()
        for (x in l(o)) out.add(x as String)
        return out
    }

    @Test fun buildSpace() = OracleCases.each(M, "buildSpace") { a -> GoalExamples.buildSpace(maps(a[0])!!, strs(a[1])!!).toJson() }

    @Test fun cells() = OracleCases.each(M, "cells") { a -> GoalExamples.cells(GoalExamples.buildSpace(maps(a[0])!!, strs(a[1])!!), strs(a[2])) }

    @Test fun cellKey() = OracleCases.each(M, "cellKey") { a -> GoalExamples.cellKey(GoalExamples.buildSpace(maps(a[0])!!, strs(a[1])!!), m(a[2])!!) }

    @Test fun decideCase() = OracleCases.each(M, "decideCase") { a -> GoalExamples.decideCase(m(a[0])!!, m(a[1])!!, m(a[2])!!) }
    @Test fun replay() = OracleCases.each(M, "replay") { a -> GoalExamples.replay(m(a[0])!!, m(a[1])!!, l(a[2]), l(a[3])) }

    @Test fun allowWitness() = OracleCases.each(M, "allowWitness") { a ->
        val g = m(a[0])!!
        val i = a[1].toString().toInt()
        GoalExamples.allowWitness(g, m(l(g["grants"])[i])!!, m(a[2])!!)
    }

    @Test fun boundaryExamples() = OracleCases.each(M, "boundaryExamples") { a -> GoalExamples.boundaryExamples(m(a[0])!!, m(a[1])!!, maps(a[2]), strs(a[3])) }

    @Test fun reviewSet() = OracleCases.each(M, "reviewSet") { a -> GoalExamples.reviewSet(l(a[0]), a[1].toString().toInt()) }
    @Test fun testsDigest() = OracleCases.each(M, "testsDigest") { a -> GoalExamples.testsDigest(l(a[0])) }
    @Test fun makeGoalTests() = OracleCases.each(M, "makeGoalTests") { a -> GoalExamples.makeGoalTests(m(a[0])!!, l(a[1])) }

    @Test fun signGoalTests() = OracleCases.each(M, "signGoalTestsSeed") { a -> GoalExamples.signGoalTests(m(a[0])!!, Keys.unb64u(a[1] as String)) }

    @Test fun checkGoalTests() = OracleCases.each(M, "checkGoalTests") { a ->
        val mode = a[2] as String
        val g = m(a[3])!!
        val ont = m(a[4])!!
        GoalExamples.checkGoalTests(m(a[0])!!, l(a[1])) { t ->
            if (mode == "ref") GoalExamples.decideCase(g, ont, t)["decision"] as String
            else if (mode == "allow") "allow" else if (mode == "deny") "deny" else "escalate"
        }
    }

    @Test fun signPin() = OracleCases.each(M, "signPinSeed") { a -> GoalExamples.signPin(m(a[0])!!, Keys.unb64u(a[1] as String)) }
    @Test fun checkPin() = OracleCases.each(M, "checkPin") { a -> GoalExamples.checkPin(m(a[0])!!, l(a[1]), m(a[2])!!) }
}
