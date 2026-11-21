package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal N-version meet and active disambiguation. */
@Suppress("UNCHECKED_CAST")
class GoalNVersionDiffTest {
    private val M = "ref-goal-nversion"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun maps(o: Any?): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (x in l(o)) out.add(m(x)!!)
        return out
    }

    @Test fun meet() = OracleCases.each(M, "meet") { a -> GoalNVersion.meet(maps(a[0])) }
    @Test fun meetGrants() = OracleCases.each(M, "meetGrants") { a -> GoalNVersion.meetGrants(l(a[0]), l(a[1])) }
    @Test fun checkPanel() = OracleCases.each(M, "checkPanel") { a -> GoalNVersion.checkPanel(maps(a[0])) }
    @Test fun disagreementMass() = OracleCases.each(M, "disagreementMass") { a -> GoalDisambiguate.disagreementMass(maps(a[0]), m(a[1])!!) }
    @Test fun questions() = OracleCases.each(M, "questions") { a -> GoalDisambiguate.questions(maps(a[0]), GoalDisambiguate.Opts(m(a[1])!!)) }

    @Test fun nVersion() = OracleCases.each(M, "nVersion") { a ->
        GoalNVersion.nVersion(maps(a[0]), GoalDisambiguate.Opts(m(a[1])!!), if (a.size > 2 && a[2] != null) a[2].toString().toDouble() else null)
    }

    @Test fun allowsWitness() = OracleCases.each(M, "allowsWitness") { a -> GoalDisambiguate.allowsWitness(m(a[0])!!, m(a[1])!!, m(a[2])!!) }

    @Test fun disambiguate() = OracleCases.each(M, "disambiguate") { a ->
        val readings = maps(a[0])
        val ont = m(a[1])!!
        val mode = a[2] as String
        val opts = GoalDisambiguate.Opts(ont)
        if (a[3] != null) opts.budget = a[3].toString().toInt()
        GoalDisambiguate.disambiguate(readings, { q ->
            if (mode == "allow") "allow" else if (mode == "deny") "deny"
            else if (GoalDisambiguate.allowsWitness(m(readings[mode.substring(6).toInt()]["goal"])!!, ont, q)) "allow" else "deny"
        }, opts)
    }
}
