package net.atlasauth.pca.goal

import java.math.BigDecimal
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Test

/** Replays the reference oracle of the review flow (card, diff, signed approval, loader) over a stub compiler kernel. */
@Suppress("UNCHECKED_CAST")
class GoalReviewDiffTest {
    private val M = "ref-goal-review"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?>? = if (o is List<*>) o as List<Any?> else null
    private fun num(n: Long): Json.Num = Json.Num(n.toString())
    private fun intOf(o: Any?): Int = (o as Json.Num).raw.toDouble().toInt()

    /** The stub kernel of the oracle (see its header). */
    private fun kernel(mode: String): GoalReview.ReviewKernel = object : GoalReview.ReviewKernel {
        override fun compile(goal: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?> {
            if (mode == "throwcompile") throw RuntimeException("boom")
            val grants = l(goal["grants"])!!
            val r = LinkedHashMap<String, Any?>()
            if (grants.isEmpty()) {
                r["ok"] = false
                r["reasons"] = arrayListOf<Any?>("empty")
                return r
            }
            val gids = ArrayList<Any?>()
            for (g in grants) gids.add(m(g)!!["gid"])
            val pol = LinkedHashMap<String, Any?>()
            pol["gids"] = gids
            pol["n"] = num(grants.size.toLong())
            r["ok"] = true
            r["policy"] = pol
            return r
        }

        override fun policyDigest(policy: Map<String, Any?>): String {
            if (mode == "throwdigest") throw RuntimeException("boom")
            val b = LinkedHashMap<String, Any?>()
            b["d"] = "stub-policy"
            b["p"] = policy
            return Pca.hashCanonical(b)
        }

        override fun analyze(policy: Map<String, Any?>): List<String> = if (intOf(policy["n"]) >= 5) listOf("too many") else listOf()

        override fun canDecide(): Boolean = mode != "nodecide"

        override fun decide(goal: Map<String, Any?>, ont: Map<String, Any?>, act: Map<String, Any?>, hist: Map<String, Any?>): String {
            for (g in l(goal["grants"])!!) if (m(g)!!["verb"] == act["verb"]) return "allow"
            return "deny"
        }

        override fun canListNewlyAllowed(): Boolean = mode != "nonewly"

        override fun newlyAllowed(prev: Map<String, Any?>, next: Map<String, Any?>, ont: Map<String, Any?>, limit: Long): Map<String, Any?> {
            val w = ArrayList<Any?>()
            for (x in l(next["grants"])!!) {
                var known = false
                for (y in l(prev["grants"])!!) if (m(y)!!["gid"] == m(x)!!["gid"]) known = true
                if (known) continue
                val a = LinkedHashMap<String, Any?>()
                a["verb"] = m(x)!!["verb"]
                a["res"] = "r"
                a["params"] = LinkedHashMap<String, Any?>()
                a["t"] = num(0)
                a["sess"] = "s"
                a["prin"] = "p"
                a["org"] = "o"
                a["agent"] = "a"
                a["depth"] = num(0)
                w.add(a)
            }
            val r = LinkedHashMap<String, Any?>()
            r["witnesses"] = w
            r["complete"] = true
            return r
        }
    }

    private fun lng(o: Any?): Long? {
        if (o == null) return null
        val d = BigDecimal((o as Json.Num).raw)
        return try { d.toBigIntegerExact().longValueExact() } catch (e: ArithmeticException) { Long.MAX_VALUE }
    }

    @Test fun effectiveLimits() = OracleCases.each(M, "effectiveLimits") { a -> GoalReview.effectiveLimits(m(a[0])) }

    @Test fun renderPolicyCard() = OracleCases.each(M, "renderPolicyCard") { a ->
        val opts = m(a[2])!!
        GoalReview.renderPolicyCard(m(a[0]), l(a[1]), m(opts["limits"]), opts["allowHoles"] == true)
    }

    @Test fun cardDigest() = OracleCases.each(M, "cardDigest") { a -> GoalReview.cardDigest(m(a[0])!!) }
    @Test fun cardToText() = OracleCases.each(M, "cardToText") { a -> GoalReview.cardToText(m(a[0])!!) }

    @Test fun diffGoals() = OracleCases.each(M, "diffGoals") { a ->
        val op = m(a[2])!!
        val km = op["kmode"] as String
        GoalReview.diffGoals(m(a[0])!!, m(a[1])!!, if (km == "none") null else kernel(km), m(op["limits"]), m(op["ontology"]))
    }

    @Test fun diffToText() = OracleCases.each(M, "diffToText") { a -> GoalReview.diffToText(m(a[0])!!) }

    @Test fun approveGoalSeed() = OracleCases.each(M, "approveGoalSeed") { a ->
        val op = m(a[2])!!
        val o = GoalReview.ApproveOptions()
        o.kernel = kernel(op["kmode"] as String)
        o.now = lng(op["now"])
        o.ttlMs = lng(op["ttlMs"])
        o.limits = m(op["limits"])
        o.base = m(op["base"])
        GoalReview.approveGoal(m(a[0])!!, Keys.unb64u(a[1] as String), o)
    }

    @Test fun loadApprovedGoal() = OracleCases.each(M, "loadApprovedGoal") { a ->
        val op = m(a[2])!!
        val o = GoalReview.LoadOptions()
        o.kernel = kernel(op["kmode"] as String)
        o.reviewers = l(op["reviewers"])
        o.ontologyDigest = op["ontology_digest"] as String?
        o.now = lng(op["now"])
        o.limits = m(op["limits"])
        GoalReview.loadApprovedGoal(a[0], m(a[1]), o)
    }
}
