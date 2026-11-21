package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal precedent log (scripted flows over signed escalation answers). */
@Suppress("UNCHECKED_CAST")
class GoalPrecedentDiffTest {
    private val M = "ref-goal-precedent"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun entryOut(r: Map<String, Any?>, withCell: Boolean): Map<String, Any?> {
        if (r["ok"] != true) return r
        val e = m(r["entry"])!!
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = true
        out["digest"] = e["digest"]
        if (withCell) out["cell"] = e["cell"]
        out["seq"] = e["seq"]
        return out
    }

    @Test fun flow() = OracleCases.each(M, "flow") { a ->
        val goal = m(a[0])!!
        val ont = m(a[1])!!
        val grant = m(a[2])!!
        val log = GoalPrecedent.Log(l(a[3]))
        val space = GoalExamples.buildSpace(listOf(goal), ArrayList())
        val out = ArrayList<Any?>()
        for (so in l(a[4])) {
            val s = m(so)!!
            val now = if (s["now"] == null) 0L else s["now"].toString().toLong()
            when (s["op"] as String) {
                "append" -> out.add(entryOut(log.append(m(s["answer"])!!, m(s["answered"])!!, grant, space, now), true))
                "revoke" -> out.add(entryOut(log.revoke(m(s["rev"])!!), false))
                "verifyChain" -> out.add(log.verifyChain(space))
                "lookup" -> {
                    val h = log.lookup(s["policyDigest"] as String, space, m(s["case"])!!, now.toDouble())
                    out.add(if (h == null) null else linkedMapOf("decision" to h["decision"], "digest" to m(h["entry"])!!["digest"]))
                }
                "authorize" -> {
                    val r = GoalPrecedent.authorizeWithPrecedents(goal, ont, s["policyDigest"] as String, log, m(s["case"])!!, now.toDouble())
                    val o2 = LinkedHashMap<String, Any?>()
                    o2["decision"] = r["decision"]
                    o2["via"] = r["via"]
                    if (r["precedent"] != null) o2["digest"] = m(r["precedent"])!!["digest"]
                    out.add(o2)
                }
                "tamper" -> {
                    val e = log.entries()[s["index"].toString().toInt()]
                    if (s["del"] == true) e.remove(s["key"] as String) else e[s["key"] as String] = s["value"]
                    out.add(true)
                }
                else -> out.add(log.head())
            }
        }
        out
    }

    @Test fun ceilingsOf() = OracleCases.each(M, "ceilingsOf") { a -> GoalPrecedent.ceilingsOf(m(a[0])!!) }

    @Test fun answerBodyFor() = OracleCases.each(M, "answerBodyFor") { a ->
        val o = m(a[1])!!
        GoalPrecedent.answerBodyFor(m(a[0])!!, o["principal"] as String, o["decision"] as String, o["iat"], o["expires_at"], o["nonce"] as String)
    }

    @Test fun signRevocation() = OracleCases.each(M, "signRevocationSeed") { a -> GoalPrecedent.signRevocation(m(a[0])!!, Keys.unb64u(a[1] as String)) }
}
