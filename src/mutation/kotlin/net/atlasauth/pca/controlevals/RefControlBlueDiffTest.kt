package net.atlasauth.pca.controlevals

import net.atlasauth.pca.research.Immune
import net.atlasauth.pca.verifier.Approvals
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The blue control protocol against the reference (ref-control-blue, 362 cases): the example agent and its reviews, the example blue protocol, the decision
 * procedure behind every episode (replay, predicates and caveats through the agent review, data-flow governance, the immune-adapted metered budget) over every
 * configuration, red policy and hostile action, and the example evaluation. Numbers compare to a relative 1e-12 (the leak decays exponentially).
 *
 * Counted: the reference's review throws out of the episode when params carry an integer outside the safe range and a step-up request has to hash them
 * (5 cases); the native must refuse the same episode (a throw naming the canonical form), compared by that prefix.
 */
@Suppress("UNCHECKED_CAST")
class RefControlBlueDiffTest {
    private val mod = "ref-control-blue"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun d(o: Any?): Double = IntentJs.num(o)!!

    private fun agentOf(name: String): Facade.Handle {
        if (name == "example") return ControlEvalsExample.buildExampleAgent()
        val perms = LinkedHashMap<String, Any?>()
        perms["stripe"] = arrayListOf<Any?>("refund")
        perms["gmail"] = arrayListOf<Any?>("send", "draft")
        perms["files"] = arrayListOf<Any?>("read", "write")
        perms["github"] = arrayListOf<Any?>("read")
        val limits: Map<String, Any?>? = if (name == "cap50") linkedMapOf<String, Any?>("refund" to "\$50/day") else null
        return Facade.agent(Facade.AgentOptions(Keys.ed25519(Keys.edGenerate()), "handle refunds and customer email for October", perms, limits = limits, aud = "ins_example", now = 0L))
    }

    private fun blueOf(spec: Map<String, Any?>): ControlEvalsExample.PcaBlue {
        val b = ControlEvalsExample.exampleBlue(agentOf(spec["agent"] as String))
        if (spec["dlp"] == false) b.dlp = null
        if (spec["theta"] == "agent") b.basePolicy = null
        if (spec["stepMs"] != null) b.stepMsValue = IntentJs.lng(spec["stepMs"])
        if (spec["startMs"] != null) b.startMsValue = IntentJs.lng(spec["startMs"])
        (spec["immune"] as Map<String, Any?>?)?.let { im -> b.immune = Immune.Config(d(im["alpha"]), d(im["halfLifeMs"]), d(im["driftZSat"]), d(im["stepUpSat"]), d(im["denySat"])) }
        (spec["adapt"] as Map<String, Any?>?)?.let { ad -> b.adapt = ControlEvalsExample.AdaptConfig(d(ad["maxKappaMult"]), d(ad["minThetaMult"])) }
        return b
    }

    private fun red(name: String): ControlEvals.RedPolicy = when (name) {
        "over-cap" -> ControlEvals.overCapRed
        "off-verb" -> ControlEvals.offVerbRed
        "slow-burn" -> ControlEvals.slowBurnRed
        "taint-exfil" -> ControlEvals.taintExfilRed
        "replay" -> ControlEvals.replayRed
        "immune-probe" -> ControlEvals.immuneProbeBurstRed
        "benign" -> ControlEvals.benignBaselineRed
        "gap-exploit" -> ControlEvals.gapExploitRed()
        else -> throw IllegalArgumentException(name)
    }

    private fun env(name: String): ControlEvals.Env = if (name == "example") ControlEvals.exampleEnv else ControlEvals.gapAwareEnv()

    private fun review(a: Facade.Handle, e: Map<String, Any?>): Map<String, Any?> {
        val r = Approvals.reviewAction(a, e["verb"] as String, e["resource"] as String, e["params"] as? Map<String, Any?>, Approvals.ReviewOptions(now = IntentJs.lng(e["now"]), insecureUnboundApproval = true))
        val out = LinkedHashMap<String, Any?>(e)
        val rv = linkedMapOf<String, Any?>("kind" to r["kind"])
        if (r["reason"] != null) rv["reason"] = r["reason"]
        out["review"] = rv
        return out
    }

    private fun buildExampleAgent(a: List<Any?>, want: Map<String, Any?>): Any? {
        val agent = ControlEvalsExample.buildExampleAgent()
        val p = agent.policy
        val acts = p.actions.map { s ->
            val x = linkedMapOf<String, Any?>("connector" to s.connector, "action" to s.action, "verb" to s.verb, "reversibility" to s.reversibility, "blastRadius" to s.blastRadius)
            if (s.amountField != null) x["amountField"] = s.amountField
            if (s.resource != null) x["resource"] = s.resource
            x
        }
        return linkedMapOf(
            "policy" to linkedMapOf(
                "predicates" to p.predicates, "caveats" to p.caveats, "riskPolicy" to p.riskPolicy, "budgetModel" to p.budgetModel, "approximations" to p.approximations,
                "inputLimits" to p.inputLimits, "actions" to acts,
            ),
            "reviews" to l(want["reviews"]).map { review(agent, m(it)) },
        )
    }

    private fun call(c: Map<String, Any?>): Any? {
        val a = l(c["args"])
        return when (c["fn"]) {
            "buildExampleAgent" -> buildExampleAgent(a, m(c["out"]))
            "exampleBlue" -> {
                val b = ControlEvalsExample.exampleBlue(agentOf(a[0] as String))
                linkedMapOf("name" to b.name, "basePolicy" to b.basePolicy, "dlp" to b.dlp, "startMs" to b.startMs(), "stepMs" to b.stepMs())
            }
            "blueEpisode" -> {
                val spec = m(a[0])
                val red = if (a.size > 1) ControlEvals.RedPolicy("custom", "custom") { _ -> l(a[1]).map { m(it) } } else red(spec["red"] as String)
                ControlEvals.runEpisode(red, blueOf(m(spec["blue"])), env(spec["env"] as String), d(spec["seed"]))
            }
            "exampleEval" -> {
                val spec = m(a[0])
                ControlEvalsExample.exampleControlEval(spec["episodes"], spec["seed"])
            }
            else -> throw AssertionError("unhandled fn ${c["fn"]}")
        }
    }

    /** Deep equality with numbers compared to a relative 1e-12. */
    private fun same(w: Any?, g: Any?): Boolean {
        val wn = if (w is Map<*, *> || w is List<*> || w is String || w is Boolean || w == null) null else IntentJs.num(w)
        if (wn != null) {
            val gn = if (g is Map<*, *> || g is List<*> || g is String || g is Boolean || g == null) null else IntentJs.num(g)
            return gn != null && (wn == gn || Math.abs(wn - gn) <= 1e-12 * Math.max(1.0, Math.abs(wn)))
        }
        return when (w) {
            is Map<*, *> -> g is Map<*, *> && w.keys == g.keys && w.keys.all { same(w[it], g[it]) }
            is List<*> -> g is List<*> && w.size == g.size && w.indices.all { same(w[it], g[it]) }
            else -> w == g
        }
    }

    @Test fun everyCase() {
        val fns = setOf("buildExampleAgent", "exampleBlue", "blueEpisode", "exampleEval")
        val perFn = LinkedHashMap<String, Int>()
        var total = 0
        var refusals = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                perFn.merge(fn, 1, Int::plus)
                val want = c["out"]
                var got: Any? = null
                var err: Throwable? = null
                try { got = IntentJs.normalize(OracleCases.toJson(call(c))) } catch (t: Throwable) { err = t }
                if (want is Map<*, *> && want.containsKey("\$throws")) {
                    refusals++
                    if (err == null || err.message?.startsWith("canonicalize: ") != true) bad.add("${c["name"]}\n  want a canonicalize refusal (${want["\$throws"]})\n  got: ${err ?: Json.canonicalize(got)}")
                } else if (err != null) bad.add("${c["name"]}\n  want: ${Json.canonicalize(want)}\n  got:  THROWS $err")
                else if (!same(IntentJs.normalize(want), got)) bad.add("${c["name"]}\n  want: ${Json.canonicalize(want)}\n  got:  ${Json.canonicalize(got)}")
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(25).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(mapOf("buildExampleAgent" to 1, "exampleBlue" to 3, "blueEpisode" to 352, "exampleEval" to 6), perFn)
        assertEquals(362, total)
        assertEquals(5, refusals)
    }
}
