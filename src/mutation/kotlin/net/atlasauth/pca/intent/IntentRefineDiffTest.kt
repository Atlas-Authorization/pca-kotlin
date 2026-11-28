package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.intent.IntentRefine.PartialAnswer
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of cut refinement, partial answers and adaptive elicitation. */
@Suppress("UNCHECKED_CAST")
class IntentRefineDiffTest {
    private val m = "ref-intent-refine"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun ints(a: IntArray): List<Any?> = a.map { it.toDouble() }

    private fun make(omega: Any?, mapOpts: Any?, obs: Any?): IntentLearner {
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts))
        for (xo in ls(obs)) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, if (x["region"] == null) null else IntentRegion.Region.fromJson(x["region"]))
        }
        return l
    }

    private fun observations(l: IntentLearner): List<Any?> = l.observations.map { it.toJson() }

    private fun metrics(r: IntentLearner.LearnerMetrics): Map<String, Any?> = linkedMapOf(
        "residualRisk" to r.residualRisk, "burden" to r.burden, "uncertainty" to r.uncertainty, "entropyBits" to r.entropyBits,
        "log2VersionSpace" to r.log2VersionSpace, "disagreementMass" to r.disagreementMass, "meanHarm" to r.meanHarm,
        "questions" to r.questions.toDouble(), "conflicts" to r.conflicts.toDouble(),
    )

    private fun cells(l: IntentLearner): List<Any?> = l.cells().map { c -> linkedMapOf("verb" to c.verb, "cell" to ints(c.cell), "p" to c.p) }

    private fun synth(l: IntentLearner): Map<String, Any?> {
        val s = l.synthesize()
        return linkedMapOf("predicates" to s.predicates, "caveats" to s.caveats)
    }

    private fun cellOf(o: Any?): IntArray = ls(o).let { cl -> IntArray(cl.size) { IntentOmega.dbl(cl[it]).toInt() } }

    @Test fun refineOmega() = OracleCases.each(m, "refineOmega") { a ->
        IntentOmega.omegaToJson(IntentRefine.refineOmega(IntentOmega.omegaFromJson(a[0]), IntentRefine.Refinement.fromJson(a[1])))
    }

    @Test fun regionsOf() = OracleCases.each(m, "regionsOf") { a ->
        val l = make(a[0], a[1], a[2])
        val om = if (a[3] == true) IntentOmega.Omega(ArrayList(), ArrayList()) else l.omega
        l.observations.map { IntentRefine.regionOfObservation(om, it).toJson() }
    }

    @Test fun refineScenario() = OracleCases.each(m, "refineScenario") { a ->
        val l = make(a[0], a[1], a[2])
        val nl = IntentRefine.refineLearner(l, IntentRefine.Refinement.fromJson(a[3]), null)
        linkedMapOf("omega" to IntentOmega.omegaToJson(nl.omega), "observations" to observations(nl), "metrics" to metrics(nl.metrics()), "cells" to cells(nl))
    }

    @Test fun partialScenario() = OracleCases.each(m, "partialScenario") { a ->
        val l = make(a[0], a[1], a[2])
        val q = mp(a[3])
        val verb = q["verb"] as String
        val vs = l.omega.verbs.lastOrNull { it.verb == verb }
        val cell = cellOf(q["cell"])
        val oc = if (vs == null) IntentOmega.Outcome(verb, LinkedHashMap()) else IntentOmega.cellRep(vs, cell)
        val question = IntentLearner.Question(verb, cell, oc, l.acceptance(oc), 0.0)
        val r = IntentRefine.answerPartial(l, question, PartialAnswer.fromJson(a[4]))
        val added: List<Any?> = r.added.map { it.toJson() }
        if (verb == "nope") added
        else linkedMapOf(
            "omega" to IntentOmega.omegaToJson(r.learner.omega), "added" to added, "observations" to observations(r.learner),
            "metrics" to metrics(r.learner.metrics()), "synth" to synth(r.learner),
        )
    }

    @Test fun adaptiveScenario() = OracleCases.each(m, "adaptiveScenario") { a ->
        val l0 = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a[0]), MapLearnerOptions.fromJson(a[1]))
        val adm = IntentPolicy.admitter(a[2])
        val ps = ls(a[3]).map { PartialAnswer.fromJson(it) }
        val ev = IntentOmega.dbl(a[4]).toInt()
        val oo = mp(a[5])
        val kp = intArrayOf(0, 0)
        val ans = IntentRefine.AdaptiveAnswer { q, l ->
            kp[0]++
            if (kp[0] % ev == 0 && kp[1] < ps.size && q.verb == "stripe.refund") ps[kp[1]++]
            else {
                val vs = l.omega.verbs.last { it.verb == q.verb }
                if (adm.admits(vs, q.outcome)) 1 else 0
            }
        }
        val eo = IntentLearner.ElicitOptions(0.001, 0.01, if (oo["maxQuestions"] == null) 25 else IntentOmega.dbl(oo["maxQuestions"]).toInt(), oo["audit"] == true)
        if (oo["seed"] != null) {
            for (s in ls(oo["seed"])) {
                val sm = mp(s)
                eo.seed.add(Pair(sm["verb"] as String, cellOf(sm["cell"])))
            }
        }
        val maxRef = if (oo["maxRefinements"] == null) null else IntentOmega.dbl(oo["maxRefinements"]).toInt()
        val r = IntentRefine.elicitAdaptive(l0, ans, eo, maxRef)
        linkedMapOf(
            "stop" to r.stop, "questions" to r.questions.toDouble(), "auditQuestions" to r.auditQuestions.toDouble(), "seedQuestions" to r.seedQuestions.toDouble(),
            "refinements" to r.refinements.toDouble(),
            "asked" to r.asked.map { q -> linkedMapOf("verb" to q.verb, "cell" to ints(q.cell), "outcome" to IntentOmega.outcomeToJson(q.outcome), "p" to q.p, "score" to q.score) },
            "omega" to IntentOmega.omegaToJson(r.learner.omega), "metrics" to metrics(r.learner.metrics()), "observations" to observations(r.learner),
        )
    }
}
