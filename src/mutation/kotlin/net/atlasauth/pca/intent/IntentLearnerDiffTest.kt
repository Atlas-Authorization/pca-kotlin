package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentLearner.ElicitOptions
import net.atlasauth.pca.intent.IntentLearner.LearnerMetrics
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions
import net.atlasauth.pca.intent.IntentLearner.Question
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the elicitation learner: posterior, grant, questions, synthesis and the elicitation loop. */
class IntentLearnerDiffTest {
    private val m = "ref-intent-learner"

    private fun ints(a: IntArray): List<Any?> = a.map { it.toDouble() }

    private fun outcome(verb: String, values: Any?) = IntentOmega.outcomeFromJson(linkedMapOf("verb" to verb, "values" to values))

    private fun question(q: Question?): Map<String, Any?>? {
        if (q == null) return null
        return linkedMapOf("verb" to q.verb, "cell" to ints(q.cell), "outcome" to IntentOmega.outcomeToJson(q.outcome), "p" to q.p, "score" to q.score)
    }

    private fun metrics(r: LearnerMetrics): Map<String, Any?> = linkedMapOf(
        "residualRisk" to r.residualRisk, "burden" to r.burden, "uncertainty" to r.uncertainty, "entropyBits" to r.entropyBits,
        "log2VersionSpace" to r.log2VersionSpace, "disagreementMass" to r.disagreementMass, "meanHarm" to r.meanHarm,
        "questions" to r.questions.toDouble(), "conflicts" to r.conflicts.toDouble(),
    )

    private fun options(o: Any?): LearnerOptions {
        val mm = IntentOmega.obj(o)
        val opts = LearnerOptions.fromJson(o)
        if ("byRev" == mm["nullMassFn"]) opts.nullMassFn = { vs -> if (vs.reversibility == "reversible") 0.1 else 0.3 }
        if (mm["priorMix"] != null) {
            val pm = IntentOmega.obj(mm["priorMix"])
            val kind = pm["weight"] as String
            val wt = if (kind == "size") IntentLearner.PriorWeight { _, has ->
                var k = 1.0
                for (c in 0 until 64) if (has(c)) k++
                k
            } else if (kind == "neg") IntentLearner.PriorWeight { _, _ -> -1.0 } else IntentLearner.PriorWeight { _, _ -> 0.0 }
            opts.priorMix = IntentLearner.PriorMix(IntentOmega.dbl(pm["beta"]), wt)
        }
        return opts
    }

    private fun scenario(a: List<Any?>): Any? {
        val omega = IntentOmega.omegaFromJson(a[0])
        val opts = options(a[1])
        val l = IntentLearner(omega, opts)
        val out = ArrayList<Any?>()
        for (oo in IntentOmega.arr(a[2])) {
            val op = IntentOmega.obj(oo)
            when (op["op"] as String) {
                "observe" -> {
                    val src = if (op["source"] == null) "elicitation" else op["source"] as String
                    val region = if (op["region"] == null) null else IntentRegion.Region.fromJson(op["region"])
                    val ob = l.observe(outcome(op["verb"] as String, op["values"]), IntentOmega.dbl(op["y"]).toInt(), src, region)
                    out.add(ob?.toJson())
                }
                "probe" -> {
                    val oc = outcome(op["verb"] as String, op["values"])
                    out.add(listOf(l.acceptance(oc), l.admitsOutcome(oc), l.isVetoed(oc)))
                }
                "next" -> out.add(question(l.nextQuestion()))
                "metrics" -> out.add(metrics(l.metrics()))
                "cells" -> out.add(l.cells().map { c ->
                    linkedMapOf("verb" to c.verb, "cell" to ints(c.cell), "p" to c.p, "mass" to c.mass, "harm" to c.harm, "inGrant" to c.inGrant, "vetoed" to c.vetoed)
                })
                "unconfirmed" -> out.add(l.unconfirmedGrantCells().map { c -> linkedMapOf("verb" to c.verb, "cell" to ints(c.cell), "weight" to c.weight) })
                "synth" -> {
                    val s = l.synthesize()
                    out.add(linkedMapOf("predicates" to s.predicates, "caveats" to s.caveats))
                }
                "vetoed" -> out.add(l.vetoedCells())
                "observations" -> out.add(l.observations.map { it.toJson() })
                "replay" -> out.add(metrics(IntentLearner.replay(omega, opts, l.observations).metrics()))
                "elicit" -> out.add(elicit(l, omega, op))
                else -> throw IllegalArgumentException("bad op")
            }
        }
        return out
    }

    private fun elicit(l: IntentLearner, omega: IntentOmega.Omega, op: Map<String, Any?>): Any? {
        val adm = IntentPolicy.admitter(op["policy"])
        val flip = if (op["flipEvery"] == null) 0 else IntentOmega.dbl(op["flipEvery"]).toInt()
        val k = intArrayOf(0)
        val ans = IntentLearner.Answer { q ->
            val vs = omega.verbs.last { it.verb == q.verb }
            val y = if (adm.admits(vs, q.outcome)) 1 else 0
            k[0]++
            if (flip != 0 && k[0] % flip == 0) 1 - y else y
        }
        val eo = ElicitOptions(IntentOmega.dbl(op["epsRisk"]), IntentOmega.dbl(op["epsBurden"]), IntentOmega.dbl(op["maxQuestions"]).toInt(), op["audit"] == true)
        if (op["seed"] != null) {
            for (s in IntentOmega.arr(op["seed"])) {
                val sm = IntentOmega.obj(s)
                val cl = IntentOmega.arr(sm["cell"])
                eo.seed.add(Pair(sm["verb"] as String, IntArray(cl.size) { IntentOmega.dbl(cl[it]).toInt() }))
            }
        }
        val r = IntentLearner.elicit(l, ans, eo)
        return linkedMapOf(
            "stop" to r.stop, "questions" to r.questions.toDouble(), "auditQuestions" to r.auditQuestions.toDouble(), "seedQuestions" to r.seedQuestions.toDouble(),
            "asked" to r.asked.map { question(it) }, "metrics" to metrics(l.metrics()),
        )
    }

    @Test fun scenarios() = OracleCases.each(m, "scenario") { a -> scenario(a) }

    @Test fun hypothesisCellSets() = OracleCases.each(m, "hypothesisCellSets") { a ->
        val vs = IntentOmega.verbSpaceFromJson(a[0])
        val hc = if (a[1] == null) null else IntentLearner.HypothesisClassSpec.fromJson(a[1])
        var mh: Int? = null
        if (a.size > 2 && a[2] != null) mh = IntentOmega.dbl(IntentOmega.obj(a[2])["maxHypotheses"]).toInt()
        val r = IntentLearner.hypothesisCellSets(vs, hc, mh, null)
        if (a.size > 2 || a[1] == null) r.sets.size.toDouble()
        else linkedMapOf("sets" to r.sets.map { s -> s.map { if (it) 1.0 else 0.0 } }, "complexity" to ArrayList<Any?>(r.complexity))
    }

    @Test fun hypothesisClassName() = OracleCases.each(m, "hypothesisClassName") { a -> IntentLearner.hypothesisClassName(IntentLearner.HypothesisClassSpec.fromJson(a[0])) }

    @Test fun boxesToPredicates() = OracleCases.each(m, "boxesToPredicates") { a ->
        val al = IntentOmega.arr(a[1])
        IntentLearner.boxesToPredicates(IntentOmega.verbSpaceFromJson(a[0]), BooleanArray(al.size) { IntentOmega.dbl(al[it]).toInt() != 0 })
    }
}
