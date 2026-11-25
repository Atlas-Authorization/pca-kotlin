package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the runtime bridges (consent, calibration, effects, ramp and question cards). */
class IntentRuntimeDiffTest {
    private val m = "ref-intent-runtime"

    private fun map(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun d(o: Any?): Double = IntentOmega.dbl(o)

    private fun vs(o: Any?) = IntentOmega.verbSpaceFromJson(o)

    private fun out(o: Any?) = IntentOmega.outcomeFromJson(o)

    private fun idx(o: Any?): IntArray = IntentOmega.arr(o).let { l -> IntArray(l.size) { d(l[it]).toInt() } }

    private fun verbOf(omega: Any?, o: IntentOmega.Outcome) = IntentOmega.verbSpace(IntentOmega.omegaFromJson(omega), o.verb)!!

    @Test fun pcactnActionOf() = OracleCases.each(m, "pcactnActionOf") { a -> IntentRuntime.pcactnActionOf(vs(a[0]), out(a[1])) }

    @Test fun judgeInputOf() = OracleCases.each(m, "judgeInputOf") { a ->
        val o = out(a[1])
        IntentRuntime.judgeInputOf(verbOf(a[0], o), o, d(a[2]), map(a[3]))
    }

    @Test fun jitConsentRequest() = OracleCases.each(m, "jitConsentRequest") { a ->
        val o = out(a[1])
        val c = map(a[3])
        IntentRuntime.jitConsentRequest(verbOf(a[0], o), o, d(a[2]), c["intentRef"] as String?, c["mapDigest"] as String?)
    }

    @Test fun jitConsentDigest() = OracleCases.each(m, "jitConsentDigest") { a -> IntentRuntime.jitConsentDigest(a[0]) }

    @Test fun calibrationDigest() = OracleCases.each(m, "calibrationDigest") { a -> IntentRuntime.calibrationDigest(map(a[0])) }

    @Test fun icAttDigest() = OracleCases.each(m, "icAttDigest") { a -> IntentRuntime.icAttDigest(a[0]) }

    @Test fun foldSemanticRisk() = OracleCases.each(m, "foldSemanticRisk") { a -> IntentRuntime.foldSemanticRisk(d(a[0]), map(a[1])) }

    @Test fun defaultPostconditions() = OracleCases.each(m, "defaultPostconditions") { _ -> IntentEffects.DEFAULT_POSTCONDITIONS }

    @Test fun effectContext() = OracleCases.each(m, "effectContext") { a -> IntentEffects.effectContext(vs(a[0]), out(a[1]), map(a[2])) }

    @Test fun checkPostconditions() = OracleCases.each(m, "checkPostconditions") { a ->
        if (a.size > 3) IntentEffects.checkPostconditions(vs(a[0]), out(a[1]), map(a[2]), a[3] as List<*>)
        else IntentEffects.checkPostconditions(vs(a[0]), out(a[1]), map(a[2]))
    }

    @Test fun signalLabel() = OracleCases.each(m, "signalLabel") { a -> IntentRamp.signalLabel(a[0] as String?) }

    @Test fun narrowStart() = OracleCases.each(m, "narrowStart") { a ->
        val o = map(a[2])
        IntentRamp.narrowStart(IntentOmega.omegaFromJson(a[0]), a[1], if (o.containsKey("slotNullMass")) d(o["slotNullMass"]) else null,
            if (o.containsKey("otherNullMass")) d(o["otherNullMass"]) else null)
    }

    @Test fun driftRun() = OracleCases.each(m, "driftRun") { a ->
        val o = map(a[0])
        val dd = IntentRamp.DriftDetector(if (o.containsKey("rho0")) d(o["rho0"]) else null, if (o.containsKey("rho1")) d(o["rho1"]) else null,
            if (o.containsKey("h")) d(o["h"]) else null)
        val states = ArrayList<Any?>()
        for (x in a[1] as List<*>) states.add(dd.update(x as Boolean).toJson())
        states.add(dd.state().toJson())
        dd.reset()
        states.add(dd.state().toJson())
        states
    }

    @Test fun questionCard() = OracleCases.each(m, "questionCard") { a ->
        val q = map(a[1])
        IntentUx.questionCard(IntentOmega.omegaFromJson(a[0]), q["verb"] as String, idx(q["cell"]))
    }

    @Test fun parseCardAnswer() = OracleCases.each(m, "parseCardAnswer") { a -> IntentUx.parseCardAnswer(a[0], a[1]) }
}
