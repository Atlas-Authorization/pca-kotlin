package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal core: tape codec, digests, normalize, fmt, card, reference semantics, binding, signing. */
@Suppress("UNCHECKED_CAST")
class GoalDiffTest {
    private val M = "ref-goal"

    private fun m(o: Any?): Map<String, Any?> = if (o is Map<*, *>) o as Map<String, Any?> else throw NullPointerException("object expected")
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun s(o: Any?): String = o as String
    private fun dbl(o: Any?): Double = if (o is Json.Num) o.raw.toDouble() else o.toString().toDouble()

    @Test fun encodeGoal() = OracleCases.each(M, "encodeGoal") { a -> GoalCodec.encodeGoal(m(a[0])) }
    @Test fun decodeGoal() = OracleCases.each(M, "decodeGoal") { a -> GoalCodec.decodeGoal(l(a[0])) }
    @Test fun encodeOntology() = OracleCases.each(M, "encodeOntology") { a -> GoalCodec.encodeOntology(m(a[0])) }
    @Test fun encodeAct() = OracleCases.each(M, "encodeAct") { a -> GoalCodec.encodeAct(m(a[0])) }
    @Test fun encodeHist() = OracleCases.each(M, "encodeHist") { a -> GoalCodec.encodeHist(m(a[0])) }
    @Test fun decodePolicy() = OracleCases.each(M, "decodePolicy") { a -> GoalCodec.decodePolicy(l(a[0])) }

    @Test fun goalDigest() = OracleCases.each(M, "goalDigest") { a -> GoalDigests.goalDigest(a[0]) }
    @Test fun nlDigest() = OracleCases.each(M, "nlDigest") { a -> GoalDigests.nlDigest(s(a[0])) }
    @Test fun modelSetDigest() = OracleCases.each(M, "modelSetDigest") { a -> GoalDigests.modelSetDigest(l(a[0]).map { s(it) }) }
    @Test fun approvalDigest() = OracleCases.each(M, "approvalDigest") { a -> GoalDigests.approvalDigest(m(a[0])) }
    @Test fun canonicalizeGoal() = OracleCases.each(M, "canonicalizeGoal") { a -> GoalNormalize.canonicalizeGoal(m(a[0])) }
    @Test fun stable() = OracleCases.each(M, "stable") { a -> GoalNormalize.stable(a[0]) }

    @Test fun fmtMoney() = OracleCases.each(M, "fmtMoney") { a -> GoalFmt.fmtMoney(s(a[0]), a[1]) }
    @Test fun fmtQuantity() = OracleCases.each(M, "fmtQuantity") { a -> GoalFmt.fmtQuantity(m(a[0])) }
    @Test fun fmtValue() = OracleCases.each(M, "fmtValue") { a -> GoalFmt.fmtValue(m(a[0])) }
    @Test fun fmtAct() = OracleCases.each(M, "fmtAct") { a -> GoalFmt.fmtAct(m(a[0])) }
    @Test fun renderCard() = OracleCases.each(M, "renderCard") { a -> GoalCard.renderCard(m(a[0])) }
    @Test fun renderCond() = OracleCases.each(M, "renderCond") { a -> GoalCard.cond(m(a[0])) }

    @Test fun refExplain() = OracleCases.each(M, "refExplain") { a -> GoalRefsem.refExplain(m(a[0]), m(a[1]), m(a[2]), m(a[3])) }
    @Test fun refDecide() = OracleCases.each(M, "refDecide") { a -> GoalRefsem.refDecide(m(a[0]), m(a[1]), m(a[2]), m(a[3])) }
    @Test fun canonicalPolicy() = OracleCases.each(M, "canonicalPolicy") { a -> GoalCompiler.canonicalPolicy(m(a[0])) }
    @Test fun policyDigest() = OracleCases.each(M, "policyDigest") { a -> GoalCompiler.policyDigest(m(a[0])) }

    @Test fun actionDigest() = OracleCases.each(M, "actionDigest") { a -> GoalBinding.actionDigest(m(a[0])) }
    @Test fun bindDecision() = OracleCases.each(M, "bindDecision") { a -> GoalBinding.bindDecision(m(a[0]), s(a[1])) }
    @Test fun guardExecute() = OracleCases.each(M, "guardExecute") { a -> GoalBinding.guardExecute(a[0] as Map<String, Any?>?, m(a[1])) }
    @Test fun claimGate() = OracleCases.each(M, "claimGate") { a -> GoalBinding.claimGate(s(a[0]), dbl(a[1]), if (a[2] == null) null else dbl(a[2])) }
    @Test fun goalCommit() = OracleCases.each(M, "goalCommit") { a -> GoalBinding.goalCommit(s(a[0]), s(a[1]), s(a[2])) }
    @Test fun openCommit() = OracleCases.each(M, "openCommit") { a -> GoalBinding.openCommit(s(a[0]), s(a[1]), s(a[2]), s(a[3])) }

    @Test fun signPayload() = OracleCases.each(M, "signPayloadSeed") { a -> GoalSign.signPayload(s(a[0]), a[1], Keys.unb64u(s(a[2]))) }
    @Test fun signGoalArtifact() = OracleCases.each(M, "signGoalArtifactSeed") { a -> GoalSign.signGoalArtifact(s(a[0]), m(a[1]), Keys.unb64u(s(a[2]))) }
    @Test fun signerId() = OracleCases.each(M, "signerId") { a -> GoalSign.signerId(Keys.unb64u(s(a[0]))) }
    @Test fun goalDomain() = OracleCases.each(M, "goalDomain") { a -> GoalSign.goalDomain(s(a[0])) }
    @Test fun verifyPayload() = OracleCases.each(M, "verifyPayload") { a -> GoalSign.verifyPayload(if (a[0] is Map<*, *>) m(a[0]) else null, s(a[1]), l(a[2])) }
    @Test fun verifyGoalArtifact() = OracleCases.each(M, "verifyGoalArtifact") { a -> GoalSign.verifyGoalArtifact(s(a[0]), a[1], s(a[2]), l(a[3])) }
}
