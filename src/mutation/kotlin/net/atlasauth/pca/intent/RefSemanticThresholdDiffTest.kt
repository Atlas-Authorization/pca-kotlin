package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The semantic judge threshold against the reference (ref-semantic-threshold, 186 cases): the signed statement and message, verdict signing under
 * Ed25519, ML-DSA-65 and the hybrid suite (signature bytes compare), verdict and attestation verification, the k-of-n threshold with the attested-judge
 * gate and PQ pins, the hook and the risk contribution. A non-finite number is {"$num": text} on both sides. The two cases the reference accepts only
 * through its legacy `allowUnboundPq` option are asserted refused (the option is not offered: a PQ key the verdict carries is never trusted by itself).
 */
@Suppress("UNCHECKED_CAST")
class RefSemanticThresholdDiffTest {
    private val mod = "ref-semantic-threshold"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun enc(v: Any?): Any? = when (v) {
        is Double -> if (v.isNaN() || v.isInfinite()) linkedMapOf<String, Any?>("\$num" to Json.jsNumberText(v)) else v
        is Json.Num -> if (v.raw == "NaN" || v.raw.endsWith("Infinity")) linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is Map<*, *> -> (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { enc(it.value) }
        is List<*> -> v.map { enc(it) }
        else -> v
    }

    private fun signer(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun attestationOf(o: Any?): IntentSemantic.SemanticAttestation? {
        val m = o as Map<String, Any?>? ?: return null
        val by = m["byJudge"] as Map<String, Any?>? ?: emptyMap()
        return IntentSemantic.SemanticAttestation({ v -> by[v["judge"]] }, m["approved"], m["require"] == true)
    }

    private fun threshold(a: List<Any?>): Any? {
        val o = LinkedHashMap(map(a[1]))
        val att = attestationOf(o.remove("attestation"))
        o.remove("allowUnboundPq")
        val r = IntentSemantic.verifySemanticThreshold(a[0], o, att)
        return enc(r)
    }

    private fun hook(a: List<Any?>): Any? {
        val o = map(a[0])
        val mode = o["actionDigestMode"] as String? ?: "default"
        val fixed: ((Any?) -> String)? = if (mode.startsWith("fixed:")) { _ -> mode.substring(6) } else null
        val h = IntentSemantic.createSemanticVerifier(
            o["judgeKeys"], o["k"], { ctx -> IntentJs.get(ctx, "verdicts") }, { ctx -> IntentJs.get(ctx, "goal") }, o["calibration"], fixed, o["optionalWhenAbsent"] == true,
            { ctx -> attestationOf(IntentJs.get(ctx, "attestation")) },
        )
        return (a[1] as List<Any?>).map { h(it) }
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf("SEMANTIC_JUDGE_DOMAIN" to IntentSemantic.SEMANTIC_JUDGE_DOMAIN, "SCORE_SCALE" to IntentSemantic.SCORE_SCALE.toLong())
        "quantizeScore" -> if (IntentOmega.isNumber(a[0])) IntentSemantic.quantizeScore(IntentOmega.dbl(a[0])) else 0L // Number.isFinite of a non-number is false
        "statementOf" -> IntentSemantic.statementOf(map(a[0]))
        "semanticJudgeMessage" -> IntentSemantic.semanticJudgeMessage(a[0])
        "verdictDigest" -> IntentSemantic.verdictDigest(a[0])
        "signJudgeVerdict" -> enc(IntentSemantic.signJudgeVerdict(signer(a[0], arg(a, 2)), map(a[1])))
        "verifyJudgeVerdict" -> {
            val e = map(a[1])
            val pins = (arg(a, 2) as Map<String, Any?>?)?.get("pqPins") as Map<String, Any?>?
            IntentSemantic.verifyJudgeVerdict(a[0], e["actionDigest"] as String?, e["goalCommitment"] as String?, pins)
        }
        "verifyJudgeAttestation" -> IntentSemantic.verifyJudgeAttestation(a[0], arg(a, 1), arg(a, 2))
        "verifySemanticThreshold" -> threshold(a)
        "semanticVerifier" -> hook(a)
        "semanticRiskContribution" -> IntentSemantic.semanticRiskContribution(a[0])
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val unboundOnly = setOf("verifyJudgeVerdict/pq-unbound#92", "verifySemanticThreshold/pq-unbound#157")

    @Test fun everyFunction() {
        val fns = setOf(
            "constants", "quantizeScore", "statementOf", "semanticJudgeMessage", "verdictDigest", "signJudgeVerdict", "verifyJudgeVerdict", "verifyJudgeAttestation",
            "verifySemanticThreshold", "semanticVerifier", "semanticRiskContribution",
        )
        var total = 0
        var refused = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val args = OracleCases.decNum(c["args"]) as List<Any?>
                if (c["name"] in unboundOnly) {
                    val r = call(fn, args)
                    if (fn == "verifyJudgeVerdict") assertFalse(c["name"].toString(), r as Boolean) else assertEquals(c["name"].toString(), false, map(r)["ok"])
                    refused++
                    continue
                }
                val case = LinkedHashMap(c)
                case["args"] = args
                OracleCases.diff(case, c["out"]) { x -> call(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(2, refused)
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(186, total)
    }
}
