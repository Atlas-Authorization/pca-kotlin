package net.atlasauth.pca.harness

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference vectors of the attested orchestration harness through the native port. */
@Suppress("UNCHECKED_CAST")
class HarnessDiffTest {
    private val M = "ref-harness"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun consts() = OracleCases.each(M, "consts") {
        linkedMapOf("HARNESS_VERSION" to Harness.HARNESS_VERSION, "HARNESS_MODEL_ID" to Harness.HARNESS_MODEL_ID, "ENFORCED_CHECKS" to Harness.ENFORCED_CHECKS)
    }

    @Test fun measurement() = OracleCases.each(M, "computeHarnessMeasurement") { a -> Harness.computeHarnessMeasurement(a[0], a[1], a[2]) }

    @Test fun attestationVerifier() = OracleCases.each(M, "harnessAttest") { a -> Harness.createHarnessAttestationVerifier(a[0])(a[1]) }

    @Test fun harness() = OracleCases.each(M, "harness") { a ->
        val spec = m(a[0])
        val op = m(spec["opts"])
        var t = 1_800_000_000_000L
        var k = 0
        val h: Harness
        try {
            val o = Harness.Options()
            o.grant = m(op["grant"])
            o.chain = if (op["chain"] == null) null else l(op["chain"])
            o.agentSeed = OracleCases.seed(op["label"] as String)
            o.plan = op["plan"]
            o.audience = op["audience"]
            o.budget = op["budget"]
            o.policy = if (op["policy"] == null) null else m(op["policy"])
            o.baseRisk = if (op["baseRisk"] == null) null else m(op["baseRisk"])
            o.now = { t }
            o.ttlMs = if (op["ttlMs"] == null) null else IntentJs.num(op["ttlMs"])!!.toLong()
            o.measurementManifest = if (op["manifest"] == null) null else l(op["manifest"]).map { it as String }
            o.nonce = { "n" + (k++) }
            o.attestation = if (op["attestation"] == null) null else m(op["attestation"])
            h = Harness(o)
        } catch (e: RuntimeException) {
            return@each linkedMapOf("\$err" to true)
        }
        val outs = ArrayList<Any?>()
        for (s in l(spec["steps"])) {
            val st = m(s)
            if ("now" == st["op"]) { t = IntentJs.num(st["t"])!!.toLong(); outs.add(null); continue }
            val orc = m(st["oracle"])
            outs.add(h.step {
                if ("throw" == orc["kind"]) throw IllegalStateException(orc["msg"] as String)
                if ("bad" == orc["kind"]) orc["v"] else orc["c"]
            })
        }
        linkedMapOf("steps" to outs, "budget" to h.budget(), "counter" to h.counter(), "planRoot" to h.planRoot(), "measurement" to h.harnessMeasurement())
    }

    @Test fun randomNonceIsHex() {
        val o = Harness.Options()
        o.grant = linkedMapOf("id" to "g")
        o.agentSeed = ByteArray(32)
        o.plan = arrayListOf<Any?>(linkedMapOf("id" to "n1", "verb" to "read", "resource" to "doc:1"))
        o.audience = "aud"
        o.budget = linkedMapOf("B" to Json.Num("1"), "tau" to Json.Num("0"), "asOf" to Json.Num("0"))
        o.now = { 0L }
        val cand = linkedMapOf<String, Any?>("verb" to "read", "resource" to "doc:1", "nodeId" to "n1")
        val r = Harness(o).step { cand }
        assertTrue(r["ok"] == true)
        assertTrue(((m(r["pcactn"])["nonce"]) as String).matches(Regex("[0-9a-f]{32}")))
    }
}
