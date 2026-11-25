package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The post-quantum software attestation root against the reference (ref-attest-pq-software, 137 cases): the constants, statement minting under the ML-DSA
 * suites (bytes compare), the construction refusals, and the verifier over every suite, trust, signature, binding and policy refusal.
 */
@Suppress("UNCHECKED_CAST")
class RefAttestPqSoftwareDiffTest {
    private val mod = "ref-attest-pq-software"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict(if (o is Map<*, *>) o["\$bytes"] else o, 32) ?: throw IllegalArgumentException("not a key seed")

    private fun attestor(spec: Map<String, Any?>, name: String): AttestPqSoftware.Attestor {
        val alg = spec["alg"]
        val prim = if (name.contains("wrong-key-family")) Pq.Prim.ML_DSA_65 else Pq.resolveSigAlg(alg, true)?.pq ?: Pq.Prim.ML_DSA_65
        val pq = spec["seed"]?.let { Keys.pqFromSeed(prim, seed(it)) }
        val ed = spec["edSecret"]?.let { Keys.edFromSeed(seed(it)) }
        return AttestPqSoftware.createPqSoftwareAttestor(alg, ed, pq)
    }

    private fun publicKeys(a: AttestPqSoftware.Attestor): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("pqPublicKey" to a.pqPublicKey)
        a.ed25519PublicKey?.let { m["ed25519PublicKey"] = it }
        return m
    }

    private fun verify(a: List<Any?>): Any? {
        val sc = map(a[0])
        val config = map(sc["config"])
        val evidence = sc["evidence"]
        val resolver = if (config["noEvidenceSeam"] == true) null else AttestPqSoftware.EvidenceResolver { _, _ -> evidence }
        val v = AttestPqSoftware.createPqSoftwareVerifier(config, resolver)
        return v.verify(map(sc["input"]))
    }

    private fun build(a: List<Any?>): Any? {
        AttestPqSoftware.createPqSoftwareVerifier(map(a[0]), AttestPqSoftware.EvidenceResolver { _, _ -> null })
        return linkedMapOf("built" to true)
    }

    @Test fun everyFunction() {
        val fns = setOf("constants", "attest", "buildAttestor", "verifyPq", "buildVerifier")
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val name = c["name"] as String
                val case = LinkedHashMap(c)
                case["args"] = OracleCases.decNum(c["args"])
                OracleCases.diff(case, c["out"]) { a ->
                    when (fn) {
                        "constants" -> linkedMapOf("PQ_ATTEST_DOMAIN" to AttestPqSoftware.PQ_ATTEST_DOMAIN)
                        "attest" -> {
                            val at = attestor(map(a[0]), name)
                            publicKeys(at).also { it["statement"] = at.attest(map(a[1])) }
                        }
                        "buildAttestor" -> publicKeys(attestor(map(a[0]), name))
                        "verifyPq" -> verify(a)
                        else -> build(a)
                    }
                }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(137, total)
    }
}
