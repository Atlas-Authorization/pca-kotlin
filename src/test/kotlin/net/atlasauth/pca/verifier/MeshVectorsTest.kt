package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The shared mesh corpus (`mesh-vectors.json`): whole mesh proofs with the TypeScript verdict. `ok` is reproduced on every vector,
 * `reason` and `hop` on every refusal (a `chain:` refusal by its prefix: the chain verifier words its own detail). A vector whose
 * `requires` names a signature suite this SDK does not implement must be refused (never accepted, never skipped).
 */
@Suppress("UNCHECKED_CAST")
class MeshVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("mesh-vectors.json") }

    @Test
    fun everyMeshVectorDecidesLikeTheReference() {
        val vecs = doc["mesh"] as List<Map<String, Any?>>
        assertTrue("expected at least 100 mesh vectors, got ${vecs.size}", vecs.size >= 100)
        val supported = Pq.supportedSuites().toSet()
        val bad = ArrayList<String>()
        for (v in vecs) {
            val name = v["name"] as String
            val expect = v["expect"] as Map<String, Any?>
            val got = Mesh.verifyMeshProof(v["proof"], v["trust"])
            val req = v["requires"] as? String
            if (req != null && req !in supported) {
                if (got.ok) bad.add("$name: requires $req (unimplemented) but was accepted")
                continue
            }
            val wantOk = expect["ok"] as Boolean
            if (got.ok != wantOk) { bad.add("$name: ok = ${got.ok} (reason '${got.reason}'), want $wantOk (reason '${expect["reason"]}')"); continue }
            if (wantOk) continue
            val wantReason = expect["reason"] as? String ?: ""
            if (wantReason.startsWith("chain:")) {
                if (!got.reason.startsWith("chain:")) bad.add("$name: reason '${got.reason}', want a chain refusal ('$wantReason')")
                continue
            }
            if (got.reason != wantReason) { bad.add("$name: reason '${got.reason}', want '$wantReason'"); continue }
            val wantHop = if (expect.containsKey("hop")) Json.asLong(expect["hop"]).toInt() else -1
            if (got.hop != wantHop) bad.add("$name: hop ${got.hop}, want $wantHop")
        }
        assertTrue("${bad.size}/${vecs.size} mesh vectors differ:\n" + bad.take(30).joinToString("\n"), bad.isEmpty())
    }

    @Test
    fun hostileInputsAreVerdictsNeverExceptions() {
        val trust = (doc["mesh"] as List<Map<String, Any?>>)[0]["trust"]
        for (s in listOf("null", "1", "\"x\"", "[]", "{}", "{\"chain\":[],\"hops\":[],\"heads\":[],\"rev_leaves\":[]}", "[null]")) {
            val r = Mesh.verifyMeshProof(ParityVectors.parse(s), trust)
            assertFalse(s, r.ok)
            assertEquals(s, -1, r.hop)
        }
        assertFalse(Mesh.verifyMeshProof(null, null).ok)
        assertEquals("invalid trust configuration", Mesh.verifyMeshProof(null, "x").reason)
    }
}
