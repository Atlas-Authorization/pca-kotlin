package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The build-provenance corpus (`provenance-vectors.json`, track K9). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class ProvenanceVectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private val doc = ParityVectors.load("provenance-vectors.json")

    private fun rows(name: String): List<Any?> = m(doc["primitives"])[name] as List<Any?>

    private fun unhex(h: Any?): ByteArray {
        val s = h as String
        return ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    private fun same(want: Any?, got: Any?, name: Any?) = assertTrue("$name: want $want, got $got", IntentJs.jsonEquals(want, got))

    @Test
    fun merkleInclusion() {
        val rs = rows("merkle_inclusion")
        assertEquals(44, rs.size)
        for (x in rs) {
            val v = m(x)
            val i = m(v["input"])
            val ok = ProvenanceGate.verifyRfc9162Inclusion(
                ProvenanceGate.rfc9162LeafHash(unhex(i["leaf_hex"])),
                IntentJs.lng(i["index"]),
                IntentJs.lng(i["size"]),
                (i["proof_hex"] as List<Any?>).map { unhex(it) },
                unhex(i["root_hex"]),
            )
            same(v["expect"], mapOf("ok" to ok), v["name"])
        }
    }

    @Test
    fun gate() {
        val rs = rows("gate")
        assertEquals(45, rs.size)
        for (x in rs) {
            val v = m(x)
            val r = ProvenanceGate.provenanceGate(v["input"])
            val got: Map<String, Any?> = if (r.ok) mapOf("ok" to true, "level" to r.level, "claims" to r.claims) else mapOf("ok" to false, "code" to r.code)
            same(v["expect"], got, v["name"])
        }
    }

    @Test
    fun modelPath() {
        val rs = rows("model_path")
        assertEquals(7, rs.size)
        for (x in rs) {
            val v = m(x)
            same(v["expect"], mapOf("model" to PcaDecision.isModelDerivedPath(m(v["input"])["path"])), v["name"])
        }
    }

    @Test
    fun caveatDefaultsAndOrder() {
        val c = ProvenanceGate.provenanceCaveat(ProvenanceGate.CaveatOptions(issuer = "slsa", minLevel = 3, sourceRepo = "r"))
        same(
            Json.parseLenient(
                """{"type":"needs_discharge","id":"provenance","issuer":"slsa","issuer_class":"artifact","bind":"action","ttl_ms":300000,""" +
                    """"require":[{"claim":"slsa_level","op":"gte","value":3},{"claim":"source_repo","op":"eq","value":"r"},{"claim":"runtime_bound","op":"eq","value":true}]}""",
            ),
            c,
            "defaults",
        )
        assertNull(CaveatLang.needsDischargeError(c))
        val all = ProvenanceGate.provenanceCaveat(
            ProvenanceGate.CaveatOptions(
                issuer = "slsa", minLevel = 2, id = "prov", builderIds = listOf("b"), oidcIssuer = "i", requireRuntime = false, bind = "chain_hop", ttlMs = 1000L,
            ),
        )
        same(
            Json.parseLenient("""[{"claim":"slsa_level","op":"gte","value":2},{"claim":"builder_id","op":"in","value":["b"]},{"claim":"oidc_issuer","op":"eq","value":"i"}]"""),
            all["require"],
            "require",
        )
        assertEquals(listOf("prov", "chain_hop", 1000L), listOf(all["id"], all["bind"], all["ttl_ms"]))
    }
}
