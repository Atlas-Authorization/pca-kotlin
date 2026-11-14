package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The leaf holder's action signature and the compact mesh proof the producer assembles from per-hop evidence. */
@Suppress("UNCHECKED_CAST")
class Kill15MeshProofTest {
    private val leaf = Keys.edFromSeed(ByteArray(32) { 11 })

    private fun obj(vararg kv: Pair<String, Any?>) = Issue.obj(*kv)
    private fun canon(o: Any?) = Json.canonicalize(o)
    private fun l(o: Any?) = o as List<Any?>
    private fun m(o: Any?) = o as Map<String, Any?>

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private val cap0 = obj("id" to "cap-0", "holder" to "h0")
    private val cap1 = obj("id" to "cap-1", "holder" to "h1")
    private val action = obj("verb" to "read", "resource" to "doc/1")

    @Test fun theLeafSignsTheActionBoundToTheLastHopOfTheChain() {
        val sig = SignersMore.signMeshAction(listOf(cap0, cap1), action, leaf)
        val msg = Pca.concat(Mesh.ACTION_DOMAIN.toByteArray(Charsets.UTF_8),
            Pca.canonBytes(obj("action" to action, "tip" to Pca.capHash(cap1))))
        assertEquals(Pca.b64(leaf.sign(msg)), sig)
        val first = Pca.concat(Mesh.ACTION_DOMAIN.toByteArray(Charsets.UTF_8),
            Pca.canonBytes(obj("action" to action, "tip" to Pca.capHash(cap0))))
        assertTrue(sig != Pca.b64(leaf.sign(first)))
        // a one-hop chain is accepted
        assertEquals(Pca.b64(leaf.sign(first)), SignersMore.signMeshAction(listOf(cap0), action, leaf))
    }

    @Test fun anEmptyChainIsRefused() {
        assertEquals("signMeshAction: empty chain", refusal { SignersMore.signMeshAction(emptyList(), action, leaf) })
        assertEquals("signMeshAction: empty chain", refusal { SignersMore.signMeshAction(null, action, leaf) })
    }

    private fun leafOf(id: String) = obj("id" to id)

    private fun head(n: Long, root: String) = obj("size" to n, "root" to root)

    private fun cosig(w: String) = obj("witness" to w, "sig" to "sig-$w")

    @Test fun hopsOnTheSameHeadShareOneTableEntryAndLeavesAreCarriedOnce() {
        val h1 = head(1L, "r1")
        val h2 = head(2L, "r2")
        val hop0Cosigs = arrayListOf<Any?>(cosig("w1"))
        val hop0 = obj("domain" to "d0", "head" to obj("head" to h1, "sig" to "s1", "cosigs" to hop0Cosigs), "inclusion" to obj("path" to listOf("x")),
            "revocation" to obj("cap" to obj("size" to 2L, "lo" to leafOf("L1"), "hi" to leafOf("H1")), "issuer_key" to obj("size" to 2L, "lo" to leafOf("L1"))),
            "binding" to obj("b" to 1L))
        val hop1 = obj("domain" to "d1", "head" to obj("head" to h1, "sig" to "s1", "cosigs" to listOf(cosig("w1"), cosig("w2"))), "inclusion" to obj("path" to listOf("y")),
            "revocation" to obj("cap" to obj("size" to 3L, "lo" to leafOf("L2")), "issuer_key" to obj("size" to 2L, "hi" to leafOf("H1"))))
        val hop2 = obj("domain" to "d2", "head" to obj("head" to h1, "sig" to "s2", "cosigs" to emptyList<Any?>()), "inclusion" to obj("path" to emptyList<Any?>()),
            "revocation" to obj("cap" to obj("size" to 5L, "lo" to leafOf("L1")), "issuer_key" to obj("size" to 1L)))
        val hop3 = obj("domain" to "d3", "head" to obj("head" to h2, "sig" to "s1", "cosigs" to listOf(cosig("w3"))), "inclusion" to obj("path" to listOf("z")),
            "revocation" to obj("cap" to obj("size" to 1L), "issuer_key" to obj("size" to 1L)), "binding" to null)
        val chain = listOf<Any?>(cap0, cap1)
        val p = SignersMore.assembleMeshProof(chain, listOf(hop0, hop1, hop2, hop3), action, leaf)

        val expected = obj(
            "chain" to listOf(cap0, cap1),
            "heads" to listOf(
                obj("head" to h1, "sig" to "s1", "cosigs" to listOf(cosig("w1"), cosig("w2"))),
                obj("head" to h1, "sig" to "s2", "cosigs" to emptyList<Any?>()),
                obj("head" to h2, "sig" to "s1", "cosigs" to listOf(cosig("w3"))),
            ),
            "rev_leaves" to listOf(leafOf("L1"), leafOf("H1"), leafOf("L2")),
            "hops" to listOf(
                obj("domain" to "d0", "head" to 0L, "inclusion" to obj("path" to listOf("x")),
                    "revocation" to obj("cap" to obj("size" to 2L, "lo" to 0L, "hi" to 1L), "issuer_key" to obj("size" to 2L, "lo" to 0L)), "binding" to obj("b" to 1L)),
                obj("domain" to "d1", "head" to 0L, "inclusion" to obj("path" to listOf("y")),
                    "revocation" to obj("cap" to obj("size" to 3L, "lo" to 2L), "issuer_key" to obj("size" to 2L, "hi" to 1L))),
                obj("domain" to "d2", "head" to 1L, "inclusion" to obj("path" to emptyList<Any?>()),
                    "revocation" to obj("cap" to obj("size" to 5L, "lo" to 0L), "issuer_key" to obj("size" to 1L))),
                obj("domain" to "d3", "head" to 2L, "inclusion" to obj("path" to listOf("z")),
                    "revocation" to obj("cap" to obj("size" to 1L), "issuer_key" to obj("size" to 1L))),
            ),
            "action" to action,
            "action_sig" to SignersMore.signMeshAction(chain, action, leaf),
        )
        assertEquals(canon(expected), canon(p))
        assertEquals(setOf("chain", "heads", "rev_leaves", "hops", "action", "action_sig"), p.keys)
        // the caller's own cosignature list is not merged into
        assertEquals(1, hop0Cosigs.size)
        // the chain is a copy
        assertFalse(p["chain"] === chain)
    }

    @Test fun pinProofsAreCarriedOnlyWhenThereAreSome() {
        val hop = obj("domain" to "d", "head" to obj("head" to head(1L, "r"), "sig" to "s", "cosigs" to emptyList<Any?>()), "inclusion" to obj("path" to emptyList<Any?>()),
            "revocation" to obj("cap" to obj("size" to 0L), "issuer_key" to obj("size" to 0L)))
        val chain = listOf<Any?>(cap0)
        assertFalse(SignersMore.assembleMeshProof(chain, listOf(hop), action, leaf).containsKey("pin_proofs"))
        assertFalse(SignersMore.assembleMeshProof(chain, listOf(hop), action, leaf, null).containsKey("pin_proofs"))
        assertFalse(SignersMore.assembleMeshProof(chain, listOf(hop), action, leaf, emptyList()).containsKey("pin_proofs"))
        val pins = arrayListOf<Any?>(obj("pin" to 1L))
        val p = SignersMore.assembleMeshProof(chain, listOf(hop), action, leaf, pins)
        assertEquals(canon(listOf(obj("pin" to 1L))), canon(p["pin_proofs"]))
        assertFalse(p["pin_proofs"] === pins)
    }

    @Test fun aProofWithNoHopsHasEmptyTables() {
        val p = SignersMore.assembleMeshProof(listOf<Any?>(cap0), emptyList(), action, leaf)
        assertEquals(0, l(p["heads"]).size)
        assertEquals(0, l(p["rev_leaves"]).size)
        assertEquals(0, l(p["hops"]).size)
        assertEquals(1, l(p["chain"]).size)
    }
}
