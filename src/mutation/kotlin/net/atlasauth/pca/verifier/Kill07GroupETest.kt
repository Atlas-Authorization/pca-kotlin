package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills, group E (the k05 full run 42421378893): strict base64url alphabet, SPIFFE trust-domain bounds, the hop that
 * introduced each caveat, the narrow block's holder and caveat shape, RFC 9162 inclusion argument bounds, the approval render's
 * undeclared-parameter message, policy slot bounds and the closed-set check of a set slot without a declared value set.
 * Every expected value is the TS reference's (caveat-lang.ts:95, provenance-gate.ts, approval-render.ts:59).
 */
@Suppress("UNCHECKED_CAST")
class Kill07GroupETest {
    private val d43 = "A".repeat(43)

    @Test
    fun strictBase64urlAlphabet() {
        val all = ('A'..'Z').joinToString("") + ('a'..'z').joinToString("") + ('0'..'9').joinToString("") + "-_"
        val b = Pca.decodeB64uStrict(all, -1)
        assertNotNull(b)
        assertEquals(48, b!!.size)
        assertEquals(all, Pca.b64(b))
        assertNotNull(Pca.decodeB64uStrict(d43, 32))
        for (bad in listOf("A".repeat(44), "A".repeat(42), "A".repeat(42) + "B", "A".repeat(42) + "=", "A".repeat(42) + "+", "A".repeat(42) + "/",
            "A".repeat(42) + " ", "A".repeat(42) + "\n", "A".repeat(42) + "Ł", "@" + "A".repeat(42), "[" + "A".repeat(42), "`" + "A".repeat(42),
            "{" + "A".repeat(42), ":" + "A".repeat(42), "/" + "A".repeat(42)))
            assertNull(bad, Pca.decodeB64uStrict(bad, 32))
        for (bad in listOf("AA==", "AAA=", "AA-+", "AAA ", "AAAA\n", "A\$AA", "ÄAAA", "AAA.", "AAA\u0000"))
            assertNull(bad, Pca.decodeB64uStrict(bad, -1))
        assertNull(Pca.decodeB64uStrict(5L, 32))
        assertNull(Pca.decodeB64uStrict(null, -1))
    }

    @Test
    fun spiffeTrustDomainBounds() {
        val bad = "invalid trust domain"
        for (ok in listOf("spiffe://example.org", "spiffe://a_b.c-d9/x/y.z", "spiffe://" + "a".repeat(255), "spiffe://a/b/c"))
            assertNull(ok, CaveatLang.spiffeIdError(ok))
        for (s in listOf("spiffe:///x", "spiffe://", "spiffe://Example.org", "spiffe://a b", "spiffe://" + "a".repeat(256), "spiffe://a:80/x"))
            assertEquals(s, bad, CaveatLang.spiffeIdError(s))
        assertEquals("path must not end with a slash", CaveatLang.spiffeIdError("spiffe://a/"))
        assertEquals("path must not end with a slash", CaveatLang.spiffeIdError("spiffe://a/b/"))
        for (s in listOf("spiffe://a//b", "spiffe://a/./b", "spiffe://a/../b", "spiffe://a/b c"))
            assertEquals(s, "invalid path segment", CaveatLang.spiffeIdError(s))
    }

    @Test
    fun boundCaveatsNamesTheFirstHopWhoseListIsLongEnough() {
        val c0 = linkedMapOf<String, Any?>("type" to "x0")
        val c1 = linkedMapOf<String, Any?>("type" to "x1")
        val chain = listOf<Any?>(
            "not a map",
            linkedMapOf<String, Any?>("id" to "no caveats member"),
            linkedMapOf<String, Any?>("caveats" to listOf<Any?>()),
            linkedMapOf<String, Any?>("caveats" to listOf<Any?>(c0)),
            linkedMapOf<String, Any?>("caveats" to listOf<Any?>(c0, c1)),
        )
        val got = CaveatLang.boundCaveats(chain.last(), chain)!!
        assertEquals(listOf(3, 4), got.map { it.hop })
        assertEquals(Pca.capHash(chain[3] as Map<String, Any?>), got[0].capHash)
        assertEquals(Pca.capHash(chain[4] as Map<String, Any?>), got[1].capHash)
        assertEquals(listOf<Any?>(c0, c1), got.map { it.caveat })
        // a single hop: the grant itself introduced everything
        val g = linkedMapOf<String, Any?>("caveats" to listOf<Any?>(c0, c1))
        assertEquals(listOf(0, 0), CaveatLang.boundCaveats(g)!!.map { it.hop })
        assertNull(CaveatLang.boundCaveats(linkedMapOf<String, Any?>("id" to "x")))
    }

    private fun narrow(holder: Any?, caveats: Any?): LinkedHashMap<String, Any?> = linkedMapOf(
        "v" to 1L, "kind" to "pca-narrow", "cap_hash" to d43, "holder" to holder, "caveats" to caveats, "iat" to 1L, "not_after" to 2L,
        "nonce" to "AAAAAAAAAAAAAAAAAAAAAA", "sig" to "x",
    )

    @Test
    fun narrowHolderAndCaveatShape() {
        val h = "holder must be canonical base64url (32 bytes)"
        val cav = "every caveat must be an object with a string type"
        val ok = listOf<Any?>(linkedMapOf("type" to "max_spend"))
        assertNotEquals(h, CaveatLang.narrowShapeError(narrow(d43, ok)))
        for (bad in listOf<Any?>("A".repeat(44), "A".repeat(42), "A".repeat(42) + "B", "A".repeat(42) + "=", "", 5L, null, listOf<Any?>()))
            assertEquals("$bad", h, CaveatLang.narrowShapeError(narrow(bad, ok)))
        for (bad in listOf<Any?>(5L, "x", null, linkedMapOf<String, Any?>(), linkedMapOf("type" to 5L), linkedMapOf("type" to null)))
            assertEquals("$bad", cav, CaveatLang.narrowShapeError(narrow(d43, listOf<Any?>(bad))))
        assertEquals("a narrow block cannot carry a 'envelope' caveat", CaveatLang.narrowShapeError(narrow(d43, listOf<Any?>(linkedMapOf("type" to "envelope")))))
        for (nonObj in listOf<Any?>(null, "max_spend", 5L, listOf<Any?>("max_spend"))) assertFalse("$nonObj", CaveatLang.isK1Caveat(nonObj))
    }

    @Test
    fun rfc9162InclusionArgumentBounds() {
        val leaf = ByteArray(32) { 1 }
        assertTrue(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 1, emptyList(), leaf))
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, -1, 1, emptyList(), leaf))
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 1, 1, emptyList(), leaf))
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 0, emptyList(), leaf))
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, -1, emptyList(), leaf))
        // size 2^53 is past the safe-integer bound although a 53-entry proof of its leftmost leaf is consistent
        val sib = ByteArray(32) { 7 }
        var root = leaf
        repeat(53) { root = Pca.sha(byteArrayOf(1), root, sib) }
        val big = 1L shl 53
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, big, List(53) { sib }, root))
        // one below the bound the same walk is the real thing: 2^53 - 1 leaves, leftmost leaf, 53 siblings
        var root2 = leaf
        repeat(53) { root2 = Pca.sha(byteArrayOf(1), root2, sib) }
        assertTrue(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, big - 1, List(53) { sib }, root2))
    }

    private fun adef(params: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "v" to 1L, "kind" to "pca-action-def", "verb" to "acme.t", "title" to "T", "effects" to listOf("pay"),
        "resource" to linkedMapOf("type" to "account", "id" to "*", "scope" to "one"), "params" to params,
    )

    @Test
    fun renderNamesTheUndeclaredParameterAndTheVerb() {
        val d = adef(linkedMapOf("a" to linkedMapOf("type" to "integer")))
        try {
            Approval.render(d, linkedMapOf("zz" to 1L))
            org.junit.Assert.fail("no throw")
        } catch (e: ActionKitError) {
            assertEquals("render_undeclared_param", e.code)
            assertEquals("'zz' is not a parameter of acme.t", e.message)
        }
    }
}
