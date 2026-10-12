package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The reference per-hop type check (capability.ts wellTyped) with EXACT reasons: an ill-typed hop is "hop N: malformed
 * capability" (never an exception routed through the total catch), checked before any signature work, so a validly signed root
 * that only gains an ill-typed unsigned field is refused. Plus the lenient canonical cap on nested OBJECTS and the empty
 * signer-set hash / registry (the inlined `any` / `all` fast paths).
 */
class WellTypedKillTest {
    private fun root(): LinkedHashMap<String, Any?> = LinkedHashMap(KUtil.mm(KUtil.twoHop()[0]))
    private fun chain1(r: Map<String, Any?>) = Pca.verifyChain(l(r), r["issuer"] as String, true, null)

    @Test fun validRootBaseline() {
        assertEquals("", chain1(root()))
        assertTrue(Pca.wellTyped(root()))
    }

    @Test fun emptyChain() {
        assertEquals("empty chain", Pca.verifyChain(l(), "x", true, null))
    }

    @Test fun illTypedOptionalFieldsOnASignedRoot() {
        for (k in listOf("alg", "pq_pk", "pq_sig", "holder_pq", "parent")) {
            for (bad in listOf<Any?>(5, null, l(), m("a" to 1), true)) {
                val r = root(); r[k] = bad
                assertFalse("$k=$bad", Pca.wellTyped(r))
                assertEquals("$k=$bad", "hop 0: malformed capability", chain1(r))
            }
        }
        for (k in listOf("id", "issuer", "holder", "body_digest", "sig")) {
            val r = root(); r[k] = 5
            assertFalse(k, Pca.wellTyped(r))
            r.remove(k)
            assertFalse(k, Pca.wellTyped(r))
        }
    }

    @Test fun illTypedCaveats() {
        for (bad in listOf<Any?>(5, null, "x", m("type" to "a"))) {
            val r = root(); r["caveats"] = bad
            assertFalse("$bad", Pca.wellTyped(r))
            assertEquals("$bad", "hop 0: malformed capability", chain1(r))
        }
        val r = root(); r.remove("caveats")
        assertEquals("hop 0: malformed capability", chain1(r))
        for (badCv in listOf<Any?>(5, null, "x", l("type", "a"), m("note" to 1), m("type" to 5), m("type" to null))) {
            val c = root()
            c["caveats"] = ArrayList(c["caveats"] as List<Any?>).also { it.add(badCv) }
            assertFalse("$badCv", Pca.wellTyped(c))
            assertEquals("$badCv", "hop 0: malformed capability", chain1(c))
        }
        assertFalse(Pca.wellTyped(null)); assertFalse(Pca.wellTyped("x")); assertFalse(Pca.wellTyped(l()))
        val e = root(); e["caveats"] = l()
        assertTrue(Pca.wellTyped(e))
        // only the first ill-typed caveat matters: one good caveat before a bad one is not enough
        val g = root(); g["caveats"] = l(m("type" to "a"), 5)
        assertFalse(Pca.wellTyped(g))
    }

    private fun nestedMap(k: Int): Any? { var a: Any? = 1; repeat(k) { a = m("k" to a) }; return a }

    private fun iae(body: () -> Unit): String {
        try { body() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected IllegalArgumentException"); return ""
    }

    @Test fun lenientCapOnNestedObjects() {
        var err: Throwable? = null
        val t = Thread(null, {
            try {
                assertNotNull(Json.canonicalize(nestedMap(Json.MAX_LENIENT_DEPTH)))
                assertEquals("canonicalize: nesting too deep", iae { Json.canonicalize(nestedMap(Json.MAX_LENIENT_DEPTH + 1)) })
                assertNotNull(Json.canonicalizeStrict(nestedMap(Json.MAX_DEPTH)))
                assertEquals("canonicalize: nesting too deep", iae { Json.canonicalizeStrict(nestedMap(Json.MAX_DEPTH + 1)) })
            } catch (e: Throwable) { err = e }
        }, "small-stack", 512L * 1024)
        t.start(); t.join()
        err?.let { throw it }
    }

    @Test fun emptySignerSet() {
        assertNotNull(Threshold.signerSetHashB64u(l()))
        assertEquals(emptyMap<String, Pair<String, String?>>(), Threshold.validatedRegistry(l()))
        // three distinct members: the one-key-two-roles scan (`any` over the registry) must not fire
        val a = Pca.b64(ByteArray(32) { 1 }); val g = Pca.b64(ByteArray(32) { 2 }); val p = Pca.b64(ByteArray(32) { 3 })
        assertEquals(3, Threshold.validatedRegistry(l(m("role" to "agent", "publicKey" to a), m("role" to "guardian", "publicKey" to g), m("role" to "principal", "publicKey" to p)))!!.size)
    }
}
