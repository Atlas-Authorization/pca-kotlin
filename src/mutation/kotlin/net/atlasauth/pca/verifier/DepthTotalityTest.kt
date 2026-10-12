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
 * Depth caps and totality on untrusted / hostile values (R6-05 + the native depth audit). Strict profile: [Json.MAX_DEPTH]
 * (32, top-level container = depth 1, as in TS strict-json.ts). Every protocol digest (capHash / hop body digest, Merkle
 * leaves, the signer-set hash) uses the STRICT canonical form, as hash.ts canonicalBytes: before, hops/leaves were hashed
 * under the LENIENT form, so a hop signed over out-of-profile bytes (depth 33, a lone surrogate) verified where the reference
 * refuses it, and a deeply nested caveat / leaf / grant (or a cycle) overflowed the stack: the StackOverflowError escaped
 * every "total" entry point (they only catch RuntimeException). The public lenient [Json.canonicalize] is capped at
 * [Json.MAX_LENIENT_DEPTH].
 * The hostile checks run on a 512 KiB-stack thread (a typical servlet worker), independent of the surefire -Xss.
 */
class DepthTotalityTest {
    private fun small(body: () -> Unit) {
        var err: Throwable? = null
        val t = Thread(null, { try { body() } catch (e: Throwable) { err = e } }, "small-stack", 512L * 1024)
        t.start(); t.join()
        err?.let { throw it }
    }

    private fun nested(k: Int): Any? { var a: Any? = 1; repeat(k) { a = arrayListOf(a) }; return a }

    private fun iae(body: () -> Unit): String {
        try { body() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected IllegalArgumentException"); return ""
    }

    @Test fun strictParseDepthLimitBoundary() = small {
        assertNotNull(Json.parse("[".repeat(31) + "]".repeat(31)))
        assertNotNull(Json.parse("[".repeat(32) + "]".repeat(32)))
        assertTrue(iae { Json.parse("[".repeat(33) + "]".repeat(33)) }.startsWith("nesting too deep"))
        assertTrue(iae { Json.parse("[".repeat(100000) + "]".repeat(100000)) }.startsWith("nesting too deep"))
        assertTrue(iae { Json.parse("{\"a\":".repeat(100000) + "1" + "}".repeat(100000)) }.startsWith("nesting too deep"))
    }

    @Test fun lenientCanonicalDepthCap() = small {
        val cap = Json.MAX_LENIENT_DEPTH
        assertNotNull(Json.canonicalize(nested(cap - 1)))
        assertNotNull(Json.canonicalize(nested(cap)))
        assertEquals("canonicalize: nesting too deep", iae { Json.canonicalize(nested(cap + 1)) })
        assertEquals("canonicalize: nesting too deep", iae { Json.canonicalize(nested(100000)) })
        val cyc = ArrayList<Any?>(); cyc.add(cyc)
        assertEquals("canonicalize: nesting too deep", iae { Json.canonicalize(cyc) })
        val cm = LinkedHashMap<String, Any?>(); cm["self"] = cm
        assertEquals("canonicalize: nesting too deep", iae { Json.canonicalize(cm) })
    }

    /** A root signed by `principal` over the LENIENT canonical bytes of its body (what a non-reference signer emits). */
    private fun leniently(caveats: List<Any?>): Map<String, Any?> {
        val body = m("issuer" to PqChainTest.pub("principal"), "holder" to PqChainTest.pub("agent"), "caveats" to caveats, "parent" to null)
        val digest = Pca.b64(Pca.sha(Json.canonicalize(body).toByteArray(Charsets.UTF_8)))
        val msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!)
        return m("id" to digest, "issuer" to body["issuer"], "holder" to body["holder"], "caveats" to caveats, "body_digest" to digest,
            "sig" to PqChainTest.edSign("principal", msg))
    }

    /** A root whose one caveat carries a value nested `k` lists deep (hop depth 3 + k), signed over the lenient bytes. */
    private fun rootWithDepth(k: Int): Map<String, Any?> = leniently(l(m("type" to "note", "v" to nested(k))))

    @Test fun chainHopDepthAroundTheStrictLimit() {
        // hop digests are strict (TS capHash = canonicalizeStrict): hop depth 31 and 32 verify, 33 is refused even though
        // it is validly signed over the (uncapped) lenient bytes
        for (hopDepth in listOf(31, 32)) {
            val r = rootWithDepth(hopDepth - 3)
            assertEquals("hop depth $hopDepth", "", Pca.verifyChain(l(r), r["issuer"] as String, true, null))
        }
        val r33 = rootWithDepth(30)
        assertEquals("hop 0: malformed body", Pca.verifyChain(l(r33), r33["issuer"] as String, true, null))
    }

    @Test fun chainHopOutOfProfileIsRefused() {
        // a lone surrogate in a caveat: the lenient form hashes it (as U+FFFD), the reference's strict form refuses it
        val r = leniently(l(m("type" to "note", "v" to "\uD800")))
        assertEquals("hop 0: malformed body", Pca.verifyChain(l(r), r["issuer"] as String, true, null))
        val lenientRoot = Pca.b64(Pca.sha(byteArrayOf(0x00), Json.canonicalize(m("a" to "\uD800")).toByteArray(Charsets.UTF_8)))
        assertFalse(Pca.verifyInclusion(lenientRoot, m("index" to 0, "size" to 1, "path" to l()), m("a" to "\uD800")))
        val okRoot = Pca.b64(Pca.sha(byteArrayOf(0x00), Json.canonicalizeStrict(m("a" to "x")).toByteArray(Charsets.UTF_8)))
        assertTrue(Pca.verifyInclusion(okRoot, m("index" to 0, "size" to 1, "path" to l()), m("a" to "x")))
    }

    @Test fun chainIsTotalOnHostileDepth() = small {
        val r = rootWithDepth(1)
        val issuer = r["issuer"] as String
        val deep = LinkedHashMap(r); deep["caveats"] = l(m("type" to "note", "v" to nested(100000)))
        assertEquals("hop 0: malformed body", Pca.verifyChain(l(deep), issuer, true, null))
        val cv = m("type" to "note"); cv["self"] = cv
        val cyc = LinkedHashMap(r); cyc["caveats"] = l(cv)
        assertEquals("hop 0: malformed body", Pca.verifyChain(l(cyc), issuer, true, null))
        assertFalse(Pca.verifyChain(l(deep, LinkedHashMap(r)), issuer, false, null).isEmpty())
    }

    @Test fun inclusionIsTotalOnHostileDepth() = small {
        assertFalse(Pca.verifyInclusion("x", m("index" to 0, "size" to 1, "path" to l()), nested(100000)))
    }

    @Test fun pcactnIsTotalOnHostileGrant() = small {
        val p = KUtil.valid()
        val g = LinkedHashMap(KUtil.validGrant()); g["zz"] = nested(100000)
        assertFalse(Pca.verifyPcactn(p, g, 0L, KUtil.Of).allow)
        val deep = LinkedHashMap(p); deep["risk_claim"] = m("r" to 0, "inputs" to m("x" to nested(100000)))
        val w = Pca.verifyPcactn(deep, KUtil.validGrant(), 0L, KUtil.Of)
        assertFalse(w.allow)
        assertEquals(false, w.checks["wire"])
    }

    @Test fun chainIsTotalOnAThrowingHostMap() {
        // a host-supplied Map implementation that throws: the defence-in-depth catch of verifyChain turns it into a refusal
        val evil = object : LinkedHashMap<String, Any?>() {
            override fun get(key: String): Any? = throw IllegalStateException("boom")
        }
        assertEquals("malformed capability chain: IllegalStateException", Pca.verifyChain(l(evil), "x", true, null))
    }
}
