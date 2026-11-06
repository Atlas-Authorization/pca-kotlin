package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for ListAuthorized (k05 small group); expectations follow packages/pca-grants/src/list-authorized.ts. */
class Kill05SmallListAuthorizedTest {
    private val label = "k05-list-authorized"
    private val signer = IntentTestKit.pub(label)
    private fun n(s: String) = Json.Num(s)

    private fun bindMap(limit: Any? = n("10"), relation: Any? = null): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["subject"] = "alice"; b["resourceType"] = "doc"; b["filterId"] = "f1"; b["policyDigest"] = "p1"; b["limit"] = limit
        if (relation != null) b["relation"] = relation
        return b
    }

    /** A cursor token over `c` (completed with v, bind and signer unless overridden), signed unless `sig` is given. */
    private fun cursor(vararg over: Pair<String, Any?>, sig: String? = null, tail: String = ""): String {
        val c = LinkedHashMap<String, Any?>()
        c["v"] = n("1"); c["skip"] = n("3"); c["bind"] = ListAuthorized.listBind(bindMap()); c["signer"] = signer
        for ((k, v) in over) c[k] = v
        val s = sig ?: IntentTestKit.sign(label, IntentJs.message(ListAuthorized.LIST_CURSOR_DOMAIN, c))
        return Pca.b64(IntentJs.utf8(Json.canonicalizeStrict(c))) + "." + s + tail
    }

    @Test fun listBindRelation() {
        val none = K3Sig.digestOf("s" to "alice", "t" to "doc", "f" to "f1", "p" to "p1", "r" to null, "l" to n("10"))
        assertEquals(none, ListAuthorized.listBind(bindMap()))
        // a relation that is not an object contributes null, as `a.relation?.relation ?? null` does
        assertEquals(none, ListAuthorized.listBind(bindMap(relation = "viewer")))
        val viewer = mapOf("relation" to "viewer")
        assertEquals(K3Sig.digestOf("s" to "alice", "t" to "doc", "f" to "f1", "p" to "p1", "r" to "viewer", "l" to n("10")), ListAuthorized.listBind(bindMap(relation = viewer)))
    }

    @Test fun cursorAcceptAndGetters() {
        val ok = ListAuthorized.verifyCursor(cursor(), signer, bindMap())
        assertTrue(ok.ok)
        assertNull(ok.inner)
        assertEquals(n("3"), ok.skip)
        assertEquals("", ok.reason)
        assertFalse(ok.toJson().containsKey("inner"))
        assertEquals(n("3"), ok.toJson()["skip"])
        val withInner = ListAuthorized.verifyCursor(cursor("inner" to "page-7"), signer, bindMap())
        assertTrue(withInner.ok)
        assertEquals("page-7", withInner.inner)
        assertEquals("page-7", withInner.toJson()["inner"])
    }

    @Test fun cursorRefusals() {
        fun reason(tok: Any?, bind: Map<String, Any?>? = bindMap()): String {
            val r = ListAuthorized.verifyCursor(tok, signer, bind)
            assertFalse(r.ok)
            assertNull(r.skip)
            return r.reason
        }
        assertEquals("malformed", reason(n("1")))
        assertEquals("malformed", reason(cursor(tail = ".x")))
        assertEquals("malformed", reason("!!." + cursor().substringAfter('.')))
        assertEquals("signature", reason(cursor(sig = "A".repeat(86))))
        assertEquals("bind", reason(cursor(), bindMap(limit = n("11"))))
        // a bad inner is malformed before the signature or the bind is looked at
        assertEquals("malformed", reason(cursor("inner" to n("5"), sig = "A".repeat(86))))
        assertEquals("malformed", reason(cursor("inner" to null, sig = "A".repeat(86))))
        assertEquals("malformed", reason(cursor("inner" to n("5")), bindMap(limit = n("11"))))
        // a bind that cannot be hashed fails closed as malformed
        assertEquals("malformed", reason(cursor(), bindMap(limit = n("1e5"))))
    }

    private fun receipt(objects: List<Any?>, count: Any? = n(objects.size.toString())): LinkedHashMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["v"] = n("1"); r["subject"] = "alice"; r["resource_type"] = "doc"; r["policy_digest"] = "p1"; r["fresh_at"] = "fa"
        r["filter_digest"] = "f1"; r["count"] = count; r["objects_digest"] = ListAuthorized.objectsDigest(objects)
        r["issued_at"] = n("1000"); r["signer"] = signer
        r["sig"] = IntentTestKit.sign(label, IntentJs.message(ListAuthorized.LIST_RECEIPT_DOMAIN, LinkedHashMap(r)))
        return r
    }

    @Test fun receipts() {
        val objs = listOf<Any?>("a", "b")
        val r = receipt(objs)
        assertTrue(ListAuthorized.verifyReceipt(r, signer))
        assertTrue(ListAuthorized.verifyReceipt(r, signer, objs))
        assertFalse(ListAuthorized.verifyReceipt(r, signer, listOf("b", "a")))
        assertFalse(ListAuthorized.verifyReceipt(r, signer, listOf("a")))
        assertFalse(ListAuthorized.verifyReceipt("x", signer))
        assertFalse(ListAuthorized.verifyReceipt(null, signer))
        // objects whose digest cannot be computed (a non-canonical number) fail closed after the count matched
        assertFalse(ListAuthorized.verifyReceipt(r, signer, listOf(n("1e5"), "b")))
    }
}
