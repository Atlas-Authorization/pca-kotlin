package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for A2a.kt, pinned to packages/pca/src/pca-need.ts (validatePcaNeed / decodePcaNeed) and
 * packages/pca-a2a/src/a2a-receipt.ts: every bound and empty-collection case of a need, the decode edges, the resume
 * gate's proof check, the push salt bound and each shape check of a signed task-update receipt.
 */
class Kill05CtxA2aTest {
    private fun n(s: String) = Json.Num(s)
    private fun s(k: Int) = "x".repeat(k)

    private fun need(vararg over: Pair<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to n("1"), "kind" to "scope", "verb" to "v", "resource" to "r")
        for ((k, v) in over) m[k] = v
        return m
    }

    @Test
    fun needBounds() {
        assertNull(A2a.needError(need()))
        assertEquals("bad_version", A2a.needError(emptyMap<String, Any?>()))
        for (v in listOf<Any?>("1", n("x"), n("2"))) assertEquals("$v", "bad_version", A2a.needError(need("v" to v)))
        val ok = listOf<Pair<String, Any?>>(
            "verb" to s(128), "resource" to s(512),
            "scopes" to emptyList<Any?>(), "scopes" to List(16) { "s$it" },
            "scopes" to listOf("a\u001cb"), "scopes" to listOf("a\u0085b"), // not JS \s
            "grant_ref" to "g", "grant_ref" to s(128), "policy_digest" to "p", "policy_digest" to s(128),
            "limits" to emptyMap<String, Any?>(), "limits" to mapOf("k" to n("0")), "limits" to mapOf(s(64) to n("1")),
            "limits" to (0 until 16).associate { "k$it" to n("1") },
            "discharges" to emptyList<Any?>(), "discharges" to List(16) { mapOf("issuer" to "i", "claim" to "c") })
        for (o in ok) assertNull("$o", A2a.needError(need(o)))
        val bad = listOf<Pair<String, Any?>>(
            "verb" to null, "verb" to s(129), "resource" to null, "resource" to "", "resource" to s(513),
            "scopes" to listOf(" a"), "scopes" to List(17) { "s$it" },
            "scopes" to listOf("a\uFEFFb"), "scopes" to listOf("a\u00A0b"), "scopes" to listOf("a\u2003b"), "scopes" to listOf("a\u3000b"), "scopes" to listOf("a\tb"), // pca-need.ts:69
            "grant_ref" to "", "grant_ref" to s(129), "grant_ref" to 5, "policy_digest" to "", "policy_digest" to s(129), "policy_digest" to 5,
            "limits" to emptyList<Any?>(), "limits" to mapOf("k" to n("1e999")), "limits" to mapOf(s(65) to n("1")),
            "limits" to (0 until 17).associate { "k$it" to n("1") },
            "discharges" to "x", "discharges" to listOf(emptyMap<String, Any?>()), "discharges" to List(17) { mapOf("issuer" to "i", "claim" to "c") })
        for (o in bad) assertEquals("$o", "bad_field", A2a.needError(need(o)))
    }

    private val needText = "{\"kind\":\"scope\",\"resource\":\"r\",\"v\":1,\"verb\":\"v\"}"
    private val needEnc = Pca.b64(needText.toByteArray(Charsets.UTF_8))

    @Test
    fun decodeEdges() {
        for (v in listOf<Any?>(null, 5, "")) assertEquals("$v", "bad_base64", A2a.decodeNeed(v).code)
        // 2048 characters is not too long: 1536 NUL bytes are valid UTF-8 but not JSON
        assertEquals("bad_json", A2a.decodeNeed("A".repeat(2048)).code)
        assertEquals("too_long", A2a.decodeNeed("A".repeat(2049)).code)
        val d = A2a.decodeNeed(needEnc)
        assertNull(d.code)
        assertEquals("v", d.need!!["verb"])
    }

    @Test
    fun resumeNeedsBothProofHalves() {
        val dg = A2a.needDigest(A2a.decodeNeed(needEnc).need!!)
        val st = "TASK_STATE_AUTH_REQUIRED"
        assertEquals("no_proof", A2a.resumeGate(st, needEnc, dg, null, "r"))
        assertEquals("no_proof", A2a.resumeGate(st, needEnc, dg, "v", null))
        assertEquals("action_mismatch", A2a.resumeGate(st, needEnc, dg, "v", "other"))
        assertNull(A2a.resumeGate(st, needEnc, dg, "v", "r"))
    }

    @Test
    fun pushSalt() {
        assertNotNull(A2a.pushToken("t", listOf("a"), s(16)))
        assertNull(A2a.pushToken("t", listOf("a"), s(15)))
        assertNull(A2a.pushToken("t", listOf("a"), 5))
    }

    private val label = "k05-a2a-receipt"
    private val signer = IntentTestKit.pub(label)
    private val chain = PcaGrant.chainDigest(listOf("a"))

    private fun receipt(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to n("1"), "task_id" to "t1", "state" to "TASK_STATE_WORKING", "seq" to 0L, "prev" to null,
            "chain" to chain, "issued_at" to 1000L, "signer" to signer)
        for ((k, v) in over) m[k] = v
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer")) body[k] = m[k]
        m["sig"] = IntentTestKit.sign(label, IntentJs.message(A2a.RECEIPT_DOMAIN, body))
        return m
    }

    @Test
    fun receiptShape() {
        val r0 = receipt()
        assertTrue(A2a.verifyReceipt(r0, signer))
        assertTrue(A2a.verifyReceipt(receipt("task_id" to s(4096)), signer))
        val link = A2a.receiptDigest(r0)
        assertTrue(A2a.verifyReceipt(receipt("seq" to 1L, "prev" to link), signer))
        for (x in listOf<Any?>(null, "x", listOf(r0))) assertFalse("$x", A2a.verifyReceipt(x, signer))
        val bad = listOf<Pair<String, Any?>>("task_id" to "", "task_id" to s(4097), "task_id" to 5, "state" to "TASK_STATE_BOGUS",
            "seq" to -1L, "seq" to "0", "issued_at" to -1L, "issued_at" to "5",
            "chain" to Pca.b64(ByteArray(31)), "chain" to "x", "prev" to "x", "prev" to link, "seq" to 1L)
        for (o in bad) assertFalse("$o", A2a.verifyReceipt(receipt(o), signer))
        assertFalse(A2a.verifyReceipt(receipt("seq" to 1L, "prev" to "x"), signer))
        val ok = A2a.checkReceiptChain(listOf(r0), signer, "t1", listOf("a"))
        assertNull(ok.code)
        assertEquals(-1, ok.at)
        assertFalse(ok.terminal)
        assertEquals("TASK_STATE_WORKING", ok.lastState)
    }
}
