package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills for [Undo] (TS reference packages/pca/src/undo.ts), beyond the k05-undo oracle (K05UndoDiffTest): the
 * public vocabularies, record-id bounds, token decoding bounds, receipt member types, the chain's first `at`, absent-member
 * refusals of the signers, the fail-closed transition handler, String(array) with null items, and the @JvmOverloads window bridges.
 */
@Suppress("UNCHECKED_CAST")
class Kill05WfUndoTest {
    private val seed = ByteArray(32) { 9 }
    private val signer = Keys.edFromSeed(seed).id()

    private fun receipt(over: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val b = linkedMapOf<String, Any?>("record" to "r1", "event" to "opened", "state" to "open", "at" to 0L, "compensation_digest" to "cd", "prev" to "", "note" to "")
        b.putAll(over)
        return Undo.signReceipt(b, seed)
    }

    private fun b64(s: String) = Pca.b64(s.toByteArray(StandardCharsets.UTF_8))

    @Test fun vocabularies() {
        assertEquals(listOf("open", "vetoed", "compensated", "compensation_failed", "finalized"), Undo.STATES)
        assertEquals(listOf("opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect"), Undo.EVENTS)
        assertEquals(listOf("token", "operator", "fraud_proof", "revocation"), Undo.VETO_VIAS)
    }

    @Test fun recordIds() {
        assertFalse(Undo.idOk(null))
        assertFalse(Undo.idOk(5L))
        assertFalse(Undo.idOk(listOf("a")))
        assertFalse(Undo.idOk(""))
        assertTrue(Undo.idOk("a"))
        assertTrue(Undo.idOk("x".repeat(256)))
        assertFalse(Undo.idOk("x".repeat(257)))
        assertFalse(Undo.idOk("a\u0000"))
        assertFalse(Undo.idOk("a\u001f"))
        assertFalse(Undo.idOk("\u001fa"))
        assertFalse(Undo.idOk("\u0000"))
        assertTrue(Undo.idOk("a b"))
        assertTrue(Undo.idOk("\u007f"))
    }

    @Test fun decodeTokenBounds() {
        val at4096 = b64(Json.canonicalizeStrict(linkedMapOf("x" to "a".repeat(3064))))
        assertEquals(4096, at4096.length)
        assertEquals("a".repeat(3064), Undo.decodeToken(at4096)!!["x"])
        val over = b64(Json.canonicalizeStrict(linkedMapOf("x" to "a".repeat(3067))))
        assertEquals(4100, over.length)
        assertNull(Undo.decodeToken(over))
        assertEquals(mapOf("v" to Json.Num("1")).keys, Undo.decodeToken(b64("{\"v\":1}"))!!.keys)
        assertNull(Undo.decodeToken(null))
        assertNull(Undo.decodeToken(5L))
        assertNull(Undo.decodeToken(""))
        assertNull(Undo.decodeToken("!!!!"))
        assertNull(Undo.decodeToken(Pca.b64(byteArrayOf(0x7b, 0xff.toByte(), 0x7d))))
        assertNull(Undo.decodeToken(b64("[1]")))
        assertNull(Undo.decodeToken(b64("\"x\"")))
        assertNull(Undo.decodeToken(b64("null")))
    }

    @Test fun tokenMembersAreExact() {
        val rec = linkedMapOf<String, Any?>("id" to "r1", "aud" to "svc", "principal" to "p", "compensation_digest" to "cd", "window_end" to 100L)
        val t = Undo.signToken(rec, seed)
        assertEquals("ok", Undo.tokenCheck(t, signer, rec, 50L))
        val extra = LinkedHashMap(t).also { it["extra"] = 1L }
        assertEquals("malformed", Undo.tokenCheck(extra, signer, rec, 50L))
        val swapped = LinkedHashMap(t).also { it.remove("aud"); it["extra"] = "svc" }
        assertEquals("malformed", Undo.tokenCheck(swapped, signer, rec, 50L))
        assertEquals("malformed", Undo.tokenCheck(null, signer, rec, 50L))
        assertEquals("malformed", Undo.tokenCheck("x", signer, rec, 50L))
    }

    @Test fun receiptMembersAreTyped() {
        assertTrue(Undo.verifyReceipt(receipt(), signer))
        assertFalse(Undo.verifyReceipt(receipt(mapOf("compensation_digest" to 5L)), signer))
        assertFalse(Undo.verifyReceipt(receipt(mapOf("prev" to null)), signer))
        assertFalse(Undo.verifyReceipt(receipt(mapOf("prev" to 5L)), signer))
        assertFalse(Undo.verifyReceipt(receipt(mapOf("note" to 5L)), signer))
        assertFalse(Undo.verifyReceipt(receipt(mapOf("note" to null)), signer))
        assertFalse(Undo.verifyReceipt(null, signer))
        assertFalse(Undo.verifyReceipt("x", signer))
    }

    @Test fun chainStartsAtAnyTime() {
        val rec = linkedMapOf<String, Any?>("id" to "r1", "compensation_digest" to "cd", "state" to "open", "receipts" to listOf(receipt()))
        assertNull(Undo.receiptChainError(rec, signer))
        rec["receipts"] = listOf(receipt(mapOf("at" to -5L)))
        assertNull(Undo.receiptChainError(rec, signer))
    }

    @Test fun signersRefuseAbsentMembers() {
        val c = linkedMapOf<String, Any?>("verb" to "v", "resource" to "r", "params" to emptyMap<String, Any?>(), "undo_of" to "u", "def_digest" to "d")
        Undo.compensationDigest(c)
        for (k in c.keys) {
            val m = LinkedHashMap(c).also { it.remove(k) }
            val e = assertThrows(IllegalArgumentException::class.java) { Undo.compensationDigest(m) }
            assertEquals("canonicalize: unsupported type (member $k is absent)", e.message)
        }
        val b = linkedMapOf<String, Any?>("record" to "r1", "event" to "opened", "state" to "open", "at" to 0L, "compensation_digest" to "cd", "prev" to "", "note" to "")
        for (k in b.keys) {
            val m = LinkedHashMap(b).also { it.remove(k) }
            val e = assertThrows(IllegalArgumentException::class.java) { Undo.signReceipt(m, seed) }
            assertEquals("canonicalize: unsupported type (member $k is absent)", e.message)
        }
    }

    @Test fun transitionThatThrowsFailsClosed() {
        val boom: Map<String, Any?> = object : AbstractMap<String, Any?>() {
            override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("boom")
        }
        val rec = linkedMapOf<String, Any?>("state" to "open", "window_end" to 100L, "ver" to 1L)
        val t = Undo.transition(rec, boom, 50L)
        assertEquals("refused", t.outcome)
        assertEquals("invalid", t.code)
        assertEquals("evaluation error (fail closed)", t.reason)
    }

    // JavaScript String([null, "a"]) is ",a": a null array item prints empty
    @Test fun abortReasonArrayWithNull() {
        val rec = linkedMapOf<String, Any?>("state" to "open", "window_end" to 100L, "ver" to 1L)
        val t = Undo.transition(rec, mapOf("kind" to "abort", "reason" to listOf(null, "a", listOf(null))), 50L)
        assertEquals("applied", t.outcome)
        assertEquals(",a,", t.note)
        assertEquals(",a,", (t.record!!["outcome"] as Map<String, Any?>)["reason"])
    }

    @Test fun windowClamp() {
        assertEquals(30_000L, Undo.resolveWindow(1000L))
        assertEquals(30_000L, Undo.resolveWindow(1000L, 1000.0, null, null))
        assertEquals(40_000L, Undo.resolveWindow(1000L, 40_000.0, null, null))
        assertEquals(900_000L, Undo.resolveWindow(null))
        assertEquals(86_400_000L, Undo.resolveWindow(1e12))
    }

    // the @JvmOverloads bridges are what a Java caller links against (Kotlin callers use resolveWindow$default)
    @Test fun windowOverloadBridges() {
        val c = Undo::class.java
        val d = Double::class.javaObjectType
        assertEquals(30_000L, c.getMethod("resolveWindow", Any::class.java).invoke(Undo, 1000L))
        assertEquals(40_000L, c.getMethod("resolveWindow", Any::class.java, d).invoke(Undo, 1000L, 40_000.0))
        assertEquals(50_000L, c.getMethod("resolveWindow", Any::class.java, d, d).invoke(Undo, 99_000_000L, null, 50_000.0))
        assertNotNull(c.getMethod("resolveWindow", Any::class.java, d, d, d))
    }
}
