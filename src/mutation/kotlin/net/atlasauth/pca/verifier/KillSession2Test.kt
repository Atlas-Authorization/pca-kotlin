package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kill tests for the IntentJs.kt survivors of the 0.4.2 Kotlin mutation run: the JavaScript value semantics every Intent
 * Layer v2 rule judges by (typeof tests, `Number.isSafeInteger` / `Number.isFinite`, the lenient-canonical `deepEq`,
 * `TextEncoder` byte length, `JSON.parse` number normalization, the suite seam). Expectations are hand-computed from the
 * JavaScript semantics the reference relies on (noted per case).
 */
class KillSession2Test {
    private fun n(s: String) = Json.Num(s)

    @Test fun typeofs() {
        assertTrue(IntentJs.isObj(linkedMapOf<String, Any?>()))
        assertFalse(IntentJs.isObj(listOf<Any?>()))
        assertFalse(IntentJs.isObj(null))
        assertTrue(IntentJs.isArr(listOf<Any?>()))
        assertFalse(IntentJs.isArr(linkedMapOf<String, Any?>()))
        assertTrue(IntentJs.isStr(""))
        assertFalse(IntentJs.isStr(n("1")))
    }

    @Test fun num() {
        assertEquals(1.5, IntentJs.num(n("1.5"))!!, 0.0)
        assertNull(IntentJs.num(n("x")))
        assertEquals(7.0, IntentJs.num(7)!!, 0.0)
        assertEquals(-3.0, IntentJs.num(-3)!!, 0.0)
        assertEquals(9007199254740993.0, IntentJs.num(9007199254740993L)!!, 0.0)
        assertEquals(2.25, IntentJs.num(2.25)!!, 0.0)
        assertNull(IntentJs.num("1"))
        assertNull(IntentJs.num(null))
        assertNull(IntentJs.num(true))
        assertTrue(IntentJs.isNumber(3))
        assertFalse(IntentJs.isNumber("3"))
    }

    @Test fun safeInteger() {
        // Number.isSafeInteger: finite, integral, |v| <= 2^53 - 1 (-0 accepted)
        assertTrue(IntentJs.isSafeInteger(n("9007199254740991")))
        assertTrue(IntentJs.isSafeInteger(n("-9007199254740991")))
        assertFalse(IntentJs.isSafeInteger(n("9007199254740992")))
        assertFalse(IntentJs.isSafeInteger(n("-9007199254740992")))
        assertTrue(IntentJs.isSafeInteger(n("-0")))
        assertTrue(IntentJs.isSafeInteger(0))
        assertFalse(IntentJs.isSafeInteger(n("1.5")))
        assertFalse(IntentJs.isSafeInteger(n("-1.5")))
        assertFalse(IntentJs.isSafeInteger(Double.NaN))
        assertFalse(IntentJs.isSafeInteger(Double.POSITIVE_INFINITY))
        assertFalse(IntentJs.isSafeInteger(Double.NEGATIVE_INFINITY))
        assertFalse(IntentJs.isSafeInteger(n("1e400")))
        assertFalse(IntentJs.isSafeInteger("1"))
        assertTrue(IntentJs.isInt(n("5")))
        assertFalse(IntentJs.isInt(n("-0")))
        assertFalse(IntentJs.isNonNeg(n("-1")))
        assertTrue(IntentJs.isNonNeg(n("0")))
    }

    @Test fun finite() {
        assertTrue(IntentJs.isFinite(n("1.5")))
        assertTrue(IntentJs.isFinite(0))
        assertTrue(IntentJs.isFinite(-1.0e308))
        assertFalse(IntentJs.isFinite(n("1e400")))
        assertFalse(IntentJs.isFinite(n("-1e400")))
        assertFalse(IntentJs.isFinite(Double.NaN))
        assertFalse(IntentJs.isFinite(Double.POSITIVE_INFINITY))
        assertFalse(IntentJs.isFinite(Double.NEGATIVE_INFINITY))
        assertFalse(IntentJs.isFinite("1"))
        assertFalse(IntentJs.isFinite(null))
    }

    @Test fun jsonEquals() {
        val eq = { a: Any?, b: Any? -> IntentJs.jsonEquals(a, b) }
        assertTrue(eq(null, null))
        assertFalse(eq(null, n("0")))
        assertFalse(eq(n("0"), null))
        assertFalse(eq(null, "x"))
        assertFalse(eq("x", null))
        assertTrue(eq("a", "a"))
        assertFalse(eq("a", "b"))
        assertFalse(eq("1", n("1")))
        assertFalse(eq(n("1"), "1"))
        assertTrue(eq(true, true))
        assertFalse(eq(true, false))
        assertFalse(eq(true, n("1")))
        assertFalse(eq(n("1"), true))
        assertTrue(eq(n("1"), n("1.0")))
        assertTrue(eq(n("1000"), n("1e3")))
        assertTrue(eq(n("-0"), n("0")))
        assertTrue(eq(n("2"), 2))
        assertFalse(eq(n("1"), n("2")))
        assertFalse(eq(n("1e400"), n("1e400")))
        assertFalse(eq(n("1"), n("1e400")))
        assertFalse(eq(n("1e400"), n("1")))
        assertFalse(eq(n("1"), listOf(n("1"))))
        assertFalse(eq(listOf(n("1")), n("1")))
        assertFalse(eq(n("1"), mapOf("a" to n("1"))))
        // arrays element-wise
        assertTrue(eq(listOf<Any?>(), listOf<Any?>()))
        assertTrue(eq(listOf(n("1"), "a", null), listOf(n("1.0"), "a", null)))
        assertFalse(eq(listOf(n("1")), listOf(n("1"), n("1"))))
        assertFalse(eq(listOf(n("1"), n("2")), listOf(n("1"), n("3"))))
        assertFalse(eq(listOf(n("2"), n("1")), listOf(n("3"), n("1"))))
        // objects by key set and member values
        assertTrue(eq(linkedMapOf<String, Any?>(), linkedMapOf<String, Any?>()))
        assertTrue(eq(linkedMapOf("a" to n("1"), "b" to null), linkedMapOf("b" to null, "a" to n("1.0"))))
        assertFalse(eq(linkedMapOf("a" to n("1")), linkedMapOf("a" to n("1"), "b" to n("1"))))
        assertFalse(eq(linkedMapOf("a" to n("1"), "b" to n("1")), linkedMapOf("a" to n("1"))))
        assertFalse(eq(linkedMapOf("a" to null), linkedMapOf("b" to null)))
        assertFalse(eq(linkedMapOf("a" to n("1")), linkedMapOf("a" to n("2"))))
        assertFalse(eq(linkedMapOf("a" to n("1"), "b" to n("2")), linkedMapOf("a" to n("1"), "b" to n("3"))))
        // an array never equals an object; a non-JSON value never equals anything
        assertFalse(eq(listOf<Any?>(), linkedMapOf<String, Any?>()))
        assertFalse(eq(linkedMapOf<String, Any?>(), listOf<Any?>()))
        val o = Any()
        assertFalse(eq(o, o))
    }

    @Test fun u8len() {
        // TextEncoder: U+0000..7F 1 byte, ..7FF 2, BMP 3, a surrogate PAIR 4, a lone surrogate (U+FFFD) 3
        assertEquals(0, IntentJs.u8len(""))
        assertEquals(1, IntentJs.u8len("\u0000"))
        assertEquals(1, IntentJs.u8len("\u007f"))
        assertEquals(2, IntentJs.u8len("\u0080"))
        assertEquals(2, IntentJs.u8len("߿"))
        assertEquals(3, IntentJs.u8len("ࠀ"))
        assertEquals(3, IntentJs.u8len("￿"))
        assertEquals(4, IntentJs.u8len("😀"))
        assertEquals(3, IntentJs.u8len("\ud800"))
        assertEquals(3, IntentJs.u8len("\udc00"))
        assertEquals(6, IntentJs.u8len("\udc00\ud800"))
        assertEquals(4, IntentJs.u8len("\ud800a"))
        assertEquals(6, IntentJs.u8len("\ud800ࠀ"))
        assertEquals(5, IntentJs.u8len("a😀"))
        assertEquals(7, IntentJs.u8len("😀ࠀ"))
        assertEquals(8, IntentJs.u8len("😀😀"))
        for (s in listOf("aéࠀ😀z", "߿\u0080\u007f")) assertEquals(s, s.toByteArray(StandardCharsets.UTF_8).size, IntentJs.u8len(s))
    }

    @Test fun strings() {
        assertTrue(IntentJs.hasLoneSurrogate("a\ud800"))
        assertFalse(IntentJs.hasLoneSurrogate("a😀"))
        assertTrue(IntentJs.compareUtf8("a", "b") < 0)
        assertTrue(IntentJs.compareUtf8("b", "a") > 0)
        assertEquals(0, IntentJs.compareUtf8("a", "a"))
        // UTF-8 byte order, not UTF-16: U+FFFF (EF BF BF) sorts before U+1F600 (F0 ...)
        assertTrue(IntentJs.compareUtf8("￿", "😀") < 0)
        assertTrue(IntentJs.b64any("AAAA"))
        assertTrue(IntentJs.b64any("AA"))
        assertFalse(IntentJs.b64any("AA=A"))
        assertFalse(IntentJs.b64any("A"))
        assertFalse(IntentJs.b64any(1))
    }

    @Test fun suiteSeam() {
        val msg = "m".toByteArray(StandardCharsets.UTF_8)
        val pub = IntentTestKit.pub("ksess/ed")
        val sig = IntentTestKit.sign("ksess/ed", msg)
        assertTrue(IntentJs.verifyEd(pub, msg, sig))
        assertFalse(IntentJs.verifyEd(1, msg, sig))
        assertFalse(IntentJs.verifyEd(pub, msg, 1))
        assertFalse(IntentJs.verifyEd(null, msg, null))

        assertEquals("ed25519", IntentJs.suiteOf(linkedMapOf()))
        assertEquals("ml-dsa-65", IntentJs.suiteOf(linkedMapOf("alg" to "ml-dsa-65")))
        assertNull(IntentJs.suiteOf(linkedMapOf("alg" to "nope-dsa")))
        assertNull(IntentJs.suiteOf(linkedMapOf("alg" to null)))

        val base = linkedMapOf<String, Any?>("a" to n("1"))
        assertSame(base, IntentJs.bindSuiteFields(base, null, false, "PK", true))
        assertSame(base, IntentJs.bindSuiteFields(base, "ed25519", true, "PK", true))
        assertSame(base, IntentJs.bindSuiteFields(base, "nope-dsa", true, "PK", true))
        assertEquals(linkedMapOf<String, Any?>("a" to n("1"), "alg" to "ml-dsa-65", "pq_pk" to "PK"), IntentJs.bindSuiteFields(base, "ml-dsa-65", true, "PK", true))
        assertEquals(linkedMapOf<String, Any?>("a" to n("1"), "alg" to "ml-dsa-65"), IntentJs.bindSuiteFields(base, "ml-dsa-65", true, null, false))
        assertEquals(linkedMapOf<String, Any?>("a" to n("1")), base)

        // verifyPinnedSuite: an unknown suite is refused (never verified under ed25519)
        assertTrue(IntentJs.verifyPinnedSuite(null, false, pub, null, msg, sig, null, null))
        assertTrue(IntentJs.verifyPinnedSuite("ed25519", true, pub, null, msg, sig, null, null))
        assertFalse(IntentJs.verifyPinnedSuite("nope-dsa", true, pub, null, msg, sig, null, null))
        assertFalse(IntentJs.verifyPinnedSuite(1, true, pub, null, msg, sig, null, null))
        // a PQ suite with no pinned key / an unpinned artifact key is refused
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, "AAAA", msg, sig, null, null))
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, "AAAA", msg, sig, null, linkedMapOf(pub to "AAAA")))

        assertNull(IntentJs.pin("id", null))
        assertNull(IntentJs.pin("id", n("1")))
        assertEquals(linkedMapOf<String, Any?>("id" to "PK"), IntentJs.pin("id", "PK"))
    }

    private fun norm(v: Any?): String = (IntentJs.normalize(v) as Json.Num).raw

    @Test fun normalizeNumbers() {
        // JSON.parse then JavaScript's digits, printed without an exponent
        assertEquals("1", norm(n("1.0")))
        assertEquals("1000", norm(n("1e3")))
        assertEquals("-5", norm(n("-5.00")))
        assertEquals("-0", norm(n("-0")))
        assertEquals("-0", norm(n("-0.0")))
        assertEquals("0", norm(n("0e5")))
        assertEquals("0.1", norm(n("0.1")))
        assertEquals("0.1", norm(n("1e-1")))
        assertEquals("1.5", norm(n("1.50")))
        assertEquals("0.30000000000000004", norm(n("0.30000000000000004")))
        assertEquals("123456789.12345679", norm(n("123456789.123456789")))
        assertEquals("9007199254740992", norm(n("9007199254740993")))
        // above 2^53 JavaScript prints the shortest round-trip digits zero-padded, not the exact binary value
        assertEquals("999999999999999900000", norm(n("999999999999999900000")))
        assertEquals("1152921504606847000", norm(n("1152921504606846976")))
        assertEquals("9007199254740994", norm(n("9007199254740994")))
        assertEquals("123456789012345680000", norm(n("123456789012345678901")))
        assertEquals("9007199254740990", norm(n("9007199254740990")))
        assertEquals("1000000000000000000000", norm(n("1e21")))
        assertEquals("1230000000000000000000", norm(n("1.23e21")))
        assertEquals("0.000001", norm(n("1e-6")))
        assertEquals("0.0000001", norm(n("1e-7")))
        assertEquals("1e400", norm(n("1e400")))
        assertEquals("-1e400", norm(n("-1e400")))
        assertEquals("abc", norm(n("abc")))
        assertEquals("NaN", norm(n("NaN")))
        // binary64 values held as Double
        assertEquals("1.5", norm(1.5))
        assertEquals("3", norm(3.0))
        assertEquals("-0", norm(-0.0))
        assertEquals("0.1", norm(0.1))
        assertEquals("NaN", norm(Double.NaN))
        assertEquals("Infinity", norm(Double.POSITIVE_INFINITY))
        assertEquals("0.30000000000000004", IntentJs.shortest(0.1 + 0.2))
        assertEquals("5", IntentJs.shortest(5.0))
        assertEquals("1.7976931348623157", IntentJs.shortest(1.7976931348623157).substring(0, 18))
        assertEquals("4.9e-324".toDouble(), IntentJs.shortest(4.9e-324).toDouble(), 0.0)
        assertEquals(n("2"), IntentJs.normNum("2.0"))
        assertEquals(n("x"), IntentJs.normNum("x"))
    }

    @Test fun normalizeTrees() {
        val inner = linkedMapOf<String, Any?>("z" to n("1.0"), "a" to listOf(n("2e0"), "s", null, true))
        val out = IntentJs.normalize(linkedMapOf<String, Any?>("k" to inner, "d" to 0.5, "i" to 7))
        assertEquals("{\"k\":{\"z\":1,\"a\":[2,\"s\",null,true]},\"d\":0.5,\"i\":7}", canonOrder(out))
        // a fresh copy: the input tree is untouched
        assertEquals(n("1.0"), inner["z"])
        val l = IntentJs.normalize(listOf(n("1.0"), listOf(n("3.0")))) as List<*>
        assertEquals(listOf(n("1"), listOf(n("3"))), l)
        assertEquals("s", IntentJs.normalize("s"))
        assertNull(IntentJs.normalize(null))
        assertEquals(7, IntentJs.normalize(7))
        val m = IntentJs.normalize(linkedMapOf<String, Any?>("b" to n("1"), "a" to n("2"))) as Map<*, *>
        assertEquals(listOf("b", "a"), m.keys.toList())
    }

    /** Insertion-order rendering (not the sorted canonical form), to pin the copy's member order and values. */
    private fun canonOrder(v: Any?): String = when (v) {
        null -> "null"
        is String -> "\"" + v + "\""
        is Json.Num -> v.raw
        is Map<*, *> -> v.entries.joinToString(",", "{", "}") { "\"${it.key}\":" + canonOrder(it.value) }
        is List<*> -> v.joinToString(",", "[", "]") { canonOrder(it) }
        else -> v.toString()
    }
}
