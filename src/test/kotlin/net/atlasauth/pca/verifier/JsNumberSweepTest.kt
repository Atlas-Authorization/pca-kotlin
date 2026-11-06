package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The string-to-number helper against JavaScript `Number(x)` (ECMAScript StringToNumber). A form JS reads as NaN must never
 * become a number here: `String.toDouble` alone accepts "1f", "1d", "NaN" and hex floats.
 */
class JsNumberSweepTest {
    private fun js(s: String) = AttestNvidia.jsNumberFromString(s)

    @Test
    fun everyFormJsReadsAsNaNIsRefused() {
        for (s in listOf(
            "+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000",
            "١", "１", "infinity", "INFINITY", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L",
            "0x1p3", "0x1.8p1", "1F", "1D", "-NaN", "1\u0000", "\u0085", "\u180E", "\u00851", "1\u180E",
        )) assertNull("Number('$s') is NaN", js(s))
    }

    @Test
    fun everyFormJsReadsAsANumberParses() {
        val want = mapOf(
            "" to 0.0, "   " to 0.0, " 12 " to 12.0, "﻿12 " to 12.0, " ﻿" to 0.0,
            "Infinity" to Double.POSITIVE_INFINITY, "+Infinity" to Double.POSITIVE_INFINITY, "-Infinity" to Double.NEGATIVE_INFINITY,
            "0x10" to 16.0, "0X1f" to 31.0, "0o7" to 7.0, "0O10" to 8.0, "0b1" to 1.0, "0B11" to 3.0,
            "1." to 1.0, ".5" to 0.5, "1e3" to 1000.0, "+1.5" to 1.5, "-0" to -0.0,
            "0x" + "f".repeat(300) to Double.POSITIVE_INFINITY,
        )
        for ((s, v) in want) assertEquals("Number('$s')", v, js(s))
    }

    @Test
    fun aMonitorDeadlineReadsItsCountAsNumberDoes() {
        // intent-history.ts:143 Number(q.slice('pending:'.length)); the event matches neither p nor q
        val m = linkedMapOf<String, Any?>("kind" to "responds_within", "p" to mapOf("verb" to "a", "resource" to "*"), "q" to mapOf("verb" to "b", "resource" to "*"), "within" to 3L)
        val e = linkedMapOf<String, Any?>("verb" to "x", "resource" to "r", "params" to emptyMap<String, Any?>(), "status" to "committed")
        fun step(q: String) = IntentHistory.monitorStep(m, q, e)
        for (bad in listOf("1f", "1d", "NaN", "0x1p3", "+0x1", "1_0")) assertEquals(bad, "pending:NaN", step("pending:$bad"))
        assertEquals("missed", step("pending:")) // Number('') is 0
        assertEquals("pending:2", step("pending:﻿3 "))
        assertEquals("pending:15", step("pending:0x10"))
        assertEquals("pending:Infinity", step("pending:Infinity"))
    }

    @Test
    fun aVersionComponentReadsAsNumberDoes() {
        // a NaN component never compares equal
        for (bad in listOf("1f", "1d", "NaN", "0x1p0")) assertEquals(bad, 1, Bundle.compareVersion(bad, "1"))
        assertEquals(0, Bundle.compareVersion("0x1", "1"))
    }

    @Test
    fun aCharacterReferenceHasOnlyAsciiDigitsAndNoSign() {
        for (ent in listOf("#+65", "#x+41", "#١", "#x１")) {
            val e = org.junit.Assert.assertThrows(AttErr::class.java) { AttestXml.parse("<a>&$ent;</a>") }
            assertEquals(ent, "invalid character reference &$ent;", e.message)
        }
        assertEquals("A", AttestXml.parse("<a>&#65;</a>").root.textContent())
        assertEquals("A", AttestXml.parse("<a>&#x41;</a>").root.textContent())
    }
}
