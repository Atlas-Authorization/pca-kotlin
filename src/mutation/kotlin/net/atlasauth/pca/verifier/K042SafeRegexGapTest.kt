package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Boundary kills for SafeRegex parser / char-set internals that the TS-differential corpus does not reach. */
class K042SafeRegexGapTest {
    private fun fm(p: String, s: String): Boolean? = SafeRegex.fullMatch(p, s)

    @Test fun binarySearchOverManyRanges() {
        val ins = (0 until 40).map { intArrayOf(4 * it, 4 * it + 1) }
        val rs = SafeRegex.normalize(ins)
        val pos = SafeRegex.CharSet(rs, false); val neg = SafeRegex.CharSet(rs, true)
        for (c in 0..170) {
            val inside = c < 160 && c % 4 < 2
            assertEquals("has $c", inside, pos.has(c))
            assertEquals("negated has $c", !inside, neg.has(c))
        }
        val three = SafeRegex.CharSet(arrayOf(intArrayOf(10, 12), intArrayOf(20, 22), intArrayOf(30, 32)), false)
        for (c in intArrayOf(9, 10, 12, 13, 19, 20, 22, 23, 29, 30, 32, 33)) assertEquals("three $c", listOf(10, 11, 12, 20, 21, 22, 30, 31, 32).contains(c), three.has(c))
    }

    @Test fun complementReachesTheLastCodeUnit() {
        assertEquals("[[65535, 65535]]", SafeRegex.complement(arrayOf(intArrayOf(0, 0xfffe))).map { it.toList() }.toString())
        assertEquals("[]", SafeRegex.complement(arrayOf(intArrayOf(0, 0xffff))).map { it.toList() }.toString())
        assertEquals("[[0, 65533]]", SafeRegex.complement(arrayOf(intArrayOf(0xfffe, 0xffff))).map { it.toList() }.toString())
        assertEquals(true, fm("[\\D]", "\uffff"))
        assertEquals(true, fm("[\\W]", "\uffff"))
    }

    @Test fun nulCharactersAreOrdinary() {
        assertEquals(true, fm("\\\u0000", "\u0000"))
        assertEquals(true, fm("[\u0000]", "\u0000"))
        assertEquals(false, fm("[\u0000]", "a"))
        assertEquals(true, fm("[\u0000-\u0001]", "\u0001"))
        assertEquals(false, fm("[\u0000-\u0001]", "-"))
        assertEquals(true, fm("[\u0000-\u0000]", "\u0000"))
        assertEquals(false, fm("[\u0000-\u0000]", "-"))
        assertNull(SafeRegex.compile("[a-\u0000]"))
        assertEquals(true, fm("[\\0-\\x01]", "\u0001"))
    }

    @Test fun classDashHandlingAtEveryOffset() {
        for (pad in 0 until 140) {
            val p = "a".repeat(pad)
            assertEquals("range pad $pad", true, fm("$p[a-c]", p + "b"))
            assertEquals("range dash pad $pad", false, fm("$p[a-c]", "$p-"))
            assertEquals("trailing dash pad $pad", true, fm("$p[a-]", "$p-"))
            assertEquals("trailing dash pad $pad", false, fm("$p[a-]", p + "b"))
        }
        assertEquals(true, fm("[\\]-a]", "^"))
        assertEquals(false, fm("[\\]-a]", "-"))
        assertEquals(true, fm("[\\]-a]", "a"))
        assertNull(SafeRegex.compile("[a-"))
        assertNull(SafeRegex.compile("[a-b"))
        assertEquals(true, fm("[\\d-x]", "-")); assertEquals(true, fm("[\\d-x]", "x")); assertEquals(true, fm("[\\d-x]", "5")); assertEquals(false, fm("[\\d-x]", "w"))
        assertEquals(true, fm("[a-\\d]", "-")); assertEquals(true, fm("[a-\\d]", "7")); assertEquals(false, fm("[a-\\d]", "b"))
    }

    @Test fun hexEscapesRejectSignsAndNonAsciiDigits() {
        for (p in listOf("\\x+1", "\\x-1", "\\x1+", "\\u+001", "\\u-001", "\\u001-", "\\u00+1", "\\x\uff11\uff11", "\\u\u0661\u0661\u0661\u0661", "\\x 1", "\\x1 "))
            assertNull(p, SafeRegex.compile(p))
        assertNull(SafeRegex.compile("\\x")); assertNull(SafeRegex.compile("\\x4")); assertNull(SafeRegex.compile("\\u123"))
        assertEquals(true, fm("\\x41", "A")); assertEquals(true, fm("\\x4a", "J")); assertEquals(true, fm("\\u0041", "A"))
        assertEquals(true, fm("a\\x41", "aA")); assertEquals(true, fm("\\u00e9", "\u00e9"))
    }

    private val DIG = SafeRegex.compile("\\d")!!; private val NDIG = SafeRegex.compile("\\D")!!
    private val WRD = SafeRegex.compile("\\w")!!; private val NWRD = SafeRegex.compile("\\W")!!
    private val SPC = SafeRegex.compile("\\s")!!; private val NSPC = SafeRegex.compile("\\S")!!
    private val CDIG = SafeRegex.compile("[\\d]")!!; private val CNDIG = SafeRegex.compile("[\\D]")!!
    private val CNWRD = SafeRegex.compile("[\\W]")!!; private val CNSPC = SafeRegex.compile("[\\S]")!!
    private val DOT = SafeRegex.compile(".")!!

    @Test fun escapeSetsAreExact() {
        for (c in 0..0xffff) {
            val s = c.toChar().toString()
            val d = c in '0'.code..'9'.code
            val w = d || c in 'a'.code..'z'.code || c in 'A'.code..'Z'.code || c == '_'.code
            val sp = c in 9..13 || c == 32 || c == 0xa0 || c == 0x1680 || c in 0x2000..0x200a || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff
            assertEquals("\\d $c", d, SafeRegex.run(DIG, s)); assertEquals("\\D $c", !d, SafeRegex.run(NDIG, s))
            assertEquals("\\w $c", w, SafeRegex.run(WRD, s)); assertEquals("\\W $c", !w, SafeRegex.run(NWRD, s))
            assertEquals("\\s $c", sp, SafeRegex.run(SPC, s)); assertEquals("\\S $c", !sp, SafeRegex.run(NSPC, s))
            assertEquals("[\\d] $c", d, SafeRegex.run(CDIG, s)); assertEquals("[\\D] $c", !d, SafeRegex.run(CNDIG, s))
            assertEquals("[\\W] $c", !w, SafeRegex.run(CNWRD, s)); assertEquals("[\\S] $c", !sp, SafeRegex.run(CNSPC, s))
            assertEquals(". $c", c != 10 && c != 13 && c != 0x2028 && c != 0x2029, SafeRegex.run(DOT, s))
        }
    }

    @Test fun identityEscapesAndControlEscapes() {
        for (c in "@[`{:/!\"#%&',-;<=>~ ^$.*+?()[]{}|\\/") assertEquals("\\$c", true, fm("\\" + c, c.toString()))
        for (c in "AZaz09_BDSWdswkKpPuxcb") {
            if ("dswDSWxuc0".indexOf(c) >= 0) continue
            assertNull("\\$c", SafeRegex.compile("\\" + c))
        }
        for (p in listOf("\\9", "\\1", "\\00", "\\01", "\\c1", "\\c@", "\\c[", "\\c`", "\\c{", "\\c", "\\b", "a\\")) assertNull(p, SafeRegex.compile(p))
        assertEquals(true, fm("\\0", "\u0000")); assertEquals(true, fm("\\0a", "\u0000a"))
        assertEquals(true, fm("\\ca", "\u0001")); assertEquals(true, fm("\\cA", "\u0001")); assertEquals(true, fm("\\cz", "\u001a")); assertEquals(true, fm("\\cZ", "\u001a"))
        assertEquals(true, fm("[\\b]", "\b"))
        for ((p, s) in listOf("\\t" to "\t", "\\n" to "\n", "\\v" to "\u000b", "\\f" to "\u000c", "\\r" to "\r")) assertEquals(p, true, fm(p, s))
    }

    @Test fun quantifierWindow() {
        assertEquals(true, fm("a{0,2}", "aa"))
        for (p in listOf("a{12345}", "a{1,12345}", "a{1234,5678}", "a{2,1}", "a{,2}", "a{1,2", "a{", "{1}")) assertNull(p, SafeRegex.compile(p))
        assertEquals(true, fm("a{2,}", "aaaa")); assertEquals(false, fm("a{2,}", "a"))
        assertEquals(true, fm("a{2}", "aa")); assertEquals(false, fm("a{2}", "aaa")); assertEquals(true, fm("a{0,2}?", "aa"))
    }

    @Test fun alternationOfOneAndMany() {
        assertEquals(true, fm("a|b", "b")); assertEquals(true, fm("a|b|c", "c")); assertEquals(false, fm("a|b|c", "d"))
        assertEquals(true, fm("(?:ab|cd)e", "cde")); assertEquals(true, fm("|a", "")); assertEquals(true, fm("a|", ""))
        assertEquals(true, fm("", "")); assertEquals(false, fm("", "a"))
    }

    @Test fun stepCapBoundaryIsExact() {
        val two = SafeRegex.compile("a")!!; val three = SafeRegex.compile("ab")!!
        assertEquals(2, two.size()); assertEquals(3, three.size())
        assertNotNull(SafeRegex.run(two, "a".repeat(999_999)))
        assertNull(SafeRegex.run(two, "a".repeat(1_000_000)))
        assertNotNull(SafeRegex.run(three, "a".repeat(666_665)))
        assertNull(SafeRegex.run(three, "a".repeat(666_666)))
    }

    @Test fun guardScansEscapedBracketsAndLazyQuantifiers() {
        assertTrue(SafeRegex.isSafeSource("(?:[\\]|])+"))
        assertTrue(SafeRegex.isSafeSource("(?:[\\]a|b])+"))
        assertFalse(SafeRegex.isSafeSource("(?:[a]|b)+"))
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,63}?"))
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}??"))
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}c?"))
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,62}?"))
        assertTrue(SafeRegex.isSafeSource("a{1,2}?b{1,2}?"))
    }
}
