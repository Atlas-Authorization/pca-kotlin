package net.atlasauth.pca.verifier

import org.junit.Assert.*
import org.junit.Test

/** Direct boundary kills for SafeRegex: hex-escape digit classes and the isSafeSource guard's character / cost boundaries. */
class K042SafeRegexGuardTest {
    private val HEX = "0123456789abcdefABCDEF"

    @Test fun hexDigitsAcceptedEveryPositionOfXAndU() {
        for (c in HEX) {
            for (pos in 0 until 2) {
                val d = if (pos == 0) "" + c + "0" else "0" + c
                assertNotNull("\\x$d", SafeRegex.compile("\\x$d"))
            }
            for (pos in 0 until 4) {
                val d = StringBuilder("0000")
                d.setCharAt(pos, c)
                assertNotNull("\\u$d", SafeRegex.compile("\\u$d"))
            }
        }
    }

    @Test fun justOutsideEveryHexRangeIsRefused() {
        for (c in charArrayOf('/', ':', '@', 'G', '`', 'g', 'z', ' ')) {
            for (pos in 0 until 2) {
                val d = if (pos == 0) "" + c + "0" else "0" + c
                assertNull("\\x$d", SafeRegex.compile("\\x$d"))
                assertFalse(SafeRegex.isSafeSource("\\x$d"))
            }
            for (pos in 0 until 4) {
                val d = StringBuilder("0000")
                d.setCharAt(pos, c)
                assertNull("\\u$d", SafeRegex.compile("\\u$d"))
            }
        }
        assertNull(SafeRegex.compile("\\x0"))
        assertNull(SafeRegex.compile("\\u000"))
        assertEquals(true, SafeRegex.fullMatch("\\x41\\u0042", "AB"))
        assertEquals(true, SafeRegex.fullMatch("\\xaF\\uAbCd", "¯ꯍ"))
    }

    @Test fun backreferenceAndNamedEscapesAreRefusedByTheGuard() {
        for (c in '1'..'9') assertFalse("\\" + c, SafeRegex.isSafeSource("(a)\\" + c))
        assertFalse(SafeRegex.isSafeSource("\\k"))
        assertFalse(SafeRegex.isSafeSource("a\\"))
        assertTrue(SafeRegex.isSafeSource("a\\."))
        assertTrue(SafeRegex.isSafeSource("a\\d"))
        assertFalse(SafeRegex.isSafeSource("a\\j")) // an unknown escape does not compile
    }

    @Test fun classScanning() {
        assertTrue(SafeRegex.isSafeSource("[^a]"))
        assertTrue(SafeRegex.isSafeSource("[^\\]a]"))
        assertFalse(SafeRegex.isSafeSource("[a"))
        assertFalse(SafeRegex.isSafeSource("["))
        assertFalse(SafeRegex.isSafeSource("[^"))
        assertFalse(SafeRegex.isSafeSource("[\\]"))
        assertTrue(SafeRegex.isSafeSource("[\\]]"))
    }

    @Test fun costBudgetBoundary() {
        assertTrue(SafeRegex.isSafeSource("a*b*"));                       // 16 bits
        assertTrue(SafeRegex.isSafeSource("a*b*" + "|".repeat(6)));       // 22: allowed
        assertFalse(SafeRegex.isSafeSource("a*b*" + "|".repeat(7)));      // 23
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,63}"));                // 16 + ceilLog2(64) = 22
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}c?"))  // 23
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,62}"));                // 16 + ceilLog2(63) = 22
        assertTrue(SafeRegex.isSafeSource("a{0,1}a{2}a{3,3}"));           // 1 + 0 + 0
        assertTrue(SafeRegex.isSafeSource("a{0,64}"))
        assertFalse(SafeRegex.isSafeSource("a{0,65}"))
        assertFalse(SafeRegex.isSafeSource("a{2,1}"))
        assertTrue(SafeRegex.isSafeSource("a{2,}"))
        assertFalse(SafeRegex.isSafeSource("a{65,}")) // does not compile
        assertFalse(SafeRegex.isSafeSource("a{"))
        assertFalse(SafeRegex.isSafeSource("a{x}"))
    }

    @Test fun structureGuards() {
        assertFalse(SafeRegex.isSafeSource("*a"))
        assertFalse(SafeRegex.isSafeSource("(*a)"))
        assertFalse(SafeRegex.isSafeSource("a|*"))
        assertFalse(SafeRegex.isSafeSource("(a*)*"))
        assertFalse(SafeRegex.isSafeSource("(a|b)*"))
        assertFalse(SafeRegex.isSafeSource("(a|b){2}"))
        assertTrue(SafeRegex.isSafeSource("(a)*"))
        assertTrue(SafeRegex.isSafeSource("(?:a)+"))
        assertTrue(SafeRegex.isSafeSource("(a*)b"))
        assertTrue(SafeRegex.isSafeSource("(a|b)c*"))
        assertFalse(SafeRegex.isSafeSource("(?=a)"))
        assertFalse(SafeRegex.isSafeSource("(?"))
        assertFalse(SafeRegex.isSafeSource("(?<n>a)"))
        assertFalse(SafeRegex.isSafeSource("(a"))
        assertFalse(SafeRegex.isSafeSource("a)"))
        assertTrue(SafeRegex.isSafeSource("(a*)(b*)"))
        assertFalse(SafeRegex.isSafeSource(null))
        assertTrue(SafeRegex.isSafeSource("a*?"))
        assertTrue(SafeRegex.isSafeSource("a??"))
        assertTrue(SafeRegex.isSafeSource(""))
    }
}
