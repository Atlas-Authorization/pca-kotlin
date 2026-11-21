package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests (BRIEF-deadline): SafeRegex, Predicates.globMatch, IntentJs, K3Sig, K4 cursors. */
class Kill06DeadlineARegexPredTest {
    private fun <T> dl(b: () -> T): T = Deadline.within { b() }

    @Test fun charSetBinarySearch() = dl {
        val rs = arrayOf(intArrayOf(2, 3), intArrayOf(10, 12), intArrayOf(20, 20), intArrayOf(30, 40), intArrayOf(100, 200))
        val cs = SafeRegex.CharSet(rs, false)
        val neg = SafeRegex.CharSet(rs, true)
        val inside = setOf(2, 3, 10, 11, 12, 20, 30, 35, 40, 100, 150, 200)
        for (c in listOf(0, 1, 2, 3, 4, 9, 10, 12, 13, 19, 20, 21, 29, 30, 40, 41, 99, 100, 200, 201, 70000)) {
            assertEquals("c=$c", c in inside, cs.has(c))
            assertEquals("neg c=$c", c !in inside, neg.has(c))
        }
        assertFalse(SafeRegex.CharSet(arrayOf(), false).has(5))
    }

    @Test fun complementAndNormalize() = dl {
        val c = SafeRegex.complement(arrayOf(intArrayOf(0x41, 0x5a), intArrayOf(0x30, 0x39), intArrayOf(0x3a, 0x40)))
        assertEquals(listOf(listOf(0, 0x2f), listOf(0x5b, 0xffff)), c.map { it.toList() })
        val c2 = SafeRegex.complement(arrayOf(intArrayOf(0x61, 0x62), intArrayOf(0x70, 0x71)))
        assertEquals(listOf(listOf(0, 0x60), listOf(0x63, 0x6f), listOf(0x72, 0xffff)), c2.map { it.toList() })
        assertArrayEquals(intArrayOf(0, 0xffff), SafeRegex.complement(arrayOf())[0])
        assertTrue(SafeRegex.fullMatch("[\\D]+", "abc") == true)
        assertTrue(SafeRegex.fullMatch("[\\D]+", "a1") == false)
    }

    @Test fun safeSourceScansEveryTokenKind() = dl {
        val src = "[^a\\]b]\\d(?:x|y)(z)w{2,3}?v*u+t?s"
        assertTrue(SafeRegex.isSafeSource(src))
        assertEquals(true, SafeRegex.fullMatch(src, "c5xzwwus"))
        assertEquals(false, SafeRegex.fullMatch(src, "]5xzwwus"))
        assertTrue(SafeRegex.isSafeSource("abc"))
        assertTrue(SafeRegex.isSafeSource("(ab)c|d"))
        assertTrue(SafeRegex.isSafeSource("\\.\\*x"))
        assertTrue(SafeRegex.isSafeSource("[\\\\a]b"))
        assertFalse(SafeRegex.isSafeSource("(a+)+"))
        assertFalse(SafeRegex.isSafeSource("(a|b)*"))
        assertFalse(SafeRegex.isSafeSource("(a)\\1"))
        assertFalse(SafeRegex.isSafeSource("a{65}"))
        assertFalse(SafeRegex.isSafeSource("[abc"))
        assertFalse(SafeRegex.isSafeSource("a)"))
        assertFalse(SafeRegex.isSafeSource("*a"))
    }

    @Test fun runLongerSubjectsAndAlternation() = dl {
        assertEquals(true, SafeRegex.fullMatch("(?:ab|cd)+e", "abcdabe"))
        assertEquals(true, SafeRegex.fullMatch("a.*b", "a" + "x".repeat(50) + "b"))
        assertEquals(false, SafeRegex.fullMatch("a.*b", "a" + "x".repeat(50)))
        assertEquals(true, SafeRegex.fullMatch("^[a-c]{3,5}$", "abcab"))
        assertEquals(false, SafeRegex.fullMatch("[a-c]{3,5}", "abcabc"))
        assertEquals(true, SafeRegex.fullMatch("x?y?z?", ""))
    }

    @Test fun globMatchCursors() = dl {
        assertEquals(true, Predicates.globMatch("a*b?c", "aXXbYc"))
        assertEquals(true, Predicates.globMatch("*", "anything"))
        assertEquals(true, Predicates.globMatch("a**b", "aXb"))
        assertEquals(true, Predicates.globMatch("ab*", "ab"))
        assertEquals(true, Predicates.globMatch("ab**", "abzz"))
        assertEquals(true, Predicates.globMatch("*ab", "xaab"))
        assertEquals(true, Predicates.globMatch("*a*b*c", "zzazzbzzc"))
        assertEquals(true, Predicates.globMatch("a\\*b", "a*b"))
        assertEquals(false, Predicates.globMatch("a\\*b", "aXb"))
        assertEquals(false, Predicates.globMatch("a*b", "aXc"))
        assertEquals(false, Predicates.globMatch("a?c", "ac"))
        assertEquals(false, Predicates.globMatch("abc", "abcd"))
        assertEquals(true, Predicates.globMatch("", ""))
        assertEquals(null, Predicates.globMatch("a\\", "a"))
    }

    @Test fun intentJsUtf8AndJsonEquals() = dl {
        assertEquals(0, IntentJs.u8len(""))
        assertEquals(10, IntentJs.u8len("aé€😀"))
        assertEquals(3, IntentJs.u8len("\uD83D"))
        assertEquals(8, IntentJs.u8len("😀😁"))
        assertEquals(5, IntentJs.u8len("hello"))
        val n = { s: String -> Json.Num(s) }
        assertTrue(IntentJs.jsonEquals(listOf(n("1"), "a", listOf(true, null)), listOf(n("1"), "a", listOf(true, null))))
        assertFalse(IntentJs.jsonEquals(listOf(n("1"), n("2"), n("3")), listOf(n("1"), n("2"), n("4"))))
        assertFalse(IntentJs.jsonEquals(listOf(n("1")), listOf(n("1"), n("2"))))
        assertTrue(IntentJs.jsonEquals(mapOf("a" to listOf(n("1"), n("2"))), mapOf("a" to listOf(n("1"), n("2")))))
    }

    @Test fun k3SigDigestAndLuhn() = dl {
        val a = K3Sig.digestOf("a" to "x", "b" to 2, "c" to listOf("q"))
        assertEquals(Pca.hashCanonical(linkedMapOf("a" to "x", "b" to 2, "c" to listOf("q"))), a)
        assertNotEquals(a, K3Sig.digestOf("a" to "x", "b" to 2))
        assertTrue(K4.looksLikePan("4111 1111 1111 1111"))
        assertTrue(K4.looksLikePan("order 5500-0000-0000-0004 shipped"))
        assertFalse(K4.looksLikePan("4111 1111 1111 1112"))
        assertFalse(K4.looksLikePan("1234"))
    }
}
