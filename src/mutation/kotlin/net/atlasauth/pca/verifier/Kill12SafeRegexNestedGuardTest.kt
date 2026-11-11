package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SafeRegex.isSafeSource enforces two things that SafeRegex.compile does NOT: the 22-bit cost budget (a bounded repeat `{lo,hi}` costs
 * ceilLog2(hi - lo + 1) bits) and the rule that a quantified group may not contain an alternation, however deeply nested. Every
 * source below compiles; only the guard refuses it, so each assertion pins a line of the guard that the compile step cannot cover.
 */
class Kill12SafeRegexNestedGuardTest {
    private fun guard(src: String) = SafeRegex.isSafeSource(src)
    private fun compiles(src: String) = assertNotNull("must compile: $src", SafeRegex.compile(src))

    @Test fun aBoundedRepeatCostsCeilLog2OfItsOptionCount() {
        // options = hi - lo + 1: 65 options cost 7 bits (not 6); a `+ 1` that became `+ 0` would charge 64 options, 6 bits
        for (src in listOf("a*b*a{0,64}", "a*b*a{0,63}", "a*b*a{0,62}", "a*b*a{2,63}", "a*b*a{1,64}")) compiles(src)
        assertFalse(guard("a*b*a{0,64}"))      // 8 + 8 + ceilLog2(65) = 23 > 22
        assertTrue(guard("a*b*a{0,63}"))       // 8 + 8 + ceilLog2(64) = 22
        assertTrue(guard("a*b*a{0,62}"))       // 8 + 8 + ceilLog2(63) = 22
        assertTrue(guard("a*b*a{2,63}"))       // 62 options: 6 bits
        assertTrue(guard("a*b*a{1,64}"))       // 64 options: 6 bits
    }

    @Test fun everyOptionalFragmentIsChargedOneBit() {
        val twentyTwo = "a{0,1}".repeat(22)
        val twentyThree = "a{0,1}".repeat(23)
        compiles(twentyThree)
        assertTrue(guard(twentyTwo))            // 22 x ceilLog2(2) = 22 bits
        assertFalse(guard(twentyThree))         // 23 bits: a repeat charged 0 bits would let this through
        val exact = "a{3,4}".repeat(22) // two options each: 1 bit
        assertTrue(guard(exact))
        assertFalse(guard("a{3,4}".repeat(23)))
    }

    @Test fun aSingleOptionRepeatIsFree() {
        assertTrue(guard("a{3}".repeat(40)))
        assertTrue(guard("a{0}".repeat(40)))
    }

    @Test fun aGroupThatContainsANestedAlternationCannotBeQuantified() {
        for (s in listOf("(a|(b))*", "((a|b))*", "((a)|b)*", "(((a|b)))+", "(a|(b|c)){2}", "((a|b)c)*", "(c(a|b))*", "(?:a|(?:b))*")) {
            compiles(s)
            assertFalse(s, guard(s))
        }
        // the same groups without the quantifier, or with the quantifier after the alternation's group closed, are safe
        for (s in listOf("(a|(b))", "((a|b))", "(a|(b))c*", "((a|b))c*", "(a|b)(c)*", "((a)b)*")) {
            compiles(s)
            assertTrue(s, guard(s))
        }
    }

    @Test fun aGroupThatContainsANestedQuantifierCannotBeQuantified() {
        for (s in listOf("((a*))*", "(b(a*))*", "((a*)b)+")) {
            compiles(s)
            assertFalse(s, guard(s))
        }
        assertEquals(true, guard("((a*))b"))
    }
}
