package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Kill tests for SafeRegex outside the parser / compiler differential: range normalisation and complement, the CharSet search, ceilLog2, the run() step cap and the per-document budget. */
class K042SafeRegexUnitTest {
    private fun rs(vararg v: Int): Array<IntArray> = Array(v.size / 2) { intArrayOf(v[2 * it], v[2 * it + 1]) }
    private fun str(r: Array<IntArray>) = r.map { it.toList() }.toString()

    @Test fun normalizeSortsAndMergesOverlappingAndAdjacentRangesWithoutTouchingTheInput() {
        val inp = rs(5, 7, 1, 2, 3, 4, 10, 10, 8, 8, 12, 20, 13, 14, 22, 30, 21, 21)
        val copy = inp.map { it.clone() }
        assertEquals(str(rs(1, 8, 10, 10, 12, 30)), str(SafeRegex.normalize(inp.toList())))
        assertEquals("normalize must not mutate its input", copy.map { it.toList() }.toString(), inp.map { it.toList() }.toString())
        assertEquals(str(rs(1, 10)), str(SafeRegex.normalize(rs(1, 10, 2, 3).toList())))
        assertEquals(str(rs(1, 3, 5, 6)), str(SafeRegex.normalize(rs(5, 6, 1, 3).toList())))
        assertEquals(str(rs(0, 0, 2, 2)), str(SafeRegex.normalize(rs(2, 2, 0, 0).toList())))
        assertEquals(str(rs(0, 0)), str(SafeRegex.normalize(rs(0, 0, 0, 0).toList())))
        assertEquals("[]", str(SafeRegex.normalize(emptyList())))
        val one = rs(3, 4)
        assertNotSame(one[0], SafeRegex.normalize(one.toList())[0])
    }

    @Test fun complementIsExactAtBothEndsOfTheCodeUnitSpace() {
        assertEquals(str(rs(0, 0xffff)), str(SafeRegex.complement(emptyArray())))
        assertEquals("[]", str(SafeRegex.complement(rs(0, 0xffff))))
        assertEquals(str(rs(1, 0xffff)), str(SafeRegex.complement(rs(0, 0))))
        assertEquals(str(rs(0, 0xfffe)), str(SafeRegex.complement(rs(0xffff, 0xffff))))
        assertEquals(str(rs(0, 0, 3, 4, 8, 0xffff)), str(SafeRegex.complement(rs(5, 7, 1, 2))))
        assertEquals(str(rs(0, 1, 6, 0xffff)), str(SafeRegex.complement(rs(4, 5, 2, 3))))
        assertEquals(str(rs(1, 1, 0xfffe, 0xfffe)), str(SafeRegex.complement(rs(0, 0, 2, 0xfffd, 0xffff, 0xffff))))
        val inp = rs(9, 9, 1, 1)
        SafeRegex.complement(inp)
        assertEquals("complement must not mutate its input", str(rs(9, 9, 1, 1)), str(inp))
    }

    @Test fun charSetHasAgreesWithALinearScanOnEveryCodeUnit() {
        val sets = listOf(emptyArray(), rs(0, 0), rs(0xffff, 0xffff), rs(0, 0xffff), rs(0x30, 0x39), rs(0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a),
            rs(0x09, 0x0d, 0x20, 0x20, 0xa0, 0xa0, 0x1680, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x202f, 0x205f, 0x205f, 0x3000, 0x3000, 0xfeff, 0xfeff),
            rs(1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13))
        for (r in sets) for (neg in listOf(false, true)) {
            val cs = SafeRegex.CharSet(r, neg)
            for (c in 0..0xffff) {
                val inside = r.any { c >= it[0] && c <= it[1] }
                if (cs.has(c) != (inside != neg)) fail("has($c) on ${str(r)} negated=$neg")
            }
        }
    }

    @Test fun ceilLog2IsExact() {
        val cases = listOf(2L to 1, 3L to 2, 4L to 2, 5L to 3, 7L to 3, 8L to 3, 9L to 4, 16L to 4, 17L to 5, 63L to 6, 64L to 6, 65L to 7, (1L shl 40) to 40, ((1L shl 40) + 1) to 41)
        for ((n, want) in cases) assertEquals("ceilLog2($n)", want, SafeRegex.ceilLog2(n))
    }

    @Test fun nullsAreRefused() {
        assertNull(SafeRegex.compile(null)); assertFalse(SafeRegex.isSafeSource(null)); assertNull(SafeRegex.fullMatch(null, "a"))
    }

    @Test fun runRefusesExactlyAboveTheStepCap() {
        val star = SafeRegex.compile("a*")!!
        assertEquals(4, star.size())
        assertEquals(true, SafeRegex.run(star, "a".repeat(499_999)))
        assertNull(SafeRegex.run(star, "a".repeat(500_000)))
        assertEquals(false, SafeRegex.run(star, "a".repeat(499_998) + "b"))
        val a = SafeRegex.compile("a")!!
        assertEquals(2, a.size())
        assertEquals(false, SafeRegex.run(a, "a".repeat(999_999)))
        assertNull(SafeRegex.run(a, "a".repeat(1_000_000)))
        assertEquals(true, SafeRegex.fullMatch("a", "a"))
        assertNull(SafeRegex.fullMatch("a*", "a".repeat(500_000)))
        val big = SafeRegex.compile("a".repeat(4095))!!
        assertEquals(4096, big.size())
        assertNull(SafeRegex.run(big, "a".repeat(600_000)))
        assertNull(SafeRegex.run(big, "a".repeat(488)))
        assertEquals(false, SafeRegex.run(big, "a".repeat(487)))
    }

    private fun state(b: SafeRegex.Budget, ev: Int, chars: Int, steps: Long, refusals: Int) {
        assertEquals("evaluations", ev, b.evaluations); assertEquals("chars", chars, b.chars); assertEquals("steps", steps, b.steps); assertEquals("refusals", refusals, b.refusals)
    }

    @Test fun budgetRefusesAnUncompilablePatternWithoutChargingIt() {
        val b = SafeRegex.Budget()
        assertFalse(b.charge("(a", 5)); state(b, 0, 0, 0, 1)
        assertTrue(b.charge("ab", 3)); state(b, 1, 2, 12, 1)
        assertFalse(b.charge("a{65}", 0)); state(b, 1, 2, 12, 2)
        assertTrue(b.charge("a*", 0)); state(b, 2, 4, 16, 2)
    }

    @Test fun budgetEvaluationCapIs64ThenPoisoned() {
        val b = SafeRegex.Budget()
        for (k in 1..64) { assertTrue("evaluation $k", b.charge("a", 1)); state(b, k, k, 4L * k, 0) }
        assertFalse(b.charge("a", 1)); state(b, 65, 64, 256, 1)
        assertFalse(b.charge("b", 0)); state(b, 65, 64, 256, 2)
    }

    @Test fun budgetSourceCharCapIs8192() {
        val big = "a".repeat(4095)
        val b = SafeRegex.Budget()
        assertTrue(b.charge(big, 0)); assertTrue(b.charge(big, 0)); state(b, 2, 8190, 8192, 0)
        assertTrue(b.charge("ab", 0)); state(b, 3, 8192, 8195, 0)
        assertFalse(b.charge("a", 0)); state(b, 65, 8192, 8195, 1)
        assertFalse(b.charge("a", 0)); state(b, 65, 8192, 8195, 2)
        val c = SafeRegex.Budget()
        assertTrue(c.charge(big, 0)); assertTrue(c.charge(big, 0))
        assertFalse(c.charge("abc", 0)); state(c, 65, 8190, 8192, 1)
    }

    @Test fun budgetStepCapIs5MillionComputedInLong() {
        val b = SafeRegex.Budget()
        assertTrue(b.charge("a", 2_499_999)); state(b, 1, 1, 5_000_000L, 0)
        assertFalse(b.charge("a", 0)); state(b, 65, 1, 5_000_000L, 1)
        val c = SafeRegex.Budget()
        assertFalse(c.charge("a", 2_500_000)); state(c, 65, 0, 0, 1)
        val d = SafeRegex.Budget()
        assertFalse(d.charge("a".repeat(4095), Int.MAX_VALUE - 1)); state(d, 65, 0, 0, 1)
        val e = SafeRegex.Budget()
        assertTrue(e.charge("ab", 1_666_665)); assertTrue(e.charge("", 0)); state(e, 2, 2, 4_999_999L, 0)
        assertTrue(e.charge("", 0)); state(e, 3, 2, 5_000_000L, 0)
        assertFalse(e.charge("", 0)); state(e, 65, 2, 5_000_000L, 1)
    }

    @Test fun chargeOutsideAScopeUsesAFreshBudgetEachTime() {
        for (k in 0 until 100) assertTrue("unscoped charge $k", SafeRegex.charge("a", 1))
        assertFalse(SafeRegex.charge("(", 1)); assertFalse(SafeRegex.charge("a", 2_500_000)); assertTrue(SafeRegex.charge("a", 2_499_999))
    }

    @Test fun withBudgetSharesOneBudgetAcrossNestedScopesAndClosesIt() {
        val seen = IntArray(3)
        val r = SafeRegex.withBudget {
            for (k in 0 until 60) if (SafeRegex.charge("a", 1)) seen[0]++
            SafeRegex.withBudget { for (k in 0 until 4) if (SafeRegex.charge("a", 1)) seen[1]++; null }
            if (SafeRegex.charge("a", 1)) seen[2]++
            "done"
        }
        assertEquals("done", r)
        assertEquals(listOf(60, 4, 0), seen.toList())
        assertTrue("the scope is closed afterwards", SafeRegex.charge("a", 1))
        assertEquals(7, SafeRegex.withBudget { 7 })
        try { SafeRegex.withBudget { for (k in 0 until 70) SafeRegex.charge("a", 1); throw IllegalStateException("x") }; fail() } catch (e: IllegalStateException) { assertEquals("x", e.message) }
        assertTrue(SafeRegex.charge("a", 1))
        assertEquals(true, SafeRegex.withBudget { var all = true; for (k in 0 until 64) all = all and SafeRegex.charge("a", 1); all && !SafeRegex.charge("a", 1) })
    }
}
