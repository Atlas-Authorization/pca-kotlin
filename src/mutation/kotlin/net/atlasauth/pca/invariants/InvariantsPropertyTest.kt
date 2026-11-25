package net.atlasauth.pca.invariants

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Runs the seeded safety-invariant property suite over the real core at the default seed and run count. */
class InvariantsPropertyTest {
    private inline fun <reified T : Throwable> throws(f: () -> Unit): T {
        try { f() } catch (t: Throwable) { if (t is T) return t; throw t }
        fail("expected ${T::class.java.simpleName}")
        throw IllegalStateException()
    }

    @Test fun everyInvariantHoldsAtTheDefaultSeed() {
        val results = InvariantProperties.checkInvariants(null, null, false)
        assertEquals(Invariants.INVARIANT_NAMES.size, results.size)
        for ((i, res) in results.withIndex()) {
            assertEquals(Invariants.INVARIANT_NAMES[i], res["name"])
            assertEquals("${res["name"]}: ${res["error"]}", true, res["ok"])
            assertEquals(Invariants.DEFAULT_NUM_RUNS.toLong(), res["numRuns"])
            assertEquals(Invariants.DEFAULT_SEED, res["seed"])
        }
    }

    @Test fun theRegistryMatchesTheNameList() = assertEquals(Invariants.INVARIANT_NAMES, InvariantProperties.INVARIANTS.keys.toList())

    @Test fun theSameSeedGeneratesTheSameCases() {
        val a = Rng(Invariants.DEFAULT_SEED)
        val b = Rng(Invariants.DEFAULT_SEED)
        for (i in 0 until 100) assertEquals(a.next(), b.next(), 0.0)
        assertEquals(Rng(1).string(0, 10), Rng(1).string(0, 10))
        assertTrue(Rng(7).bytes(32).contentEquals(Rng(7).bytes(32)))
    }

    /** mulberry32's first outputs for seed 1 (the reference generator's well-known sequence). */
    @Test fun theGeneratorIsMulberry32() {
        val r = Rng(1)
        assertEquals(0.6270739405881613, r.next(), 0.0)
        assertEquals(0.002735721180215478, r.next(), 0.0)
    }

    @Test fun aViolatedPropertyFailsTheRunWithItsIndex() {
        val e = throws<AssertionError> { InvariantProperties.run({ r -> r.next() < 0.5 }, 1000, 1) }
        assertTrue(e.message!!.contains("Property failed after"))
        InvariantProperties.run({ true }, 10, 1)
    }

    @Test fun aPropertyThatThrowsFails() {
        throws<AssertionError> { InvariantProperties.run({ throw IllegalStateException("boom") }, 5, 1) }
    }

    @Test fun aCheckOfZeroCasesIsRefused() {
        throws<IllegalArgumentException> { InvariantProperties.checkInvariants(0L, null, false) }
        throws<IllegalArgumentException> { InvariantProperties.checkInvariants(-3L, null, false) }
        throws<IllegalArgumentException> { InvariantProperties.checkInvariants(5L, 9007199254740992L, false) }
    }

    @Test fun bailStopsAtTheFirstFailure() {
        val all = InvariantProperties.checkInvariants(5L, 3L, true)
        assertFalse(all.isEmpty())
        assertTrue(all.size <= Invariants.INVARIANT_NAMES.size)
    }
}
