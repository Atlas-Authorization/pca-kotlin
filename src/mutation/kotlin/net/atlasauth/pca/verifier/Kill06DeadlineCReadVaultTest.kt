package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Deadline tests for ReadVault's samplers. Scripted [ReadVault.Draws] that cannot terminate a sampler count their calls and
 * throw once far past the documented give-up bound (100 000 steps), so a mutant that loses the bound fails at once instead of
 * spinning; the real code gives up with its own message at the exact count. No randomness: every stream is scripted or seeded.
 */
class Kill06DeadlineCReadVaultTest {
    private class Capped(val cap: Long, val f: (Long) -> Long) : ReadVault.Draws {
        var calls = 0L
        override fun uniform(n: Long): Long {
            if (++calls > cap) throw IllegalStateException("overrun: the sampler did not give up")
            return f(n)
        }
    }

    private fun iae(block: () -> Unit): String = try { block(); "no exception" } catch (e: IllegalArgumentException) { e.message ?: "" }

    @Test fun samplersGiveUpAtTheirBounds() {
        Deadline.within {
            // every Bernoulli succeeds: the exp(-1) trial never stops
            val zero = Capped(300_000) { 0L }
            assertEquals("bernoulli: no termination", iae { ReadVault.discreteLaplace(zero, 1, 1) })
            assertEquals(100_002L, zero.calls)
            // every exp(-1) trial succeeds at once: the geometric count never stops
            val high = Capped(300_000) { it }
            assertEquals("laplace: no termination", iae { ReadVault.discreteLaplace(high, 1, 3) })
            assertEquals(100_003L, high.calls)
            // every sample is a negative zero, rejected and redrawn until the outer bound
            val negZero = Capped(900_000) { if (it == 2L) 1L else 0L }
            assertEquals("laplace: no sample", iae { ReadVault.discreteLaplace(negZero, 1, 3) })
            assertEquals(500_000L, negZero.calls)
        }
    }

    @Test fun uniformGivesUpOnAStreamThatNeverFits() {
        Deadline.within {
            var reads = 0L
            val msg = iae { ReadVault.uniformOf(3) { if (++reads > 300_000) throw IllegalStateException("overrun"); (1L shl 48) - 1 } }
            assertEquals("uniform: no draw", msg)
            assertEquals(100_000L, reads)
        }
    }

    @Test fun samplersTerminateOnOrdinaryStreams() {
        Deadline.within {
            val a = ReadVault.seededDraws("k06-seed")
            val b = ReadVault.seededDraws("k06-seed")
            val xs = (0 until 40).map { ReadVault.discreteLaplace(a, 1, 2) }
            val ys = (0 until 40).map { ReadVault.discreteLaplace(b, 1, 2) }
            assertEquals(xs, ys) // seeded: the same stream gives the same samples
            // scripted: u = 2 of t = 5 accepted at the first trial; v = 1; sign negative -> -((2 + 5) / 3)
            val d = object : ReadVault.Draws {
                val vs = longArrayOf(2, 9, 9, 0, 1, 1)
                var at = 0
                override fun uniform(n: Long): Long = vs[at++]
            }
            assertEquals(-((2L + 5L) / 3L), ReadVault.discreteLaplace(d, 3, 5))
            assertEquals(6, d.at)
        }
    }
}
