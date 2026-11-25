package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * IntentHistory.accPost is public and takes an unvalidated accumulator map. An agg outside {sum, count, max, distinct} is
 * refused before the hash-switched `when`s in IntentAcc.preValue / combineAcc can see it, a colliding string included
 * ("tVm" has the hash of "sum"), as the reference accPost refuses it (intent-history.ts:115).
 */
class Kill05R2AccAggGuardTest {
    @Test
    fun anUnknownAggIsRefused() {
        assertEquals("sum".hashCode(), "tVm".hashCode())
        for (agg in listOf<Any?>("SUM", "tVm", "", null, 1L)) {
            val e = assertThrows(IllegalStateException::class.java) {
                IntentHistory.accPost(linkedMapOf("id" to "a", "agg" to agg), emptyList(), "send", emptyMap(), 1000L, null)
            }
            assertEquals("$agg", "accPost: unknown agg", e.message)
        }
        val absent = assertThrows(IllegalStateException::class.java) { IntentHistory.accPost(linkedMapOf("id" to "a"), emptyList(), "send", emptyMap(), 1000L, null) }
        assertEquals("accPost: unknown agg", absent.message)
    }
}
