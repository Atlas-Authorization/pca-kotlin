package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * IntentMap.u64be fills eight bytes from the last one down. A mutant that stops the loop counter from moving spins on one
 * byte for ever (it allocates nothing), so it must FAIL a test at a deadline instead of ending as a PIT timeout nobody decided.
 */
class Kill10U64beDeadlineTest {
    @Test
    fun u64beEndsAndFillsEveryByte() {
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), Deadline.within { IntentMap.u64be(0x0102030405060708L) })
        assertArrayEquals(ByteArray(8) { -1 }, Deadline.within { IntentMap.u64be(-1L) })
        assertArrayEquals(ByteArray(8), Deadline.within { IntentMap.u64be(0L) })
    }
}
