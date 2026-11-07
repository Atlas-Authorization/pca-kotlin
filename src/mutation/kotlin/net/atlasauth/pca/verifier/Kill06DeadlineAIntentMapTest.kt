package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.seed
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** Deadline tests (BRIEF-deadline): IntentMap split / u64be / cellOf / decide loops, run under a 5 s deadline. */
class Kill06DeadlineAIntentMapTest {
    private fun <T> dl(b: () -> T): T = Deadline.within { b() }

    @Test fun u64beBytes() = dl {
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), IntentMap.u64be(0x0102030405060708L))
        assertArrayEquals(byteArrayOf(0, 0, 0, 0, 0, 0, 1, 0), IntentMap.u64be(256L))
        assertArrayEquals(ByteArray(8) { 0xff.toByte() }, IntentMap.u64be(-1L))
    }

    @Test fun commitLeavesEverySplitSize() = dl {
        val seen = HashSet<String>()
        for (n in 1..9) {
            val ls = ArrayList<Any?>()
            for (i in 0 until n) ls.add(jm("kind", "cell", "salt", Pca.b64(seed("dl/salt/$i")), "leaf", jm("verb", "v", "cell", jl(i.toLong()), "p_ppm", 1L, "in_grant", true)))
            val c = IntentMap.commitLeaves(ls)
            assertEquals(43, c.length)
            assertEquals(true, seen.add(c))
        }
    }

    @Test fun existingKillSuiteUnderDeadline() = dl {
        val t = IntentMapKillTest()
        t.commitmentMatchesTheReferenceShape()
        t.grantedCellAndPolicyBound()
        t.prefixOrder()
        t.rootFromPathShape()
        t.valuesOutsideTheirDimension()
        t.openingsAndLayout()
    }
}
