package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Actions.closure must visit each trait id once. A mutant that drops the `seen` check re-expands every shared implication
 * (exponential on a ladder) and never ends on an implies cycle; both fail the deadline instead of hanging the run.
 */
class Kill07RunErrClosureTest {
    private fun trait(vararg implies: String): Map<String, Any?> = linkedMapOf("implies" to ArrayList<Any?>(implies.toList()))

    @Test fun aLadderOfSharedImplicationsIsWalkedOnce() {
        val reg = LinkedHashMap<String, Map<String, Any?>>()
        for (i in 0 until 60) {
            val deps = ArrayList<String>()
            if (i >= 1) deps.add("t%02d".format(i - 1))
            if (i >= 2) deps.add("t%02d".format(i - 2))
            reg["t%02d".format(i)] = trait(*deps.toTypedArray())
        }
        val got = Deadline.within { Actions.closure(reg, listOf("t59")) }
        assertEquals((0 until 60).map { "t%02d".format(it) }, got)
    }

    @Test fun anImpliesCycleTerminates() {
        val reg = linkedMapOf<String, Map<String, Any?>>("a" to trait("b"), "b" to trait("a"), "c" to trait("c"))
        assertEquals(listOf("a", "b"), Deadline.within { Actions.closure(reg, listOf("a")) })
        assertEquals(listOf("c"), Deadline.within { Actions.closure(reg, listOf("c")) })
    }
}
