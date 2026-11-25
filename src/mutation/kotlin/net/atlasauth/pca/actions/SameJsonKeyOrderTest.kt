package net.atlasauth.pca.actions

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The version diff compares unit / default / resource id / bindings independent of object key order, never of list order. */
class SameJsonKeyOrderTest {
    private fun o(vararg kv: Pair<String, Any?>) = linkedMapOf(*kv)

    @Test fun reversedKeysAreTheSameValueAtAnyDepth() {
        val a = o("kind" to "money", "n" to o("x" to 1, "y" to listOf(o("p" to 1, "q" to 2))))
        val b = o("n" to o("y" to listOf(o("q" to 2, "p" to 1)), "x" to 1), "kind" to "money")
        assertTrue(J.sameJson(a, true, b, true))
        assertTrue(J.sameJsonMember(o("unit" to a), o("unit" to b), "unit"))
    }

    @Test fun listOrderAndValuesStillMatter() {
        assertFalse(J.sameJson(listOf(1, 2), true, listOf(2, 1), true))
        assertFalse(J.sameJson(o("a" to 1, "b" to 2), true, o("b" to 2, "a" to 3), true))
        assertFalse(J.sameJson(null, true, null, false))
    }
}
