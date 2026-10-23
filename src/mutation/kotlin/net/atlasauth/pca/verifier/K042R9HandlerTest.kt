package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * r9 fault injection for Predicates.predicateInner's handlers: a predicate whose member lookup throws (a RuntimeException, then a
 * StackOverflowError) does not match (default deny); the same predicate with a well-behaved lookup does match, so the false is the handler's.
 */
class K042R9HandlerTest {
    private val ctx: Map<String, Any?> = mapOf("action" to mapOf("verb" to "v", "resource" to "r"))

    private class Faulty(private val fault: () -> Nothing?) : AbstractMap<Any?, Any?>() {
        override val entries: Set<Map.Entry<Any?, Any?>> get() = emptySet()
        override fun get(key: Any?): Any? = if (key == "verb") fault() else null
        override fun containsKey(key: Any?): Boolean = false
    }

    @Test
    fun aThrowingLookupIsAPredicateThatDoesNotMatch() {
        assertTrue(Predicates.predicateMatches(mapOf("verb" to "v"), ctx))
        assertFalse(Predicates.predicateMatches(Faulty { throw IllegalStateException("boom") }, ctx))
        assertFalse(Predicates.predicateMatches(Faulty { throw StackOverflowError() }, ctx))
        assertFalse(Predicates.evaluatePredicates(listOf(Faulty { throw StackOverflowError() }), ctx))
        assertFalse(Predicates.evaluatePredicates(listOf(Faulty { throw IllegalStateException("boom") }), ctx))
        assertTrue(Predicates.evaluatePredicates(listOf(Faulty { throw StackOverflowError() }, mapOf("verb" to "v")), ctx))
    }
}
