package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Direct kill tests for the Predicates internals: glob edge cases, fail-closed evaluation over a throwing context, path resolution. */
class K042PredJsUnitTest {
    private fun map(vararg kv: Pair<String, Any?>) = KUtil.m(*kv)
    private fun list(vararg xs: Any?) = KUtil.l(*xs)
    private val T = Predicates.Tri.TRUE; private val F = Predicates.Tri.FALSE; private val U = Predicates.Tri.UNKNOWN

    @Test fun globDirect() {
        assertNull(Predicates.globMatch("a\\", "a")); assertNull(Predicates.globMatch("\\", ""))
        assertEquals(true, Predicates.globMatch("", "")); assertEquals(false, Predicates.globMatch("", "a"))
        assertEquals(true, Predicates.globMatch("*", "")); assertEquals(true, Predicates.globMatch("**", "")); assertEquals(false, Predicates.globMatch("?", ""))
        assertEquals(true, Predicates.globMatch("a\\*b", "a*b")); assertEquals(false, Predicates.globMatch("a\\*b", "axb"))
        assertEquals(true, Predicates.globMatch("a\\?b", "a?b")); assertEquals(false, Predicates.globMatch("a\\?b", "axb"))
        assertEquals(true, Predicates.globMatch("a*", "a")); assertEquals(false, Predicates.globMatch("a*b", "a"))
        assertEquals(false, Predicates.globMatch("Ana", "xAna")); assertEquals(false, Predicates.globMatch("na", "Ana"))
        assertEquals(true, Predicates.globMatch("*a*a*a", "banana")); assertEquals(false, Predicates.globMatch("*a*a*a*a", "banana"))
        assertEquals(true, Predicates.globMatch("a\u0000", "a\u0000")); assertEquals(false, Predicates.globMatch("a*", "b\u0000")); assertEquals(false, Predicates.globMatch("?", "\u0000\u0000"))
    }

    private class BoomCtx : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("boom")
        override fun containsKey(key: String): Boolean = throw IllegalStateException("boom")
        override fun get(key: String): Any? = throw IllegalStateException("boom")
    }

    @Test fun evaluatorsFailClosedOnAThrowingContext() {
        val boom: Map<String, Any?> = BoomCtx()
        assertEquals(U, Predicates.evaluateConditionTri(map("field" to "env.a", "op" to "exists"), boom))
        assertEquals(U, Predicates.evaluateConditionTri(map("all_of" to list(map("field" to "env.a", "op" to "exists"))), boom))
        assertFalse(Predicates.evaluateCondition(map("field" to "env.a", "op" to "exists"), boom))
        assertFalse(Predicates.predicateMatches(map("verb" to "*"), boom))
        assertFalse(Predicates.evaluatePredicates(list(map("verb" to "*")), boom))
        val ok = map("action" to map("verb" to "v", "resource" to "r"))
        assertTrue(Predicates.evaluatePredicates(list(map("verb" to "*")), ok))
        val throwingList = object : AbstractList<Any?>() {
            override val size: Int get() = 1
            override fun get(index: Int): Any? = throw IllegalStateException("boom")
            override fun iterator(): Iterator<Any?> = throw IllegalStateException("boom")
        }
        assertFalse(Predicates.evaluatePredicates(throwingList, ok))
        assertFalse(Predicates.evaluatePredicates(null, ok)); assertFalse(Predicates.evaluatePredicates(map("verb" to "*"), ok)); assertFalse(Predicates.evaluatePredicates(list(), ok))
    }

    @Test fun resolvePathDirect() {
        val ctx = map("action" to map("verb" to "v", "resource" to "r", "params" to map("tags" to list("a", "b"), "" to "e")))
        val r = Predicates.resolvePath(ctx, "action.params.tags.1")
        assertTrue(r.found); assertEquals("b", r.value)
        assertFalse(Predicates.resolvePath(ctx, "action.params.tags.2").found); assertNull(Predicates.resolvePath(ctx, "action.params.tags.2").value)
        assertFalse(Predicates.resolvePath(ctx, "action.params.tags.01").found)
        assertEquals("e", Predicates.resolvePath(ctx, "action.params.").value)
        assertFalse(Predicates.resolvePath(ctx, "").found); assertFalse(Predicates.resolvePath(ctx, 5).found); assertFalse(Predicates.resolvePath(null, "action").found)
        assertFalse(Predicates.resolvePath(ctx, "env").found)
        assertTrue(Predicates.resolvePath(map("env" to null), "env").found)
        assertEquals(1, Predicates.resolvePath(map("env" to map("x" to 1)), "env.x").value)
    }
}
