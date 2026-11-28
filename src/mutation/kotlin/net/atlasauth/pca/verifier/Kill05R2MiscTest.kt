package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Round-2 kills from full run 41911466407 (small sites outside the big groups). */
class Kill05R2MiscTest {
    /** Pca.ApprovedGoal.fromJson never throws: a non-object, or non-string digests, give a malformed (fail-closed) ref. */
    @Test fun approvedGoalFromJsonIsTotal() {
        val notObj = Pca.ApprovedGoal.fromJson(5L)
        assertNull(notObj.goalDigest)
        assertNull(notObj.policyDigest)
        assertFalse(notObj.closed)
        assertFalse(notObj.isWellFormed)
        val nums = Pca.ApprovedGoal.fromJson(linkedMapOf("goal_digest" to 5L, "policy_digest" to listOf("x")))
        assertNull(nums.goalDigest)
        assertNull(nums.policyDigest)
        assertEquals(true, nums.closed)
        assertFalse(nums.isWellFormed)
        val mixed = Pca.ApprovedGoal.fromJson(linkedMapOf("goal_digest" to "g", "policy_digest" to 7L))
        assertEquals("g", mixed.goalDigest)
        assertNull(mixed.policyDigest)
    }

    /** IntentMap.cellError, pinned to intent-map-commit.ts (mutation-kill-r13-g4-map-commit.test.ts 'cell leaves'). */
    @Test fun mapCellLeaves() {
        fun c0(vararg over: Pair<String, Any?>): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("verb" to "v", "cell" to listOf(0L, 1L), "p_ppm" to 5L, "in_grant" to false)
            for ((k, v) in over) m[k] = v
            return m
        }
        assertNull(IntentMap.cellError(c0()))
        val noG = c0().toMutableMap().also { it.remove("in_grant") }
        val leaf = "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
        for (c in listOf(null, 5L, emptyList<Any?>(), c0("x" to 1L), noG)) assertEquals("$c", leaf, IntentMap.cellError(c))
        for (verb in listOf<Any?>("", 5L, "x".repeat(129)))
            assertEquals("cell.verb must be a non-empty string of at most 128 UTF-8 bytes", IntentMap.cellError(c0("verb" to verb)))
        assertNull(IntentMap.cellError(c0("verb" to "x".repeat(128))))
        val cells = listOf<Any?>("x", null, listOf(-1L), listOf(0L, -1L), listOf(1.5), listOf("0"), List(17) { 0L })
        for (cell in cells) assertEquals("$cell", "cell.cell must be an array of non-negative safe integers", IntentMap.cellError(c0("cell" to cell)))
        assertNull(IntentMap.cellError(c0("cell" to List(16) { 0L })))
        assertNull(IntentMap.cellError(c0("cell" to emptyList<Any?>())))
        for (p in listOf<Any?>(-1L, 1_000_001L, 1.5, "5"))
            assertEquals("$p", "cell.p_ppm must be a safe integer in [0, 1000000]", IntentMap.cellError(c0("p_ppm" to p)))
        for (p in listOf(0L, 1_000_000L)) assertNull(IntentMap.cellError(c0("p_ppm" to p)))
        for (g in listOf<Any?>(1L, "true", null)) assertEquals("cell.in_grant must be a boolean", IntentMap.cellError(c0("in_grant" to g)))
        assertNull(IntentMap.cellError(c0("in_grant" to true)))
    }

    /** IntentJs.jsKeys: array-index keys ascending by VALUE whatever their insertion order, then the rest in insertion order. */
    @Test fun jsKeysSortsIndexKeysNumerically() {
        fun keys(vararg k: String) = IntentJs.jsKeys(linkedMapOf<String, Any?>(*k.map { it to 1L }.toTypedArray()))
        assertEquals(listOf("0", "1", "2", "b", "a"), keys("b", "0", "1", "a", "2"))
        assertEquals(listOf("0", "1", "2"), keys("0", "1", "2"))
        assertEquals(listOf("9", "10", "100"), keys("100", "10", "9"))
        assertEquals(listOf("2", "10", "x"), keys("10", "x", "2"))
    }

    /** Predicates.describeCondition / showValue / firstUnmetLimit edges. */
    @Test fun limitDescriptions() {
        assertEquals("x <condition>", Predicates.describeCondition(linkedMapOf("field" to "action.params.x", "op" to 5L, "value" to 1L)))
        assertEquals("x <condition>", Predicates.describeCondition(linkedMapOf("field" to "action.params.x", "op" to "nope", "value" to 1L)))
        assertEquals("x == 1", Predicates.describeCondition(linkedMapOf("field" to "action.params.x", "op" to "eq", "value" to 1L)))
        // every character is checked, the first one included
        assertEquals("\"...\"", Predicates.showValue("\"ab"))
        assertEquals("\"...\"", Predicates.showValue("\u0001ab"))
        assertEquals("\"ab\"", Predicates.showValue("ab"))
        assertEquals("\"...\"", Predicates.showValue("ab\\"))
        val pay = Json.parseLenient("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":500,\"cur\":\"eur\"}}}") as Map<String, Any?>
        // a predicate whose limits are all met does not end the search: the next in-scope predicate's unmet limit is named
        val two = "[{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"gte\",\"value\":1}]}," +
            "{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.cur\",\"op\":\"eq\",\"value\":\"usd\"}]}]"
        assertEquals("cur == \"usd\"", Predicates.firstUnmetLimit(Json.parseLenient(two), pay))
        // of two unmet limits the first is named
        val both = "[{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.cur\",\"op\":\"eq\",\"value\":\"usd\"}," +
            "{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}]"
        assertEquals("cur == \"usd\"", Predicates.firstUnmetLimit(Json.parseLenient(both), pay))
    }

    /** Predicates.resolvePath never throws: a non-string or empty path is not found. */
    @Test fun resolvePathRefusesNonStringPaths() {
        val ctx = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to "v"))
        for (path in listOf<Any?>(5L, null, listOf("action"), "")) {
            val r = Predicates.resolvePath(ctx, path)
            assertFalse("$path", r.found)
            assertNull("$path", r.value)
        }
        assertEquals("v", Predicates.resolvePath(ctx, "action.verb").value)
    }

    /**
     * IntentV2 rule 21 (`tighten`) is reported only when envelope.tighten, a model_polarity (envelope or policy) or a
     * model-read path is present (intent-v2.ts decideIntentV2); a grant without an envelope reports nothing and never throws.
     */
    @Test fun tightenIsNotReportedWithoutATrigger() {
        val p = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to "v", "resource" to "r"))
        for (grant in listOf<Map<String, Any?>?>(null, linkedMapOf("caveats" to emptyList<Any?>()))) {
            val d = IntentV2.decide(p, grant, null, 0L)
            assertEquals("$grant", emptyList<String>(), d.checks.map { it.name })
        }
    }

    /**
     * Json.compareUtf8 encodes each LONE surrogate as U+FFFD (TS TextEncoder; Java's encoder writes '?'), then breaks an
     * equal-bytes tie by UTF-16 code-unit order (hash.ts compareUtf8: `a < b ? -1 : 1`); a valid pair is kept.
     */
    @Test fun compareUtf8LoneSurrogatesAreFffd() {
        // as EF BF BD a lone surrogate sorts after 'a' (61) and before U+FFFE (EF BF BE); as '?' (3F) it would sort before 'a'
        for (lone in listOf("x\uDC00", "x\uD800")) assertTrue(lone, Json.compareUtf8(lone, "xa") > 0)
        assertTrue(Json.compareUtf8("\uD800x", "ax") > 0) // a lone high before a non-surrogate
        assertTrue(Json.compareUtf8("a\uD800", "a\uFFFE") < 0) // a lone high at the end
        assertTrue(Json.compareUtf8("\uD83D\uDE00\uD800", "\uD83D\uDE00a") > 0) // a pair kept, then a lone high
        // equal bytes (lone vs U+FFFD): the UTF-16 code-unit tie-break, never 0
        assertTrue(Json.compareUtf8("x\uDC00", "x\uFFFD") < 0)
        assertTrue(Json.compareUtf8("x\uFFFD", "x\uDC00") > 0)
        assertTrue(Json.compareUtf8("\uD800", "\uDBFF") < 0)
        assertTrue(Json.compareUtf8("\uD83D\uDE00", "\uFFFD") > 0) // F0 9F 98 80 sorts after EF BF BD
    }
}
