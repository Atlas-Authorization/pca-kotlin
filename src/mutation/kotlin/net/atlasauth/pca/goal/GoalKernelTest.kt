package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Replay of the goal kernel over the kernel tape corpus (the reference's compiled kernel on the goal conformance vectors): every
 * op's output tape must be identical, as harness text.
 */
@Suppress("UNCHECKED_CAST")
class GoalKernelTest {
    private val m = "ref-goal-kernel"

    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun tape(s: String): List<Any?> {
        val t = GoalKernel.tapeFromText(s)
        assertEquals("tape text round trip", s, GoalKernel.tapeToText(t))
        return t
    }

    @Test fun tapeText() {
        val cases = OracleCases.of(m, "kernel")
        assertTrue(cases.size > 150)
        for (c in cases) { val a = l(c["args"]); tape(a[0] as String); tape(a[1] as String) }
        assertEquals("k5 i-3 s s68.1f600", GoalKernel.tapeToText(GoalKernel.tapeFromText("k5 i-3 s s68.1f600")))
        assertEquals("h😀", l(GoalKernel.tapeFromText("s68.1f600")[0])[1])
    }

    @Test fun kernelTapes() = OracleCases.each(m, "kernel") { a ->
        val g = tape(a[0] as String)
        val o = tape(a[1] as String)
        val out = LinkedHashMap<String, Any?>()
        for (op in listOf("typecheck", "compile", "render")) out[op] = GoalKernel.tapeToText(GoalKernel.call(op, g, o, null, null))
        out["probes"] = l(a[2]).map { p ->
            val pp = l(p)
            val act = tape(pp[0] as String)
            val hist = tape(pp[1] as String)
            listOf(
                GoalKernel.tapeToText(GoalKernel.call("decideg", g, o, act, hist)),
                GoalKernel.tapeToText(GoalKernel.call("decidep", g, o, act, hist)),
            )
        }
        out
    }

    /** The typed front door's renderTape is the kernel's: same tape as the corpus render of every canonical goal tape. */
    @Test fun compilerRenderTapeReplaysCorpus() {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(m, "kernel")) {
            val g = tape(l(c["args"])[0] as String)
            val goal = try { GoalCodec.decodeGoal(g) } catch (e: RuntimeException) { continue }  // a malformed goal tape has no typed goal
            if (GoalKernel.tapeToText(GoalCodec.encodeGoal(goal)) != GoalKernel.tapeToText(g)) continue  // not canonical
            if ("i0 " + GoalKernel.tapeToText(GoalCompiler.renderTape(goal)) != (c["out"] as Map<String, Any?>)["render"]) bad.add(c["name"] as String)
        }
        assertTrue("${bad.size} divergent render(s): " + bad.take(25), bad.isEmpty())
    }

    /** A string token of a million characters crosses the kernel without a stack overflow. */
    @Test fun hugeStringDoesNotOverflow() {
        val big = listOf<Any?>(listOf("s", "a".repeat(1 shl 20)))
        for (op in listOf("typecheck", "compile", "render")) assertEquals(op, "i", l(GoalKernel.call(op, big, ArrayList<Any?>(), null, null)[0])[0])
    }

    @Test fun malformedIsRefused() {
        assertTrue(GoalKernel.available())
        val bad = GoalKernel.tapeFromText("i7")
        assertEquals("i9", GoalKernel.tapeToText(GoalKernel.call("typecheck", bad, ArrayList<Any?>(), null, null)))
        try { GoalKernel.call("nope", bad, bad, null, null); fail("unknown op accepted") } catch (e: IllegalArgumentException) { /* expected */ }
        try {
            GoalKernel.call("typecheck", GoalKernel.tapeFromText("k9007199254740992"), bad, null, null)
            fail("unsafe integer accepted")
        } catch (e: RuntimeException) { /* expected */ }
    }
}
