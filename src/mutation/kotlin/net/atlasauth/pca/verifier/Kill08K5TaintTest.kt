package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Kotlin 0.5 mutation kills for [Taint] (group k5), from packages/pca/src/taint.ts and mutation-kill-taint.test.ts: the label each ref is
 * classified to (the registered label, first party through the resource graph, `agent` with its id up to 128 chars inclusive), the join
 * of labels (the higher rank wins in either order, equal ranks keep the id only when both agree), the rank of a malformed label, the
 * exact [Taint.Computed] members (label, valid, reason) of every fail-closed outcome, the gate's rank table at its exact boundaries, and
 * the propagation of an Error that is not contained. Earlier tests read only `taint` and the reason.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K5TaintTest {
    private fun reg(vararg kv: Pair<String, Map<String, Any?>?>): Taint.Registry {
        val m = mapOf(*kv)
        return Taint.Registry { ref -> m[ref] }
    }

    private fun prov(refs: Any?, include: Boolean = true): Map<String, Any?> {
        val p = linkedMapOf<String, Any?>("causal_hash" to "", "taint_level" to 0L)
        if (include) p["trusted_refs"] = refs
        return p
    }

    private fun k(kind: String) = mapOf<String, Any?>("kind" to kind)
    private fun k(kind: String, id: String) = mapOf<String, Any?>("kind" to kind, "id" to id)

    private val registry = reg(
        "t" to k("trusted"), "f" to k("first_party"), "tool1" to k("tool", "tool1"), "tool2" to k("tool", "tool2"), "toolx" to k("tool"),
        "w" to k("web"), "a1" to k("agent", "a1"), "five" to mapOf<String, Any?>("kind" to 5L), "bogus" to k("bogus"), "nokind" to emptyMap<String, Any?>(),
    )

    private fun computed(refs: List<String>, g: Taint.ResourceGraph? = null) = Taint.computeTaint(prov(refs), registry, g)

    private fun assertComputed(refs: List<String>, taint: Double, label: Map<String, Any?>, g: Taint.ResourceGraph? = null) {
        val r = computed(refs, g)
        assertTrue(refs.toString(), r.valid)
        assertNull(refs.toString(), r.reason)
        assertEquals(refs.toString(), label, r.label)
        assertEquals(refs.toString(), taint, r.taint, 0.0)
    }

    @Test fun eachRefIsClassifiedToItsLabelAndTaint() {
        assertComputed(listOf("t"), 0.0, k("trusted"))
        assertComputed(listOf("f"), 0.25, k("first_party"))
        assertComputed(listOf("tool1"), 0.5, k("tool", "tool1"))
        assertComputed(listOf("w"), 0.75, k("web"))
        assertComputed(listOf("a1"), 1.0, k("agent", "a1"))
        // not vouched by the registry: the agent label, with the ref as id
        assertComputed(listOf("unknown"), 1.0, k("agent", "unknown"))
        // a registry answer whose kind is not a level (or no kind) vouches nothing
        assertComputed(listOf("five"), 1.0, k("agent", "five"))
        assertComputed(listOf("bogus"), 1.0, k("agent", "bogus"))
        assertComputed(listOf("nokind"), 1.0, k("agent", "nokind"))
    }

    @Test fun anUnverifiableRefKeepsItsIdUpTo128CharactersInclusive() {
        val r127 = "r".repeat(127)
        val r128 = "r".repeat(128)
        val r129 = "r".repeat(129)
        assertComputed(listOf("r"), 1.0, k("agent", "r"))
        assertComputed(listOf(r127), 1.0, k("agent", r127))
        assertComputed(listOf(r128), 1.0, k("agent", r128))
        assertComputed(listOf(r129), 1.0, k("agent"))
    }

    @Test fun theResourceGraphVouchesFirstPartyOnlyForAKnownNode() {
        val graph = Taint.ResourceGraph { ref -> if (ref == "node") true else null }
        assertComputed(listOf("node"), 0.25, k("first_party"), graph)
        assertComputed(listOf("other"), 1.0, k("agent", "other"), graph)
        // the registry answers first, a throwing graph is the worst case for that ref, an absent graph vouches nothing
        assertComputed(listOf("w"), 0.75, k("web"), graph)
        assertComputed(listOf("node"), 1.0, k("agent", "node"), Taint.ResourceGraph { throw IllegalStateException("x") })
        assertComputed(listOf("node"), 1.0, k("agent", "node"), null)
    }

    @Test fun theJoinKeepsTheHigherRankInEitherOrder() {
        assertComputed(listOf("t", "f"), 0.25, k("first_party"))
        assertComputed(listOf("f", "t"), 0.25, k("first_party"))
        assertComputed(listOf("w", "tool1"), 0.75, k("web"))
        assertComputed(listOf("tool1", "w"), 0.75, k("web"))
        assertComputed(listOf("tool1", "t"), 0.5, k("tool", "tool1"))
        assertComputed(listOf("t", "tool1"), 0.5, k("tool", "tool1"))
        assertComputed(listOf("t", "w", "f", "a1", "tool1"), 1.0, k("agent", "a1"))
        assertComputed(listOf("a1", "t"), 1.0, k("agent", "a1"))
        assertComputed(listOf("t", "a1"), 1.0, k("agent", "a1"))
    }

    @Test fun equalRanksKeepTheIdOnlyWhenBothAgree() {
        assertComputed(listOf("tool1", "tool1"), 0.5, k("tool", "tool1"))
        assertComputed(listOf("tool1", "tool2"), 0.5, k("tool"))
        assertComputed(listOf("tool2", "tool1"), 0.5, k("tool"))
        assertComputed(listOf("tool1", "toolx"), 0.5, k("tool"))
        assertComputed(listOf("toolx", "tool1"), 0.5, k("tool"))
        assertComputed(listOf("toolx", "toolx"), 0.5, k("tool"))
        assertComputed(listOf("f", "f"), 0.25, k("first_party"))
        assertComputed(listOf("u1", "u1"), 1.0, k("agent", "u1"))
        assertComputed(listOf("u1", "u2"), 1.0, k("agent"))
        assertComputed(listOf("u1", "u2", "u1"), 1.0, k("agent"))
        assertComputed(listOf("t", "t"), 0.0, k("trusted"))
    }

    @Test fun theEmptyAndTheMissingLineageAreTheWorstCaseButValid() {
        for (p in listOf(prov(emptyList<String>()), prov(null, include = false))) {
            val r = Taint.computeTaint(p, registry)
            assertTrue(r.valid)
            assertNull(r.reason)
            assertEquals(k("agent"), r.label)
            assertEquals(1.0, r.taint, 0.0)
        }
    }

    private fun invalid(r: Taint.Computed, reason: String) {
        assertFalse(reason, r.valid)
        assertEquals(reason, r.reason)
        assertEquals(k("agent"), r.label)
        assertEquals(1.0, r.taint, 0.0)
    }

    @Test fun everyFailClosedOutcomeIsAnInvalidWorstCaseComputation() {
        invalid(Taint.computeTaint(prov(listOf("t")), null), "taint: no trusted-input registry")
        // a registry is checked before the lineage: a bad lineage with no registry is still "no registry"
        invalid(Taint.computeTaint(prov(listOf(5L)), null), "taint: no trusted-input registry")
        invalid(Taint.computeTaint(prov("t"), null), "taint: no trusted-input registry")
        invalid(Taint.computeTaint(null, null), "taint: no trusted-input registry")
        for (bad in listOf<Any?>(null, "x", 5L, emptyList<Any?>())) invalid(Taint.computeTaint(bad, registry), "taint: provenance is absent or malformed")
        invalid(Taint.computeTaint(prov("t"), registry), "taint: trusted_refs must be an array")
        invalid(Taint.computeTaint(prov(null), registry), "taint: trusted_refs must be an array")
        invalid(Taint.computeTaint(prov(mapOf("a" to "b")), registry), "taint: trusted_refs must be an array")
        for (refs in listOf<List<Any?>>(listOf("t", ""), listOf("t", null), listOf("t", 5L), listOf(""), listOf(5L), listOf(listOf("t")), listOf(true)))
            invalid(Taint.computeTaint(prov(refs), registry), "taint: trusted_refs must be non-empty strings")
        invalid(Taint.computeTaint(prov(listOf("t")), Taint.Registry { throw IllegalStateException("boom") }), "taint: evaluation error (fail closed): boom")
        invalid(Taint.computeTaint(prov(listOf("t")), Taint.Registry { throw LinkageError("link") }), "taint: evaluation error (fail closed): link")
    }

    private class Boom : Error("boom")

    @Test fun anErrorThatIsNotContainedPropagatesFromComputeAndGate() {
        val boom = Taint.Registry { throw Boom() }
        try {
            Taint.computeTaint(prov(listOf("t")), boom)
            fail("computeTaint must not swallow an Error")
        } catch (e: Boom) {
            assertEquals("boom", e.message)
        }
        try {
            Taint.gate(prov(listOf("t")), Taint.Gate(boom, 1.0))
            fail("gate must not swallow an Error")
        } catch (e: Boom) {
            assertEquals("boom", e.message)
        }
    }

    // ---- the gate ----

    private fun gate(refs: Any?, max: Double?, reg: Taint.Registry? = registry, graph: Taint.ResourceGraph? = null) = Taint.gate(prov(refs), Taint.Gate(reg, max, graph))

    @Test fun theGateRankTableAtItsExactBoundaries() {
        // (ref, taint, smallest max that admits it)
        val rows = listOf(Triple("t", 0.0, 0.0), Triple("f", 0.25, 0.25), Triple("tool1", 0.5, 0.5), Triple("w", 0.75, 0.75), Triple("u", 1.0, 1.0))
        for ((ref, taint, admit) in rows) {
            assertNull("$ref admitted at $admit", gate(listOf(ref), admit))
            assertNull("$ref admitted above $admit", gate(listOf(ref), admit + 0.001))
            assertNull("$ref admitted at 1", gate(listOf(ref), 1.0))
            assertNull("$ref admitted at 7", gate(listOf(ref), 7.0))
            if (admit > 0.0) {
                val below = admit - 0.001
                assertEquals("$ref refused below $admit", "information-flow taint ${AttestUtil.jsNumString(taint)} exceeds policy max ${AttestUtil.jsNumString(below)}", gate(listOf(ref), below))
            }
        }
        assertEquals("information-flow taint 0.25 exceeds policy max 0.2", gate(listOf("f"), 0.2))
        assertEquals("information-flow taint 0.5 exceeds policy max 0.25", gate(listOf("tool1"), 0.25))
        assertEquals("information-flow taint 0.75 exceeds policy max 0.5", gate(listOf("w"), 0.5))
        assertEquals("information-flow taint 1 exceeds policy max 0.75", gate(listOf("u"), 0.75))
        assertEquals("information-flow taint 1 exceeds policy max 0", gate(listOf("u"), 0.0))
        assertEquals("information-flow taint 0.25 exceeds policy max 0", gate(listOf("f"), 0.0))
        // the worst ref of the lineage decides
        assertEquals("information-flow taint 0.75 exceeds policy max 0.5", gate(listOf("t", "w", "f"), 0.5))
        assertNull(gate(listOf("t", "f"), 0.25))
    }

    @Test fun theGateRefusesAnInvalidLineageBeforeAMisconfiguredBound() {
        assertEquals("taint: no trusted-input registry", gate(listOf("t"), -1.0, null))
        assertEquals("taint: trusted_refs must be an array", gate("t", 1.0))
        assertEquals("taint: trusted_refs must be non-empty strings", gate(listOf(""), 1.0))
        val mis = "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"
        for (bad in listOf(-0.5, -1e-9, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, null)) assertEquals("$bad", mis, gate(listOf("t"), bad))
        // negative zero is not negative
        assertNull(gate(listOf("t"), -0.0))
    }

    @Test fun theGateUsesItsResourceGraph() {
        val graph = Taint.ResourceGraph { ref -> if (ref == "node") true else null }
        assertNull(gate(listOf("node"), 0.25, registry, graph))
        assertEquals("information-flow taint 1 exceeds policy max 0.25", gate(listOf("node"), 0.25, registry, null))
        val g = Taint.Gate(registry, 0.25, graph)
        assertSame(graph, g.resourceGraph)
        assertSame(registry, g.registry)
        assertEquals(0.25, g.maxTaint!!, 0.0)
        assertNull(Taint.Gate(registry, 0.25).resourceGraph)
    }

    // ---- the private rank helpers, called directly with the shapes no classifier produces ----

    @Test fun theRankOfAnyLabelIsTheWorstWhenItsKindIsNotALevel() {
        fun rank(label: Any?): Int = KUtil.priv(Taint, "labelRank", label)
        fun level(kind: Any?): Boolean = KUtil.priv(Taint, "level", kind)
        for ((i, kind) in Taint.LEVELS.withIndex()) {
            assertEquals(kind, i, rank(mapOf("kind" to kind)))
            assertTrue(kind, level(kind))
        }
        for (bad in listOf<Any?>("bogus", "", 5L, null, true, listOf("web"), mapOf("kind" to "web"))) {
            assertEquals("$bad", 4, rank(mapOf("kind" to bad)))
            assertFalse("$bad", level(bad))
        }
        for (notALabel in listOf<Any?>(null, "web", 3L, emptyMap<String, Any?>(), listOf("web"))) assertEquals("$notALabel", 4, rank(notALabel))
    }

    @Test fun theInMemoryRegistryRecordsOnlyLevelsAndHandsOutCopies() {
        val r = Taint.InMemoryRegistry()
        assertSame(r, r.record("d", k("web")))
        r.record("", k("web"))
        r.record("x", mapOf("kind" to 5L))
        r.record("y", k("bogus"))
        r.record("z", emptyMap())
        assertEquals(1, r.size)
        val got = r.lookup("d") as MutableMap<String, Any?>
        assertEquals(k("web"), got)
        got["kind"] = "trusted"
        assertEquals(k("web"), r.lookup("d"))
        assertNull(r.lookup("nope"))
        r.recordTrusted("a"); r.recordFirstParty("b"); r.recordTool("c", "cid"); r.recordWeb("e")
        assertEquals(k("trusted"), r.lookup("a"))
        assertEquals(k("first_party"), r.lookup("b"))
        assertEquals(k("tool", "cid"), r.lookup("c"))
        assertEquals(k("web"), r.lookup("e"))
        assertEquals(5, r.size)
    }

    /** A vouched label whose `kind` read fails when (and only when) it is read by `gate` itself, after computeTaint answered. */
    private class LateFailingLabel(val failure: () -> Throwable) : LinkedHashMap<String, Any?>() {
        init { put("kind", "web") }

        override fun get(key: String): Any? {
            val st = Thread.currentThread().stackTrace
            val i = st.indexOfFirst { it.methodName == "labelRank" }
            if (i >= 0 && i + 1 < st.size && st[i + 1].methodName == "gate") throw failure()
            return super.get(key)
        }
    }

    @Test fun aContainedFailureInsideTheGateItselfIsAFailClosedRefusalAndAnErrorPropagates() {
        fun gateWith(failure: () -> Throwable): String? =
            Taint.gate(prov(listOf("x")), Taint.Gate(Taint.Registry { LateFailingLabel(failure) }, 1.0))
        assertEquals("taint gate error (fail closed): late", gateWith { IllegalStateException("late") })
        assertEquals("taint gate error (fail closed): link", gateWith { LinkageError("link") })
        try {
            gateWith { Boom() }
            fail("gate must not swallow an Error")
        } catch (e: Boom) {
            assertEquals("boom", e.message)
        }
        // computeTaint itself reads the same label without failing: the lineage is valid and the label is the registered one
        val r = Taint.computeTaint(prov(listOf("x")), Taint.Registry { LateFailingLabel { IllegalStateException("late") } })
        assertTrue(r.valid)
        assertEquals(0.75, r.taint, 0.0)
    }
}
