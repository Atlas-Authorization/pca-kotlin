package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mutation kills for `ForbidWins`: trigger and condition validation, the fail-closed trigger match, the decision order, the certificate and its overloads. */
@Suppress("UNCHECKED_CAST")
class ForbidWinsKillTest {
    private fun o(vararg kv: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*kv)
    private fun leaf() = o("field" to "action.verb", "op" to "eq", "value" to "read")
    private fun ne() = o("field" to "action.verb", "op" to "ne", "value" to "read")
    private fun ctx(verb: String, resource: String) = o("action" to o("verb" to verb, "resource" to resource))
    private val read = ctx("read", "doc/1")
    private fun clause(id: String, kind: String, signer: String?, `when`: Any?): MutableMap<String, Any?> {
        val c = o("id" to id, "kind" to kind)
        if (signer != null) c["signer"] = signer
        c["when"] = `when`
        return c
    }
    private fun hit() = o("verb" to "read")
    private fun miss() = o("verb" to "write")
    private fun unknownWhen() = o("verb" to "read", "where" to listOf<Any?>(o("field" to "env.nothing", "op" to "eq", "value" to "x")))
    private fun lst(vararg xs: Any?): MutableList<Any?> = ArrayList(xs.toList())

    // ---- validateCondition

    @Test fun conditionOperatorsAreCheckedOneByOne() {
        assertEquals("condition not an object", ForbidWins.validateCondition("x", 0))
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("op" to "eq"), 0))
        assertEquals("unknown condition op undefined", ForbidWins.validateCondition(o("field" to "f"), 0))
        assertEquals("unknown condition op 5", ForbidWins.validateCondition(o("field" to "f", "op" to 5L), 0))
        assertEquals("unknown condition op zz", ForbidWins.validateCondition(o("field" to "f", "op" to "zz"), 0))
        assertEquals("unknown condition op EQ", ForbidWins.validateCondition(o("field" to "f", "op" to "EQ"), 0))
        for (op in listOf("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of")) {
            assertNull(op, ForbidWins.validateCondition(o("field" to "f", "op" to op), 0))
        }
        assertEquals("bad condition.ref", ForbidWins.validateCondition(o("field" to "f", "op" to "eq", "ref" to ""), 0))
        assertNull(ForbidWins.validateCondition(o("field" to "f", "op" to "eq", "ref" to "g"), 0))
        assertEquals("bad condition.collection", ForbidWins.validateCondition(o("field" to "f", "op" to "member_of", "collection" to ""), 0))
        assertNull(ForbidWins.validateCondition(o("field" to "f", "op" to "member_of", "collection" to "c"), 0))
        assertNull(ForbidWins.validateCondition(o("field" to "f", "op" to "member_of"), 0))
        // depth 32 is the last accepted level
        assertNull(ForbidWins.validateCondition(leaf(), 32))
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(leaf(), 33))
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of" to emptyList<Any?>()), 0))
        assertNull(ForbidWins.validateCondition(o("any_of" to listOf<Any?>(leaf())), 0))
    }

    // ---- validateWhen

    @Test fun triggerVerbsResourcesAndRegexPrefix() {
        assertEquals("L: not an object", ForbidWins.validateWhen(null, "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o(), "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb" to ""), "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb" to emptyList<Any?>()), "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb" to lst("a", "")), "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb" to lst("a", 5L)), "L"))
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb" to lst("")), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a"), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to lst("a", "b", "c")), "L"))
        assertEquals("L: bad resource", ForbidWins.validateWhen(o("verb" to "a", "resource" to 5L), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "re"), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:abc"), "L"))
        // the prefix is exactly lower-case `re:` and three characters long: the source after it is what is judged
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "RE:(a+)+"), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "re(a+)+"), "L"))
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:(a+)+"), "L"))
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:*"), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:" + "a".repeat(200)), "L"))
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:" + "a".repeat(201)), "L"))
        assertEquals("L: where not an array", ForbidWins.validateWhen(o("verb" to "a", "where" to "x"), "L"))
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "where" to listOf<Any?>(leaf())), "L"))
        assertEquals("L: condition.field missing", ForbidWins.validateWhen(o("verb" to "a", "where" to listOf<Any?>(leaf(), o("op" to "eq"))), "L"))
        // the default safe-source judge is SafeRegex's: an injected judge is honoured
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:abc"), "L") { false })
        assertNull(ForbidWins.validateWhen(o("verb" to "a", "resource" to "re:abc"), "L") { true })
    }

    // ---- whenMatches

    @Test fun whenMatchesIsTheVetoPolarity() {
        assertTrue(ForbidWins.whenMatches(hit(), read))
        assertFalse(ForbidWins.whenMatches(miss(), read))
        assertTrue(ForbidWins.whenMatches(o("verb" to lst("x", "read")), read))
        assertTrue(ForbidWins.whenMatches(o("verb" to "read", "resource" to "doc/*"), read))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "resource" to "other/*"), read))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:zzz"), read))
        // a where that is cleanly false clears the veto; true or undecidable keeps it
        assertTrue(ForbidWins.whenMatches(o("verb" to "read", "where" to listOf<Any?>(leaf())), read))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "where" to listOf<Any?>(ne())), read))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "where" to listOf<Any?>(leaf(), ne())), read))
        assertTrue(ForbidWins.whenMatches(unknownWhen(), read))
        assertFalse(ForbidWins.whenMatches(o("verb" to "write", "where" to listOf<Any?>(leaf())), read))
        assertTrue(ForbidWins.whenMatches(o("verb" to "read", "where" to emptyList<Any?>()), read))
    }

    @Test fun whenMatchesFailsClosedOnAMalformedTriggerOrContext() {
        assertTrue(ForbidWins.whenMatches(o("verb" to ""), read))
        assertTrue(ForbidWins.whenMatches("x", read))
        assertTrue(ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:(a+)+"), read))
        assertTrue(ForbidWins.whenMatches(hit(), null))
        assertTrue(ForbidWins.whenMatches(hit(), o()))
        assertTrue(ForbidWins.whenMatches(hit(), o("action" to "x")))
        assertTrue(ForbidWins.whenMatches(hit(), o("action" to o("verb" to 5L, "resource" to "doc/1"))))
        assertTrue(ForbidWins.whenMatches(hit(), o("action" to o("verb" to "read"))))
        assertTrue(ForbidWins.whenMatches(hit(), o("action" to o("verb" to "read", "resource" to 5L))))
        assertTrue(ForbidWins.whenMatches(hit(), o("action" to o("resource" to "doc/1"))))
        // a well-formed context never vetoes a plain mismatch (each operand of the context test is live)
        assertFalse(ForbidWins.whenMatches(miss(), read))
        assertFalse(ForbidWins.whenMatches(miss(), o("action" to o("verb" to "read", "resource" to "doc/1", "params" to o()))))
        // a context that throws when read is undecidable: the veto applies
        val throwing = object : HashMap<String, Any?>() {
            override fun get(key: String): Any? = throw IllegalStateException("boom")
        }
        assertTrue(ForbidWins.whenMatches(miss(), throwing))
    }

    @Test fun anOversizedRegexSubjectCountsAsMatched() {
        val w = o("verb" to "read", "resource" to "re:b")
        assertFalse(ForbidWins.whenMatches(w, ctx("read", "a".repeat(512))))
        assertTrue(ForbidWins.whenMatches(w, ctx("read", "a".repeat(513))))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "resource" to "b"), ctx("read", "a".repeat(513))))
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:b", "where" to listOf<Any?>(ne())), ctx("read", "a".repeat(513))))
        assertFalse(ForbidWins.whenMatches(o("verb" to "zzz"), ctx("read", "a".repeat(513))))
    }

    @Test fun aRefusedRegexIsMatchedButEarlierRefusalsDoNotTurnAPlainMismatchIntoAMatch() {
        fun exhaust() { for (i in 0 until 70) SafeRegex.charge("a", 1) }
        assertFalse(SafeRegex.withBudget { ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:b"), ctx("read", "a")) })
        assertTrue(SafeRegex.withBudget {
            exhaust()
            assertTrue(SafeRegex.refusals() > 0)
            ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:a"), ctx("read", "a"))
        })
        assertFalse(SafeRegex.withBudget {
            exhaust()
            ForbidWins.whenMatches(o("verb" to "read", "resource" to "re:a", "where" to listOf<Any?>(ne())), ctx("read", "a"))
        })
        // the refusals counted BEFORE this trigger are not this trigger's
        assertFalse(SafeRegex.withBudget {
            exhaust()
            ForbidWins.whenMatches(o("verb" to "write"), ctx("read", "a"))
        })
        assertFalse(SafeRegex.withBudget {
            exhaust()
            ForbidWins.whenMatches(o("verb" to "read", "resource" to "other"), ctx("read", "a"))
        })
    }

    // ---- clausesError

    @Test fun clauseKindAndShapeMessages() {
        assertEquals("clauses must be an array", ForbidWins.clausesError("x"))
        assertNull(ForbidWins.clausesError(emptyList<Any?>()))
        assertEquals("clauses[0] must be an object", ForbidWins.clausesError(listOf("x")))
        for (kind in listOf<Any?>("allow", "", 5L, null)) {
            assertEquals("kind $kind", "clauses[0].kind must be permit, forbid or escalate", ForbidWins.clausesError(listOf(o("id" to "a", "kind" to kind, "when" to hit()))))
        }
        assertEquals("clauses[0].kind must be permit, forbid or escalate", ForbidWins.clausesError(listOf(o("id" to "a", "when" to hit()))))
        for (k in listOf("permit", "forbid", "escalate")) assertNull(k, ForbidWins.clausesError(listOf(clause("a", k, null, hit()))))
        assertEquals("clauses[0].when must be a predicate object", ForbidWins.clausesError(listOf(o("id" to "a", "kind" to "permit"))))
        assertEquals("clauses[1].id 'a' is a duplicate", ForbidWins.clausesError(listOf(clause("a", "permit", null, hit()), clause("a", "forbid", null, hit()))))
        val bad = clause("a", "permit", null, hit())
        bad["signer"] = "s".repeat(257)
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ForbidWins.clausesError(listOf(bad)))
        bad["signer"] = "s".repeat(256)
        assertNull(ForbidWins.clausesError(listOf(bad)))
    }

    // ---- decide

    private fun decide(clauses: Any?, c: Map<String, Any?>?, prec: List<String>? = null, permitSigners: List<String>? = null) =
        ForbidWins.decide(clauses, c, prec, permitSigners)

    private fun assertMalformed(d: ForbidWins.Decision) {
        assertEquals("deny", d.decision)
        assertEquals("malformed", d.winnerKind)
        assertNull(d.winnerId)
        assertTrue(d.shadowed.isEmpty())
        assertTrue(d.values.isEmpty())
    }

    @Test fun decideRefusesMalformedContextsOperandByOperand() {
        val ok = lst(clause("p", "permit", null, hit()))
        assertMalformed(decide(ok, null))
        assertMalformed(decide(ok, o()))
        assertMalformed(decide(ok, o("action" to "x")))
        assertMalformed(decide(ok, o("action" to o("verb" to 5L, "resource" to "doc/1"))))
        assertMalformed(decide(ok, o("action" to o("resource" to "doc/1"))))
        assertMalformed(decide(ok, o("action" to o("verb" to "read", "resource" to 5L))))
        assertMalformed(decide(ok, o("action" to o("verb" to "read"))))
        assertMalformed(decide("x", read))
        assertEquals("allow", decide(ok, read).decision)
    }

    @Test fun anExceptionWhileDecidingIsMalformed() {
        val throwing = object : java.util.AbstractList<String>() {
            override val size: Int get() = 1
            override fun get(index: Int): String = "s1"
            override fun contains(element: String): Boolean = throw IllegalStateException("boom")
        }
        assertMalformed(decide(lst(clause("p", "permit", "s1", hit())), read, null, throwing))
    }

    @Test fun anUnsignedForbidIsRankedWithoutLookingItUpInAnullIntolerantPrecedence() {
        // a precedence list that rejects a null lookup: the unsigned clause must not be looked up at all
        val strict = object : AbstractList<String>() {
            override val size: Int get() = 1
            override fun get(index: Int): String = "s1"
            override fun indexOf(element: String): Int = if (element == "s1") 0 else -1
        }
        val d = decide(lst(clause("z", "forbid", null, hit()), clause("a", "forbid", "s1", hit())), read, strict)
        assertEquals("forbid", d.winnerKind)
        assertEquals("a", d.winnerId)
        assertEquals(listOf("z"), d.shadowed)
    }

    @Test fun valuesForEachKind() {
        val clauses = lst(
            clause("p1", "permit", null, hit()), clause("p2", "permit", null, miss()),
            clause("f1", "forbid", null, hit()), clause("f2", "forbid", null, miss()), clause("f3", "forbid", null, unknownWhen()),
            clause("e1", "escalate", null, hit()), clause("e2", "escalate", null, miss()), clause("e3", "escalate", null, unknownWhen()),
        )
        val d = decide(clauses, read)
        val want = listOf("true", "false", "true", "false", "unknown", "true", "false", "unknown")
        val ids = listOf("p1", "p2", "f1", "f2", "f3", "e1", "e2", "e3")
        val kinds = listOf("permit", "permit", "forbid", "forbid", "forbid", "escalate", "escalate", "escalate")
        assertEquals(8, d.values.size)
        for (i in 0 until 8) {
            assertEquals(ids[i], d.values[i]["id"])
            assertEquals(kinds[i], d.values[i]["kind"])
            assertEquals(ids[i], want[i], d.values[i]["value"])
            assertEquals(3, d.values[i].size)
        }
        assertEquals("deny", d.decision)
        assertEquals("f1", d.winnerId)
        assertEquals(listOf("f3", "p1", "e1", "e3"), d.shadowed)
    }

    @Test fun outcomesAndTheirShadowedLists() {
        var d = decide(lst(clause("p1", "permit", null, hit()), clause("p2", "permit", null, hit()), clause("e", "escalate", null, miss())), read)
        assertEquals("allow", d.decision); assertEquals("permit", d.winnerKind); assertEquals("p1", d.winnerId)
        assertEquals(listOf("p2"), d.shadowed)
        d = decide(lst(clause("p1", "permit", null, hit()), clause("e1", "escalate", null, hit()), clause("e2", "escalate", null, hit())), read)
        assertEquals("escalate", d.decision); assertEquals("e1", d.winnerId)
        assertEquals(listOf("p1", "e2"), d.shadowed)
        d = decide(lst(clause("p1", "permit", null, hit()), clause("e1", "escalate", null, hit()), clause("f1", "forbid", null, hit())), read)
        assertEquals("deny", d.decision); assertEquals("forbid", d.winnerKind); assertEquals("f1", d.winnerId)
        assertEquals(listOf("p1", "e1"), d.shadowed)
        d = decide(lst(clause("p1", "permit", null, miss()), clause("e1", "escalate", null, hit())), read)
        assertEquals("deny", d.decision); assertEquals("none", d.winnerKind); assertNull(d.winnerId)
        assertEquals(listOf("e1"), d.shadowed)
        d = decide(lst(), read)
        assertEquals("none", d.winnerKind)
        assertTrue(d.shadowed.isEmpty())
        d = decide(lst(clause("p1", "permit", null, hit()), clause("f1", "forbid", null, unknownWhen())), read)
        assertEquals("deny", d.decision); assertEquals("f1", d.winnerId)
    }

    @Test fun forbidWinnerOrderIsPrecedenceThenId() {
        val prec = listOf("s1", "s2")
        var d = decide(lst(clause("b", "forbid", null, hit()), clause("a", "forbid", null, hit())), read, prec)
        assertEquals("a", d.winnerId); assertEquals(listOf("b"), d.shadowed)
        d = decide(lst(clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit())), read, prec)
        assertEquals("b", d.winnerId); assertEquals(listOf("a"), d.shadowed)
        d = decide(lst(clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit())), read)
        assertEquals("a", d.winnerId)
        d = decide(lst(clause("a", "forbid", null, hit()), clause("z", "forbid", "s1", hit())), read, listOf("s1"))
        assertEquals("z", d.winnerId)
        d = decide(lst(clause("a", "forbid", "other", hit()), clause("z", "forbid", "s1", hit())), read, listOf("s1"))
        assertEquals("z", d.winnerId)
        d = decide(lst(clause("b", "forbid", null, hit()), clause("a", "forbid", "other", hit())), read, listOf("s1"))
        assertEquals("a", d.winnerId)
    }

    @Test fun permitSignersDropOtherSignersPermits() {
        val only = listOf("s1")
        var d = decide(lst(clause("p", "permit", "s1", hit())), read, null, only)
        assertEquals("allow", d.decision)
        assertEquals("true", d.values[0]["value"])
        d = decide(lst(clause("p", "permit", "s2", hit())), read, null, only)
        assertEquals("none", d.winnerKind)
        assertEquals("false", d.values[0]["value"])
        d = decide(lst(clause("p", "permit", null, hit())), read, null, only)
        assertEquals("deny", d.decision)
        d = decide(lst(clause("p", "permit", "s1", hit()), clause("f", "forbid", "s2", hit())), read, null, only)
        assertEquals("f", d.winnerId)
        assertEquals("true", d.values[1]["value"])
        d = decide(lst(clause("p", "permit", "s1", hit()), clause("e", "escalate", null, hit())), read, null, only)
        assertEquals("escalate", d.decision)
        assertEquals("allow", decide(lst(clause("p", "permit", "s2", hit())), read, null, null).decision)
        assertEquals("deny", decide(lst(clause("p", "permit", "s1", hit())), read, null, emptyList()).decision)
    }

    // ---- certify / consistent / check, and the generated overloads

    private fun goodCert() = ForbidWins.certify(lst(clause("p", "permit", null, hit()), clause("e", "escalate", null, hit())), read, null, null) as MutableMap<String, Any?>

    @Test fun certifyBuildsTheCanonicalCertificate() {
        val clauses = lst(clause("p", "permit", "s1", hit()), clause("e", "escalate", null, hit()))
        val cert = ForbidWins.certify(clauses, read, null, null)
        assertEquals(listOf("v", "kind", "policy", "action", "decision", "winner", "shadowed", "clauses"), cert.keys.toList())
        assertEquals("forbid-wins", cert["kind"])
        assertEquals(Pca.hashCanonical(clauses), cert["policy"])
        assertEquals(Pca.hashCanonical(read), cert["action"])
        assertEquals("escalate", cert["decision"])
        assertEquals("e", (cert["winner"] as Map<String, Any?>)["id"])
        assertEquals(listOf("p"), cert["shadowed"])
        val rows = cert["clauses"] as List<Map<String, Any?>>
        assertEquals(listOf("id", "kind", "signer", "value"), rows[0].keys.toList())
        assertEquals("s1", rows[0]["signer"])
        assertEquals(listOf("id", "kind", "value"), rows[1].keys.toList())
        // a malformed policy is a deny certificate with no rows, whatever else the list holds
        val bad = ForbidWins.certify(lst("x", o("id" to 5L), o("id" to "ok", "kind" to "permit", "when" to hit())), read, null, null)
        assertEquals("deny", bad["decision"])
        assertEquals(emptyList<Any?>(), bad["clauses"])
    }

    @Test fun consistentAcceptsWhatCertifyBuildsAndRefusesBrokenTables() {
        assertTrue(ForbidWins.consistent(goodCert()))
        assertTrue(ForbidWins.consistent(ForbidWins.certify("x", read)))
        assertFalse(ForbidWins.consistent(null))
        assertFalse(ForbidWins.consistent("x"))
        var c = goodCert(); c["decision"] = "allow"
        assertFalse(ForbidWins.consistent(c))
        c = goodCert(); (c["winner"] as MutableMap<String, Any?>)["id"] = "p"
        assertFalse(ForbidWins.consistent(c))
        c = goodCert(); (c["shadowed"] as MutableList<Any?>).clear()
        assertFalse(ForbidWins.consistent(c))
        c = goodCert(); c["kind"] = "other"
        assertFalse(ForbidWins.consistent(c))
    }

    @Test fun checkRecomputesTheCertificate() {
        val clauses = lst(clause("p", "permit", null, hit()), clause("e", "escalate", null, hit()))
        assertNull(ForbidWins.check(goodCert(), clauses, read))
        assertEquals("malformed clauses", ForbidWins.check(goodCert(), "x", read))
        val tampered = goodCert(); tampered["decision"] = "allow"
        assertEquals("certificate table does not entail its decision", ForbidWins.check(tampered, clauses, read))
        val other = ctx("read", "doc/2")
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(goodCert(), clauses, other))
    }

    /** The `@JvmOverloads` entry points a Java caller sees: each must behave exactly as the full signature with the omitted arguments null. */
    @Test fun theGeneratedOverloadsDelegateWithTheirDefaults() {
        val clauses = lst(clause("p", "permit", null, hit()), clause("e", "escalate", null, hit()))
        val cls = ForbidWins::class.java
        val obj = Any::class.java
        val map = Map::class.java
        val list = List::class.java

        val cert2 = cls.getMethod("certify", obj, map).invoke(ForbidWins, clauses, read) as Map<*, *>
        assertEquals(Json.canonicalize(goodCert()), Json.canonicalize(cert2))
        val cert3 = cls.getMethod("certify", obj, map, list).invoke(ForbidWins, clauses, read, null) as Map<*, *>
        assertEquals(Json.canonicalize(goodCert()), Json.canonicalize(cert3))

        val d2 = cls.getMethod("decide", obj, map).invoke(ForbidWins, clauses, read) as ForbidWins.Decision
        assertEquals("escalate", d2.decision)
        assertEquals("e", d2.winnerId)
        val d3 = cls.getMethod("decide", obj, map, list).invoke(ForbidWins, clauses, read, null) as ForbidWins.Decision
        assertEquals("escalate", d3.decision)

        assertEquals(true, cls.getMethod("consistent", obj).invoke(ForbidWins, goodCert()))
        val broken = goodCert(); broken["decision"] = "allow"
        assertEquals(false, cls.getMethod("consistent", obj).invoke(ForbidWins, broken))

        assertNull(cls.getMethod("check", obj, obj, map).invoke(ForbidWins, goodCert(), clauses, read))
        assertNull(cls.getMethod("check", obj, obj, map, list).invoke(ForbidWins, goodCert(), clauses, read, null))
        assertNull(cls.getMethod("check", obj, obj, map, list, list).invoke(ForbidWins, goodCert(), clauses, read, null, null))
        assertEquals("malformed clauses", cls.getMethod("check", obj, obj, map).invoke(ForbidWins, goodCert(), "x", read))
        assertEquals("malformed clauses", cls.getMethod("check", obj, obj, map, list).invoke(ForbidWins, goodCert(), "x", read, null))
    }

    // ---- a non-string value is never compared with the lists of known names

    /** Not a String, but `equals` a given text and hashes like it: a membership test that skips the String guard would take it for that text. */
    private class Alias(private val text: String) {
        override fun equals(other: Any?): Boolean = other == text || (other is Alias && other.text == text)
        override fun hashCode(): Int = text.hashCode()
        override fun toString(): String = "alias"
    }

    @Test fun aNonStringKindOrOperatorEqualToAKnownNameIsStillRefused() {
        for (k in listOf("permit", "forbid", "escalate")) {
            assertEquals(k, "clauses[0].kind must be permit, forbid or escalate", ForbidWins.clausesError(listOf(o("id" to "a", "kind" to Alias(k), "when" to hit()))))
        }
        for (op in listOf("eq", "member_of", "like")) {
            assertEquals(op, "unknown condition op alias", ForbidWins.validateCondition(o("field" to "f", "op" to Alias(op)), 0))
        }
    }

    @Test fun anUnsignedClauseIsRankedWithoutAskingTheListForNull() {
        // an immutable list refuses a null lookup with a NullPointerException: the unsigned clause must not be looked up at all
        val immutable = java.util.List.of("s1", "s2")
        val d = decide(lst(clause("z", "forbid", null, hit()), clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit())), read, immutable)
        assertEquals("forbid", d.winnerKind)
        assertEquals("b", d.winnerId)
        assertEquals(listOf("a", "z"), d.shadowed)
    }

    @Test fun theWhereConditionsAreReadOnlyAsFarAsTheListSays() {
        // a list whose iterator would keep yielding past its size: only the declared element is evaluated
        val overrunning = object : java.util.AbstractList<Any?>() {
            override val size: Int get() = 1
            override fun get(index: Int): Any? = if (index == 0) leaf() else ne()
        }
        assertTrue(ForbidWins.whenMatches(o("verb" to "read", "where" to overrunning), read))
        // the same elements, as many as declared: the second one is false and clears the veto
        val two = object : java.util.AbstractList<Any?>() {
            override val size: Int get() = 2
            override fun get(index: Int): Any? = if (index == 0) leaf() else ne()
        }
        assertFalse(ForbidWins.whenMatches(o("verb" to "read", "where" to two), read))
    }
}
