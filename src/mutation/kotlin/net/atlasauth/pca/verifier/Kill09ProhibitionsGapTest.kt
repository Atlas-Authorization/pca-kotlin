package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.canon
import net.atlasauth.pca.verifier.K08K4.m
import net.atlasauth.pca.verifier.K08K4.num
import net.atlasauth.pca.verifier.K08K4.q
import net.atlasauth.pca.verifier.K08K4.state0
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Prohibition engine: the seams the reference oracle replay cannot see. The type and message of each thrown error, the private
 * comparison and evaluation helpers, the Java-facing overloads of the defaulted entry points, and every operand of the state
 * shape test on its own.
 */
@Suppress("UNCHECKED_CAST")
class Kill09ProhibitionsGapTest {
    private fun n(d: Double) = Prohibitions.jn(d)

    private fun entry(t: Double, amount: Double): Map<String, Any?> = Prohibitions.map("t", n(t), "amount", n(amount))

    private fun cmp(a: Map<String, Any?>, b: Map<String, Any?>): Int = KUtil.priv<Int>(Prohibitions, "cmpEntry", a, b)

    private fun constitution(invariants: String): Map<String, Any?> = m(q("{'version':1,'principal':'p','invariants':$invariants}"))

    private fun iae(message: String, f: () -> Any?) {
        val e = assertThrows(IllegalArgumentException::class.java) { f() }
        assertEquals(message, e.message)
    }

    // ---- state shape: each operand of the early test fires on its own, before the later field checks

    @Test fun eachStateOperandIsRefusedBeforeTheSequenceIsRead() {
        val good = Prohibitions.emptyState(n(100.0))
        assertEquals(null, Prohibitions.stateProblem(good))
        fun broken(k: String, v: Any?): Map<String, Any?> = LinkedHashMap(good).also { it["seq"] = n(-1.0); it[k] = v }
        // with only seq broken the later check names the field
        assertEquals("malformed monitor state: seq", Prohibitions.stateProblem(LinkedHashMap(good).also { it["seq"] = n(-1.0) }))
        // each of the three operands, alone, refuses with the plain reason (the seq check would otherwise answer first)
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("now", "x")))
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("now", n(Double.NaN))))
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("ledger", ArrayList<Any?>())))
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("ledger", null)))
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("latched", "x")))
        assertEquals("malformed monitor state", Prohibitions.stateProblem(broken("latched", null)))
        for (notAState in listOf<Any?>(null, "x", n(1.0), ArrayList<Any?>(), true)) {
            assertEquals("malformed monitor state", Prohibitions.stateProblem(notAState))
        }
    }

    @Test fun canonicalStateThrowsTheReasonAsAnIllegalArgument() {
        iae("malformed monitor state") { Prohibitions.canonicalState("x") }
        iae("malformed monitor state") { Prohibitions.canonicalState(null) }
        iae("malformed monitor state: seq") { Prohibitions.canonicalState(LinkedHashMap(state0()).also { it["seq"] = n(-1.0) }) }
        assertEquals("1700000000000", canon(Prohibitions.canonicalState(state0())["now"]))
    }

    // ---- evidence signing: the thrown type and message of every refusal

    private fun evidence(): LinkedHashMap<String, Any?> =
        Prohibitions.map("v", n(1.0), "constitution", "c", "action_digest", "a", "state_digest", "s", "evaluated", ArrayList<Any?>(), "ok", true, "violated", ArrayList<Any?>())

    @Test fun signSafetyEvidenceRefusalsAreIllegalArgumentsWithTheirOwnMessage() {
        val seed = ByteArray(32) { 1 }
        val pub = K08K4.PRIN
        for (bad in listOf<Any?>("x", null, ArrayList<Any?>(), evidence().also { it.remove("v") }, evidence().also { it["v"] = n(0.0) }, evidence().also { it["v"] = n(2.0) },
            evidence().also { it["v"] = Json.Num("1.5") }, evidence().also { it["v"] = "1" }, evidence().also { it["v"] = null })) {
            iae("signSafetyEvidence: unsupported evidence") { Prohibitions.signSafetyEvidence(bad, seed, pub) }
        }
        for (k in listOf("constitution", "action_digest", "state_digest")) {
            for (bad in listOf<Any?>(null, "", Prohibitions.UNHASHABLE, 5L, ArrayList<Any?>())) {
                iae("signSafetyEvidence: unbound evidence") { Prohibitions.signSafetyEvidence(evidence().also { it[k] = bad }, seed, pub) }
            }
            iae("signSafetyEvidence: unbound evidence") { Prohibitions.signSafetyEvidence(evidence().also { it.remove(k) }, seed, pub) }
        }
        iae("signSafetyEvidence: signer missing") { Prohibitions.signSafetyEvidence(evidence(), seed, null) }
        iae("signSafetyEvidence: signer missing") { Prohibitions.signSafetyEvidence(evidence(), seed, "") }
        val signed = Prohibitions.signSafetyEvidence(evidence(), seed, pub)
        assertEquals(pub, signed["signer"])
        assertEquals(Prohibitions.safetyBindingId(evidence(), pub), signed["id"])
        assertTrue((signed["sig"] as String).isNotEmpty())
    }

    @Test fun safetyBindingIdNamesAMissingBoundDigest() {
        for (k in listOf("constitution", "action_digest", "state_digest")) {
            iae("canonicalize: unsupported type undefined") { Prohibitions.safetyBindingId(evidence().also { it.remove(k) }, "signer") }
        }
        assertTrue(Prohibitions.safetyBindingId(evidence(), "signer").isNotEmpty())
    }

    // ---- the ledger ordering helper, called directly (a sort of two or three entries never reaches its gallop-side results)

    @Test fun cmpEntryOrdersByTimeThenAmount() {
        assertEquals(-1, cmp(entry(1.0, 9.0), entry(2.0, 0.0)))
        assertEquals(1, cmp(entry(2.0, 0.0), entry(1.0, 9.0)))
        assertEquals(-1, cmp(entry(5.0, 1.0), entry(5.0, 2.0)))
        assertEquals(1, cmp(entry(5.0, 2.0), entry(5.0, 1.0)))
        assertEquals(0, cmp(entry(5.0, 2.0), entry(5.0, 2.0)))
        assertEquals(0, cmp(entry(0.0, 0.0), entry(0.0, 0.0)))
        assertEquals(-1, cmp(entry(-3.0, 0.0), entry(-2.0, 0.0)))
        assertEquals(1, cmp(entry(1.0, 0.0), entry(-1.0, 0.0)))
    }

    // ---- an invariant that changed kind after validation is refused by the evaluator itself

    private fun collide(k: String): String = (k[0] + 1).toString() + (k[1] - 31).toString() + k.substring(2)

    @Test fun evalOneRefusesAnUnknownKindEvenWhenItsHashCodeCollidesWithAKnownOne() {
        val kinds = listOf("never", "never_unless", "cap", "rate", "never_after", "require_prior", "require_approval_over")
        for (k in kinds + listOf("bogus", "", "NEVER")) {
            val clash = if (k in kinds) collide(k) else k
            if (k in kinds) assertEquals(k.hashCode(), clash.hashCode())
            val inv = Prohibitions.map("id", "x", "kind", clash)
            val e = assertThrows(IllegalStateException::class.java) { KUtil.priv<Any?>(Prohibitions, "evalOne", inv, act("x"), state0()) }
            assertEquals("unknown invariant kind", e.message)
        }
    }

    // ---- the Java-facing overloads of the defaulted entry points

    @Test fun theOmittedArgumentOverloadsAgreeWithTheDefaultedCalls() {
        val c = constitution("[{'id':'n','kind':'never','when':{'verb':'delete'}}]")
        val a = act("read")
        val s = state0()
        val adv = Prohibitions::class.java.getMethod("advanceStateStrict", Any::class.java, Any::class.java, Any::class.java)
        val viaJava = adv.invoke(Prohibitions, a, c, s) as Map<String, Any?>
        assertEquals(true, viaJava["ok"])
        assertEquals(canon(Prohibitions.advanceStateStrict(a, c, s)), canon(viaJava))
        val four = Prohibitions::class.java.getMethod("checkAndAdvance", java.lang.Boolean.TYPE, Any::class.java, Any::class.java, Any::class.java)
        val five = Prohibitions::class.java.getMethod("checkAndAdvance", java.lang.Boolean.TYPE, Any::class.java, Any::class.java, Any::class.java, Any::class.java)
        for (permitted in listOf(true, false)) {
            val r4 = four.invoke(Prohibitions, permitted, a, c, s) as Map<String, Any?>
            assertEquals(permitted, r4["allow"])
            assertEquals(canon(Prohibitions.checkAndAdvance(permitted, a, c, s)), canon(r4))
            val r5 = five.invoke(Prohibitions, permitted, a, c, s, n(0.0)) as Map<String, Any?>
            assertEquals(permitted, r5["allow"])
            assertEquals(canon(Prohibitions.checkAndAdvance(permitted, a, c, s, n(0.0))), canon(r5))
            val stale = five.invoke(Prohibitions, permitted, a, c, s, n(7.0)) as Map<String, Any?>
            assertEquals(false, stale["allow"])
            assertEquals("stale state head (seq)", stale["reason"])
        }
    }

    // ---- advance: the clock defaults and each kind updates only its own part of the state

    @Test fun advanceReadsTheClockFromTheStateOnlyWhenItIsOmitted() {
        val c = constitution("[{'id':'n','kind':'never','when':{'verb':'delete'}}]")
        val a = act("read")
        val s = state0()
        assertEquals("1700000000000", canon(m(Prohibitions.advanceStateStrict(a, c, s)["state"])["now"]))
        assertEquals("1700000000005", canon(m(Prohibitions.advanceStateStrict(a, c, s, num(K08K4.NOW + 5.0))["state"])["now"]))
        assertEquals("clock regression", Prohibitions.advanceStateStrict(a, c, s, null)["reason"])
        assertEquals("clock regression", Prohibitions.advanceStateStrict(a, c, s, num(K08K4.NOW - 1.0))["reason"])
        for (notAState in listOf<Any?>("x", null, ArrayList<Any?>())) {
            val r = Prohibitions.advanceStateStrict(a, c, notAState)
            assertEquals(false, r["ok"])
            assertEquals("malformed monitor state", r["reason"])
        }
    }

    @Test fun advanceTouchesTheLedgerOnlyForCapAndRateAndTheLatchesOnlyForTheirKinds() {
        val c = constitution(
            "[{'id':'c1','kind':'cap','when':{'verb':'x'},'amount':'action.params.amt','max':100,'window_secs':60}," +
                "{'id':'r1','kind':'rate','when':{'verb':'x'},'max':5,'window_secs':60}," +
                "{'id':'na','kind':'never_after','after':{'verb':'x'},'forbid':{'verb':'y'}}," +
                "{'id':'rp','kind':'require_prior','when':{'verb':'y'},'prior':{'verb':'x'}}," +
                "{'id':'nv','kind':'never','when':{'verb':'z'}}," +
                "{'id':'nu','kind':'never_unless','when':{'verb':'z'},'unless':[{'field':'action.params.ok','op':'eq','value':1}]}]",
        )
        val r = Prohibitions.advanceStateStrict(act("x", "/r", "{'amt':7}"), c, state0())
        assertEquals(true, r["ok"])
        val next = m(r["state"])
        assertEquals(canon(q("{'c1':[{'t':1700000000000,'amount':7}],'r1':[{'t':1700000000000,'amount':1}]}")), canon(next["ledger"]))
        assertEquals(canon(q("{'na':1700000000000,'rp':1700000000000}")), canon(next["latched"]))
        assertEquals("1", canon(next["seq"]))
        // an action none of them matches changes neither part
        val idle = m(Prohibitions.advanceStateStrict(act("w"), c, state0())["state"])
        assertEquals("{}", canon(idle["ledger"]))
        assertEquals("{}", canon(idle["latched"]))
    }

    // ---- the monitor window: the lower bound is exclusive, `now` itself is inside

    private fun capState(ledger: String): Map<String, Any?> =
        m(q("{'now':100000,'seq':0,'parent':null,'ledger':$ledger,'latched':{}}"))

    @Test fun theCapWindowIsExclusiveAtItsLowerBound() {
        val c = constitution("[{'id':'c1','kind':'cap','when':{'verb':'x'},'amount':'action.params.amt','max':10,'window_secs':10}]")
        val a = act("x", "/r", "{'amt':1}")
        // lo = 100000 - 10 * 1000 = 90000: an entry exactly at lo is out, one millisecond later is in
        assertEquals(true, Prohibitions.checkProhibitions(a, c, capState("{'c1':[{'t':90000,'amount':9},{'t':90001,'amount':1}]}"))["ok"])
        assertEquals(false, Prohibitions.checkProhibitions(a, c, capState("{'c1':[{'t':90001,'amount':10}]}"))["ok"])
        assertEquals(false, Prohibitions.checkProhibitions(a, c, capState("{'c1':[{'t':100000,'amount':10}]}"))["ok"])
        assertEquals(true, Prohibitions.checkProhibitions(a, c, capState("{'c1':[{'t':89999,'amount':10}]}"))["ok"])
        assertEquals(true, Prohibitions.checkProhibitions(a, c, capState("{'other':[{'t':100000,'amount':10}]}"))["ok"])
    }

    // ---- the number helpers

    @Test fun negZeroAndIsIntegerOnTheirOwn() {
        assertTrue(Prohibitions.negZero(Json.Num("-0")))
        assertTrue(Prohibitions.negZero(-0.0))
        assertFalse(Prohibitions.negZero(Json.Num("0")))
        assertFalse(Prohibitions.negZero(0.0))
        assertFalse(Prohibitions.negZero(Json.Num("1")))
        assertFalse(Prohibitions.negZero(Json.Num("-1")))
        assertFalse(Prohibitions.negZero("x"))
        assertFalse(Prohibitions.negZero(null))
        assertTrue(Prohibitions.isInteger(Json.Num("2")))
        assertTrue(Prohibitions.isInteger(Json.Num("-0")))
        assertFalse(Prohibitions.isInteger(Json.Num("2.5")))
        assertFalse(Prohibitions.isInteger("2"))
        assertFalse(Prohibitions.isInteger(null))
    }

    // ---- affirmative matching refuses a trigger the veto polarity would also refuse

    @Test fun whenAffirmativeRequiresAWellFormedTrigger() {
        val ctx = act("delete")
        assertTrue(Prohibitions.whenAffirmative(m(q("{'verb':'delete'}")), ctx))
        assertTrue(Prohibitions.whenAffirmative(m(q("{'verb':['x','delete']}")), ctx))
        // the predicate would match (the list holds 'delete'), the trigger is malformed (an empty verb): not affirmative
        assertFalse(Prohibitions.whenAffirmative(m(q("{'verb':['delete','']}")), ctx))
        assertFalse(Prohibitions.whenAffirmative(m(q("{'verb':'delete','where':[{'field':'action.resource','op':'bogus','value':1}]}")), ctx))
        assertFalse(Prohibitions.whenAffirmative(m(q("{'verb':'other'}")), ctx))
        assertFalse(Prohibitions.whenAffirmative("x", ctx))
        assertFalse(Prohibitions.whenAffirmative(null, ctx))
    }
}
