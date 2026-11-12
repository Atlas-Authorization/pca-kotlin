package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.PRIN
import net.atlasauth.pca.verifier.K08K4.arr
import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.contract
import net.atlasauth.pca.verifier.K08K4.key
import net.atlasauth.pca.verifier.K08K4.key2
import net.atlasauth.pca.verifier.K08K4.m
import net.atlasauth.pca.verifier.K08K4.never
import net.atlasauth.pca.verifier.K08K4.q
import net.atlasauth.pca.verifier.K08K4.w
import net.atlasauth.pca.verifier.K08K4.withKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for ContractEnforcer (k4): a port of packages/pca/src/contracts-enforcer.test.ts plus the fail-closed paths
 * (store faults, a non-finite clock, every corrupt-document shape, reset). Reasons are the reference's.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K4EnforcerTest {
    private val clauses = arr(never("no-delete", "delete"), "{'id':'review-first','kind':'precedes','p':${w("review")},'q':${w("deploy")}}")
    private val sc: Map<String, Any?> = Contracts.signContract(contract(clauses), key.seed)
    private val id: String = sc["id"] as String
    private val docKey = "contract/$id"
    private val corrupt = "<state>: stored state is corrupt or belongs to another contract"
    private val noDelete = "no-delete: never-invariant violated (forbidden action)"
    private val reviewFirst = "review-first: precedence violated (prerequisite p not yet admitted before q)"

    /** A store that can be made to fail, or to ignore `update` altogether. */
    private class StoreKv : AtomicKv {
        val inner = MemoryAtomicKv()
        var noop = false
        var failGet: (() -> Unit)? = null
        var failUpdate: (() -> Unit)? = null
        override fun get(key: String): Any? {
            failGet?.invoke()
            return inner.get(key)
        }
        override fun set(key: String, value: Any?) {
            inner.set(key, value)
        }
        override fun update(key: String, fn: (Any?) -> Any?): Any? {
            if (noop) return null
            failUpdate?.invoke()
            return inner.update(key, fn)
        }
    }

    private fun enf(kv: AtomicKv, latch: Boolean = true, clock: () -> Double = { K08K4.NOW }, k: String? = null): ContractEnforcer =
        ContractEnforcer.open(kv, sc, PRIN, k, clock, latch)

    private fun res(r: ContractEnforcer.Result, allow: Boolean, reason: String, violated: List<String>, reasons: List<String>, seq: Long) {
        assertEquals(allow, r.allow)
        assertEquals(reason, r.reason)
        assertEquals(violated, r.violated)
        assertEquals(reasons, r.reasons)
        assertEquals(seq, r.seq)
    }

    private fun iae(f: () -> Any?): String? = assertThrows(IllegalArgumentException::class.java) { f() }.message

    // ---- open

    @Test fun openRefusals() {
        assertEquals("ContractEnforcer: a durable key-value store is required", iae { ContractEnforcer.open(null, sc, PRIN) })
        assertEquals("ContractEnforcer: a durable key-value store is required", iae { ContractEnforcer.open(null, sc, null) })
        assertEquals("ContractEnforcer: a pinned principal is required", iae { ContractEnforcer.open(MemoryAtomicKv(), sc, null) })
        assertEquals("ContractEnforcer: a pinned principal is required", iae { ContractEnforcer.open(MemoryAtomicKv(), sc, "") })
        assertEquals("ContractEnforcer: contract refused: principal mismatch", iae { ContractEnforcer.open(MemoryAtomicKv(), sc, key2.id()) })
        assertEquals("ContractEnforcer: contract refused: id does not match content", iae { ContractEnforcer.open(MemoryAtomicKv(), withKey(sc, "clauses", ArrayList<Any?>()), PRIN) })
        assertEquals("ContractEnforcer: contract refused: contract not an object", iae { ContractEnforcer.open(MemoryAtomicKv(), null, PRIN) })
        assertNotNull(ContractEnforcer.open(MemoryAtomicKv(), sc, PRIN))
    }

    @Test fun theDefaultKeyIsTheContractIdAndACustomKeyIsUsed() {
        val kv = MemoryAtomicKv()
        val en = ContractEnforcer.open(kv, sc, PRIN, null, { K08K4.NOW }, true)
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        assertNotNull(kv.get(docKey))
        val kv2 = MemoryAtomicKv()
        res(enf(kv2, k = "mykey").check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        assertNotNull(kv2.get("mykey"))
        assertNull(kv2.get(docKey))
    }

    @Test fun theDefaultClockIsTheWallClockAndLatchingIsTheDefault() {
        val kv = MemoryAtomicKv()
        val en = ContractEnforcer.open(kv, sc, PRIN)
        val before = System.currentTimeMillis().toDouble()
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        val after = System.currentTimeMillis().toDouble()
        val now = Prohibitions.dv(m(en.state()!!["state"])["now"])
        assertTrue("now $now not within [$before, $after]", now >= before && now <= after)
        assertEquals("violated", en.check(act("delete"), true).reason)
        assertEquals("latched", en.check(act("review"), true).reason)
    }

    // ---- check

    @Test fun admitsInOrderAndAdvancesTheSequence() {
        val en = enf(MemoryAtomicKv())
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        res(en.check(act("deploy"), true), true, "ok", emptyList(), emptyList(), 2)
    }

    @Test fun permissionDeniedIsRefusedWithoutLatchOrAdvance() {
        val en = enf(MemoryAtomicKv())
        res(en.check(act("review"), false), false, "permission", emptyList(), listOf("<permission>: not permitted"), 0)
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        res(en.check(act("other"), false), false, "permission", emptyList(), listOf("<permission>: not permitted"), 1)
    }

    @Test fun aViolationIsRefusedNamesTheClauseAndLatches() {
        val kv = MemoryAtomicKv()
        val en = enf(kv)
        res(en.check(act("deploy"), true), false, "violated", listOf("review-first"), listOf(reviewFirst), 0)
        res(en.check(act("review"), true), false, "latched", listOf("review-first"), listOf("<latched>: contract violated at seq 0"), 0)
        assertEquals(true, en.state()!!["latched"])
    }

    @Test fun aViolationWithoutPermissionIsStillAViolation() {
        val en = enf(MemoryAtomicKv())
        res(en.check(act("delete"), false), false, "violated", listOf("no-delete"), listOf(noDelete), 0)
        assertEquals("latched", en.check(act("review"), true).reason)
    }

    @Test fun theLatchRecordsTheSequenceOfTheViolation() {
        val en = enf(MemoryAtomicKv())
        en.check(act("review"), true)
        res(en.check(act("delete"), true), false, "violated", listOf("no-delete"), listOf(noDelete), 1)
        res(en.check(act("review"), true), false, "latched", listOf("no-delete"), listOf("<latched>: contract violated at seq 1"), 1)
    }

    @Test fun withoutLatchingAViolationIsOnlyDenied() {
        val kv = MemoryAtomicKv()
        val en = enf(kv, latch = false)
        res(en.check(act("delete"), true), false, "violated", listOf("no-delete"), listOf(noDelete), 0)
        assertNull(kv.get(docKey))
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        assertEquals(false, en.state()!!["latched"])
    }

    @Test fun aStructuralRefusalIsAStateErrorAndNeverLatches() {
        val en = enf(MemoryAtomicKv())
        res(en.check(q("{}"), true), false, "state-error", emptyList(), listOf("<action>: malformed action"), 0)
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        res(en.check(q("{}"), true), false, "state-error", emptyList(), listOf("<action>: malformed action"), 1)
        assertEquals(false, en.state()!!["latched"])
    }

    // ---- reset

    @Test fun resetNeedsThePrincipalSignatureAtTheLatchedSequence() {
        val kv = MemoryAtomicKv()
        val en = enf(kv)
        assertFalse(en.reset(ContractEnforcer.signReset(key.seed, id, 0)))
        en.check(act("review"), true)
        assertFalse("not latched yet", en.reset(ContractEnforcer.signReset(key.seed, id, 1)))
        en.check(act("delete"), true)
        assertFalse(en.reset(null))
        assertFalse(en.reset(ContractEnforcer.signReset(key2.seed, id, 1)))
        assertFalse(en.reset(ContractEnforcer.signReset(key.seed, id, 0)))
        assertFalse(en.reset(ContractEnforcer.signReset(key.seed, "other", 1)))
        assertEquals("latched", en.check(act("review"), true).reason)
        assertTrue(en.reset(ContractEnforcer.signReset(key.seed, id, 1)))
        assertFalse(en.reset(ContractEnforcer.signReset(key.seed, id, 1)))
        assertEquals(false, en.state()!!["latched"])
        res(en.check(act("deploy"), true), true, "ok", emptyList(), emptyList(), 2)
    }

    @Test fun resetOfACorruptOrForeignLatchedDocumentIsRefused() {
        val kv = MemoryAtomicKv()
        val en = enf(kv)
        en.check(act("review"), true)
        en.check(act("delete"), true)
        val good = m(kv.get(docKey))
        val sig = ContractEnforcer.signReset(key.seed, id, 1)
        kv.set(docKey, withKey(good, "state", q("{}")))
        assertFalse(en.reset(sig))
        kv.set(docKey, withKey(good, "contract_id", "other"))
        assertFalse(en.reset(sig))
        assertTrue(m(kv.get(docKey)).containsKey("latched"))
    }

    @Test fun resetFailsClosedOnAStoreFaultAndNeverSwallowsAFatalError() {
        val kv = StoreKv()
        val en = enf(kv)
        en.check(act("review"), true)
        en.check(act("delete"), true)
        val sig = ContractEnforcer.signReset(key.seed, id, 1)
        kv.failUpdate = { throw RuntimeException("down") }
        assertFalse(en.reset(sig))
        kv.failUpdate = { throw InternalError("fatal") }
        assertThrows(InternalError::class.java) { en.reset(sig) }
        kv.failUpdate = null
        assertTrue(en.reset(sig))
    }

    @Test fun signResetIsTheDomainSeparatedSignatureOverIdAndSequence() {
        assertEquals("atlas-pca/contract-reset/v1\u0000", ContractEnforcer.RESET_DOMAIN)
        val msg = Pca.concat(ContractEnforcer.RESET_DOMAIN.toByteArray(Charsets.UTF_8), AttestUtil.sha256("$id:7".toByteArray(Charsets.UTF_8)))
        val sig = ContractEnforcer.signReset(key.seed, id, 7)
        assertEquals(Pca.b64(key.sign(msg)), sig)
        assertTrue(IntentJs.verifyEd(PRIN, msg, sig))
        assertTrue(sig != ContractEnforcer.signReset(key.seed, id, 8))
        assertTrue(sig != ContractEnforcer.signReset(key.seed, "x$id", 7))
        assertFalse(sig.isEmpty())
    }

    // ---- store faults

    @Test fun aStoreThatNeverRunsTheUpdateIsUnavailable() {
        val kv = StoreKv()
        kv.noop = true
        res(enf(kv).check(act("review"), true), false, "store-error", emptyList(), listOf("store unavailable"), 0)
    }

    @Test fun aStoreErrorDeniesAndAFatalErrorEscapes() {
        val kv = StoreKv()
        val en = enf(kv)
        kv.failUpdate = { throw RuntimeException("down") }
        res(en.check(act("review"), true), false, "store-error", emptyList(), listOf("store error (fail closed)"), 0)
        kv.failUpdate = { throw InternalError("fatal") }
        assertThrows(InternalError::class.java) { en.check(act("review"), true) }
        kv.failUpdate = null
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
    }

    // ---- the clock

    @Test fun aNonFiniteClockOverAStoredStateIsAStateError() {
        for (bad in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            var wall = K08K4.NOW
            val en = enf(MemoryAtomicKv(), clock = { wall })
            res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
            wall = bad
            res(en.check(act("deploy"), true), false, "state-error", emptyList(), listOf("<state>: clock is not finite"), 1)
            wall = K08K4.NOW
            res(en.check(act("deploy"), true), true, "ok", emptyList(), emptyList(), 2)
        }
    }

    @Test fun aNonFiniteClockOnAFreshStoreIsRefusedAsAClockRegressionOrReadAsZero() {
        for (bad in listOf(Double.NaN, Double.POSITIVE_INFINITY)) {
            res(enf(MemoryAtomicKv(), clock = { bad }).check(act("review"), true), false, "state-error", emptyList(), listOf("<state>: advance failed: clock regression"), 0)
        }
        val kv = MemoryAtomicKv()
        val en = enf(kv, clock = { Double.NEGATIVE_INFINITY })
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        assertEquals(0.0, Prohibitions.dv(m(en.state()!!["state"])["now"]), 0.0)
    }

    @Test fun theStateClockNeverGoesBack() {
        var wall = K08K4.NOW + 100
        val en = enf(MemoryAtomicKv(), clock = { wall })
        res(en.check(act("review"), true), true, "ok", emptyList(), emptyList(), 1)
        assertEquals(K08K4.NOW + 100, Prohibitions.dv(m(en.state()!!["state"])["now"]), 0.0)
        wall = K08K4.NOW
        res(en.check(act("deploy"), true), true, "ok", emptyList(), emptyList(), 2)
        assertEquals(K08K4.NOW + 100, Prohibitions.dv(m(en.state()!!["state"])["now"]), 0.0)
        wall = K08K4.NOW + 500
        res(en.check(act("other"), true), true, "ok", emptyList(), emptyList(), 3)
        assertEquals(K08K4.NOW + 500, Prohibitions.dv(m(en.state()!!["state"])["now"]), 0.0)
    }

    // ---- peek

    @Test fun peekEvaluatesWithoutAdvancingOrLatching() {
        val kv = MemoryAtomicKv()
        val en = enf(kv)
        res(en.peek(act("delete")), false, "violated", listOf("no-delete"), listOf(noDelete), 0)
        assertNull(en.state())
        res(en.peek(act("review")), true, "ok", emptyList(), emptyList(), 0)
        assertNull(en.state())
        en.check(act("review"), true)
        res(en.peek(act("deploy")), true, "ok", emptyList(), emptyList(), 1)
        res(en.peek(act("delete")), false, "violated", listOf("no-delete"), listOf(noDelete), 1)
        assertEquals(false, en.state()!!["latched"])
        res(en.check(act("deploy"), true), true, "ok", emptyList(), emptyList(), 2)
    }

    @Test fun peekReportsALatchedContract() {
        val en = enf(MemoryAtomicKv())
        en.check(act("delete"), true)
        res(en.peek(act("review")), false, "latched", listOf("no-delete"), listOf("<latched>: contract violated at seq 0"), 0)
        val en2 = enf(MemoryAtomicKv())
        en2.check(act("review"), true)
        en2.check(act("delete"), true)
        res(en2.peek(act("review")), false, "latched", listOf("no-delete"), listOf("<latched>: contract violated at seq 1"), 1)
    }

    @Test fun peekReadsANonFiniteClockAsZero() {
        for (bad in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            val en = enf(MemoryAtomicKv(), clock = { bad })
            res(en.peek(act("review")), true, "ok", emptyList(), emptyList(), 0)
        }
    }

    @Test fun peekRefusesACorruptDocumentAndFailsClosedOnAStoreFault() {
        val kv = StoreKv()
        val en = enf(kv)
        kv.set(docKey, q("{'v':2}"))
        res(en.peek(act("review")), false, "state-error", emptyList(), listOf(corrupt), 0)
        kv.inner.set(docKey, "x")
        res(en.peek(act("review")), false, "state-error", emptyList(), listOf(corrupt), 0)
        kv.failGet = { throw RuntimeException("down") }
        res(en.peek(act("review")), false, "store-error", emptyList(), listOf("store error (fail closed)"), 0)
        kv.failGet = { throw InternalError("fatal") }
        assertThrows(InternalError::class.java) { en.peek(act("review")) }
    }

    // ---- state and the document shapes

    @Test fun stateIsNullBeforeTheFirstAdmissionAndThenTheStoredState() {
        val en = enf(MemoryAtomicKv())
        assertNull(en.state())
        en.check(act("review"), true)
        val st = en.state()!!
        assertEquals(setOf("state", "latched"), st.keys)
        assertEquals(1.0, Prohibitions.dv(m(st["state"])["seq"]), 0.0)
        assertEquals(false, st["latched"])
    }

    private fun latchedDoc(kv: MemoryAtomicKv): Map<String, Any?> {
        val en = enf(kv)
        en.check(act("review"), true)
        en.check(act("delete"), true)
        return m(kv.get(docKey))
    }

    private fun assertCorrupt(kv: MemoryAtomicKv, doc: Any?, label: String) {
        kv.set(docKey, doc)
        val e = assertThrows(label, IllegalStateException::class.java) { enf(kv).state() }
        assertEquals("ContractEnforcer: stored state is corrupt or belongs to another contract", e.message)
        res(enf(kv).check(act("review"), true), false, "state-error", emptyList(), listOf(corrupt), 0)
    }

    @Test fun everyMalformedDocumentShapeIsCorrupt() {
        val kv = MemoryAtomicKv()
        val good = latchedDoc(kv)
        assertEquals(true, enf(kv).state()!!["latched"])
        val unlatched = LinkedHashMap(good)
        unlatched.remove("latched")
        kv.set(docKey, unlatched)
        assertEquals(false, enf(kv).state()!!["latched"])
        assertCorrupt(kv, "x", "a string")
        assertCorrupt(kv, ArrayList<Any?>(), "a list")
        assertCorrupt(kv, withKey(good, "v", K08K4.num(2.0)), "v 2")
        assertCorrupt(kv, withKey(good, "v", "1"), "v string")
        assertCorrupt(kv, withKey(good, "v", Json.Num("1.5")), "v 1.5")
        val noV = LinkedHashMap(good)
        noV.remove("v")
        assertCorrupt(kv, noV, "no v")
        assertCorrupt(kv, withKey(good, "contract_id", "other"), "foreign contract")
        val noId = LinkedHashMap(good)
        noId.remove("contract_id")
        assertCorrupt(kv, noId, "no contract id")
        assertCorrupt(kv, withKey(good, "state", q("{}")), "empty state")
        assertCorrupt(kv, withKey(good, "state", "x"), "string state")
    }

    @Test fun everyMalformedLatchShapeIsCorruptAndAValidOneIsNot() {
        val kv = MemoryAtomicKv()
        val good = latchedDoc(kv)
        val latched = m(good["latched"])
        assertCorrupt(kv, withKey(good, "latched", K08K4.num(5.0)), "latched not an object")
        assertCorrupt(kv, withKey(good, "latched", "x"), "latched a string")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "seq", "1")), "seq string")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "seq", Json.Num("1.5"))), "seq fractional")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "seq", Json.Num("-0"))), "seq negative zero")
        val noSeq = LinkedHashMap(latched)
        noSeq.remove("seq")
        assertCorrupt(kv, withKey(good, "latched", noSeq), "no seq")
        val noViolated = LinkedHashMap(latched)
        noViolated.remove("violated")
        assertCorrupt(kv, withKey(good, "latched", noViolated), "no violated")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "violated", "x")), "violated a string")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "violated", arrayListOf<Any?>(K08K4.num(5.0)))), "violated with a number")
        assertCorrupt(kv, withKey(good, "latched", withKey(latched, "violated", arrayListOf<Any?>("a", null))), "violated with null")
        // seq 0 and an empty or multi-id violated list are well formed
        kv.set(docKey, withKey(good, "latched", withKey(withKey(latched, "seq", Json.Num("0")), "violated", ArrayList<Any?>())))
        assertEquals(true, enf(kv).state()!!["latched"])
        kv.set(docKey, withKey(good, "latched", withKey(latched, "violated", arrayListOf<Any?>("a", "b"))))
        assertEquals(true, enf(kv).state()!!["latched"])
        val en = enf(kv)
        res(en.check(act("review"), true), false, "latched", listOf("a", "b"), listOf("<latched>: contract violated at seq 1"), 1)
        assertTrue(en.reset(ContractEnforcer.signReset(key.seed, id, 1)))
    }
}
