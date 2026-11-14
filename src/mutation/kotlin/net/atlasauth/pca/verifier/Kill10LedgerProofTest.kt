package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.PRIN
import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.arr
import net.atlasauth.pca.verifier.K08K4.canon
import net.atlasauth.pca.verifier.K08K4.contract
import net.atlasauth.pca.verifier.K08K4.key
import net.atlasauth.pca.verifier.K08K4.key2
import net.atlasauth.pca.verifier.K08K4.m
import net.atlasauth.pca.verifier.K08K4.never
import net.atlasauth.pca.verifier.K08K4.q
import net.atlasauth.pca.verifier.K08K4.state0
import net.atlasauth.pca.verifier.K08K4.w
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every reading of the mutations that the equivalent-mutant ledger does not claim: the monitor's amount tests, the signature and
 * decision tests, the beacon integer test, and the enforcer's clock, peek and reset paths, each driven to a result that tells the
 * readings apart.
 */
@Suppress("UNCHECKED_CAST")
class Kill10LedgerProofTest {
    private fun constitution(invariants: String): Map<String, Any?> = m(q("{'version':1,'principal':'p','invariants':$invariants}"))

    private fun reasons(r: Map<String, Any?>): List<Any?> = r["reasons"] as List<Any?>

    // ---- the lists returned for a well-formed invariant or clause are real, mutable ArrayLists

    @Test fun wellFormedInvariantsAndClausesYieldMutableLists() {
        val cap = Prohibitions.validateInvariant(m(q("{'id':'c','kind':'cap','when':{'verb':'x'},'amount':'action.amt','max':1}")))
        val rate = Prohibitions.validateInvariant(m(q("{'id':'r','kind':'rate','when':{'verb':'x'},'max':1,'window_secs':1}")))
        val clause = Contracts.validateClause(q("{'id':'p','kind':'precedes','p':${w("a")},'q':${w("b")}}"), HashSet<String>(), 1)
        for (l in listOf(cap, rate, clause)) {
            assertTrue(l.isEmpty())
            assertTrue(l.javaClass.name, l is java.util.ArrayList<*>)
        }
    }

    // ---- amounts that do not resolve: the exact reason, in the check and in the advance

    private val capC = constitution("[{'id':'c1','kind':'cap','when':{'verb':'x'},'amount':'action.params.amt','max':10}]")

    @Test fun anUnresolvableCapAmountIsRefusedWithItsOwnReason() {
        fun check(params: String) = Prohibitions.checkProhibitions(act("x", "/r", params), capC, state0())
        assertEquals(true, check("{'amt':5}")["ok"])
        assertEquals(true, check("{'amt':10}")["ok"])
        assertEquals(listOf<Any?>("c1: cap exceeded: 0 + 11 > 10"), reasons(check("{'amt':11}")))
        for (bad in listOf("{'amt':'abc'}", "{}", "{'amt':-1}", "{'amt':null}", "{'amt':true}")) {
            val r = check(bad)
            assertEquals(bad, false, r["ok"])
            assertEquals(bad, listOf<Any?>("c1: amount unresolvable (fail closed)"), reasons(r))
        }
    }

    @Test fun anUnresolvableCapAmountFailsTheAdvanceWithItsOwnReason() {
        fun adv(params: String) = Prohibitions.advanceStateStrict(act("x", "/r", params), capC, state0())
        assertEquals(true, adv("{'amt':5}")["ok"])
        for (bad in listOf("{'amt':'abc'}", "{}", "{'amt':-1}", "{'amt':null}", "{'amt':true}")) {
            val r = adv(bad)
            assertEquals(bad, false, r["ok"])
            assertEquals(bad, "c1: amount unresolvable", r["reason"])
        }
    }

    @Test fun approvalOverAThresholdTreatsAnUnresolvableAmountAsOver() {
        val c = constitution(
            "[{'id':'ap','kind':'require_approval_over','when':{'verb':'x'},'amount':'action.params.amt','threshold':100," +
                "'approved':[{'field':'action.params.ok','op':'eq','value':1}]}]",
        )
        fun check(params: String) = Prohibitions.checkProhibitions(act("x", "/r", params), c, state0())
        val need = listOf<Any?>("ap: approval required over 100")
        assertEquals(true, check("{'amt':50}")["ok"])
        assertEquals(true, check("{'amt':100}")["ok"])
        assertEquals(true, check("{'amt':150,'ok':1}")["ok"])
        assertEquals(need, reasons(check("{'amt':150}")))
        for (bad in listOf("{'amt':'abc'}", "{}", "{'amt':-5}", "{'amt':'abc','ok':2}")) assertEquals(bad, need, reasons(check(bad)))
        assertEquals(true, check("{'amt':'abc','ok':1}")["ok"])
    }

    // ---- the decision of the composed check

    @Test fun theComposedDecisionNamesTheDeciderAndOmitsAReasonWhenThereIsNone() {
        val c = constitution("[{'id':'n','kind':'never','when':{'verb':'delete'}}]")
        val s = state0()
        val bad = act("delete")
        val good = act("read")
        for (permitted in listOf(true, false)) {
            val r = Prohibitions.checkAndAdvance(permitted, bad, c, s)
            assertEquals(false, r["allow"])
            assertEquals("prohibition", r["decidedBy"])
            assertFalse(r.containsKey("reason"))
        }
        val denied = Prohibitions.checkAndAdvance(false, good, c, s)
        assertEquals(false, denied["allow"])
        assertEquals("permission", denied["decidedBy"])
        assertFalse(denied.containsKey("reason"))
        val allowed = Prohibitions.checkAndAdvance(true, good, c, s)
        assertEquals(true, allowed["allow"])
        assertEquals("none", allowed["decidedBy"])
        val stale = Prohibitions.checkAndAdvance(true, good, c, s, Prohibitions.jn(9.0))
        assertEquals("state", stale["decidedBy"])
        assertEquals("stale state head (seq)", stale["reason"])
        val staleDigest = Prohibitions.checkAndAdvance(true, good, c, s, Prohibitions.ABSENT, "nope")
        assertEquals("stale state head (digest)", staleDigest["reason"])
    }

    // ---- signatures: a valid one verifies, a wrong or non-string one is "bad signature", an untrusted signer is refused

    private fun badSig(): String = Pca.b64(key.sign(ByteArray(8) { 7 }))

    @Test fun aSignedConstitutionVerifiesAndAWrongOrNonStringSignatureDoesNot() {
        val c = LinkedHashMap(constitution("[{'id':'n','kind':'never','when':{'verb':'delete'}}]")).also { it["principal"] = PRIN }
        val id = Prohibitions.constitutionId(c)
        val sig = Pca.b64(key.sign(Prohibitions.domainMessage(Prohibitions.CONSTITUTION_SIG_DOMAIN, id)))
        val signed = LinkedHashMap(c).also { it["id"] = id; it["sig"] = sig }
        assertNull(Prohibitions.verifyConstitution(signed, PRIN))
        assertNull(Prohibitions.verifyConstitution(signed, null))
        assertEquals("principal mismatch", Prohibitions.verifyConstitution(signed, key2.id()))
        assertEquals("bad signature", Prohibitions.verifyConstitution(LinkedHashMap(signed).also { it["sig"] = badSig() }, PRIN))
        assertEquals("bad signature", Prohibitions.verifyConstitution(LinkedHashMap(signed).also { it["sig"] = Prohibitions.jn(5.0) }, PRIN))
        assertEquals("bad signature", Prohibitions.verifyConstitution(LinkedHashMap(signed).also { it["sig"] = null }, PRIN))
    }

    @Test fun aSignedContractVerifiesAndAWrongOrNonStringSignatureDoesNot() {
        val sc = Contracts.signContract(contract(), key.seed)
        assertNull(Contracts.verifyContract(sc, PRIN))
        assertEquals("bad signature", Contracts.verifyContract(LinkedHashMap(sc).also { it["sig"] = badSig() }, PRIN))
        assertEquals("bad signature", Contracts.verifyContract(LinkedHashMap(sc).also { it["sig"] = Prohibitions.jn(5.0) }, PRIN))
        assertEquals("bad signature", Contracts.verifyContract(LinkedHashMap(sc).also { it["sig"] = null }, PRIN))
    }

    @Test fun signedSafetyEvidenceVerifiesOnlyForATrustedSignerWithAGoodSignature() {
        val c = constitution("[{'id':'n','kind':'never','when':{'verb':'delete'}}]")
        val a = act("read")
        val s = state0()
        val ev = Prohibitions.proveSafety(a, c, s)
        val signed = Prohibitions.signSafetyEvidence(ev, key.seed, PRIN)
        val full = Prohibitions.map("signer", PRIN, "action", a, "constitution", c, "state", s)
        assertNull(Prohibitions.verifySignedSafetyEvidence(signed, full))
        assertEquals("signer not trusted", Prohibitions.verifySignedSafetyEvidence(signed, Prohibitions.map("signer", key2.id(), "action", a, "constitution", c, "state", s)))
        assertEquals("signer not trusted", Prohibitions.verifySignedSafetyEvidence(LinkedHashMap(signed).also { it["signer"] = Prohibitions.jn(5.0) }, full))
        assertEquals("bad signature", Prohibitions.verifySignedSafetyEvidence(LinkedHashMap(signed).also { it["sig"] = badSig() }, full))
        assertEquals("bad signature", Prohibitions.verifySignedSafetyEvidence(LinkedHashMap(signed).also { it["sig"] = Prohibitions.jn(5.0) }, full))
        // digests and the constitution instead of the documents: the rows must cover every invariant
        val byDigest = Prohibitions.map("signer", PRIN, "actionDigest", ev["action_digest"], "constitution", c, "stateDigest", ev["state_digest"])
        assertNull(Prohibitions.verifySignedSafetyEvidence(signed, byDigest))
        val thin = LinkedHashMap(ev).also { it["evaluated"] = ArrayList<Any?>() }
        val signedThin = Prohibitions.signSafetyEvidence(thin, key.seed, PRIN)
        assertEquals("evidence does not cover every invariant", Prohibitions.verifySignedSafetyEvidence(signedThin, byDigest))
    }

    // ---- beacons

    private val ed = Keys.edGenerate()
    private val t0 = 1_000_000_020_000L
    private fun ln(v: Long) = IntentJs.ofLong(v)

    private fun beacon(over: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val b = linkedMapOf<String, Any?>(
            "v" to ln(2), "instance" to "ins_1", "scope" to "g1", "epoch" to ln(Math.floorDiv(t0, Beacons.EPOCH_MS)), "seq" to ln(1),
            "issued_at" to ln(t0), "not_after" to ln(t0 + 60_000), "issuer" to ed.id(),
        )
        for ((k, v) in over) b[k] = v
        return LinkedHashMap(b).also { it["sig"] = Pca.b64(ed.sign(Pca.concat(IntentJs.utf8("atlas-pca/beacon/v2\u0000"), IntentJs.canonBytes(b)))) }
    }

    private fun verify(b: Map<String, Any?>) = Beacons.verify(b, listOf(ed.id()), t0, "ins_1", "g1", null)

    @Test fun everyWindowFieldIsCheckedAsAnIntegerAndASequenceOfZeroIsAllowed() {
        val ok = verify(beacon())
        assertTrue(ok.reason, ok.ok)
        assertNull(ok.reason)
        assertTrue(verify(beacon(mapOf("seq" to ln(0)))).ok)
        for (k in listOf("epoch", "seq", "issued_at", "not_after")) {
            val r = verify(beacon(mapOf(k to Json.Num("1.5"))))
            assertFalse(k, r.ok)
            assertEquals(k, "malformed window", r.reason)
        }
        val neg = verify(beacon(mapOf("seq" to ln(-1))))
        assertFalse(neg.ok)
        assertEquals("malformed window", neg.reason)
    }

    @Test fun isIntegerOnItsOwn() {
        fun isInt(x: Any?): Boolean = KUtil.priv<Boolean>(Beacons, "isInteger", x)
        assertTrue(isInt(Json.Num("2")))
        assertTrue(isInt(Json.Num("-3")))
        assertTrue(isInt(Json.Num("0")))
        assertTrue(isInt(2L))
        assertFalse(isInt(Json.Num("1.5")))
        assertFalse(isInt(Json.Num("NaN")))
        assertFalse(isInt(Json.Num("Infinity")))
        assertFalse(isInt(Json.Num("-Infinity")))
        assertFalse(isInt("2"))
        assertFalse(isInt(null))
    }

    // ---- the enforcer

    private val clauses = arr(never("no-delete", "delete"), "{'id':'review-first','kind':'precedes','p':${w("review")},'q':${w("deploy")}}")
    private val sc: Map<String, Any?> = Contracts.signContract(contract(clauses), key.seed)
    private val id: String = sc["id"] as String
    private val docKey = "contract/$id"

    private fun enf(kv: AtomicKv, clock: () -> Double = { K08K4.NOW }): ContractEnforcer = ContractEnforcer.open(kv, sc, PRIN, null, clock, true)

    private class SpyKv(val inner: AtomicKv) : AtomicKv {
        var threw = false
        override fun get(key: String): Any? = inner.get(key)
        override fun set(key: String, value: Any?) = inner.set(key, value)
        override fun update(key: String, fn: (Any?) -> Any?): Any? = try {
            inner.update(key, fn)
        } catch (t: Throwable) {
            threw = true
            throw t
        }
    }

    @Test fun aFiniteClockIsStoredAsACanonicalNumberAndAdmissionsKeepAdvancing() {
        val en = enf(MemoryAtomicKv())
        assertEquals(1L, en.check(act("review"), true).seq)
        assertEquals("1700000000000", canon((en.state()!!["state"] as Map<String, Any?>)["now"]))
        val second = en.check(act("deploy"), true)
        assertTrue(second.reason, second.allow)
        assertEquals(2L, second.seq)
        assertEquals("1700000000000", canon((en.state()!!["state"] as Map<String, Any?>)["now"]))
        val later = enf(MemoryAtomicKv()) { K08K4.NOW + 5.0 }
        assertTrue(later.check(act("review"), true).allow)
        assertEquals("1700000000005", canon((later.state()!!["state"] as Map<String, Any?>)["now"]))
    }

    @Test fun peekReadsTheStoredStateAndSeedsAGenesisStateOtherwise() {
        val en = enf(MemoryAtomicKv())
        val fresh = en.peek(act("deploy"))
        assertFalse(fresh.allow)
        assertEquals("violated", fresh.reason)
        assertEquals(0L, fresh.seq)
        assertTrue(en.peek(act("review")).allow)
        assertTrue(en.check(act("review"), true).allow)
        val after = en.peek(act("deploy"))
        assertTrue(after.reason, after.allow)
        assertEquals("ok", after.reason)
        assertEquals(1L, after.seq)
        for (clock in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, 0.0, -5.0, 1.0e300)) {
            val r = enf(MemoryAtomicKv()) { clock }.peek(act("review"))
            assertTrue("$clock ${r.reason}", r.allow)
            assertEquals("ok", r.reason)
        }
    }

    @Test fun resetClearsOnlyOurOwnLatchedDocumentWithTheRightSignatureAndNeverThrowsInsideTheUpdate() {
        val kv = MemoryAtomicKv()
        val en = enf(kv)
        assertTrue(en.check(act("review"), true).allow)
        assertEquals("violated", en.check(act("delete"), true).reason)
        val seq = Prohibitions.dv(((kv.get(docKey) as Map<String, Any?>)["latched"] as Map<String, Any?>)["seq"]).toLong()
        val good = ContractEnforcer.signReset(key.seed, id, seq)
        assertFalse(en.reset(null))
        assertFalse(en.reset(ContractEnforcer.signReset(key2.seed, id, seq)))
        assertFalse(en.reset(ContractEnforcer.signReset(key.seed, id, seq + 1)))
        assertTrue((kv.get(docKey) as Map<String, Any?>).containsKey("latched"))
        assertTrue(en.reset(good))
        assertFalse((kv.get(docKey) as Map<String, Any?>).containsKey("latched"))
        assertFalse(en.reset(good))

        // a latched document that belongs to another contract is left alone even for a signature that fits this one
        val foreignKv = MemoryAtomicKv()
        val foreign = enf(foreignKv)
        foreign.check(act("delete"), true)
        val doc = LinkedHashMap(foreignKv.get(docKey) as Map<String, Any?>)
        assertTrue(doc.containsKey("latched"))
        doc["contract_id"] = "another-contract"
        foreignKv.set(docKey, doc)
        val fseq = Prohibitions.dv((doc["latched"] as Map<String, Any?>)["seq"]).toLong()
        assertFalse(foreign.reset(ContractEnforcer.signReset(key.seed, id, fseq)))
        assertTrue((foreignKv.get(docKey) as Map<String, Any?>).containsKey("latched"))

        // a valid document that is not latched is declined by the early return, not by an exception inside the update
        val spy = SpyKv(MemoryAtomicKv())
        val plain = enf(spy)
        assertTrue(plain.check(act("review"), true).allow)
        assertFalse(plain.reset(ContractEnforcer.signReset(key.seed, id, 1)))
        assertFalse(spy.threw)
        // and a missing document likewise
        val empty = SpyKv(MemoryAtomicKv())
        assertFalse(enf(empty).reset(ContractEnforcer.signReset(key.seed, id, 0)))
        assertFalse(empty.threw)
    }

    // ---- a contract reports the rows of its invariants and latches a prerequisite in the next state

    @Test fun contractsReportInvariantRowsAndLatchPrerequisites() {
        val c = contract("[{'id':'rf','kind':'precedes','p':${w("review")},'q':${w("deploy")}}]", "[{'id':'nd','kind':'never','when':${w("delete")}}]")
        val bad = Contracts.checkContract(act("delete"), c, state0())
        assertEquals(listOf<Any?>("nd"), bad["violated"])
        val good = Contracts.checkContract(act("review"), c, state0())
        assertEquals(true, good["ok"])
        assertEquals(listOf("nd:pass", "rf:pass"), K08K4.rows(good))
        val r = Contracts.advanceContract(state0(), act("review"), c)
        assertEquals(true, r["ok"])
        assertEquals(canon(q("{'rf':1700000000000}")), canon((r["next"] as Map<String, Any?>)["latched"]))
        val idle = Contracts.advanceContract(state0(), act("read"), c)
        assertEquals("{}", canon((idle["next"] as Map<String, Any?>)["latched"]))
    }
}
