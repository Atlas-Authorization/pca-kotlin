package net.atlasauth.pca.verifier

import java.security.SecureRandom
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for Revocation.kt (k05 survivors): exact reasons of the TS revocation staleness / epoch / non-membership code. */
@Suppress("UNCHECKED_CAST")
class Kill05PolRevocationTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guard: String get() = doc["guardian_public"] as String
    private val now = 1_800_000_000_000L
    private val nowD = now.toDouble()

    /** The vectors' guardian signs with 32 bytes of 0x0b. */
    private fun edSign(msg: ByteArray): String {
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + ByteArray(32) { 11 }
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val s = java.security.Signature.getInstance("Ed25519")
        s.initSign(key)
        s.update(msg)
        return Pca.b64(s.sign())
    }

    private fun body(epoch: Long = 0L, root: Any? = "r", grantRef: String = "g1", issuedAt: Long = now - 1_000): LinkedHashMap<String, Any?> = linkedMapOf(
        "instance_id" to "i", "grant_ref" to grantRef, "epoch" to epoch, "set_size" to 0L, "root" to root,
        "issued_at" to issuedAt, "not_after" to issuedAt + 600_000L,
    )

    private fun msg(signed: Map<String, Any?>): ByteArray = Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(signed))

    /** An Ed25519 epoch (no alg). */
    private fun edEpoch(epoch: Long = 0L, root: Any? = "r", grantRef: String = "g1", issuedAt: Long = now - 1_000): Map<String, Any?> {
        val b = body(epoch, root, grantRef, issuedAt)
        return LinkedHashMap(b).also { it["guardian"] = guard; it["sig"] = edSign(msg(b)) }
    }

    private val pqKey: AsymmetricCipherKeyPair by lazy {
        val g = MLDSAKeyPairGenerator(); g.init(MLDSAKeyGenerationParameters(SecureRandom(), MLDSAParameters.ml_dsa_65)); g.generateKeyPair()
    }
    private val pqPk: String by lazy { Pca.b64((pqKey.public as MLDSAPublicKeyParameters).encoded) }

    /** A hybrid-ed25519-ml-dsa-65 epoch: alg and pq_pk are bound into the signed body; `sig` Ed25519, `pq_sig` ML-DSA over the same message. */
    private fun hybridEpoch(): Map<String, Any?> {
        val signed = LinkedHashMap(body())
        signed["alg"] = "hybrid-ed25519-ml-dsa-65"
        signed["pq_pk"] = pqPk
        val m = msg(signed)
        val s = MLDSASigner(); s.init(true, pqKey.private); s.update(m, 0, m.size)
        return LinkedHashMap(signed).also {
            it["guardian"] = guard; it["sig"] = edSign(m); it["pq_sig"] = Pca.b64(s.generateSignature())
        }
    }

    @Test fun classRankAndCheckBasics() {
        assertEquals(2, Revocation.classRank("bogus"))
        assertEquals(2, Revocation.classRank(7L))
        assertEquals(2, Revocation.classRank(null))
        assertEquals(1, Revocation.classRank("costly"))
        assertEquals(0, Revocation.classRank("reversible"))
        assertEquals("Revocation.Check(ok=false, reason=r)", Revocation.Check(false, "r").toString())
        assertEquals("Revocation.Check(ok=true, reason=null)", Revocation.Check(true).toString())
        // a positive sub-millisecond window is a valid configuration (TS: finite and > 0)
        val p = Revocation.StalenessPolicy(maxRevocationAgeMs = 0.5, irreversibleMs = 0.5, costlyMs = 0.5)
        assertEquals(0.5, Revocation.maxAgeMs(p, "irreversible"), 0.0)
    }

    @Test fun fmtIsJavaScriptString() {
        assertEquals("Infinity", Revocation.fmt(Double.POSITIVE_INFINITY))
        assertEquals("-Infinity", Revocation.fmt(Double.NEGATIVE_INFINITY))
        assertEquals("NaN", Revocation.fmt(Double.NaN))
        assertEquals("1.5", Revocation.fmt(1.5))
        assertEquals("0", Revocation.fmt(0.0))
    }

    @Test fun maxAgeOfAnUnknownClassIsTheMaximumEvenOnAHashCollision() {
        // same String.hashCode as the class names (c+1, next-31): the `when` must compare the strings, not only the hashes
        val p = Revocation.StalenessPolicy(maxRevocationAgeMs = 300_000.0, irreversibleMs = 1_000.0, costlyMs = 2_000.0)
        for ((alias, real) in listOf("jSreversible" to "irreversible", "dPstly" to "costly", "sBte_limited" to "rate_limited")) {
            assertEquals(real.hashCode(), alias.hashCode())
            assertEquals(alias, 300_000.0, Revocation.maxAgeMs(p, alias), 0.0)
        }
        assertEquals(1_000.0, Revocation.maxAgeMs(p, "irreversible"), 0.0)
        assertEquals(2_000.0, Revocation.maxAgeMs(p, "costly"), 0.0)
        assertEquals(2_000.0, Revocation.maxAgeMs(p, "rate_limited"), 0.0)
    }

    @Test fun anUnknownOrNonFiniteIssueTimeIsUnknownAge() {
        val unknown = "revocation state age is unknown (unverifiable revocation state)"
        for (t in listOf<Any?>(null, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, "1")) {
            val c = Revocation.checkAge(t, nowD, 300_000.0)
            assertFalse("$t", c.ok)
            assertEquals("$t", unknown, c.reason)
        }
        assertTrue(Revocation.checkAge(now - 1_000, nowD, 300_000.0).ok)
    }

    @Test fun fromJson() {
        val r = Revocation.State.Root("r")
        assertSame(r, Revocation.State.fromJson(r))
        val e = Revocation.State.fromJson(linkedMapOf("kind" to "epoch", "epoch" to "x", "root" to "y", "last_accepted_epoch" to 5L)) as Revocation.State.Epoch
        assertEquals("x", e.epoch); assertEquals("y", e.root); assertEquals(5L, e.lastAcceptedEpoch)
        assertNull((Revocation.State.fromJson(linkedMapOf("kind" to "epoch", "last_accepted_epoch" to Json.Num("1.5"))) as Revocation.State.Epoch).lastAcceptedEpoch)
        val rt = Revocation.State.fromJson(linkedMapOf("kind" to "root", "root" to "z", "issued_at" to 3L)) as Revocation.State.Root
        assertEquals("z", rt.root); assertEquals(3L, rt.issuedAt)
        assertNull(Revocation.State.fromJson(linkedMapOf("kind" to "other")))
        assertNull(Revocation.State.fromJson(null))
    }

    @Test fun checkEpochEdges() {
        // a non-string member name makes the normalisation throw: the fail-closed handler answers
        val odd = linkedMapOf<Any?, Any?>("guardian" to guard, 7 to 1)
        assertEquals("revocation epoch check error", Revocation.checkEpoch(odd, guard, nowD).reason)
        // a non-number PCActn freshness.epoch predates any epoch
        val c = Revocation.checkEpoch(edEpoch(), guard, nowD, grantRef = "g1", pcactnEpoch = "x")
        assertEquals("PCActn freshness.epoch x predates the revocation epoch 0", c.reason)
        assertTrue(Revocation.checkEpoch(edEpoch(), guard, nowD, grantRef = "g1", pcactnEpoch = 0L).ok)
        // the age cap passes, then the rollback check still runs
        val rb = Revocation.checkEpoch(edEpoch(), guard, nowD, grantRef = "g1", lastAcceptedEpoch = 5L, maxAgeMs = 300_000.0)
        assertEquals("revocation epoch 0 is older than the last accepted 5 (rollback)", rb.reason)
        // ... and a stale epoch stops at the age cap
        val stale = Revocation.checkEpoch(edEpoch(issuedAt = now - 10_000), guard, nowD, grantRef = "g1", maxAgeMs = 5_000.0)
        assertEquals("revocation epoch is 10000 ms old, over the verifier's maximum of 5000 ms (stale revocation state)", stale.reason)
    }

    @Test fun hybridEpochVerifiesOnlyUnderTheVerifiersPin() {
        val ep = hybridEpoch()
        assertTrue(Revocation.checkEpoch(ep, guard, nowD, grantRef = "g1", pqPins = mapOf(guard to pqPk)).ok)
        val bad = "revocation epoch signature invalid"
        assertEquals(bad, Revocation.checkEpoch(ep, guard, nowD, grantRef = "g1").reason)
        assertEquals(bad, Revocation.checkEpoch(ep, guard, nowD, grantRef = "g1", pqPins = mapOf(guard to "AAAA")).reason)
        // the same through checkState: the pin comes from the policy
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, pqPins = mapOf(guard to pqPk))
        val st = Revocation.checkState(pol, Revocation.State.Epoch(ep), nowD, grantRef = "g1", signedClass = "reversible", serverClass = "reversible")
        assertTrue(st.reason, st.ok)
        assertEquals(ep, st.epoch)
        val noPin = Revocation.checkState(Revocation.StalenessPolicy(guardianPublic = guard), Revocation.State.Epoch(ep), nowD, grantRef = "g1", signedClass = "reversible")
        assertEquals(bad, noPin.reason)
    }

    @Test fun checkStateEpochBranch() {
        val ep = edEpoch()
        val none = "no signed revocation epoch"
        // the guardian: explicit, else the policy's
        val explicit = Revocation.checkState(null, Revocation.State.Epoch(ep), nowD, grantRef = "g1", guardianPublic = guard)
        assertTrue(explicit.reason, explicit.ok)
        assertEquals(ep, explicit.epoch)
        assertTrue(Revocation.checkState(Revocation.StalenessPolicy(guardianPublic = guard), Revocation.State.Epoch(ep), nowD, grantRef = "g1", signedClass = "reversible").ok)
        assertTrue(Revocation.checkState(Revocation.StalenessPolicy(), Revocation.State.Epoch(ep), nowD, grantRef = "g1", signedClass = "reversible", guardianPublic = guard).ok)
        assertEquals(none, Revocation.checkState(null, Revocation.State.Epoch(ep), nowD, grantRef = "g1").reason)
        assertEquals(none, Revocation.checkState(null, Revocation.State.Epoch(ep), nowD, grantRef = "g1", guardianPublic = "").reason)
        assertEquals(none, Revocation.checkState(null, Revocation.State.Epoch("x"), nowD, grantRef = "g1", guardianPublic = guard).reason)
        assertEquals(none, Revocation.checkState(null, null, nowD, guardianPublic = guard).reason)
        // rollback against the state's last accepted epoch (with a policy: the age cap runs first)
        val rb = Revocation.checkState(
            Revocation.StalenessPolicy(), Revocation.State.Epoch(ep, lastAcceptedEpoch = 5L), nowD, grantRef = "g1",
            signedClass = "reversible", guardianPublic = guard,
        )
        assertEquals("revocation epoch 0 is older than the last accepted 5 (rollback)", rb.reason)
    }

    @Test fun checkStateRootBranch() {
        val noRoot = "no revocation root"
        for (r in listOf<Any?>("", 5L, null)) assertEquals("$r", noRoot, Revocation.checkState(null, Revocation.State.Root(r), nowD).reason)
        assertTrue(Revocation.checkState(null, Revocation.State.Root("r"), nowD).ok)
        // a fresh root under a policy still needs a proof per id
        val pol = Revocation.StalenessPolicy(maxRevocationAgeMs = 300_000.0)
        val c = Revocation.checkState(pol, Revocation.State.Root("r", now - 1_000), nowD, signedClass = "reversible", ids = listOf("a"))
        assertEquals("no non-membership proof for a", c.reason)
        // a throwing proof source is a fail-closed refusal
        val t = Revocation.checkState(null, Revocation.State.Root("r"), nowD, ids = listOf("a"), proofFor = { _ -> throw IllegalStateException("boom") })
        assertEquals("revocation state check error (fail closed)", t.reason)
    }

    @Test fun nonJsonIntegerSpellingsInAProofAreRefused() {
        val set = doc["revocation_set"] as Map<String, Any?>
        val root = (set["single"] as Map<String, Any?>)["root"] as String
        fun hi(index: Any?, size: Any?) = linkedMapOf<String, Any?>("id" to "only", "proof" to linkedMapOf("index" to index, "size" to size, "path" to ArrayList<Any?>()))
        assertTrue(Revocation.verifyNonMembership(root, linkedMapOf("size" to 1L, "hi" to hi(0L, 1L)), "a"))
        assertFalse(Revocation.verifyNonMembership(root, linkedMapOf("size" to 1L, "hi" to hi(Json.Num("00"), 1L)), "a"))
        assertFalse(Revocation.verifyNonMembership(root, linkedMapOf("size" to 1L, "hi" to hi(0L, Json.Num("01"))), "a"))
        assertFalse(Revocation.verifyNonMembership(root, linkedMapOf("size" to Json.Num("01"), "hi" to hi(0L, 1L)), "a"))
    }

    // ---- authorize(): onEpochAccepted ----

    @Test fun onEpochAcceptedRunsForAnAdmittedSignedEpoch() {
        val c = AuthorizeTestKit.case("envelope-max-spend-within")
        val p = AuthorizeTestKit.pcactn(c)
        val gref = p["grant_ref"] as String
        val ep = edEpoch(root = IntentRevocation.revsetRoot(emptyList()), grantRef = gref, issuedAt = AuthorizeTestKit.NOW - 1_000)
        val seen = ArrayList<Map<String, Any?>>()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, proofFor = { _, _ -> linkedMapOf("size" to 0L) }, onEpochAccepted = { e, _ -> seen.add(e) })
        val ctx = linkedMapOf<String, Any?>("reversibility_class" to "reversible", "revocation_state" to linkedMapOf("kind" to "epoch", "epoch" to ep))
        val r = Authorize.authorize(
            p,
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { AuthorizeTestKit.grant(c) },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW,
                plan = Authorize.SINGLE_STEP, context = { ctx }, revocationStaleness = pol,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(AuthorizeTestKit.op(c)),
            ),
        )
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals(1, seen.size)
        assertEquals(gref, seen[0]["grant_ref"])
    }
}
