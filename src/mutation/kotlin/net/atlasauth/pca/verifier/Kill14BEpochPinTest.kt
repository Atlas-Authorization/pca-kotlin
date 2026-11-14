package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** H13: the revocation-epoch rollback pin (`<grantId>:epoch` in the state store) is automatic. */
@Suppress("UNCHECKED_CAST")
class Kill14BEpochPinTest {
    private val c = case("envelope-max-spend-within")
    private val stale: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guard: String get() = stale["guardian_public"] as String
    private val gid: String get() = grant(c)["id"] as String
    private val pinKey: String get() = "$gid:epoch"

    private fun signedEpoch(grantRef: String, issuedAt: Long, epoch: Long): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to grantRef, "epoch" to epoch, "set_size" to 0L, "root" to IntentRevocation.revsetRoot(emptyList()),
            "issued_at" to issuedAt, "not_after" to issuedAt + 600_000L,
        )
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + ByteArray(32) { 11 }
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        return LinkedHashMap(body).also { it["guardian"] = guard; it["sig"] = Pca.b64(sig.sign()) }
    }

    @After fun resetHook() { Authorize.coreHook = null }

    private fun run(store: Authorize.StateStore, epoch: Long, hostLast: Long? = null, revoked: Boolean = false, gate: Authorize.FreshnessGate? = null): Authorize.Result {
        // the proof carries a freshness anchor at the revocation epoch (it must not predate it); the signed fixture is then edited under a neutral core verdict
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        p["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to (if (gate != null) "r" else ""), "epoch" to IntentJs.ofLong(epoch), "accumulator_witness" to "")
        val st = linkedMapOf<String, Any?>("kind" to "epoch", "epoch" to signedEpoch(p["grant_ref"] as String, AuthorizeTestKit.NOW - 1_000, epoch))
        if (hostLast != null) st["last_accepted_epoch"] = hostLast
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, proofFor = { _, _ -> linkedMapOf("size" to 0L) })
        return Authorize.authorize(
            p,
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) },
                stateStore = store, isRevoked = { _, _ -> revoked }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP,
                context = { mapOf("revocation_state" to st, "reversibility_class" to "reversible") }, revocationStaleness = pol,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(AuthorizeTestKit.op(c)), risk = AuthorizeTestKit.calmRisk,
                enforceFreshness = gate,
            ),
        )
    }

    @Test fun anOlderEpochAfterANewerOneIsARollbackWithoutAHostPin() {
        val store = Authorize.MemoryStateStore()
        val first = run(store, 5)
        assertTrue(first.reasons.toString(), first.allow)
        assertEquals(5L, store.last(pinKey))
        val back = run(store, 4)
        assertFalse(back.allow)
        assertEquals("freshness: revocation epoch 4 is older than the last accepted 5 (rollback)", back.reason)
    }

    @Test fun aSeededPinFloorsTheHostValueAndANewerEpochRaisesIt() {
        val store = Authorize.MemoryStateStore()
        store.claim(pinKey, 7)
        assertEquals("freshness: revocation epoch 6 is older than the last accepted 7 (rollback)", run(store, 6, hostLast = 1).reason)
        // the host value counts too when it is higher than the pin
        assertEquals("freshness: revocation epoch 8 is older than the last accepted 9 (rollback)", run(store, 8, hostLast = 9).reason)
        assertTrue(run(store, 8).allow)
        assertEquals(8L, store.last(pinKey))
    }

    @Test fun aDeniedActionNeverRaisesThePin() {
        val store = Authorize.MemoryStateStore()
        store.claim(pinKey, 3)
        val r = run(store, 9, revoked = true)
        assertFalse(r.allow)
        assertEquals(3L, store.last(pinKey))
    }

    @Test fun theSameEpochTwiceIsNotARollback() {
        val store = Authorize.MemoryStateStore()
        store.claim(pinKey, 5)
        assertTrue(run(store, 5).allow)
        assertEquals(5L, store.last(pinKey))
    }

    @Test fun aStoreThatCannotHoldPinsIsRefusedAtConstruction() {
        val plain = object : Authorize.StateStore { override fun claim(key: String, counter: Long): Authorize.ClaimResult? = Authorize.ClaimResult(true) }
        val pol = Revocation.StalenessPolicy(guardianPublic = guard)
        val msg = "revocation staleness needs a state store that implements pins (rollback protection)"
        assertEquals(msg, assertThrows(IllegalArgumentException::class.java) { Authorize.AuthorizeOptions(plain, null, revocationStaleness = pol, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk) }.message)
        assertEquals(msg, assertThrows(IllegalArgumentException::class.java) {
            Authorize.Input(null, "a", null, plain, null, revocationStaleness = pol, risk = AuthorizeTestKit.calmRisk)
        }.message)
        Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), null, revocationStaleness = pol, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk)
        assertNull(Authorize.AuthorizeOptions(plain, null, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).revocationStaleness)
    }

    @Test fun aStoreThatThrowsOnThePinReadFailsClosed() {
        val flaky = object : Authorize.StateStore, Authorize.LastStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = Authorize.ClaimResult(true)
            override fun last(key: String): Long? = throw IllegalStateException("down")
        }
        val r = run(flaky, 5)
        assertFalse(r.allow)
        assertEquals("freshness: revocation epoch pin unavailable (fail closed)", r.reason)
    }

    @Test fun aFailedFreshnessAnchorIsNeverOverwrittenByAPassingEpoch() {
        // enforce.freshness and the revocation-epoch check share the `freshness` check: the epoch passing must not hide a stale anchor
        val stale = run(Authorize.MemoryStateStore(), 5, gate = Authorize.FreshnessGate(1000.0))
        assertFalse(stale.allow)
        assertEquals("fail", stale.checks["freshness"])
        assertTrue(stale.reasons.toString(), stale.reasons.any { it.startsWith("freshness: freshness anchor is stale") })
        val store = Authorize.MemoryStateStore()
        assertNull(store.last(pinKey))
        assertFalse(run(store, 5, gate = Authorize.FreshnessGate(1000.0)).allow)
        assertNull("a denied action never raises the pin", store.last(pinKey))
        // both passing: one passing check
        val ok = run(Authorize.MemoryStateStore(), 5, gate = Authorize.FreshnessGate(1e15))
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["freshness"])
    }
}
