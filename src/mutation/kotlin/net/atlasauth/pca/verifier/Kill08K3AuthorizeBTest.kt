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

/**
 * Authorize.kt k3 survivors, part B: the revocation-staleness step (epoch state kinds, the automatic rollback pin and its containment,
 * the pin write-back, the accepted-epoch callback). The guardian-signed epoch is built as in Kill14BEpochPinTest; the core verdict is
 * held neutral so the signed fixture can be edited.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K3AuthorizeBTest {
    @After fun reset() { Authorize.coreHook = null }

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

    private fun neutral() {
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
    }

    /** A store with the pin and claim seams overridable. */
    private class Seam(val inner: Authorize.MemoryStateStore = Authorize.MemoryStateStore()) : Authorize.StateStore, Authorize.LastStore {
        var onLast: ((String) -> Long?)? = null
        var onClaim: ((String, Long) -> Authorize.ClaimResult?)? = null
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? = onClaim?.invoke(key, counter) ?: inner.claim(key, counter)
        override fun last(key: String): Long? = if (onLast != null) onLast!!.invoke(key) else inner.last(key)
    }

    private fun run(
        store: Authorize.StateStore, epoch: Long, hostLast: Long? = null, state: Map<String, Any?>? = null,
        onAccepted: ((Map<String, Any?>, Map<String, Any?>) -> Unit)? = null,
    ): Authorize.Result {
        neutral()
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        p["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to "", "epoch" to IntentJs.ofLong(epoch), "accumulator_witness" to "")
        val st: Map<String, Any?> = state ?: linkedMapOf<String, Any?>("kind" to "epoch", "epoch" to signedEpoch(p["grant_ref"] as String, AuthorizeTestKit.NOW - 1_000, epoch)).also {
            if (hostLast != null) it["last_accepted_epoch"] = hostLast
        }
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, proofFor = { _, _ -> linkedMapOf("size" to 0L) }, onEpochAccepted = onAccepted)
        return Authorize.authorize(
            p,
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) },
                stateStore = store, isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP,
                context = { mapOf("revocation_state" to st, "reversibility_class" to "reversible") }, revocationStaleness = pol,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(AuthorizeTestKit.op(c)), risk = AuthorizeTestKit.calmRisk,
            ),
        )
    }

    @Test fun aRootStateIsJudgedAsARootNotAnEpoch() {
        val root = linkedMapOf<String, Any?>("kind" to "root", "root" to IntentRevocation.revsetRoot(emptyList()), "issued_at" to IntentJs.ofLong(AuthorizeTestKit.NOW - 1_000))
        val r = run(Authorize.MemoryStateStore(), 5, state = root)
        assertFalse(r.allow)
        assertNull(r.checks["authorize"])
        eq("fail", r.checks["freshness"])
        assertTrue(r.reasons.toString(), r.reasons.contains("freshness: unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)"))
    }

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)

    @Test fun theStoredPinFloorsTheHostValue() {
        fun why(pin: Long?, epoch: Long, host: Long?): String? {
            val store = Authorize.MemoryStateStore()
            if (pin != null) store.claim(pinKey, pin)
            return run(store, epoch, hostLast = host).reasons.firstOrNull { it.startsWith("freshness:") }
        }
        eq("freshness: revocation epoch 6 is older than the last accepted 7 (rollback)", why(7, 6, null))
        eq("freshness: revocation epoch 6 is older than the last accepted 7 (rollback)", why(7, 6, 1))
        eq("freshness: revocation epoch 8 is older than the last accepted 9 (rollback)", why(7, 8, 9))
        eq("freshness: revocation epoch 2 is older than the last accepted 3 (rollback)", why(null, 2, 3))
        assertNull(why(7, 7, 7))
        assertNull(why(null, 4, null))
    }

    @Test fun theEpochPinCallbacksAreContained() {
        val oom = OutOfMemoryError()
        // reading the pin
        val readFatal = Seam().also { it.onLast = { _ -> throw oom } }
        assertThrows(OutOfMemoryError::class.java) { run(readFatal, 5) }
        val readDown = Seam().also { it.onLast = { _ -> throw IllegalStateException("down") } }
        val rd = run(readDown, 5)
        assertFalse(rd.allow)
        assertTrue(rd.reasons.toString(), rd.reasons.contains("freshness: revocation epoch pin unavailable (fail closed)"))
        // raising the pin after an allow: the value, then the containment
        val ok = Authorize.MemoryStateStore()
        val a = run(ok, 5)
        assertTrue(a.reasons.toString(), a.allow)
        eq(5L, ok.last(pinKey))
        val claimFatal = Seam().also { s -> s.onClaim = { k, n -> if (k.endsWith(":epoch")) throw oom else s.inner.claim(k, n) } }
        assertThrows(OutOfMemoryError::class.java) { run(claimFatal, 5) }
        val claimDown = Seam().also { s -> s.onClaim = { k, n -> if (k.endsWith(":epoch")) throw IllegalStateException("down") else s.inner.claim(k, n) } }
        val cd = run(claimDown, 5)
        assertTrue(cd.reasons.toString(), cd.allow)
        assertNull(claimDown.inner.last(pinKey))
        // the accepted-epoch callback: called with the signed epoch and the proof; a fatal error escapes, an ordinary one is the host's
        var seen: Pair<Map<String, Any?>, Map<String, Any?>>? = null
        val cb = run(Authorize.MemoryStateStore(), 5, onAccepted = { e, pp -> seen = Pair(e, pp) })
        assertTrue(cb.reasons.toString(), cb.allow)
        eq(5L, Json.asLong(seen!!.first["epoch"]))
        eq(pcactn(c)["grant_ref"], seen!!.second["grant_ref"])
        assertThrows(OutOfMemoryError::class.java) { run(Authorize.MemoryStateStore(), 5, onAccepted = { _, _ -> throw oom }) }
        val ex = run(Authorize.MemoryStateStore(), 5, onAccepted = { _, _ -> throw IllegalStateException("x") })
        assertTrue(ex.reasons.toString(), ex.allow)
    }
}
