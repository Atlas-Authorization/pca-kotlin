package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Kotlin 0.5 mutation kills for [Beacons] (group k5), ported from packages/pca/src/mutation-kill-beacons.test.ts: every guard of verify is
 * reached by a beacon whose signature is VALID over the tampered body (so each guard fires on its own reason), with BOTH Verdict members
 * asserted (the older tests read the reason only), the signed message layout including `alg` / `pq_pk` of a post-quantum suite, the
 * pinned PQ key lookup, the default arguments of verify, and the containment of a throwing beacon.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K5BeaconsTest {
    private val ed = Keys.edGenerate()
    private val t0 = 1_000_000_020_000L
    private fun num(v: Long) = IntentJs.ofLong(v)
    private val domain = IntentJs.utf8("atlas-pca/beacon/v2\u0000")

    /** The beacon body without `sig`; `over` replaces / adds members (a null value removes the member). */
    private fun body(over: Map<String, Any?> = emptyMap(), issuer: String = ed.id()): LinkedHashMap<String, Any?> {
        val b = linkedMapOf<String, Any?>(
            "v" to num(2), "instance" to "ins_1", "scope" to "g1", "epoch" to num(Math.floorDiv(t0, Beacons.EPOCH_MS)), "seq" to num(1),
            "issued_at" to num(t0), "not_after" to num(t0 + 60_000), "issuer" to issuer,
        )
        for ((k, v) in over) if (v == null) b.remove(k) else b[k] = v
        return b
    }

    /** A beacon with an arbitrary body and a valid Ed25519 signature over `domain || canon(body)` (the body as given, no alg / pq_pk added). */
    private fun signed(over: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val b = body(over)
        return LinkedHashMap(b).also { it["sig"] = Pca.b64(ed.sign(Pca.concat(domain, IntentJs.canonBytes(b)))) }
    }

    private fun v(b: Any?, now: Long = t0, scope: String? = "g1", instance: String? = "ins_1", issuers: Any? = listOf(ed.id())) =
        Beacons.verify(b, issuers, now, instance, scope, null)

    private fun refused(reason: String, got: Beacons.Verdict) {
        assertFalse(reason, got.ok)
        assertEquals(reason, got.reason)
    }

    private fun accepted(got: Beacons.Verdict) {
        assertTrue(got.reason, got.ok)
        assertNull(got.reason)
    }

    @Test fun aWellFormedBeaconIsAcceptedWithBothMembers() {
        accepted(v(signed()))
        // seq 0 is allowed
        accepted(v(signed(mapOf("seq" to num(0)))))
        // the default arguments: no scope (not checked) and no pins
        accepted(Beacons.verify(signed(), listOf(ed.id()), t0, "ins_1"))
        accepted(Beacons.verify(signed(mapOf("scope" to "other")), listOf(ed.id()), t0, "ins_1"))
        refused("scope not covered", Beacons.verify(signed(), listOf(ed.id()), t0, "ins_1", "g2"))
        accepted(Beacons.verify(signed(), listOf(ed.id()), t0, "ins_1", "g1"))
        accepted(Beacons.verify(signed(mapOf("scope" to Beacons.GLOBAL_SCOPE)), listOf(ed.id()), t0, "ins_1", "anything"))
    }

    @Test fun malformedBeaconIsRefusedWithItsReason() {
        refused("malformed beacon", v(null))
        refused("malformed beacon", v("x"))
        refused("malformed beacon", v(listOf<Any?>()))
        refused("malformed beacon", v(signed(mapOf("v" to num(1)))))
        refused("malformed beacon", v(signed(mapOf("v" to num(3)))))
        refused("malformed beacon", v(signed(mapOf("v" to null))))
        refused("malformed beacon", v(signed(mapOf("alg" to "rot13"))))
        refused("malformed beacon", v(signed(mapOf("alg" to 5L))))
        refused("wrong instance", v(signed(), instance = "other"))
        refused("wrong instance", v(signed(), instance = null))
        refused("issuer not pinned", v(signed(), issuers = listOf("someone-else")))
        refused("issuer not pinned", v(signed(), issuers = emptyList<String>()))
        refused("issuer not pinned", v(signed(), issuers = ed.id()))
        refused("issuer not pinned", v(signed(), issuers = null))
        refused("issuer not pinned", v(signed(), issuers = mapOf(ed.id() to true)))
    }

    @Test fun aNonStringPinnedIssuerFailsTheSignatureNotTheCast() {
        val b = signed(mapOf("issuer" to Json.Num("5")))
        refused("bad signature", v(b, issuers = listOf<Any?>(Json.Num("5"))))
    }

    @Test fun theSignatureCoversTheDomainPrefixAndEveryBodyMember() {
        val b = body()
        val bare = LinkedHashMap(b).also { it["sig"] = Pca.b64(ed.sign(IntentJs.canonBytes(b))) }
        refused("bad signature", v(bare))
        val forged = signed().toMutableMap().also { it["seq"] = num(2) }
        refused("bad signature", v(forged))
        val noSig = signed().toMutableMap().also { it.remove("sig") }
        refused("bad signature", v(noSig))
        refused("bad signature", v(signed().toMutableMap().also { it["sig"] = 5L }))
    }

    @Test fun eachWindowFieldMustBeAnInteger() {
        for (over in listOf<Map<String, Any?>>(
            mapOf("epoch" to "5"), mapOf("seq" to "1"), mapOf("issued_at" to "5"), mapOf("not_after" to "5"), mapOf("seq" to num(-1)),
            mapOf("epoch" to Json.Num("1.5")), mapOf("seq" to Json.Num("1.5")), mapOf("issued_at" to Json.Num("1.5")), mapOf("not_after" to Json.Num("1.5")),
            mapOf("epoch" to true), mapOf("seq" to listOf<Any?>()),
        )) {
            val got = v(signed(over))
            assertFalse(over.toString(), got.ok)
            assertEquals(over.toString(), "malformed window", got.reason)
        }
        // an ABSENT member cannot be signed over (the TypeScript canonicalizer refuses undefined): the verifier's message carries null, so the signature fails; refused either way
        for (k in listOf("epoch", "seq", "issued_at", "not_after")) assertFalse(k, v(signed(mapOf(k to null))).ok)
    }

    @Test fun validityIsStrictlyPositiveAndBoundedInclusively() {
        refused("validity exceeds the hard maximum", v(signed(mapOf("not_after" to num(t0)))))
        refused("validity exceeds the hard maximum", v(signed(mapOf("not_after" to num(t0 - 1)))))
        accepted(v(signed(mapOf("not_after" to num(t0 + 1)))))
        accepted(v(signed(mapOf("not_after" to num(t0 + Beacons.MAX_VALIDITY_MS)))))
        refused("validity exceeds the hard maximum", v(signed(mapOf("not_after" to num(t0 + Beacons.MAX_VALIDITY_MS + 1)))))
    }

    @Test fun theEpochIsFloorOfIssuedAtOverTheEpochLength() {
        val e = Math.floorDiv(t0, Beacons.EPOCH_MS)
        accepted(v(signed(mapOf("epoch" to num(e)))))
        refused("epoch does not match issued_at", v(signed(mapOf("epoch" to num(e + 1)))))
        refused("epoch does not match issued_at", v(signed(mapOf("epoch" to num(e - 1)))))
        // an issued_at that is not a multiple of the epoch: the floor, not the round
        val odd = t0 + 59_999
        accepted(v(signed(mapOf("issued_at" to num(odd), "not_after" to num(odd + 60_000), "epoch" to num(e))), odd))
        refused("epoch does not match issued_at", v(signed(mapOf("issued_at" to num(odd), "not_after" to num(odd + 60_000), "epoch" to num(e + 1))), odd))
    }

    @Test fun theSkewAndTheExpiryAreExact() {
        accepted(v(signed(), t0 - Beacons.CLOCK_SKEW_MS))
        refused("not yet valid", v(signed(), t0 - Beacons.CLOCK_SKEW_MS - 1))
        accepted(v(signed(), t0 + 60_000))
        refused("expired", v(signed(), t0 + 60_001))
        accepted(v(signed(mapOf("scope" to "g1")), t0, "g1"))
        refused("scope not covered", v(signed(mapOf("scope" to "g1")), t0, "g2"))
    }

    @Test fun anUncanonicalBodyIsRefusedAsMalformedNotThrown() {
        // a Double scope cannot be canonicalised: the message builder throws, the verdict is a refusal
        refused("malformed beacon", v(signed().toMutableMap().also { it["scope"] = 1.5 }))
    }

    private class Boom : Error("boom")

    @Test fun anErrorThatIsNotContainedPropagates() {
        val m = object : HashMap<String, Any?>() {
            override fun get(key: String): Any? = throw Boom()
        }
        try {
            Beacons.verify(m, listOf(ed.id()), t0, "ins_1")
            fail("a non-contained Error must propagate")
        } catch (e: Boom) {
            assertEquals("boom", e.message)
        }
    }

    // ---- post-quantum suites: alg and pq_pk are signed and the pq_pk is pinned ----

    private fun pqBeacon(alg: String, sk: Keys.SuiteKey, issuer: String, over: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val b = body(over, issuer)
        b["alg"] = alg
        b["pq_pk"] = sk.pqPk()
        val (sig, pqSig) = sk.sign(Pca.concat(domain, IntentJs.canonBytes(b)))
        return LinkedHashMap(b).also { it["sig"] = sig; if (pqSig != null) it["pq_sig"] = pqSig }
    }

    private fun flip(s: String): String {
        val raw = Keys.unb64u(s)
        raw[0] = (raw[0].toInt() xor 1).toByte()
        return Keys.b64u(raw)
    }

    @Test fun aPurePostQuantumBeaconNeedsItsPinnedKey() {
        val pq = Keys.pqGenerate(Pq.Prim.ML_DSA_65)
        val sk = Keys.suite("ml-dsa-65", null, pq)
        val b = pqBeacon("ml-dsa-65", sk, "pq-issuer")
        val pins = mapOf<String, Any?>("pq-issuer" to pq.pkB64u())
        accepted(Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", "g1", pins))
        accepted(Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", null, pins))
        // no pin for the issuer, or another key pinned: the artifact's own pq_pk is never enough
        refused("bad signature", Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", "g1", null))
        refused("bad signature", Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", "g1", emptyMap()))
        val other = Keys.pqGenerate(Pq.Prim.ML_DSA_65)
        refused("bad signature", Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", "g1", mapOf<String, Any?>("pq-issuer" to other.pkB64u())))
        refused("bad signature", Beacons.verify(b, listOf("pq-issuer"), t0, "ins_1", "g1", mapOf<String, Any?>("someone" to pq.pkB64u())))
        // a signature over the body WITHOUT alg and pq_pk does not verify
        val plain = body(issuer = "pq-issuer")
        val unbound = LinkedHashMap(plain).also { it["alg"] = "ml-dsa-65"; it["pq_pk"] = pq.pkB64u(); it["sig"] = sk.sign(Pca.concat(domain, IntentJs.canonBytes(plain))).first }
        refused("bad signature", Beacons.verify(unbound, listOf("pq-issuer"), t0, "ins_1", "g1", pins))
        // the signed pq_pk is the one verified: a swapped pq_pk (re-pinned to match) breaks the signature
        val swapped = LinkedHashMap(b).also { it["pq_pk"] = other.pkB64u() }
        refused("bad signature", Beacons.verify(swapped, listOf("pq-issuer"), t0, "ins_1", "g1", mapOf<String, Any?>("pq-issuer" to other.pkB64u())))
    }

    @Test fun aHybridBeaconNeedsBothHalvesAndTheIssuersPin() {
        val pq = Keys.pqGenerate(Pq.Prim.ML_DSA_65)
        val sk = Keys.suite("hybrid-ed25519-ml-dsa-65", ed, pq)
        val b = pqBeacon("hybrid-ed25519-ml-dsa-65", sk, ed.id())
        val pins = Keys.pqPin(sk)
        accepted(Beacons.verify(b, listOf(ed.id()), t0, "ins_1", "g1", pins))
        refused("bad signature", Beacons.verify(b, listOf(ed.id()), t0, "ins_1", "g1", null))
        refused("bad signature", Beacons.verify(LinkedHashMap(b).also { it["pq_sig"] = flip(b["pq_sig"] as String) }, listOf(ed.id()), t0, "ins_1", "g1", pins))
        refused("bad signature", Beacons.verify(LinkedHashMap(b).also { it.remove("pq_sig") }, listOf(ed.id()), t0, "ins_1", "g1", pins))
        refused("bad signature", Beacons.verify(LinkedHashMap(b).also { it["sig"] = flip(b["sig"] as String) }, listOf(ed.id()), t0, "ins_1", "g1", pins))
        val other = Keys.pqGenerate(Pq.Prim.ML_DSA_65)
        refused("bad signature", Beacons.verify(b, listOf(ed.id()), t0, "ins_1", "g1", mapOf<String, Any?>(ed.id() to other.pkB64u())))
    }

    @Test fun anExplicitEd25519AlgIsNotPartOfTheSignedBody() {
        val b = signed().toMutableMap().also { it["alg"] = "ed25519" }
        accepted(v(b))
        // a signature that DID cover alg is wrong for ed25519
        val withAlg = body(mapOf("alg" to "ed25519"))
        val s = LinkedHashMap(withAlg).also { it["sig"] = Pca.b64(ed.sign(Pca.concat(domain, IntentJs.canonBytes(withAlg)))) }
        refused("bad signature", v(s))
    }

    @Test fun suppliedKeepsItsPinsAndTheBeaconRefBindsTheWholeBeacon() {
        val pins = mapOf<String, Any?>("a" to "b")
        val b = signed()
        val s = Beacons.Supplied(b, listOf("i"), "ins_1", pins)
        assertSame(pins, s.pqPins)
        assertSame(b, s.beacon)
        assertEquals(listOf("i"), s.issuers)
        assertEquals("ins_1", s.instance)
        assertNull(Beacons.Supplied(b, listOf("i"), "ins_1").pqPins)
        assertEquals(Pca.hashCanonical(b), Beacons.beaconRef(b))
        assertFalse(Beacons.beaconRef(b) == Beacons.beaconRef(signed(mapOf("seq" to num(2)))))
    }
}
