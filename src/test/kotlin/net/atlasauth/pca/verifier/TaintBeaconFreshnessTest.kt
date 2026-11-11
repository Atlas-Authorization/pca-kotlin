package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The information-flow taint gate, the liveness beacons and the freshness-anchor gate of `authorize` (0.5 F3). */
@Suppress("UNCHECKED_CAST")
class TaintBeaconFreshnessTest {
    @After fun reset() { Authorize.coreHook = null }

    // ---- taint ----

    private fun prov(refs: Any?, include: Boolean = true): Map<String, Any?> {
        val p = linkedMapOf<String, Any?>("causal_hash" to "", "taint_level" to 0L)
        if (include) p["trusted_refs"] = refs
        return p
    }

    private val registry = Taint.InMemoryRegistry().also {
        it.recordTrusted("t")
        it.recordFirstParty("f")
        it.recordTool("tool1", "tool1")
        it.recordWeb("w")
        it.record("", mapOf("kind" to "trusted"))
        it.record("x", mapOf("kind" to "bogus"))
    }
    private val graph = Taint.ResourceGraph { ref -> if (ref == "graph-node") true else null }
    private fun taintOf(refs: Any?, g: Taint.ResourceGraph? = graph) = Taint.computeTaint(prov(refs), registry, g).taint

    @Test fun theLatticeRanksTheLineageByItsWorstRef() {
        assertEquals(0.0, taintOf(listOf("t")), 0.0)
        assertEquals(0.25, taintOf(listOf("t", "f")), 0.0)
        assertEquals(0.5, taintOf(listOf("f", "tool1")), 0.0)
        assertEquals(0.75, taintOf(listOf("tool1", "w", "t")), 0.0)
        assertEquals(1.0, taintOf(listOf("t", "unknown")), 0.0) // an unverifiable ref is the agent label
        assertEquals(0.25, taintOf(listOf("graph-node")), 0.0) // the server's own resource graph vouches first party
        assertEquals(1.0, taintOf(listOf("x")), 0.0) // an unknown level is not a vouching
        assertEquals(4, registry.size) // an empty digest and an unknown level are never recorded
        assertTrue(Taint.computeTaint(prov(listOf("t")), registry, graph).valid)
        // the empty lineage and an absent trusted_refs are the worst case (no verifiable trusted input), still valid
        for (p in listOf(prov(emptyList<String>()), prov(null, include = false))) {
            val r = Taint.computeTaint(p, registry, graph)
            assertTrue(r.valid)
            assertEquals(1.0, r.taint, 0.0)
        }
        // a throwing graph is the worst case for that ref
        assertEquals(1.0, taintOf(listOf("a"), Taint.ResourceGraph { throw IllegalStateException("x") }), 0.0)
    }

    @Test fun malformedProvenanceFailsClosed() {
        val noReg = Taint.computeTaint(prov(listOf("t")), null)
        assertFalse(noReg.valid)
        assertEquals("taint: no trusted-input registry", noReg.reason)
        for (bad in listOf(null, "x", emptyList<Any?>())) assertEquals("taint: provenance is absent or malformed", Taint.computeTaint(bad, registry).reason)
        assertEquals("taint: trusted_refs must be an array", Taint.computeTaint(prov("t"), registry).reason)
        assertEquals("taint: trusted_refs must be an array", Taint.computeTaint(prov(null), registry).reason)
        for (refs in listOf(listOf("t", ""), listOf("t", null), listOf("t", 5L)))
            assertEquals("taint: trusted_refs must be non-empty strings", Taint.computeTaint(prov(refs), registry).reason)
        val thrown = Taint.computeTaint(prov(listOf("t")), Taint.Registry { throw IllegalStateException("boom") })
        assertFalse(thrown.valid)
        assertEquals(1.0, thrown.taint, 0.0)
        assertEquals("taint: evaluation error (fail closed): boom", thrown.reason)
    }

    @Test fun theGateBoundsTheTaint() {
        fun gate(refs: Any?, max: Double?, reg: Taint.Registry? = registry) = Taint.gate(prov(refs), Taint.Gate(reg, max, graph))
        assertNull(gate(listOf("t"), 0.0))
        assertNull(gate(listOf("f"), 0.25))
        assertEquals("information-flow taint 0.25 exceeds policy max 0.2", gate(listOf("f"), 0.2))
        assertNull(gate(listOf("w"), 0.8))
        assertEquals("information-flow taint 1 exceeds policy max 0.99", gate(listOf("unknown"), 0.99))
        assertNull(gate(listOf("unknown"), 1.0))
        assertEquals("taint: trusted_refs must be an array", gate("t", 1.0))
        // the invalid lineage is reported before a misconfigured bound; a negative, NaN or missing bound is misconfigured
        assertEquals("taint: no trusted-input registry", gate(listOf("t"), -1.0, null))
        val mis = "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"
        assertEquals(mis, gate(listOf("t"), -0.5))
        assertEquals(mis, gate(listOf("t"), Double.NaN))
        assertEquals(mis, gate(listOf("t"), null))
        assertEquals(mis, gate(listOf("t"), Double.POSITIVE_INFINITY))
    }

    // ---- shared authorize plumbing: the signed fixture with the core verdict held neutral, the PCActn's members tampered ----

    private val c = case("envelope-predicate-within")

    private fun neutral() {
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
    }

    private fun attempt(
        member: Pair<String, Any?>?, store: Authorize.StateStore = Authorize.MemoryStateStore(), freshness: Authorize.FreshnessGate? = null,
        taint: Taint.Gate? = null, beacon: ((String, Map<String, Any?>) -> Beacons.Supplied?)? = null,
    ): Authorize.Result {
        neutral()
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        if (member != null) p[member.first] = member.second
        val b = input(c, stateStore = store)
        return Authorize.authorize(
            p,
            Authorize.Input(
                operation = b.operation, audience = b.audience, resolveGrant = b.resolveGrant, stateStore = store, isRevoked = b.isRevoked, now = b.now,
                plan = b.plan, provenanceOptions = b.provenanceOptions, provenance = b.provenance, risk = b.risk,
                enforceFreshness = freshness, enforceTaint = taint, beacon = beacon,
            ),
        )
    }

    @Test fun theAuthorizeTaintGateRecordsTaintGate() {
        val gate = Taint.Gate(registry, 0.25)
        val ok = attempt("provenance" to prov(listOf("t")), taint = gate)
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["taint_gate"])
        val no = attempt("provenance" to prov(listOf("t", "unknown")), taint = gate)
        assertFalse(no.allow)
        assertEquals("fail", no.checks["taint_gate"])
        assertTrue(no.reasons.toString(), no.reasons.contains("taint_gate: information-flow taint 1 exceeds policy max 0.25"))
        assertEquals("not-enforced", attempt("provenance" to prov(listOf("unknown"))).checks["taint_gate"])
    }

    // ---- the freshness anchor ----

    private val epochNow = Math.floorDiv(NOW, 60_000L)

    private fun anchor(epoch: Long, ref: String = "ref") = "freshness" to linkedMapOf<String, Any?>("beacon_ref" to ref, "epoch" to IntentJs.ofLong(epoch))

    @Test fun theFreshnessAnchorGate() {
        val g = Authorize.FreshnessGate(200_000.0)
        val ok = attempt(anchor(epochNow - 1), freshness = g)
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["freshness_anchor"])
        fun why(m: Pair<String, Any?>?, gate: Authorize.FreshnessGate = g): String? {
            val r = attempt(m, freshness = gate)
            assertFalse(r.allow)
            assertEquals("fail", r.checks["freshness_anchor"])
            return r.reasons.firstOrNull { it.startsWith("freshness_anchor: ") }
        }
        val missing = "freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
        assertEquals(missing, why(null))
        assertEquals(missing, why(anchor(epochNow - 1, ref = "")))
        assertEquals(missing, why(anchor(0)))
        assertEquals(missing, why(anchor(-5)))
        assertEquals("freshness_anchor: freshness anchor is in the future", why(anchor(epochNow + 10)))
        assertEquals("freshness_anchor: freshness anchor is stale (older than 1000 ms)", why(anchor(epochNow - 1), Authorize.FreshnessGate(1000.0)))
        // a clock skew tolerates a future anchor; a negative or non-finite skew reads as none
        assertTrue(attempt(anchor(epochNow + 10), freshness = Authorize.FreshnessGate(200_000.0, clockSkewMs = 10_000_000.0)).allow)
        assertEquals("freshness_anchor: freshness anchor is in the future", why(anchor(epochNow + 10), Authorize.FreshnessGate(200_000.0, clockSkewMs = -5.0)))
        // the gate's own clock and epoch length
        assertTrue(attempt(anchor(10), freshness = Authorize.FreshnessGate(5_000.0, epochMs = 1000.0, now = 10_500)).allow)
        val mis = "freshness_anchor: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
        assertEquals(mis, why(anchor(epochNow - 1), Authorize.FreshnessGate(null)))
        assertEquals(mis, why(anchor(epochNow - 1), Authorize.FreshnessGate(-1.0)))
        assertEquals(mis, why(anchor(epochNow - 1), Authorize.FreshnessGate(1000.0, epochMs = 0.0)))
        assertEquals(mis, why(anchor(epochNow - 1), Authorize.FreshnessGate(Double.NaN)))
        assertNull(attempt(null).checks["freshness_anchor"])
    }

    // ---- the liveness beacon ----

    private val issuer = Keys.edGenerate()
    private val issued = NOW - 120_000L

    private fun beacon(instance: String, scope: String, seq: Long, issuedAt: Long, notAfter: Long, epoch: Long = Math.floorDiv(issuedAt, Beacons.EPOCH_MS), key: Keys.EdKey = issuer): Map<String, Any?> {
        val b = linkedMapOf<String, Any?>(
            "v" to IntentJs.ofLong(2), "instance" to instance, "scope" to scope, "epoch" to IntentJs.ofLong(epoch), "seq" to IntentJs.ofLong(seq),
            "issued_at" to IntentJs.ofLong(issuedAt), "not_after" to IntentJs.ofLong(notAfter), "issuer" to key.id(),
        )
        val msg = Pca.concat(IntentJs.utf8("atlas-pca/beacon/v2\u0000"), IntentJs.canonBytes(b))
        return LinkedHashMap(b).also { it["sig"] = Pca.b64(key.sign(msg)) }
    }

    private fun good() = beacon("inst", "*", 5, issued, issued + 300_000L)
    private fun verify(b: Any?, now: Long, scope: String? = null) = Beacons.verify(b, listOf(issuer.id()), now, "inst", scope, null).reason

    @Test fun aBeaconVerifiesOnlyWhereItIsBoundAndFresh() {
        assertNull(verify(good(), NOW, "g1"))
        assertEquals("malformed beacon", verify(null, NOW))
        assertEquals("malformed beacon", verify("x", NOW))
        assertEquals("malformed beacon", verify(good().toMutableMap().also { it["v"] = IntentJs.ofLong(3) }, NOW))
        assertEquals("malformed beacon", verify(good().toMutableMap().also { it["alg"] = "nope" }, NOW))
        assertEquals("wrong instance", Beacons.verify(good(), listOf(issuer.id()), NOW, "other", null, null).reason)
        assertEquals("issuer not pinned", Beacons.verify(good(), listOf("someone-else"), NOW, "inst", null, null).reason)
        val forged = good().toMutableMap().also { it["seq"] = IntentJs.ofLong(6) }
        assertEquals("bad signature", verify(forged, NOW))
        // the window: valid from issued - 30 s, until not_after inclusive
        assertNull(verify(good(), issued - Beacons.CLOCK_SKEW_MS))
        assertEquals("not yet valid", verify(good(), issued - Beacons.CLOCK_SKEW_MS - 1))
        assertNull(verify(good(), issued + 300_000L))
        assertEquals("expired", verify(good(), issued + 300_001L))
        // the hard maximum validity: one hour exactly passes, one millisecond more is refused
        assertNull(verify(beacon("inst", "*", 5, issued, issued + Beacons.MAX_VALIDITY_MS), issued))
        assertEquals("validity exceeds the hard maximum", verify(beacon("inst", "*", 5, issued, issued + Beacons.MAX_VALIDITY_MS + 1), issued))
        assertEquals("validity exceeds the hard maximum", verify(beacon("inst", "*", 5, issued, issued), issued))
        // the epoch must be floor(issued_at / 60000); a negative seq is a malformed window
        assertEquals("epoch does not match issued_at", verify(beacon("inst", "*", 5, issued, issued + 300_000L, epoch = Math.floorDiv(issued, Beacons.EPOCH_MS) + 1), NOW))
        assertEquals("malformed window", verify(beacon("inst", "*", -1, issued, issued + 1000), NOW))
        // scope: the global scope or the grant's own
        assertNull(verify(beacon("inst", "g1", 5, issued, issued + 300_000L), NOW, "g1"))
        assertEquals("scope not covered", verify(beacon("inst", "g1", 5, issued, issued + 300_000L), NOW, "g2"))
        assertNull(verify(beacon("inst", "g1", 5, issued, issued + 300_000L), NOW, null)) // no scope given: not checked
        // the reference is a function of the whole beacon
        assertEquals(Beacons.beaconRef(good()), Beacons.beaconRef(good()))
        assertNotEquals(Beacons.beaconRef(good()), Beacons.beaconRef(forged))
        assertEquals(43, Beacons.beaconRef(good()).length)
        // the decision combinator
        assertEquals("not-enforced", Beacons.decision(false, true, false, true))
        assertEquals("rejected", Beacons.decision(true, false, false, true))
        assertEquals("replayed", Beacons.decision(true, true, true, true))
        assertEquals("unbound", Beacons.decision(true, true, false, false))
        assertEquals("pass", Beacons.decision(true, true, false, true))
    }

    private fun withBeacon(store: Authorize.StateStore, b: Map<String, Any?>, ref: String? = null): Authorize.Result =
        attempt(anchor(1, ref ?: Beacons.beaconRef(b)), store, beacon = { _, _ -> Beacons.Supplied(b, listOf(issuer.id()), "inst") })

    @Test fun authorizeChecksTheBeaconAndKeepsItsSequencePin() {
        val pin = "${AuthorizeTestKit.grant(c)["id"]}:beacon"
        val store = Authorize.MemoryStateStore()
        val ok = withBeacon(store, good())
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["beacon"])
        assertEquals(5L, store.last(pin)) // an allow raises the pin
        // a replayed older beacon: below the stored pin
        val seeded = Authorize.MemoryStateStore()
        seeded.claim(pin, 9)
        val old = withBeacon(seeded, good())
        assertFalse(old.allow)
        assertTrue(old.reasons.toString(), old.reasons.contains("beacon: beacon seq 5 is older than the last accepted 9 (replay)"))
        assertEquals(9L, seeded.last(pin))
        // an equal seq is not a replay
        val equal = Authorize.MemoryStateStore()
        equal.claim(pin, 5)
        assertTrue(withBeacon(equal, good()).allow)
        // a PCActn that commits another beacon
        val unbound = withBeacon(Authorize.MemoryStateStore(), good(), ref = "not-the-ref")
        assertFalse(unbound.allow)
        assertTrue(unbound.reasons.toString(), unbound.reasons.contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon"))
        // a beacon that does not verify
        val expired = withBeacon(Authorize.MemoryStateStore(), beacon("inst", "*", 5, issued - 3_000_000L, issued - 3_000_000L + 60_000L))
        assertFalse(expired.allow)
        assertTrue(expired.reasons.toString(), expired.reasons.contains("beacon: expired"))
        // none supplied: not enforced
        assertEquals("not-enforced", attempt(null).checks["beacon"])
    }
}
