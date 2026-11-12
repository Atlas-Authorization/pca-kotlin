package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Authorize.kt k3 survivors (targeted run 43105942049), part A: the value classes and their accessors, the in-memory budget CAS, the
 * pq pins, the principal resolver, the freshness-anchor gate boundaries, the liveness beacon, the risk / budget / threshold / adaptive
 * step (every reason string), the forbid / template / contract / passport pre-guard refusals and the host-callback containment sites.
 * The signed fixture is tampered only under a neutral [Authorize.coreHook]; every pinned reason and boundary is the TypeScript wording.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K3AuthorizeATest {
    @After fun reset() { Authorize.coreHook = null }

    private val c = case("envelope-predicate-within")
    private val gid: String get() = grant(c)["id"] as String
    private val holder: String get() = ((pcactn(c)["cap_chain"] as List<Any?>).last() as Map<String, Any?>)["holder"] as String
    private val budgetKey: String get() = "$gid:$holder"

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)

    private fun neutral() {
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
    }

    private fun inject(check: String, reason: String) {
        Authorize.coreHook = { core ->
            core.checks[check] = false
            core.reasons.add("$check: $reason")
            core.allow = false
        }
    }

    private fun p0(): MutableMap<String, Any?> = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
    private fun g0(): MutableMap<String, Any?> = IntentJs.normalize(grant(c)) as MutableMap<String, Any?>
    private fun envOf(g: Map<String, Any?>): MutableMap<String, Any?> =
        (g["caveats"] as List<Any?>).first { it is Map<*, *> && it["type"] == "envelope" } as MutableMap<String, Any?>
    private fun polOf(g: Map<String, Any?>): MutableMap<String, Any?> = envOf(g)["risk_policy"] as MutableMap<String, Any?>
    private fun weights(g: Map<String, Any?>): MutableMap<String, Any?> = polOf(g)["weights"] as MutableMap<String, Any?>

    private fun ctxOf(vararg kv: Pair<String, Any?>): ((Map<String, Any?>) -> Map<String, Any?>?) {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return { _ -> m }
    }

    /** A store with every seam overridable; each defaults to the in-memory behaviour. */
    private class Wrap(val inner: Authorize.MemoryStateStore = Authorize.MemoryStateStore()) : Authorize.StateStore, Authorize.LastStore, Authorize.BudgetStore {
        var onClaim: ((String, Long) -> Authorize.ClaimResult?)? = null
        var onLast: ((String) -> Long?)? = null
        var onCas: ((String, Risk.Budget?, Risk.Budget) -> Boolean)? = null
        val cas = ArrayList<Triple<String, Risk.Budget?, Risk.Budget>>()
        override val scope: String get() = Authorize.SCOPE_PROCESS
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? = onClaim?.invoke(key, counter) ?: inner.claim(key, counter)
        override fun last(key: String): Long? = if (onLast != null) onLast!!.invoke(key) else inner.last(key)
        override fun budget(key: String): Risk.Budget? = inner.budget(key)
        override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean {
            cas.add(Triple(key, old, new))
            return if (onCas != null) onCas!!.invoke(key, old, new) else inner.budgetCas(key, old, new)
        }
    }

    /** Only the replay claim: not a [Authorize.LastStore], not a [Authorize.BudgetStore]. */
    private class Plain(val inner: Authorize.MemoryStateStore = Authorize.MemoryStateStore()) : Authorize.StateStore {
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? = inner.claim(key, counter)
    }

    private fun input(
        store: Authorize.StateStore = Authorize.MemoryStateStore(),
        g: Map<String, Any?> = g0(),
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        risk: ((Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>?)? = AuthorizeTestKit.calmRisk,
        pqPins: Map<String, Any?>? = null,
        resolvePrincipal: ((String, Map<String, Any?>) -> Authorize.PrincipalInfo?)? = null,
        requireVerifiedPrincipal: Boolean = false,
        enforceFreshness: Authorize.FreshnessGate? = null,
        beacon: ((String, Map<String, Any?>) -> Beacons.Supplied?)? = null,
        thresholdHook: ((Map<String, Any?>, Map<String, Any?>) -> Authorize.ThresholdResult?)? = null,
        requireRiskInputs: List<String>? = null,
        adaptivePolicy: ((Long) -> Map<String, Any?>?)? = null,
        seedBudget: ((Map<String, Any?>, Long) -> Risk.Budget?)? = null,
        resolve: ((String) -> Map<String, Any?>?)? = { g },
        forbid: ForbidWins.Options? = null,
        forbidCertificate: Any? = null,
        requireLinkedTemplate: (() -> Any?)? = null,
        contracts: ContractEnforcer? = null,
        requirePassport: Authorize.PassportRequirement? = null,
        passport: Any? = null,
        escalationRender: ((Map<String, Any?>) -> String?)? = null,
        undo: Authorize.UndoHook? = null,
        intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        provenanceOptions: Authorize.ProvenanceOptions? = ProvHarness.options,
    ): Authorize.Input {
        val operation = op(c)
        return Authorize.Input(
            operation = operation, audience = AUD, resolveGrant = resolve, stateStore = store, isRevoked = { _, _ -> false }, now = NOW,
            plan = Authorize.SINGLE_STEP, context = context, intentV2 = intentV2, escalationRender = escalationRender, insecureUnboundApproval = true,
            provenanceOptions = provenanceOptions, provenance = ProvHarness.bundle(operation), undo = undo, pqPins = pqPins, risk = risk,
            thresholdHook = thresholdHook, requireRiskInputs = requireRiskInputs, adaptivePolicy = adaptivePolicy, seedBudget = seedBudget,
            enforceFreshness = enforceFreshness, beacon = beacon, resolvePrincipal = resolvePrincipal, requireVerifiedPrincipal = requireVerifiedPrincipal,
            requirePassport = requirePassport, passport = passport, requireLinkedTemplate = requireLinkedTemplate, forbid = forbid,
            forbidCertificate = forbidCertificate, contracts = contracts,
        )
    }

    private fun go(i: Authorize.Input, p: Map<String, Any?> = p0()): Authorize.Result { neutral(); return Authorize.authorize(p, i) }

    // ---------------------------------------------------------------- value classes

    @Test fun valueClassMembers() {
        val th = Risk.Threshold(2, "standard", false)
        val bd = Risk.Budget(5.0, 6.0, 7.0)
        val res = Authorize.Result(true, 200, emptyMap(), emptyList(), null, risk = 0.25, requiredThreshold = th, budget = bd, template = "linked")
        assertEquals(0.25, res.risk!!, 0.0)
        assertSame(th, res.requiredThreshold)
        assertSame(bd, res.budget)
        eq("linked", res.template)
        val bare = Authorize.Result(false, 403, emptyMap(), emptyList(), null)
        assertNull(bare.risk); assertNull(bare.requiredThreshold); assertNull(bare.budget); assertNull(bare.template)

        val tr = Authorize.ThresholdResult(true, true, 2.5, "why")
        assertTrue(tr.enforced); assertTrue(tr.ok); assertEquals(2.5, tr.t!!, 0.0); eq("why", tr.reason)
        val tr0 = Authorize.ThresholdResult(false)
        assertFalse(tr0.enforced); assertFalse(tr0.ok); assertNull(tr0.t); assertNull(tr0.reason)

        val pi = Authorize.PrincipalInfo(true, "agent", "id1")
        assertTrue(pi.verified); eq("agent", pi.subjectType); eq("id1", pi.subjectId)
        val pi0 = Authorize.PrincipalInfo(false)
        assertFalse(pi0.verified); assertNull(pi0.subjectType); assertNull(pi0.subjectId)

        val impl = object : Attest.VendorImpl {
            override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = Attest.Result(false, false, "x")
        }
        val dh = Attest.DefaultHardware(Attest.VendorVerifier("test", impl, null))
        val att: HardwareAttester = { _, _ -> Attest.Result(true, true, "", null) }
        val pins = mapOf("i" to "k")
        val now: () -> Long = { 3L }
        val pr = Authorize.PassportRequirement(listOf("a"), { _, _, _ -> false }, hardware = true, clockSkewMs = 11L, maxEvidenceAgeMs = 22L, pqPins = pins, attest = att, defaultHardware = dh, now = now)
        assertTrue(pr.hardware); eq(11L, pr.clockSkewMs); eq(22L, pr.maxEvidenceAgeMs); assertSame(pins, pr.pqPins); assertSame(att, pr.attest); assertSame(dh, pr.defaultHardware); assertSame(now, pr.now)
        val pr0 = Authorize.PassportRequirement(listOf("a"), null)
        assertFalse(pr0.hardware); assertNull(pr0.clockSkewMs); assertNull(pr0.maxEvidenceAgeMs); assertNull(pr0.pqPins); assertNull(pr0.attest); assertNull(pr0.defaultHardware); assertNull(pr0.now)

        val fg = Authorize.FreshnessGate(1.5, 2.5, 3L, 4.5)
        assertEquals(1.5, fg.maxAgeMs!!, 0.0); assertEquals(2.5, fg.epochMs!!, 0.0); eq(3L, fg.now); assertEquals(4.5, fg.clockSkewMs!!, 0.0)
        val fg0 = Authorize.FreshnessGate(null)
        assertNull(fg0.maxAgeMs); assertNull(fg0.epochMs); assertNull(fg0.now); assertNull(fg0.clockSkewMs)
    }

    @Test fun inputAndOptionsMembers() {
        val store = Authorize.MemoryStateStore()
        val risk: (Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>? = { _, _, _ -> null }
        val hook: (Map<String, Any?>, Map<String, Any?>) -> Authorize.ThresholdResult? = { _, _ -> null }
        val need = listOf("taint")
        val adaptive: (Long) -> Map<String, Any?>? = { null }
        val seed: (Map<String, Any?>, Long) -> Risk.Budget? = { _, _ -> null }
        val fg = Authorize.FreshnessGate(1.0)
        val tg = Taint.Gate(null, 1.0)
        val beacon: (String, Map<String, Any?>) -> Beacons.Supplied? = { _, _ -> null }
        val rp: (String, Map<String, Any?>) -> Authorize.PrincipalInfo? = { _, _ -> null }
        val pr = Authorize.PassportRequirement(listOf("a"), { _, _, _ -> false })
        val link: () -> Any? = { null }
        val fo = ForbidWins.Options({ _, _ -> emptyList() })
        val en: ContractEnforcer? = null
        val pins = mapOf("i" to "k")
        val suites = listOf("ed25519")
        val i = Authorize.Input(
            null, "a", null, store, null, allowedSuites = suites, pqPins = pins, risk = risk, thresholdHook = hook, requireRiskInputs = need,
            adaptivePolicy = adaptive, seedBudget = seed, enforceFreshness = fg, enforceTaint = tg, beacon = beacon, resolvePrincipal = rp,
            requireVerifiedPrincipal = true, requirePassport = pr, requireLinkedTemplate = link, forbid = fo, contracts = en,
        )
        assertSame(suites, i.allowedSuites); assertSame(pins, i.pqPins); assertSame(risk, i.risk); assertSame(hook, i.thresholdHook); assertSame(need, i.requireRiskInputs)
        assertSame(adaptive, i.adaptivePolicy); assertSame(seed, i.seedBudget); assertSame(fg, i.enforceFreshness); assertSame(tg, i.enforceTaint)
        assertSame(beacon, i.beacon); assertSame(rp, i.resolvePrincipal); assertTrue(i.requireVerifiedPrincipal); assertSame(pr, i.requirePassport)
        assertSame(link, i.requireLinkedTemplate); assertSame(fo, i.forbid); assertNull(i.contracts)
        val bare = Authorize.Input(null, "a", null, store, null)
        assertFalse(bare.requireVerifiedPrincipal)

        val o = Authorize.AuthorizeOptions(
            store, null, allowedSuites = suites, pqPins = pins, risk = risk, thresholdHook = hook, requireRiskInputs = need, adaptivePolicy = adaptive,
            seedBudget = seed, enforceFreshness = fg, enforceTaint = tg, beacon = beacon, resolvePrincipal = rp, requireVerifiedPrincipal = true,
            requirePassport = pr, requireLinkedTemplate = link, forbid = fo, contracts = en,
        )
        assertSame(suites, o.allowedSuites); assertSame(pins, o.pqPins); assertSame(risk, o.risk); assertSame(hook, o.thresholdHook); assertSame(need, o.requireRiskInputs)
        assertSame(adaptive, o.adaptivePolicy); assertSame(seed, o.seedBudget); assertSame(fg, o.enforceFreshness); assertSame(tg, o.enforceTaint)
        assertSame(beacon, o.beacon); assertSame(rp, o.resolvePrincipal); assertTrue(o.requireVerifiedPrincipal); assertSame(pr, o.requirePassport)
        assertSame(link, o.requireLinkedTemplate); assertSame(fo, o.forbid); assertNull(o.contracts)
        assertFalse(Authorize.AuthorizeOptions(store, null).requireVerifiedPrincipal)
        // run() forwards every one of them into the Input it authorizes with
        neutral()
        var seenHook = false
        var seenSeed: Pair<Map<String, Any?>, Long>? = null
        val g = g0()
        val full = Authorize.AuthorizeOptions(
            store, { _, _ -> false }, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk,
            thresholdHook = { _, _ -> seenHook = true; Authorize.ThresholdResult(true, true, 3.0) },
            seedBudget = { gr, n -> seenSeed = Pair(gr, n); null },
            requireRiskInputs = listOf("nope"), pqPins = mapOf("someone" to "k"),
            resolvePrincipal = { _, _ -> Authorize.PrincipalInfo(true, "u", "x") }, requireVerifiedPrincipal = true,
            adaptivePolicy = { _ -> null }, provenance = ProvHarness.options,
        )
        val r = full.run(p0(), op(c), AUD, { g }, now = NOW, provenance = ProvHarness.bundle(op(c)))
        assertTrue(seenHook)
        assertSame(g, seenSeed!!.first)
        eq(NOW, seenSeed!!.second)
        eq("fail", r.checks["risk_inputs"])
        eq("pass", r.checks["pq_pin"])
        eq("pass", r.checks["principal"])
        assertTrue(r.reasons.toString(), r.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: nope"))
    }

    // ---------------------------------------------------------------- the in-memory budget CAS

    @Test fun memoryBudgetCompareAndSet() {
        val m = Authorize.MemoryStateStore()
        val b1 = Risk.Budget(1.0, 2.0, 3.0)
        val b2 = Risk.Budget(4.0, 5.0, 6.0)
        assertNull(m.budget("k"))
        assertTrue(m.budgetCas("k", null, b1))
        eq(b1, m.budget("k"))
        assertFalse(m.budgetCas("k", null, b2)) // stored is not null
        eq(b1, m.budget("k"))
        assertFalse(m.budgetCas("k", b2, b2)) // stored is not b2
        eq(b1, m.budget("k"))
        assertTrue(m.budgetCas("k", b1, b2))
        eq(b2, m.budget("k"))
        assertNull(m.budget("other"))
    }

    // ---------------------------------------------------------------- passport assurance

    @Test fun passportAssuranceEntries() {
        fun assur(v: Passport.Verdict, rp: Authorize.PassportRequirement): Map<String, Any?> = KUtil.priv(Authorize, "passportAssurance", v, rp)
        val soft = Passport.Verdict(true, null)
        eq(mapOf("outcome" to "pass", "level" to "software"), assur(soft, Authorize.PassportRequirement(listOf("a"), null)))
        val hw = Passport.Verdict(true, null, hardwareVerified = true)
        val impl = object : Attest.VendorImpl {
            override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = Attest.Result(false, false, "x")
        }
        val dh = Assurance.setLabel(Attest.DefaultHardware(Attest.VendorVerifier("test", impl, null)), "multi_root", "dh-vendor")
        // no label anywhere
        eq(mapOf("outcome" to "pass", "level" to "unknown"), assur(hw, Authorize.PassportRequirement(listOf("a"), null, hardware = true)))
        // the default hardware's label when no attester is given
        eq(mapOf("outcome" to "pass", "level" to "multi_root", "vendor" to "dh-vendor"), assur(hw, Authorize.PassportRequirement(listOf("a"), null, hardware = true, defaultHardware = dh)))
        // the attester's label wins over the default's
        val att: HardwareAttester = Assurance.setLabel({ _: Map<String, Any?>, _: Attest.Binding -> Attest.Result(true, true, "", null) }, "hardware", "att-vendor")
        eq(mapOf("outcome" to "pass", "level" to "hardware", "vendor" to "att-vendor"), assur(hw, Authorize.PassportRequirement(listOf("a"), null, hardware = true, attest = att, defaultHardware = dh)))
        // an empty vendor is not reported
        val emptyVendor: HardwareAttester = Assurance.setLabel({ _: Map<String, Any?>, _: Attest.Binding -> Attest.Result(true, true, "", null) }, "hardware", "")
        eq(mapOf("outcome" to "pass", "level" to "hardware"), assur(hw, Authorize.PassportRequirement(listOf("a"), null, hardware = true, attest = emptyVendor)))
    }

    private fun signedPassport(issuer: Keys.EdKey, hardware: Boolean, nbf: Long = NOW - 1000, evidenceAt: Long = NOW): Map<String, Any?> {
        val ident = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to hardware)
        ident["id"] = Passport.fingerprint(ident)
        val body = linkedMapOf<String, Any?>(
            "typ" to "atlas-pca/passport", "ver" to 1L, "passport" to ident, "iss" to issuer.id(), "sub" to holder,
            "iat" to nbf, "nbf" to nbf, "exp" to NOW + 600_000,
        )
        if (hardware) body["evidence"] = mapOf("document" to mapOf("nonce" to "n1"), "at" to evidenceAt)
        val signed = LinkedHashMap(body)
        signed["sig"] = Pca.b64(issuer.sign(IntentJs.message(Passport.SIG_DOMAIN, body)))
        return signed
    }

    private val measured = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to true)

    @Test fun aHardwarePassportDemandWithoutEvidenceIsARefusal() {
        val issuer = Keys.edGenerate()
        val signed = signedPassport(issuer, false)
        val req = Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, hardware = true, now = { NOW })
        val r = go(input(requirePassport = req, passport = signed))
        assertFalse(r.allow)
        eq(403, r.status)
        eq(mapOf("passport" to "fail"), r.checks)
        eq("passport: hardware_evidence_missing", r.reason)
        // the same passport without the hardware demand is admitted and carries its verdict
        val ok = go(input(requirePassport = Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, now = { NOW }), passport = signed))
        assertTrue(ok.reasons.toString(), ok.allow)
        assertTrue(ok.passport!!.ok)
        // a rejected passport is a 403 refusal named passport (the requirement's own clock is past the passport's exp)
        val late = go(input(requirePassport = Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, now = { NOW + 10_000_000L }), passport = signed))
        assertFalse(late.allow)
        eq(403, late.status)
        eq(mapOf("passport" to "fail"), late.checks)
        eq("passport: expired", late.reason)
    }

    @Test fun passportOptionsAreForwardedToTheVerifier() {
        val issuer = Keys.edGenerate()
        val impl = object : Attest.VendorImpl {
            override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = Attest.Result(true, true, "", measured)
        }
        val dh = Assurance.setLabel(Attest.DefaultHardware(Attest.VendorVerifier("test", impl, null)), "hardware", "dh-vendor")
        val hw = signedPassport(issuer, true, evidenceAt = NOW - 5000)
        fun req(hardware: Boolean = true, maxAge: Long? = null, skew: Long? = null, att: HardwareAttester? = null, def: Attest.DefaultHardware? = null) =
            Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, hardware = hardware, clockSkewMs = skew, maxEvidenceAgeMs = maxAge, attest = att, defaultHardware = def, now = { NOW })
        // the default hardware verifies and its label is reported
        val viaDefault = go(input(requirePassport = req(def = dh), passport = hw))
        assertTrue(viaDefault.reasons.toString(), viaDefault.allow)
        eq(mapOf("outcome" to "pass", "level" to "hardware", "vendor" to "dh-vendor"), viaDefault.assurance["passport"])
        // evidence older than the configured age is stale
        val stale = go(input(requirePassport = req(maxAge = 1000L, def = dh), passport = hw))
        assertFalse(stale.allow)
        eq("passport: hardware_evidence_stale", stale.reason)
        eq(403, stale.status)
        // an integrator attester is used
        val att: HardwareAttester = { _, _ -> Attest.Result(true, true, "", measured) }
        val viaAttest = go(input(requirePassport = req(att = att), passport = hw))
        assertTrue(viaAttest.reasons.toString(), viaAttest.allow)
        // neither: no verifier
        eq("passport: hardware_verifier_missing", go(input(requirePassport = req(), passport = hw)).reason)
        // the clock skew admits a passport that is not yet valid
        val early = signedPassport(issuer, false, nbf = NOW + 30_000)
        val refused = go(input(requirePassport = req(hardware = false), passport = early))
        eq("passport: not_yet_valid", refused.reason)
        val skewed = go(input(requirePassport = req(hardware = false, skew = 60_000L), passport = early))
        assertTrue(skewed.reasons.toString(), skewed.allow)
    }

    @Test fun aMalformedChainNeverReachesThePassportCheck() {
        val req = Authorize.PassportRequirement(listOf("i"), { _, _, _ -> false }, now = { NOW })
        for (chain in listOf<Any?>("x", ArrayList<Any?>(), listOf(mapOf("holder" to 5L)))) {
            val p = p0()
            p["cap_chain"] = chain
            val r = go(input(requirePassport = req), p)
            assertFalse(r.allow)
            assertNull(r.checks["passport"])
            assertNull(r.checks["authorize"])
        }
    }

    @Test fun aLeafUnreadableUpFrontIsRefusedAtCommitWithSubjectMismatch() {
        // seam: the proof's first read of cap_chain (the passport subject) is unusable, every later read is the real chain
        val issuer = Keys.edGenerate()
        val signed = signedPassport(issuer, false)
        val seam = object : LinkedHashMap<String, Any?>(p0()) {
            var first = true
            override fun get(key: String): Any? {
                if (key == "cap_chain" && first) { first = false; return "x" }
                return super.get(key)
            }
        }
        val req = Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, now = { NOW })
        val r = go(input(requirePassport = req, passport = signed), seam)
        assertFalse(r.allow)
        eq(403, r.status)
        eq("fail", r.checks["passport"])
        assertTrue(r.reasons.toString(), r.reasons.contains("passport: subject_mismatch"))
        assertNull(r.passport)
    }

    @Test fun aMalformedBeaconIsRejectedNotAnError() {
        val r = withBeacon(Authorize.MemoryStateStore(), linkedMapOf<String, Any?>(), ref = "r")
        assertFalse(r.allow)
        eq("fail", r.checks["beacon"])
        assertNull(r.checks["authorize"])
        assertTrue(r.reasons.toString(), r.reasons.contains("beacon: malformed beacon"))
    }

    @Test fun configurationRefusalsNameEveryMissingComponent() {
        val r = Authorize.authorize(
            p0(), Authorize.Input(op(c), null, null, null, null, plan = "multi", requirePassport = Authorize.PassportRequirement(emptyList(), null)),
        )
        eq(403, r.status)
        eq(mapOf("authorize_config" to "fail"), r.checks)
        val want = listOf("audience", "resolveGrant", "stateStore", "isRevoked", "plan (only 'single-step' or null)", "requirePassport.trustedIssuers", "requirePassport.revoked")
        eq(want, r.missing)
        eq("authorize_config: missing required component(s): ${want.joinToString(", ")} (fail closed)", r.reason)
        fun one(i: Authorize.Input): List<String>? = Authorize.authorize(p0(), i).missing
        val store = Authorize.MemoryStateStore()
        val rev: (Map<String, Any?>, Map<String, Any?>) -> Any? = { _, _ -> false }
        eq(listOf("audience"), one(Authorize.Input(op(c), "", { null }, store, rev)))
        eq(listOf("resolveGrant"), one(Authorize.Input(op(c), "a", null, store, rev)))
        eq(listOf("stateStore"), one(Authorize.Input(op(c), "a", { null }, null, rev)))
        eq(listOf("isRevoked"), one(Authorize.Input(op(c), "a", { null }, store, null)))
        eq(listOf("plan (only 'single-step' or null)"), one(Authorize.Input(op(c), "a", { null }, store, rev, plan = "x")))
        eq(listOf("requirePassport.trustedIssuers"), one(Authorize.Input(op(c), "a", { null }, store, rev, requirePassport = Authorize.PassportRequirement(emptyList(), { _, _, _ -> false }))))
        eq(listOf("requirePassport.revoked"), one(Authorize.Input(op(c), "a", { null }, store, rev, requirePassport = Authorize.PassportRequirement(listOf("i"), null))))
        assertNull(one(Authorize.Input(op(c), "a", { null }, store, rev, plan = Authorize.SINGLE_STEP)))
    }

    // ---------------------------------------------------------------- pq pins

    @Test fun pqPinsDecideByAlgorithmAndPin() {
        val issuer = grant(c)["issuer"] as String
        fun check(g: Map<String, Any?>, pins: Map<String, Any?>): Pair<String?, String?> {
            val r = go(input(g = g, pqPins = pins))
            return Pair(r.checks["pq_pin"], r.reasons.firstOrNull { it.startsWith("pq_pin:") })
        }
        // an Ed25519 grant (no alg member) whose issuer has no pin passes; one whose issuer IS pinned is refused
        eq(Pair("pass", null), check(g0(), mapOf("other" to "k")))
        eq(Pair("fail", "pq_pin: ${Pca.PQ_PIN_CLASSICAL_REASON}"), check(g0(), mapOf(issuer to "k")))
        val ed = g0().also { it["alg"] = "ed25519" }
        eq(Pair("pass", null), check(ed, mapOf("other" to "k")))
        eq(Pair("fail", "pq_pin: ${Pca.PQ_PIN_CLASSICAL_REASON}"), check(ed, mapOf(issuer to "k")))
        // a grant without an issuer string is not pinned
        val noIssuer = g0().also { it.remove("issuer") }
        eq(Pair("pass", null), check(noIssuer, mapOf(issuer to "k")))
        val numIssuer = g0().also { it["issuer"] = 5L }
        eq(Pair("pass", null), check(numIssuer, mapOf(issuer to "k")))
        // a post-quantum grant: the pin must equal its pq_pk
        val pq = g0().also { it["alg"] = "hybrid"; it["pq_pk"] = "PK1" }
        eq(Pair("pass", null), check(pq, mapOf(issuer to "PK1")))
        eq(Pair("fail", "pq_pin: the grant pq_pk does not match the server-side pin"), check(pq, mapOf(issuer to "PK2")))
        eq(Pair("fail", "pq_pin: no server-side PQ pin for the grant issuer (suite hybrid)"), check(pq, mapOf("other" to "PK1")))
        eq(Pair("fail", "pq_pin: the grant pq_pk does not match the server-side pin"), check(pq, mapOf(issuer to 5L)))
        val noPk = g0().also { it["alg"] = "hybrid" }
        eq(Pair("fail", "pq_pin: the grant pq_pk does not match the server-side pin"), check(noPk, mapOf(issuer to "PK1")))
        val numPk = g0().also { it["alg"] = "hybrid"; it["pq_pk"] = 5L }
        eq(Pair("fail", "pq_pin: the grant pq_pk does not match the server-side pin"), check(numPk, mapOf(issuer to "5")))
        val noIss = g0().also { it["alg"] = "hybrid"; it["pq_pk"] = "PK1"; it.remove("issuer") }
        eq(Pair("fail", "pq_pin: no server-side PQ pin for the grant issuer (suite hybrid)"), check(noIss, mapOf(issuer to "PK1")))
        // no pins configured: the check is not reported
        assertNull(go(input()).checks["pq_pin"])
    }

    // ---------------------------------------------------------------- principal resolver

    @Test fun principalResolverSeesTheIssuerAndTheGrant() {
        val g = g0()
        var seen: Pair<String, Map<String, Any?>>? = null
        val ok = go(input(g = g, resolvePrincipal = { iss, gr -> seen = Pair(iss, gr); Authorize.PrincipalInfo(true, "agent", "id1") }, requireVerifiedPrincipal = true))
        assertTrue(ok.reasons.toString(), ok.allow)
        eq("pass", ok.checks["principal"])
        eq(g["issuer"], seen!!.first)
        assertSame(g, seen!!.second)
        eq("id1", ok.principal!!.subjectId)
        // a grant without an issuer string reaches the resolver as the empty string
        val bare = g0().also { it.remove("issuer") }
        var seenIssuer: String? = null
        go(input(g = bare, resolvePrincipal = { iss, _ -> seenIssuer = iss; null }))
        eq("", seenIssuer)
        // not required: an unverified or unknown principal is not-enforced and the call still allows
        for (info in listOf<Authorize.PrincipalInfo?>(Authorize.PrincipalInfo(false), null)) {
            val r = go(input(resolvePrincipal = { _, _ -> info }))
            assertTrue(r.reasons.toString(), r.allow)
            eq("not-enforced", r.checks["principal"])
        }
        // required: an unverified, unknown or failing resolver is refused with its own reason
        for (info in listOf<Authorize.PrincipalInfo?>(Authorize.PrincipalInfo(false), null)) {
            val r = go(input(resolvePrincipal = { _, _ -> info }, requireVerifiedPrincipal = true))
            assertFalse(r.allow)
            eq("fail", r.checks["principal"])
            assertTrue(r.reasons.contains("principal: the grant issuer is not an enrolled, verified principal"))
        }
        val thrown = go(input(resolvePrincipal = { _, _ -> throw IllegalStateException("x") }, requireVerifiedPrincipal = true))
        eq(listOf("principal: the principal resolver failed (fail closed)"), thrown.reasons.filter { it.startsWith("principal") })
        val thrownOpt = go(input(resolvePrincipal = { _, _ -> throw IllegalStateException("x") }))
        assertFalse(thrownOpt.allow)
        eq("fail", thrownOpt.checks["principal"])
        // required with no resolver
        val none = go(input(requireVerifiedPrincipal = true))
        assertFalse(none.allow)
        assertTrue(none.reasons.contains("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver"))
        assertNull(go(input()).checks["principal"])
    }

    // ---------------------------------------------------------------- freshness anchor boundaries

    private fun anchor(epoch: Long) = "freshness" to linkedMapOf<String, Any?>("beacon_ref" to "ref", "epoch" to IntentJs.ofLong(epoch))

    private fun gate(g: Authorize.FreshnessGate, epoch: Long?): Authorize.Result {
        val p = p0()
        if (epoch != null) { val a = anchor(epoch); p[a.first] = a.second }
        return go(input(enforceFreshness = g), p)
    }

    @Test fun freshnessAnchorBoundaries() {
        // epochMs = 1000: epoch e is the instant e * 1000
        val now10 = 10_000L
        fun g(maxAge: Double?, skew: Double? = null, epochMs: Double? = 1000.0) = Authorize.FreshnessGate(maxAge, epochMs, now10, skew)
        // an anchor exactly now, with max age 0, passes (maxAgeMs >= 0 is valid; the age is not greater than it)
        assertEquals("pass", gate(g(0.0), 10).checks["freshness"])
        // the smallest valid epoch is 1
        assertEquals("pass", gate(Authorize.FreshnessGate(1_000_000.0, 1000.0, 1_500L), 1).checks["freshness"])
        // the future bound: anchor <= now + skew
        eq("pass", gate(g(5000.0, 1000.0), 11).checks["freshness"])
        eq("fail", gate(g(5000.0, 999.0), 11).checks["freshness"])
        eq("fail", gate(g(5000.0), 11).checks["freshness"])
        // a fractional skew is not rounded up to 1
        eq("fail", gate(g(5000.0, 0.5, epochMs = 1.0), 10_001).checks["freshness"])
        eq("fail", gate(Authorize.FreshnessGate(5000.0, 1.0, 10_000L, null), 10_001).checks["freshness"]) // default skew is 0, not 1
        eq("fail", gate(Authorize.FreshnessGate(5000.0, 1.0, 10_000L, -5.0), 10_001).checks["freshness"]) // a negative skew reads as 0
        // a non-finite skew reads as no skew
        eq("fail", gate(g(5000.0, Double.NaN), 11).checks["freshness"])
        eq("fail", gate(g(5000.0, Double.POSITIVE_INFINITY), 11).checks["freshness"])
        eq("fail", gate(g(5000.0, Double.NEGATIVE_INFINITY), 11).checks["freshness"])
        // the age bound: now - anchor <= maxAge
        eq("pass", gate(g(5000.0), 5).checks["freshness"])
        eq("fail", gate(g(4999.0), 5).checks["freshness"])
        assertTrue(gate(g(4999.0), 5).reasons.contains("freshness: freshness anchor is stale (older than 4999 ms)"))
        assertTrue(gate(g(5000.0, 999.0), 11).reasons.contains("freshness: freshness anchor is in the future"))
        // misconfigured gates
        val mis = "freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
        assertTrue(gate(g(5000.0, epochMs = 0.0), 10).reasons.contains(mis))
        assertTrue(gate(g(5000.0, epochMs = Double.NaN), 10).reasons.contains(mis))
        assertTrue(gate(g(5000.0, epochMs = Double.POSITIVE_INFINITY), 10).reasons.contains(mis))
        assertTrue(gate(g(-1.0), 10).reasons.contains(mis))
        assertTrue(gate(g(null), 10).reasons.contains(mis))
        assertTrue(gate(g(Double.NaN), 10).reasons.contains(mis))
        assertTrue(gate(g(Double.POSITIVE_INFINITY), 10).reasons.contains(mis))
        // the stub anchors
        val missing = "freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
        assertTrue(gate(g(5000.0), null).reasons.contains(missing))
        assertTrue(gate(g(5000.0), 0).reasons.contains(missing))
        assertTrue(gate(g(5000.0), -1).reasons.contains(missing))
        val emptyRef = p0().also { it["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to "", "epoch" to IntentJs.ofLong(10)) }
        assertTrue(go(input(enforceFreshness = g(5000.0)), emptyRef).reasons.contains(missing))
        val nullRef = p0().also { it["freshness"] = linkedMapOf<String, Any?>("epoch" to IntentJs.ofLong(10)) }
        assertTrue(go(input(enforceFreshness = g(5000.0)), nullRef).reasons.contains(missing))
        val strFresh = p0().also { it["freshness"] = "x" }
        assertTrue(go(input(enforceFreshness = g(5000.0)), strFresh).reasons.contains(missing))
        val fracEpoch = p0().also { it["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to "r", "epoch" to Json.Num("1.5")) }
        assertTrue(go(input(enforceFreshness = g(5000.0)), fracEpoch).reasons.contains(missing))
        // the gate's own clock defaults to the call's clock, the epoch length to a minute
        val wall = Authorize.FreshnessGate(5000.0)
        eq("pass", gate(wall, NOW / 60_000L).checks["freshness"])
        // absent gate: no check
        assertNull(go(input()).checks["freshness"])
    }

    // ---------------------------------------------------------------- liveness beacon

    private val bIssuer = Keys.edGenerate()
    private val issued = NOW - 120_000L

    private fun beaconOf(seq: Long, issuedAt: Long = issued, notAfter: Long = issued + 300_000L): Map<String, Any?> {
        val b = linkedMapOf<String, Any?>(
            "v" to IntentJs.ofLong(2), "instance" to "inst", "scope" to "*", "epoch" to IntentJs.ofLong(Math.floorDiv(issuedAt, Beacons.EPOCH_MS)), "seq" to IntentJs.ofLong(seq),
            "issued_at" to IntentJs.ofLong(issuedAt), "not_after" to IntentJs.ofLong(notAfter), "issuer" to bIssuer.id(),
        )
        val msg = Pca.concat(IntentJs.utf8("atlas-pca/beacon/v2\u0000"), IntentJs.canonBytes(b))
        return LinkedHashMap(b).also { it["sig"] = Pca.b64(bIssuer.sign(msg)) }
    }

    private fun withBeacon(store: Authorize.StateStore, b: Map<String, Any?>, ref: String? = null): Authorize.Result {
        val p = p0()
        p["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to (ref ?: Beacons.beaconRef(b)), "epoch" to IntentJs.ofLong(1))
        return go(input(store = store, beacon = { _, _ -> Beacons.Supplied(b, listOf(bIssuer.id()), "inst") }), p)
    }

    @Test fun beaconPinAndOutcomes() {
        val pin = "$gid:beacon"
        val store = Authorize.MemoryStateStore()
        val ok = withBeacon(store, beaconOf(5))
        assertTrue(ok.reasons.toString(), ok.allow)
        eq("pass", ok.checks["beacon"])
        eq(5L, store.last(pin))
        // seq 0 is accepted and is the pin it leaves (a rejected beacon would leave seq 0 too, so a pass must set the pin)
        val zero = Authorize.MemoryStateStore()
        assertTrue(withBeacon(zero, beaconOf(0)).allow)
        eq(0L, zero.last(pin))
        // replay: strictly older than the pin
        val seeded = Authorize.MemoryStateStore().also { it.claim(pin, 9) }
        val old = withBeacon(seeded, beaconOf(5))
        assertFalse(old.allow)
        assertTrue(old.reasons.toString(), old.reasons.contains("beacon: beacon seq 5 is older than the last accepted 9 (replay)"))
        eq(9L, seeded.last(pin))
        // an equal seq is not a replay; the one above is not either
        val equal = Authorize.MemoryStateStore().also { it.claim(pin, 5) }
        assertTrue(withBeacon(equal, beaconOf(5)).allow)
        val above = Authorize.MemoryStateStore().also { it.claim(pin, 4) }
        assertTrue(withBeacon(above, beaconOf(5)).allow)
        eq(5L, above.last(pin))
        // unbound ref, rejected beacon
        val unbound = withBeacon(Authorize.MemoryStateStore(), beaconOf(5), ref = "not-the-ref")
        assertTrue(unbound.reasons.toString(), unbound.reasons.contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon"))
        val expired = withBeacon(Authorize.MemoryStateStore(), beaconOf(5, issued - 3_000_000L, issued - 3_000_000L + 60_000L))
        assertTrue(expired.reasons.toString(), expired.reasons.contains("beacon: expired"))
        val bad = LinkedHashMap(beaconOf(5)).also { it["seq"] = IntentJs.ofLong(6) }
        assertTrue(withBeacon(Authorize.MemoryStateStore(), bad).reasons.contains("beacon: bad signature"))
        // a beacon fn that returns none or throws: not-enforced, and the required beacon check denies
        for (fn in listOf<(String, Map<String, Any?>) -> Beacons.Supplied?>({ _, _ -> null }, { _, _ -> throw IllegalStateException("x") })) {
            val r = go(input(beacon = fn))
            assertFalse(r.allow)
            eq("fail", r.checks["beacon"]) // required + unavailable: the default-deny flips not-enforced to fail (TS verdict.checks.beacon)
            assertTrue(r.reasons.toString(), r.reasons.contains("beacon: required check is not-enforced (default-deny: not enforced by this resource server)"))
        }
        // without the option the check is not-enforced and not required
        val plain = go(input())
        assertTrue(plain.reasons.toString(), plain.allow)
        eq("not-enforced", plain.checks["beacon"])
        // the beacon fn gets the grant ref and the proof
        var seen: Pair<String, Map<String, Any?>>? = null
        val p = p0()
        go(input(beacon = { r, pp -> seen = Pair(r, pp); null }), p)
        eq(gid, seen!!.first)
        assertSame(p, seen!!.second)
        // a store that cannot read the pin reads as no pin; one that cannot write it never undoes the allow
        val flaky = Wrap().also { w ->
            w.onLast = { k -> if (k.endsWith(":beacon")) throw IllegalStateException("down") else w.inner.last(k) }
            w.onClaim = { k, n -> if (k.endsWith(":beacon")) throw IllegalStateException("down") else w.inner.claim(k, n) }
        }
        val r = withBeacon(flaky, beaconOf(5))
        assertTrue(r.reasons.toString(), r.allow)
        assertNull(flaky.inner.last(pin))
    }

    // ---------------------------------------------------------------- risk, budget and threshold

    private fun caution(v: Double): MutableMap<String, Any?> = p0().also { it["caution"] = Json.Num(IntentJs.shortest(v)) }

    @Test fun cautionFloorsTheRiskScore() {
        for ((caut, want) in listOf(0.3 to 0.3, 1.5 to 1.0, -0.5 to 0.0, 0.0 to 0.0, 1.0 to 1.0, 0.75 to 0.75)) {
            val r = go(input(), caution(caut))
            assertEquals("caution $caut", want, r.risk!!, 0.0)
        }
        // no caution and a calm server: r is 0, threshold 1
        val calm = go(input())
        assertTrue(calm.reasons.toString(), calm.allow)
        assertEquals(0.0, calm.risk!!, 0.0)
        eq(1, calm.requiredThreshold!!.t)
        eq("claim", calm.requiredThreshold!!.proof)
        eq("pass", calm.checks["budget"])
        eq("not-enforced", calm.checks["threshold"])
        // a non-finite caution is no floor
        assertEquals(0.0, go(input(), p0().also { it["caution"] = "x" }).risk!!, 0.0)
    }

    @Test fun theThresholdFollowsTheRiskBands() {
        val big = Risk.Budget(1000.0, NOW.toDouble(), NOW.toDouble())
        val ctx = ctxOf("budget" to big)
        val a = go(input(context = ctx), caution(0.5))
        assertTrue(a.reasons.toString(), a.allow) // r == theta1 is still t = 1
        eq(1, a.requiredThreshold!!.t)
        val b = go(input(context = ctx), caution(0.6))
        assertFalse(b.allow)
        eq(2, b.requiredThreshold!!.t)
        eq("standard", b.requiredThreshold!!.proof)
        assertFalse(b.requiredThreshold!!.optimisticAllowed)
        assertTrue(b.reasons.toString(), b.reasons.contains("policy: risk 0.600 exceeds auto threshold: step-up to t=2"))
        assertTrue(b.reasons.toString(), b.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"))
        eq("fail", b.checks["threshold"])
        val b2 = go(input(context = ctx), caution(0.8))
        eq(2, b2.requiredThreshold!!.t) // r == theta2 is still t = 2
        val c3 = go(input(context = ctx), caution(0.9))
        eq(3, c3.requiredThreshold!!.t)
        eq("strong", c3.requiredThreshold!!.proof)
        assertTrue(c3.reasons.toString(), c3.reasons.contains("policy: risk 0.900 exceeds auto threshold: step-up to t=3"))
        assertTrue(c3.reasons.toString(), c3.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"))
        // a depleted budget makes a machine-only action step up to a human
        val empty = ctxOf("budget" to Risk.Budget(0.0, NOW.toDouble(), NOW.toDouble()))
        for (caut in listOf(0.3, 0.6)) {
            val d = go(input(context = empty), caution(caut))
            assertFalse(d.allow)
            eq(3, d.requiredThreshold!!.t)
            assertTrue(d.reasons.toString(), d.reasons.contains("policy: trust budget depleted: human recharge required"))
        }
        // r = 0 costs nothing: even an empty budget covers it
        assertTrue(go(input(context = empty)).allow)
        // the optimistic fast path depends on the reversibility class
        for ((cls, want) in listOf("reversible" to true, "rate_limited" to true, "costly" to true, "irreversible" to false, "weird" to false)) {
            val p = caution(0.3)
            (p["action"] as MutableMap<String, Any?>)["reversibility_class"] = cls
            val r = go(input(), p)
            assertEquals(cls, want, r.requiredThreshold!!.optimisticAllowed)
        }
    }

    @Test fun theThresholdHookDecidesTheStepUp() {
        val ctx = ctxOf("budget" to Risk.Budget(100.0, NOW.toDouble(), NOW.toDouble()))
        fun hooked(t: Double?, ok: Boolean = true, enforced: Boolean = true, reason: String? = null, throws: Throwable? = null, caut: Double = 0.6): Authorize.Result =
            go(input(context = ctx, thresholdHook = { _, _ -> if (throws != null) throw throws else Authorize.ThresholdResult(enforced, ok, t, reason) }), caution(caut))
        val pass = hooked(2.0)
        assertTrue(pass.reasons.toString(), pass.allow)
        eq("pass", pass.checks["threshold"])
        assertEquals(99.4, pass.budget!!.B, 1e-9) // t = 2 is metered: debited kappa * r
        assertTrue(hooked(2.9).allow) // the hook's t is floored
        assertTrue(hooked(1e300).allow) // and clamped to the safe-integer range
        val below = hooked(1.9)
        assertFalse(below.allow)
        eq("fail", below.checks["threshold"])
        assertTrue(below.reasons.toString(), below.reasons.contains("threshold: threshold hook enforced t=1.9 but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"))
        assertTrue(hooked(-5.5).reasons.contains("threshold: threshold hook enforced t=-5.5 but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"))
        assertTrue(hooked(null).reasons.contains("threshold: threshold hook enforced t=unreported but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"))
        assertTrue(hooked(Double.NaN).reasons.contains("threshold: threshold hook enforced t=NaN but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"))
        assertTrue(hooked(Double.POSITIVE_INFINITY).reasons.contains("threshold: threshold hook enforced t=Infinity but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"))
        // the proof was rejected, with and without a reason
        val rej = hooked(2.0, ok = false, reason = "nope")
        eq("fail", rej.checks["threshold"])
        assertTrue(rej.reasons.toString(), rej.reasons.contains("threshold: nope"))
        assertTrue(rej.reasons.toString(), rej.reasons.contains("threshold: t=2 required and the threshold proof was rejected"))
        assertTrue(hooked(2.0, ok = false).reasons.contains("threshold: rejected"))
        // a hook that throws fails closed; a fatal error escapes
        val thrown = hooked(2.0, throws = IllegalStateException("x"))
        assertTrue(thrown.reasons.toString(), thrown.reasons.contains("threshold: threshold hook error (fail closed)"))
        assertTrue(thrown.reasons.contains("threshold: t=2 required and the threshold proof was rejected"))
        eq("fail", thrown.checks["threshold"])
        assertThrows(OutOfMemoryError::class.java) { hooked(2.0, throws = OutOfMemoryError()) }
        // a hook that is not enforced, or none: the verifier is absent, so the required threshold FAILS (TS verify.ts applyThreshold)
        for (r in listOf(hooked(2.0, enforced = false), go(input(context = ctx, thresholdHook = { _, _ -> null }), caution(0.6)))) {
            eq("fail", r.checks["threshold"])
            assertTrue(r.reasons.toString(), r.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"))
        }
        // at t = 1 the hook is consulted but not required
        val calm = go(input(context = ctx, thresholdHook = { _, _ -> Authorize.ThresholdResult(true, true, 1.0) }), caution(0.3))
        assertTrue(calm.reasons.toString(), calm.allow)
        eq("pass", calm.checks["threshold"])
        // an enforced hook that rejects at t = 1 is a failed status but no step-up failure
        val calmRej = go(input(context = ctx, thresholdHook = { _, _ -> Authorize.ThresholdResult(true, false, null, "r") }), caution(0.3))
        eq("fail", calmRej.checks["threshold"])
        eq(listOf("threshold: r"), calmRej.reasons.filter { it.startsWith("threshold:") })
        // the hook is called with the proof and the grant
        val g = g0()
        val p = caution(0.3)
        var seen: Pair<Map<String, Any?>, Map<String, Any?>>? = null
        go(input(g = g, thresholdHook = { pp, gr -> seen = Pair(pp, gr); null }), p)
        assertSame(p, seen!!.first)
        assertSame(g, seen!!.second)
        // a policy that fails releases nothing: no threshold failure
        val deniedPolicy = case("envelope-predicate-400-refused")
        neutral()
        val dp = IntentJs.normalize(pcactn(deniedPolicy)) as MutableMap<String, Any?>
        dp["caution"] = Json.Num("0.6")
        val dg = IntentJs.normalize(grant(deniedPolicy)) as MutableMap<String, Any?>
        val opD = op(deniedPolicy)
        val rD = Authorize.authorize(
            dp,
            Authorize.Input(
                operation = opD, audience = AUD, resolveGrant = { dg }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = NOW,
                plan = Authorize.SINGLE_STEP, provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(opD), risk = AuthorizeTestKit.calmRisk,
                context = ctx,
            ),
        )
        eq("fail", rD.checks["policy"])
        eq("not-enforced", rD.checks["threshold"])
        assertFalse(rD.reasons.toString(), rD.reasons.any { it.startsWith("threshold:") })
    }

    @Test fun theBudgetIsMeteredAndPersisted() {
        // the stored budget is used when present; the seed otherwise; the grant's bMax is the default seed
        val store = Authorize.MemoryStateStore()
        val r = go(input(store = store), caution(0.3))
        assertTrue(r.reasons.toString(), r.allow)
        eq("pass", r.checks["budget"])
        assertEquals(999.7, r.budget!!.B, 1e-9)
        eq(NOW.toDouble(), r.budget!!.tau)
        eq(NOW.toDouble(), r.budget!!.asOf)
        eq(r.budget, store.budget(budgetKey))
        val stored = Authorize.MemoryStateStore()
        stored.budgetCas(budgetKey, null, Risk.Budget(50.0, 5.0, NOW.toDouble()))
        val r2 = go(input(store = stored), caution(0.3))
        assertEquals(49.7, r2.budget!!.B, 1e-9)
        eq(5.0, r2.budget!!.tau)
        // the seed option: called with the grant and the clock; null means no budget
        val g = g0()
        var seen: Pair<Map<String, Any?>, Long>? = null
        val seeded = go(input(g = g, seedBudget = { gr, n -> seen = Pair(gr, n); Risk.Budget(7.0, 1.0, NOW.toDouble()) }), caution(0.3))
        assertSame(g, seen!!.first)
        eq(NOW, seen!!.second)
        assertEquals(6.7, seeded.budget!!.B, 1e-9)
        // no budget at all (a seed that yields none, or a non-finite one): B = 0, nothing persisted, a r = 0 call still allows
        for (seed in listOf<(Map<String, Any?>, Long) -> Risk.Budget?>({ _, _ -> null }, { _, _ -> Risk.Budget(Double.NaN, 0.0, 0.0) }, { _, _ -> Risk.Budget(1.0, Double.POSITIVE_INFINITY, 0.0) })) {
            val w = Wrap()
            val none = go(input(store = w, seedBudget = seed))
            assertTrue(none.reasons.toString(), none.allow)
            eq("not-enforced", none.checks["budget"])
            assertTrue(none.reasons.toString(), none.reasons.contains("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"))
            assertTrue("nothing persisted", w.cas.isEmpty())
            assertNull(w.inner.budget(budgetKey))
            eq(Risk.Budget(0.0, NOW.toDouble(), NOW.toDouble()), none.budget)
        }
        // a store that is not a budget store has none: the same fail-closed default; a supplied budget is never persisted
        val plain = go(input(store = Plain()))
        eq("not-enforced", plain.checks["budget"])
        assertTrue(plain.reasons.contains("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"))
        val wrap = Wrap()
        val supplied = go(input(store = wrap, context = ctxOf("budget" to mapOf("B" to 10.0, "tau" to NOW.toDouble(), "asOf" to NOW.toDouble()))), caution(0.3))
        assertTrue(supplied.reasons.toString(), supplied.allow)
        eq("pass", supplied.checks["budget"])
        assertEquals(9.7, supplied.budget!!.B, 1e-9)
        assertTrue("a supplied budget is never persisted", wrap.cas.isEmpty())
        assertNull(wrap.inner.budget(budgetKey))
        // a supplied budget with a non-finite member is no budget
        val bad = go(input(context = ctxOf("budget" to mapOf("B" to "x", "tau" to 1.0))))
        eq("not-enforced", bad.checks["budget"])
        val badTau = go(input(context = ctxOf("budget" to mapOf("B" to 1.0, "tau" to "x"))))
        eq("not-enforced", badTau.checks["budget"])
        val noAsOf = go(input(context = ctxOf("budget" to mapOf("B" to 1.0, "tau" to NOW.toDouble()))), caution(0.3))
        eq("pass", noAsOf.checks["budget"])
        assertEquals(0.7, noAsOf.budget!!.B, 1e-9)
        // the CAS carries (key, stored, after)
        val w2 = Wrap()
        w2.inner.budgetCas(budgetKey, null, Risk.Budget(20.0, 1.0, NOW.toDouble()))
        val before = w2.inner.budget(budgetKey)
        w2.cas.clear()
        assertTrue(go(input(store = w2), caution(0.3)).allow)
        eq(1, w2.cas.size)
        eq(budgetKey, w2.cas[0].first)
        eq(before, w2.cas[0].second)
        assertEquals(19.7, w2.cas[0].third.B, 1e-9)
        // a refused or throwing CAS denies after the counter was spent
        val refused = Wrap().also { it.onCas = { _, _, _ -> false } }
        val rr = go(input(store = refused))
        assertFalse(rr.allow)
        eq("fail", rr.checks["budget"])
        assertTrue(rr.reasons.toString(), rr.reasons.contains("budget: the budget store refused the update (changed concurrently or failed): fail closed"))
        eq(403, rr.status)
        val throwing = Wrap().also { it.onCas = { _, _, _ -> throw IllegalStateException("down") } }
        val rt = go(input(store = throwing))
        assertFalse(rt.allow)
        eq("fail", rt.checks["budget"])
        assertThrows(OutOfMemoryError::class.java) { go(input(store = Wrap().also { it.onCas = { _, _, _ -> throw OutOfMemoryError() } })) }
        // an unmetered allow (t = 3 through the hook) is not debited
        val unmetered = go(
            input(context = ctxOf("budget" to Risk.Budget(100.0, NOW.toDouble(), NOW.toDouble())), thresholdHook = { _, _ -> Authorize.ThresholdResult(true, true, 3.0) }),
            caution(0.9),
        )
        assertTrue(unmetered.reasons.toString(), unmetered.allow)
        assertEquals(100.0, unmetered.budget!!.B, 0.0)
        // the budget leaks at lambda per second since asOf
        val g2 = g0().also { polOf(it)["lambda"] = 2.0 }
        val leaked = go(input(g = g2, context = ctxOf("budget" to Risk.Budget(100.0, 0.0, (NOW - 10_000L).toDouble()))), caution(0.3))
        assertEquals(79.7, leaked.budget!!.B, 1e-9)
        // a policy kappa scales the cost, and bMax is the seed
        val g3 = g0().also { polOf(it)["kappa"] = 10.0; polOf(it)["bMax"] = 500.0 }
        val scaled = go(input(g = g3), caution(0.3))
        assertEquals(497.0, scaled.budget!!.B, 1e-9)
    }

    @Test fun riskInputsComeFromTheServerAndThePlan() {
        // weights: only age counts, so r is the age input
        val ageG = g0().also { weights(it)["zeta"] = 1.0 }
        val noAge: (Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>? =
            { _, _, _ -> mapOf("semanticDistance" to 0L, "reversibility" to 1L, "blastRadius" to 0L, "taint" to 0L, "confidence" to 1L) }
        fun withBudget(tau: Double) = "budget" to Risk.Budget(1000.0, tau, NOW.toDouble())
        // the age since the last human touch over the default one-hour horizon
        assertEquals(0.25, go(input(g = ageG, risk = noAge, context = ctxOf(withBudget(NOW - 900_000.0)))).risk!!, 1e-12)
        // over the context's horizon
        assertEquals(0.5, go(input(g = ageG, risk = noAge, context = ctxOf(withBudget(NOW - 900_000.0), "age_horizon_ms" to 1_800_000.0))).risk!!, 1e-12)
        // a non-finite horizon is the worst age even for a fresh touch
        assertEquals(1.0, go(input(g = ageG, risk = noAge, context = ctxOf(withBudget(NOW.toDouble()), "age_horizon_ms" to "x"))).risk!!, 0.0)
        // a supplied age wins over the derived one
        assertEquals(0.0, go(input(g = ageG, context = ctxOf(withBudget(NOW - 900_000.0)))).risk!!, 0.0)
        // a missing input is its worst case and is named (age and the plan-covered semanticDistance are not)
        val allG = g0().also { for (k in listOf("beta", "gamma", "delta", "epsilon")) weights(it)[k] = 1.0 }
        val none = go(input(g = allG, risk = null))
        assertTrue(none.reasons.toString(), none.reasons.contains("policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence"))
        assertEquals(1.0, none.risk!!, 0.0) // clamp(4 * worst) = 1
        val partial = go(input(g = allG, risk = { _, _, _ -> mapOf("reversibility" to 1L, "taint" to 0L, "confidence" to 1L, "blastRadius" to 0L, "semanticDistance" to 0L) }))
        assertFalse(partial.reasons.toString(), partial.reasons.any { it.contains("risk input(s) missing") })
        assertEquals(0.0, partial.risk!!, 0.0)
        // the context risk is merged with the server's: the riskier wins
        val merged = go(input(g = allG, context = ctxOf("risk" to mapOf("taint" to 0.5))))
        assertEquals(0.5, merged.risk!!, 1e-12)
        // the semantic distance of a context plan (4 nodes: distance is index based without edges)
        val semG = g0().also { weights(it)["alpha"] = 1.0 }
        val nodes = listOf("n1", "n2", "n3", "n4", "n5").map { id -> linkedMapOf<String, Any?>("id" to id, "verb" to "x", "resource" to "y") }
        val onlyOthers: (Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>? =
            { _, _, _ -> mapOf("reversibility" to 1L, "blastRadius" to 0L, "taint" to 0L, "confidence" to 1L, "age" to 0L) }
        fun semantic(extra: Array<Pair<String, Any?>> = emptyArray(), risk: ((Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>?)? = onlyOthers, p: Map<String, Any?> = p0()) =
            go(input(g = semG, risk = risk, context = ctxOf("plan" to nodes, "plan_authorized" to true, *extra)), p).risk!!
        assertEquals(1.0, semantic(), 1e-12) // the goal defaults to the last node: n1 -> n5 is 4 / 4
        assertEquals(0.5, semantic(arrayOf("goal_node_id" to "n3")), 1e-12)
        assertEquals(1.0, semantic(arrayOf("goal_node_id" to "unknown")), 1e-12)
        assertEquals(0.25, semantic(arrayOf("goal_node_id" to "n2")), 1e-12)
        // no node id on the proof: the worst distance
        val noNode = p0().also { (it["plan"] as MutableMap<String, Any?>).remove("node_id") }
        assertEquals(1.0, semantic(arrayOf("goal_node_id" to "n2"), p = noNode), 1e-12)
        // a supplied distance wins over the plan's
        assertEquals(0.25, semantic(risk = { _, _, _ -> mapOf("semanticDistance" to 0.25, "reversibility" to 1L, "blastRadius" to 0L, "taint" to 0L, "confidence" to 1L, "age" to 0L) }), 1e-12)
        // single-step: the node is its own goal
        assertEquals(0.0, go(input(g = semG, risk = onlyOthers)).risk!!, 0.0)
        // the risk option gets the operation, the grant and the proof
        val g = g0()
        val p = p0()
        var seen: Triple<Authorize.Operation, Map<String, Any?>, Map<String, Any?>>? = null
        go(input(g = g, risk = { o, gr, pp -> seen = Triple(o, gr, pp); null }), p)
        eq(op(c).verb, seen!!.first.verb)
        eq(op(c).resource, seen!!.first.resource)
        assertSame(g, seen!!.second)
        assertSame(p, seen!!.third)
    }

    @Test fun mergedRiskAndBudgetOfHelpers() {
        val i = input(risk = { _, _, _ -> mapOf("taint" to 0.5, "confidence" to 0.2) })
        fun merged(ctx: Map<String, Any?>, inp: Authorize.Input = i): Map<String, Any?> = KUtil.priv(Authorize, "mergedRisk", ctx, inp, op(c), g0(), p0())
        eq(mapOf("taint" to 0.5, "confidence" to 0.2), merged(emptyMap()))
        eq(mapOf("taint" to 0.5, "confidence" to 0.2), merged(mapOf("risk" to "x")))
        val both = merged(mapOf("risk" to mapOf("taint" to 0.9, "confidence" to 0.9)))
        eq(0.9, both["taint"])
        eq(0.2, both["confidence"])
        eq(mapOf("taint" to 0.1), merged(mapOf("risk" to mapOf("taint" to 0.1)), input(risk = null)))
        eq(emptyMap<String, Any?>(), merged(emptyMap(), input(risk = null)))

        fun budgetOf(o: Any?): Risk.Budget? = KUtil.priv(Authorize, "budgetOf", o)
        val b = Risk.Budget(1.0, 2.0, 3.0)
        assertSame(b, budgetOf(b))
        assertNull(budgetOf(Risk.Budget(Double.NaN, 2.0)))
        assertNull(budgetOf(Risk.Budget(1.0, Double.NaN)))
        assertNull(budgetOf(Risk.Budget(Double.POSITIVE_INFINITY, 2.0)))
        assertNull(budgetOf(Risk.Budget(1.0, Double.NEGATIVE_INFINITY)))
        eq(Risk.Budget(1.0, 2.0, 3.0), budgetOf(mapOf("B" to 1.0, "tau" to 2.0, "asOf" to 3.0)))
        eq(Risk.Budget(1.0, 2.0, null), budgetOf(mapOf("B" to 1.0, "tau" to 2.0)))
        eq(Risk.Budget(1.0, 2.0, null), budgetOf(mapOf("B" to 1.0, "tau" to 2.0, "asOf" to "x")))
        assertNull(budgetOf(mapOf("B" to 1.0)))
        assertNull(budgetOf(mapOf("tau" to 1.0)))
        assertNull(budgetOf(mapOf("B" to "x", "tau" to 1.0)))
        assertNull(budgetOf(null))
        assertNull(budgetOf("x"))
        assertNull(budgetOf(5L))
    }

    @Test fun requiredRiskInputsAndTheAdaptivePolicy() {
        val noSem: (Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>? =
            { _, _, _ -> mapOf("reversibility" to 1L, "blastRadius" to 0L, "taint" to 0L, "confidence" to 1L, "age" to 0L) }
        // supplied inputs pass; the plan covers the semantic distance
        val ok = go(input(requireRiskInputs = listOf("taint", "semanticDistance"), risk = noSem))
        eq("pass", ok.checks["risk_inputs"])
        eq("pass", go(input(requireRiskInputs = emptyList())).checks["risk_inputs"])
        assertNull(go(input()).checks["risk_inputs"])
        val lack = go(input(requireRiskInputs = listOf("x", "taint", "y")))
        eq("fail", lack.checks["risk_inputs"])
        assertTrue(lack.reasons.toString(), lack.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: x, y"))
        val lackOne = go(input(requireRiskInputs = listOf("blastRadius"), risk = { _, _, _ -> mapOf("blastRadius" to "x") }))
        assertTrue(lackOne.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: blastRadius"))

        // adaptive: only ever tighter
        val tight = linkedMapOf<String, Any?>(
            "weights" to linkedMapOf<String, Any?>("alpha" to 0L, "beta" to 0L, "gamma" to 0L, "delta" to 0L, "epsilon" to 0L, "zeta" to 0L),
            "theta1" to 0.1, "theta2" to 0.8, "kappa" to 1L, "lambda" to 0L, "rho" to 0L, "bMax" to 1000L,
        )
        var arg: Long? = null
        val a = go(input(adaptivePolicy = { n -> arg = n; tight }), caution(0.3))
        eq(NOW, arg)
        assertFalse(a.allow)
        eq("fail", a.checks["adaptive"])
        assertTrue(a.reasons.toString(), a.reasons.contains("adaptive: tightened policy requires threshold t=2 (grant policy: t=1)"))
        // as strict as the grant's own is no tightening
        val same = LinkedHashMap(tight).also { it["theta1"] = 0.5 }
        val s = go(input(adaptivePolicy = { _ -> same }), caution(0.3))
        assertTrue(s.reasons.toString(), s.allow)
        assertNull(s.checks["adaptive"])
        // looser: no failure either
        val loose = LinkedHashMap(tight).also { it["theta1"] = 0.9; it["theta2"] = 0.95 }
        assertNull(go(input(adaptivePolicy = { _ -> loose }), caution(0.3)).checks["adaptive"])
        // an invalid one fails with the validator's reason; none is nothing
        val invalid = go(input(adaptivePolicy = { _ -> mapOf("theta1" to 1L) }), caution(0.3))
        eq("fail", invalid.checks["adaptive"])
        assertTrue(invalid.reasons.toString(), invalid.reasons.contains("adaptive: invalid policy (risk_policy.weights missing)"))
        assertNull(go(input(adaptivePolicy = { _ -> null }), caution(0.3)).checks["adaptive"])
        assertNull(go(input(), caution(0.3)).checks["adaptive"])
    }

    @Test fun riskStepDirectBoundaries() {
        // a budget that exactly covers the cost is covered; one cent less is not
        val exact = go(input(context = ctxOf("budget" to Risk.Budget(0.3, NOW.toDouble(), NOW.toDouble()))), caution(0.3))
        assertTrue(exact.reasons.toString(), exact.allow)
        assertEquals(0.0, exact.budget!!.B, 1e-12)
        val short = go(input(context = ctxOf("budget" to Risk.Budget(0.29, NOW.toDouble(), NOW.toDouble()))), caution(0.3))
        assertFalse(short.allow)
        assertTrue(short.reasons.toString(), short.reasons.contains("policy: trust budget depleted: human recharge required"))
        // the escalation reason at t = 3 is the step-up one even when the budget is empty
        val high = go(input(context = ctxOf("budget" to Risk.Budget(0.0, NOW.toDouble(), NOW.toDouble()))), caution(0.9))
        assertTrue(high.reasons.toString(), high.reasons.contains("policy: risk 0.900 exceeds auto threshold: step-up to t=3"))
        assertFalse(high.reasons.toString(), high.reasons.contains("policy: trust budget depleted: human recharge required"))
    }

    // ---------------------------------------------------------------- forbid / template / contract pre-guard refusals

    private fun clause(id: String, kind: String, verb: String, signer: String? = null, where: List<Any?>? = null): Map<String, Any?> {
        val w = linkedMapOf<String, Any?>("verb" to verb)
        if (where != null) w["where"] = where
        val m = linkedMapOf<String, Any?>("id" to id, "kind" to kind, "when" to w)
        if (signer != null) m["signer"] = signer
        return m
    }

    @Test fun forbidReceivesTheOperationTheGrantAndItsOptions() {
        val g = g0()
        var grantSeen: Any? = "unset"
        var opSeen: Authorize.Operation? = null
        val permit = clause("p1", "permit", "payments.send")
        val opts = ForbidWins.Options(
            clauses = { o, gr -> opSeen = o; grantSeen = gr; listOf(permit) },
            context = { _ -> mapOf("subject" to mapOf("role" to "admin")) },
        )
        val r = go(input(g = g, forbid = opts))
        assertTrue(r.reasons.toString(), r.allow)
        assertSame(g, grantSeen)
        eq(op(c), opSeen)
        // an unresolvable grant reaches the clause source as null, then the guard refuses
        var grantSeen2: Any? = "unset"
        val r2 = go(input(resolve = { throw IllegalStateException("x") }, forbid = ForbidWins.Options(clauses = { _, gr -> grantSeen2 = gr; listOf(permit) })))
        assertNull(grantSeen2)
        assertFalse(r2.allow)
        assertTrue(r2.reasons.toString(), r2.reason!!.startsWith("resolve_grant:"))
        // a grant_ref that is not a string reaches it as null
        var grantSeen3: Any? = "unset"
        val p = p0().also { it["grant_ref"] = 5L }
        go(input(forbid = ForbidWins.Options(clauses = { _, gr -> grantSeen3 = gr; listOf(permit) })), p)
        assertNull(grantSeen3)
        assertThrows(OutOfMemoryError::class.java) { go(input(resolve = { throw OutOfMemoryError() }, forbid = ForbidWins.Options(clauses = { _, _ -> listOf(permit) }))) }
        // a condition false under the context (admin is not intern) is no veto; a missing one would be
        val cond = listOf(linkedMapOf<String, Any?>("field" to "subject.role", "op" to "eq", "value" to "intern"))
        val withCtx = ForbidWins.Options(
            clauses = { _, _ -> listOf(permit, clause("f1", "forbid", "payments.send", where = cond)) },
            context = { _ -> mapOf("subject" to mapOf("role" to "admin")) },
        )
        val ok = go(input(forbid = withCtx))
        assertTrue(ok.reasons.toString(), ok.allow)
        val noCtx = go(input(forbid = ForbidWins.Options(clauses = { _, _ -> listOf(permit, clause("f1", "forbid", "payments.send", where = cond)) })))
        assertFalse(noCtx.allow)
        eq("forbid: deny by forbid f1", noCtx.reason)
        eq(403, noCtx.status)
    }

    @Test fun forbidPrecedencePermitSignersAndCertificate() {
        // precedence: org outranks user, whatever the ids
        val clauses = listOf(
            clause("p1", "permit", "payments.send"),
            clause("a", "forbid", "payments.send", signer = "user"),
            clause("b", "forbid", "payments.send", signer = "org"),
        )
        val byPrec = go(input(forbid = ForbidWins.Options(clauses = { _, _ -> clauses }, precedence = listOf("org", "user"))))
        eq("forbid: deny by forbid b", byPrec.reason)
        val byId = go(input(forbid = ForbidWins.Options(clauses = { _, _ -> clauses })))
        eq("forbid: deny by forbid a", byId.reason)
        // permitSigners: a permit by another signer is ignored
        val permits = listOf(clause("p1", "permit", "payments.send", signer = "trusted"), clause("p2", "permit", "payments.send", signer = "other"))
        val opts = ForbidWins.Options(clauses = { _, _ -> permits }, permitSigners = listOf("trusted"))
        val ok = go(input(forbid = opts))
        assertTrue(ok.reasons.toString(), ok.allow)
        val rows = ok.forbid!!["clauses"] as List<Map<String, Any?>>
        eq("true", rows.first { it["id"] == "p1" }["value"])
        eq("false", rows.first { it["id"] == "p2" }["value"])
        val onlyOther = go(input(forbid = ForbidWins.Options(clauses = { _, _ -> listOf(permits[1]) }, permitSigners = listOf("trusted"))))
        assertFalse(onlyOther.allow)
        eq("forbid: deny by none", onlyOther.reason)
        // a required certificate recomputed under the same options is accepted; the check uses precedence and permitSigners too
        val withCert = ForbidWins.Options(clauses = { _, _ -> permits }, permitSigners = listOf("trusted"), requireCertificate = true)
        val accepted = go(input(forbid = withCert, forbidCertificate = ok.forbid))
        assertTrue(accepted.reasons.toString(), accepted.allow)
        // missing certificate
        val none = go(input(forbid = withCert))
        eq("forbid: the call carries no certificate (fail closed)", none.reason)
        eq(403, none.status)
        val stale = go(input(forbid = withCert, forbidCertificate = LinkedHashMap(ok.forbid!!).also { it["decision"] = "deny" }))
        assertTrue(stale.reason!!, stale.reason!!.startsWith("forbid: certificate refused ("))
        eq(403, stale.status)
        eq(mapOf("forbid" to "fail"), stale.checks)
    }

    @Test fun templateRefusalsBeforeAndAfterTheGuard() {
        val link: () -> Any? = { LinkedHashMap<String, Any?>() }
        // no readable grant / no envelope / no template_ref
        val noGrant = go(input(resolve = { null }, requireLinkedTemplate = link))
        eq(403, noGrant.status)
        eq("template: the grant has no readable envelope", noGrant.reason)
        eq(mapOf("template" to "fail"), noGrant.checks)
        val noEnv = go(input(g = g0().also { it["caveats"] = ArrayList<Any?>() }, requireLinkedTemplate = link))
        eq("template: the grant has no readable envelope", noEnv.reason)
        val noRef = go(input(requireLinkedTemplate = link))
        eq("template: the grant carries no template_ref", noRef.reason)
        eq(403, noRef.status)
        val nonStringRef = p0().also { it["grant_ref"] = 5L }
        eq("template: the grant has no readable envelope", go(input(requireLinkedTemplate = link), nonStringRef).reason)
        // a grant resolver that throws is the guard's to refuse; a fatal error escapes
        val thrown = go(input(resolve = { throw IllegalStateException("x") }, requireLinkedTemplate = link))
        assertTrue(thrown.reason!!, thrown.reason!!.startsWith("resolve_grant:"))
        assertThrows(OutOfMemoryError::class.java) { go(input(resolve = { throw OutOfMemoryError() }, requireLinkedTemplate = link)) }
        // the commit-time re-check: the first (pre-guard) read throws and is left to the guard, the second one refuses after the counter was spent
        val g = g0().also { envOf(it)["template_ref"] = "t1" }
        var calls = 0
        val store = Authorize.MemoryStateStore()
        val late = go(input(store = store, g = g, requireLinkedTemplate = { calls++; if (calls == 1) throw IllegalStateException("once") else LinkedHashMap<String, Any?>() }))
        assertFalse(late.allow)
        eq(2, calls)
        eq("fail", late.checks["template"])
        eq("template: ${PolicyAuthoring.verifyLinkedPolicy(envOf(g), LinkedHashMap<String, Any?>())}", late.reason)
        eq(403, late.status)
        assertNull(late.template)
        // a registry the policy matches is "linked"
        val calm = go(input(requireLinkedTemplate = null))
        assertNull(calm.template)
    }

    private class FailingKv(val inner: MemoryAtomicKv = MemoryAtomicKv()) : AtomicKv {
        override fun get(key: String): Any? = inner.get(key)
        override fun set(key: String, value: Any?) = inner.set(key, value)
        override fun update(key: String, fn: (Any?) -> Any?): Any? = throw IllegalStateException("down")
    }

    private fun contractOf(vararg invariants: Map<String, Any?>): Pair<Map<String, Any?>, Keys.EdKey> {
        val key = Keys.edGenerate()
        val ct = linkedMapOf<String, Any?>("version" to IntentJs.ofLong(1), "principal" to key.id(), "invariants" to ArrayList<Any?>(invariants.toList()))
        return Contracts.signContract(ct, key.seed) to key
    }

    private fun never(id: String, verb: String): Map<String, Any?> = linkedMapOf("id" to id, "kind" to "never", "when" to linkedMapOf<String, Any?>("verb" to verb))

    @Test fun contractRefusalsBeforeAndAfterTheGuard() {
        // violated before the guard: status 403, check contract, the violated ids joined by a comma, the counter untouched
        val (bad, key) = contractOf(never("i1", "payments.send"), never("i2", "payments.send"))
        val store = Authorize.MemoryStateStore()
        val en = ContractEnforcer.open(MemoryAtomicKv(), bad, key.id(), "k", { 1000.0 }, true)
        val r = go(input(store = store, contracts = en))
        assertFalse(r.allow)
        eq(403, r.status)
        eq(mapOf("contract" to "fail"), r.checks)
        eq("contract: violated (i1,i2)", r.reason)
        assertTrue("the counter was not consumed", go(input(store = store)).allow)
        // a clean contract admits and the enforcer advances
        val (good, gkey) = contractOf(never("i3", "payments.refund"))
        val kv = MemoryAtomicKv()
        val en2 = ContractEnforcer.open(kv, good, gkey.id(), "k", { 1000.0 }, true)
        val ok = go(input(contracts = en2))
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals(1.0, Prohibitions.dv((en2.state()!!["state"] as Map<String, Any?>)["seq"]), 0.0)
        // the commit-time check refuses after the counter was spent (the store fails on the write, the peek read is fine)
        val en3 = ContractEnforcer.open(FailingKv(), good, gkey.id(), "k", { 1000.0 }, true)
        val store3 = Authorize.MemoryStateStore()
        val late = go(input(store = store3, contracts = en3))
        assertFalse(late.allow)
        eq("fail", late.checks["contract"])
        eq("contract: store-error", late.reason)
        eq(403, late.status)
        assertFalse("the counter was spent", go(input(store = store3)).allow)
    }

    @Test fun contractWhyRendersTheViolations() {
        fun why(r: ContractEnforcer.Result): String = KUtil.priv(Authorize, "contractWhy", r)
        eq("violated (a,b)", why(ContractEnforcer.Result(false, "violated", listOf("a", "b"), emptyList(), 0L)))
        eq("violated (a)", why(ContractEnforcer.Result(false, "violated", listOf("a"), emptyList(), 0L)))
        eq("latched", why(ContractEnforcer.Result(false, "latched", emptyList(), emptyList(), 0L)))
    }

    // ---------------------------------------------------------------- containment sites

    @Test fun hostCallbacksThatThrowAreContainedAndFatalErrorsEscape() {
        val oom = OutOfMemoryError()
        fun fatal(label: String, body: () -> Authorize.Result) {
            assertThrows(label, OutOfMemoryError::class.java) { body() }
        }
        fun contained(label: String, body: () -> Authorize.Result): Authorize.Result {
            val r = body()
            assertFalse(label, r.allow)
            return r
        }
        // the context callback
        fatal("context") { go(input(context = { throw oom })) }
        eq("context: the context callback failed (fail closed)", contained("context") { go(input(context = { throw IllegalStateException("x") })) }.reason)
        // the Intent v2 state callback
        fatal("intentV2") { go(input(intentV2 = { throw oom })) }
        eq("intent_v2: verifier state unavailable (fail closed)", contained("intentV2") { go(input(intentV2 = { throw IllegalStateException("x") })) }.reason)
        // the principal resolver
        fatal("principal") { go(input(resolvePrincipal = { _, _ -> throw oom })) }
        // the beacon supplier
        fatal("beacon") { go(input(beacon = { _, _ -> throw oom })) }
        // the beacon pin read and write
        val readStore = Wrap().also { it.onLast = { k -> if (k.endsWith(":beacon")) throw oom else it.inner.last(k) } }
        fatal("beacon last") { withBeacon(readStore, beaconOf(5)) }
        val writeStore = Wrap().also { it.onClaim = { k, n -> if (k.endsWith(":beacon")) throw oom else it.inner.claim(k, n) } }
        fatal("beacon claim") { withBeacon(writeStore, beaconOf(5)) }
        // the provenance configuration
        fatal("provenance facts") { go(input(provenanceOptions = Authorize.ProvenanceOptions(actions = { throw oom }))) }
        val pf = contained("provenance facts") { go(input(provenanceOptions = Authorize.ProvenanceOptions(actions = { throw IllegalStateException("x") }))) }
        assertTrue(pf.reasons.toString(), pf.reasons.contains("provenance_flow: the provenance configuration failed (fail closed)"))
        // the replay head read in the failing-checks branch, the claim and the escalation callbacks
        inject("validity", "x") // not "revocation": authorize re-marks that check after the core hook, so no check would fail
        val headStore = Wrap().also { it.onLast = { _ -> throw oom } }
        fatal("deny head") { Authorize.authorize(p0(), input(store = headStore)) }
        val headOk = Wrap().also { it.onLast = { _ -> throw IllegalStateException("x") } }
        assertFalse(Authorize.authorize(p0(), input(store = headOk)).allow)
        inject("tighten", "escalate: asked by tighten rule 'a'")
        fatal("escalation render") { Authorize.authorize(p0(), input(escalationRender = { throw oom })) }
        val rendered = Authorize.authorize(p0(), input(escalationRender = { throw IllegalStateException("x") }))
        eq("escalate", rendered.decision)
        fatal("undo admit") { Authorize.authorize(p0(), input(undo = Authorize.UndoHook { _, _, _ -> throw oom })) }
        val undone = Authorize.authorize(p0(), input(undo = Authorize.UndoHook { _, _, _ -> throw IllegalStateException("x") }))
        eq("escalate", undone.decision)
        assertNull(undone.undo)
        neutral()
        val claimStore = Wrap().also { it.onClaim = { _, _ -> throw oom } }
        fatal("claim") { Authorize.authorize(p0(), input(store = claimStore)) }
        val claimOk = Wrap().also { it.onClaim = { _, _ -> throw IllegalStateException("x") } }
        val cr = Authorize.authorize(p0(), input(store = claimOk))
        assertFalse(cr.allow)
        assertTrue(cr.reasons.toString(), cr.reasons.contains("replay: the replay store failed (fail closed)"))
    }

    @Test fun evaluateAgentCaveatsFailsWhatItCannotSatisfy() {
        val ctx = linkedMapOf<String, Any?>("now" to NOW)
        val r = Authorize.evaluateAgentCaveats(listOf(linkedMapOf<String, Any?>("type" to "no-such-type")), ctx)
        assertFalse(r.ok)
        eq(listOf("no-such-type"), r.failed)
        val r2 = Authorize.evaluateAgentCaveats(listOf(5L, linkedMapOf<String, Any?>("type" to "predicates", "allow" to listOf<Any?>())), ctx, linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to "v", "resource" to "r")))
        eq(listOf("<malformed>", "predicates"), r2.failed)
    }

    // ---------------------------------------------------------------- the epoch pin key

    @Test fun theEpochPinKeyIsTheGrantIdWithASuffix() {
        eq("g1:epoch", Authorize.epochPinKey("g1"))
        assertNull(Authorize.epochPinKey(5L))
        assertNull(Authorize.epochPinKey(null))
        eq(":epoch", Authorize.epochPinKey(""))
    }
}
