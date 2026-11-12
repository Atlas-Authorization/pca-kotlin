package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Mutation kills for the wiring inside `Authorize.authorizeUnchecked`: the passport clock and options, the forbid-wins options, the
 * non-string members of an unverified proof, rethrown fatal errors, the pq pin, the principal resolver, the freshness gate, the
 * liveness beacon, the revocation epoch pin, the risk step, the threshold hook, the adaptive policy and the linked template.
 */
@Suppress("UNCHECKED_CAST")
class AuthorizeWiringKillTest {
    @After fun reset() { Authorize.coreHook = null }

    private val c = case("envelope-predicate-within")
    private val allowCase get() = case("envelope-max-spend-within")
    private val gid get() = grant(c)["id"] as String

    private fun neutral() {
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
    }

    /** The Input of the neutral-core fixture with every option the tests below vary. */
    private fun inp(
        store: Authorize.StateStore = Authorize.MemoryStateStore(),
        grantMap: Map<String, Any?> = AuthorizeTestKit.grant(c),
        resolveGrant: ((String) -> Map<String, Any?>?)? = { grantMap },
        isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)? = { _, _ -> false },
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        risk: ((Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>?)? = AuthorizeTestKit.calmRisk,
        plan: String? = Authorize.SINGLE_STEP,
        staleness: Revocation.StalenessPolicy? = null,
        freshness: Authorize.FreshnessGate? = null,
        beacon: ((String, Map<String, Any?>) -> Beacons.Supplied?)? = null,
        pqPins: Map<String, Any?>? = null,
        resolvePrincipal: ((String, Map<String, Any?>) -> Authorize.PrincipalInfo?)? = null,
        thresholdHook: ((Map<String, Any?>, Map<String, Any?>) -> Authorize.ThresholdResult?)? = null,
        adaptivePolicy: ((Long) -> Map<String, Any?>?)? = null,
        requirePassport: Authorize.PassportRequirement? = null,
        passport: Any? = null,
        requireLinkedTemplate: (() -> Any?)? = null,
        forbid: ForbidWins.Options? = null,
        workflow: Authorize.WorkflowGate? = null,
        plans: PlanLifecycle.PlanRegistry? = null,
    ): Authorize.Input {
        val b = input(c, stateStore = store)
        return Authorize.Input(
            operation = b.operation, audience = b.audience, resolveGrant = resolveGrant, stateStore = store, isRevoked = isRevoked, now = b.now,
            plan = plan, context = context, revocationStaleness = staleness, plans = plans, workflow = workflow,
            provenanceOptions = b.provenanceOptions, provenance = b.provenance, pqPins = pqPins, risk = risk, thresholdHook = thresholdHook,
            adaptivePolicy = adaptivePolicy, enforceFreshness = freshness, beacon = beacon, resolvePrincipal = resolvePrincipal,
            requirePassport = requirePassport, passport = passport, requireLinkedTemplate = requireLinkedTemplate, forbid = forbid,
        )
    }

    /** A copy of the fixture proof (numbers normalised, so members can be put) run under the neutral core. */
    private fun attempt(
        edit: (MutableMap<String, Any?>) -> Unit = {},
        store: Authorize.StateStore = Authorize.MemoryStateStore(),
        grantMap: Map<String, Any?> = AuthorizeTestKit.grant(c),
        isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)? = { _, _ -> false },
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        risk: ((Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>?)? = AuthorizeTestKit.calmRisk,
        plan: String? = Authorize.SINGLE_STEP,
        staleness: Revocation.StalenessPolicy? = null,
        freshness: Authorize.FreshnessGate? = null,
        beacon: ((String, Map<String, Any?>) -> Beacons.Supplied?)? = null,
        pqPins: Map<String, Any?>? = null,
        resolvePrincipal: ((String, Map<String, Any?>) -> Authorize.PrincipalInfo?)? = null,
        thresholdHook: ((Map<String, Any?>, Map<String, Any?>) -> Authorize.ThresholdResult?)? = null,
        adaptivePolicy: ((Long) -> Map<String, Any?>?)? = null,
        requireLinkedTemplate: (() -> Any?)? = null,
    ): Authorize.Result {
        neutral()
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        edit(p)
        return Authorize.authorize(
            p,
            inp(
                store = store, grantMap = grantMap, isRevoked = isRevoked, context = context, risk = risk, plan = plan, staleness = staleness, freshness = freshness,
                beacon = beacon, pqPins = pqPins, resolvePrincipal = resolvePrincipal, thresholdHook = thresholdHook, adaptivePolicy = adaptivePolicy,
                requireLinkedTemplate = requireLinkedTemplate,
            ),
        )
    }

    private fun grantWith(vararg kv: Pair<String, Any?>): Map<String, Any?> = LinkedHashMap(grant(c)).also { for ((k, v) in kv) it[k] = v }

    // ---- agent caveats and the contract option

    @Test fun anAgentToolCallReachesTheToolSchemaCaveat() {
        val schema = Json.parse("""{"props":{"n":{"type":"integer","min":0,"max":10}},"required":["n"]}""")
        val cv = linkedMapOf<String, Any?>(
            "type" to "tool_schema", "tool" to "pay", "signature_digest" to "sig", "schema" to schema, "schema_digest" to Pca.hashCanonical(schema),
            "binding_digest" to Pca.hashCanonical(linkedMapOf("tool" to "pay", "signature_digest" to "sig", "schema" to schema)),
        )
        val ctx = mapOf<String, Any?>("now" to 1)
        val call = mapOf<String, Any?>("tool" to "pay", "args" to mapOf("n" to 3), "tool_signature_digest" to "sig")
        assertEquals(Caveats.Result(true, emptyList()), Authorize.evaluateAgentCaveats(listOf(cv), ctx, null, call))
        assertEquals(Caveats.Result(false, listOf("tool_schema")), Authorize.evaluateAgentCaveats(listOf(cv), ctx, null, null))
        assertEquals(Caveats.Result(false, listOf("tool_schema")), Authorize.evaluateAgentCaveats(listOf(cv), ctx, null, mapOf("tool" to "other", "args" to mapOf("n" to 3))))
    }

    @Test fun theOptionsCarryTheContractEnforcerIntoTheInput() {
        val ac = allowCase
        val key = Keys.edGenerate()
        val invariant = linkedMapOf<String, Any?>("id" to "i1", "kind" to "never", "when" to linkedMapOf<String, Any?>("verb" to "payments.send"))
        val contract = Contracts.signContract(
            linkedMapOf<String, Any?>("version" to IntentJs.ofLong(1), "principal" to key.id(), "invariants" to arrayListOf<Any?>(invariant)), key.seed,
        )
        val en = ContractEnforcer.open(MemoryAtomicKv(), contract, key.id(), "k", { 1000.0 }, true)
        val o = Authorize.AuthorizeOptions(
            stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, plan = Authorize.SINGLE_STEP, provenance = ProvHarness.options,
            risk = AuthorizeTestKit.calmRisk, contracts = en,
        )
        assertSame(en, o.contracts)
        val r = o.run(pcactn(ac), AuthorizeTestKit.op(ac), AuthorizeTestKit.AUD, { grant(ac) }, now = NOW, provenance = ProvHarness.bundle(AuthorizeTestKit.op(ac)))
        assertFalse(r.allow)
        assertEquals("contract: violated (i1)", r.reason)
    }

    // ---- the passport

    private val issuerKey = Keys.edGenerate()

    private fun leafOf(ac: Map<String, Any?>): String = ((pcactn(ac)["cap_chain"] as List<Any?>).last() as Map<String, Any?>)["holder"] as String

    private fun softwareBody(sub: String, nbf: Long, exp: Long, iss: String = issuerKey.id(), hardware: Boolean = false, evidenceAt: Long? = null): LinkedHashMap<String, Any?> {
        val ident = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to hardware)
        ident["id"] = Passport.fingerprint(ident)
        val body = linkedMapOf<String, Any?>(
            "typ" to "atlas-pca/passport", "ver" to 1L, "passport" to ident, "iss" to iss, "sub" to sub, "iat" to nbf, "nbf" to nbf, "exp" to exp,
        )
        if (hardware) body["evidence"] = mapOf("document" to mapOf("nonce" to "n1"), "at" to evidenceAt!!)
        return body
    }

    private fun edSigned(body: Map<String, Any?>): Map<String, Any?> {
        val signed = LinkedHashMap(body)
        signed["sig"] = Pca.b64(issuerKey.sign(IntentJs.message(Passport.SIG_DOMAIN, body)))
        return signed
    }

    private fun runPassport(ac: Map<String, Any?>, req: Authorize.PassportRequirement, doc: Any?): Authorize.Result {
        val base = input(ac)
        return Authorize.authorize(
            pcactn(ac),
            Authorize.Input(
                operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = base.stateStore, isRevoked = base.isRevoked, now = base.now,
                plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk,
                requirePassport = req, passport = doc,
            ),
        )
    }

    private val measured = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to true)
    private val okAttester: HardwareAttester = { _, _ -> Attest.Result(true, true, "", measured) }

    @Test fun thePassportClockDefaultsToTheWallClock() {
        val ac = allowCase
        val real = System.currentTimeMillis()
        val doc = edSigned(softwareBody(leafOf(ac), real - 60_000, real + 3_600_000))
        val r = runPassport(ac, Authorize.PassportRequirement(listOf(issuerKey.id()), { _, _, _ -> false }), doc)
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("software", (r.assurance["passport"] as Map<String, Any?>)["level"])
    }

    @Test fun thePassportOptionsReachTheVerifier() {
        val ac = allowCase
        val leaf = leafOf(ac)
        val iss = listOf(issuerKey.id())
        val revokedNever: (String, String, String) -> Boolean = { _, _, _ -> false }
        // a revoked passport is refused
        val soft = edSigned(softwareBody(leaf, NOW - 1000, NOW + 600_000))
        assertEquals("passport: revoked", runPassport(ac, Authorize.PassportRequirement(iss, { _, _, _ -> true }, now = { NOW }), soft).reason)
        // the clock skew tolerates a passport that is not yet valid by a little
        val early = edSigned(softwareBody(leaf, NOW + 500, NOW + 600_000))
        assertEquals("passport: not_yet_valid", runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, now = { NOW }), early).reason)
        val skewed = runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, clockSkewMs = 1000L, now = { NOW }), early)
        assertTrue(skewed.reasons.toString(), skewed.allow)
        // the evidence age cap
        val hw = edSigned(softwareBody(leaf, NOW - 1000, NOW + 600_000, hardware = true, evidenceAt = NOW - 5000))
        assertEquals(
            "passport: hardware_evidence_stale",
            runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, hardware = true, maxEvidenceAgeMs = 1000L, attest = okAttester, now = { NOW }), hw).reason,
        )
        val fresh = runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, hardware = true, maxEvidenceAgeMs = 10_000L, attest = okAttester, now = { NOW }), hw)
        assertTrue(fresh.reasons.toString(), fresh.allow)
        // the built-in vendor verifier when the integrator gives none
        val vendor = Attest.VendorVerifier(
            "amd-sev-snp",
            object : Attest.VendorImpl {
                override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = Attest.Result(true, true, "", measured)
            },
            null,
        )
        val viaDefault = runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, hardware = true, defaultHardware = Attest.DefaultHardware(vendor), now = { NOW }), hw)
        assertTrue(viaDefault.reasons.toString(), viaDefault.allow)
        assertEquals("passport: hardware_verifier_missing", runPassport(ac, Authorize.PassportRequirement(iss, revokedNever, hardware = true, now = { NOW }), hw).reason)
    }

    @Test fun aPostQuantumPassportVerifiesOnlyUnderTheRequirementsPins() {
        val ac = allowCase
        val gen = MLDSAKeyPairGenerator()
        gen.init(MLDSAKeyGenerationParameters(java.security.SecureRandom(), MLDSAParameters.ml_dsa_65))
        val kp = gen.generateKeyPair()
        val pk = Pca.b64((kp.public as MLDSAPublicKeyParameters).encoded)
        val iss = issuerKey.id()
        val body = softwareBody(leafOf(ac), NOW - 1000, NOW + 600_000, iss = iss)
        body["alg"] = "ml-dsa-65"
        body["pq_pk"] = pk
        val msg = IntentJs.message(Passport.SIG_DOMAIN, body)
        val signer = MLDSASigner()
        signer.init(true, kp.private as MLDSAPrivateKeyParameters)
        signer.update(msg, 0, msg.size)
        val doc = LinkedHashMap(body)
        doc["sig"] = Pca.b64(signer.generateSignature())
        val pinned = Authorize.PassportRequirement(listOf(iss), { _, _, _ -> false }, pqPins = mapOf(iss to pk), now = { NOW })
        val r = runPassport(ac, pinned, doc)
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("passport: bad_signature", runPassport(ac, Authorize.PassportRequirement(listOf(iss), { _, _, _ -> false }, now = { NOW }), doc).reason)
    }

    @Test fun anUnreadableProofHasNoPassportSubject() {
        neutral()
        val req = Authorize.PassportRequirement(listOf("x"), { _, _, _ -> false })
        val variants = listOf<Any?>(
            null,
            mapOf<String, Any?>(),
            mapOf("cap_chain" to "x"),
            mapOf("cap_chain" to emptyList<Any?>()),
            mapOf("cap_chain" to listOf("x")),
            mapOf("cap_chain" to listOf(mapOf("id" to "h"))),
            mapOf("cap_chain" to listOf(mapOf("holder" to 5L))),
        )
        for (v in variants) {
            val r = Authorize.authorize(v, inp(requirePassport = req, passport = mapOf("typ" to "other")))
            assertFalse("$v", r.allow)
            assertFalse("$v: ${r.reasons}", r.checks.containsKey("passport"))
            assertFalse("$v: ${r.reasons}", r.reasons.any { it.startsWith("authorize:") })
        }
    }

    // ---- forbid-wins

    private fun clause(id: String, kind: String, signer: String?, verb: String): Map<String, Any?> {
        val c = linkedMapOf<String, Any?>("id" to id, "kind" to kind)
        if (signer != null) c["signer"] = signer
        c["when"] = linkedMapOf<String, Any?>("verb" to verb)
        return c
    }

    private fun forbidInput(ac: Map<String, Any?>, opts: ForbidWins.Options, cert: Any? = null): Authorize.Input {
        val base = input(ac)
        return Authorize.Input(
            operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = base.stateStore, isRevoked = base.isRevoked, now = base.now,
            plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk, forbid = opts, forbidCertificate = cert,
        )
    }

    private fun actionCtx(ac: Map<String, Any?>, extra: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val op = AuthorizeTestKit.op(ac)
        val m = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to op.verb, "resource" to op.resource, "params" to Json.parse(Json.canonicalize(op.params))))
        m.putAll(extra)
        return m
    }

    @Test fun theForbidOptionsReachDecisionCertificateAndCheck() {
        val ac = allowCase
        val verb = AuthorizeTestKit.op(ac).verb
        val clauses = listOf(clause("p1", "permit", "s1", verb), clause("p2", "permit", "s2", verb))
        // the signers allowed to permit, and the context merged into the action context
        val withCtx = ForbidWins.Options(clauses = { _, _ -> clauses }, context = { mapOf("env" to mapOf("k" to "v")) }, permitSigners = listOf("s1"))
        val r = Authorize.authorize(pcactn(ac), forbidInput(ac, withCtx))
        assertTrue(r.reasons.toString(), r.allow)
        val want = ForbidWins.certify(clauses, actionCtx(ac, mapOf("env" to mapOf("k" to "v"))), null, listOf("s1"))
        assertEquals(Pca.hashCanonical(want), Pca.hashCanonical(r.forbid))
        // a context callback that returns nothing leaves the action context alone
        val nullCtx = ForbidWins.Options(clauses = { _, _ -> clauses }, context = { null }, permitSigners = listOf("s1"))
        val r2 = Authorize.authorize(pcactn(ac), forbidInput(ac, nullCtx))
        assertTrue(r2.reasons.toString(), r2.allow)
        assertEquals(Pca.hashCanonical(ForbidWins.certify(clauses, actionCtx(ac), null, listOf("s1"))), Pca.hashCanonical(r2.forbid))
        // the certificate the call carries is recomputed with the same permit signers
        val plain = ForbidWins.Options(clauses = { _, _ -> clauses }, permitSigners = listOf("s1"))
        val cert = Authorize.authorize(pcactn(ac), forbidInput(ac, plain)).forbid
        val required = ForbidWins.Options(clauses = { _, _ -> clauses }, permitSigners = listOf("s1"), requireCertificate = true)
        val ok = Authorize.authorize(pcactn(ac), forbidInput(ac, required, cert = cert))
        assertTrue(ok.reasons.toString(), ok.allow)
    }

    @Test fun theForbidPrecedenceReachesTheCertificateCheck() {
        val ac = allowCase
        val verb = AuthorizeTestKit.op(ac).verb
        val prec = listOf("s2", "s1")
        val denying = listOf(clause("fa", "forbid", "s1", verb), clause("fb", "forbid", "s2", verb), clause("p", "permit", null, verb))
        val denyCert = ForbidWins.certify(denying, actionCtx(ac), prec, null)
        assertTrue(ForbidWins.consistent(denyCert, prec))
        assertFalse(ForbidWins.consistent(denyCert, emptyList()))
        val opts = ForbidWins.Options(clauses = { _, _ -> listOf(clause("p", "permit", null, verb)) }, precedence = prec, requireCertificate = true)
        val r = Authorize.authorize(pcactn(ac), forbidInput(ac, opts, cert = denyCert))
        assertFalse(r.allow)
        assertEquals("forbid: certificate refused (certificate does not match the recomputed decision)", r.reason)
    }

    @Test fun theClauseSourceSeesTheGrantOnlyWhenTheProofNamesOne() {
        neutral()
        val seen = ArrayList<Map<String, Any?>?>()
        val opts = ForbidWins.Options(clauses = { _, g -> seen.add(g); emptyList() })
        fun go(p: Any?): Map<String, Any?>? {
            seen.clear()
            Authorize.authorize(p, inp(forbid = opts))
            return seen.single()
        }
        assertNull(go(null))
        assertNull(go(mapOf<String, Any?>()))
        assertNull(go(mapOf("grant_ref" to 5L)))
        assertSame(grant(c), go(pcactn(c)))
    }

    // ---- fatal errors are never swallowed

    @Test fun aFatalErrorFromTheGrantResolverIsRethrownInTheForbidStep() {
        neutral()
        try {
            Authorize.authorize(pcactn(c), inp(forbid = ForbidWins.Options(clauses = { _, _ -> emptyList() }), resolveGrant = { throw InternalError("fatal") }))
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    @Test fun aFatalErrorFromTheGrantResolverIsRethrownInTheTemplateStep() {
        neutral()
        try {
            Authorize.authorize(
                pcactn(c),
                inp(requireLinkedTemplate = { emptyMap<String, Any?>() }, workflow = Authorize.WorkflowGate(null, null, required = true), resolveGrant = { throw InternalError("fatal") }),
            )
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    @Test fun aFatalErrorFromThePlanRegistryIsRethrown() {
        neutral()
        val kv = object : AtomicKv {
            override fun get(key: String): Any? = throw InternalError("fatal")
            override fun set(key: String, value: Any?) {}
            override fun update(key: String, fn: (Any?) -> Any?): Any? = null
        }
        try {
            Authorize.authorize(pcactn(c), inp(plans = PlanLifecycle.PlanRegistry(kv = kv)))
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    private class ThrowingLastStore(private val inner: Authorize.MemoryStateStore = Authorize.MemoryStateStore()) : Authorize.StateStore by inner, Authorize.LastStore {
        override fun last(key: String): Long? = throw InternalError("fatal")
    }

    // ---- the linked template

    @Test fun aLinkedTemplateAllowCarriesTheLinkAndAnOrdinaryOneDoesNot() {
        val key = Keys.edGenerate()
        val g = LinkedHashMap(grant(c))
        val cavs = g["caveats"] as List<Any?>
        val env = LinkedHashMap(cavs[0] as Map<String, Any?>)
        val def = linkedMapOf<String, Any?>(
            "v" to IntentJs.ofLong(1), "kind" to "pca-policy-template", "id" to "tpl", "version" to "1", "slots" to linkedMapOf<String, Any?>(),
            "body" to linkedMapOf<String, Any?>("predicates" to env["predicates"], "caveats" to env["caveats"]),
        )
        val digest = PolicyAuthoring.templateDigest(def)
        val sigMsg = Pca.concat(IntentJs.utf8("atlas-pca/policy-template/v1\u0000"), java.security.MessageDigest.getInstance("SHA-256").digest(IntentJs.utf8(digest)))
        val registry = linkedMapOf<String, Any?>(
            "templates" to linkedMapOf<String, Any?>(digest to linkedMapOf<String, Any?>("def" to def, "signer" to key.id(), "sig" to Pca.b64(key.sign(sigMsg)))),
            "trusted" to listOf(key.id()),
        )
        env["template_ref"] = linkedMapOf<String, Any?>("template_id" to "tpl", "version_digest" to digest, "slots" to linkedMapOf<String, Any?>())
        g["caveats"] = listOf<Any?>(env) + cavs.drop(1)
        val linked = attempt(grantMap = g, requireLinkedTemplate = { registry })
        assertTrue(linked.reasons.toString(), linked.allow)
        assertEquals("linked", linked.template)
        val plain = attempt()
        assertTrue(plain.reasons.toString(), plain.allow)
        assertNull(plain.template)
    }

    // ---- the pq pin and the principal resolver

    @Test fun theGrantAlgorithmAndIssuerAreReadDefensively() {
        // a non-string alg reads as the default ed25519
        val r = attempt(grantMap = grantWith("alg" to 5L), pqPins = emptyMap())
        assertEquals("pass", r.checks["pq_pin"])
        assertFalse(r.reasons.toString(), r.reasons.any { it.startsWith("authorize:") })
        // an issuer-less grant is looked up in no pin at all (this map refuses a null lookup)
        val strict = java.util.concurrent.ConcurrentHashMap<String, Any>()
        val noIssuer = LinkedHashMap(grant(c)).also { it.remove("issuer") }
        val r2 = attempt(grantMap = noIssuer, pqPins = strict)
        assertEquals("pass", r2.checks["pq_pin"])
        assertFalse(r2.reasons.toString(), r2.reasons.any { it.startsWith("authorize:") })
    }

    @Test fun thePrincipalResolverIsGivenAnEmptyIssuerWhenTheGrantNamesNone() {
        val seen = ArrayList<String?>()
        val resolver: (String, Map<String, Any?>) -> Authorize.PrincipalInfo? = { iss, _ -> seen.add(iss); Authorize.PrincipalInfo(true) }
        val nonString = attempt(grantMap = grantWith("issuer" to 5L), resolvePrincipal = resolver)
        assertEquals("pass", nonString.checks["principal"])
        val none = attempt(grantMap = LinkedHashMap(grant(c)).also { it.remove("issuer") }, resolvePrincipal = resolver)
        assertEquals("pass", none.checks["principal"])
        assertEquals(listOf<String?>("", ""), seen)
    }

    // ---- enforce.freshness

    private val epochNow = Math.floorDiv(NOW, 60_000L)

    private fun anchor(epoch: Long, ref: Any? = "ref"): (MutableMap<String, Any?>) -> Unit =
        { it["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to ref, "epoch" to IntentJs.ofLong(epoch)) }

    @Test fun theFreshnessGateSkewAndBoundsAreExact() {
        // skew: an anchor 2 s ahead of the gate's clock passes with 5 s of skew and is refused without
        val skewed = attempt(anchor(12), freshness = Authorize.FreshnessGate(200_000.0, epochMs = 1000.0, now = 10_000L, clockSkewMs = 5000.0))
        assertEquals(skewed.reasons.toString(), "pass", skewed.checks["freshness"])
        val bare = attempt(anchor(12), freshness = Authorize.FreshnessGate(200_000.0, epochMs = 1000.0, now = 10_000L))
        assertTrue(bare.reasons.toString(), bare.reasons.contains("freshness: freshness anchor is in the future"))
        // an epoch length and a maximum age below one are valid
        val tiny = attempt(anchor(20_000), freshness = Authorize.FreshnessGate(0.5, epochMs = 0.5, now = 10_000L))
        assertEquals(tiny.reasons.toString(), "pass", tiny.checks["freshness"])
        // a beacon_ref that is not a string is a missing anchor
        val missing = "freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
        val bad = attempt(anchor(epochNow - 1, ref = 5L), freshness = Authorize.FreshnessGate(200_000.0))
        assertTrue(bad.reasons.toString(), bad.reasons.contains(missing))
        // an enforce.freshness verdict is never overwritten by the staleness step that has no state
        val pol = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true, ids = { emptyList() })
        val kept = attempt(anchor(epochNow - 1), freshness = Authorize.FreshnessGate(200_000.0), staleness = pol)
        assertEquals(kept.reasons.toString(), "pass", kept.checks["freshness"])
    }

    // ---- the liveness beacon

    private val beaconKey = Keys.edGenerate()
    private val issued = NOW - 120_000L

    private fun beaconBody(scope: String, seq: Long, issuer: String): LinkedHashMap<String, Any?> = linkedMapOf(
        "v" to IntentJs.ofLong(2), "instance" to "inst", "scope" to scope, "epoch" to IntentJs.ofLong(Math.floorDiv(issued, Beacons.EPOCH_MS)), "seq" to IntentJs.ofLong(seq),
        "issued_at" to IntentJs.ofLong(issued), "not_after" to IntentJs.ofLong(issued + 300_000L), "issuer" to issuer,
    )

    private fun edBeacon(scope: String, seq: Long): Map<String, Any?> {
        val b = beaconBody(scope, seq, beaconKey.id())
        val msg = Pca.concat(IntentJs.utf8("atlas-pca/beacon/v2\u0000"), IntentJs.canonBytes(b))
        return LinkedHashMap(b).also { it["sig"] = Pca.b64(beaconKey.sign(msg)) }
    }

    private fun withBeacon(store: Authorize.StateStore, b: Map<String, Any?>, supplied: Beacons.Supplied, grantMap: Map<String, Any?> = AuthorizeTestKit.grant(c)): Authorize.Result =
        attempt(anchor(1, Beacons.beaconRef(b)), store = store, grantMap = grantMap, beacon = { _, _ -> supplied })

    @Test fun aBeaconIsScopedToTheGrantAndItsPinIsKeyedByAStringGrantId() {
        val own = edBeacon(gid, 5)
        val supplied = Beacons.Supplied(own, listOf(beaconKey.id()), "inst")
        val ok = withBeacon(Authorize.MemoryStateStore(), own, supplied)
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["beacon"])
        val other = edBeacon("some-other-grant", 5)
        val refused = withBeacon(Authorize.MemoryStateStore(), other, Beacons.Supplied(other, listOf(beaconKey.id()), "inst"))
        assertFalse(refused.allow)
        assertTrue(refused.reasons.toString(), refused.reasons.contains("beacon: scope not covered"))
        // a grant whose id is not a string has no sequence pin to read and no scope to check
        val seeded = Authorize.MemoryStateStore()
        seeded.claim("5:beacon", 100)
        val global = edBeacon("*", 5)
        val odd = withBeacon(seeded, global, Beacons.Supplied(global, listOf(beaconKey.id()), "inst"), grantMap = grantWith("id" to 5L))
        assertEquals(odd.reasons.toString(), "pass", odd.checks["beacon"])
        assertFalse(odd.reasons.toString(), odd.reasons.any { it.startsWith("authorize:") || it.contains("replay") })
    }

    @Test fun aPostQuantumBeaconVerifiesUnderTheSuppliedPins() {
        val gen = MLDSAKeyPairGenerator()
        gen.init(MLDSAKeyGenerationParameters(java.security.SecureRandom(), MLDSAParameters.ml_dsa_65))
        val kp = gen.generateKeyPair()
        val pk = Pca.b64((kp.public as MLDSAPublicKeyParameters).encoded)
        val issuer = "pq-beacon-issuer"
        val b = beaconBody("*", 5, issuer)
        b["alg"] = "ml-dsa-65"
        b["pq_pk"] = pk
        val msg = Pca.concat(IntentJs.utf8("atlas-pca/beacon/v2\u0000"), IntentJs.canonBytes(b))
        val signer = MLDSASigner()
        signer.init(true, kp.private as MLDSAPrivateKeyParameters)
        signer.update(msg, 0, msg.size)
        val signed = LinkedHashMap(b)
        signed["sig"] = Pca.b64(signer.generateSignature())
        val pinned = withBeacon(Authorize.MemoryStateStore(), signed, Beacons.Supplied(signed, listOf(issuer), "inst", mapOf(issuer to pk)))
        assertEquals(pinned.reasons.toString(), "pass", pinned.checks["beacon"])
        val unpinned = withBeacon(Authorize.MemoryStateStore(), signed, Beacons.Supplied(signed, listOf(issuer), "inst"))
        assertFalse(unpinned.allow)
        assertTrue(unpinned.reasons.toString(), unpinned.reasons.contains("beacon: bad signature"))
    }

    // ---- the revocation epoch pin

    private val stale: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guardian: String get() = stale["guardian_public"] as String

    private fun signedEpoch(epochNo: Long): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to (pcactn(c)["grant_ref"] as String), "epoch" to epochNo, "set_size" to 0L, "root" to IntentRevocation.revsetRoot(emptyList()),
            "issued_at" to NOW - 1000, "not_after" to NOW - 1000 + 600_000L,
        )
        val seed = ByteArray(32) { 11 }
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + seed
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        return LinkedHashMap(body).also { it["guardian"] = guardian; it["sig"] = Pca.b64(sig.sign()) }
    }

    private fun epochPolicy() = Revocation.StalenessPolicy(guardianPublic = guardian, proofFor = { _, _ -> linkedMapOf("size" to 0L) })

    private fun epochAttempt(state: Any?, store: Authorize.StateStore, pol: Revocation.StalenessPolicy = epochPolicy()): Authorize.Result =
        attempt(edit = { it["freshness"] = linkedMapOf<String, Any?>("beacon_ref" to "ref", "epoch" to IntentJs.ofLong(100)) }, store = store, staleness = pol, context = { mapOf("revocation_state" to state, "reversibility_class" to "reversible") })

    private fun pinned(n: Long): Authorize.MemoryStateStore = Authorize.MemoryStateStore().also { it.claim(Authorize.epochPinKey(gid)!!, n) }

    @Test fun theStoredEpochPinFloorsTheSuppliedLastAcceptedEpoch() {
        // no supplied floor: the stored pin (5) is the floor
        val ok = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6)), pinned(5))
        assertEquals(ok.reasons.toString(), "pass", ok.checks["freshness"])
        val below = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(4)), pinned(5))
        assertEquals("fail", below.checks["freshness"])
        assertTrue(below.reasons.toString(), below.reasons.any { it.contains("is older than the last accepted 5 (rollback)") })
        // a supplied floor above the pin wins
        val higher = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6), "last_accepted_epoch" to 7L), pinned(5))
        assertEquals("fail", higher.checks["freshness"])
        assertTrue(higher.reasons.toString(), higher.reasons.any { it.contains("is older than the last accepted 7 (rollback)") })
        // a supplied floor below the pin does not lower it
        val lower = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(4), "last_accepted_epoch" to 1L), pinned(5))
        assertEquals("fail", lower.checks["freshness"])
        // a supplied root is still compared with the signed epoch's when a pin exists
        val mismatch = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6), "root" to "not-the-root"), pinned(5))
        assertEquals("fail", mismatch.checks["freshness"])
        assertTrue(mismatch.reasons.toString(), mismatch.reasons.any { it.contains("revocation root does not match the signed epoch") })
    }

    @Test fun aRootStateIsNotTouchedByTheEpochPin() {
        val pol = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true, irreversibleMs = 10_000.0, ids = { emptyList() })
        val state = linkedMapOf<String, Any?>("kind" to "root", "root" to "r", "issued_at" to NOW - 10_000)
        val r = epochAttempt(state, pinned(3), pol)
        assertEquals(r.reasons.toString(), "pass", r.checks["freshness"])
    }

    @Test fun aFatalErrorWhileReadingTheEpochPinIsRethrown() {
        try {
            epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6)), ThrowingLastStore())
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    // ---- a failing check does not read a replay counter that is not a safe integer

    @Test fun aNonIntegerCounterIsNoReplayEvidence() {
        val store = Authorize.MemoryStateStore()
        val holder = ((pcactn(c)["cap_chain"] as List<Any?>).last() as Map<String, Any?>)["holder"] as String
        store.claim(Authorize.stateKey(gid, holder), 5)
        val r = attempt(edit = { it["counter"] = "abc" }, store = store, isRevoked = { _, _ -> true })
        assertFalse(r.allow)
        assertFalse(r.reasons.toString(), r.reasons.any { it.startsWith("replay:") || it.startsWith("authorize:") })
    }

    // ---- the risk step

    private fun alphaGrant(): Map<String, Any?> {
        val g = LinkedHashMap(grant(c))
        val cavs = (g["caveats"] as List<Any?>).toMutableList()
        val env = LinkedHashMap(cavs[0] as Map<String, Any?>)
        val rp = LinkedHashMap(env["risk_policy"] as Map<String, Any?>)
        rp["weights"] = linkedMapOf<String, Any?>("alpha" to 1.0, "beta" to 0.0, "gamma" to 0.0, "delta" to 0.0, "epsilon" to 0.0, "zeta" to 0.0)
        rp["theta1"] = 0.5
        rp["theta2"] = 0.8
        env["risk_policy"] = rp
        cavs[0] = env
        g["caveats"] = cavs
        return g
    }

    private fun riskWith(sd: Double?): (Authorize.Operation, Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>? =
        { _, _, _ -> if (sd == null) AuthorizeTestKit.CALM_RISK - "semanticDistance" else AuthorizeTestKit.CALM_RISK + ("semanticDistance" to sd) }

    private fun nodes(vararg ids: String?): List<Map<String, Any?>> = ids.map { if (it == null) linkedMapOf<String, Any?>() else linkedMapOf<String, Any?>("id" to it) }

    private fun riskOf(
        sd: Double?, planNodes: List<Any?>? = null, nodeId: String? = "n", goal: String? = null, caution: Any? = null, plan: String? = Authorize.SINGLE_STEP,
    ): Authorize.Result = attempt(
        edit = {
            val pl = it["plan"] as MutableMap<String, Any?>
            if (nodeId == null) pl.remove("node_id") else pl["node_id"] = nodeId
            if (caution != null) it["caution"] = caution
        },
        grantMap = alphaGrant(),
        risk = riskWith(sd),
        plan = plan,
        context = if (planNodes == null && goal == null) null else ({ _ ->
            val m = linkedMapOf<String, Any?>()
            if (planNodes != null) { m["plan"] = planNodes; m["plan_authorized"] = true }
            if (goal != null) m["goal_node_id"] = goal
            m
        }),
    )

    @Test fun aSuppliedSemanticDistanceIsNeverRecomputed() {
        assertEquals(0.9, riskOf(0.9).risk!!, 1e-12)
        assertEquals(0.0, riskOf(0.0).risk!!, 1e-12)
    }

    @Test fun theSemanticDistanceComesFromThePlanGeodesicWhenNoneIsSupplied() {
        // the goal defaults to the last plan node
        assertEquals(0.5, riskOf(null, nodes("a", "b", "c"), nodeId = "b").risk!!, 1e-12)
        // the context's goal wins
        assertEquals(0.5, riskOf(null, nodes("a", "b", "c"), nodeId = "a", goal = "b").risk!!, 1e-12)
        // no node id on the proof: the worst case, even though an id-less plan node exists
        assertEquals(1.0, riskOf(null, nodes(null, "b", "c"), nodeId = null, goal = "b").risk!!, 1e-12)
        // no goal and an id-less last node: the worst case
        assertEquals(1.0, riskOf(null, nodes("a", "b", null), nodeId = "b").risk!!, 1e-12)
        // no plan at all: the worst case and no error
        val none = riskOf(null, plan = null)
        assertEquals(1.0, none.risk!!, 1e-12)
        assertFalse(none.reasons.toString(), none.reasons.any { it.startsWith("authorize:") })
    }

    @Test fun theCautionFloorsTheRisk() {
        assertEquals(0.7, riskOf(0.0, caution = 0.7).risk!!, 1e-12)
        assertEquals(0.0, riskOf(0.0, caution = -0.5).risk!!, 1e-12)
        assertEquals(1.0, riskOf(0.0, caution = 5.0).risk!!, 1e-12)
    }

    // ---- the threshold hook

    private fun hookRun(hook: (Map<String, Any?>, Map<String, Any?>) -> Authorize.ThresholdResult?): Authorize.Result =
        attempt(grantMap = alphaGrant(), risk = riskWith(0.9), thresholdHook = hook)

    private fun thresholdReason(r: Authorize.Result): String? = r.reasons.firstOrNull { it.startsWith("threshold: ") }

    @Test fun theThresholdHookTMustReachTheServerThreshold() {
        fun why(t: Double?) = thresholdReason(hookRun { _, _ -> Authorize.ThresholdResult(true, true, t) })
        val tail = " but the server requires t=3 (below the server-derived threshold; derive t from server-held data)"
        assertEquals("threshold: threshold hook enforced t=unreported$tail", why(null))
        assertEquals("threshold: threshold hook enforced t=2$tail", why(2.0))
        assertEquals("threshold: threshold hook enforced t=2.9$tail", why(2.9))
        assertEquals("threshold: threshold hook enforced t=Infinity$tail", why(Double.POSITIVE_INFINITY))
        assertEquals("threshold: threshold hook enforced t=-Infinity$tail", why(Double.NEGATIVE_INFINITY))
        assertEquals("threshold: threshold hook enforced t=NaN$tail", why(Double.NaN))
        assertNull(why(3.0))
        assertNull(why(3.9))
        val pass = hookRun { _, _ -> Authorize.ThresholdResult(true, true, 3.0) }
        assertEquals("pass", pass.checks["threshold"])
    }

    @Test fun aRejectedOrFailingThresholdHookIsNamed() {
        val rejected = hookRun { _, _ -> Authorize.ThresholdResult(true, false, null, null) }
        assertEquals("fail", rejected.checks["threshold"])
        assertTrue(rejected.reasons.toString(), rejected.reasons.contains("threshold: rejected"))
        assertTrue(rejected.reasons.toString(), rejected.reasons.contains("threshold: t=3 required and the threshold proof was rejected"))
        val named = hookRun { _, _ -> Authorize.ThresholdResult(true, false, null, "no quorum") }
        assertTrue(named.reasons.toString(), named.reasons.contains("threshold: no quorum"))
        val thrown = hookRun { _, _ -> throw IllegalStateException("boom") }
        assertEquals("fail", thrown.checks["threshold"])
        assertTrue(thrown.reasons.toString(), thrown.reasons.contains("threshold: threshold hook error (fail closed)"))
        val off = hookRun { _, _ -> Authorize.ThresholdResult(false) }
        assertEquals("fail", off.checks["threshold"])
        assertTrue(off.reasons.toString(), off.reasons.any { it.startsWith("threshold: t=3 (strong) required but no threshold verifier is enforced") })
    }

    // ---- the adaptive policy

    @Test fun anAdaptivePolicyThatFailsValidationIsRefusedEvenWhenItsNumbersAreFinite() {
        val g = alphaGrant()
        val rp = LinkedHashMap(((g["caveats"] as List<Any?>)[0] as Map<String, Any?>)["risk_policy"] as Map<String, Any?>)
        rp["theta1"] = 0.6
        rp["theta2"] = 0.2
        val r = attempt(grantMap = g, adaptivePolicy = { rp })
        assertEquals("fail", r.checks["adaptive"])
        assertTrue(r.reasons.toString(), r.reasons.contains("adaptive: invalid policy (risk_policy requires 0 <= theta1 <= theta2)"))
    }

    // ---- the grant a proof names is looked up only when it names one

    @Test fun theForbidStepResolvesNoGrantForAProofThatNamesNone() {
        neutral()
        val calls = ArrayList<Any?>()
        val lenient: (String?) -> Map<String, Any?>? = { ref -> calls.add(ref); grant(c) }
        val resolver = lenient as (String) -> Map<String, Any?>?
        val seen = ArrayList<Map<String, Any?>?>()
        val opts = ForbidWins.Options(clauses = { _, g -> seen.add(g); emptyList() })
        for (p in listOf<Any?>(null, mapOf<String, Any?>(), mapOf("grant_ref" to 5L))) {
            calls.clear()
            seen.clear()
            Authorize.authorize(p, inp(forbid = opts, resolveGrant = resolver))
            assertEquals("$p", listOf<Map<String, Any?>?>(null), seen)
            assertTrue("$p: $calls", calls.isEmpty())
        }
    }

    @Test fun aLinkedTemplateIsRefusedBeforeTheGuardWhenTheProofNamesNoReadableGrant() {
        neutral()
        for (p in listOf<Any?>(null, mapOf<String, Any?>(), mapOf("grant_ref" to 5L))) {
            val r = Authorize.authorize(p, inp(requireLinkedTemplate = { emptyMap<String, Any?>() }))
            assertFalse("$p", r.allow)
            assertEquals("$p", 403, r.status)
            assertEquals("$p", "template: the grant has no readable envelope", r.reason)
            assertEquals("$p", mapOf("template" to "fail"), r.checks)
        }
    }

    // ---- a negative clock skew is no skew

    @Test fun aNegativeFreshnessSkewIsClampedToZero() {
        // the anchor sits exactly at the gate's clock: a skew of -5 s must not turn it into a future anchor
        val r = attempt(anchor(10), freshness = Authorize.FreshnessGate(200_000.0, epochMs = 1000.0, now = 10_000L, clockSkewMs = -5000.0))
        assertEquals(r.reasons.toString(), "pass", r.checks["freshness"])
        assertFalse(r.reasons.toString(), r.reasons.any { it.contains("in the future") })
        // an anchor one epoch ahead is still a future anchor under a negative skew
        val ahead = attempt(anchor(11), freshness = Authorize.FreshnessGate(200_000.0, epochMs = 1000.0, now = 10_000L, clockSkewMs = -5000.0))
        assertTrue(ahead.reasons.toString(), ahead.reasons.contains("freshness: freshness anchor is in the future"))
    }

    // ---- the revocation epoch pin read

    private class PinReadFails(private val failure: Throwable, private val pinKey: String, private val inner: Authorize.MemoryStateStore = Authorize.MemoryStateStore()) :
        Authorize.StateStore by inner, Authorize.LastStore {
        override fun last(key: String): Long? = if (key == pinKey) throw failure else inner.last(key)
    }

    @Test fun aFatalErrorReadingOnlyTheEpochPinIsRethrown() {
        val store = PinReadFails(InternalError("fatal"), Authorize.epochPinKey(gid)!!)
        try {
            epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6)), store)
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    @Test fun anOrdinaryErrorReadingTheEpochPinFailsClosed() {
        val r = epochAttempt(linkedMapOf("kind" to "epoch", "epoch" to signedEpoch(6)), PinReadFails(IllegalStateException("down"), Authorize.epochPinKey(gid)!!))
        assertFalse(r.reasons.toString(), r.allow)
        assertEquals("fail", r.checks["freshness"])
        assertTrue(r.reasons.toString(), r.reasons.contains("freshness: revocation epoch pin unavailable (fail closed)"))
    }

    // ---- the goal node of a plan

    @Test fun thePlanGeodesicGoalIsNeverReadFromAnEmptyPlanOrANonObjectNode() {
        for ((label, plan) in listOf<Pair<String, List<Any?>>>(
            "empty" to emptyList<Any?>(),
            "non-object last node" to listOf(linkedMapOf<String, Any?>("id" to "a"), "not a node"),
        )) {
            val r = riskOf(null, plan, nodeId = "a")
            assertEquals(label, 1.0, r.risk!!, 1e-12)
            assertFalse("$label: ${r.reasons}", r.reasons.any { it.startsWith("authorize:") })
        }
    }
}
