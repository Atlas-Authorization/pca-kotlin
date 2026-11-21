package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The 0.5 policy gates wired into `authorize`: forbid-wins, behavioural contracts, linked template, principal, passport. */
@Suppress("UNCHECKED_CAST")
class AuthorizeHardeningWiringTest {
    private val allowCase get() = case("envelope-max-spend-within")

    private fun clause(id: String, kind: String, verb: String, resource: String? = null): Map<String, Any?> {
        val w = linkedMapOf<String, Any?>("verb" to verb)
        if (resource != null) w["resource"] = resource
        return linkedMapOf("id" to id, "kind" to kind, "when" to w)
    }

    private fun forbidInput(c: Map<String, Any?>, clauses: List<Map<String, Any?>>, require: Boolean = false, cert: Any? = null, store: Authorize.StateStore = Authorize.MemoryStateStore()): Authorize.Input {
        val base = input(c, stateStore = store)
        return Authorize.Input(
            operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = store, isRevoked = base.isRevoked, now = base.now,
            plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk,
            forbid = ForbidWins.Options(clauses = { _, _ -> clauses }, requireCertificate = require), forbidCertificate = cert,
        )
    }

    @Test fun aPermitWithNoForbidAllowsAndTheAllowCarriesTheCertificate() {
        val c = allowCase
        val clauses = listOf(clause("p1", "permit", "payments.send", "payments/acme"))
        val r = Authorize.authorize(pcactn(c), forbidInput(c, clauses))
        assertTrue(r.reasons.toString(), r.allow)
        val cert = r.forbid!!
        assertEquals("allow", cert["decision"])
        val ctx = linkedMapOf<String, Any?>("action" to linkedMapOf("verb" to "payments.send", "resource" to "payments/acme", "params" to Json.parse(Json.canonicalize(AuthorizeTestKit.op(c).params))))
        assertNull(ForbidWins.check(cert, clauses, ctx))
    }

    @Test fun aMatchingForbidRefusesBeforeTheCounterIsSpent() {
        val c = allowCase
        val store = Authorize.MemoryStateStore()
        val r = Authorize.authorize(pcactn(c), forbidInput(c, listOf(clause("p1", "permit", "payments.send"), clause("f1", "forbid", "payments.send")), store = store))
        assertFalse(r.allow)
        assertEquals("forbid: deny by forbid f1", r.reason)
        assertEquals(listOf("forbid"), r.checks.keys.toList())
        assertTrue("the counter was not consumed", Authorize.authorize(pcactn(c), input(c, stateStore = store)).allow)
    }

    @Test fun noPermitDeniesAndRequireCertificateIsEnforced() {
        val c = allowCase
        assertEquals("forbid: deny by none", Authorize.authorize(pcactn(c), forbidInput(c, emptyList())).reason)
        val clauses = listOf(clause("p1", "permit", "payments.send"))
        assertEquals("forbid: the call carries no certificate (fail closed)", Authorize.authorize(pcactn(c), forbidInput(c, clauses, require = true)).reason)
        val bad = Authorize.authorize(pcactn(c), forbidInput(c, clauses, require = true, cert = linkedMapOf("v" to 1L)))
        assertTrue(bad.reason!!, bad.reason!!.startsWith("forbid: certificate refused ("))
        val ok = Authorize.authorize(pcactn(c), forbidInput(c, clauses, require = true, cert = Authorize.authorize(pcactn(c), forbidInput(c, clauses)).forbid))
        assertTrue(ok.reasons.toString(), ok.allow)
    }

    private fun contractOf(vararg invariants: Map<String, Any?>): Pair<Map<String, Any?>, Keys.EdKey> {
        val key = Keys.edGenerate()
        val c = linkedMapOf<String, Any?>("version" to IntentJs.ofLong(1), "principal" to key.id(), "invariants" to ArrayList<Any?>(invariants.toList()))
        return Contracts.signContract(c, key.seed) to key
    }

    private fun contractInput(c: Map<String, Any?>, en: ContractEnforcer, store: Authorize.StateStore): Authorize.Input {
        val base = input(c, stateStore = store)
        return Authorize.Input(
            operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = store, isRevoked = base.isRevoked, now = base.now,
            plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk, contracts = en,
        )
    }

    @Test fun aViolatedContractRefusesBeforeTheCounterAndAnAdmittedActionAdvancesIt() {
        val c = allowCase
        val kv = MemoryAtomicKv()
        val (bad, key) = contractOf(linkedMapOf("id" to "i1", "kind" to "never", "when" to linkedMapOf<String, Any?>("verb" to "payments.send")))
        val store = Authorize.MemoryStateStore()
        val en = ContractEnforcer.open(kv, bad, key.id(), "k", { 1000.0 }, true)
        val r = Authorize.authorize(pcactn(c), contractInput(c, en, store))
        assertFalse(r.allow)
        assertEquals("contract: violated (i1)", r.reason)
        assertTrue("the counter was not consumed", Authorize.authorize(pcactn(c), input(c, stateStore = store)).allow)

        val (good, gkey) = contractOf(linkedMapOf("id" to "i2", "kind" to "never", "when" to linkedMapOf<String, Any?>("verb" to "payments.refund")))
        val kv2 = MemoryAtomicKv()
        val en2 = ContractEnforcer.open(kv2, good, gkey.id(), "k", { 1000.0 }, true)
        val ok = Authorize.authorize(pcactn(c), contractInput(c, en2, Authorize.MemoryStateStore()))
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals(1.0, Prohibitions.dv((en2.state()!!["state"] as Map<String, Any?>)["seq"]), 0.0)
    }

    @Test fun principalEnforcement() {
        val c = allowCase
        fun withResolver(resolver: ((String, Map<String, Any?>) -> Authorize.PrincipalInfo?)?, require: Boolean): Authorize.Result {
            val base = input(c)
            return Authorize.authorize(
                pcactn(c),
                Authorize.Input(
                    operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = base.stateStore, isRevoked = base.isRevoked, now = base.now,
                    plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk,
                    resolvePrincipal = resolver, requireVerifiedPrincipal = require,
                ),
            )
        }
        assertEquals("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver", withResolver(null, true).reasons.single { it.startsWith("principal") })
        assertEquals("principal: the grant issuer is not an enrolled, verified principal", withResolver({ _, _ -> null }, true).reasons.single { it.startsWith("principal") })
        assertEquals("principal: the principal resolver failed (fail closed)", withResolver({ _, _ -> throw IllegalStateException("x") }, true).reasons.single { it.startsWith("principal") })
        val notEnforced = withResolver({ _, _ -> Authorize.PrincipalInfo(false) }, false)
        assertTrue(notEnforced.allow)
        assertEquals("not-enforced", notEnforced.checks["principal"])
        val ok = withResolver({ _, _ -> Authorize.PrincipalInfo(true, "user", "u1") }, true)
        assertTrue(ok.allow)
        assertEquals("pass", ok.checks["principal"])
        assertEquals("u1", ok.principal!!.subjectId)
    }

    @Test fun passportAndLinkedTemplateRefuseBeforeTheGuard() {
        val c = allowCase
        val base = input(c)
        fun go(passport: Authorize.PassportRequirement?, link: (() -> Any?)?) = Authorize.authorize(
            pcactn(c),
            Authorize.Input(
                operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = base.stateStore, isRevoked = base.isRevoked, now = base.now,
                plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk,
                requirePassport = passport, requireLinkedTemplate = link,
            ),
        )
        val req = Authorize.PassportRequirement(listOf("issuer"), { _, _, _ -> false })
        assertEquals("passport: malformed", go(req, null).reason)
        assertEquals(listOf("passport"), go(req, null).checks.keys.toList())
        val missing = go(Authorize.PassportRequirement(emptyList(), null), null)
        assertEquals(listOf("requirePassport.trustedIssuers", "requirePassport.revoked"), missing.missing)
        assertEquals("template: the grant carries no template_ref", go(null, { LinkedHashMap<String, Any?>() }).reason)
        assertNotNull(go(null, null).operation)
    }

    private fun passportRun(hardware: Boolean, label: ((HardwareAttester) -> HardwareAttester)? = null): Authorize.Result {
        val c = allowCase
        val leaf = (((pcactn(c)["cap_chain"] as List<Any?>).last()) as Map<String, Any?>)["holder"] as String
        val issuer = Keys.edGenerate()
        val ident = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to hardware)
        ident["id"] = Passport.fingerprint(ident)
        val now = AuthorizeTestKit.NOW
        val body = linkedMapOf<String, Any?>(
            "typ" to "atlas-pca/passport", "ver" to 1L, "passport" to ident, "iss" to issuer.id(), "sub" to leaf,
            "iat" to now - 1000, "nbf" to now - 1000, "exp" to now + 600_000,
        )
        if (hardware) body["evidence"] = mapOf("document" to mapOf("nonce" to "n1"), "at" to now)
        val signed = LinkedHashMap(body)
        signed["sig"] = Pca.b64(issuer.sign(IntentJs.message(Passport.SIG_DOMAIN, body)))
        val measured = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to true)
        var attester: HardwareAttester = { _, _ -> Attest.Result(true, true, "", measured) }
        if (label != null) attester = label(attester)
        val base = input(c)
        val req = Authorize.PassportRequirement(listOf(issuer.id()), { _, _, _ -> false }, hardware = hardware, attest = if (hardware) attester else null, now = { now })
        return Authorize.authorize(
            pcactn(c),
            Authorize.Input(
                operation = base.operation, audience = base.audience, resolveGrant = base.resolveGrant, stateStore = base.stateStore, isRevoked = base.isRevoked, now = base.now,
                plan = base.plan, provenanceOptions = base.provenanceOptions, provenance = base.provenance, risk = base.risk,
                requirePassport = req, passport = signed,
            ),
        )
    }

    @Test fun aPassingPassportAddsItsAssuranceEntry() {
        val sw = passportRun(false)
        assertTrue(sw.reasons.toString(), sw.allow)
        assertEquals(mapOf("outcome" to "pass", "level" to "software"), sw.assurance["passport"])
        assertNull(Authorize.authorize(pcactn(allowCase), input(allowCase, stateStore = Authorize.MemoryStateStore())).assurance["passport"])
    }

    @Test fun aHardwarePassportTakesItsLevelAndVendorFromTheVerifierLabel() {
        val vendor = passportRun(true) { Assurance.setLabel(it, "hardware", "amd-sev-snp") }
        assertTrue(vendor.reasons.toString(), vendor.allow)
        assertEquals(mapOf("outcome" to "pass", "level" to "hardware", "vendor" to "amd-sev-snp"), vendor.assurance["passport"])
        val noVendor = passportRun(true) { Assurance.setLabel(it, "multi_root") }
        assertEquals(mapOf("outcome" to "pass", "level" to "multi_root"), noVendor.assurance["passport"])
        val unlabelled = passportRun(true)
        assertTrue(unlabelled.reasons.toString(), unlabelled.allow)
        assertEquals(mapOf("outcome" to "pass", "level" to "unknown"), unlabelled.assurance["passport"])
    }
}
