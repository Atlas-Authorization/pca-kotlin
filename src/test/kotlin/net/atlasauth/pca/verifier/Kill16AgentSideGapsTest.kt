package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Agent-side paths the shared vectors do not reach: a pure post-quantum suite that also names an Ed25519 identity, one-character
 * members, and facade handles whose policy lacks a cap or a budget, carries extra caveats, or caps the budget below the per-action cap.
 */
@Suppress("UNCHECKED_CAST")
class Kill16AgentSideGapsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }

    private val now = 1_800_000_000_000L
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })
    private val agentS = Keys.ed25519(agentEd)
    private val pq by lazy { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 }) }
    private val pureWithEd by lazy { Keys.suite("ml-dsa-65", agentEd, pq) }

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun canon(o: Any?) = Json.canonicalize(o)

    private fun argMap(op: String, key: String): MutableMap<String, Any?> {
        val c = l(doc["cases"]).map { m(it) }.first { it["op"] == op }
        return LinkedHashMap(m(ParityVectors.parse(Json.canonicalize(m(c["args"])[key]))))
    }

    // ---- a pure post-quantum suite signs once: no second signature member ------------------------------------------------

    @Test fun aPureSuiteShareCarriesItsAlgAndNoSecondSignature() {
        val s = SignersMore.signPreparedShare("agent", pureWithEd, ByteArray(8) { 3 })
        assertEquals(listOf("role", "publicKey", "sig", "alg"), s.keys.toList())
        assertEquals("ml-dsa-65", s["alg"])
        assertEquals(agentEd.id(), s["publicKey"])
    }

    @Test fun aPureSuiteSiteSignatureHasNoPqValue() {
        val site = pureWithEd
        val schema = SignersMore.signActionSchema(argMap("sign_action_schema", "doc"), "site-k1", site)
        assertEquals(listOf("alg", "kid", "value"), m(schema["sig"]).keys.toList())
        assertEquals("ml-dsa-65", m(schema["sig"])["alg"])
        val ir = SignersMore.signIntentRequired(argMap("sign_intent_required", "body"), "site-k1", site)
        assertEquals(listOf("alg", "kid", "value"), m(ir["sig"]).keys.toList())
        assertEquals("ml-dsa-65", m(ir["sig"])["alg"])
    }

    // ---- a one-character member is non-empty ---------------------------------------------------------------------------------

    @Test fun aOneCharacterDigestHolderOrVerbIsAccepted() {
        assertNull(SignersMore.cautionBodyError(Issue.obj("action_digest" to "d", "holder" to "h", "caution" to 0L)))
        val body = argMap("sign_intent_required", "body")
        body["cell"] = Issue.obj("verb" to "r", "coords" to Issue.obj("a" to listOf("x")))
        assertNull(SignersMore.intentRequiredShapeError(body))
    }

    // ---- facade handles over a hand-built policy ---------------------------------------------------------------------------

    private val refund = Issue.obj("verb" to "stripe.refund", "resource" to "*")

    private fun handOf(riskPolicy: Map<String, Any?>, budgetModel: String = "risk", predicates: List<Any?> = emptyList(),
                       caveats: List<Any?> = emptyList()): Facade.Handle {
        val base = Facade.agent(Facade.AgentOptions(principal, "goal", Issue.obj("stripe" to listOf("refund")), holder = agentS, aud = "rs", now = now,
            goalSalt = "s"))
        val policy = Facade.CompiledPolicy(predicates, caveats, riskPolicy, base.policy.actions, budgetModel, LinkedHashMap(), LinkedHashMap(), ArrayList())
        return Facade.Handle(base.grant, base.chain, base.goalSalt, policy, base.holder, base.principalPublic, Catalog.DEFAULT, "rs", now, base.provenance)
    }

    @Test fun aMissingBudgetIsZero() {
        val h = handOf(Issue.obj("kappa" to 2L))
        assertEquals("{\"B\":0,\"asOf\":$now,\"tau\":$now}", canon(h.budget()))
        assertEquals(0.0, h.autonomyBound(), 0.0)
    }

    @Test fun aMissingOrNonPositiveCapBoundsNothing() {
        val noCap = handOf(Issue.obj("bMax" to 5L))
        assertEquals("5", canon(noCap.budget()["B"]))
        assertEquals(0.0, noCap.autonomyBound(), 0.0)
        val negativeCap = handOf(Issue.obj("kappa" to -2L, "bMax" to 5L))
        assertEquals(0.0, negativeCap.autonomyBound(), 0.0)
    }

    @Test fun aNegativeBudgetCountsAsNone() {
        val h = handOf(Issue.obj("kappa" to 1L, "bMax" to -3L))
        assertEquals("-3", canon(h.budget()["B"]))
        assertEquals(0.0, h.autonomyBound(), 0.0)
    }

    @Test fun aDollarHandleWithoutACapClaimsTheBlastRadius() {
        val h = handOf(Issue.obj("bMax" to 5L), budgetModel = "dollars")
        val r = h.act("stripe.refund", "charge:1", Issue.obj("amount" to 100L), Facade.ActOptions(now = now))
        assertEquals("0.9", canon(m(r.pcactn["risk_claim"])["r"]))
        // no predicate in this policy: the advisory pre-check stops there
        assertFalse(r.dryRun.allowed)
        assertEquals("no predicate permits stripe.refund on charge:1", r.dryRun.reason)
    }

    @Test fun theDryRunCaveatContextCarriesTheBlastRadius() {
        val tight = handOf(Issue.defaultRiskPolicy(), predicates = listOf(refund), caveats = listOf(Issue.obj("type" to "max_blast_radius", "max" to Json.Num("0.5"))))
        val d = tight.dryRun("stripe.refund", "charge:1", null, now)
        assertFalse(d.allowed)
        assertEquals("caveat(s) failed: max_blast_radius", d.reason)
        val wide = handOf(Issue.defaultRiskPolicy(), predicates = listOf(refund), caveats = listOf(Issue.obj("type" to "max_blast_radius", "max" to Json.Num("0.95"))))
        val ok = wide.dryRun("stripe.refund", "charge:1", null, now)
        assertTrue(ok.allowed)
        assertEquals(3, ok.t)
    }

    @Test fun theDryRunCaveatContextCarriesTheDelegationDepth() {
        val h = handOf(Issue.defaultRiskPolicy(), predicates = listOf(refund), caveats = listOf(Issue.obj("type" to "delegation_depth", "max" to 0L)))
        assertTrue(h.dryRun("stripe.refund", "charge:1", null, now).allowed)
        val sub = h.subAgent(Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 2 })))
        val d = sub.dryRun("stripe.refund", "charge:1", null, now)
        assertFalse(d.allowed)
        assertEquals("caveat(s) failed: delegation_depth", d.reason)
    }

    @Test fun aDryRunWithoutParamsSeesAnEmptyParamsObject() {
        val emptyParams = Issue.obj("verb" to "stripe.refund", "resource" to "*",
            "where" to listOf(Issue.obj("field" to "action.params", "op" to "eq", "value" to Issue.obj())))
        val h = handOf(Issue.defaultRiskPolicy(), predicates = listOf(emptyParams))
        assertTrue(h.dryRun("stripe.refund", "charge:1", null, now).allowed)
        assertFalse(h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 1L), now).allowed)
    }

    @Test fun theDryRunActionCarriesTheReversibilityClass() {
        val irreversibleOnly = Issue.obj("verb" to "stripe.refund", "resource" to "*",
            "where" to listOf(Issue.obj("field" to "action.reversibility_class", "op" to "eq", "value" to "irreversible")))
        val h = handOf(Issue.defaultRiskPolicy(), predicates = listOf(irreversibleOnly))
        assertTrue(h.dryRun("stripe.refund", "charge:1", null, now).allowed)
    }

    // ---- the catalog lookup and the envelope's action pins ------------------------------------------------------------------

    @Test fun aCataloguedVerbWithoutADotIsFoundAsIs() {
        val solo = Catalog.Spec("solo", "solo", "solo", "reversible", 0.1, null, "d")
        assertSame(solo, Facade.specFor(Catalog(listOf(solo)), "solo"))
    }

    @Test fun anActionsPinObjectIsCheckedMemberByMember() {
        val e = Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy(),
            "actions" to Issue.obj("pack" to "x"))
        assertEquals("actions.pack must be {ns, root}", Issue.envelopeError(e))
    }

    // ---- facade handles from compilePolicy ------------------------------------------------------------------------------------

    private fun handle(permissions: Map<String, Any?>, limits: Map<String, Any?>? = null, riskPolicy: Map<String, Any?>? = null, at: Long = now) =
        Facade.agent(Facade.AgentOptions(principal, "goal", permissions, limits = limits, holder = agentS, riskPolicy = riskPolicy, aud = "rs", now = at,
            goalSalt = "s"))

    @Test fun anActionsAdvisoryPreCheckRunsAtTheActionsClock() {
        val h = handle(Issue.obj("github" to listOf("comment")), Issue.obj("comment" to "5/hour"), at = 1_000L)
        val r = h.act("github.comment", "pr:1", null, Facade.ActOptions(now = 1_500L))
        assertTrue(r.dryRun.allowed)
        assertEquals(1_500L, r.pcactn["iat"])
    }

    @Test fun aBudgetBelowTheCapEscalatesWhatItCannotCover() {
        val h = handle(Issue.obj("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"), riskPolicy = Issue.obj("bMax" to 100L))
        assertEquals("100", canon(m(h.policy.riskPolicy)["bMax"]))
        assertEquals("500", canon(m(h.policy.riskPolicy)["kappa"]))
        // 100 / 500 = 0.2 is the machine-only tier and costs exactly the budget
        assertEquals(1, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 100L), now).t)
        // 110 / 500 = 0.22 is still the machine-only tier, but its cost (110) is over the budget: a human co-sign
        assertEquals(3, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 110L), now).t)
    }
}
