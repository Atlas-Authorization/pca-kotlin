package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The agent side: grant envelope checks, the suite-aware PCActn signer, request headers, the facade and the built-in catalog. */
@Suppress("UNCHECKED_CAST")
class AgentSideTest {
    private val now = 1_800_000_000_000L
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })

    private fun envelope(vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val e = Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())
        e.putAll(extra)
        return e
    }

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private fun mintError(env: Map<String, Any?>) = refusal { Issue.mintGrant(principal, agentEd.id(), null, env, "g", "s") }

    @Test fun mintGrantRefusesAMalformedEnvelopeWithTheReferenceText() {
        assertEquals("mintGrant: model_polarity must be 'legacy' when present", mintError(envelope("model_polarity" to "inverted")))
        assertEquals("mintGrant: model_polarity must be 'legacy' when present", mintError(envelope("model_polarity" to null)))
        assertEquals("mintGrant: goal required", refusal { Issue.mintGrant(principal, agentEd.id(), null, envelope(), "", "s") })
        assertEquals("mintGrant: envelope.predicates is required", mintError(envelope().also { it.remove("predicates") }))
        assertTrue(mintError(envelope("risk_policy" to Issue.obj("v" to 1L))).startsWith("mintGrant: "))
        assertTrue(mintError(envelope("tighten" to null)).startsWith("mintGrant: "))
    }

    @Test fun mintGrantKeepsOnlyTheEnvelopeMembers() {
        val g = Issue.mintGrant(principal, agentEd.id(), null, envelope("model_polarity" to "legacy", "surprise" to 1L), "g", "s")
        val env = (g.grant["caveats"] as List<Any?>)[0] as Map<String, Any?>
        // the signed grant is canonical JSON, so its members come back sorted
        assertEquals("[agent_binding, caveats, goal_commit, model_polarity, predicates, risk_policy, type]", env.keys.toString())
        assertEquals(LinkedHashMap<String, Any?>(), env["agent_binding"])
    }

    @Test fun signPCActnBindsTheSuiteAndVerifies() {
        val pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 })
        val me = Keys.suite("hybrid-ed25519-ml-dsa-65", agentEd, pq)
        val g = Issue.mintGrant(principal, agentEd.id(), pq.pkB64u(), envelope(), "g", "s")
        val a = Agent(me, "rs", g.grant, clock = { now }).act("read", "x")
        val body = LinkedHashMap(a).also { it["sig"] = "junk" }
        val re = Issue.signPCActn(body, me)
        assertEquals("hybrid-ed25519-ml-dsa-65", re["alg"])
        assertEquals(pq.pkB64u(), re["pq_pk"])
        assertEquals(a["sig"], re["sig"]) // Ed25519 and ML-DSA are deterministic: re-signing reproduces the PCActn
        assertEquals(a["pq_sig"], re["pq_sig"])
        assertTrue(Pca.verifyPcactn(re, g.grant, now, Pca.Audience.Of("rs"), insecureSkipPlanRootCheck = true).allow)
        val ed = Issue.signPCActn(body, Keys.ed25519(agentEd))
        assertFalse(ed.containsKey("alg") || ed.containsKey("pq_pk") || ed.containsKey("pq_sig"))
    }

    @Test fun headersCarryOnlyWhatIsGiven() {
        val g = Issue.mintGrant(principal, agentEd.id(), null, envelope(), "g", "s")
        val a = Agent(Keys.ed25519(agentEd), "rs", g.grant, clock = { now }).act("read", "x")
        assertEquals("[PCA-Action]", Issue.headers(a, discharges = emptyList()).keys.toString())
        val h = Issue.headers(a, listOf(Issue.obj("d" to 1L)), Issue.obj("n" to 1L), Issue.obj("e" to 1L), Issue.obj("scope" to "s"), Issue.obj("p" to 1L))
        assertEquals("[PCA-Action, PCA-Provenance, PCA-Discharges, PCA-Narrow, PCA-Escalation-Answer, pca-fresh-at]", h.keys.toString())
        assertEquals("[{\"d\":1}]", String(Pca.decodeB64uStrict(h["PCA-Discharges"], -1)!!, Charsets.UTF_8))
        assertEquals("{\"scope\":\"s\"}", h["pca-fresh-at"])
        assertEquals(Issue.header(a), h["PCA-Action"])
        assertFalse(Issue.headers(a, provenance = Issue.obj("p" to "x".repeat(Issue.PROVENANCE_HEADER_MAX))).containsKey("PCA-Provenance"))
    }

    @Test fun facadeRefusesAnOutOfPolicyActionAndSignsAnInPolicyOne() {
        val h = Agent.fromPrincipal(Facade.AgentOptions(principal, "refund order 1", Issue.obj("stripe" to listOf("refund")),
            limits = Issue.obj("refund" to "\$500/day"), holder = Keys.ed25519(agentEd), aud = "rs", now = now, goalSalt = "s"))
        assertFalse(h.dryRun("stripe.charge", "charge:ch_1", Issue.obj("amount" to 5L), now).allowed)
        assertTrue(h.dryRun("stripe.refund", "charge:ch_1", Issue.obj("amount" to 5L), now).allowed)
        val r = h.act("stripe.refund", "charge:ch_1", Issue.obj("amount" to 5L), Facade.ActOptions(now = now))
        assertEquals(1L, r.pcactn["counter"])
        assertEquals(r.encoded, Issue.encode(r.pcactn))
        assertTrue(Pca.verifyPcactn(r.pcactn, h.grant, now, Pca.Audience.Of("rs"), insecureSkipPlanRootCheck = true).allow)
        assertEquals(Json.canonicalize(h.grant), h.encodeGrant())
        assertEquals(2, h.subAgent(Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 2 }))).chain.size)
    }

    @Test fun parseLimitRefusals() {
        assertEquals("parseLimit: empty limit", refusal { Facade.parseLimit("") })
        assertEquals("parseLimit: cannot parse limit 'abc'", refusal { Facade.parseLimit("abc") })
        assertEquals("{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}", Json.canonicalize(Facade.parseLimit("\$500/day").toJson()))
    }

    /** The built-in catalog is generated from the reference's: every row must match it member for member. */
    @Test fun builtinCatalogMatchesTheReference() {
        val src = generateSequence(java.io.File(System.getProperty("user.dir")).absoluteFile) { it.parentFile }
            .map { java.io.File(it, "packages/pca/src/catalog-builtin.generated.ts") }.firstOrNull { it.exists() }
            ?: throw IllegalStateException("the reference catalog is missing: the comparison must run (never skipped)")
        val ts = src.readText(Charsets.UTF_8)
        val rows = ts.lines().map { it.trim() }.filter { it.startsWith("{ connector:") }.map { line ->
            val row = Json.parseLenient(line.removeSuffix(",").replace(Regex("([{,]\\s*)(\\w+):"), "$1\"$2\":")) as MutableMap<String, Any?>
            row.values.removeAll { it is List<*> && it.isEmpty() } // an empty list and no list read the same
            row
        }
        assertEquals(rows.size, Catalog.BUILTIN.size)
        for ((i, s) in Catalog.BUILTIN.withIndex()) {
            val o = Issue.obj("connector" to s.connector, "action" to s.action, "verb" to s.verb, "reversibility" to s.reversibility,
                "blastRadius" to Facade.jn(s.blastRadius), "description" to s.description)
            if (s.amountField != null) o["amountField"] = s.amountField
            if (s.aliases.isNotEmpty()) o["aliases"] = ArrayList<Any?>(s.aliases)
            if (s.traits.isNotEmpty()) o["traits"] = ArrayList<Any?>(s.traits)
            assertEquals(s.verb, Json.canonicalize(rows[i]), Json.canonicalize(o))
        }
        assertEquals("stripe.refund", Catalog.DEFAULT.resolve("stripe", "issue_refund")!!.verb)
        assertNull(Catalog.DEFAULT.resolve("stripe", "no_such_action"))
    }
}
