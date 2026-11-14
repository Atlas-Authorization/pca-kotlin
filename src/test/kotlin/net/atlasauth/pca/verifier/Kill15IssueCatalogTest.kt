package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The envelope checks of `mintGrant`, the PCActn re-signer, the request headers and the facade's connector catalog. */
@Suppress("UNCHECKED_CAST")
class Kill15IssueCatalogTest {
    private val now = 1_800_000_000_000L
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun canon(o: Any?) = Json.canonicalize(o)

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private fun envelope(): LinkedHashMap<String, Any?> =
        Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())

    // ---- the envelope members ----------------------------------------------------------------------------------------------

    @Test fun theGrantKeepsExactlyTheTwelveEnvelopeMembers() {
        assertEquals(listOf("predicates", "caveats", "agent_binding", "risk_policy", "objective_risk", "progress", "units", "tighten",
            "model_polarity", "template_ref", "actions", "provenance"), Issue.ENVELOPE_MEMBERS)
    }

    // ---- the reference's checks, one member at a time -----------------------------------------------------------------------

    private val badUnits: Any? = "x"
    private val badTighten: Any? = "x"
    private val badTemplateRef: Any? = "x"
    private val badActions: Any? = "x"
    private val badProvenance: Any? = "x"

    @Test fun aValidEnvelopeWithEveryOptionalMemberPasses() {
        val e = envelope()
        e["units"] = Issue.obj("action.params.amount" to Issue.obj("kind" to "money"))
        e["tighten"] = ArrayList<Any?>()
        e["template_ref"] = Issue.obj("template_id" to "refund_desk", "version_digest" to "abc", "slots" to Issue.obj())
        e["provenance"] = Issue.obj("mode" to "enforce")
        e["model_polarity"] = "legacy"
        assertNull(Issue.envelopeError(e))
        assertNull(Issue.envelopeError(envelope()))
    }

    @Test fun eachOptionalMemberIsCheckedWhenPresent() {
        val units = envelope().also { it["units"] = badUnits }
        assertEquals(PcaDecision.unitTagsError(badUnits), Issue.envelopeError(units))
        assertEquals("units must be an object", Issue.envelopeError(units))
        val tighten = envelope().also { it["tighten"] = badTighten }
        assertEquals(PcaDecision.tightenListError(badTighten), Issue.envelopeError(tighten))
        assertEquals("tighten must be an array", Issue.envelopeError(tighten))
        val ref = envelope().also { it["template_ref"] = badTemplateRef }
        assertEquals(PolicyAuthoring.templateRefError(badTemplateRef), Issue.envelopeError(ref))
        assertEquals("template_ref must be an object", Issue.envelopeError(ref))
        val actions = envelope().also { it["actions"] = badActions }
        assertEquals(ActionsRegistry.actionPinError(badActions), Issue.envelopeError(actions))
        assertEquals("actions must be an object", Issue.envelopeError(actions))
        val prov = envelope().also { it["provenance"] = badProvenance }
        assertEquals(ArgProvenance.envelopeError(badProvenance), Issue.envelopeError(prov))
        assertEquals("provenance must be an object", Issue.envelopeError(prov))
        val pol = envelope().also { it["model_polarity"] = "inverted" }
        assertEquals("model_polarity must be 'legacy' when present", Issue.envelopeError(pol))
        val rp = envelope().also { it["risk_policy"] = "x" }
        assertEquals(Authorize.riskPolicyError("x"), Issue.envelopeError(rp))
        assertEquals("risk_policy must be an object", Issue.envelopeError(rp))
    }

    @Test fun aPresentNullIsCheckedNotSkipped() {
        for (k in listOf("units", "tighten", "template_ref", "actions", "provenance", "model_polarity")) {
            val e = envelope()
            e[k] = null
            assertNotNull(k, Issue.envelopeError(e))
        }
    }

    @Test fun theFirstFailingCheckInTheReferenceOrderWins() {
        val all = envelope()
        all["risk_policy"] = "x"
        all["units"] = badUnits
        all["tighten"] = badTighten
        all["template_ref"] = badTemplateRef
        all["actions"] = badActions
        all["provenance"] = badProvenance
        all["model_polarity"] = "inverted"
        val order = listOf(
            "risk_policy" to "risk_policy must be an object",
            "units" to "units must be an object",
            "tighten" to "tighten must be an array",
            "template_ref" to "template_ref must be an object",
            "actions" to "actions must be an object",
            "provenance" to "provenance must be an object",
            "model_polarity" to "model_polarity must be 'legacy' when present",
        )
        for ((k, want) in order) {
            assertEquals(k, want, Issue.envelopeError(all))
            if (k == "risk_policy") all[k] = Issue.defaultRiskPolicy() else all.remove(k)
        }
        assertNull(Issue.envelopeError(all))
    }

    @Test fun mintGrantCarriesTheCheckedMembersAndRefusesTheRest() {
        val e = envelope()
        e["units"] = badUnits
        assertEquals("mintGrant: units must be an object", refusal { Issue.mintGrant(principal, agentEd.id(), null, e, "g", "s") })
        val ok = envelope()
        ok["tighten"] = ArrayList<Any?>()
        ok["provenance"] = Issue.obj("mode" to "enforce")
        val g = Issue.mintGrant(principal, agentEd.id(), null, ok, "g", "s")
        val env = m(Pca.asList(g.grant["caveats"])[0])
        assertTrue(env.containsKey("tighten"))
        assertTrue(env.containsKey("provenance"))
    }

    // ---- re-signing a PCActn body --------------------------------------------------------------------------------------------

    private fun action(signer: Keys.SuiteKey, holderPq: String?): Pair<Map<String, Any?>, Map<String, Any?>> {
        val g = Issue.mintGrant(principal, agentEd.id(), holderPq, envelope(), "g", "s")
        return Pair(g.grant, Agent(signer, "rs", g.grant, clock = { now }).act("read", "x"))
    }

    @Test fun reSigningDropsTheSignatureMembersAndRebindsTheSuite() {
        val ed = Keys.ed25519(agentEd)
        val a = action(ed, null).second
        val body = LinkedHashMap(a)
        body["sig"] = "junk"
        body["pq_sig"] = "junk"
        body["threshold"] = Issue.obj("x" to 1L)
        body["alg"] = "junk-alg"
        body["pq_pk"] = "junk-pk"
        val action0 = canon(a["action"])
        val r = Issue.signPCActn(body, ed)
        for (k in listOf("pq_sig", "threshold", "alg", "pq_pk")) assertFalse(k, r.containsKey(k))
        assertEquals(a["sig"], r["sig"])
        // the signature members are re-added after the body
        assertEquals("sig", r.keys.last())
        assertEquals(Pca.b64(agentEd.sign(Pca.thresholdMessage(LinkedHashMap(r).also { it.remove("sig") }))), r["sig"])
        // the result is a copy: changing the caller's nested members afterwards does not reach it
        (body["action"] as MutableMap<String, Any?>)["verb"] = "changed"
        assertEquals(action0, canon(r["action"]))
    }

    @Test fun reSigningAHybridBodyReplacesTheJunkSuiteMembers() {
        val pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 })
        val me = Keys.suite("hybrid-ed25519-ml-dsa-65", agentEd, pq)
        val a = action(me, pq.pkB64u()).second
        val body = LinkedHashMap(a)
        body["sig"] = "junk"
        body["pq_sig"] = "junk"
        body["threshold"] = Issue.obj("x" to 1L)
        body["alg"] = "junk-alg"
        body["pq_pk"] = "junk-pk"
        val r = Issue.signPCActn(body, me)
        assertEquals("hybrid-ed25519-ml-dsa-65", r["alg"])
        assertEquals(pq.pkB64u(), r["pq_pk"])
        assertFalse(r.containsKey("threshold"))
        assertEquals(a["sig"], r["sig"])
        assertEquals(a["pq_sig"], r["pq_sig"])
        assertEquals(listOf("alg", "pq_pk", "sig", "pq_sig"), r.keys.toList().takeLast(4))
    }

    // ---- request headers ----------------------------------------------------------------------------------------------------

    private fun decoded(h: Map<String, String>, k: String) = String(Pca.decodeB64uStrict(h[k], -1)!!, Charsets.UTF_8)

    @Test fun everyHeaderCarriesItsOwnBody() {
        val a = action(Keys.ed25519(agentEd), null).second
        val h = Issue.headers(a, listOf(Issue.obj("d" to 1L)), Issue.obj("n" to 1L), Issue.obj("e" to 1L), Issue.obj("scope" to "s"), Issue.obj("p" to 1L))
        assertEquals("{\"n\":1}", decoded(h, "PCA-Narrow"))
        assertEquals("{\"e\":1}", decoded(h, "PCA-Escalation-Answer"))
        assertEquals("[{\"d\":1}]", decoded(h, "PCA-Discharges"))
        assertEquals("{\"p\":1}", decoded(h, ArgProvenance.HEADER))
        assertEquals("{\"scope\":\"s\"}", h["pca-fresh-at"])
        assertEquals(Issue.header(a), h["PCA-Action"])
        val none = Issue.headers(a)
        assertEquals(setOf("PCA-Action"), none.keys)
        assertEquals(setOf("PCA-Action"), Issue.headers(a, emptyList()).keys)
    }

    @Test fun aProvenanceBundleTravelsInAHeaderUpToExactlyEightKiB() {
        val a = action(Keys.ed25519(agentEd), null).second
        // `{"p":"<n x>"}` is n + 8 bytes: 6144 bytes is exactly 8192 base64url characters
        val fits = Issue.headers(a, provenance = Issue.obj("p" to "x".repeat(6136)))
        assertEquals(8192, fits[ArgProvenance.HEADER]!!.length)
        val tooBig = Issue.headers(a, provenance = Issue.obj("p" to "x".repeat(6137)))
        assertFalse(tooBig.containsKey(ArgProvenance.HEADER))
        assertEquals(8192, Issue.PROVENANCE_HEADER_MAX)
    }

    // ---- the connector catalog -----------------------------------------------------------------------------------------------

    private fun spec(connector: String, action: String, vararg aliases: String) =
        Catalog.Spec(connector, action, "$connector.$action", "reversible", 0.1, null, "d", aliases.toList())

    @Test fun aVerbIsLookedUpExactly() {
        val a = spec("c", "x")
        val b = spec("c", "y")
        val cat = Catalog(listOf(a, b))
        assertSame(a, cat.get("c.x"))
        assertSame(b, cat.get("c.y"))
        assertNull(cat.get("c.z"))
        assertNull(cat.get("x"))
    }

    @Test fun aLaterSpecWithTheSameVerbWinsAndAllListsEachVerbOnce() {
        val first = spec("c", "x")
        val second = Catalog.Spec("c", "x", "c.x", "irreversible", 0.9, null, "later")
        val other = spec("d", "y")
        val cat = Catalog(listOf(first, other, second))
        assertSame(second, cat.get("c.x"))
        assertEquals(listOf(second, other), cat.all())
        // all() is a copy
        (cat.all() as MutableList<Catalog.Spec>).clear()
        assertEquals(2, cat.all().size)
        assertEquals(Catalog.BUILTIN.size, Catalog.DEFAULT.all().size)
        assertTrue(Catalog.DEFAULT.all().size >= 21)
    }

    @Test fun anAliasResolvesOnlyWhenItNamesExactlyOneAction() {
        val x = spec("c", "x")
        val y = spec("c", "y", "x", "why")
        val z = spec("c", "z", "why")
        val other = spec("d", "w", "x")
        val cat = Catalog(listOf(x, y, z, other))
        // the exact verb wins over an alias of another action
        assertSame(x, cat.resolve("c", "x"))
        // one action lists the alias
        assertSame(y, Catalog(listOf(y, other)).resolve("c", "x"))
        // two actions list it: no guess
        assertNull(cat.resolve("c", "why"))
        // an alias of another connector does not count
        assertSame(other, cat.resolve("d", "x"))
        assertNull(cat.resolve("e", "x"))
        assertNull(cat.resolve("c", "nothing"))
        assertSame(z, Catalog(listOf(z)).resolve("c", "why"))
    }
}
