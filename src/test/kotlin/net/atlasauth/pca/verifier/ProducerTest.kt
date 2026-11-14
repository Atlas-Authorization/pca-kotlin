package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The producer side (Keys / Issue / Agent), round-tripped through this SDK's own verifier. */
@Suppress("UNCHECKED_CAST")
class ProducerTest {
    private val now = 1_800_000_000_000L
    private val aud = "ins_producer_test"

    private fun hex(h: String) = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun seed(b: String) = hex(b.repeat(32))

    private fun envelope(): Map<String, Any?> =
        Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())

    private fun verify(pcactn: Map<String, Any?>, grant: Map<String, Any?>): Pca.Verdict =
        Pca.verifyPcactnJson(Issue.encode(pcactn), Issue.norm(grant), now, Pca.Audience.Of(aud), insecureSkipPlanRootCheck = true)

    private fun agent(k: Keys.SuiteKey, g: Issue.Grant) = Agent(k, aud, g.grant, clock = { now })

    private fun principal() = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))

    @Test fun ed25519Rfc8032Vector1() {
        val k = Keys.edFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", hexOf(k.pub))
        assertEquals(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            hexOf(k.sign(ByteArray(0))),
        )
    }

    @Test fun edSuiteRoundTripAndHeader() {
        val p = principal()
        val me = Keys.ed25519(Keys.edFromSeed(seed("01")))
        val g = Issue.mintGrant(p, me.id()!!, null, envelope(), "pay invoices", Pca.b64(ByteArray(16)))
        assertEquals(Issue.goalCommit("pay invoices", Pca.b64(ByteArray(16))), g.goalCommit)
        assertEquals("", Pca.verifyChain(listOf(Issue.norm(g.grant)), p.id()!!, true, null))
        val a = agent(me, g)
        val a1 = a.act("pay", "invoice/7", mapOf("amount" to 1200L))
        val v = verify(a1, g.grant)
        assertTrue(v.reason, v.allow)
        assertEquals(1L, a1["counter"])
        val a2 = a.act("pay", "invoice/8")
        assertEquals(2L, a2["counter"])
        assertNotEquals(a1["nonce"], a2["nonce"])
        assertEquals(Issue.encode(a1), String(Pca.decodeB64uStrict(Agent.header(a1), -1)!!, Charsets.UTF_8))
        assertTrue(Agent.actionsBody(a1).startsWith("{\"pcactn\":{"))
    }

    @Test fun tamperedActionIsRefused() {
        val me = Keys.ed25519(Keys.edFromSeed(seed("02")))
        val g = Issue.mintGrant(principal(), me.id()!!, null, envelope(), "g")
        val a = agent(me, g).act("read", "x")
        (a["action"] as MutableMap<String, Any?>)["resource"] = "y"
        assertFalse(verify(a, g.grant).allow)
    }

    @Test fun multiNodePlanProofs() {
        val me = Keys.ed25519(Keys.edFromSeed(seed("03")))
        val g = Issue.mintGrant(principal(), me.id()!!, null, envelope(), "g")
        val a = agent(me, g)
        val nodes = (0 until 5).map { Issue.obj("id" to "s$it", "verb" to "step", "resource" to "r/$it") }
        val p = a.commitPlan(nodes)
        for (i in 0 until 5) {
            val v = verify(a.actNode("s$i"), g.grant)
            assertTrue("node $i: ${v.reason}", v.allow)
        }
        assertEquals(p.root, Pca.merkleRoot(nodes.map { Pca.planLeaf(it["id"], it, Pca.conditionsDigest(null, null)) }))
    }

    @Test fun delegationNarrows() {
        val p = principal()
        val me = Keys.ed25519(Keys.edFromSeed(seed("04")))
        val sub = Keys.ed25519(Keys.edFromSeed(seed("05")))
        val g = Issue.mintGrant(p, me.id()!!, null, envelope(), "g")
        val child = agent(me, g).delegate(sub, listOf(Issue.obj("type" to "max_uses", "id" to "u1", "n" to 3L, "until" to now + 3_600_000L)))
        assertEquals(2, child.chain.size)
        assertEquals("", Pca.verifyChain(Issue.norm(child.chain), p.id()!!, true, null))
        val v = verify(child.act("read", "x"), g.grant)
        assertTrue(v.reason, v.allow)
    }

    @Test fun hybridMlDsaLeafAndRoot() {
        val pEd = Keys.edFromSeed(ByteArray(32))
        val principal = Keys.suite("hybrid-ed25519-ml-dsa-65", pEd, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32)))
        val aEd = Keys.edFromSeed(seed("06"))
        val aPq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("07"))
        val me = Keys.suite("hybrid-ed25519-ml-dsa-65", aEd, aPq)
        assertEquals(1952, aPq.pk.size)
        val g = Issue.mintGrant(principal, aEd.id(), aPq.pkB64u(), envelope(), "g")
        assertEquals("hybrid-ed25519-ml-dsa-65", g.grant["alg"])
        val a = agent(me, g).act("read", "x")
        assertEquals("hybrid-ed25519-ml-dsa-65", a["alg"])
        val v = verify(a, g.grant)
        assertTrue(v.reason, v.allow)
        assertArrayEquals(aPq.pk, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("07")).pk)
    }

    @Test fun everyPqSuiteLeafRoundTrips() {
        val p = principal()
        val cases = listOf(
            "ml-dsa-65" to Pq.Prim.ML_DSA_65, "hybrid-nested-ed25519-ml-dsa-65" to Pq.Prim.ML_DSA_65, "ml-dsa-87" to Pq.Prim.ML_DSA_87,
            "hybrid-ed25519-ml-dsa-87" to Pq.Prim.ML_DSA_87, "slh-dsa-sha2-128f" to Pq.Prim.SLH_DSA_SHA2_128F,
            "hybrid-ed25519-slh-dsa-sha2-128f" to Pq.Prim.SLH_DSA_SHA2_128F,
        )
        for ((alg, prim) in cases) {
            val ed = Keys.edFromSeed(seed("08"))
            val pq = Keys.pqGenerate(prim)
            val me = Keys.suite(alg, ed, pq)
            val g = Issue.mintGrant(p, ed.id(), pq.pkB64u(), envelope(), "g")
            val a = agent(me, g).act("read", "x")
            val v = verify(a, g.grant)
            assertTrue("$alg: ${v.reason}", v.allow)
        }
    }

    private fun refuses(f: () -> Unit) {
        try { f() } catch (e: IllegalArgumentException) { return }
        fail("expected IllegalArgumentException")
    }

    @Test fun suiteKeysFailClosed() {
        val ed = Keys.edGenerate()
        refuses { Keys.suite("ml-dsa-65", null, null) }
        refuses { Keys.suite("hybrid-ed25519-ml-dsa-65", ed, null) }
        refuses { Keys.suite("fn-dsa-512", ed, null) }
        refuses { Keys.suite("hybrid-ed25519-ml-dsa-65", null, Keys.pqGenerate(Pq.Prim.ML_DSA_65)) }
        refuses { Keys.suite("ml-dsa-87", ed, Keys.pqGenerate(Pq.Prim.ML_DSA_65)) }
        refuses { Keys.edFromSeed(ByteArray(31)) }
    }

    @Test fun escalationAnswerVerifies() {
        val p = principal()
        val me = Keys.ed25519(Keys.edFromSeed(seed("09")))
        val g = Issue.mintGrant(p, me.id()!!, null, envelope(), "g")
        val pa = Issue.norm(agent(me, g).act("read", "x"))
        val grant = Issue.norm(g.grant)
        val ans = Issue.escalationAnswer(p, grant, pa, null, true, now, now + 60_000)
        val b = Escalation.Binding(Escalation.policyDigest(grant), Escalation.actionDigest(pa), Escalation.historyHead(null))
        val r = Escalation.verifyAnswer(ans, listOf(Escalation.Principal(p.id()!!)), b, now + 1)
        assertTrue(r.reason ?: "", r.ok)
        assertEquals("allow", r.decision)
        assertFalse(Escalation.verifyAnswer(ans, listOf(Escalation.Principal(me.id()!!)), b, now + 1).ok)
        assertFalse(Escalation.verifyAnswer(ans, listOf(Escalation.Principal(p.id()!!)), b, now + 120_000).ok)
        refuses { Issue.escalationAnswer(p, grant, pa, null, true, now, now + 90_000_000L) }
    }

    @Test fun dischargeVerifies() {
        val me = Keys.ed25519(Keys.edFromSeed(seed("0a")))
        val oracle = Keys.ed25519(Keys.edFromSeed(seed("0b")))
        val g = Issue.mintGrant(principal(), me.id()!!, null, envelope(), "g")
        val hop = Issue.norm(g.grant)
        val d = Issue.discharge(oracle, "kyc", "kyc-service", hop, "chain_hop", null, Issue.obj("approved" to true), now, now + 60_000)
        val caveat = Issue.norm(
            Issue.obj(
                "type" to "needs_discharge", "id" to "kyc", "issuer" to "kyc-service", "issuer_class" to "workload", "bind" to "chain_hop",
                "ttl_ms" to 3_600_000L, "require" to listOf(Issue.obj("claim" to "approved", "op" to "eq", "value" to true)),
            ),
        )
        val bind = CaveatLang.DischargeBinding(capHash = Pca.capHash(hop), pins = listOf(CaveatLang.DischargePin("kyc-service", "workload", oracle.id()!!)), now = now + 1)
        val v = CaveatLang.verifyDischarge(d, caveat, bind)
        assertTrue(v.reason ?: "", v.ok)
    }

    @Test fun narrowVerifies() {
        val me = Keys.ed25519(Keys.edFromSeed(seed("0c")))
        val g = Issue.mintGrant(principal(), me.id()!!, null, envelope(), "g")
        val hop = Issue.norm(g.grant)
        val n = Issue.narrow(me, hop, listOf(Issue.obj("type" to "max_uses", "id" to "u2", "n" to 2L, "until" to now + 3_600_000L)), null, now, now + 60_000)
        val v = CaveatLang.verifyNarrow(n, hop, null, now + 1)
        assertTrue(v.reason ?: "", v.ok)
    }

    @Test fun passportVerifies() {
        val issuer = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
        val agent = Keys.ed25519(Keys.edFromSeed(seed("0d")))
        val p = Issue.issuePassport(Issue.obj("model_id" to "m1", "operator" to "acme", "hardware_rooted" to false, "issued_at" to now))
        val sp = Issue.signPassport(p, issuer, agent.id()!!, now, null, now + 3_600_000L)
        val v = Passport.verify(sp, Passport.Options(trustedIssuers = listOf(issuer.id()!!), nowMs = now + 1, revoked = { _, _, _ -> false }))
        assertTrue(v.toString(), v.ok)
        refuses { Issue.signPassport(Issue.issuePassport(Issue.obj("model_id" to "m", "operator" to "o", "hardware_rooted" to true, "issued_at" to now)), issuer, agent.id()!!, now, null, now + 1) }
    }

    // ---- natives -> reference: this SDK's signed artifacts for the reference verifier ------------------------------------------

    private val v3Aud = "rs-kotlin-producer"
    private val v3Now = now + 1000

    private val vectors: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }

    private fun vkey(name: String) = Keys.edFromSeed(Pca.decodeB64uStrict((vectors["keys"] as Map<String, Any?>)[name].let { (it as Map<String, Any?>)["seed"] }, 32)!!)

    private fun vargs(name: String): Map<String, Any?> =
        ((vectors["cases"] as List<Any?>).map { it as Map<String, Any?> }.first { it["name"] == name })["args"] as Map<String, Any?>

    private fun fill(b: Int, n: Int) = ByteArray(n) { b.toByte() }

    /** A fixed seed of the length the primitive's seeded key generation takes. */
    private fun pqSeed(p: Pq.Prim, b: Int) = fill(b, when (p) { Pq.Prim.SLH_DSA_SHA2_128F -> 48; Pq.Prim.SLH_DSA_SHA2_256S -> 96; else -> 32 })

    private fun pins(k: Keys.SuiteKey, vararg extra: Pair<String, Any?>): Map<String, Any?> {
        val p = Issue.obj(*extra)
        p["pk"] = k.ed!!.id()
        k.pqPk()?.let { p["pq_pk"] = it }
        return p
    }

    private fun pcactnCase(alg: String, grant: Map<String, Any?>, pcactn: Map<String, Any?>) =
        Issue.obj("kind" to "pcactn", "alg" to alg, "grant" to Issue.norm(grant), "pcactn" to Issue.norm(pcactn))

    private fun artifactCase(kind: String, alg: String, pins: Map<String, Any?>, artifact: Map<String, Any?>) =
        Issue.obj("kind" to kind, "alg" to alg, "pins" to pins, "artifact" to Issue.norm(artifact))

    /**
     * One PCActn per suite this SDK signs (and one from a delegated sub-agent under each), one facade act with params, and each
     * artifact kind under Ed25519 and a hybrid ML-DSA suite. PCActns and escalation answers are checked here; the reference checks all.
     */
    private fun nativeFile(): Map<String, Any?> {
        val principalEd = vkey("principal")
        val agentEd = vkey("agent")
        val subEd = vkey("subagent")
        val principal = Keys.ed25519(principalEd)
        val env = Issue.obj("predicates" to listOf(Issue.obj("verb" to "refund", "resource" to "orders/*")), "caveats" to ArrayList<Any?>(),
            "agent_binding" to Issue.obj(), "risk_policy" to Issue.defaultRiskPolicy())
        val cases = ArrayList<Any?>()
        var i = 0
        for (alg in Pq.supportedSuites()) {
            val prim = Pq.resolveSigAlg(alg, true)!!.pq
            if (prim == Pq.Prim.LESS_CAT1) continue // LESS signing is not offered by this SDK
            i++
            val me = if (prim == null) Keys.ed25519(agentEd) else Keys.suite(alg, agentEd, Keys.pqFromSeed(prim, pqSeed(prim, i)))
            val g = Issue.mintGrant(principal, agentEd.id(), me.pqPk(), env, "refund an order", "s")
            val a = Agent(me, v3Aud, g.grant, clock = { now })
            cases.add(pcactnCase(alg, g.grant, a.act("refund", "orders/1", Issue.obj("amount" to 5L))))
            val sub = if (prim == null) Keys.ed25519(subEd) else Keys.suite(alg, subEd, Keys.pqFromSeed(prim, pqSeed(prim, 100 + i)))
            cases.add(pcactnCase(alg, g.grant, a.delegate(sub, listOf(Issue.obj("type" to "budget_alloc", "limit" to 5L))).act("refund", "orders/2", Issue.obj("amount" to 1L))))
        }
        val h = Agent.fromPrincipal(Facade.AgentOptions(principal, "refund order 1", Issue.obj("stripe" to listOf("refund")),
            limits = Issue.obj("refund" to "\$500/day"), holder = Keys.ed25519(agentEd), aud = v3Aud, now = now))
        h.provenance.principal("refund order 1")
        cases.add(pcactnCase("ed25519", h.grant, h.act("stripe.refund", "charge:ch_1", Issue.obj("amount" to 42L, "currency" to "usd"), Facade.ActOptions(now = now)).pcactn))

        val pq1 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(42, 32))
        val pq2 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(43, 32))
        for (alg in listOf("ed25519", "hybrid-ed25519-ml-dsa-65")) {
            fun sk(ed: Keys.EdKey, pq: Keys.PqKey) = if (alg == "ed25519") Keys.ed25519(ed) else Keys.suite(alg, ed, pq)
            val p = sk(principalEd, pq1)
            val guardian = sk(vkey("guardian"), pq2)
            val site = sk(vkey("site"), pq2)
            val oracle = sk(vkey("oracle"), pq1)
            val ans = LinkedHashMap(vargs("escalation-answer-allow")["body"] as Map<String, Any?>)
            ans["principal"] = principalEd.id()
            cases.add(artifactCase("escalation_answer", alg, pins(p), Issue.signEscalationAnswer(ans, p)))
            cases.add(artifactCase("revocation_epoch", alg, pins(guardian), SignersMore.signRevocationEpoch(guardian, vargs("revocation-epoch")["body"] as Map<String, Any?>)))
            cases.add(artifactCase("session_root", alg, pins(p), SignersMore.signSessionRoot(vargs("session-root")["body"] as Map<String, Any?>, p)))
            cases.add(artifactCase("action_schema", alg, pins(site, "kid" to "site-k1", "alg" to alg),
                SignersMore.signActionSchema(vargs("action-schema")["doc"] as Map<String, Any?>, "site-k1", site)))
            cases.add(artifactCase("intent_required", alg, pins(site, "kid" to "site-k1", "alg" to alg),
                SignersMore.signIntentRequired(vargs("intent-required")["body"] as Map<String, Any?>, "site-k1", site)))
            val lb = vargs("labels")["body"] as Map<String, Any?>
            cases.add(artifactCase("labels", alg, pins(site, "kid" to lb["kid"], "site" to lb["site"]), SignersMore.signLabels(lb, site)))
            cases.add(artifactCase("fact", alg, pins(oracle), SignersMore.signFact(vargs("fact-integer")["body"] as Map<String, Any?>, oracle)))
        }
        cases.add(artifactCase("caution", "ed25519", pins(Keys.ed25519(agentEd)), SignersMore.signCaution(vargs("caution")["body"] as Map<String, Any?>, agentEd)))
        cases.add(artifactCase("pq_binding", "ed25519", pins(Keys.ed25519(agentEd)), SignersMore.signPqBinding(agentEd, vargs("pq-binding")["pq_pk"] as String, 1, v3Aud)))
        return Issue.obj("lang" to "kotlin", "aud" to v3Aud, "now" to v3Now, "cases" to cases)
    }

    /** Builds this SDK's artifacts for the reference verifier; with PCA_PRODUCER_OUT set (CI) writes them there. */
    @Test fun nativeProducerFile() {
        val doc = nativeFile()
        val cases = (doc["cases"] as List<Any?>).map { it as Map<String, Any?> }
        assertEquals("[action_schema, caution, escalation_answer, fact, intent_required, labels, pcactn, pq_binding, revocation_epoch, session_root]",
            cases.map { it["kind"] as String }.toSortedSet().toString())
        var pcactns = 0
        var subs = 0
        for (c in cases) {
            if (c["kind"] == "pcactn") {
                val p = c["pcactn"] as Map<String, Any?>
                val v = Pca.verifyPcactn(p, c["grant"] as Map<String, Any?>, v3Now, Pca.Audience.Of(v3Aud), insecureSkipPlanRootCheck = true)
                assertTrue("${c["alg"]}: ${v.reason}", v.allow)
                pcactns++
                if ((p["cap_chain"] as List<Any?>).size == 2) subs++
            }
            if (c["kind"] == "escalation_answer") {
                val a = c["artifact"] as Map<String, Any?>
                val pin = c["pins"] as Map<String, Any?>
                val b = Escalation.Binding(a["policy_digest"] as String, a["action_digest"] as String, a["history_head"] as String)
                val r = Escalation.verifyAnswer(a, listOf(Escalation.Principal(pin["pk"] as String, pin["pq_pk"] as String?)), b, v3Now)
                assertTrue("${c["alg"]}: ${r.reason}", r.ok)
            }
        }
        assertEquals("one delegated sub-agent PCActn per suite", (pcactns - 1) / 2, subs)
        val out = System.getenv("PCA_PRODUCER_OUT")
        if (out.isNullOrEmpty()) return
        java.io.File(out).writeText(Json.canonicalize(doc), Charsets.UTF_8)
    }
}
