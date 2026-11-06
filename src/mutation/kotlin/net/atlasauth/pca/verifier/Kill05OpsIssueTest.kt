package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The producer side (Issue) member by member, against the reference (`@atlasauth/pca` issue / artifacts): every refusal message,
 * every default and pass-through of buildPCActn, the suite members of signed bodies, nonce sizes, and that every signed result is a
 * copy through the strict canonical form (a later change to the caller's input never reaches it).
 */
@Suppress("UNCHECKED_CAST")
class Kill05OpsIssueTest {
    private val now = 1_800_000_000_000L
    private fun seed(b: Int) = ByteArray(32) { b.toByte() }
    private val principal = Keys.ed25519(Keys.edFromSeed(seed(1)))
    private val holder = Keys.ed25519(Keys.edFromSeed(seed(2)))
    private val pqKey by lazy { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(3)) }

    private fun env(): Map<String, Any?> =
        Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())

    private fun iae(msg: String, f: () -> Unit) {
        try {
            f()
        } catch (e: IllegalArgumentException) {
            assertEquals(msg, e.message)
            return
        }
        fail("expected IllegalArgumentException: $msg")
    }

    private fun canon(v: Any?) = Json.canonicalize(v)

    private fun nonceBytes(m: Map<String, Any?>): Int = Pca.decodeB64uStrict(m["nonce"], -1)!!.size

    @Test
    fun theDefaultRiskPolicyHasTheReferenceIntegers() {
        val p = Issue.defaultRiskPolicy()
        assertEquals(1L, p["kappa"])
        assertEquals(1L, p["bMax"])
    }

    // ---- capability chain ----------------------------------------------------------------------------------------------

    @Test
    fun aRootNeedsAnEd25519IdentityAndCarriesItsSuite() {
        iae("a root issuer needs an Ed25519 identity") { Issue.mintRoot(Keys.suite("ml-dsa-65", null, pqKey), "h", null, emptyList()) }
        val ed = Keys.edFromSeed(seed(4))
        val pure = Issue.mintRoot(Keys.suite("ml-dsa-65", ed, pqKey), "h", null, emptyList())
        assertEquals("ml-dsa-65", pure["alg"])
        assertEquals(pqKey.pkB64u(), pure["pq_pk"])
        assertFalse("a pure post-quantum signature has no pq_sig", pure.containsKey("pq_sig"))
        val hybrid = Issue.mintRoot(Keys.suite("hybrid-ed25519-ml-dsa-65", ed, pqKey), "h", null, emptyList())
        assertTrue(hybrid["pq_sig"] is String)
        val plain = Issue.mintRoot(principal, "h", null, emptyList())
        assertFalse(plain.containsKey("alg") || plain.containsKey("pq_sig") || plain.containsKey("parent"))
    }

    @Test
    fun aRootIsACopyOfItsCaveats() {
        val cav = linkedMapOf<String, Any?>("type" to "max_uses", "id" to "u", "n" to 3L)
        val list = arrayListOf<Any?>(cav)
        val cap = Issue.mintRoot(principal, "h", null, list)
        cav["n"] = 9L
        list.add("extra")
        assertEquals("[{\"id\":\"u\",\"n\":3,\"type\":\"max_uses\"}]", canon(cap["caveats"]))
    }

    @Test
    fun aGrantNeedsAGoalAndTheEnvelopeParts() {
        iae("mintGrant: goal required") { Issue.mintGrant(principal, "h", null, env(), "") }
        val g = Issue.mintGrant(principal, "h", null, env(), "g")
        assertEquals(Issue.goalCommit("g", g.goalSalt), g.goalCommit)
        assertEquals(16, Pca.decodeB64uStrict(g.goalSalt, -1)!!.size)
        for (k in listOf("predicates", "caveats", "risk_policy")) {
            val e = LinkedHashMap(env())
            e.remove(k)
            iae("mintGrant: envelope.$k is required") { Issue.mintGrant(principal, "h", null, e, "g") }
        }
    }

    @Test
    fun aDelegationCopiesTheParentAndAddedCaveats() {
        val root = Issue.mintRoot(principal, holder.id()!!, null, listOf(Issue.obj("type" to "max_uses", "id" to "u", "n" to 3L)))
        val added = linkedMapOf<String, Any?>("type" to "max_uses", "id" to "v", "n" to 2L)
        val child = Issue.delegate(root, "h2", listOf(added), holder)
        ((root["caveats"] as List<*>)[0] as MutableMap<String, Any?>)["n"] = 99L
        added["n"] = 98L
        assertEquals("[{\"id\":\"u\",\"n\":3,\"type\":\"max_uses\"},{\"id\":\"v\",\"n\":2,\"type\":\"max_uses\"}]", canon(child["caveats"]))
        assertEquals(Pca.capHash(Issue.mintRoot(principal, holder.id()!!, null, listOf(Issue.obj("type" to "max_uses", "id" to "u", "n" to 3L)))), child["parent"])

        val root2 = Issue.mintRoot(principal, holder.id()!!, null, listOf(Issue.obj("type" to "max_uses", "id" to "u", "n" to 3L)))
        val same = Issue.delegate(root2, "h2", null, holder)
        assertEquals("[{\"id\":\"u\",\"n\":3,\"type\":\"max_uses\"}]", canon(same["caveats"]))
        assertEquals("h2", same["holder"])
    }

    // ---- plans ---------------------------------------------------------------------------------------------------------

    private val nodes = listOf<Map<String, Any?>>(
        Issue.obj("id" to "a", "verb" to "va", "resource" to "ra"),
        Issue.obj("id" to "b", "verb" to "vb", "resource" to "rb", "reversibility_class" to "irreversible"),
        Issue.obj("id" to "c", "verb" to "vc", "resource" to "rc"),
    )

    @Test
    fun planProofsAndPlanRefusals() {
        val p = Issue.commitPlan(nodes)
        assertEquals(0L, p.proofFor("a")["index"])
        assertEquals(3L, p.proofFor("a")["size"])
        assertEquals(1L, p.proofFor("b")["index"])
        assertEquals(2L, p.proofFor("c")["index"])
        iae("commitPlan: unknown node zz") { p.proofFor("zz") }
        iae("commitPlan: missing or duplicate node id null") { Issue.commitPlan(listOf(Issue.obj("verb" to "v", "resource" to "r"))) }
        iae("commitPlan: missing or duplicate node id null") { Issue.commitPlan(listOf(Issue.obj("id" to 5L, "verb" to "v", "resource" to "r"))) }
        iae("commitPlan: missing or duplicate node id a") { Issue.commitPlan(listOf(nodes[0], nodes[0])) }
        iae("commitPlan: empty plan") { Issue.commitPlan(emptyList()) }
    }

    // ---- PCActn --------------------------------------------------------------------------------------------------------

    private val grant = Issue.obj("id" to "g1")

    @Test
    fun aPCActnNamesItsNodeAndFillsTheDefaults() {
        val plan = Issue.commitPlan(nodes)
        iae("buildPCActn: aud (audience) is required") { Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "b", 1L, holder, "", iat = now)) }
        iae("buildPCActn: unknown plan node zz") { Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "zz", 1L, holder, "a", iat = now)) }
        val p = Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "b", 7L, holder, "a", iat = now))
        assertEquals("{\"params_digest\":\"${Pca.paramsDigest(null)}\",\"resource\":\"rb\",\"reversibility_class\":\"irreversible\",\"verb\":\"vb\"}", canon(p["action"]))
        assertEquals("b", (p["plan"] as Map<*, *>)["node_id"])
        assertEquals(1L, ((p["plan"] as Map<*, *>)["inclusion_proof"] as Map<*, *>)["index"])
        assertEquals("a", p["aud"])
        assertEquals(now, p["iat"])
        assertEquals(now + Issue.DEFAULT_TTL_MS, p["exp"])
        assertEquals(1_200_000L, Issue.DEFAULT_TTL_MS)
        assertEquals(7L, p["counter"])
        assertEquals("g1", p["grant_ref"])
        assertEquals("{\"epoch\":0,\"measurement\":\"\",\"model_id\":\"unattested\",\"operator\":\"unattested\",\"quote_digest\":\"\"}", canon(p["attestation"]))
        assertEquals("{\"causal_hash\":\"\",\"taint_level\":0,\"trusted_refs\":[]}", canon(p["provenance"]))
        assertEquals("{\"accumulator_witness\":\"\",\"beacon_ref\":\"\",\"epoch\":0}", canon(p["freshness"]))
        assertEquals("{\"inputs\":{},\"r\":0}", canon(p["risk_claim"]))
        for (k in listOf("nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "intent", "intent_session", "fresh_at", "alg", "pq_pk", "pq_sig"))
            assertFalse(k, p.containsKey(k))
        // the first node too
        assertEquals("va", (Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "a", 1L, holder, "a", iat = now))["action"] as Map<*, *>)["verb"])
    }

    @Test
    fun aPCActnTimesItself() {
        val plan = Issue.commitPlan(nodes)
        val ttl = Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "a", 1L, holder, "a", iat = now, ttlMs = 5000L))
        assertEquals(now + 5000, ttl["exp"])
        val exp = Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "a", 1L, holder, "a", iat = now, exp = now + 9, ttlMs = 5000L))
        assertEquals(now + 9, exp["exp"])
        val before = System.currentTimeMillis()
        val wall = Issue.buildPCActn(Issue.ActSpec(grant, listOf(grant), plan, "a", 1L, holder, "a"))
        val iat = wall["iat"] as Long
        assertTrue(iat >= before && iat <= System.currentTimeMillis())
        assertEquals(iat + Issue.DEFAULT_TTL_MS, wall["exp"])
    }

    @Test
    fun aPCActnCarriesEveryOptionalMember() {
        val plan = Issue.commitPlan(nodes)
        val att = Issue.obj("quote_digest" to "q", "epoch" to 3L, "model_id" to "m", "measurement" to "x", "operator" to "o")
        val prov = Issue.obj("causal_hash" to "c", "taint_level" to 1L, "trusted_refs" to listOf("t"))
        val fresh = Issue.obj("beacon_ref" to "b", "epoch" to 2L, "accumulator_witness" to "w")
        val risk = Issue.obj("r" to 1L, "inputs" to Issue.obj("k" to "v"))
        val step = Issue.obj("step" to "s1")
        val intent = Issue.obj("goal" to "g")
        val session = Issue.obj("id" to "sess")
        val freshAt = Issue.obj("scope" to "inst")
        val p = Issue.buildPCActn(
            Issue.ActSpec(
                grant, listOf(grant), plan, "a", 1L, holder, "a", iat = now, nonce = "n", caution = Json.Num("0.5"), rationaleCommitment = "rc",
                toolBinding = "tb", progressStep = step, prohibitionEvidence = "pe", intent = intent, intentSession = session, freshAt = freshAt,
                provenance = prov, attestation = att, freshness = fresh, riskClaim = risk,
            ),
        )
        assertEquals(att, p["attestation"])
        assertEquals(prov, p["provenance"])
        assertEquals(fresh, p["freshness"])
        assertEquals(risk, p["risk_claim"])
        assertEquals("n", p["nonce"])
        assertEquals(Json.Num("0.5"), p["caution"])
        assertEquals("rc", p["rationale_commitment"])
        assertEquals("tb", p["tool_binding"])
        assertEquals(step, p["progress_step"])
        assertEquals("pe", p["prohibition_evidence"])
        assertEquals(intent, p["intent"])
        assertEquals(session, p["intent_session"])
        assertEquals(freshAt, p["fresh_at"])
    }

    // ---- signed artifacts ----------------------------------------------------------------------------------------------

    @Test
    fun aSignedArtifactIsACopyOfItsBody() {
        val inner = linkedMapOf<String, Any?>("k" to "v")
        val s = Issue.signArtifact("d", linkedMapOf("v" to 1L, "inner" to inner), holder)
        inner["k"] = "changed"
        assertEquals("{\"k\":\"v\"}", canon(s["inner"]))
        assertTrue(s["sig"] is String)
    }

    @Test
    fun dischargesNarrowsAndAnswersHaveTheirMembers() {
        val g = Issue.mintGrant(principal, holder.id()!!, null, env(), "g")
        val hop = Issue.norm(g.grant)
        val oracle = Keys.ed25519(Keys.edFromSeed(seed(7)))

        val d = Issue.discharge(oracle, "kyc", "kyc-service", hop, "chain_hop", null, null, now, now + 60_000)
        assertEquals("{}", canon(d["claims"]))
        assertEquals(16, nonceBytes(d))
        assertFalse(d.containsKey("action_digest"))
        val badD = try { Issue.signDischarge(emptyMap(), oracle); null } catch (e: IllegalArgumentException) { e.message }
        assertNotNull("a malformed discharge is refused", badD)
        assertTrue(badD, badD!!.startsWith("signDischarge: ") && badD != "signDischarge: null")

        val ad = Pca.hashCanonical("act")
        val n = Issue.narrow(holder, hop, listOf(Issue.obj("type" to "max_uses", "id" to "u2", "n" to 2L, "until" to now + 3_600_000L)), ad, now, now + 60_000)
        assertEquals(ad, n["action_digest"])
        assertEquals(16, nonceBytes(n))
        val badN = try { Issue.signNarrow(emptyMap(), holder); null } catch (e: IllegalArgumentException) { e.message }
        assertNotNull("a malformed narrow block is refused", badN)
        assertTrue(badN, badN!!.startsWith("signNarrow: ") && badN != "signNarrow: null")

        val pa = Issue.norm(Agent(holder, "aud", g.grant, clock = { now }).act("read", "x"))
        val gr = Issue.norm(g.grant)
        val render = Pca.hashCanonical("render")
        val deny = Issue.escalationAnswer(principal, gr, pa, null, false, now, now + 60_000, render)
        assertEquals("deny", deny["decision"])
        assertEquals(render, deny["render_digest"])
        assertEquals(16, nonceBytes(deny))
        val allow = Issue.escalationAnswer(principal, gr, pa, 3L, true, now, now + 60_000)
        assertEquals("allow", allow["decision"])
        assertFalse(allow.containsKey("render_digest"))
    }

    // ---- Ed25519 body signatures ---------------------------------------------------------------------------------------

    private val pk = Keys.edFromSeed(seed(6))
    private val rs = Keys.edFromSeed(seed(5))

    private val wfJson = """{"v":1,"id":"wf-1","principal":"PRINCIPAL","goal_digest":null,"plan_root":null,"issued_at":1800000000000,"expires_at":1800003600000,""" +
        """"steps":[{"id":"s1","verb":"pay","resource":"invoices/s1","params_digest":null,"deps":DEPS1,"sink":null,"deny_labels":[],"escalate_labels":[],"fresh_ms":null,"cost":{}},""" +
        """{"id":"s2","verb":"pay","resource":"invoices/s2","params_digest":null,"deps":["s1"],"sink":null,"deny_labels":[],"escalate_labels":[],"fresh_ms":null,"cost":{"pay":1}}],""" +
        """"edges":[{"from":{"step":"s1","field":"amount"},"to":{"step":"s2","param":"amount"},"op":"le","unit":"cents","deny_labels":[],"promise":null}],""" +
        """"budget":{"max_steps":4,"caps":{"pay":2}}}"""

    private fun body(json: String): LinkedHashMap<String, Any?> = LinkedHashMap(Json.parse(json.replace("PRINCIPAL", pk.id())) as Map<String, Any?>)

    private fun wf(deps1: String = "[]") = body(wfJson.replace("DEPS1", deps1))

    @Test
    fun aWorkflowIsSignedOnlyWhenWellFormedAndIsACopy() {
        val b = wf()
        val s = Issue.signWorkflow(pk, b)
        b["id"] = "changed"
        assertEquals("wf-1", (s["body"] as Map<*, *>)["id"])
        assertTrue(s["sig"] is String)
        iae("signWorkflow: malformed workflow") { Issue.signWorkflow(pk, wf("[\"s2\"]")) } // a cycle
        iae("signWorkflow: malformed workflow") { Issue.signWorkflow(pk, wf().also { it["v"] = 2L }) }
        iae("signWorkflow: principal is not the signer") { Issue.signWorkflow(rs, wf()) }
    }

    @Test
    fun stepReceiptsChainAndCopyTheirOutputs() {
        val w = wf()
        val amount = linkedMapOf<String, Any?>("digest" to Workflow.valueDigest(400L), "num" to 400L, "unit" to "cents", "labels" to ArrayList<Any?>())
        val outputs = linkedMapOf<String, Any?>("amount" to amount)
        val pd = Pca.paramsDigest(null)
        val r0 = Issue.signStepReceipt(rs, w, "s1", "ok", pd, outputs, now + 1000, null)
        amount["num"] = 1L
        assertEquals("{\"amount\":{\"digest\":\"${Workflow.valueDigest(400L)}\",\"labels\":[],\"num\":400,\"unit\":\"cents\"}}", canon(r0["outputs"]))
        val r1 = Issue.signStepReceipt(rs, w, "s2", "ok", pd, outputs, now + 2000, r0)
        val r2 = Issue.signStepReceipt(rs, w, "s2", "ok", pd, outputs, now + 3000, r1)
        assertEquals(0L, Json.asLong(r0["seq"]))
        assertEquals(1L, Json.asLong(r1["seq"]))
        assertEquals(2L, Json.asLong(r2["seq"]))
        assertNull(r0["prev"])
        assertEquals(Workflow.receiptRef(r0), r1["prev"])
        assertEquals(Workflow.workflowDigest(w), r0["wf"])
    }

    @Test
    fun aReceiptOutputCarriesItsNumberOnlyWhenAsked() {
        assertEquals(
            linkedMapOf<String, Any?>("digest" to Workflow.valueDigest(400L), "num" to 400L, "unit" to "cents", "labels" to listOf("a", "b")),
            Issue.wfOutput(400L, listOf("b", "a"), "cents", true),
        )
        assertEquals(linkedMapOf<String, Any?>("digest" to Workflow.valueDigest(400L), "num" to null, "unit" to null, "labels" to emptyList<Any?>()), Issue.wfOutput(400L))
        assertEquals(linkedMapOf<String, Any?>("digest" to Workflow.valueDigest("x"), "num" to null, "unit" to null, "labels" to emptyList<Any?>()), Issue.wfOutput("x", num = true))
    }

    @Test
    fun readAndAggregateGrantsAreCopies() {
        val rg = body(
            """{"v":1,"id":"rg-1","principal":"PRINCIPAL","issued_at":1800000000000,"expires_at":1800003600000,"reads":[{"verb":"read","resource_prefix":"customers/",""" +
                """"purposes":["support"],"modes":{"email":"hash","ssn":"drop"},"default_mode":"show"}],"caps":{"rows":100},"sinks":{"llm":{"allow":["public"],"escalate":["pii"]}}}""",
        )
        val sr = Issue.signReadGrant(pk, rg)
        rg["id"] = "changed"
        assertEquals("rg-1", (sr["body"] as Map<*, *>)["id"])
        iae("signReadGrant: malformed grant") { Issue.signReadGrant(rs, rg) }

        val ag = body(
            """{"v":1,"id":"ag-1","principal":"PRINCIPAL","issued_at":1800000000000,"expires_at":1800003600000,"rules":[{"verb":"aggregate","resource_prefix":"orders/",""" +
                """"purposes":["analytics"],"fns":["count","sum"],"min_group":5,"clamp":1000,"epsilon_micro":100000,"dp":true}],"epsilon_budget_micro":1000000,"max_queries":10}""",
        )
        val sa = Issue.signAggregateGrant(pk, ag)
        ag["id"] = "changed"
        assertEquals("ag-1", (sa["body"] as Map<*, *>)["id"])
        iae("signAggregateGrant: malformed grant") { Issue.signAggregateGrant(rs, ag) }
    }

    @Test
    fun aFreshAtTokenIsACopyOfItsState() {
        val digest = linkedMapOf<String, Any?>("v" to "pol-2")
        val t = Issue.signFreshAt(
            rs, "inst_1",
            Issue.obj("revocation_epoch" to 3L, "ledger_tree_size" to 40L, "budget_version" to 7L, "policy_revision" to 2L, "policy_digest" to digest), now,
        )
        digest["v"] = "changed"
        assertEquals("{\"v\":\"pol-2\"}", canon(t["policy_digest"]))
        assertEquals(rs.id(), t["signer"])
    }

    // ---- passports -----------------------------------------------------------------------------------------------------

    @Test
    fun aPassportFingerprintCoversEveryIdentityField() {
        val p = Issue.obj(
            "model_id" to "m", "weights_digest" to "w", "system_prompt_digest" to "s", "tool_manifest_digest" to "t", "runtime_measurement" to "r",
            "operator" to "o", "hardware_rooted" to false, "extra" to "ignored",
        )
        val want = Pca.hashCanonical(
            Issue.obj(
                "d" to "atlas-pca/passport/v1", "model_id" to "m", "weights_digest" to "w", "system_prompt_digest" to "s", "tool_manifest_digest" to "t",
                "runtime_measurement" to "r", "operator" to "o", "hardware_rooted" to false,
            ),
        )
        assertEquals(want, Issue.passportFingerprint(p))
        assertEquals(want, Issue.issuePassport(p)["id"])
    }

    @Test
    fun aSignedPassportHasItsWindowEvidenceAndSuite() {
        val identity = Issue.obj("model_id" to "m1", "operator" to "acme", "hardware_rooted" to false, "issued_at" to now)
        val pp = Issue.issuePassport(identity)
        val plain = Issue.signPassport(pp, principal, "sub", now, null, now + 10)
        assertEquals(now, Json.asLong(plain["nbf"]))
        assertEquals(now + 10, Json.asLong(plain["exp"]))
        assertEquals(principal.id(), plain["iss"])
        assertFalse(plain.containsKey("evidence") || plain.containsKey("alg") || plain.containsKey("pq_pk") || plain.containsKey("pq_sig"))
        iae("signPassport: exp must be after nbf") { Issue.signPassport(pp, principal, "sub", now, null, now) }
        val nb = Issue.signPassport(pp, principal, "sub", now, now + 5, now + 10)
        assertEquals(now + 5, Json.asLong(nb["nbf"]))
        iae("signPassport: exp must be after nbf") { Issue.signPassport(pp, principal, "sub", now, now + 10, now + 10) }

        // the passport is copied: a later change to the caller's map never reaches the signed body
        val mutable = LinkedHashMap(pp)
        val copied = Issue.signPassport(mutable, principal, "sub", now, null, now + 10)
        mutable["operator"] = "changed"
        assertEquals("acme", (copied["passport"] as Map<*, *>)["operator"])

        // evidence: stamped with iat when it has no time of its own, never in the caller's map
        val ev = linkedMapOf<String, Any?>("kind" to "tdx")
        val e1 = Issue.signPassport(pp, principal, "sub", now, null, now + 10, ev)
        assertEquals(now, Json.asLong((e1["evidence"] as Map<*, *>)["at"]))
        assertFalse(ev.containsKey("at"))
        val e2 = Issue.signPassport(pp, principal, "sub", now, null, now + 10, linkedMapOf("kind" to "tdx", "at" to now - 7))
        assertEquals(now - 7, Json.asLong((e2["evidence"] as Map<*, *>)["at"]))

        // a post-quantum issuer signs its suite into the body; only a hybrid adds pq_sig
        val ed = Keys.edFromSeed(seed(4))
        val hy = Issue.signPassport(pp, Keys.suite("hybrid-ed25519-ml-dsa-65", ed, pqKey), "sub", now, null, now + 10)
        assertEquals("hybrid-ed25519-ml-dsa-65", hy["alg"])
        assertEquals(pqKey.pkB64u(), hy["pq_pk"])
        assertTrue(hy["pq_sig"] is String)
        val pure = Issue.signPassport(pp, Keys.suite("ml-dsa-65", ed, pqKey), "sub", now, null, now + 10)
        assertEquals("ml-dsa-65", pure["alg"])
        assertFalse(pure.containsKey("pq_sig"))
    }
}
