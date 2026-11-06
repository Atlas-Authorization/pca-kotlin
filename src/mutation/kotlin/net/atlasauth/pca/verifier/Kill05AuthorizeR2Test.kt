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
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Authorize.kt survivors of full run 41911466407 (shard 8): show()'s control escapes, classRank on a non-string, the hop ids,
 * the workflow wall clock, the side-carried fresh_at header, revocation staleness (signed class, server class, PCActn epoch, custom
 * ids, the accepted-epoch pin), the plan leaf conditions, the caveat context (depth, class, env, tool name, plan-node class),
 * narrow blocks (stock caveats into the leaf extras and, without a chain, the root caveats), a throwing predicate, the degraded
 * assurance, and an escalation request that cannot be built. Signed fixtures are tampered only under a neutral [Authorize.coreHook].
 */
@Suppress("UNCHECKED_CAST")
class Kill05AuthorizeR2Test {
    @After fun reset() { Authorize.coreHook = null }

    private val c = case("envelope-predicate-within") // chain of 1, action irreversible, counter 1
    private val d2 = case("delegated-max-spend-within") // chain of 2, leaf carries one extra caveat (max_spend)

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)
    private fun num(v: Long) = Json.Num(v.toString())

    private fun neutral(extra: (Pca.Verdict) -> Unit = {}) {
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
            extra(core)
        }
    }

    private fun pc(cs: Map<String, Any?> = c): MutableMap<String, Any?> = IntentJs.normalize(pcactn(cs)) as MutableMap<String, Any?>
    private fun gr(cs: Map<String, Any?> = c, vararg root: Map<String, Any?>): MutableMap<String, Any?> {
        val g = IntentJs.normalize(grant(cs)) as MutableMap<String, Any?>
        for (r in root) (g["caveats"] as MutableList<Any?>).add(r)
        return g
    }
    private fun action(p: Map<String, Any?>): MutableMap<String, Any?> = p["action"] as MutableMap<String, Any?>
    private fun leaf(p: Map<String, Any?>): MutableMap<String, Any?> = (p["cap_chain"] as MutableList<Any?>).last() as MutableMap<String, Any?>

    private fun input(
        cs: Map<String, Any?> = c,
        g: Map<String, Any?>? = grant(cs),
        now: Long? = NOW,
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        staleness: Revocation.StalenessPolicy? = null,
        k1: CaveatLang.K1Input? = null,
        freshAt: FreshAt.Policy? = null,
        freshAtHeader: String? = null,
        requireAssurance: Map<String, Any?>? = null,
        intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        plans: PlanLifecycle.PlanRegistry? = null,
        prov: Authorize.ProvenanceOptions = ProvHarness.options,
        allowUnsupported: List<String> = emptyList(),
    ) = Authorize.Input(
        operation = op(cs), audience = AUD, resolveGrant = { g }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false },
        now = now, plan = Authorize.SINGLE_STEP, context = context, intentV2 = intentV2, revocationStaleness = staleness, plans = plans,
        requireAssurance = requireAssurance, k1 = k1, freshAt = freshAt, freshAtHeader = freshAtHeader, insecureUnboundApproval = true,
        provenanceOptions = prov, provenance = ProvHarness.bundle(op(cs)), allowUnsupported = allowUnsupported,
    )

    private fun run(p: Any?, i: Authorize.Input) = Authorize.authorize(p, i)

    private fun noError(r: Authorize.Result) = assertFalse(r.reasons.toString(), r.checks.containsKey("authorize"))

    // ---- show(): a control character is a \\u escape of its code

    @Test fun showEscapesControlCharactersByCode() {
        val show: (String) -> String = { s -> KUtil.priv(Authorize, "show", s) }
        eq("\"a\\u0001b\"", show("a\u0001b"))
        eq("\"\\u001f\"", show("\u001f"))
        eq("\"\\ud800\"", show("\uD800"))
    }

    // ---- classRank: a non-string server class ranks as irreversible (never a cast)

    @Test fun aNonStringServerClassRanksAsIrreversible() {
        neutral()
        val r = run(pcactn(c), input(context = { mapOf("reversibility_class" to 5L) }))
        noError(r)
        eq("pass", r.checks["reversibility"])
    }

    // ---- workflow: no clock anywhere is the wall clock (the fixture commitment is long expired)

    private val wf: Map<String, Any?> by lazy { ParityVectors.load("authorize-workflow-fixtures.json") }

    @Test fun aWorkflowWithoutAnyClockUsesTheWallClock() {
        val s = (((wf["cases"] as List<Map<String, Any?>>).first { it["name"] == "pay-after-quote" })["steps"] as List<Map<String, Any?>>)[0]
        val w = s["workflow"] as Map<String, Any?>
        val g = wf["grant"] as Map<String, Any?>
        val operation = Authorize.Operation.fromJson(s["operation"])
        val call = Authorize.WorkflowStep(w["commitment"], w["receipts"], w["step"] as String?, (w["units"] as Map<String, Any?>?) ?: emptyMap(), null)
        val r = Authorize.authorize(
            s["pcactn"],
            Authorize.Input(
                operation = operation, audience = wf["audience"] as String, resolveGrant = { ref -> if (ref == g["id"]) g else null },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = null,
                context = { _ -> mapOf("plan" to wf["plan"], "plan_authorized" to true) },
                workflow = Authorize.WorkflowGate(wf["principal"] as String, wf["rs_signer"] as String, false, null), workflowCall = call,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(operation),
            ),
        )
        assertFalse(r.allow)
        eq(403, r.status)
        eq(mapOf("workflow" to "fail"), r.checks)
        eq(listOf("workflow: expired (step quote)"), r.reasons)
    }

    // ---- fresh_at: the side-carried header

    private val faLabel = "k05-r2-fresh-at"
    private val faSigner: String get() = IntentTestKit.pub(faLabel)
    private val local: FreshAt.State by lazy {
        val m = LinkedHashMap<String, Any?>()
        m["revocation_epoch"] = num(1); m["ledger_tree_size"] = num(2); m["budget_version"] = num(3); m["policy_revision"] = num(4); m["policy_digest"] = "pd"
        FreshAt.State.fromJson(m)!!
    }
    private fun faToken(): LinkedHashMap<String, Any?> {
        val t = LinkedHashMap<String, Any?>()
        t["v"] = num(1); t["scope"] = "s"; t["revocation_epoch"] = num(1); t["ledger_tree_size"] = num(2); t["budget_version"] = num(3)
        t["policy_revision"] = num(4); t["policy_digest"] = "pd"; t["issued_at"] = num(1000); t["signer"] = faSigner
        t["sig"] = IntentTestKit.sign(faLabel, IntentJs.message(FreshAt.DOMAIN, LinkedHashMap(t)))
        return t
    }

    @Test fun theSideCarriedFreshAtHeader() {
        val header = Json.canonicalize(faToken())
        // a valid header token is read and passes
        val ok = run(pcactn(c), input(freshAt = FreshAt.Policy(faSigner, "s", local), freshAtHeader = header))
        assertTrue(ok.reasons.toString(), ok.allow)
        eq("pass", ok.checks["fresh_at"])
        // the policy's token age cap is carried over to the header form
        val old = run(pcactn(c), input(freshAt = FreshAt.Policy(faSigner, "s", local, maxTokenAgeMs = 1L), freshAtHeader = header))
        assertFalse(old.allow)
        eq("fail", old.checks["fresh_at"])
        // a caller that side-carried the token itself: the header is never read
        val own = run(pcactn(c), input(freshAt = FreshAt.Policy(faSigner, "s", local, hasSideCarried = true, sideCarried = faToken()), freshAtHeader = "not json {"))
        assertTrue(own.reasons.toString(), own.allow)
        eq("pass", own.checks["fresh_at"])
        // no header and no requirement: no fresh_at entry at all
        val none = run(pcactn(c), input(freshAt = FreshAt.Policy(faSigner, "s", local)))
        assertTrue(none.reasons.toString(), none.allow)
        assertFalse(none.checks.containsKey("fresh_at"))
    }

    // ---- revocation staleness

    private val stale: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guard: String get() = stale["guardian_public"] as String

    private fun signedEpoch(grantRef: String, issuedAt: Long, epoch: Long = 0L): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to grantRef, "epoch" to epoch, "set_size" to 0L, "root" to IntentRevocation.revsetRoot(emptyList()),
            "issued_at" to issuedAt, "not_after" to issuedAt + 600_000L,
        )
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + ByteArray(32) { 11 }
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        return LinkedHashMap(body).also { it["guardian"] = guard; it["sig"] = Pca.b64(sig.sign()) }
    }

    private fun epochCtx(p: Map<String, Any?>, issuedAt: Long, cls: String?, epoch: Long = 0L): (Map<String, Any?>) -> Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("revocation_state" to mapOf("kind" to "epoch", "epoch" to signedEpoch(p["grant_ref"] as String, issuedAt, epoch)))
        if (cls != null) m["reversibility_class"] = cls
        return { m }
    }

    private val proofs: (Map<String, Any?>, String) -> Any? = { _, _ -> linkedMapOf("size" to 0L) }

    @Test fun withoutStateTheSignedClassDecides() {
        neutral()
        val rev = pc()
        action(rev)["reversibility_class"] = "reversible"
        eq("not-enforced", run(rev, input(staleness = Revocation.StalenessPolicy())).checks["freshness"])
        // no action object at all: no signed class, so the action counts as irreversible
        for (a in listOf<Any?>(null, "x")) {
            val p = pc()
            if (a == null) p.remove("action") else p["action"] = a
            val r = run(p, input(staleness = Revocation.StalenessPolicy()))
            noError(r)
            eq("fail", r.checks["freshness"])
            assertTrue(r.reasons.toString(), r.reasons.contains("freshness: no verifiable (guardian-signed) revocation state for an irreversible action"))
        }
    }

    @Test fun theStricterOfTheSignedAndServerClassCapsTheEpochAge() {
        neutral()
        val pol = Revocation.StalenessPolicy(irreversibleMs = 1_000.0, guardianPublic = guard, proofFor = proofs)
        val p = pc()
        action(p)["reversibility_class"] = "reversible"
        eq("pass", run(p, input(staleness = pol, context = epochCtx(p, NOW - 5_000, "reversible"))).checks["freshness"])
        eq("fail", run(p, input(staleness = pol, context = epochCtx(p, NOW - 5_000, "irreversible"))).checks["freshness"])
        val irr = pc() // signed irreversible
        eq("fail", run(irr, input(staleness = pol, context = epochCtx(irr, NOW - 5_000, "reversible"))).checks["freshness"])
    }

    @Test fun thePcactnEpochMustNotPredateTheRevocationEpoch() {
        neutral()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, proofFor = proofs)
        val behind = pc()
        behind["freshness"] = linkedMapOf<String, Any?>("epoch" to num(2))
        val r = run(behind, input(staleness = pol, context = epochCtx(behind, NOW - 1_000, "reversible", epoch = 3L)))
        eq("fail", r.checks["freshness"])
        assertTrue(r.reasons.toString(), r.reasons.any { it.startsWith("freshness: PCActn freshness.epoch 2 predates the revocation epoch") })
        for (f in listOf<Any?>(linkedMapOf<String, Any?>("epoch" to num(5)), "x", null)) {
            val p = pc()
            if (f == null) p.remove("freshness") else p["freshness"] = f
            val ok = run(p, input(staleness = pol, context = epochCtx(p, NOW - 1_000, "reversible", epoch = 3L)))
            noError(ok)
            assertEquals("freshness=$f ${ok.reasons}", "pass", ok.checks["freshness"])
        }
    }

    @Test fun customIdsReplaceTheHopIdsEvenWhenEmpty() {
        val p = pc()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, ids = { emptyList() })
        val r = run(p, input(staleness = pol, context = epochCtx(p, NOW - 1_000, "reversible")))
        assertTrue(r.reasons.toString(), r.allow)
        eq("pass", r.checks["freshness"])
    }

    @Test fun theHopIdsAreTheStringIdsOfMapHops() {
        neutral()
        val p = pc()
        val hop = leaf(p)
        p["cap_chain"] = mutableListOf<Any?>("x", linkedMapOf<String, Any?>("id" to num(5)), hop)
        val ids = ArrayList<Any?>()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, proofFor = { _, id -> ids.add(id); linkedMapOf("size" to 0L) })
        val r = run(p, input(staleness = pol, context = epochCtx(p, NOW - 1_000, "reversible")))
        eq(listOf<Any?>(hop["id"]), ids)
        eq("pass", r.checks["freshness"])
        // a chain that is not a list has no hop ids
        val q = pc()
        q["cap_chain"] = "x"
        val rq = run(q, input(staleness = Revocation.StalenessPolicy(guardianPublic = guard), context = epochCtx(q, NOW - 1_000, "reversible")))
        noError(rq)
        eq("pass", rq.checks["freshness"])
    }

    @Test fun theAcceptedEpochPinRunsOnlyForAnAcceptedEpoch() {
        var calls = 0
        // a Function2 over Any? (as a Java host would pass): a Kotlin lambda's own non-null parameter check would throw before
        // counting, inside authorize's catch, and hide a call made with no accepted epoch
        @Suppress("UNCHECKED_CAST")
        val pin = object : Function2<Any?, Any?, Unit> { override fun invoke(a: Any?, b: Any?) { calls++ } } as (Map<String, Any?>, Map<String, Any?>) -> Unit
        val pol = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true, onEpochAccepted = pin)
        val r = run(pcactn(c), input(staleness = pol))
        assertTrue(r.reasons.toString(), r.allow)
        eq("not-enforced", r.checks["freshness"])
        eq(0, calls)
    }

    // ---- the plan leaf conditions

    private fun nodes(p: Map<String, Any?>, cls: Any?, id: Any? = "n1", pre: Any? = null, post: Any? = null): List<Map<String, Any?>> {
        val a = p["action"] as Map<String, Any?>
        val n = linkedMapOf<String, Any?>("id" to id, "verb" to a["verb"], "resource" to a["resource"], "params_digest" to a["params_digest"], "reversibility_class" to cls)
        if (pre != null) n["pre"] = pre
        if (post != null) n["post"] = post
        return listOf(n)
    }
    private fun rootOf(ns: List<Map<String, Any?>>): String {
        val n = ns[0]
        return Pca.merkleRoot(listOf(Pca.planLeaf(n["id"], n, Pca.conditionsDigest(n["pre"], n["post"]))))
    }

    @Test fun aPlanNodesConditionsAreInItsLeaf() {
        neutral()
        val p = pc()
        val ns = nodes(p, "irreversible", pre = "a", post = "b")
        (p["plan"] as MutableMap<String, Any?>)["root"] = rootOf(ns)
        val r = run(p, input(context = { mapOf("plan" to ns, "plan_authorized" to true) }))
        assertTrue(r.reasons.toString(), r.allow)
        eq("pass", r.checks["plan_root_authorized"])
    }

    // ---- the caveat context

    @Test fun noChainIsDepthZeroNotMinusOne() {
        neutral()
        val p = pc()
        p["cap_chain"] = mutableListOf<Any?>()
        val r = run(p, input(g = gr(c, mapOf("type" to "delegation_depth", "max" to -1L))))
        eq(listOf("policy: root caveat(s) not satisfied: delegation_depth"), r.reasons)
    }

    private fun withPredicate(where: Map<String, Any?>): MutableMap<String, Any?> {
        val g = gr(c)
        val env = (g["caveats"] as MutableList<Any?>)[0] as MutableMap<String, Any?>
        env["predicates"] = mutableListOf<Any?>(linkedMapOf("verb" to "payments.send", "resource" to "payments/*", "where" to mutableListOf<Any?>(where)))
        return g
    }

    @Test fun noEffectiveClassLeavesTheMemberAbsent() {
        neutral()
        val p = pc()
        val ns = nodes(p, "irreversible")
        (p["plan"] as MutableMap<String, Any?>)["root"] = rootOf(ns)
        action(p).remove("reversibility_class")
        val g = withPredicate(linkedMapOf("field" to "action.reversibility_class", "op" to "exists", "value" to false))
        val r = run(p, input(g = g, context = { mapOf("plan" to ns, "plan_authorized" to true) }))
        assertTrue(r.reasons.toString(), r.allow)
    }

    @Test fun anIntentSessionEnvDropsTheReservedMembers() {
        neutral()
        val p = pc()
        p["intent_session"] = "x"
        val g = withPredicate(linkedMapOf("field" to "env.canon", "op" to "exists", "value" to false))
        val r = run(p, input(g = g, context = { mapOf("env" to mapOf("canon" to 1L)) }))
        eq("pass", r.checks["policy"])
    }

    @Test fun theToolNameIsTheVerb() {
        val ts = case("delegated-tool-schema-within")
        val ok = run(pcactn(ts), input(cs = ts))
        assertTrue(ok.reasons.toString(), ok.allow)
        neutral()
        val p = pc()
        action(p)["verb"] = num(5)
        noError(run(p, input()))
    }

    @Test fun theDeclaredClassWinsOverThePlanNode() {
        neutral()
        // a declared (signed) class: the plan node's class is never consulted
        val p = pc()
        action(p)["reversibility_class"] = "reversible"
        val ns = nodes(p, "irreversible")
        (p["plan"] as MutableMap<String, Any?>)["node_id"] = "n1"
        (p["plan"] as MutableMap<String, Any?>)["root"] = rootOf(ns)
        val r = run(p, input(g = gr(c, mapOf("type" to "reversibility_max", "class" to "reversible")), context = { mapOf("plan" to ns, "plan_authorized" to true) }))
        assertTrue(r.reasons.toString(), r.allow)
        // a node id that is not a string never selects a node
        val q = pc()
        action(q).remove("reversibility_class")
        val qn = nodes(q, "rate_limited", id = num(5))
        (q["plan"] as MutableMap<String, Any?>)["node_id"] = num(5)
        (q["plan"] as MutableMap<String, Any?>)["root"] = rootOf(qn)
        val rq = run(q, input(g = gr(c, mapOf("type" to "reversibility_max", "class" to "rate_limited")), context = { mapOf("plan" to qn, "plan_authorized" to true) }))
        eq(listOf("policy: root caveat(s) not satisfied: reversibility_max"), rq.reasons)
        // a plan that is not a list is never walked
        val x = pc()
        action(x).remove("reversibility_class")
        (x["plan"] as MutableMap<String, Any?>)["node_id"] = "n1"
        val rx = run(x, input(context = { mapOf("plan" to "x", "plan_authorized" to true) }))
        noError(rx)
        eq("fail", rx.checks["plan_root_authorized"])
    }

    // ---- narrow blocks: their stock caveats join the leaf extras (with a chain) or the root caveats (without)

    private val nbLabel = "k05-r2-narrow"
    private val nbHolder: String get() = IntentTestKit.pub(nbLabel)

    private fun narrow(hop: Map<String, Any?>, p: Map<String, Any?>, vararg cav: Map<String, Any?>): Map<String, Any?> {
        val nb = linkedMapOf<String, Any?>(
            "v" to num(1), "kind" to "pca-narrow", "cap_hash" to Pca.capHash(hop), "holder" to nbHolder, "caveats" to cav.toMutableList<Any?>(),
            "iat" to num(NOW - 1_000), "not_after" to num(NOW + 1_000), "nonce" to KUtil.B32, "action_digest" to CaveatLang.dischargeActionDigest(p),
        )
        nb["sig"] = IntentTestKit.sign(nbLabel, IntentArtifacts.artifactMessage(CaveatLang.NARROW_DOMAIN, nb))
        return nb
    }
    private fun expired() = linkedMapOf<String, Any?>("type" to "expires", "at" to num(NOW - 1))
    private fun notYet() = linkedMapOf<String, Any?>("type" to "not_before", "at" to num(NOW + 1))

    @Test fun aNarrowBlocksStockCaveatsJoinTheLeafExtras() {
        neutral()
        val p = pc(d2)
        val hop = leaf(p)
        hop["holder"] = nbHolder
        (hop["caveats"] as MutableList<Any?>).add(notYet())
        val k1 = CaveatLang.K1Input(narrow = narrow(hop, p, expired()))
        val r = run(p, input(cs = d2, k1 = k1))
        assertFalse(r.allow)
        eq("pass", r.checks["policy"])
        eq(listOf("delegated_caveats: delegation caveat(s) not satisfied: not_before, expires"), r.reasons)
    }

    @Test fun withoutAChainANarrowBlocksStockCaveatsJoinTheRootCaveats() {
        neutral()
        val p = pc()
        p["cap_chain"] = mutableListOf<Any?>()
        val g = gr(c, notYet())
        g["holder"] = nbHolder
        val k1 = CaveatLang.K1Input(narrow = narrow(g, p, expired()))
        val r = run(p, input(g = g, k1 = k1))
        assertFalse(r.allow)
        eq(listOf("policy: root caveat(s) not satisfied: not_before, expires"), r.reasons)
    }

    @Test fun aLeafWithoutCaveatsUnderANarrowBlockFailsClosedWithoutAnError() {
        neutral()
        val p = pc(d2)
        val hop = leaf(p)
        hop.remove("caveats")
        hop["holder"] = nbHolder
        val r = run(p, input(cs = d2, k1 = CaveatLang.K1Input(narrow = narrow(hop, p, expired()))))
        assertFalse(r.allow)
        noError(r)
        eq("fail", r.checks["delegated_caveats"])
    }

    @Test fun anAbsentNarrowBlockLeavesTheStockPathAlone() {
        neutral()
        for (k1 in listOf<CaveatLang.K1Input?>(null, CaveatLang.K1Input())) {
            val p = pc(d2)
            leaf(p).remove("caveats")
            val r = run(p, input(cs = d2, k1 = k1))
            assertEquals("k1=$k1", listOf("delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>"), r.reasons)
        }
    }

    // ---- a predicate evaluation that throws a checked exception

    @Test fun aThrowingPredicateIsAPolicyError() {
        neutral()
        val hostile = object : java.util.AbstractMap<String, Any?>() {
            override val entries: MutableSet<MutableMap.MutableEntry<String, Any?>>
                get() {
                    if (Thread.currentThread().stackTrace.any { it.methodName.contains("envelopePredicates") }) throw java.io.IOException("predicate store")
                    return LinkedHashSet()
                }
        }
        val g = gr(c)
        ((g["caveats"] as MutableList<Any?>)[0] as MutableMap<String, Any?>)["predicates"] = mutableListOf<Any?>(hostile)
        val r = run(pcactn(c), input(g = g))
        noError(r)
        eq("fail", r.checks["policy"])
        assertTrue(r.reasons.toString(), r.reasons.contains("policy: policy evaluation error (fail closed)"))
    }

    // ---- a high-assurance policy never accepts the legacy-polarity tighten pass

    @Test fun aDegradedTightenPassFailsTheAssurancePolicy() {
        Authorize.coreHook = { core -> core.legacyModelPolarity = true; core.checks["tighten"] = true }
        val r = run(pcactn(c), input(requireAssurance = emptyMap()))
        assertFalse(r.allow)
        eq("fail", r.checks["assurance"])
        assertTrue(r.reasons.toString(), r.reasons.any { it.startsWith("assurance: tighten rests on a degraded") })
        Authorize.coreHook = null
        assertTrue(run(pcactn(c), input(requireAssurance = emptyMap())).allow)
    }

    // ---- an escalation whose request cannot be built is a plain deny

    @Test fun anUnbuildableEscalationRequestIsADeny() {
        neutral { core ->
            core.checks["tighten"] = false
            core.reasons.add("tighten: escalate: asked by tighten rule 'a'")
            core.allow = false
        }
        val g = gr(c)
        g["zz"] = "\uD800" // the policy digest cannot canonicalize a lone surrogate
        val r = run(pcactn(c), input(g = g))
        assertFalse(r.allow)
        noError(r)
        eq("deny", r.decision)
        assertNull(r.escalation)
        eq("fail", r.checks["tighten"])
    }

    // ---- the plan registry: a registered plan the principal has not approved is not the principal's plan

    @Test fun anUnapprovedRegisteredPlanDoesNotTrustTheProvenance() {
        neutral()
        val p = pc()
        val reg = PlanLifecycle.PlanRegistry()
        val t = reg.draft(p["grant_ref"] as String, nodes(p, "irreversible"))
        assertTrue(t.reason, t.ok)
        (p["plan"] as MutableMap<String, Any?>)["root"] = t.record!!["root"]
        // web content was observed in this session: only a principal-approved plan makes the control and params trusted
        val web = Authorize.ProvenanceOptions(listOf(ProvHarness.pin), observed = { _, _, _ -> listOf<Any?>(mapOf("origin" to "web", "source" to "news")) })
        val r = run(p, input(plans = reg, prov = web))
        assertFalse(r.allow)
        eq("fail", r.checks["plan_state"])
        eq("fail", r.checks["provenance_flow"])
    }

    // ---- the Intent v2 context the core receives

    /** A grant whose envelope carries one tighten rule (so the v2 pipeline runs even without a v2 context). */
    private fun tightenGrant(field: String): MutableMap<String, Any?> {
        val g = gr(c)
        val env = (g["caveats"] as MutableList<Any?>)[0] as MutableMap<String, Any?>
        env["tighten"] = mutableListOf<Any?>(
            linkedMapOf<String, Any?>("id" to "t", "when" to linkedMapOf<String, Any?>("field" to field, "op" to "exists", "value" to true), "signal" to "deny"),
        )
        return g
    }

    /** Neutral, except the core's own tighten verdict (the edited grant breaks the signed bindings, not the rule). */
    private fun keepTighten() {
        Authorize.coreHook = { core ->
            val t = core.checks["tighten"]
            val why = core.reasons.filter { it.startsWith("tighten:") }
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
            if (t == false) {
                core.checks["tighten"] = false
                core.reasons.addAll(why)
                core.allow = false
            }
        }
    }

    private val deniedByT = "tighten: denied by tighten rule 't'"

    private val bondRefused = "bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)"

    /** server/verify.ts:528-533: a carried bond is never a pass, and denies unless the check is listed. */
    @Test fun aCarriedBondDenies() {
        neutral()
        val p = LinkedHashMap(pcactn(c)).also { it["bond_ref"] = "b1" }
        val r = run(p, input())
        assertFalse(r.reasons.toString(), r.allow)
        eq(403, r.status)
        eq("deny", r.decision)
        eq("unsupported", r.checks["bond"])
        eq(listOf(bondRefused), r.reasons)
        // listed: reported, not denied
        val ok = run(p, input(allowUnsupported = listOf("bond")))
        assertTrue(ok.reasons.toString(), ok.allow)
        eq("unsupported", ok.checks["bond"])
        assertFalse(run(p, input(allowUnsupported = listOf("other"))).allow)
        // no bond: no check
        val plain = run(pcactn(c), input())
        assertTrue(plain.reasons.toString(), plain.allow)
        assertFalse(plain.checks.containsKey("bond"))
        // already refused for another reason: both are reported
        val both = run(LinkedHashMap(p).also { it["action"] = LinkedHashMap(action(p)).also { a -> a["verb"] = "other" } }, input())
        assertFalse(both.allow)
        assertTrue(both.reasons.toString(), both.reasons.contains(bondRefused) && both.checks["operation"] == "fail")
    }

    /** server/verify.ts:299: a pin alone runs the v2 pipeline, and with no schema configured it fails closed. */
    @Test fun aGrantPinAloneRunsTheV2Pipeline() {
        var pinCheck: Boolean? = null
        var why: List<String> = emptyList()
        Authorize.coreHook = { core -> pinCheck = core.checks["pin"]; why = core.reasons.toList() }
        val g = gr(c)
        val env = (g["caveats"] as MutableList<Any?>)[0] as MutableMap<String, Any?>
        env["actions"] = linkedMapOf<String, Any?>("pack" to linkedMapOf("ns" to "stripe", "root" to "Q".repeat(43)), "on_new_action" to "deny")
        run(pcactn(c), input(g = g))
        eq(false, pinCheck)
        assertTrue(why.toString(), why.any { it == "pin: this verifier has no action schema configured" })
    }

    @Test fun aHostV2ContextKeepsItsOwnParams() {
        keepTighten()
        val g = tightenGrant("action.params.zz")
        // the operation has no zz: without a v2 context the rule cannot hold
        val plain = run(pcactn(c), input(g = g))
        assertFalse(plain.reasons.toString(), plain.reasons.any { it.startsWith(deniedByT) })
        // the host's own params win over the operation's (and its context is never replaced by an empty one)
        val host = run(pcactn(c), input(g = g, intentV2 = { IntentV2.Context.fromJson(mapOf("params" to mapOf("zz" to 1L))) }))
        eq("fail", host.checks["tighten"])
        assertTrue(host.reasons.toString(), host.reasons.any { it.startsWith(deniedByT) })
    }

    @Test fun aHostV2ContextKeepsItsOwnEnv() {
        keepTighten()
        val g = tightenGrant("env.k")
        val host = run(pcactn(c), input(g = g, intentV2 = { IntentV2.Context.fromJson(mapOf("env" to mapOf("k" to 1L))) }))
        eq("fail", host.checks["tighten"])
        assertTrue(host.reasons.toString(), host.reasons.any { it.startsWith(deniedByT) })
        // with no env of its own, the authorize context's env is used
        val ctxEnv = run(pcactn(c), input(g = g, intentV2 = { IntentV2.Context.fromJson(emptyMap<String, Any?>()) }, context = { mapOf("env" to mapOf("k" to 1L)) }))
        assertTrue(ctxEnv.reasons.toString(), ctxEnv.reasons.any { it.startsWith(deniedByT) })
    }

    @Test fun aMalformedV2ContextIsNeverGivenTheHostEnv() {
        // the host env is not JSON (a non-string key): copying it into a malformed context would fail on the copy
        val env = mapOf("x" to mapOf(1L to 2L))
        val r = run(pcactn(c), input(intentV2 = { IntentV2.Context.fromJson("x") }, context = { mapOf("env" to env) }))
        assertFalse(r.allow)
        noError(r)
    }

    @Test fun noV2ContextIsBuiltForAGrantWithoutModelRules() {
        // a non-object host env would make a built context malformed (schema / intent_session fail); with no context it is unread by the core
        val r = run(pcactn(c), input(context = { mapOf("env" to "x") }))
        assertTrue(r.reasons.toString(), r.allow)
        assertFalse(r.checks.containsKey("schema"))
    }
}
