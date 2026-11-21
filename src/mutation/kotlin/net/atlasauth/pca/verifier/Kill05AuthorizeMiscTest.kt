package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
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
 * Authorize.kt k05 survivors outside the pipeline body: the value classes and their accessors, the replay-store defaults, the
 * envelope / model-rule readers, the decisive reason, the proof coercion's size limits, the outer fail-closed handler, the provenance
 * bundle's session, the Intent v2 predicate env, and isAuthorizedFor.
 */
@Suppress("UNCHECKED_CAST")
class Kill05AuthorizeMiscTest {
    @After fun reset() { Authorize.coreHook = null }

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)

    private fun throwsIae(want: String, body: () -> Unit) {
        try { body(); fail("expected IllegalArgumentException") } catch (e: IllegalArgumentException) { eq(want, e.message) }
    }

    // ---- value classes

    @Test fun operationFromJsonRefusesEveryMistypedMember() {
        assertNull(Authorize.Operation.fromJson(mapOf("verb" to 5L, "resource" to "r", "params" to mapOf<String, Any?>())))
        assertNull(Authorize.Operation.fromJson(mapOf("verb" to "v", "resource" to 5L, "params" to mapOf<String, Any?>())))
        assertNull(Authorize.Operation.fromJson(mapOf("verb" to "v", "resource" to "r", "params" to 5L)))
        assertNull(Authorize.Operation.fromJson("x"))
        eq(Authorize.Operation("v", "r", mapOf("a" to 1L)), Authorize.Operation.fromJson(mapOf("verb" to "v", "resource" to "r", "params" to mapOf("a" to 1L))))
    }

    @Test fun resultMembers() {
        val plain = Authorize.Result(false, 403, linkedMapOf("a" to "fail"), listOf("a: x"), "a: x")
        assertFalse(plain.legacyModelPolarity)
        assertNull(plain.verdict)
        eq("Authorize.Result(allow=false, decision=deny, status=403, reason=a: x, checks={a=fail})", plain.toString())
        val v = Pca.Verdict()
        val legacy = Authorize.Result(true, 200, emptyMap(), emptyList(), null, verdict = v, legacyModelPolarity = true)
        assertTrue(legacy.legacyModelPolarity)
        assertSame(v, legacy.verdict)
        eq("allow", legacy.decision)
    }

    @Test fun workflowAndInputMembers() {
        val clock: () -> Long = { 7L }
        assertSame(clock, Authorize.WorkflowGate("p", "s", now = clock).now)
        val step = Authorize.WorkflowStep(null, null, "s", mapOf("u" to "x"), "g")
        eq(mapOf("u" to "x"), step.units)
        eq("g", step.goalDigest)
        val ip = Pca.IntentPolicy(require = true)
        val suites = listOf("ed25519")
        val input = Authorize.Input(null, "a", null, null, null, intentPolicy = ip, allowedSuites = suites, risk = AuthorizeTestKit.calmRisk)
        assertSame(ip, input.intentPolicy)
        assertSame(suites, input.allowedSuites)
    }

    @Test fun authorizeOptionsMembers() {
        val store = Authorize.MemoryStateStore()
        val ctx: (Map<String, Any?>) -> Map<String, Any?>? = { null }
        val stale = Revocation.StalenessPolicy()
        val k1 = CaveatLang.K1Input()
        val render: (Map<String, Any?>) -> String? = { "r" }
        val wf = Authorize.WorkflowGate("p", "s")
        val prov = Authorize.ProvenanceOptions()
        val undo = Authorize.UndoHook { _, _, _ -> null }
        val principals = listOf(Escalation.Principal("pk"))
        val o = Authorize.AuthorizeOptions(
            store, { _, _ -> false }, plan = null, context = ctx, require = listOf("x"), escalationPrincipals = principals,
            revocationStaleness = stale, requireAssurance = mapOf("signature" to "pq"), k1 = k1, usesStore = store, escalationRender = render,
            insecureUnboundApproval = true, workflow = wf, provenance = prov, undo = undo, risk = AuthorizeTestKit.calmRisk,
        )
        assertSame(store, o.stateStore)
        assertNull(o.plan)
        assertNull(Authorize.AuthorizeOptions(store, null, risk = AuthorizeTestKit.calmRisk).plan)
        assertSame(ctx, o.context)
        eq(listOf("x"), o.require)
        assertSame(principals, o.escalationPrincipals)
        assertSame(stale, o.revocationStaleness)
        eq(mapOf("signature" to "pq"), o.requireAssurance)
        assertSame(k1, o.k1)
        assertSame(store, o.usesStore)
        assertSame(render, o.escalationRender)
        assertTrue(o.insecureUnboundApproval)
        assertFalse(Authorize.AuthorizeOptions(store, null, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).insecureUnboundApproval)
        assertSame(wf, o.workflow)
        assertSame(prov, o.provenance)
        assertSame(undo, o.undo)
        // escalation answers need a LastStore
        val plainStore = object : Authorize.StateStore { override fun claim(key: String, counter: Long): Authorize.ClaimResult? = null }
        throwsIae(Authorize.ESCALATION_NEEDS_LAST) { Authorize.AuthorizeOptions(plainStore, null, escalationPrincipals = principals, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk) }
        throwsIae(Authorize.ESCALATION_NEEDS_LAST) { Authorize.Input(null, "a", null, plainStore, null, escalationPrincipals = principals, risk = AuthorizeTestKit.calmRisk) }
    }

    @Test fun coreHookAccessor() {
        val h: (Pca.Verdict) -> Unit = { }
        Authorize.coreHook = h
        assertSame(h, Authorize.coreHook)
    }

    // ---- replay stores

    private class Recording(val answer: Authorize.ClaimResult?) : Authorize.StateStore {
        val seen = ArrayList<Pair<String, Long>>()
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? { seen.add(Pair(key, counter)); return answer }
    }

    @Test fun theDefaultConsumeOnceIsAClaimOfOne() {
        val ok = Recording(Authorize.ClaimResult(true))
        assertTrue(ok.consumeOnce("k", 5L, 5L))
        eq(listOf(Pair("k", 1L)), ok.seen)
        assertFalse(Recording(Authorize.ClaimResult(false, 1L)).consumeOnce("k", 6L, 5L))
        assertFalse(Recording(null).consumeOnce("k", 6L, 5L))
        val msg = "consumeOnce needs a key and a retention horizon not before now"
        throwsIae(msg) { ok.consumeOnce("", 6L, 5L) }
        throwsIae(msg) { ok.consumeOnce("k", 4L, 5L) }
        eq(1, ok.seen.size)
    }

    @Test fun memoryConsumeOnceKeepsTheLatestHorizon() {
        val m = Authorize.MemoryStateStore()
        throwsIae("consumeOnce needs a key and a retention horizon not before now") { m.consumeOnce("", 10L, 0L) }
        assertTrue(m.consumeOnce("k", 10L, 0L))
        assertFalse(m.consumeOnce("k", 100L, 5L)) // live: refused, the horizon grows to 100
        assertFalse(m.consumeOnce("k", 200L, 50L)) // still live at 50 only because the horizon grew
        assertTrue(m.consumeOnce("k", 400L, 300L)) // expired at 300 (horizon 200)
        assertTrue(m.consumeOnce("j", 7L, 7L))
        eq(Authorize.ClaimResult(true), m.claim("s", 3L))
        eq(Authorize.ClaimResult(false, 3L), m.claim("s", 3L))
        eq(3L, m.last("s"))
        assertNull(m.last("t"))
    }

    // ---- envelope readers

    private fun envCaveat(vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val e = KUtil.m(
            "type" to "envelope", "goal_commit" to "g", "predicates" to KUtil.l(KUtil.m("verb" to "*")), "caveats" to KUtil.l(),
            "agent_binding" to KUtil.m(), "risk_policy" to Issue.defaultRiskPolicy(),
        )
        for ((k, v) in extra) e[k] = v
        return e
    }

    private fun needsModelRules(grant: Any?): Boolean = KUtil.priv(Authorize, "needsModelRules", grant)

    @Test fun modelRulesAreNeededOnlyForTheirMembers() {
        assertFalse(needsModelRules(KUtil.m("caveats" to KUtil.l())))
        assertFalse(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat()))))
        assertTrue(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat("units" to KUtil.m())))))
        assertTrue(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat("tighten" to KUtil.l())))))
        assertTrue(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat("model_polarity" to "legacy")))))
        val model = KUtil.l(KUtil.m("verb" to "*", "where" to KUtil.l(KUtil.m("field" to "env.class.tone", "op" to "eq", "value" to "x"))))
        assertTrue(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat("predicates" to model)))))
        val plain = KUtil.l(KUtil.m("verb" to "*", "where" to KUtil.l(KUtil.m("field" to "action.params.amount", "op" to "eq", "value" to 1L))))
        assertFalse(needsModelRules(KUtil.m("caveats" to KUtil.l(envCaveat("predicates" to plain)))))
    }

    @Test fun theEnvelopeIsTheFirstEnvelopeCaveat() {
        val g = KUtil.m("caveats" to KUtil.l(KUtil.m("type" to "expires", "at" to 1L), envCaveat("x" to 1L), envCaveat("x" to 2L)))
        val e = Authorize.readEnvelope(g)!!
        eq(1L, e["x"])
        assertFalse(e.containsKey("type"))
        assertNull(Authorize.readEnvelope(KUtil.m("caveats" to KUtil.l(KUtil.m("type" to "expires")))))
    }

    // ---- decisive

    private fun decisive(checks: Map<String, String>, vararg reasons: String): String = KUtil.priv(Authorize, "decisive", checks, listOf(*reasons))

    @Test fun theDecisiveReason() {
        eq("operation: O", decisive(linkedMapOf("a" to "fail", "operation" to "fail"), "a: A", "operation: O"))
        eq("b: B", decisive(linkedMapOf("a" to "pass", "b" to "fail"), "a: A", "b: B"))
        eq("b: B", decisive(linkedMapOf("operation" to "fail", "b" to "fail"), "b: B"))
        eq("a: y", decisive(linkedMapOf("a" to "fail"), "ab: x", "a: y", "a: z"))
        eq("policy: b", decisive(linkedMapOf("policy" to "fail"), "POLICY: a", "policy: b"))
        eq("zz", decisive(linkedMapOf("a" to "fail"), "zz", "yy"))
        eq("denied", decisive(linkedMapOf("a" to "fail")))
        eq("denied", decisive(linkedMapOf()))
    }

    // ---- proof coercion

    @Test fun coercionSizeLimits() {
        val max = Pca.MAX_ARTIFACT_BYTES
        val atMax = ("{\"a\":\"" + "x".repeat(max - 8) + "\"}").toByteArray(Charsets.UTF_8)
        eq(max, atMax.size)
        val okBytes = Authorize.coerceProof(atMax)
        assertNull(okBytes.second)
        eq(max - 8, (okBytes.first!!["a"] as String).length)
        eq(Pair(null, "undecodable"), Authorize.coerceProof(ByteArray(max + 1) { ' '.code.toByte() }))
        eq(Pair(null, "undecodable"), Authorize.coerceProof(byteArrayOf(0xff.toByte())))
        eq(Pair(null, "undecodable"), Authorize.coerceProof("{\"a\":\"" + "x".repeat(max) + "\"}"))
        eq(Pair(null, "absent"), Authorize.coerceProof(null))
        eq(Pair(null, "undecodable"), Authorize.coerceProof(5L))
        eq(Pair(null, "undecodable"), Authorize.coerceProof("[1]"))
    }

    // ---- the outer handler

    @Test fun aStackOverflowInsideIsADenial() {
        // a host callback that overflows is contained where it is called (grant resolution here) ...
        val contained = Authorize.authorize(
            KUtil.m("grant_ref" to "g"),
            Authorize.Input(
                operation = Authorize.Operation("v", "r", emptyMap()), audience = "a", resolveGrant = { throw StackOverflowError() },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = 1L, risk = AuthorizeTestKit.calmRisk,
            ),
        )
        assertFalse(contained.allow)
        eq(mapOf("resolve_grant" to "fail"), contained.checks)
        // ... and one that escapes inside the pipeline reaches the outer handler
        try {
            Authorize.coreHook = { throw StackOverflowError() }
            val r = Authorize.authorize(
                KUtil.m("grant_ref" to "g"),
                Authorize.Input(
                    operation = Authorize.Operation("v", "r", emptyMap()), audience = "a", resolveGrant = { KUtil.m("id" to "g") },
                    stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = 1L, risk = AuthorizeTestKit.calmRisk,
                ),
            )
            assertFalse(r.allow)
            eq(403, r.status)
            eq(mapOf("authorize" to "fail"), r.checks)
            eq("authorize: error (fail closed): StackOverflowError", r.reason)
        } finally {
            Authorize.coreHook = null
        }
    }

    // ---- provenance bundle session

    private fun bundleSession(b: Any?): String? = KUtil.priv(Authorize, "bundleSession", b)

    @Test fun theBundleSessionIsTheFirstReceipts() {
        eq("s1", bundleSession(KUtil.m("receipts" to KUtil.l(KUtil.m("session" to "s1"), KUtil.m("session" to "s2")))))
        for (b in listOf<Any?>(null, "x", KUtil.m(), KUtil.m("receipts" to "x"), KUtil.m("receipts" to KUtil.l()), KUtil.m("receipts" to KUtil.l(5L)),
            KUtil.m("receipts" to KUtil.l(KUtil.m())), KUtil.m("receipts" to KUtil.l(KUtil.m("session" to 5L)))))
            assertNull("$b", bundleSession(b))
    }

    // ---- the Intent v2 predicate env

    private val v2case: Map<String, Any?> by lazy {
        val all = GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-intentv2-cases.json.gz"))).use {
            (Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8)) as Map<String, Any?>)["cases"] as List<Map<String, Any?>>
        }
        all.first { it["name"] == "vec/session-g0" }
    }

    @Test fun theV2EnvReplacesTheVerifierComputedMembers() {
        val p = Json.parseLenient(v2case["p"] as String) as Map<String, Any?>
        val grant = Json.parseLenient(v2case["grant"] as String) as Map<String, Any?>
        val ctx = IntentV2.Context.fromJsonText(v2case["ctx"] as String)
        val now = (v2case["now"] as Json.Num).raw.toLong()
        val decided = IntentV2.decide(p, grant, ctx, now).env
        eq(listOf("acc", "canon", "mon"), decided.keys.sorted())
        val host = KUtil.m("acc" to "h", "mon" to "h", "canon" to "h", "world" to "h", "prov" to "h", "class" to "h", "keep" to 1L)
        val got = KUtil.priv<Map<String, Any?>>(Authorize, "v2Env", p, grant, ctx, now, host)
        eq(listOf("keep") + decided.keys.toList(), got.keys.toList())
        eq(1L, got["keep"])
        for (k in decided.keys) eq(Json.canonicalize(decided[k]), Json.canonicalize(got[k]))
        // without an intent session the host env is used as is
        val bare = LinkedHashMap(p).also { it.remove("intent_session") }
        assertSame(host, KUtil.priv<Any?>(Authorize, "v2Env", bare, grant, ctx, now, host))
    }

    // ---- isAuthorizedFor

    @Test fun isAuthorizedForNeedsAnAllowBoundToTheOperation() {
        val o = Authorize.Operation("v", "r", mapOf("a" to 1L))
        val bound = Authorize.AuthorizedOperation("v", "r", Pca.paramsDigest(Json.parse(Json.canonicalize(o.params))), "id")
        val allow = Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = bound)
        assertTrue(Authorize.isAuthorizedFor(allow, o))
        assertFalse(Authorize.isAuthorizedFor(Authorize.Result(false, 403, emptyMap(), emptyList(), null, operation = bound), o))
        assertFalse(Authorize.isAuthorizedFor(null, o))
        assertFalse(Authorize.isAuthorizedFor(allow, Authorize.Operation("v", "r", mapOf("a" to 2L))))
        // params outside the JSON model throw inside: fail closed
        assertFalse(Authorize.isAuthorizedFor(allow, Authorize.Operation("v", "r", mapOf("a" to Any()))))
        assertNotNull(allow.operation)
    }
}
