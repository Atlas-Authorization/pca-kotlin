package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Authorize.kt k05 survivors inside the authorize pipeline: the early refusals (operation, grant_ref, resolveGrant, context, plan
 * registry, Intent v2 state, wire), the wall clock, the core-option forwarding, revocation staleness, the action / plan / chain
 * readers, the reversibility class, every caveat-context member (subject, env, blast radius, reversibility, rate, delegation depth),
 * the delegated extra caveats and the K1 reasons, the required checks, the escalation ternary (replay first, answers, undo windows),
 * workflow admission and the counter stream. Signed fixtures are tampered only under a neutral [Authorize.coreHook].
 */
@Suppress("UNCHECKED_CAST")
class Kill05AuthorizePipelineTest {
    @After fun reset() { Authorize.coreHook = null }

    private val c = case("envelope-predicate-within") // chain of 1, action irreversible, counter 1
    private val d2 = case("delegated-max-spend-within") // chain of 2, leaf carries one extra caveat (max_spend)

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)

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

    private fun inject(check: String, reason: String) {
        Authorize.coreHook = { core ->
            core.checks[check] = false
            core.reasons.add("$check: $reason")
            core.allow = false
        }
    }

    private fun pc(cs: Map<String, Any?> = c): MutableMap<String, Any?> = IntentJs.normalize(pcactn(cs)) as MutableMap<String, Any?>
    private fun gr(cs: Map<String, Any?> = c, vararg root: Map<String, Any?>): MutableMap<String, Any?> {
        val g = IntentJs.normalize(grant(cs)) as MutableMap<String, Any?>
        for (r in root) (g["caveats"] as MutableList<Any?>).add(r)
        return g
    }
    private fun leafCaveats(p: Map<String, Any?>): MutableList<Any?> {
        val chain = p["cap_chain"] as MutableList<Any?>
        return (chain[chain.size - 1] as MutableMap<String, Any?>)["caveats"] as MutableList<Any?>
    }

    private fun input(
        cs: Map<String, Any?> = c,
        g: Map<String, Any?>? = grant(cs),
        operation: Authorize.Operation? = op(cs),
        now: Long? = NOW,
        resolve: ((String) -> Map<String, Any?>?)? = { g },
        store: Authorize.StateStore = Authorize.MemoryStateStore(),
        plan: String? = Authorize.SINGLE_STEP,
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        intentPolicy: Pca.IntentPolicy? = null,
        intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        allowedSuites: List<String>? = null,
        require: List<String> = emptyList(),
        principals: List<Escalation.Principal> = emptyList(),
        answer: Any? = null,
        staleness: Revocation.StalenessPolicy? = null,
        plans: PlanLifecycle.PlanRegistry? = null,
        undo: Authorize.UndoHook? = null,
    ) = Authorize.Input(
        operation = operation, audience = AUD, resolveGrant = resolve, stateStore = store, isRevoked = { _, _ -> false }, now = now,
        plan = plan, context = context, intentPolicy = intentPolicy, intentV2 = intentV2, allowedSuites = allowedSuites, require = require,
        escalationPrincipals = principals, escalationAnswer = answer, revocationStaleness = staleness, plans = plans,
        insecureUnboundApproval = true, provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(operation), undo = undo, risk = AuthorizeTestKit.calmRisk,
    )

    private fun run(p: Any?, i: Authorize.Input) = Authorize.authorize(p, i)

    private fun only(r: Authorize.Result, status: Int, check: String, reason: String) {
        assertFalse(r.allow)
        eq(status, r.status)
        eq(mapOf(check to "fail"), r.checks)
        eq(reason, r.reason)
        eq(listOf(reason), r.reasons)
    }

    // ---- results and their assurance

    @Test fun anAllowCarriesItsAssuranceReport() {
        val r = run(pcactn(c), input())
        assertTrue(r.reasons.toString(), r.allow)
        eq(emptyList<String>(), r.reasons)
        eq(mapOf("outcome" to "pass"), r.assurance["policy"])
        eq(mapOf("outcome" to "pass"), r.assurance["replay"])
        assertTrue(r.degraded.isEmpty())
        assertFalse(r.legacyModelPolarity)
    }

    @Test fun legacyPolarityDegradesTheTightenPassEverywhere() {
        Authorize.coreHook = { core -> core.legacyModelPolarity = true; core.checks["tighten"] = true }
        val r = run(pcactn(c), input())
        assertTrue(r.reasons.toString(), r.allow)
        assertTrue(r.legacyModelPolarity)
        eq(mapOf("tighten" to Authorize.LEGACY_POLARITY_DEGRADED), r.degraded)
        eq(true, r.assurance["tighten"]?.get("degraded"))
        // a deny keeps the flag too
        Authorize.coreHook = { core -> core.legacyModelPolarity = true; core.checks["x"] = false; core.reasons.add("x: no"); core.allow = false }
        val d = run(pcactn(c), input())
        assertFalse(d.allow)
        assertTrue(d.legacyModelPolarity)
        eq("x: no", d.reason)
    }

    @Test fun anAllowingCoreVerdictsReasonsAreNotCopied() {
        neutral { core -> core.reasons.add("zz: ignored") }
        val r = run(pcactn(c), input())
        assertTrue(r.reasons.toString(), r.allow)
        eq(emptyList<String>(), r.reasons)
    }

    // ---- early refusals

    @Test fun earlyRefusals() {
        only(run(pcactn(c), input(operation = Authorize.Operation("", "r", emptyMap()))), 403, "operation",
            "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)")
        val p = pc()
        p["grant_ref"] = 5L
        val m = run(p, input())
        only(m, 401, "malformed", "malformed: grant_ref is not a string")
        assertSame(p, m.pcactn)
        val q = pc()
        val e = run(q, input(resolve = { throw IllegalStateException("db") }))
        only(e, 403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)")
        assertSame(q, e.pcactn)
        only(run(pcactn(c), input(resolve = { null })), 401, "grant_ref", "grant_ref: does not resolve to a known grant")
        only(run(pcactn(c), input(context = { throw IllegalStateException("ctx") })), 403, "context", "context: the context callback failed (fail closed)")
        // a callback that returns a non-map (a Java caller; here an erased cast) is refused as such, not read as a context
        @Suppress("UNCHECKED_CAST")
        val notAMap = { _: Map<String, Any?> -> "not a map" } as (Map<String, Any?>) -> Map<String, Any?>?
        only(run(pcactn(c), input(context = notAMap)), 403, "context", "context: the context callback must return a map (fail closed)")
        only(run(pcactn(c), input(intentV2 = { throw IllegalStateException("v2") })), 403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)")
    }

    @Test fun aContextCallbackThatReturnsANonMapIsRefused() {
        // a Java caller (or an unchecked cast) can hand back anything
        val bad = ({ _: Map<String, Any?> -> "not a map" } as (Map<String, Any?>) -> Any?) as (Map<String, Any?>) -> Map<String, Any?>?
        val r = run(pcactn(c), input(context = bad))
        assertFalse(r.allow)
        eq(403, r.status)
        eq(mapOf("context" to "fail"), r.checks)
        assertTrue(r.reason!!, r.reason!!.startsWith("context: the context callback"))
    }

    @Test fun aWireFailureIsA401WithItsOwnReason() {
        Authorize.coreHook = { core -> core.checks["wire"] = false; core.reason = "" }
        val r = run(pcactn(c), input())
        eq(401, r.status)
        eq(mapOf("wire" to "fail", "malformed" to "fail"), r.checks)
        eq("wire: malformed PCActn", r.reason)
        eq(listOf("wire: malformed PCActn"), r.reasons)
        assertNotNull(r.verdict)
        Authorize.coreHook = { core -> core.checks["wire"] = false; core.reason = "w" }
        eq("w", run(pcactn(c), input()).reason)
    }

    @Test fun theWallClockIsUsedWithoutNow() {
        // the fixture was minted at NOW (in the past): only the wall clock satisfies not_before NOW and fails expires NOW
        neutral()
        val nb = gr(c, mapOf("type" to "not_before", "at" to NOW))
        assertTrue(run(pcactn(c), input(g = nb, now = null)).allow)
        val ex = gr(c, mapOf("type" to "expires", "at" to NOW + 1))
        assertTrue(run(pcactn(c), input(g = ex)).allow)
        val r = run(pcactn(c), input(g = ex, now = null))
        assertFalse(r.allow)
        eq(listOf("policy: root caveat(s) not satisfied: expires"), r.reasons)
    }

    @Test fun coreOptionsAreForwarded() {
        assertTrue(run(pcactn(c), input()).allow)
        assertFalse(run(pcactn(c), input(allowedSuites = listOf("ml-dsa-65"))).allow)
        assertFalse(run(pcactn(c), input(intentPolicy = Pca.IntentPolicy(require = true))).allow)
    }

    // ---- the plan registry

    private class Kv(val fail: Boolean) : AtomicKv {
        val keys = ArrayList<String>()
        override fun get(key: String): Any? { keys.add(key); if (fail) throw IllegalStateException("kv"); return null }
        override fun set(key: String, value: Any?) { keys.add(key); if (fail) throw IllegalStateException("kv") }
        override fun update(key: String, fn: (Any?) -> Any?): Any? { keys.add(key); if (fail) throw IllegalStateException("kv"); return fn(null) }
    }

    private fun singleStepNodes(p: Map<String, Any?>, cls: Any?): List<Map<String, Any?>> {
        val a = p["action"] as Map<String, Any?>
        return listOf(linkedMapOf("id" to "n1", "verb" to a["verb"], "resource" to a["resource"], "params_digest" to a["params_digest"], "reversibility_class" to cls))
    }

    @Test fun thePlanRegistry() {
        val p = pc()
        val gref = p["grant_ref"] as String
        val root = (p["plan"] as Map<String, Any?>)["root"] as String
        val broken = run(p, input(plans = PlanLifecycle.PlanRegistry(Kv(true))))
        only(broken, 403, "plans", "plans: the plan registry failed (fail closed)")
        assertSame(p, broken.pcactn)
        // a context that supplies the plan wins: the registry is never read
        val ctxPlan = mapOf("plan" to singleStepNodes(p, "irreversible"), "plan_authorized" to true)
        val kv0 = Kv(true)
        assertTrue(run(pcactn(c), input(plans = PlanLifecycle.PlanRegistry(kv0), context = { ctxPlan })).allow)
        eq(emptyList<String>(), kv0.keys)
        // an unknown root names itself (and the registry is asked for exactly this grant and root)
        val kv = Kv(false)
        val r = run(pcactn(c), input(plans = PlanLifecycle.PlanRegistry(kv), plan = null))
        assertFalse(r.allow)
        eq("fail", r.checks["plan_state"])
        assertTrue(r.reasons.toString(), r.reasons.contains("plan_state: plan $root is unknown to the plan registry"))
        assertTrue(kv.keys.isNotEmpty())
        for (k in kv.keys) eq("pca-plan:$gref:$root", k)
        // a PCActn without a string plan root asks for the empty root
        neutral()
        for (plan in listOf<Any?>(null, mapOf("root" to 5L), "x")) {
            val q = pc()
            if (plan == null) q.remove("plan") else q["plan"] = plan
            val kv2 = Kv(false)
            val r2 = run(q, input(plans = PlanLifecycle.PlanRegistry(kv2), plan = null))
            assertTrue(r2.reasons.toString(), r2.reasons.contains("plan_state: plan  is unknown to the plan registry"))
            for (k in kv2.keys) eq("pca-plan:$gref:", k)
        }
    }

    // ---- revocation staleness

    private val stale: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guard: String get() = stale["guardian_public"] as String

    private fun signedEpoch(grantRef: String, issuedAt: Long): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to grantRef, "epoch" to 0L, "set_size" to 0L, "root" to IntentRevocation.revsetRoot(emptyList()),
            "issued_at" to issuedAt, "not_after" to issuedAt + 600_000L,
        )
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + ByteArray(32) { 11 }
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        return LinkedHashMap(body).also { it["guardian"] = guard; it["sig"] = Pca.b64(sig.sign()) }
    }

    @Test fun stalenessReadsTheSignedActionClass() {
        // the fixture action is irreversible: with no state and no opt-out the action is refused
        val r = run(pcactn(c), input(staleness = Revocation.StalenessPolicy()))
        assertFalse(r.allow)
        eq("fail", r.checks["freshness"])
        eq("freshness: no verifiable (guardian-signed) revocation state for an irreversible action", r.reason)
        eq("not-enforced", run(pcactn(c), input(staleness = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true))).checks["freshness"])
    }

    @Test fun anAcceptedEpochReachesTheHostAfterTheAllow() {
        val p = pc()
        val gref = p["grant_ref"] as String
        val state = mapOf("kind" to "epoch", "epoch" to signedEpoch(gref, NOW - 1_000))
        val seen = ArrayList<Pair<Map<String, Any?>, Map<String, Any?>>>()
        val ids = ArrayList<String>()
        val pol = Revocation.StalenessPolicy(
            guardianPublic = guard, onEpochAccepted = { e, q -> seen.add(Pair(e, q)) },
            proofFor = { _, id -> ids.add(id); linkedMapOf("size" to 0L) },
        )
        val r = run(p, input(staleness = pol, context = { mapOf("revocation_state" to state, "reversibility_class" to "reversible") }))
        assertTrue(r.reasons.toString(), r.allow)
        eq("pass", r.checks["freshness"])
        eq(1, seen.size)
        eq(gref, seen[0].first["grant_ref"])
        assertSame(p, seen[0].second)
        // the default ids are the chain's hop ids
        val hops = (p["cap_chain"] as List<Map<String, Any?>>).map { it["id"] as String }
        eq(hops, ids)
        // a throwing pin never undoes the allow; a policy without a pin is fine
        val loud = Revocation.StalenessPolicy(guardianPublic = guard, onEpochAccepted = { _, _ -> throw IllegalStateException("pin") }, proofFor = { _, _ -> linkedMapOf("size" to 0L) })
        assertTrue(run(pc(), input(staleness = loud, context = { mapOf("revocation_state" to state, "reversibility_class" to "reversible") })).allow)
        // an epoch for another grant is refused with the checker's own reason
        val other = mapOf("kind" to "epoch", "epoch" to signedEpoch("g1", NOW - 1_000))
        val bad = run(pc(), input(staleness = Revocation.StalenessPolicy(guardianPublic = guard), context = { mapOf("revocation_state" to other, "reversibility_class" to "irreversible") }))
        assertFalse(bad.allow)
        eq("freshness: revocation epoch is for a different grant", bad.reason)
        assertTrue(seen.size == 1)
    }

    @Test fun customIdsReplaceTheHopIds() {
        val p = pc()
        val state = mapOf("kind" to "epoch", "epoch" to signedEpoch(p["grant_ref"] as String, NOW - 1_000))
        val ids = ArrayList<String>()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, ids = { listOf("x1", "x2") }, proofFor = { _, id -> ids.add(id); linkedMapOf("size" to 0L) })
        assertTrue(run(p, input(staleness = pol, context = { mapOf("revocation_state" to state, "reversibility_class" to "reversible") })).allow)
        eq(listOf("x1", "x2"), ids)
    }

    // ---- missing members of the proof

    @Test fun missingProofMembersFailClosedWithoutAnError() {
        neutral()
        for (k in listOf("action", "plan", "cap_chain")) {
            for (v in listOf<Any?>(null, "x")) {
                val p = pc()
                if (v == null) p.remove(k) else p[k] = v
                val r = run(p, input())
                assertFalse("$k=$v", r.allow)
                assertFalse("$k=$v ${r.reasons}", r.checks.containsKey("authorize"))
                when (k) {
                    "action" -> eq("fail", r.checks["operation"])
                    "plan" -> eq("fail", r.checks["plan_root_authorized"])
                    else -> {
                        eq("fail", r.checks["replay"])
                        eq("replay: no counter stream for this proof (fail closed)", r.reasons.last())
                        assertFalse(r.checks.containsKey("delegated_caveats"))
                    }
                }
            }
        }
    }

    @Test fun aCounterOutsideTheSafeIntegersHasNoStream() {
        neutral()
        for (cn in listOf<Any?>("1", 1.5, null)) {
            val p = pc()
            if (cn == null) p.remove("counter") else p["counter"] = cn
            val r = run(p, input())
            assertFalse(r.allow)
            eq(403, r.status)
            eq("fail", r.checks["replay"])
            eq(listOf("replay: no counter stream for this proof (fail closed)"), r.reasons)
        }
    }

    // ---- reversibility and the caveat context

    @Test fun theStricterClassFeedsTheCaveats() {
        neutral()
        val g = gr(c, mapOf("type" to "reversibility_max", "class" to "irreversible"))
        assertTrue(run(pcactn(c), input(g = g)).allow)
        // a less restrictive server class keeps the declared one
        val costly = run(pcactn(c), input(g = g, context = { mapOf("reversibility_class" to "costly") }))
        assertTrue(costly.reasons.toString(), costly.allow)
        eq("pass", costly.checks["reversibility"])
        // an equally ranked server class (unknown ranks as irreversible) is the one used
        val weird = run(pcactn(c), input(g = g, context = { mapOf("reversibility_class" to "weird") }))
        assertFalse(weird.allow)
        eq("pass", weird.checks["reversibility"])
        eq(listOf("policy: root caveat(s) not satisfied: reversibility_max"), weird.reasons)
    }

    private fun withPredicate(where: Map<String, Any?>): MutableMap<String, Any?> {
        val g = gr(c)
        val env = (g["caveats"] as MutableList<Any?>)[0] as MutableMap<String, Any?>
        env["predicates"] = mutableListOf<Any?>(linkedMapOf("verb" to "payments.send", "resource" to "payments/*", "where" to mutableListOf<Any?>(where)))
        return g
    }

    @Test fun predicatesSeeTheEffectiveClassSubjectAndEnv() {
        neutral()
        val cls = withPredicate(linkedMapOf("field" to "action.reversibility_class", "op" to "eq", "value" to "irreversible"))
        assertTrue(run(pcactn(c), input(g = cls)).allow)
        assertTrue(run(pcactn(c), input(g = cls, context = { mapOf("reversibility_class" to "costly") })).allow)
        eq("fail", run(pcactn(c), input(g = cls, context = { mapOf("reversibility_class" to "weird") })).checks["policy"])

        val subj = withPredicate(linkedMapOf("field" to "subject", "op" to "eq", "value" to "u1"))
        assertTrue(run(pcactn(c), input(g = subj, context = { mapOf("subject" to "u1") })).allow)
        eq("fail", run(pcactn(c), input(g = subj, context = { mapOf("subject" to "u2") })).checks["policy"])
        val noSubj = withPredicate(linkedMapOf("field" to "subject", "op" to "exists", "value" to false))
        assertTrue(run(pcactn(c), input(g = noSubj)).allow)
        assertTrue(run(pcactn(c), input(g = noSubj, context = { mapOf("subject" to null) })).allow)
        eq("fail", run(pcactn(c), input(g = noSubj, context = { mapOf("subject" to "u1") })).checks["policy"])

        val env = withPredicate(linkedMapOf("field" to "env.x", "op" to "eq", "value" to 1L))
        assertTrue(run(pcactn(c), input(g = env, context = { mapOf("env" to mapOf("x" to 1L)) })).allow)
        eq("fail", run(pcactn(c), input(g = env)).checks["policy"])
        val noEnv = withPredicate(linkedMapOf("field" to "env", "op" to "exists", "value" to false))
        assertTrue(run(pcactn(c), input(g = noEnv)).allow)
    }

    @Test fun anUndeclaredClassFallsBackToThePlanNode() {
        neutral()
        val p = pc()
        (p["action"] as MutableMap<String, Any?>).remove("reversibility_class")
        // rate_limited: the caveat order (predicates.ts REVERSIBILITY_ORDER) has no "costly", so a costly limit is never satisfied
        val nodes = singleStepNodes(p, "rate_limited")
        (p["plan"] as MutableMap<String, Any?>)["root"] = Pca.merkleRoot(listOf(Pca.planLeaf("n1", nodes[0], Pca.conditionsDigest(null, null))))
        val ctx = mapOf("plan" to nodes, "plan_authorized" to true)
        val ok = run(p, input(g = gr(c, mapOf("type" to "reversibility_max", "class" to "rate_limited")), context = { ctx }))
        assertTrue(ok.reasons.toString(), ok.allow)
        val no = run(p, input(g = gr(c, mapOf("type" to "reversibility_max", "class" to "reversible")), context = { ctx }))
        eq(listOf("policy: root caveat(s) not satisfied: reversibility_max"), no.reasons)
    }

    @Test fun theCaveatContextMembers() {
        neutral()
        val blast = gr(c, mapOf("type" to "max_blast_radius", "max" to 5L))
        assertTrue(run(pcactn(c), input(g = blast, context = { mapOf("blast_radius" to 5L) })).allow)
        eq(listOf("policy: root caveat(s) not satisfied: max_blast_radius"), run(pcactn(c), input(g = blast, context = { mapOf("blast_radius" to 6L) })).reasons)
        eq(listOf("policy: root caveat(s) not satisfied: max_blast_radius"), run(pcactn(c), input(g = blast)).reasons)
        val rate = gr(c, mapOf("type" to "rate", "max" to 1L, "per_secs" to 60L))
        assertTrue(run(pcactn(c), input(g = rate, context = { mapOf("recent_action_times" to emptyList<Any?>()) })).allow)
        eq(listOf("policy: root caveat(s) not satisfied: rate"), run(pcactn(c), input(g = rate, context = { mapOf("recent_action_times" to listOf(NOW - 1_000)) })).reasons)
        eq(listOf("policy: root caveat(s) not satisfied: rate"), run(pcactn(c), input(g = rate)).reasons)
    }

    @Test fun theDelegationDepthIsHopsMinusOne() {
        neutral()
        val zero = mapOf("type" to "delegation_depth", "max" to 0L)
        assertTrue(run(pcactn(c), input(g = gr(c, zero))).allow)
        eq(listOf("policy: root caveat(s) not satisfied: delegation_depth"), run(pcactn(c), input(g = gr(c, mapOf("type" to "delegation_depth", "max" to -1L)))).reasons)
        val deep = run(pcactn(d2), input(cs = d2, g = gr(d2, zero)))
        eq(listOf("policy: root caveat(s) not satisfied: delegation_depth"), deep.reasons)
        assertTrue(run(pcactn(d2), input(cs = d2, g = gr(d2, mapOf("type" to "delegation_depth", "max" to 1L)))).allow)
        // no chain at all is depth 0 (refused only for the missing counter stream)
        val p = pc()
        p["cap_chain"] = mutableListOf<Any?>()
        eq(listOf("replay: no counter stream for this proof (fail closed)"), run(p, input(g = gr(c, zero))).reasons)
    }

    // ---- the delegated extra caveats

    @Test fun theLeafsExtraCaveats() {
        neutral()
        assertTrue(run(pcactn(d2), input(cs = d2)).allow)
        val p = pc(d2)
        leafCaveats(p).add(linkedMapOf("type" to "expires", "at" to NOW - 1))
        leafCaveats(p).add(linkedMapOf("type" to "not_before", "at" to NOW + 1))
        val r = run(p, input(cs = d2))
        eq(listOf("delegated_caveats: delegation caveat(s) not satisfied: expires, not_before"), r.reasons)
        // a grant with more caveats than the leaf: no extras (never an out-of-range slice)
        val big = gr(d2, mapOf("type" to "expires", "at" to NOW + 1_000), mapOf("type" to "expires", "at" to NOW + 2_000))
        val ok = run(pcactn(d2), input(cs = d2, g = big))
        assertTrue(ok.reasons.toString(), ok.allow)
        eq("pass", ok.checks["delegated_caveats"])
        // a leaf without a caveat list, or a leaf that is not an object
        val bare = pc(d2)
        ((bare["cap_chain"] as MutableList<Any?>).last() as MutableMap<String, Any?>).remove("caveats")
        val rb = run(bare, input(cs = d2))
        eq("fail", rb.checks["delegated_caveats"])
        assertTrue(rb.reasons.toString(), rb.reasons.contains("delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>"))
        val odd = pc(d2)
        val oc = odd["cap_chain"] as MutableList<Any?>
        oc[oc.size - 1] = "x"
        val ro = run(odd, input(cs = d2))
        eq("fail", ro.checks["delegated_caveats"])
        assertFalse(ro.checks.containsKey("authorize"))
        // grant caveats that are not a list: every leaf caveat is an extra
        val g = gr(d2)
        g["caveats"] = "x"
        val rg = run(pcactn(d2), input(cs = d2, g = g))
        assertFalse(rg.allow)
        assertTrue(rg.checks.containsKey("delegated_caveats"))
        assertFalse(rg.checks.containsKey("authorize"))
    }

    private val noK1 = "the caveat language is not configured (no k1 input)"

    @Test fun k1ReasonsAreJoinedWithSemicolons() {
        neutral()
        val p = pc(d2)
        leafCaveats(p).add(linkedMapOf("type" to "sealed"))
        leafCaveats(p).add(linkedMapOf("type" to "sealed"))
        val r = run(p, input(cs = d2))
        eq("fail", r.checks["delegated_caveats"])
        eq(listOf("delegated_caveats: delegation caveat(s) not satisfied: sealed, sealed ($noK1; $noK1)"), r.reasons)
        // without a chain the K1 verdict is a root-caveat failure
        val q = pc()
        q["cap_chain"] = mutableListOf<Any?>()
        val g = gr(c, mapOf("type" to "sealed"), mapOf("type" to "sealed"))
        val rr = run(q, input(g = g))
        eq("fail", rr.checks["policy"])
        assertTrue(rr.reasons.toString(), rr.reasons.contains("policy: root caveat(s) not satisfied: sealed, sealed ($noK1; $noK1)"))
    }

    // ---- required checks

    @Test fun requiredChecks() {
        val foo = run(pcactn(c), input(require = listOf("foo")))
        assertFalse(foo.allow)
        eq(listOf("foo: required check is absent (default-deny: not enforced by this resource server)"), foo.reasons)
        assertTrue(run(pcactn(c), input(require = listOf("counter"))).allow)
        val fr = run(pcactn(c), input(require = listOf("freshness"), staleness = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true)))
        eq(listOf("freshness: required check is not-enforced (default-deny: not enforced by this resource server)"), fr.reasons)
    }

    // ---- the escalation ternary

    private val principal: Map<String, Any?> by lazy { ParityVectors.load("keys.json")["principal"] as Map<String, Any?> }
    private val pub: String get() = principal["public"] as String

    private fun sign(decision: String = "allow"): Map<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        body["v"] = IntentJs.ofLong(1)
        body["kind"] = "pca-escalation-answer"
        body["principal"] = pub
        body["policy_digest"] = Escalation.policyDigest(grant(c))
        body["action_digest"] = Escalation.actionDigest(pcactn(c))
        body["history_head"] = Escalation.historyHead(null)
        body["decision"] = decision
        body["iat"] = IntentJs.ofLong(NOW - 1000)
        body["expires_at"] = IntentJs.ofLong(NOW + 600_000)
        body["nonce"] = "CQkJCQkJCQkJCQkJCQkJCQ"
        val msg = IntentArtifacts.artifactMessage(Escalation.ANSWER_DOMAIN, body)
        val sig = ByteArray(64)
        Ed25519.sign(Pca.decodeB64uStrict(principal["seed"], 32)!!, 0, msg, 0, msg.size, sig, 0)
        body["sig"] = Pca.b64(sig)
        return body
    }

    private fun streamKey(): String {
        val p = pcactn(c)
        val holder = ((p["cap_chain"] as List<*>).last() as Map<*, *>)["holder"] as String
        return Authorize.stateKey(grant(c)["id"] as String, holder)
    }

    private class Counting(val adm: Undo.Admission?) : Authorize.UndoHook {
        var calls = 0
        override fun admit(pcactn: Map<String, Any?>, grant: Map<String, Any?>, operation: Authorize.Operation): Undo.Admission? { calls++; return adm }
    }

    private fun admitting() = Counting(Undo.Admission("op_1", NOW + 900_000L, "drafts.delete", "drafts:box1"))

    private class NoHead : Authorize.StateStore, Authorize.LastStore {
        val mem = Authorize.MemoryStateStore()
        override fun claim(key: String, counter: Long): Authorize.ClaimResult = mem.claim(key, counter)
        override fun last(key: String): Long? = throw IllegalStateException("head unavailable")
    }

    @Test fun anUnansweredEscalationIsRefusedWithItsRequest() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val r = run(pcactn(c), input())
        assertFalse(r.allow)
        eq("escalate", r.decision)
        eq(403, r.status)
        assertNotNull(r.escalation)
    }

    @Test fun aReplayedCounterIsDeniedBeforeTheEscalation() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        for (last in listOf(5L, 1L)) {
            val store = Authorize.MemoryStateStore()
            store.claim(streamKey(), last)
            val r = run(pcactn(c), input(store = store))
            assertFalse(r.allow)
            eq("deny", r.decision)
            assertNull(r.escalation)
            eq("fail", r.checks["replay"])
            eq("replay: 1 is not greater than last seen $last (replay)", r.reasons.last())
        }
        val store = Authorize.MemoryStateStore()
        store.claim(streamKey(), 0L)
        eq("escalate", run(pcactn(c), input(store = store)).decision)
    }

    @Test fun answersAndUndoWindows() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        // an answer with no pinned principal: refused, and the undo hook is not consulted for an answered call
        val h0 = admitting()
        val none = run(pcactn(c), input(answer = mapOf("x" to 1L), undo = h0))
        eq("escalate", none.decision)
        assertTrue(none.reasons.toString(), none.reasons.contains("escalation: no principal is pinned for escalation answers"))
        eq(0, h0.calls)
        // a valid allow answer admits; the undo hook is never asked afterwards
        val h1 = admitting()
        val ok = run(pcactn(c), input(principals = listOf(Escalation.Principal(pub)), answer = sign(), undo = h1))
        assertTrue(ok.reasons.toString(), ok.allow)
        assertNull(ok.undo)
        eq(0, h1.calls)
        // a deny answer is reported
        val deny = run(pcactn(c), input(principals = listOf(Escalation.Principal(pub)), answer = sign("deny")))
        eq("escalate", deny.decision)
        assertTrue(deny.reasons.toString(), deny.reasons.contains("escalation: the principal answered deny"))
        // a store whose history head cannot be read: the answer is not considered at all
        val blind = run(pcactn(c), input(store = NoHead(), principals = listOf(Escalation.Principal(pub)), answer = sign()))
        assertFalse(blind.allow)
        eq("escalate", blind.decision)
        assertFalse(blind.reasons.toString(), blind.reasons.any { it.startsWith("escalation:") })
        // with no answer the hook admits under a window
        val h2 = admitting()
        val win = run(pcactn(c), input(undo = h2))
        assertTrue(win.reasons.toString(), win.allow)
        eq(1, h2.calls)
        assertNotNull(win.undo)
        eq(listOf(win.undo!!.obligation()), win.obligations)
    }

    // ---- workflow admission

    private val wf: Map<String, Any?> by lazy { ParityVectors.load("authorize-workflow-fixtures.json") }

    private fun wfRun(goal: String? = null, clock: (() -> Long)? = null, commitment: Boolean = true): Authorize.Result {
        val s = (((wf["cases"] as List<Map<String, Any?>>).first { it["name"] == "pay-after-quote" })["steps"] as List<Map<String, Any?>>)[0]
        val w = s["workflow"] as Map<String, Any?>
        val g = wf["grant"] as Map<String, Any?>
        val operation = Authorize.Operation.fromJson(s["operation"])
        val call = Authorize.WorkflowStep(if (commitment) w["commitment"] else null, w["receipts"], w["step"] as String?, (w["units"] as Map<String, Any?>?) ?: emptyMap(), goal)
        return Authorize.authorize(
            s["pcactn"],
            Authorize.Input(
                operation = operation, audience = wf["audience"] as String, resolveGrant = { ref -> if (ref == g["id"]) g else null },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = Json.asLong(wf["now"]),
                context = { _ -> mapOf("plan" to wf["plan"], "plan_authorized" to true) },
                workflow = Authorize.WorkflowGate(wf["principal"] as String, wf["rs_signer"] as String, false, clock), workflowCall = call,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(operation), risk = AuthorizeTestKit.calmRisk,
            ),
        )
    }

    @Test fun workflowAdmission() {
        assertTrue(wfRun().reasons.toString(), wfRun().allow)
        val now = Json.asLong(wf["now"])
        // the gate's clock overrides the call's: past the commitment's expiry
        only(wfRun(clock = { now + 200_000 }), 403, "workflow", "workflow: expired (step quote)")
        assertTrue(wfRun(clock = { now }).allow)
        val g = wfRun(goal = KUtil.B32)
        eq(mapOf("workflow" to "fail"), g.checks)
        eq("workflow: goal_mismatch (step quote)", g.reason)
        // a refusal that names no step has no step suffix
        only(wfRun(commitment = false), 403, "workflow", "workflow: bad_workflow")
    }
}
