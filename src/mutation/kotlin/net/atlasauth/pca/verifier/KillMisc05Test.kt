package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.norm
import net.atlasauth.pca.verifier.KUtil.B32
import net.atlasauth.pca.verifier.KUtil.B64
import net.atlasauth.pca.verifier.KUtil.NOW
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import net.atlasauth.pca.verifier.KUtil.valid
import net.atlasauth.pca.verifier.KUtil.validGrant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills across Json (UTF-8 order with lone surrogates, ECMAScript number spelling), Pca (approved-goal refs, the
 * fresh_at wire slot, the verifier's internal-error catch, reason precedence of fresh_at), Predicates (limit-naming denial
 * reasons, mirrors java-pca PredicatesK05KillTest), IntentArtifacts (param paths) and IntentV2 (single-source worlds, the
 * allow-side predicate lists, rules 20 / 21 wiring). Expected values are the TypeScript reference's.
 */
class KillMisc05Test {
    private fun j(text: String): Any? = Json.parseLenient(text)

    @Suppress("UNCHECKED_CAST")
    private fun ctx(text: String): Map<String, Any?> = Json.parseLenient(text) as Map<String, Any?>

    // ---------------------------------------------------------------- Json

    @Test fun compareUtf8WithLoneSurrogatesNextToPairs() {
        // TextEncoder: a pair is its 4-byte code point, a lone surrogate U+FFFD (EF BF BD)
        assertEquals(0xF0 - 0xEF, Json.compareUtf8("😀\uD800", "�"))
        assertEquals(0xEF - 0xF0, Json.compareUtf8("�", "😀\uD800"))
        assertEquals(0x61 - 0xEF, Json.compareUtf8("a\uD800", "�"))
        assertEquals(0x62 - 0x61, Json.compareUtf8("\uDC00b", "�a"))
        assertEquals(0xF0 - 0xEF, Json.compareUtf8("\uD800😀", "��"))
        // equal UTF-8 bytes (a lone high surrogate last, after a pair): UTF-16 code-unit order decides
        assertTrue(Json.compareUtf8("😀\uD83D", "😀�") < 0)
        assertTrue(Json.compareUtf8("😀�", "😀\uD83D") > 0)
        assertTrue(Json.compareUtf8("a\uD800", "a�") < 0)
    }

    @Test fun esNumberSpellsLikeEcmaScript() {
        val cases = linkedMapOf(
            5.0 to "5", 100.0 to "100", 120.0 to "120", 9.96 to "9.96", 123.456 to "123.456", -2.5 to "-2.5",
            0.1 to "0.1", 0.1 + 0.2 to "0.30000000000000004", 1e-6 to "0.000001", 1e-7 to "1e-7", 1.5e-7 to "1.5e-7",
            1e20 to "100000000000000000000", 1e21 to "1e+21", 1.23e22 to "1.23e+22", 1e300 to "1e+300", -1e300 to "-1e+300",
            9007199254740992.0 to "9007199254740992", 1152921504606846976.0 to "1152921504606847000",
            5e-324 to "5e-324", Double.MAX_VALUE to "1.7976931348623157e+308", 0.0 to "0", -0.0 to "0",
        )
        for ((f, s) in cases) assertEquals("$f", s, Json.esNumber(f))
        assertEquals("1.5", Json.fmtNumber("1.50"))
        assertEquals("100", Json.fmtNumber("1e2"))
    }

    // ---------------------------------------------------------------- Pca: approved goal refs

    @Test fun approvedGoalRefs() {
        assertTrue(Pca.ApprovedGoal("a", "b").closed)
        val ok = Pca.ApprovedGoal.fromJson(m("goal_digest" to B32, "policy_digest" to B32))
        assertTrue(ok.closed)
        assertTrue(ok.isWellFormed)
        assertEquals(Pca.INTENT_GOAL_V3_PREFIX + B32 + ":" + B32, Pca.intentGoalV3(ok))
        val extra = Pca.ApprovedGoal.fromJson(m("goal_digest" to B32, "policy_digest" to B32, "x" to n("1")))
        assertFalse(extra.closed)
        assertFalse(extra.isWellFormed)
        for (bad in listOf<Any?>("x", null, n("1"), jl(B32, B32))) {
            val r = Pca.ApprovedGoal.fromJson(bad)
            assertFalse("$bad", r.closed)
            assertNull("$bad", r.goalDigest)
            assertNull("$bad", r.policyDigest)
            assertFalse("$bad", r.isWellFormed)
        }
        assertThrows(IllegalArgumentException::class.java) { Pca.intentGoalV3(Pca.ApprovedGoal("x", "y")) }
        assertThrows(IllegalArgumentException::class.java) { Pca.intentGoalV3(extra) }
    }

    // ---------------------------------------------------------------- Pca: fresh_at wire slot, internal error, reason order

    private fun freshAt() = m(
        "v" to n("1"), "scope" to "s", "revocation_epoch" to n("0"), "ledger_tree_size" to n("0"), "budget_version" to n("0"),
        "policy_revision" to n("0"), "policy_digest" to "d", "issued_at" to n("1"), "signer" to B32, "sig" to B64,
    )

    @Test fun aWellFormedFreshAtDoesNotEndWireValidation() {
        val p = valid()
        p["fresh_at"] = freshAt()
        assertNull(Pca.validateWireV2(p))
        p["prohibition_evidence"] = "x"
        assertEquals("'prohibition_evidence' must be an object or array", Pca.validateWireV2(p))
        p["prohibition_evidence"] = m()
        p["threshold"] = "x"
        assertEquals("'threshold' must be {shares:[...]}", Pca.validateWireV2(p))
    }

    /** A caller-supplied grant whose FIRST read throws (then behaves): the verifier's internal-error catch is the only way out. */
    private class ThrowOnceMap(private val base: Map<String, Any?>) : Map<String, Any?> by base {
        private var armed = true
        private fun trip() { if (armed) { armed = false; throw IllegalStateException("boom") } }
        override val entries: Set<Map.Entry<String, Any?>> get() { trip(); return base.entries }
        override val keys: Set<String> get() { trip(); return base.keys }
        override val values: Collection<Any?> get() { trip(); return base.values }
        override val size: Int get() { trip(); return base.size }
        override fun get(key: String): Any? { trip(); return base[key] }
        override fun containsKey(key: String): Boolean { trip(); return base.containsKey(key) }
        override fun isEmpty(): Boolean { trip(); return base.isEmpty() }
    }

    @Test fun anInternalErrorIsTheReasonAndIsListed() {
        assertTrue(Pca.verifyPcactn(valid(), validGrant(), NOW, KUtil.Of, insecureSkipPlanRootCheck = true).allow)
        val v = Pca.verifyPcactn(valid(), ThrowOnceMap(validGrant()), NOW, KUtil.Of, insecureSkipPlanRootCheck = true)
        assertFalse(v.allow)
        assertEquals("malformed PCActn: java.lang.IllegalStateException: boom", v.reason)
        assertEquals(listOf("malformed PCActn: java.lang.IllegalStateException: boom"), v.reasons)
        assertEquals(false, v.checks["chain"])
    }

    @Test fun freshAtIsTheReasonOnlyWhenNothingFailedBefore() {
        val pol = FreshAt.Policy(signer = B32, scope = "s", local = FreshAt.State(0, 0, 0, 0, "d"), require = true)
        val need = "fresh_at: escalate: a consistency token is required (refresh and retry with the token of your latest write)"
        val alone = Pca.verifyPcactn(valid(), validGrant(), NOW, KUtil.Of, null, null, null, pol, insecureSkipPlanRootCheck = true)
        assertFalse(alone.allow)
        assertEquals(need, alone.reason)
        assertEquals(listOf(need), alone.reasons)
        assertEquals(false, alone.checks["fresh_at"])
        val both = Pca.verifyPcactn(valid(), validGrant(), NOW, Pca.Audience.Of("another-resource"), null, null, null, pol, insecureSkipPlanRootCheck = true)
        assertEquals("audience: aud does not match this resource server / instance", both.reason)
        assertEquals(listOf("audience: aud does not match this resource server / instance", need), both.reasons)
    }

    // ---------------------------------------------------------------- Predicates (limit-naming denial reasons)

    private val pay = ctx("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":500}}}")

    @Test fun firstUnmetLimitSkipsWhatIsOutOfScopeOrMalformed() {
        val limit = "[\"x\",{\"verb\":\"pay\",\"resource\":5,\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}," +
            "{\"verb\":\"pay\",\"resource\":\"acct/1\"}," +
            "{\"verb\":\"pay\",\"resource\":\"acct/1\",\"where\":5}," +
            "{\"verb\":\"pay\",\"resource\":\"acct/1\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":100}]}]"
        assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(limit), pay))
        // a met condition is skipped: the first UNMET one is named
        val second = "[{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"gte\",\"value\":1}," +
            "{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":100}]}]"
        assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(second), pay))
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"other\"}]"), pay))
        assertNull(Predicates.firstUnmetLimit(j("{}"), pay))
        assertNull(Predicates.firstUnmetLimit(j("[]"), ctx("{\"action\":5}")))
        assertNull(Predicates.firstUnmetLimit(j("[]"), null))
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"pay\"}]"), ctx("{\"action\":{\"verb\":5,\"resource\":\"r\"}}")))
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"pay\"}]"), ctx("{\"action\":{\"verb\":\"pay\",\"resource\":5}}")))
        // an absent verb or resource is no action in scope, even for a predicate that matches any verb or resource
        val unmet = "[{\"verb\":\"*\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}]"
        assertNull(Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"resource\":\"acct/1\",\"params\":{\"amount\":5}}}")))
        assertNull(Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"verb\":\"pay\",\"params\":{\"amount\":5}}}")))
        assertEquals("amount <= 1", Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":5}}}")))
    }

    @Test fun denialReasons() {
        assertEquals("envelope grants no predicates", Predicates.denialReason(j("[]"), pay))
        assertEquals("envelope grants no predicates", Predicates.denialReason(j("\"x\""), pay))
        assertEquals("no predicate permits pay on acct/1", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), pay))
        assertEquals("amount <= 100 not satisfied for pay on acct/1",
            Predicates.denialReason(j("[{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":100}]}]"), pay))
        // no action at all: still a reason, never an exception
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), ctx("{}")))
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), ctx("{\"action\":5}")))
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), null))
        // the verb / resource are spelled as JavaScript prints the parsed value
        assertEquals("no predicate permits 1.5 on 2.5", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), ctx("{\"action\":{\"verb\":1.50,\"resource\":2.50}}")))
        assertNull(Predicates.denialReason(j("[{\"verb\":\"pay\"}]"), pay))
    }

    @Test fun shownValues() {
        assertEquals("5", Predicates.showValue(Json.Num("5"), 0))
        assertEquals("5", Predicates.showValue(5L, 0))
        assertEquals("5", Predicates.showValue(5, 0))
        assertEquals("<number>", Predicates.showValue(Json.Num("1.5"), 0))
        val s64 = "a".repeat(64)
        assertEquals("\"$s64\"", Predicates.showValue(s64, 0))
        assertEquals("\"...\"", Predicates.showValue(s64 + "a", 0))
        assertEquals("\"...\"", Predicates.showValue("\"ab", 0))
        assertEquals("\"a b\"", Predicates.showValue("a b", 0))
        assertEquals("\"a!b\"", Predicates.showValue("a!b", 0))
        assertEquals("\"...\"", Predicates.showValue("a\u001fb", 0))
        assertEquals("\"...\"", Predicates.showValue("\ud800", 0))
        assertEquals("\"...\"", Predicates.showValue("\udfff", 0))
        assertEquals("\"퟿\"", Predicates.showValue("퟿", 0))
        assertEquals("\"\"", Predicates.showValue("", 0))
        assertEquals("[1, \"a\"]", Predicates.showValue(jl(Json.Num("1"), "a")))
        assertEquals("<value>", Predicates.showValue(jl("a"), 1))
    }

    @Test fun describedConditions() {
        assertEquals("not (not ((...)))", Predicates.describeCondition(j("{\"not\":{\"not\":{\"not\":{\"field\":\"a\",\"op\":\"eq\",\"value\":1}}}}")))
        assertEquals("<condition>", Predicates.describeCondition(j("{\"all_of\":5}"), 0))
        assertEquals("a <condition>", Predicates.describeCondition(j("{\"field\":\"a\",\"op\":5,\"value\":1}"), 0))
        assertEquals("a <condition>", Predicates.describeCondition(j("{\"field\":\"a\",\"value\":1}"), 0))
        assertEquals("currency in [\"usd\", \"eur\"]",
            Predicates.describeCondition(j("{\"field\":\"action.params.currency\",\"op\":\"in\",\"value\":[\"usd\",\"eur\"]}")))
        assertEquals("all of (a == 1; b <= 2)",
            Predicates.describeCondition(j("{\"all_of\":[{\"field\":\"a\",\"op\":\"eq\",\"value\":1},{\"field\":\"b\",\"op\":\"lte\",\"value\":2}]}")))
    }

    // ---------------------------------------------------------------- IntentArtifacts

    @Test fun paramPathsResolveOnlyThroughOwnObjectMembers() {
        val r = IntentArtifacts.resolveParamPath(jm("a", jm("b", 7L)), "action.params.a.b")
        assertTrue(r.found)
        assertEquals(7L, r.value)
        assertFalse(IntentArtifacts.resolveParamPath(jm("constructor", 1L), "action.params.constructor").found)
        assertFalse(IntentArtifacts.resolveParamPath(jm("a", 5L), "action.params.a.b").found)
        assertFalse(IntentArtifacts.resolveParamPath(jm("a", null), "action.params.a.b").found)
        assertFalse(IntentArtifacts.resolveParamPath(jm("a", jm()), "action.params.a.b").found)
        assertFalse(IntentArtifacts.resolveParamPath(jm("a", jl(1L)), "action.params.a.b").found)
    }

    // ---------------------------------------------------------------- IntentV2

    @Test fun withEnvNormalizesNumbers() {
        val c = IntentV2.Context.fromJson(jm()).withEnv(j("{\"x\":1.50}"))
        assertEquals("1.5", (c.get("env", "x") as Json.Num).raw)
    }

    private val wbSession = "-buMfzrK6lezjTOBxezg5o7kMM_q_sgBm_2WKGM-laQ"

    /** The killWb `wb/facts-single-source` scenario (one fact from a single-oracle world) as a v2 PCActn + verifier context. */
    private fun wbP(): Map<String, Any?> = norm(j(
        "{\"aud\":\"skyair.example\",\"action\":{\"verb\":\"air.book\",\"resource\":\"r\"}," +
            "\"intent_session\":{\"session\":\"$wbSession\",\"facts\":[\"QMLld5r5hu-RDmeX6Zp8yxsPQJBU2sKysUOSHXf3BTU\"]}}",
    ))

    private val wbCtx = "\"params\":{\"offer_id\":\"OF-2\",\"total\":77800,\"quote\":38900,\"passport\":\"X1234567\",\"body\":\"We are sorry for the delay.\"}," +
        "\"wb\":{\"artifacts\":{\"facts\":[{\"v\":1,\"kind\":\"pca-fact\",\"name\":\"fare\",\"subject\":\"OF-2\",\"value\":39800,\"t_obs\":1799999999000," +
        "\"oracle\":\"o1\",\"sig\":\"lIj41kr_R9k6Rkua8YX6_8tul2_yWCpszFqAIkI7_LxTkJtmz7YiB08k3wJ-HdTWICkh4aLk83oEInLhfdXDCw\"}]}," +
        "\"policy\":{\"world\":{\"worlds\":[{\"name\":\"fare\",\"subject_path\":\"action.params.offer_id\",\"oracles\":[" +
        "{\"kid\":\"o1\",\"pk\":\"1L0f5lhAxf6ysqflXQPi5hMBt971N9EKQet5p7ng-IY\"},{\"kid\":\"o2\",\"pk\":\"IfhUrayCH4eRdSGcf5l9CQsGB9oM1w0eJn6rY6SA004\"}," +
        "{\"kid\":\"o3\",\"pk\":\"-nkQT-b2Q4V0VvLcX4nda9lNZ53QeUSF5tH4uSjXYDg\"}],\"freshness_ms\":60000,\"min_oracles\":1,\"max_faulty\":0}]}}}"

    private fun wbContext(extra: String = ""): IntentV2.Context = IntentV2.Context.fromJsonText("{$wbCtx$extra}")

    private val readsFare = "[{\"verb\":\"air.book\",\"where\":[{\"field\":\"env.world.fare\",\"op\":\"lte\",\"value\":50000}]}]"
    private val modelRead = "a grant's where reads model-derived path(s) env.world.fare: a model may only tighten (move them into tighten[]) (rule 21)"

    private val risk = "\"risk_policy\":{\"weights\":{\"alpha\":1,\"beta\":1,\"gamma\":1,\"delta\":1,\"epsilon\":1,\"zeta\":1}," +
        "\"theta1\":0,\"theta2\":1,\"kappa\":1,\"lambda\":0,\"rho\":0,\"bMax\":1}"

    /** A root grant whose envelope caveat carries `members` (JSON text) besides the required ones. */
    private fun grant(members: String): Map<String, Any?> = norm(j(
        "{\"caveats\":[{\"type\":\"envelope\",\"goal_commit\":\"g\",\"caveats\":[],\"agent_binding\":{},$risk,$members}]}",
    ))

    private fun check(d: IntentV2.Decision, name: String): IntentV2.Check = d.checks.single { it.name == name }

    @Test fun aSingleOracleWorldIsReportedAsSingleSource() {
        val d = IntentV2.decide(wbP(), null, wbContext(), NOW)
        assertTrue(check(d, "facts").ok)
        assertEquals(listOf("fare"), d.singleSource)
        assertFalse(d.checks.any { it.name == "tighten" })
    }

    @Test fun aCeilingReadingASingleSourceWorldIsRefused() {
        // env null (no grant): the ceiling alone makes rule 21 run, and single_source makes env.world.fare model-derived
        val d = IntentV2.decide(wbP(), null, wbContext(",\"layers\":{\"org\":{\"predicates\":$readsFare}}"), NOW)
        val t = check(d, "tighten")
        assertFalse(t.ok)
        assertEquals(modelRead, t.reason)
    }

    @Test fun aGrantReadingASingleSourceWorldIsRefused() {
        val d = IntentV2.decide(wbP(), grant("\"predicates\":$readsFare"), wbContext(), NOW)
        val t = check(d, "tighten")
        assertFalse(t.ok)
        assertEquals(modelRead, t.reason)
    }

    @Test fun aTightenRuleSeesTheVerifierComputedWorld() {
        val rules = "\"predicates\":[{\"verb\":\"air.book\"}],\"tighten\":[{\"id\":\"fare_cap\",\"signal\":\"deny\"," +
            "\"when\":{\"field\":\"env.world.fare\",\"op\":\"gt\",\"value\":1000}}]"
        val d = IntentV2.decide(wbP(), grant(rules), wbContext(), NOW)
        val t = check(d, "tighten")
        assertFalse(t.ok)
        assertEquals("denied by tighten rule 'fare_cap'", t.reason)
    }

    @Test fun noModelRuleWithoutATrigger() {
        val k = IntentV2KillTest
        val p = k.build(k.G0, "salt0", k.MAP0, k.is0(), k.params(), k.REF)
        val d = IntentV2.decide(p, grant("\"predicates\":[{\"verb\":\"air.book\"}]"), IntentV2.Context.fromJson(k.ctx()), NOW)
        assertEquals(listOf("schema", "intent_session", "accumulators"), d.checks.map { it.name })
        // no context and no grant at all: nothing is reported and nothing throws
        val bare = IntentV2.decide(jm("aud", "a", "action", jm("verb", "v", "resource", "r")), null, null, NOW)
        assertTrue(bare.checks.isEmpty())
    }

    @Test fun unitsWithASchemaThatHasNoUnitsTable() {
        val k = IntentV2KillTest
        val unsigned = k.unsignedSchema()
        unsigned.remove("units")
        @Suppress("UNCHECKED_CAST")
        val total = (((unsigned["verbs"] as List<Any?>)[0] as MutableMap<String, Any?>)["params"] as MutableMap<String, Any?>)["action.params.total"] as MutableMap<String, Any?>
        total.remove("unit")
        total.remove("accumulates_into")
        val doc = k.signSchema(unsigned, "skyair-2026", k.SITE)
        val p = k.build(k.G0, "salt0", k.MAP0, k.is0("schema", ActionSchema.digest(doc)), k.params(), k.REF)
        val ctx = IntentV2.Context.fromJson(k.ctx("schema", jm("docs", jl(doc), "keys", k.KEYS)))
        val g = grant("\"predicates\":[{\"verb\":\"air.book\"}],\"units\":{\"action.params.zzz\":{\"kind\":\"count\"}}")
        val d = IntentV2.decide(p, g, ctx, NOW)
        assertTrue(check(d, "schema").ok)
        val u = check(d, "units")
        assertTrue("${u.reason}", u.ok)
        assertNull(u.reason)
    }
}
