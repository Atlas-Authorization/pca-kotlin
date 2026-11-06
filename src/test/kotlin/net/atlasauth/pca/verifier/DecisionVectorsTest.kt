package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rules 20 (units), 21 (tighten-only), the ternary decision lattice and escalation answers over the shared
 * `decision-vectors.json`, plus exact-outcome (reason string) tests for the same TypeScript behaviour.
 */
@Suppress("UNCHECKED_CAST")
class DecisionVectorsTest {
    private fun tbl(n: String) = ParityVectors.decisionTable(n)

    /** `input_text` is raw JSON text each runner parses itself (spellings such as 2.0 / 2e0 are part of the input); else `input`. */
    private fun inputOf(x: Map<String, Any?>): Map<String, Any?> =
        (x["input_text"] as? String)?.let { ParityVectors.obj(it) } ?: x["input"] as Map<String, Any?>

    @Test
    fun unitsVectors() {
        val v = tbl("intent_units")
        assertTrue(v.size >= 73)
        for (x in v) {
            val r = PcaDecision.decideUnits(inputOf(x))
            val e = x["expect"] as Map<String, Any?>
            assertEquals("${x["name"]}: ${r.reason}", e["ok"], r.ok)
            // the reason is part of the contract, byte for byte (an ok outcome has none)
            assertEquals(x["name"].toString(), e["reason"], r.reason)
        }
    }

    @Test
    fun tightenVectors() {
        val v = tbl("intent_tighten")
        assertTrue(v.size >= 70)
        for (x in v) {
            val r = PcaDecision.decideTighten(inputOf(x))
            val e = x["expect"] as Map<String, Any?>
            assertEquals("${x["name"]}: ${r.reason}", e["outcome"], r.outcome)
            assertEquals(x["name"].toString(), e["legacy"], r.legacy)
            assertEquals(x["name"].toString(), (e["offending"] as List<*>).toList(), r.offending)
            assertEquals(x["name"].toString(), e["reason"], r.reason)
        }
    }

    @Test
    fun decisionOfVectors() {
        val v = tbl("decision_of")
        assertTrue(v.size >= 25)
        for (x in v) assertEquals(x["name"].toString(), (x["expect"] as Map<String, Any?>)["decision"], PcaDecision.decisionOf(x["input"]))
    }

    @Test
    fun latticeVectors() {
        val v = tbl("decision_lattice")
        assertEquals(31, v.size)
        for (x in v) {
            val n = x["name"] as String
            val i = inputOf(x)
            val got = when (n.substring(0, 3)) {
                "mee" -> PcaDecision.meet(i["a"] as String, i["b"] as String)
                "pep" -> PcaDecision.pepDecision(i["decision"] as String, i["answered"])
                else -> PcaDecision.tighten(i["decision"] as String, i["signal"])
            }
            assertEquals(n, (x["expect"] as Map<String, Any?>)["decision"], got)
        }
    }

    @Test
    fun escalationAnswerVectors() {
        val v = tbl("escalation_answer")
        assertTrue(v.size >= 83)
        val supported = Pq.supportedSuites().toSet()
        for (x in v) {
            val i = inputOf(x)
            val pins = (i["principals"] as List<*>).map {
                if (it is String) Escalation.Principal(it) else Escalation.Principal((it as Map<String, Any?>)["pk"] as String, it["pq_pk"] as? String)
            }
            val b = i["bind"] as Map<String, Any?>
            val nowD = IntentJs.num(i["now"])!!
            val now = if (nowD == Math.floor(nowD)) nowD.toLong() else Long.MAX_VALUE // a fractional clock is not a safe integer
            val r = Escalation.verifyAnswer(i["answer"], pins, Escalation.Binding(b["policy_digest"] as String, b["action_digest"] as String, b["history_head"] as String), now)
            val e = x["expect"] as Map<String, Any?>
            val need = x["requires_suite"] as? String
            if (need != null && need !in supported) {
                // an unimplemented suite fails closed with the distinct reason (never skipped, never accepted)
                assertFalse("${x["name"]}: ${r.reason}", r.ok)
                assertTrue("${x["name"]}: '${r.reason}'", r.reason!!.contains("unsupported_suite"))
                continue
            }
            assertEquals("${x["name"]}: ${r.reason}", e["ok"], r.ok)
            if (r.ok) {
                assertEquals(x["name"].toString(), e["principal"], r.principal)
                assertEquals(x["name"].toString(), e["decision"], r.decision)
            } else assertTrue("${x["name"]}: '${r.reason}' lacks '${e["reason_contains"]}'", r.reason!!.contains(e["reason_contains"] as String))
        }
    }

    @Test
    fun escalationFoldVectors() {
        val v = tbl("escalation_fold")
        assertTrue(v.size >= 18)
        for (x in v) {
            val i = x["input"] as Map<String, Any?>
            val base = (i["core_reasons"] as List<*>).map { it as String }
            val v2 = (i["v2"] as List<*>).map {
                val m = it as Map<String, Any?>
                PcaDecision.V2Check(m["name"] as String, m["ok"] == true, m["reason"] as? String)
            }
            val got = PcaDecision.foldV2Reasons(base, v2)
            val e = x["expect"] as Map<String, Any?>
            assertEquals(x["name"].toString(), (e["reasons"] as List<*>).toList(), got)
            val checks = LinkedHashMap<String, String>()
            for ((k, st) in i["checks"] as Map<String, Any?>) checks[k] = st as String
            val d = PcaDecision.decisionOf(!checks.values.contains("fail"), checks, got)
            assertEquals(x["name"].toString(), e["decision"], d)
        }
    }

    // ---- exact outcomes (the TypeScript reason strings) ----

    private fun o(t: String) = ParityVectors.obj(t)

    @Test
    fun tightenReasonsAreTheTypeScriptStrings() {
        val deny = PcaDecision.decideTighten(
            o("""{"tighten":[{"id":"r1","when":{"field":"env.judge.s","op":"gte","value":5},"signal":"deny","reason":"too hot"}],"context":{"env":{"judge":{"s":7}}}}"""),
        )
        assertEquals("deny", deny.outcome)
        assertEquals("denied by tighten rule 'r1' (too hot)", deny.reason)
        val esc = PcaDecision.decideTighten(o("""{"tighten":[{"id":"r2","when":{"field":"env.judge.s","op":"gte","value":5},"signal":"escalate"}],"context":{"env":{"judge":{"s":7}}}}"""))
        assertEquals("escalate", esc.outcome)
        assertEquals("escalate: asked by tighten rule 'r2'", esc.reason)
        val unk = PcaDecision.decideTighten(o("""{"tighten":[{"id":"r3","when":{"field":"env.judge.s","op":"gte","value":5},"signal":"deny"}],"context":{"env":{}}}"""))
        assertEquals("escalate", unk.outcome)
        assertEquals("escalate: rule 'r3' could not be decided (a value it reads is missing or ill-typed)", unk.reason)
        val none = PcaDecision.decideTighten(o("""{"tighten":[{"id":"r4","when":{"field":"env.judge.s","op":"gte","value":5},"signal":"deny"}],"context":{"env":{"judge":{"s":1}}}}"""))
        assertEquals("ok", none.outcome)
        assertNull(none.reason)
        assertEquals("ok", PcaDecision.decideTighten(o("{}")).outcome)
    }

    @Test
    fun tightenNullIsRejectedAsTypeScriptDoes() {
        val r = PcaDecision.decideTighten(o("""{"tighten":null}"""))
        assertEquals("deny", r.outcome)
        assertEquals("malformed tighten list: tighten must be an array", r.reason)
        val p = PcaDecision.decideTighten(o("""{"polarity":null}"""))
        assertEquals("deny", p.outcome)
        assertEquals("model_polarity must be 'legacy' when present", p.reason)
        assertEquals("deny", PcaDecision.decideTighten(o("""{"polarity":"strict"}""")).outcome)
    }

    @Test
    fun tightenListErrors() {
        fun err(t: String) = PcaDecision.tightenListError(ParityVectors.parse(t))
        assertEquals("tighten[0] must be an object", err("[1]"))
        assertEquals("missing member 'tighten[0].signal'", err("""[{"id":"a","when":{}}]"""))
        assertEquals("unknown member 'tighten[0].x'", err("""[{"id":"a","when":{},"signal":"deny","x":1}]"""))
        assertEquals("tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$", err("""[{"id":"A","when":{},"signal":"deny"}]"""))
        assertEquals("tighten[1].id 'a' is a duplicate", err("""[{"id":"a","when":{},"signal":"deny"},{"id":"a","when":{},"signal":"deny"}]"""))
        assertEquals("tighten[0].when must be a condition object", err("""[{"id":"a","when":[],"signal":"deny"}]"""))
        assertEquals("tighten[0].signal must be 'escalate' or 'deny'", err("""[{"id":"a","when":{},"signal":"ok"}]"""))
        assertEquals("tighten[0].reason must be a string of at most 256 characters", err("""[{"id":"a","when":{},"signal":"deny","reason":5}]"""))
        assertNull(err("""[{"id":"a","when":{},"signal":"deny","reason":"x"}]"""))
        assertEquals("tighten must be an array", PcaDecision.tightenListError(null))
        assertNull(PcaDecision.tightenListError(null, absent = true))
        val sixtyFive = "[" + (0..64).joinToString(",") { """{"id":"r$it","when":{},"signal":"deny"}""" } + "]"
        assertEquals("tighten has more than 64 rules", err(sixtyFive))
    }

    @Test
    fun legacyPolarityReportsDegraded() {
        val preds = """[[{"verb":"*","where":[{"field":"env.class.tone","op":"eq","value":"x"}]}]]"""
        val strict = PcaDecision.decideTighten(o("""{"predicates":$preds}"""))
        assertEquals("deny", strict.outcome)
        assertFalse(strict.legacy)
        assertEquals(listOf("env.class.tone"), strict.offending)
        assertEquals("a grant's where reads model-derived path(s) env.class.tone: a model may only tighten (move them into tighten[]) (rule 21)", strict.reason)
        val legacy = PcaDecision.decideTighten(o("""{"predicates":$preds,"polarity":"legacy"}"""))
        assertEquals("ok", legacy.outcome)
        assertTrue(legacy.legacy)
        assertFalse(PcaDecision.decideTighten(o("""{"predicates":[],"polarity":"legacy"}""")).legacy)
    }

    @Test
    fun unitsReasonsAreTheTypeScriptStrings() {
        val base = """"schema_units":{"usd_minor":{"kind":"money","currency":"USD","exponent":2}},"verb_params":{"action.params.amount":{"unit":"usd_minor"}},"verb":"refund""""
        val confusion = PcaDecision.decideUnits(o("""{"units":{"action.params.amount":{"kind":"money","currency":"USD","exponent":0}},$base}"""))
        assertFalse(confusion.ok)
        assertEquals("'action.params.amount' is declared as money/USD/e2 by the action schema but the policy term is tagged money/USD/e0 (unit confusion)", confusion.reason)
        val untagged = PcaDecision.decideUnits(
            o("""{"units":{},"predicates":[[{"verb":"refund","where":[{"field":"action.params.amount","op":"lte","value":5}]}]],$base}"""),
        )
        assertEquals("a policy term reads 'action.params.amount' (money/USD/e2) without a unit tag", untagged.reason)
        val otherVerb = PcaDecision.decideUnits(o("""{"units":{},"predicates":[[{"verb":"other","where":[{"field":"action.params.amount","op":"lte","value":5}]}]],$base}"""))
        assertTrue(otherVerb.ok)
        assertEquals("the verb is missing", PcaDecision.decideUnits(o("""{"units":{}}""")).reason)
        assertEquals("the schema does not declare verb 'v'", PcaDecision.decideUnits(o("""{"units":{},"verb":"v"}""")).reason)
        assertEquals("the schema units table must be an object", PcaDecision.decideUnits(o("""{"units":{},"verb":"v","schema_units":null,"verb_params":{}}""")).reason)
        assertEquals("units must be an object", PcaDecision.decideUnits(o("""{"units":[],"verb":"v"}""")).reason)
        assertEquals("units key 'x' must be an action.params.<name> path", PcaDecision.decideUnits(o("""{"units":{"x":{"kind":"m"}},"verb":"v"}""")).reason)
        assertEquals("units['action.params.a'].exponent must be an integer in [0, 18]", PcaDecision.decideUnits(o("""{"units":{"action.params.a":{"kind":"m","exponent":19}},"verb":"v"}""")).reason)
        assertEquals("units['action.params.a'].kind must be a string of 1..64 characters", PcaDecision.decideUnits(o("""{"units":{"action.params.a":{"kind":""}},"verb":"v"}""")).reason)
        assertEquals("units['action.params.a'].currency must be a string of 1..16 characters", PcaDecision.decideUnits(o("""{"units":{"action.params.a":{"kind":"m","currency":""}},"verb":"v"}""")).reason)
    }

    @Test
    fun decisionOfIsOverTheFullFailingSet() {
        fun d(checks: Map<String, String>, vararg reasons: String) = PcaDecision.decisionOf(false, checks, reasons.toList())
        assertEquals("escalate", d(linkedMapOf("a" to "fail", "b" to "fail"), "a: intent_required: q", "b: escalate: ask"))
        assertEquals("deny", d(linkedMapOf("a" to "fail", "b" to "fail"), "a: intent_required: q", "b: nope"))
        assertEquals("deny", d(linkedMapOf("a" to "fail", "b" to "fail"), "a: intent_required: q")) // b has no reason: hard failure
        assertEquals("deny", d(linkedMapOf("a" to "fail"), "a: intent_required: q", "a: also bad"))
        assertEquals("deny", d(linkedMapOf("a" to "pass")))
        assertEquals("allow", PcaDecision.decisionOf(true, emptyMap(), emptyList()))
        assertEquals("deny", PcaDecision.meet("allow", "bogus"))
        assertEquals("deny", PcaDecision.pepDecision("deny", true))
        assertEquals("allow", PcaDecision.pepDecision("escalate", true))
        assertEquals("escalate", PcaDecision.pepDecision("escalate", false))
    }

    @Test
    fun verdictCollectsEveryFailingReason() {
        val v = Pca.verifyPcactn(o("""{}"""), o("""{}"""), 0L, Pca.Audience.Any)
        assertFalse(v.allow)
        assertEquals(v.reason, v.reasons[0])
        assertNotNull(v.reasons.firstOrNull())
    }
}
