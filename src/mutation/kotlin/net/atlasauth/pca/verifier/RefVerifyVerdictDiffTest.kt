package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The FULL verdict of the resource-server verifier against the reference (ref-verify-verdict, 1022 cases): allow, the recomputed risk, the required
 * threshold, every check with its status, the exact reasons in order, the budget and the assurance report.
 *
 * Counted differences from the reference, each asserted by name and count (never skipped silently):
 *  - the typed options cannot hold a `now` that is a string or a `require` that is not a list: those two hostile-shape cases are asserted to deny;
 *  - a reason that carries a JavaScript engine message ("verifier error (fail closed): Cannot read properties of null ...") is compared by its prefix;
 *  - the text of a strict-JSON parse error is this lane's parser's own: compared by its prefix ("undecodable PCActn: strict JSON:");
 *  - `allowUnboundPq` is not offered (ruling): the two cases that pass it are classical proofs, so the verdict is the same and is compared in full.
 */
@Suppress("UNCHECKED_CAST")
class RefVerifyVerdictDiffTest {
    private val mod = "ref-verify-verdict"
    private val enginePrefix = "verifier error (fail closed):"
    private val parsePrefix = "undecodable PCActn: strict JSON:"

    private class Unrepresentable(val tag: String) : RuntimeException(tag)

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun hook(d: Any?): PcaCore.Hook {
        val h = m(d)
        if (h.containsKey("throws")) {
            val msg = h["throws"] as String
            return PcaCore.Hook { throw RuntimeException(msg) }
        }
        val raw: Map<String, Any?>? = if (h.containsKey("raw")) h["raw"] as Map<String, Any?>? else h
        return PcaCore.Hook {
            // the reference reads `.enforced` of what the hook returned: a null return is a TypeError there, a throw here
            if (raw == null) throw RuntimeException("Cannot read properties of null (reading 'enforced')")
            if (ZkJs.truthy(raw["enforced"])) {
                val t = raw["t"]
                PcaCore.HookResult.enforced(ZkJs.truthy(raw["ok"]), raw["reason"] as String?, if (t is Json.Num) IntentJs.num(t) else null)
            } else PcaCore.HookResult.notEnforced()
        }
    }

    private fun strings(o: Any?, tag: String): List<String> {
        if (o !is List<*>) throw Unrepresentable(tag)
        return o.map { it as? String ?: throw Unrepresentable(tag) }
    }

    private fun options(j: Map<String, Any?>): ServerVerify.Options {
        val o = ServerVerify.Options(j["grant"])
        if (j.containsKey("now")) {
            val v = j["now"]
            if (v !is Json.Num) throw Unrepresentable("now")
            o.nowEpoch = IntentJs.num(v)!!.toLong()
        }
        if (j.containsKey("audience")) {
            val a = j["audience"]
            o.audience = if (a == null) Pca.Audience.Any else if (a is String) Pca.Audience.Of(a) else Pca.Audience.Of(ZkJs.string(a))
        }
        if (j.containsKey("hooks")) {
            val hm = m(j["hooks"])
            val h = PcaCore.Hooks()
            if (hm.containsKey("attestation")) h.attestation = hook(hm["attestation"])
            if (hm.containsKey("threshold")) h.threshold = hook(hm["threshold"])
            if (hm.containsKey("revocation")) h.revocation = hook(hm["revocation"])
            if (hm.containsKey("zk")) h.zk = hook(hm["zk"])
            o.hooks = h // a `replay` entry is not a hook of the reference's verifier: ignored
        }
        if (j.containsKey("context")) o.context = j["context"].let { if (it == null || it is Map<*, *>) it as Map<String, Any?>? else emptyMap() } // an array, string or number has no members the verifier reads
        if (j["require"] != null) o.require = strings(j["require"], "require") // a null require is no requirement
        if (j.containsKey("allowedSuites")) o.allowedSuites = strings(j["allowedSuites"], "allowedSuites")
        if (j.containsKey("pqPins")) o.pqPins = m(j["pqPins"])
        if (j.containsKey("operation")) o.operation = j["operation"] as Map<String, Any?>?
        o.insecureSkipPlanRootCheck = j["insecureSkipPlanRootCheck"] == true
        if (j.containsKey("intent")) {
            val i = m(j["intent"])
            o.intentPolicy = Pca.IntentPolicy(i["require"] == true, IntentJs.num(i["min_fidelity_ppm"]), IntentJs.num(i["max_residual_risk_ppm"])) // the policy members are snake case; a camel-case one is no member
        }
        if (j.containsKey("enforce")) {
            val em = m(j["enforce"])
            val e = PcaCore.Enforce()
            if (em.containsKey("freshness")) {
                val f = m(em["freshness"])
                e.freshness = PcaCore.Freshness(
                    IntentJs.num(f["maxAgeMs"])!!,
                    if (f.containsKey("epochMs")) IntentJs.num(f["epochMs"]) else null,
                    if (f.containsKey("clockSkewMs")) IntentJs.num(f["clockSkewMs"]) else null,
                    if (f.containsKey("now")) IntentJs.num(f["now"])!!.toLong() else null,
                )
            }
            if (em.containsKey("attestation")) {
                val a = m(em["attestation"])
                val g = PcaCore.AttestationGate(hook(a["verifier"]))
                if (a.containsKey("required")) g.required = a["required"] == true
                e.attestation = g
            }
            o.enforce = e
        }
        if (j.containsKey("requireRiskInputs")) o.requireRiskInputs = strings(j["requireRiskInputs"], "requireRiskInputs")
        o.assurance = j["assurance"] == true
        if (j.containsKey("requireAssurance")) o.requireAssurance = m(j["requireAssurance"])
        if (j.containsKey("allowUnsupported")) o.allowUnsupported = strings(j["allowUnsupported"], "allowUnsupported")
        return o
    }

    private fun same(a: Any?, b: Any?): Boolean = IntentJs.jsonEquals(IntentJs.normalize(a), IntentJs.normalize(OracleCases.toJson(b)))

    private fun close(a: Double, b: Double): Boolean = a == b || Math.abs(a - b) <= 1e-12 * Math.max(Math.abs(a), Math.abs(b))

    private fun reasonsMatch(want: List<String>, got: List<String>, counts: MutableMap<String, Int>): Boolean {
        if (want.size != got.size) return false
        for (i in want.indices) {
            val w = want[i]
            val g = got[i]
            when {
                w.startsWith(enginePrefix) -> { if (!g.startsWith(enginePrefix)) return false; counts.merge("engine", 1, Int::plus) }
                w.startsWith(parsePrefix) -> { if (!g.startsWith(parsePrefix)) return false; counts.merge("parse", 1, Int::plus) }
                w != g -> return false
            }
        }
        return true
    }

    @Test fun everyVerdictMatchesTheReference() {
        val cases = OracleCases.of(mod, "verifyVerdict")
        assertEquals(1022, cases.size)
        val bad = ArrayList<String>()
        val counts = LinkedHashMap<String, Int>()
        for (c in cases) {
            val a = c["args"] as List<Any?>
            val want = m(c["out"])
            val name = c["name"].toString()
            val v: ServerVerify.Verdict
            try {
                v = ServerVerify.verify(a[0], options(m(a[1])))
            } catch (u: Unrepresentable) {
                // the typed options cannot express this hostile shape: the reference's own verdict is a denial, and so is the only one we can assert
                counts.merge(u.tag, 1, Int::plus)
                if (want["allow"] != false) bad.add("$name: unrepresentable ${u.tag} but the reference allows")
                continue
            }
            val problems = ArrayList<String>()
            if (v.allow != want["allow"]) problems.add("allow ${v.allow} want ${want["allow"]}")
            if (!close(v.r, IntentJs.num(want["r"])!!)) problems.add("r ${v.r} want ${want["r"]}")
            if (!same(want["requiredThreshold"], v.requiredThreshold)) problems.add("requiredThreshold ${v.requiredThreshold} want ${want["requiredThreshold"]}")
            if (v.checks != m(want["checks"])) problems.add("checks ${v.checks} want ${want["checks"]}")
            if (!reasonsMatch((want["reasons"] as List<Any?>).map { it as String }, v.reasons, counts)) problems.add("reasons ${v.reasons} want ${want["reasons"]}")
            val wb = want["budget"] as Map<String, Any?>?
            val gb = v.budget
            if ((wb == null) != (gb == null)) problems.add("budget presence ${gb} want $wb")
            else if (wb != null && gb != null) {
                for (k in listOf("B", "tau", "asOf")) if (!close(IntentJs.num(gb[k]) ?: Double.NaN, IntentJs.num(wb[k]) ?: Double.NaN)) problems.add("budget.$k ${gb[k]} want ${wb[k]}")
            }
            if (want.containsKey("assurance") != (v.assurance != null)) problems.add("assurance presence")
            else if (want.containsKey("assurance") && !same(want["assurance"], v.assurance)) problems.add("assurance ${v.assurance} want ${want["assurance"]}")
            if (problems.isNotEmpty()) bad.add("$name\n  " + problems.joinToString("\n  "))
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        // the counted differences
        assertEquals(1, counts["now"])
        assertEquals(1, counts["require"])
        assertEquals(3, counts["parse"])
        assertEquals(5, counts["engine"])
    }

    /** `allowUnboundPq` is not offered (ruling): the two corpus cases that pass it are classical proofs, so it cannot change their verdicts. */
    @Test fun theLegacyUnboundPqOptionIsNotOffered() {
        val withOption = OracleCases.of(mod, "verifyVerdict").filter { m((it["args"] as List<Any?>)[1]).containsKey("allowUnboundPq") }
        assertEquals(2, withOption.size)
        for (c in withOption) {
            val p = (c["args"] as List<Any?>)[0] as Map<String, Any?>
            assertTrue(c["name"].toString(), p["alg"] == null && (p["cap_chain"] as List<Any?>).all { m(it)["alg"] == null })
        }
    }
}
