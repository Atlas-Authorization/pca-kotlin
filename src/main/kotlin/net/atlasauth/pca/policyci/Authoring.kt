package net.atlasauth.pca.policyci

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.analyzer.Coverage
import net.atlasauth.pca.analyzer.Exposure
import net.atlasauth.pca.analyzer.TestRunner

/**
 * Authoring gates built on the analyzer, for CI: `diff` (does a change widen authority or raise the most that can leave?), `test` (a
 * policy test document against a policy, pinned by digest) and `coverage` (which clauses and thresholds the tests or traffic never
 * exercise, and which mutations they cannot tell apart). Each returns `{ok, exitCode, lines}`: the lines to print and an exit code (0 ok,
 * 1 a gate failed, 2 unusable input). None of them signs or changes anything.
 */
object Authoring {
    /** The analyzer's policy-test runner and coverage engine, which `test` and `coverage` drive. */
    interface Backend {
        /** `runPolicyTests(policy, doc, {requireDigest?})`: `{ok, total, passed, digestMatch, failures[]}`. */
        fun runPolicyTests(policy: Map<String, Any?>, doc: Map<String, Any?>, options: Map<String, Any?>?): Map<String, Any?>

        /** `coverage(policy, actions)`: `{score, mutants, untested}`. */
        fun coverage(policy: Map<String, Any?>, actions: List<Any?>): Map<String, Any?>

        /** `coverageGate(report, thresholds)`: `{ok, reasons[]}`. */
        fun coverageGate(report: Map<String, Any?>, thresholds: Map<String, Any?>): Map<String, Any?>
    }

    /** The analyzer's test runner and coverage engine as the backend of `test` and `coverage`. */
    val ANALYZER_BACKEND: Backend = object : Backend {
        override fun runPolicyTests(policy: Map<String, Any?>, doc: Map<String, Any?>, options: Map<String, Any?>?): Map<String, Any?> =
            TestRunner.runPolicyTests(policy, doc, options != null && options["requireDigest"] == true)

        override fun coverage(policy: Map<String, Any?>, actions: List<Any?>): Map<String, Any?> = Coverage.coverage(policy, actions, LinkedHashMap())

        override fun coverageGate(report: Map<String, Any?>, thresholds: Map<String, Any?>): Map<String, Any?> = Coverage.coverageGate(report, thresholds)
    }

    private fun result(ok: Boolean, exitCode: Int, lines: List<Any?>): Map<String, Any?> = PcJs.obj("ok", ok, "exitCode", PcJs.n(exitCode.toLong()), "lines", lines)

    private fun bad(line: String): Map<String, Any?> = result(false, 2, arrayListOf<Any?>(line))

    /** A policy document as the analyzer reads it: any shape lint accepts, plus optional `vetoes` and `tighten` members. */
    @Suppress("UNCHECKED_CAST")
    fun toAnalyzerPolicy(doc: Any?): Map<String, Any?> {
        val n = Normalize.normalizePolicyInput(doc)
        if (n["ok"] != true) return n
        val np = n["policy"] as Map<String, Any?>
        val policy = LinkedHashMap<String, Any?>()
        policy["predicates"] = np["predicates"]
        policy["caveats"] = np["caveats"]
        if (PcJs.isRecord(doc)) {
            if (PcJs.get(doc, "vetoes") is List<*>) policy["vetoes"] = PcJs.get(doc, "vetoes")
            if (PcJs.get(doc, "tighten") is List<*>) policy["tighten"] = PcJs.get(doc, "tighten")
        }
        return PcJs.obj("ok", true, "policy", policy)
    }

    private fun truthy(v: Any?): Boolean {
        if (v == null || v == false) return false
        if (v is String) return v.isNotEmpty()
        val d = PcJs.num(v)
        return d == null || !(d == 0.0 || d.isNaN())
    }

    /** `diff`: options `allowWiden`, `verb`, `amountField`, `integer`, `windowSecs`, `maxExposureIncrease`. */
    @Suppress("UNCHECKED_CAST")
    fun diffCommand(oldDoc: Any?, newDoc: Any?, o: Map<String, Any?>): Map<String, Any?> {
        val a = toAnalyzerPolicy(oldDoc)
        val b = toAnalyzerPolicy(newDoc)
        if (a["ok"] != true) return bad("old policy: " + PcJs.str(a["reason"]))
        if (b["ok"] != true) return bad("new policy: " + PcJs.str(b["reason"]))
        val dopts = LinkedHashMap<String, Any?>()
        if (o["verb"] != null) {
            val ex = LinkedHashMap<String, Any?>()
            ex["verb"] = o["verb"]
            if (truthy(o["amountField"])) ex["amountField"] = o["amountField"]
            if (truthy(o["integer"])) ex["integer"] = true
            if (o["windowSecs"] != null) ex["windowSecs"] = o["windowSecs"]
            dopts["exposure"] = ex
        }
        val d = Exposure.diffPolicies(a["policy"], b["policy"], dopts)
        val allow = LinkedHashMap<String, Any?>()
        allow["widen"] = o["allowWiden"] == true
        if (o["maxExposureIncrease"] != null) allow["maxExposureIncrease"] = o["maxExposureIncrease"]
        val gate = Exposure.diffGate(d, allow)
        val gateOk = gate["ok"] == true
        val lines = ArrayList<Any?>()
        val summary = d["summary"] as List<Any?>
        if (d["equivalent"] == true) lines.add("no change in what is admitted")
        else if (summary.isNotEmpty()) lines.addAll(summary)
        else lines.add("no witness found")
        if (!gateOk) for (r in gate["reasons"] as List<Any?>) lines.add("FAIL: " + PcJs.str(r))
        lines.add(if (gateOk) "PASS" else "FAIL")
        return result(gateOk, if (gateOk) 0 else 1, lines)
    }

    /** `test`: a policy test document run against a policy; option `requireDigest`. */
    @Suppress("UNCHECKED_CAST")
    fun testCommand(policyDoc: Any?, testsDoc: Any?, o: Map<String, Any?>, backend: Backend?): Map<String, Any?> {
        val p = toAnalyzerPolicy(policyDoc)
        if (p["ok"] != true) return bad("policy: " + PcJs.str(p["reason"]))
        if (!PcJs.isRecord(testsDoc) || "pca-policy-tests" != PcJs.get(testsDoc, "kind") || PcJs.get(testsDoc, "cases") !is List<*>) return bad("tests: not a pca-policy-tests document")
        if (backend == null) return bad("tests: the analyzer's policy test runner is not available")
        val opts = LinkedHashMap<String, Any?>()
        if (o["requireDigest"] != null) opts["requireDigest"] = o["requireDigest"]
        val r = backend.runPolicyTests(p["policy"] as Map<String, Any?>, testsDoc as Map<String, Any?>, opts)
        val lines = ArrayList<Any?>()
        for (fo in r["failures"] as List<Any?>) {
            val f = fo as Map<String, Any?>
            val by = f["expectedDecidedBy"]
            val got = f["decidedBy"]
            lines.add(
                "FAIL " + PcJs.str(f["name"], f.containsKey("name")) + ": expected " + PcJs.str(f["expected"], f.containsKey("expected")) +
                    (if (truthy(by)) " by " + PcJs.str(by) else "") + ", got " + PcJs.str(f["got"], f.containsKey("got")) + " by " + (if (got != null) PcJs.str(got) else "no clause"),
            )
        }
        if (r["digestMatch"] != true) lines.add((if (truthy(o["requireDigest"])) "FAIL" else "note") + ": the policy differs from the one the examples were confirmed against")
        val ok = r["ok"] == true
        lines.add(PcJs.str(r["passed"]) + "/" + PcJs.str(r["total"]) + " examples " + (if (ok) "PASS" else "FAIL"))
        return result(ok, if (ok) 0 else 1, lines)
    }

    /** `coverage`: options `minClauses`, `minBoundaries`, `minMutation`, `maxSurvivors`. */
    @Suppress("UNCHECKED_CAST")
    fun coverageCommand(policyDoc: Any?, trafficDoc: Any?, o: Map<String, Any?>, backend: Backend?): Map<String, Any?> {
        val p = toAnalyzerPolicy(policyDoc)
        if (p["ok"] != true) return bad("policy: " + PcJs.str(p["reason"]))
        // traffic: an array of actions, or a pca-policy-tests document (its cases are the traffic)
        var actions: List<Any?>? = null
        if (trafficDoc is List<*>) actions = trafficDoc as List<Any?>
        else if (PcJs.isRecord(trafficDoc) && PcJs.get(trafficDoc, "cases") is List<*>) {
            val acts = ArrayList<Any?>()
            for (c in PcJs.get(trafficDoc, "cases") as List<Any?>) acts.add(if (PcJs.isRecord(c)) PcJs.get(c, "action") else c)
            actions = acts
        }
        var badTraffic = actions == null
        if (!badTraffic) for (a in actions!!) if (!PcJs.isRecord(a) || PcJs.get(a, "verb") !is String || PcJs.get(a, "resource") !is String) { badTraffic = true; break }
        if (badTraffic) return bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document")
        if (backend == null) return bad("traffic: the analyzer's coverage engine is not available")
        val r = backend.coverage(p["policy"] as Map<String, Any?>, actions!!)
        val th = LinkedHashMap<String, Any?>()
        if (o["minClauses"] != null) th["clauses"] = o["minClauses"]
        if (o["minBoundaries"] != null) th["boundaries"] = o["minBoundaries"]
        if (o["minMutation"] != null) th["mutation"] = o["minMutation"]
        if (o["maxSurvivors"] != null) th["maxSurvivors"] = o["maxSurvivors"]
        val gate = backend.coverageGate(r, th)
        val score = r["score"] as Map<String, Any?>
        val mutants = r["mutants"] as Map<String, Any?>
        val lines = ArrayList<Any?>()
        val total = PcJs.num(mutants["total"])!!
        val equivalent = PcJs.num(mutants["equivalent"])!!
        lines.add(
            "clauses decisive " + pct(score["clauses"]) + "%, boundaries covered " + pct(score["boundaries"]) + "%, mutants killed " + pct(score["mutation"]) + "% (" +
                PcJs.str(mutants["killed"]) + "/" + PcJs.numStr(total - equivalent) + ")",
        )
        for (id in r["untested"] as List<Any?>) lines.add("untested: " + PcJs.str(id))
        for (mo in mutants["survivors"] as List<Any?>) {
            val m = mo as Map<String, Any?>
            val killer = m["killer"]
            lines.add("survives: " + PcJs.str(m["description"], m.containsKey("description")) + (if (truthy(killer)) " (kill with " + PcJs.stringify(killer) + ")" else ""))
        }
        for (x in gate["reasons"] as List<Any?>) lines.add("FAIL: " + PcJs.str(x))
        val ok = gate["ok"] == true
        lines.add(if (ok) "PASS" else "FAIL")
        return result(ok, if (ok) 0 else 1, lines)
    }

    /** `(x * 100).toFixed(0)`: the exact binary value rounded half up. */
    private fun pct(x: Any?): String {
        val v = PcJs.num(x)!! * 100
        if (v.isNaN() || v.isInfinite()) return PcJs.numStr(v)
        return BigDecimal(v).setScale(0, RoundingMode.HALF_UP).toPlainString()
    }
}
