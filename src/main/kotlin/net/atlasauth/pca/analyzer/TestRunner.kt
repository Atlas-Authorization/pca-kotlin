package net.atlasauth.pca.analyzer

import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import java.security.MessageDigest

/**
 * POLICY-AS-CODE TEST RUNNER. A policy test document lists actions with the decision the author expects (and optionally the clause expected
 * to decide). It names the policy it was written for by digest and may be signed, so a recompile that drifts must still reproduce every
 * confirmed example or the run fails. [generateBoundaryTests] writes the examples a reviewer would otherwise have to think of: one
 * minimal allow per permit clause, one trigger per prohibition, and for every numeric threshold the points just below, at and just above it.
 * Expectations in a generated document are the policy's CURRENT behaviour, to be read and confirmed by a person.
 */
object TestRunner {
    const val POLICY_TESTS_KIND = "pca-policy-tests"
    const val POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\u0000"

    /** {v: 1, kind, policy_digest, cases}: the document for [policy] over [cases] ({name, action, expect, decidedBy?}). */
    fun policyTestsDoc(policy: Any?, cases: List<Any?>): Map<String, Any?> =
        AJs.obj("v", AJs.n(1), "kind", POLICY_TESTS_KIND, "policy_digest", Residual.policyDigestOf(Enumerate.toModel(policy)), "cases", cases)

    /** Run a document against a policy: {total, passed, failures, digestMatch, ok}. With [requireDigest] a changed policy fails even if every case passes. */
    fun runPolicyTests(policy: Any?, doc: Map<String, Any?>?, requireDigest: Boolean = false): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val cases = AJs.list(AJs.get(AJs.req(doc), "cases"))
        val failures = ArrayList<Any?>()
        for (c in cases) {
            val w = Coverage.witnessOf(model, AJs.map(AJs.get(c, "action")))
            val decidedBy = AJs.get(w["winner"], "id")
            if (!AJs.strictEq(w["decision"], AJs.get(c, "expect")) || (AJs.has(c, "decidedBy") && !AJs.strictEq(AJs.get(c, "decidedBy"), decidedBy))) {
                val f = AJs.obj()
                AJs.putIf(f, "name", c, "name")
                AJs.putIf(f, "expected", c, "expect")
                f["got"] = w["decision"]
                f["decidedBy"] = decidedBy
                if (AJs.has(c, "decidedBy")) f["expectedDecidedBy"] = AJs.get(c, "decidedBy")
                failures.add(f)
            }
        }
        val digestMatch = Residual.policyDigestOf(model) == AJs.get(doc, "policy_digest")
        return AJs.obj("total", AJs.n(cases.size), "passed", AJs.n(cases.size - failures.size), "failures", failures, "digestMatch", digestMatch,
            "ok", failures.isEmpty() && (!requireDigest || digestMatch))
    }

    private fun message(doc: Any?): ByteArray =
        POLICY_TESTS_SIG_DOMAIN.toByteArray(Charsets.UTF_8) + MessageDigest.getInstance("SHA-256").digest(Pca.hashCanonical(doc).toByteArray(Charsets.UTF_8))

    /** The principal signs the confirmed examples: {doc, signer, sig}. */
    fun signPolicyTests(doc: Map<String, Any?>, secret: Keys.EdKey, signerPublic: String): Map<String, Any?> =
        AJs.obj("doc", doc, "signer", signerPublic, "sig", Keys.b64u(secret.sign(message(doc))))

    /** Is the signed document signed by [expectedSigner]? Never throws. */
    fun verifyPolicyTests(s: Any?, expectedSigner: String?): Boolean = try {
        val doc = AJs.get(s, "doc")
        val sig = AJs.get(s, "sig")
        val signer = AJs.get(s, "signer")
        // a missing expected signer refuses (the reference throws inside its try)
        if (expectedSigner == null || expectedSigner != signer || POLICY_TESTS_KIND != AJs.get(doc, "kind")) false
        else sig is String && Pca.verifyB64u(signer as String, message(doc), sig)
    } catch (e: RuntimeException) {
        false
    }

    private fun paramPaths(p: Any?): List<String> {
        val out = LinkedHashSet<String>()
        val w = AJs.get(p, "where")
        if (w is List<*>) for (c in w) walk(c, out)
        return ArrayList(out)
    }

    private fun walk(c: Any?, out: MutableSet<String>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        val f = AJs.get(c, "field")
        if (f is String && f.startsWith("action.params.")) out.add(f)
        for (k in arrayOf("all_of", "any_of")) { val xs = AJs.get(c, k); if (xs is List<*>) for (x in xs) walk(x, out) }
        if (AJs.truthy(AJs.get(c, "not"))) walk(AJs.get(c, "not"), out)
    }

    /** Boundary examples for every clause and numeric threshold of the policy; expectations are the current behaviour. Options: epsilon (default 1). */
    fun generateBoundaryTests(policy: Any?, o: Map<String, Any?>? = null): Map<String, Any?> {
        val eps = if (AJs.get(o, "epsilon") == null) 1.0 else AJs.toNum(AJs.get(o, "epsilon"))
        val model = Enumerate.toModel(policy)
        val cases = ArrayList<Any?>()
        val seen = HashSet<String>()
        val add = { name: String, action: Map<String, Any?> ->
            if (seen.add(AJs.stringify(action))) {
                val w = Coverage.witnessOf(model, action)
                val c = AJs.obj("name", name, "action", action, "expect", w["decision"])
                val id = AJs.get(w["winner"], "id")
                if (id != null) c["decidedBy"] = id
                cases.add(c)
            }
        }
        for (i in model.predicates.indices) {
            val p = model.predicates[i]
            val r = Analyzer.alwaysDenies(AJs.obj("predicates", AJs.arr(p), "caveats", model.caveats, "vetoes", model.vetoes, "tighten", model.tighten))
            val base0 = r["witness"] ?: Analyzer.alwaysDenies(AJs.obj("predicates", AJs.arr(p), "caveats", model.caveats))["witness"] ?: continue
            val base = AJs.map(base0)
            val pid = Coverage.permitId(i)
            add("$pid: minimal admitted action", base)
            for (path in paramPaths(p)) {
                val name = path.substring("action.params.".length)
                for (t in Exposure.thresholds(Enumerate.toModel(AJs.obj("predicates", AJs.arr(p))), path)) {
                    val tags = arrayOf("below", "at", "above")
                    val vs = doubleArrayOf(t - eps, t, t + eps)
                    for (k in 0 until 3) {
                        val params = AJs.copy(base["params"])
                        params[name] = AJs.n(vs[k])
                        val a = AJs.copy(base)
                        a["params"] = params
                        add(pid + ": " + name + " " + tags[k] + " " + AJs.fmt(t), a)
                    }
                }
            }
            val other = AJs.copy(base)
            other["resource"] = base["resource"].toString() + "/__other__"
            add("$pid: unmentioned resource", other)
        }
        // a trigger per prohibition: an action some permit would allow and this prohibition stops (so the prohibition is what is tested)
        val permitOnly = model.copy()
        permitOnly.vetoes = ArrayList()
        permitOnly.tighten = ArrayList()
        val inp = ProbeInputs()
        inp.predicateSets.add(Enumerate.probeSet(model))
        inp.varyReversibility = model.revCap != null
        val pr = Enumerate.collectProbes(inp)
        for (v in model.vetoes) {
            val hit = Enumerate.collect(pr, { rep -> Enumerate.decide(permitOnly, rep) != "deny" && Enumerate.vetoApplies(v, Enumerate.contextOfAction(Enumerate.repToAction(rep))) }, Enumerate.DEFAULT_MAX_COMBINATIONS, 1.0)
            if (hit.hits.isNotEmpty()) add(CaveatAnalysis.jsString(AJs.get(v, "id"), AJs.has(v, "id")) + ": trigger", Enumerate.repToAction(hit.hits[0]))
        }
        return policyTestsDoc(policy, cases)
    }

    /** The decision of every case under [policy] (for a table in a PR comment). */
    fun decideAll(policy: Any?, doc: Map<String, Any?>?): List<Any?> {
        val model = Enumerate.toModel(policy)
        val out = ArrayList<Any?>()
        for (c in AJs.list(AJs.get(AJs.req(doc), "cases"))) out.add(Enumerate.decideAction(model, AJs.get(c, "action")))
        return out
    }
}
