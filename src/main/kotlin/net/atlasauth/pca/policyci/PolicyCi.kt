package net.atlasauth.pca.policyci

import java.util.regex.Pattern
import net.atlasauth.pca.analyzer.Validate

/**
 * A CI gate that STATICALLY catches unsafe PCA policies before they ship. It drives the static analyzer (reachability, totality,
 * delegation-safety subsumption, numeric satisfiability) over an envelope, a minted grant, a compiled policy or a delegation chain and
 * reports findings `{rule, severity, message, where?}`. Rules (each toggleable): over-broad-grant, privilege-escalation,
 * redundant-caveat, dangerous-reachability, missing-safety-floor, and schema-mismatch when a schema is given.
 *
 * Sound by construction: a hard error is only ever emitted from a proven analyzer verdict; anything undecidable fails safe to a warning
 * or note. A rule that throws is a finding (internal-error), never a crash and never silence.
 *
 * Options are JSON-shaped maps: `rules`, `maxCombinations`, `schema`, `schemaOptions`, and for the summary `maxSeverity`.
 */
object PolicyCi {
    /** Verb substrings treated as dangerous (case-insensitive `includes` match). */
    val DEFAULT_DANGEROUS_VERBS: List<String> = listOf(
        "delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant", "revoke", "deploy", "shutdown", "rotate",
    )

    /** Severity ordering used for thresholds; higher is more severe. Keys in the reference's order. */
    val SEVERITY_RANK: Map<String, Int> = linkedMapOf("info" to 1, "warn" to 2, "error" to 3)

    /** The schema check used when no analyzer schema validator is available: it refuses, so the rule reports internal-error. */
    val NO_SCHEMA_VALIDATOR = Rules.SchemaValidator { _, _, _ -> throw UnsupportedOperationException("schema validation is not available") }

    /** The analyzer's schema check (`validatePolicyAgainstSchema`): the default of every entry point that takes no validator. */
    val ANALYZER_SCHEMA_VALIDATOR = Rules.SchemaValidator { policy, schema, options -> Validate.validatePolicyAgainstSchema(policy, schema, options) }

    private fun guarded(rule: String, run: () -> List<Any?>): List<Any?> = try {
        run()
    } catch (e: RuntimeException) {
        listOf(PcJs.obj("rule", "internal-error", "severity", "error", "message", "rule $rule could not run: " + e.message.toString()))
    } catch (e: StackOverflowError) {
        listOf(PcJs.obj("rule", "internal-error", "severity", "error", "message", "rule $rule could not run: Maximum call stack size exceeded"))
    }

    // ---- resolved config ----

    private class Resolved {
        var overBroad = false
        var privilegeEscalation = false
        var redundantCaveat = false
        var dangerousReach = false
        var safetyFloor = false
        var requireExpiry = false
        var requireScopeGate = false
        var overBroadVerbs: List<String> = emptyList()
        var reachVerbs: List<String> = emptyList()
        var targets: List<*> = emptyList<Any?>()
    }

    private fun truthy(v: Any?): Boolean {
        if (v == null || v == false) return false
        if (v is String) return v.isNotEmpty()
        val d = PcJs.num(v)
        return d == null || !(d == 0.0 || d.isNaN())
    }

    @Suppress("UNCHECKED_CAST")
    private fun verbList(cfg: Any?, key: String): List<String> {
        val dv = if (cfg is Map<*, *>) cfg[key] else null
        return if (truthy(dv)) dv as List<String> else DEFAULT_DANGEROUS_VERBS
    }

    private fun resolveRules(rules: Any?): Resolved {
        val r: Any? = rules ?: emptyMap<String, Any?>()
        val ob = PcJs.get(r, "overBroadGrant")
        val dr = PcJs.get(r, "dangerousReachability")
        val sf = PcJs.get(r, "missingSafetyFloor")
        val c = Resolved()
        c.overBroad = ob != false
        c.overBroadVerbs = verbList(ob, "dangerousVerbs")
        c.privilegeEscalation = PcJs.get(r, "privilegeEscalation") != false
        c.redundantCaveat = PcJs.get(r, "redundantCaveat") != false
        c.dangerousReach = dr != false
        c.reachVerbs = verbList(dr, "dangerousVerbs")
        val t = if (dr is Map<*, *>) dr["targets"] else null
        c.targets = if (truthy(t)) t as List<*> else emptyList<Any?>()
        c.safetyFloor = sf != false
        c.requireExpiry = sf !is Map<*, *> || sf["requireExpiry"] != false
        c.requireScopeGate = sf !is Map<*, *> || sf["requireScopeGate"] != false
        return c
    }

    private fun analyzerOpts(opts: Map<String, Any?>?): Map<String, Any?> {
        val ao = LinkedHashMap<String, Any?>()
        if (opts != null && opts.containsKey("maxCombinations")) ao["maxCombinations"] = opts["maxCombinations"]
        return ao
    }

    // ---- lintPolicy / lintChain / lint ----

    /** Lint a single PCA policy (an envelope, a minted grant, a compiled policy or a bare `{predicates, caveats?}`); empty = clean. */
    @Suppress("UNCHECKED_CAST")
    fun lintPolicy(input: Any?, opts: Map<String, Any?>?, validator: Rules.SchemaValidator = ANALYZER_SCHEMA_VALIDATOR): List<Any?> {
        val norm = Normalize.normalizePolicyInput(input)
        if (norm["ok"] != true) return listOf(PcJs.obj("rule", "malformed-policy", "severity", "error", "message", norm["reason"]))
        val cfg = resolveRules(opts?.get("rules"))
        val ao = analyzerOpts(opts)
        val policy = norm["policy"] as Map<String, Any?>
        val out = ArrayList<Any?>()
        if (cfg.overBroad) out.addAll(guarded("over-broad-grant") { Rules.ruleOverBroadGrant(policy, cfg.overBroadVerbs, ao) })
        if (cfg.redundantCaveat) out.addAll(guarded("redundant-caveat") { Rules.ruleRedundantCaveat(policy) })
        if (cfg.dangerousReach) out.addAll(guarded("dangerous-reachability") { Rules.ruleDangerousReachability(policy, cfg.reachVerbs, cfg.targets, ao) })
        if (cfg.safetyFloor) out.addAll(guarded("missing-safety-floor") { Rules.ruleMissingSafetyFloor(policy, cfg.requireExpiry, cfg.requireScopeGate, cfg.overBroadVerbs) })
        if (opts != null && opts.containsKey("schema")) {
            val so = opts["schemaOptions"]
            out.addAll(guarded("schema-mismatch") { Rules.ruleSchemaMismatch(policy, opts["schema"], if (so is Map<*, *>) so as Map<String, Any?> else null, validator) })
        }
        return out
    }

    /**
     * Lint a delegation chain (root to leaf): grants or already-effective `{predicates, caveats}` hops. Runs the privilege-escalation
     * check across every consecutive pair, then the single-policy rules on the acting leaf's effective authority.
     */
    @Suppress("UNCHECKED_CAST")
    fun lintChain(chain: List<*>, opts: Map<String, Any?>?): List<Any?> {
        val norm = Normalize.normalizeChain(chain)
        if (norm["ok"] != true) return listOf(PcJs.obj("rule", "malformed-policy", "severity", "error", "message", norm["reason"]))
        val cfg = resolveRules(opts?.get("rules"))
        val ao = analyzerOpts(opts)
        val hops = norm["hops"] as List<Any?>
        val out = ArrayList<Any?>()
        if (cfg.privilegeEscalation) out.addAll(guarded("privilege-escalation") { Rules.rulePrivilegeEscalation(hops, ao) })

        if (hops.isNotEmpty()) {
            val leaf = hops[hops.size - 1] as Map<String, Any?>
            if (cfg.overBroad) out.addAll(guarded("over-broad-grant") { Rules.ruleOverBroadGrant(leaf, cfg.overBroadVerbs, ao) })
            if (cfg.redundantCaveat) out.addAll(guarded("redundant-caveat") { Rules.ruleRedundantCaveat(leaf) })
            if (cfg.dangerousReach) out.addAll(guarded("dangerous-reachability") { Rules.ruleDangerousReachability(leaf, cfg.reachVerbs, cfg.targets, ao) })
            if (cfg.safetyFloor) out.addAll(guarded("missing-safety-floor") { Rules.ruleMissingSafetyFloor(leaf, cfg.requireExpiry, cfg.requireScopeGate, cfg.overBroadVerbs) })
        }
        return out
    }

    /** Dispatch: a list input is a delegation chain, anything else a single policy. */
    fun lint(input: Any?, opts: Map<String, Any?>?, validator: Rules.SchemaValidator = ANALYZER_SCHEMA_VALIDATOR): List<Any?> =
        if (input is List<*>) lintChain(input, opts) else lintPolicy(input, opts, validator)

    // ---- lintPolicies + summary ----

    /** Lint a list of labeled policies (`{label?, policy}`) or chains and roll the findings into a summary. */
    fun lintPolicies(items: List<Map<String, Any?>>, opts: Map<String, Any?>?, validator: Rules.SchemaValidator = ANALYZER_SCHEMA_VALIDATOR): Map<String, Any?> {
        val results = ArrayList<Any?>()
        for (i in items.indices) {
            val item = items[i]
            val label = item["label"]
            results.add(PcJs.obj("label", label ?: "policy[$i]", "findings", lint(item["policy"], opts, validator)))
        }
        return summarize(results, opts)
    }

    /** Roll labeled findings into counts and an exit-code mapping (`error` gives non-zero); nothing linted never reports success. */
    fun summarize(results: List<Any?>?, opts: Map<String, Any?>?): Map<String, Any?> {
        val ms = opts?.get("maxSeverity")
        val maxSeverity: Any? = ms ?: "error"
        // an object key is the text of the value: ["error"] names "error"
        val msKey = net.atlasauth.pca.jose.Js.template(maxSeverity)
        if (!SEVERITY_RANK.containsKey(msKey)) {
            throw IllegalArgumentException("summarize: maxSeverity must be one of " + SEVERITY_RANK.keys.joinToString(", "))
        }
        var counts = PcJs.obj("error", PcJs.n(0), "warn", PcJs.n(0), "info", PcJs.n(0))
        if (results == null || results.isEmpty()) {
            return PcJs.obj("results", ArrayList<Any?>(), "counts", counts, "maxSeverity", maxSeverity, "ok", false, "exitCode", PcJs.n(2), "reason", "no policies were linted")
        }
        val n = LongArray(3) // error, warn, info
        var failing = 0
        val threshold = SEVERITY_RANK.getValue(msKey)
        for (r in results) {
            for (fo in PcJs.get(r, "findings") as List<*>) {
                val sv = PcJs.get(fo, "severity")
                val svKey = if (sv == null && !(fo is Map<*, *> && fo.containsKey("severity"))) "undefined" else net.atlasauth.pca.jose.Js.template(sv)
                val sev = if (SEVERITY_RANK.containsKey(svKey)) svKey else "error"
                if (sev == "error") n[0]++ else if (sev == "warn") n[1]++ else n[2]++
                if (SEVERITY_RANK.getValue(sev) >= threshold) failing++
            }
        }
        counts = PcJs.obj("error", PcJs.n(n[0]), "warn", PcJs.n(n[1]), "info", PcJs.n(n[2]))
        val ok = failing == 0
        return PcJs.obj("results", results, "counts", counts, "maxSeverity", maxSeverity, "ok", ok, "exitCode", PcJs.n(if (ok) 0 else 1))
    }

    // ---- pinned lint rule list ----

    private val DIGEST = Pattern.compile("[A-Za-z0-9_-]{43}")

    /**
     * Enforce the pinned digest of the action-kit lint rule list: [pinText] is the pin file's content (one digest, surrounding whitespace
     * ignored). Returns `{ok, message}`; an empty or malformed pin fails.
     */
    fun checkLintRulesPin(pinText: String, actual: String = ActionLintRules.lintRulesDigest()): Map<String, Any?> {
        val pinned = PcJs.trim(pinText)
        if (!DIGEST.matcher(pinned).matches()) return PcJs.obj("ok", false, "message", "the lint rules pin is not a digest (expected 43 base64url characters)")
        return if (pinned == actual) PcJs.obj("ok", true, "message", "lint rules digest $actual matches the pin")
        else PcJs.obj("ok", false, "message", "lint rules digest $actual differs from the pin $pinned: the rule list changed; review it and update the pin")
    }
}
