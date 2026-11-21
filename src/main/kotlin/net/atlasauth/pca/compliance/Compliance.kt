package net.atlasauth.pca.compliance

import java.util.Locale
import net.atlasauth.pca.compliance.ComplianceJs.UNDEF
import net.atlasauth.pca.compliance.ComplianceJs.obj
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.compliance.ComplianceJs as Js

/**
 * Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to EU AI Act Art. 12 / 50, ISO/IEC 42001 and
 * SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR). Everything is pure and read-only, and total where
 * the reference is: a malformed record degrades to a best-effort one. HONEST SCOPE: an evidence mapping, not a legal certification.
 * Inputs and outputs are the JSON shapes (Map / List / String / Boolean / Json.Num / null); member reads follow JavaScript semantics.
 */
@Suppress("UNCHECKED_CAST")
object Compliance {
    @JvmField val COMPLIANCE_FRAMEWORKS: List<String> = listOf("eu-ai-act", "iso-42001", "soc2")
    @JvmField val CONTROL_MAPPINGS: List<Map<String, Any?>> = ControlTable.MAPPINGS
    private val FRAMEWORK_IDS = listOf("eu-ai-act", "soc2", "gdpr")

    // ---- AuditEvent ----

    private fun isBudgetAlloc(cv: Any?): Boolean {
        if (cv !is Map<*, *>) return false
        return "budget_alloc" == cv["type"] && Js.finite(cv["limit"]) && Js.num(cv["limit"])!! >= 0
    }

    private fun numstr(x: Any?): String {
        if (!Js.finite(x)) return Js.tpl(x)
        val d = Js.num(x)!!
        if (d == Math.rint(d)) return Js.numStr(d)
        return Js.numStr(Js.round(d * 1e4) / 1e4)
    }

    /** A bounded, human-readable rendering of one caveat. */
    @JvmStatic
    fun describeCaveat(cv: Any?): String {
        if (cv !is Map<*, *> || cv["type"] !is String) return "(malformed caveat)"
        val type = cv["type"] as String
        if (type == "envelope") {
            val p = cv["predicates"]
            val c = cv["caveats"]
            return "policy envelope (" + (if (p is List<*>) p.size else 0) + " predicate(s), " + (if (c is List<*>) c.size else 0) + " caveat(s))"
        }
        if (isBudgetAlloc(cv)) return "budget allocation ≤ " + numstr(cv["limit"])
        val parts = ArrayList<String>()
        for (k in Js.keys(cv).take(8)) {
            if (k == "type") continue
            val v = cv[k]
            parts.add(k + "=" + (if (v is Map<*, *> || v is List<*>) Js.stringify(v, "", false) else numstr(v)))
        }
        return if (parts.isEmpty()) type else type + "(" + parts.joinToString(", ") + ")"
    }

    private fun buildDelegationHops(chain: Any?): List<Any?> {
        val safe: List<Any?> = if (chain is List<*>) chain as List<Any?> else emptyList()
        val hops = ArrayList<Any?>()
        for (i in safe.indices) {
            val cap = safe[i]
            if (!Js.truthy(cap)) continue
            val isRoot = i == 0
            val parent = if (i > 0) safe[i - 1] else null
            val pcv = if (Js.truthy(parent)) Js.own(parent, "caveats") else UNDEF
            val parentLen = if (pcv is List<*>) pcv.size else 0
            val ownCv = Js.own(cap, "caveats")
            val own: List<Any?> = if (ownCv is List<*>) ownCv as List<Any?> else emptyList()
            val added: List<Any?> = if (isRoot) own else if (own.size >= parentLen) own.subList(parentLen, own.size) else emptyList()
            val scope = ArrayList<Any?>()
            var budgetCv: Any? = null
            for (c in added) { scope.add(describeCaveat(c)); if (budgetCv == null && isBudgetAlloc(c)) budgetCv = c }
            val issuer = Js.own(cap, "issuer")
            val holder = Js.own(cap, "holder")
            val joined = scope.joinToString("; ") { it.toString() }
            val narrative = if (isRoot)
                "Principal " + Js.shortKey(issuer, 12) + " granted authority to " + Js.shortKey(holder, 12) + (if (scope.isEmpty()) "" else " under: $joined") + "."
            else
                Js.shortKey(issuer, 12) + " delegated to " + Js.shortKey(holder, 12) + (if (scope.isEmpty()) " (rebind only, no new constraints)" else ", narrowing scope: $joined") + "."
            val hop = obj("index", i.toLong(), "isRoot", isRoot, "issuer", issuer, "holder", holder, "scope", scope, "caveats", ArrayList<Any?>(added), "narrative", narrative)
            if (budgetCv != null) hop["budgetAlloc"] = (budgetCv as Map<String, Any?>)["limit"]
            hops.add(hop)
        }
        return hops
    }

    private fun buildHumanOverride(threshold: Any?, requiredTier: Any?, thresholdCheck: Any?): Map<String, Any?>? {
        val sh = if (Js.truthy(threshold)) Js.own(threshold, "shares") else UNDEF
        val shares: List<Any?> = if (sh is List<*>) sh as List<Any?> else emptyList()
        if (shares.isEmpty()) return null
        // The threshold block is outside the signed body: never report a signed approval from unverified shares.
        if ("pass" != thresholdCheck) {
            return obj(
                "humanApproved", false, "approvers", ArrayList<Any?>(), "guardianCosigners", ArrayList<Any?>(), "roles", ArrayList<Any?>(), "requiredTier", requiredTier,
                "narrative", shares.size.toString() + " co-signature share(s) were presented but NOT verified (threshold check: " +
                    (if (Js.nullish(thresholdCheck)) "absent" else Js.tpl(thresholdCheck)) + "); no human approval is recorded.",
            )
        }
        val approvers = ArrayList<Any?>()
        val guardians = ArrayList<Any?>()
        val roles = ArrayList<Any?>()
        for (s in shares) {
            if (!Js.truthy(s)) continue
            val role = Js.own(s, "role") as? String ?: continue
            roles.add(role)
            val pk = Js.own(s, "publicKey")
            if (role == "principal" && pk is String) approvers.add(pk)
            if (role == "guardian" && pk is String) guardians.add(pk)
        }
        val approved = approvers.isNotEmpty()
        val narrative = if (approved)
            "Step-up approved by a signed human co-signature from principal " + Js.shortKey(approvers[0], 12) +
                (if (guardians.isEmpty()) "" else " (plus " + guardians.size + " guardian co-sign)") + " at tier t=" + Js.tpl(requiredTier) + "."
        else "Co-signed by " + guardians.size + " guardian share(s) at tier t=" + Js.tpl(requiredTier) + " (no human principal signature present)."
        return obj("humanApproved", approved, "approvers", approvers, "guardianCosigners", guardians, "roles", roles, "requiredTier", requiredTier, "narrative", narrative)
    }

    private fun firstReasonOr(decision: Any?, fallback: String): Any? {
        val rs = Js.own(decision, "reasons")
        if (rs is List<*> && rs.isNotEmpty() && rs[0] is String) return rs[0]
        return fallback
    }

    private fun resolveOutcome(verify: Any?, decision: Any?): Pair<String, Any?> {
        if (!Js.truthy(verify) || true != Js.own(verify, "allow")) {
            val r = Js.qprop(verify, "reason")
            return "deny" to (if (Js.nullish(r)) "proof failed verification" else r)
        }
        if (!Js.truthy(decision)) return "allow" to "proof verified; no policy decision supplied"
        if (Js.truthy(Js.own(decision, "admit"))) return "allow" to firstReasonOr(decision, "auto-admitted within policy and budget")
        if (Js.truthy(Js.own(decision, "releaseGuardianShare"))) return "step-up" to firstReasonOr(decision, "policy satisfied but a co-signature is required")
        return "deny" to firstReasonOr(decision, "policy did not release authority (default-deny)")
    }

    private fun safeDigest(p: Any?): String {
        if (p === UNDEF) return "(undigestible)"
        return try { Pca.hashCanonical(p) } catch (e: RuntimeException) { "(undigestible)" }
    }

    private fun strOr(v: Any?, dflt: String): Any = if (v is String) v else dflt

    /**
     * A normalized AuditEvent from a PCActn, the core verifier's result and the policy decision. `input` is
     * `{pcactn, verify, decision?, now?, session?}`; `now` (epoch ms) defaults to the clock.
     */
    @JvmStatic
    fun toAuditEvent(input: Any?): Map<String, Any?> {
        val p = Js.prop(input, "pcactn")
        var verify = Js.own(input, "verify")
        if (Js.nullish(verify)) verify = obj("allow", false, "checks", LinkedHashMap<String, Any?>())
        val decision = Js.own(input, "decision")
        var now = Js.own(input, "now")
        if (Js.nullish(now)) now = Js.nowMs()
        val cc = Js.qprop(p, "cap_chain")
        val chain: List<Any?>? = if (cc is List<*>) cc as List<Any?> else null
        val hops = buildDelegationHops(chain)
        val leaf = if (chain != null && chain.isNotEmpty()) chain[chain.size - 1] else UNDEF
        val root = if (chain != null && chain.isNotEmpty()) chain[0] else UNDEF
        val (outcome, reason) = resolveOutcome(verify, decision)
        val tier = Js.qprop(Js.qprop(decision, "requiredThreshold"), "t")
        val requiredTier: Any? = if (Js.nullish(tier)) 1L else tier
        val checksRaw = Js.own(verify, "checks")
        val human = buildHumanOverride(Js.qprop(p, "threshold"), requiredTier, Js.qprop(checksRaw, "threshold"))
        val checks: Any? = if (Js.nullish(checksRaw)) LinkedHashMap<String, Any?>() else checksRaw
        val cryptoOk = "pass" == Js.own(checks, "wire") && "pass" == Js.own(checks, "leaf_signature")

        val action = Js.qprop(p, "action")
        val verb = strOr(Js.qprop(action, "verb"), "(unknown verb)") as String
        val resource = strOr(Js.qprop(action, "resource"), "(unknown resource)") as String
        val grantRef = strOr(Js.qprop(p, "grant_ref"), "(none)") as String
        val counter = Js.qprop(p, "counter")
        val nonce = Js.qprop(p, "nonce")
        val paramsDigest = strOr(Js.qprop(action, "params_digest"), "(none)")
        val evidence = obj(
            "pcactnDigest", safeDigest(p), "leafSignature", strOr(Js.qprop(p, "sig"), "(unsigned)"),
            "signatureSuite", strOr(Js.qprop(p, "alg"), "ed25519"), "planRoot", strOr(Js.qprop(Js.qprop(p, "plan"), "root"), "(none)"), "paramsDigest", paramsDigest,
            "grantRef", grantRef, "counter", if (Js.isNum(counter)) counter else -1L, "cryptographicallyVerifiable", cryptoOk,
        )
        if (nonce is String) evidence["nonce"] = nonce

        val risk = LinkedHashMap<String, Any?>()
        if (Js.truthy(decision)) {
            val rt = Js.own(decision, "requiredThreshold")
            val kv = listOf("r" to Js.own(decision, "r"), "tier" to Js.qprop(rt, "t"), "proof" to Js.qprop(rt, "proof"), "budget" to Js.own(decision, "budget"))
            for ((k, v) in kv) if (v !== UNDEF) risk[k] = v
        }
        val word = when (outcome) { "allow" -> "ALLOWED"; "deny" -> "DENIED"; else -> "STEP-UP" }
        val narrative = "Agent " + Js.shortKey(Js.qprop(leaf, "holder"), 12) + " " + word + " to " + verb + " on " + resource + " (" + hops.size +
            "-hop chain rooted at principal " + Js.shortKey(Js.qprop(root, "issuer"), 12) + "; " +
            (if (cryptoOk) "cryptographically verifiable proof" else "proof not cryptographically verifiable") +
            (if (human != null && true == human["humanApproved"]) "; human-signed step-up" else "") + "). " + Js.tpl(reason)

        val holder = Js.qprop(leaf, "holder")
        val principal = Js.qprop(root, "issuer")
        val sess = Js.own(input, "session")
        val iat = Js.qprop(p, "iat")
        val exp = Js.qprop(p, "exp")
        val agent = obj("holder", strOr(holder, "(none)"))
        if (principal is String) agent["principal"] = principal
        agent["session"] = if (Js.nullish(sess)) grantRef else sess
        val event = obj(
            "schema", "atlas-pca/audit-event/v1", "recordedAt", Js.ts(now), "agent", agent,
            "delegation", obj("depth", Math.max(0, hops.size - 1).toLong(), "hops", hops),
            "action", obj(
                "verb", verb, "resource", resource, "paramsDigest", paramsDigest,
                "reversibilityClass", strOr(Js.qprop(action, "reversibility_class"), "(unknown)"), "summary", "$verb on $resource",
            ),
            "decision", obj("outcome", outcome, "reason", reason, "proofVerified", true == Js.own(verify, "allow"), "checks", checks),
            "risk", risk,
            "timestamps", obj("issuedAt", Js.ts(if (Js.isNum(iat)) iat else Double.NaN), "expiresAt", Js.ts(if (Js.isNum(exp)) exp else Double.NaN)),
            "evidence", evidence, "narrative", narrative,
        )
        if (human != null) event["humanOverride"] = human
        return event
    }

    // ---- control mappings ----

    private fun assertFramework(fw: Any?) {
        if (fw !is String || !COMPLIANCE_FRAMEWORKS.contains(fw)) {
            throw IllegalArgumentException("pca-compliance: unknown framework '" + Js.tpl(fw) + "' (have: " + COMPLIANCE_FRAMEWORKS.joinToString(", ") + ")")
        }
    }

    /** The whole control-mapping table. */
    @JvmStatic
    fun controlMappings(): List<Map<String, Any?>> = ArrayList(CONTROL_MAPPINGS)

    /** The control mappings of one framework (throws on an unknown framework). */
    @JvmStatic
    fun controlMappings(framework: Any?): List<Map<String, Any?>> {
        assertFramework(framework)
        return CONTROL_MAPPINGS.filter { it["framework"] == framework }
    }

    // ---- ComplianceReport ----

    private class Stats {
        var total = 0L
        var verifiable = 0L
        var denied = 0L
        var stepUp = 0L
        var allowed = 0L
        var humanOverrides = 0L
        var withChain = 0L
        var withPlanRoot = 0L
        var maxDepth: Any? = 0L
        var agents = 0
        var principals = 0
        var sampleDigest: Any? = UNDEF
    }

    private fun computeStats(events: List<Any?>): Stats {
        val agents = Js.JsSet()
        val principals = Js.JsSet()
        val s = Stats()
        for (e in events) {
            if (!Js.truthy(e)) continue
            if (Js.truthy(Js.prop(Js.prop(e, "evidence"), "cryptographicallyVerifiable"))) s.verifiable++
            when (Js.prop(Js.prop(e, "decision"), "outcome")) {
                "deny" -> s.denied++
                "step-up" -> s.stepUp++
                else -> s.allowed++
            }
            if (Js.truthy(Js.qprop(Js.own(e, "humanOverride"), "humanApproved"))) s.humanOverrides++
            val hl = Js.length(Js.prop(Js.prop(e, "delegation"), "hops"))
            if (hl !== UNDEF && (hl as Long) > 0) s.withChain++
            if ("(none)" != Js.prop(Js.prop(e, "evidence"), "planRoot")) s.withPlanRoot++
            val depth = Js.prop(Js.prop(e, "delegation"), "depth")
            if (Js.gt(depth, s.maxDepth)) s.maxDepth = depth
            agents.add(Js.prop(Js.prop(e, "agent"), "holder"))
            val principal = Js.prop(Js.prop(e, "agent"), "principal")
            if (principal !== UNDEF) principals.add(principal)
            val digest = Js.prop(Js.prop(e, "evidence"), "pcactnDigest")
            if (s.sampleDigest === UNDEF && "(undigestible)" != digest) s.sampleDigest = digest
        }
        s.total = events.size.toLong()
        s.agents = agents.size()
        s.principals = principals.size()
        return s
    }

    private class ControlEval(val status: String, val evidence: String, val findings: List<Any?>)

    private fun evaluateControl(id: String, s: Stats): ControlEval {
        val findings = ArrayList<Any?>()
        val digestNote = if (s.sampleDigest === UNDEF) "" else " (e.g. " + Js.shortKey(s.sampleDigest, 16) + ")"
        val t = s.total
        if (t == 0L) return ControlEval("not-evidenced", "no actions in the reporting period", arrayListOf<Any?>("no events supplied — nothing to evidence"))
        fun tri(n: Long) = if (n == t) "satisfied" else if (n > 0) "partial" else "not-evidenced"
        return when (id) {
            "eu-ai-act:art-12" -> {
                if (s.verifiable < t) findings.add((t - s.verifiable).toString() + " of " + t + " entries are not cryptographically verifiable")
                ControlEval(if (s.verifiable == t) "satisfied" else "partial", t.toString() + " actions logged; " + s.verifiable + "/" + t + " cite a cryptographically verifiable proof" + digestNote, findings)
            }
            "eu-ai-act:art-50" -> ControlEval("satisfied", t.toString() + " actions each disclose the acting agent, the principal (" + s.principals + " distinct) and the automated decision outcome", findings)
            "iso-42001:A.6.2.8" -> ControlEval("satisfied", t.toString() + " actions each carry a decision reason + risk/tier/budget reasoning trace", findings)
            "iso-42001:A.9.2" -> {
                if (s.withChain < t) findings.add((t - s.withChain).toString() + " entries have no delegation chain")
                ControlEval(
                    tri(s.withChain),
                    s.withChain.toString() + "/" + t + " actions carry an explicit delegation chain (max depth " + Js.tpl(s.maxDepth) + ", " + s.principals + " authorizing principal(s))",
                    findings,
                )
            }
            "iso-42001:A.9.3" -> when {
                s.humanOverrides > 0 -> ControlEval(
                    "satisfied",
                    s.humanOverrides.toString() + " step-up(s) approved by a signed human co-signature; " + s.stepUp + " step-up(s) and " + s.denied + " denial(s) show oversight enforced",
                    findings,
                )
                s.stepUp > 0 || s.denied > 0 -> {
                    findings.add("no human step-up co-signature was exercised in this period")
                    ControlEval(
                        "partial",
                        "oversight boundary enforced (" + s.stepUp + " step-up(s), " + s.denied + " denial(s)) but no signed human co-signature observed in the period",
                        findings,
                    )
                }
                else -> {
                    findings.add("no higher-impact action required human oversight in this period")
                    ControlEval("partial", "all actions were auto-admitted within policy; no oversight event was triggered in the period", findings)
                }
            }
            "iso-42001:A.6.2.2" -> {
                if (s.withPlanRoot < t) findings.add((t - s.withPlanRoot).toString() + " entries are not bound to a committed plan root")
                ControlEval(tri(s.withPlanRoot), s.withPlanRoot.toString() + "/" + t + " actions are bound to a committed plan root (intended-use binding)", findings)
            }
            "soc2:CC6.1" -> {
                if (s.denied > 0) findings.add(s.denied.toString() + " out-of-scope action(s) denied — access control actively enforced")
                ControlEval(
                    "satisfied",
                    "deny-by-default access over " + t + " actions (" + s.allowed + " allowed, " + s.stepUp + " step-up, " + s.denied + " denied); all gated by signed predicates + attenuation",
                    findings,
                )
            }
            "soc2:CC6.2" -> {
                if (s.withChain < t) findings.add((t - s.withChain).toString() + " entries are not traceable to an authorizing principal")
                ControlEval(tri(s.withChain), s.agents.toString() + " agent identit(ies) traceable to " + s.principals + " authorizing principal(s) via signed delegation chains", findings)
            }
            "soc2:CC6.3" -> {
                val narrowed = Js.toNumber(s.maxDepth) >= 1
                if (!narrowed && s.denied == 0L) findings.add("no attenuating hop or denial observed in the period")
                ControlEval(
                    if (narrowed || s.denied > 0) "satisfied" else "partial",
                    "access narrowed by attenuation (max delegation depth " + Js.tpl(s.maxDepth) + ") and " + s.denied + " denied action(s)",
                    findings,
                )
            }
            else -> ControlEval("not-evidenced", "no evaluator for this control", arrayListOf<Any?>("unmapped control"))
        }
    }

    /**
     * A structured ComplianceReport for `opts.framework` from AuditEvents: per-control status + evidence, the PCA-unique
     * assurances and a coverage summary. `opts.now` (epoch ms) defaults to the clock.
     */
    @JvmStatic
    fun toComplianceReport(events: Any?, opts: Any?): Map<String, Any?> {
        val framework = Js.prop(opts, "framework")
        assertFramework(framework)
        val list = ArrayList<Any?>()
        if (events is List<*>) for (e in events) if (Js.truthy(e)) list.add(e)
        var now = Js.own(opts, "now")
        if (Js.nullish(now)) now = Js.nowMs()
        val s = computeStats(list)
        val items = ArrayList<Any?>()
        var satisfied = 0L
        var partial = 0L
        var notEvidenced = 0L
        for (m in CONTROL_MAPPINGS) {
            if (m["framework"] != framework) continue
            val r = evaluateControl(m["controlId"] as String, s)
            items.add(obj(
                "controlId", m["controlId"], "controlTitle", m["controlTitle"], "clause", m["clause"], "framework", m["framework"], "status", r.status,
                "pcaEvidence", m["pcaEvidence"], "evidence", r.evidence, "findings", r.findings,
            ))
            when (r.status) {
                "satisfied" -> satisfied++
                "partial" -> partial++
                "not-evidenced" -> notEvidenced++
            }
        }
        val total = items.size.toLong()
        val fraction = if (total > 0) satisfied.toDouble() / total else 0.0
        val iats = ArrayList<Double>()
        for (e in list) {
            val x = Js.prop(Js.prop(Js.prop(e, "timestamps"), "issuedAt"), "epochMs")
            if (Js.finite(x)) iats.add(Js.num(x)!!)
        }
        var from: Any = 0L
        var to: Any = 0L
        if (iats.isNotEmpty()) {
            from = iats.minOrNull()!!
            to = iats.maxOrNull()!!
        }
        val st = s.total
        val assurances = obj(
            "cryptographicallyVerifiable", st > 0 && s.verifiable == st, "explicitDelegationChain", st > 0 && s.withChain == st,
            "signedHumanOverrides", s.humanOverrides > 0,
            "narrative", if (st == 0L) "No events in scope."
            else s.verifiable.toString() + "/" + st + " entries cite a cryptographically verifiable proof; " + s.withChain + "/" + st +
                " carry an explicit delegation chain; " + s.humanOverrides + " step-up(s) carry a signed human co-signature.",
        )
        val summary = framework.toString() + ": " + satisfied + "/" + total + " controls satisfied" + (if (partial > 0) ", $partial partial" else "") +
            (if (notEvidenced > 0) ", $notEvidenced not evidenced" else "") + " over " + st + " action(s)."
        return obj(
            "schema", "atlas-pca/compliance-report/v1", "framework", framework, "generatedAt", Js.ts(now), "period", obj("from", Js.ts(from), "to", Js.ts(to)),
            "eventCount", st, "assurances", assurances, "items", items,
            "coverage", obj(
                "total", total, "satisfied", satisfied, "partial", partial, "notEvidenced", notEvidenced, "satisfiedFraction", fraction,
                "satisfiedPercent", Js.round(fraction * 100).toLong(),
            ),
            "summary", summary,
        )
    }

    // ---- renderers ----

    /** The report as stable, pretty JSON (`JSON.stringify(report, null, 2)`). */
    @JvmStatic
    fun renderJson(report: Any?): String = Js.stringify(report, "", true)

    private fun upper(v: Any?): String {
        if (v !is String) throw IllegalStateException("toUpperCase is not a function")
        return v.uppercase(Locale.ROOT)
    }

    private fun glyph(status: Any?): String = when (status) {
        "satisfied" -> "✓"
        "partial" -> "◐"
        "not-evidenced" -> "·"
        else -> "undefined"
    }

    private fun walk(o: Any?, vararg path: String): Any? {
        var x = o
        for (k in path) x = Js.prop(x, k)
        return x
    }

    /** The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail). */
    @JvmStatic
    fun renderMarkdown(r: Any?): String {
        val l = ArrayList<String>()
        l.add("# PCA compliance evidence — " + Js.tpl(walk(r, "framework")))
        l.add("")
        l.add(
            "Generated " + Js.tpl(walk(r, "generatedAt", "iso")) + " · " + Js.tpl(walk(r, "eventCount")) + " action(s) · coverage: " +
                Js.tpl(walk(r, "coverage", "satisfied")) + "/" + Js.tpl(walk(r, "coverage", "total")) + " satisfied (" +
                Js.tpl(walk(r, "coverage", "satisfiedPercent")) + "%)",
        )
        if (Js.gt(walk(r, "eventCount"), 0L)) {
            l.add("")
            l.add("Reporting period: " + Js.tpl(walk(r, "period", "from", "iso")) + " → " + Js.tpl(walk(r, "period", "to", "iso")))
        }
        l.add("")
        l.add("## Why this trail is admissible (what PCA uniquely provides)")
        l.add("")
        l.add(
            "- **Cryptographically verifiable** — " + (if (Js.truthy(walk(r, "assurances", "cryptographicallyVerifiable"))) "YES" else "PARTIAL") +
                ": every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.",
        )
        l.add(
            "- **Explicit delegation chain** — " + (if (Js.truthy(walk(r, "assurances", "explicitDelegationChain"))) "YES" else "PARTIAL") +
                ": each action records who authorized what scope, hop by hop, rooted at a principal.",
        )
        l.add(
            "- **Signed human-overrides** — " + (if (Js.truthy(walk(r, "assurances", "signedHumanOverrides"))) "YES" else "none in period") +
                ": a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.",
        )
        l.add("")
        l.add("> " + Js.tpl(walk(r, "assurances", "narrative")))
        l.add("")
        l.add("## Coverage summary")
        l.add("")
        l.add("| Satisfied | Partial | Not evidenced | Total |")
        l.add("| --- | --- | --- | --- |")
        l.add(
            "| " + Js.tpl(walk(r, "coverage", "satisfied")) + " | " + Js.tpl(walk(r, "coverage", "partial")) + " | " +
                Js.tpl(walk(r, "coverage", "notEvidenced")) + " | " + Js.tpl(walk(r, "coverage", "total")) + " |",
        )
        l.add("")
        l.add("## Controls")
        l.add("")
        l.add("| Control | Clause | Status | Evidence in period |")
        l.add("| --- | --- | --- | --- |")
        val items = walk(r, "items") as? List<Any?> ?: throw IllegalStateException("items is not iterable")
        for (i in items) {
            l.add(
                "| " + Js.tpl(Js.prop(i, "controlTitle")) + " (`" + Js.tpl(Js.prop(i, "controlId")) + "`) | " + Js.tpl(Js.prop(i, "clause")) + " | " +
                    glyph(Js.prop(i, "status")) + " " + upper(Js.prop(i, "status")) + " | " + Js.tpl(Js.prop(i, "evidence")) + " |",
            )
        }
        l.add("")
        l.add("## Control detail")
        l.add("")
        for (i in items) {
            l.add("### " + Js.tpl(Js.prop(i, "controlId")) + " — " + Js.tpl(Js.prop(i, "controlTitle")))
            l.add("")
            l.add("- Clause: " + Js.tpl(Js.prop(i, "clause")))
            l.add("- Status: " + glyph(Js.prop(i, "status")) + " " + upper(Js.prop(i, "status")))
            l.add("- PCA evidence basis: " + Js.tpl(Js.prop(i, "pcaEvidence")))
            l.add("- Evidence in period: " + Js.tpl(Js.prop(i, "evidence")))
            val n = Js.length(Js.prop(i, "findings"))
            if (n !== UNDEF && (n as Long) > 0) {
                l.add("- Findings:")
                val fs = Js.prop(i, "findings")
                if (fs is List<*>) for (f in fs) l.add("  - " + Js.tpl(f))
                else for (c in fs as String) l.add("  - $c") // shortcut: iterates UTF-16 units (JS iterates code points); differs only for astral characters in a malformed string findings
            }
            l.add("")
        }
        l.add("---")
        l.add("")
        l.add("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._")
        return l.joinToString("\n")
    }

    // ---- framework report (console activity stream) ----

    private fun safetyBound(p: Any?): Double {
        val kappa = Js.prop(p, "kappa")
        val bMax = Js.prop(p, "bMax")
        if (!Js.gt(kappa, 0L)) return 0.0
        val b = Js.toNumber(bMax)
        return (if (b.isNaN()) Double.NaN else Math.max(0.0, b)) / Js.toNumber(kappa)
    }

    private fun baseSummary(input: Any?): LinkedHashMap<String, Any?> {
        val events = Js.prop(input, "events") as? List<Any?> ?: throw IllegalStateException("e.filter is not a function")
        val p = Js.prop(Js.prop(input, "policy"), "riskPolicy")
        val decisions = Js.qprop(input, "decisions")
        val dlen: Any? = if (Js.nullish(decisions)) 0L else Js.length(decisions)
        var taint = 0.0
        val agents = Js.JsSet()
        var auto = 0L
        var stepUp = 0L
        var denied = 0L
        for (x in events) {
            val t = Js.prop(x, "taint")
            val v = if (t === UNDEF) 0.0 else if (Js.finite(t)) Js.num(t)!! else Double.POSITIVE_INFINITY
            taint = Math.max(taint, v)
        }
        for (x in events) agents.add(Js.prop(x, "agent"))
        for (x in events) { val o = Js.prop(x, "outcome"); if ("auto" == o || "executed" == o) auto++ }
        for (x in events) if ("step_up" == Js.prop(x, "outcome")) stepUp++
        for (x in events) if ("deny" == Js.prop(x, "outcome")) denied++
        val autonomous = safetyBound(p) * Js.toNumber(Js.prop(p, "kappa"))
        return obj(
            "totalActions", events.size.toLong(), "autonomous", auto, "humanOverseen", stepUp + (if (dlen === UNDEF) 0L else dlen as Long), "denied", denied,
            "attributableAgents", agents.size().toLong(), "autonomousBound", autonomous, "maxTaintObserved", taint,
        )
    }

    /** A number as the JSON value JavaScript would hold (integers as longs, others as doubles). */
    private fun numVal(d: Double): Any = if (d == Math.rint(d) && Math.abs(d) < 9e15) d.toLong() else d

    private fun ctl(id: String, name: String, status: String, evidence: String): Map<String, Any?> = obj("id", id, "name", name, "status", status, "evidence", evidence)

    private fun lng(o: Any?): Long = o as Long

    private fun euAiAct(input: Any?, s: Map<String, Any?>): List<Any?> {
        val logged = lng(s["totalActions"]) > 0
        val bound = s["autonomousBound"] as Double
        val fin = !bound.isNaN() && !bound.isInfinite()
        val oversight = lng(s["humanOverseen"]) > 0 || fin
        val goal = Js.truthy(Js.own(input, "hasGoalCommitment"))
        val b = Js.numStr(bound)
        return arrayListOf<Any?>(
            ctl("art12-record-keeping", "Automatic logging of events", if (logged) "pass" else "warn", s["totalActions"].toString() + " attributable actions recorded"),
            ctl("art14-human-oversight", "Human oversight", if (oversight) "pass" else "warn", s["humanOverseen"].toString() + " human-reviewed actions; autonomous bound " + b),
            ctl("art15-robustness", "Bounded autonomy (accuracy/robustness)", if (fin) "pass" else "fail", "machine-checked safety bound = $b between human co-signs"),
            ctl(
                "art13-transparency", "Transparency / traceability", if (goal) "pass" else "warn",
                if (goal) "every action binds to a signed goal commitment (lineage)" else "no goal commitment supplied",
            ),
        )
    }

    private fun soc2(input: Any?, s: Map<String, Any?>): List<Any?> {
        val preds = Js.qprop(Js.own(input, "policy"), "predicates")
        val constrained = preds is List<*> && preds.isNotEmpty()
        val any = lng(s["totalActions"]) > 0
        return arrayListOf<Any?>(
            ctl(
                "cc6.1-access", "Logical access — least privilege", if (constrained) "pass" else "warn",
                if (constrained) "actions constrained by signed predicates + capability attenuation (deny by default)" else "the supplied policy lists no predicates",
            ),
            ctl("cc7.2-monitoring", "Monitoring of anomalies", if (any) "pass" else "warn", s["denied"].toString() + " denied + " + s["humanOverseen"] + " escalated actions captured"),
            ctl("cc7.3-audit-trail", "Audit trail", if (any) "pass" else "warn", s["totalActions"].toString() + " content-addressed actions across " + s["attributableAgents"] + " agents"),
            ctl(
                "cc8.1-change", "Change management (policy integrity)", if (constrained) "pass" else "warn",
                if (constrained) "policy is signed into the grant; tampering breaks verification" else "the supplied policy lists no predicates",
            ),
        )
    }

    private fun gdpr(input: Any?, s: Map<String, Any?>): List<Any?> {
        val goal = Js.truthy(Js.own(input, "hasGoalCommitment"))
        val erasure = Js.truthy(Js.own(input, "erasureSupported"))
        return arrayListOf<Any?>(
            ctl("art5-purpose", "Purpose limitation", if (goal) "pass" else "warn", if (goal) "actions bound to a committed goal/purpose" else "no goal commitment supplied"),
            ctl(
                "art5-minimization", "Data minimisation", if (lng(s["totalActions"]) > 0) "pass" else "warn",
                "taint-gated data flows; max taint observed = " + Js.numStr(s["maxTaintObserved"] as Double),
            ),
            ctl("art5-accountability", "Accountability", if (lng(s["attributableAgents"]) > 0) "pass" else "warn", s["attributableAgents"].toString() + " attributable agent identities"),
            ctl("art17-erasure", "Right to erasure", if (erasure) "pass" else "warn", if (erasure) "erasure path wired" else "erasure path not asserted"),
        )
    }

    /** A compliance evidence report for a framework from the console activity stream; an absent `now` defaults to the clock. */
    @JvmStatic
    fun frameworkReport(framework: Any?, input: Any?, now: Any?): Map<String, Any?> {
        val summary = baseSummary(input)
        if (framework !is String || !FRAMEWORK_IDS.contains(framework)) {
            throw IllegalArgumentException("frameworkReport: unknown framework '" + Js.tpl(framework) + "' (have: " + FRAMEWORK_IDS.joinToString(", ") + ")")
        }
        val controls = when (framework) {
            "eu-ai-act" -> euAiAct(input, summary)
            "soc2" -> soc2(input, summary)
            else -> gdpr(input, summary)
        }
        val events = Js.prop(input, "events") as List<Any?>
        val ats = ArrayList<Double>()
        for (e in events) { val a = Js.prop(e, "at"); if (Js.finite(a)) ats.add(Js.num(a)!!) }
        val lo = ats.minOrNull() ?: 0.0
        val hi = ats.maxOrNull() ?: 0.0
        val pass = controls.none { "fail" == (it as Map<String, Any?>)["status"] }
        // the bound and taint are numbers (possibly Infinity / NaN) as in the reference object; stringify writes those as null
        summary["autonomousBound"] = jsonNum(summary["autonomousBound"] as Double)
        summary["maxTaintObserved"] = jsonNum(summary["maxTaintObserved"] as Double)
        return obj(
            "framework", framework, "generatedAt", if (now === UNDEF) Js.nowMs() else now, "period", obj("from", jsonNum(lo), "to", jsonNum(hi)),
            "summary", summary, "controls", controls, "pass", pass,
        )
    }

    @JvmStatic
    fun frameworkReport(framework: Any?, input: Any?): Map<String, Any?> = frameworkReport(framework, input, UNDEF)

    private fun jsonNum(d: Double): Any? = if (d.isNaN() || d.isInfinite()) d else numVal(d)

    private fun dateIso(v: Any?): String {
        val x: Any? = if (v is Boolean) (if (v) 1L else 0L) else v
        if (!Js.isNum(x) && x != null) throw IllegalArgumentException("Invalid time value")
        return Js.isoString(x)
    }

    /** A short Markdown block of a framework report, for an audit package. */
    @JvmStatic
    fun frameworkReportToMarkdown(r: Any?): String {
        val summary = Js.prop(r, "summary")
        val controls = Js.prop(r, "controls") as? List<Any?> ?: throw IllegalStateException("r.controls.map is not a function")
        val l = arrayListOf(
            "# PCA compliance evidence — " + Js.tpl(Js.prop(r, "framework")), "",
            "Generated " + dateIso(Js.prop(r, "generatedAt")) + " · " + Js.tpl(Js.prop(summary, "totalActions")) + " actions · " +
                Js.tpl(Js.prop(summary, "attributableAgents")) + " agents · overall: " + (if (Js.truthy(Js.prop(r, "pass"))) "PASS" else "FAIL"),
            "", "| Control | Status | Evidence |", "| --- | --- | --- |",
        )
        for (c in controls) {
            l.add("| " + Js.tpl(Js.prop(c, "name")) + " (" + Js.tpl(Js.prop(c, "id")) + ") | " + upper(Js.prop(c, "status")) + " | " + Js.tpl(Js.prop(c, "evidence")) + " |")
        }
        l.add("")
        l.add("_Evidence mapping, not a legal certification._")
        return l.joinToString("\n")
    }
}
