package net.atlasauth.pca.explain

import java.util.Locale
import java.util.regex.Pattern
import net.atlasauth.pca.explain.ExplainJs.UNDEF
import net.atlasauth.pca.explain.ExplainJs.get
import net.atlasauth.pca.explain.ExplainJs.nn
import net.atlasauth.pca.explain.ExplainJs.obj
import net.atlasauth.pca.explain.ExplainJs.opt
import net.atlasauth.pca.explain.ExplainJs.put
import net.atlasauth.pca.explain.ExplainJs.rd
import net.atlasauth.pca.explain.ExplainJs.str
import net.atlasauth.pca.explain.ExplainJs.truthy
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates

/**
 * Make PCA decisions self-explaining: the verifier's per-check result, the Policy VM decision and a delegation chain become
 * precise, human-readable explanations. Pure and read-only; a malformed input degrades to a best-effort explanation.
 * Explanations are JSON trees (maps) with the members of the reference explanation classes; the `*ToText` functions render
 * them. Shortcuts: statuses/reasons/caveat lists are expected to be arrays of scalars; a null envelope counts as absent.
 */
@Suppress("UNCHECKED_CAST")
object Explain {
    const val MAX_TEXT = 400
    const val PCACTN_VERSION = 2L
    const val PCACTN_MAX_LIFETIME_MS = 3_600_000L
    const val PCACTN_MAX_SKEW_MS = 60_000L

    @JvmField
    val VERIFY_CHECK_ORDER: List<String> = listOf(
        "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format",
    )

    private val CHECK_TITLE: Map<String, String> = linkedMapOf(
        "wire" to "wire format", "version" to "version", "audience" to "audience binding", "validity" to "freshness window",
        "cap_chain" to "capability chain", "grant_ref_bound" to "grant reference binding", "plan_inclusion" to "plan inclusion",
        "leaf_signature" to "leaf signature", "counter_format" to "counter format", "counter" to "counter format", "replay" to "replay",
        "plan_root_authorized" to "plan-root authorization", "taint_gate" to "taint gate", "attestation" to "agent attestation",
        "threshold" to "threshold signature", "revocation" to "revocation", "zk_compliance" to "zk compliance", "bond" to "bond",
        "malformed" to "structure",
    )

    // ---- cleanText ----------------------------------------------------------------------------------------------------------

    private const val W = "A-Za-z0-9_"
    private const val NB = "(?<![$W])" // JavaScript \b before a word character
    private val RE_JWT = Pattern.compile("${NB}eyJ[$W-]{5,}\\.[$W-]{5,}\\.[$W-]*")
    private val RE_BEARER = Pattern.compile("$NB(Bearer|Basic|Token)[${ExplainJs.WS}]+[$W.~+/=-]{6,}", Pattern.CASE_INSENSITIVE)
    private val RE_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*://)[^${ExplainJs.WS}/@]*:[^${ExplainJs.WS}/@]*@", Pattern.CASE_INSENSITIVE)
    private val RE_PAIR = Pattern.compile(
        "$NB((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|authorization|auth)[\"']?[" +
            ExplainJs.WS + "]*[:=][" + ExplainJs.WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + ExplainJs.WS + "\"'&,;]+)",
        Pattern.CASE_INSENSITIVE,
    )
    private val RE_RUN = Pattern.compile("[$W-]{40,}")

    /**
     * Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
     * `token=` style pairs, long unbroken token runs); output is cut to 400 characters. A net, not a proof.
     */
    @JvmStatic
    fun cleanText(text: Any?): String {
        var t = str(text)
        t = RE_JWT.matcher(t).replaceAll("[redacted]")
        t = RE_BEARER.matcher(t).replaceAll("$1 [redacted]")
        t = RE_USERINFO.matcher(t).replaceAll("$1[redacted]@")
        t = RE_PAIR.matcher(t).replaceAll("$1[redacted]")
        t = RE_RUN.matcher(t).replaceAll("[redacted]")
        return if (t.length > MAX_TEXT) t.substring(0, MAX_TEXT) + "..." else t
    }

    // ---- shared helpers -----------------------------------------------------------------------------------------------------

    private fun s(v: Any?): String = str(v)

    private fun shorten(key: Any?, n: Int = 10): String {
        if (key !is String || key.isEmpty()) return "<none>"
        return if (key.length <= n + 1) key else key.substring(0, n) + "…"
    }

    /** Compact number: integers stay integers, fractions round to 4 dp. Anything else prints as String(x). */
    internal fun num(x: Any?): String {
        val d = ExplainJs.numOf(x)
        if (d == null || d.isNaN() || d.isInfinite()) return str(x)
        if (d == Math.rint(d)) return ExplainJs.numString(d)
        return ExplainJs.numString(ExplainJs.round(d * 1e4) / 1e4)
    }

    private fun valueSummary(rest: Map<String, Any?>): String {
        val parts = ArrayList<String>()
        for (k in ExplainJs.keys(rest).take(6)) {
            val v = rest[k]
            parts.add(k + "=" + (if (v is Map<*, *> || v is List<*>) ExplainJs.stringify(v) else num(v)))
        }
        return parts.joinToString(", ")
    }

    private fun typeOf(cv: Any?): String = opt(cv, "type") as? String ?: "<malformed>"

    /** The caveat's non-`type` members (insertion order, array-index keys first). */
    private fun caveatRest(cv: Any?): LinkedHashMap<String, Any?> {
        val rest = obj()
        if (cv is Map<*, *> || cv is List<*>) for (k in ExplainJs.keys(cv)) if (k != "type") rest[k] = get(cv, k)
        return rest
    }

    private fun condToText(c: Any?, depth: Int): String {
        if (!(c is Map<*, *> || c is List<*>)) return "<malformed>"
        if (depth > 6) return "…"
        if (c is Map<*, *>) {
            val all = c["all_of"]
            if (c.containsKey("all_of") && all is List<*>) return "(" + joinConds(all, " AND ", depth) + ")"
            val any = c["any_of"]
            if (c.containsKey("any_of") && any is List<*>) return "(" + joinConds(any, " OR ", depth) + ")"
            if (c.containsKey("not")) return "NOT " + condToText(c["not"], depth + 1)
        }
        val ref = get(c, "ref")
        val operand = when {
            ref !== UNDEF -> "→" + s(ref)
            c is Map<*, *> && c.containsKey("value") -> num(get(c, "value"))
            else -> ""
        }
        return ExplainJs.jsTrim(s(get(c, "field")) + " " + s(get(c, "op")) + " " + operand)
    }

    private fun joinConds(l: List<*>, sep: String, depth: Int): String = l.joinToString(sep) { condToText(it, depth + 1) }

    private fun whereSummary(where: Any?): String {
        if (where !is List<*> || where.isEmpty()) return "any (no where-bound)"
        return where.joinToString(" AND ") { condToText(it, 0) }
    }

    private fun padEnd(s: String, n: Int): String = s.padEnd(n, ' ')

    private fun mapOrEmpty(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: LinkedHashMap()

    private fun len(o: Any?): Int = when (o) {
        is List<*> -> o.size
        is String -> o.length
        else -> -1
    }

    // =========================================================================================================================
    // explainVerification
    // =========================================================================================================================

    private class Pin(val detail: String, val remedy: String, val hop: Int?)

    private fun reasonTail(name: String, verifyResult: Any?): String? {
        val r = get(verifyResult, "reason") as? String ?: return null
        val pre = "$name: "
        return if (r.startsWith(pre)) r.substring(pre.length) else null
    }

    private fun validityPinpoint(p: Any?, now: Any?): Array<String> {
        val exp = get(p, "exp")
        val iat = get(p, "iat")
        val lifetime = ExplainJs.toNum(exp) - ExplainJs.toNum(iat)
        if (!ExplainJs.gt(exp, iat)) {
            return arrayOf("exp " + s(exp) + " ≤ iat " + s(iat) + ": empty validity window", "set exp strictly greater than iat.")
        }
        if (lifetime > PCACTN_MAX_LIFETIME_MS) {
            return arrayOf(
                "lifetime " + ExplainJs.numString(lifetime) + "ms exceeds the " + PCACTN_MAX_LIFETIME_MS + "ms maximum",
                "shorten the window to ≤ " + PCACTN_MAX_LIFETIME_MS + "ms (buildPCActn ttlMs).",
            )
        }
        if (now !== UNDEF) {
            val nowN = ExplainJs.toNum(now)
            val iatN = ExplainJs.toNum(iat)
            val expN = ExplainJs.toNum(exp)
            if (!(iatN <= nowN + PCACTN_MAX_SKEW_MS)) {
                return arrayOf(
                    "iat " + s(iat) + " is " + ExplainJs.numString(iatN - nowN) + "ms in the future (> " + PCACTN_MAX_SKEW_MS + "ms clock-skew allowance)",
                    "fix the signer clock; do not pre-date actions.",
                )
            }
            if (!(nowN <= expN)) {
                return arrayOf(
                    "expired " + ExplainJs.numString(nowN - expN) + "ms ago (exp " + s(exp) + ", now " + s(now) + ")",
                    "build a fresh action — a PCActn lifetime is short by design.",
                )
            }
        }
        return arrayOf("validity window invalid", "build a fresh action with a valid iat/exp window.")
    }

    private val HOP = Pattern.compile("hop (\\d+)")

    private fun capChainPinpoint(p: Any?): Pin {
        val chain = get(p, "cap_chain")
        val reason = if (chain !is List<*>) "cap_chain is not an array"
        else {
            val r = Pca.verifyChain(chain as List<Any?>, "", false)
            if (r.isEmpty()) "chain root is not the grant this verifier expects" else r
        }
        var hop: Int? = null
        val mm = HOP.matcher(reason)
        if (mm.find()) hop = Integer.valueOf(mm.group(1))
        val remedy = when {
            reason.contains("root issuer") || reason.contains("not the grant") -> "root the chain at the principal key that minted the grant."
            reason.contains("widens") -> "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation."
            reason.contains("caveat") -> "attenuation is append-only: never drop, reorder or edit a parent caveat."
            reason.contains("signature") -> "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite)."
            else -> "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats."
        }
        return Pin(reason, remedy, hop)
    }

    private fun leafSigPinpoint(p: Any?): Pin {
        val chain = get(p, "cap_chain")
        val idx = if (chain is List<*>) chain.size - 1 else -1
        val leaf = if (idx >= 0) (chain as List<*>)[idx] else UNDEF
        val alg = nn(get(p, "alg"), "ed25519")
        val remedy = "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder."
        if (!truthy(leaf)) return Pin("no leaf capability to check the signature against (empty/invalid chain)", remedy, null)
        return Pin(
            "leaf hop #" + idx + " signature (holder " + shorten(get(leaf, "holder")) + ", suite " + s(alg) + ") does not verify",
            remedy, if (idx >= 0) idx else null,
        )
    }

    /** The decisive failing check: detail, remedy and the failing hop (when known). */
    private fun pinpoint(name: String, p: Any?, verifyResult: Any?, now: Any?): Pin {
        val tail = reasonTail(name, verifyResult)
        val action = opt(p, "action")
        val plan = opt(p, "plan")
        return when (name) {
            "wire" -> Pin(tail ?: "wire structure / strict-canonical-form check failed", "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.", null)
            "version" -> Pin(
                tail ?: "unsupported ver " + num(get(p, "ver")) + " (verifier requires " + PCACTN_VERSION + ")",
                "re-mint the action at wire version $PCACTN_VERSION.", null,
            )
            "audience" -> Pin(
                tail ?: "aud " + ExplainJs.jstr(get(p, "aud")) + " does not match this resource server / instance",
                "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).", null,
            )
            "validity" -> {
                val v = validityPinpoint(p, now)
                Pin(tail ?: v[0], v[1], null)
            }
            "cap_chain" -> {
                val c = capChainPinpoint(p)
                Pin(tail ?: c.detail, c.remedy, c.hop)
            }
            "grant_ref_bound" -> Pin(
                tail ?: "grant_ref " + shorten(get(p, "grant_ref")) + " is not the id of the root capability in cap_chain",
                "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.", null,
            )
            "plan_inclusion" -> Pin(
                tail ?: "action (verb " + ExplainJs.jstr(opt(action, "verb")) + " on " + ExplainJs.jstr(opt(action, "resource")) + ") is not node " +
                    ExplainJs.jstr(opt(plan, "node_id")) + " of committed plan " + shorten(opt(plan, "root")),
                "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).", null,
            )
            "leaf_signature" -> {
                val l = leafSigPinpoint(p)
                Pin(tail ?: l.detail, l.remedy, l.hop)
            }
            "counter", "counter_format" -> Pin(
                tail ?: "counter " + num(get(p, "counter")) + " is missing or not a non-negative safe integer",
                "use a strictly increasing per-holder counter; a repeated counter is a replay.", null,
            )
            "malformed" -> Pin(tail ?: "the PCActn is structurally malformed", "rebuild the action with the SDK; do not construct the wire object by hand.", null)
            else -> Pin(tail ?: "$name check failed", "satisfy the $name requirement (supply the corresponding verifier hook / proof).", null)
        }
    }

    private fun passDetail(name: String, p: Any?): String = when (name) {
        "wire" -> "wire structure + strict canonical form valid"
        "version" -> "ver " + num(get(p, "ver")) + " supported"
        "audience" -> "aud " + ExplainJs.jstr(get(p, "aud")) + " matches this resource server"
        "validity" -> "fresh: iat/exp window valid (lifetime " + num((ExplainJs.toNum(get(p, "exp")) - ExplainJs.toNum(get(p, "iat"))) / 1000) + "s)"
        "cap_chain" -> {
            val chain = get(p, "cap_chain")
            val n = if (chain is List<*>) chain.size else 0
            val root = if (chain is List<*> && n > 0) chain[0] else UNDEF
            n.toString() + "-hop chain verifies; root issuer " + shorten(opt(root, "issuer"))
        }
        "grant_ref_bound" -> "grant_ref " + shorten(get(p, "grant_ref")) + " is the id of the chain root"
        "plan_inclusion" -> {
            val plan = opt(p, "plan")
            "action is node " + ExplainJs.jstr(opt(plan, "node_id")) + " of committed plan " + shorten(opt(plan, "root"))
        }
        "leaf_signature" -> {
            val chain = get(p, "cap_chain")
            val leaf = if (chain is List<*> && chain.isNotEmpty()) chain[chain.size - 1] else UNDEF
            "leaf holder " + shorten(opt(leaf, "holder")) + " signature valid (suite " + s(nn(get(p, "alg"), "ed25519")) + ")"
        }
        "counter", "counter_format" -> "counter " + num(get(p, "counter")) + " well-formed"
        else -> "ok"
    }

    private fun cleanCheck(c: Map<String, Any?>): LinkedHashMap<String, Any?> =
        LinkedHashMap(c).also { it["detail"] = cleanText(c["detail"]) }

    private fun verificationResult(
        verdict: String, allow: Boolean, checks: List<Map<String, Any?>>, decisive: Map<String, Any?>?, summary: String,
    ): LinkedHashMap<String, Any?> {
        val out = obj()
        out["kind"] = "verification"
        out["verdict"] = verdict
        out["allow"] = allow
        out["checks"] = ArrayList<Any?>(checks)
        val passed = ArrayList<Any?>()
        val failed = ArrayList<Any?>()
        val notEnforced = ArrayList<Any?>()
        for (c in checks) {
            when (c["status"]) {
                "pass" -> passed.add(c["name"])
                "fail" -> failed.add(c["name"])
                "not-enforced" -> notEnforced.add(c["name"])
            }
        }
        out["passed"] = passed
        out["failed"] = failed
        out["notEnforced"] = notEnforced
        if (decisive != null) out["decisive"] = decisive
        out["summary"] = summary
        return out
    }

    private fun deniedVerification(why: String): LinkedHashMap<String, Any?> {
        val e = obj()
        e["name"] = "malformed"
        e["status"] = "fail"
        e["title"] = CHECK_TITLE["malformed"]
        e["detail"] = why
        e["remedy"] = "pass the PCActn and the verifier result you verified."
        e["decisive"] = true
        return verificationResult("deny", false, listOf(e), e, "Denied: $why")
    }

    /**
     * Explain the offline verification of a PCActn: walk the normative checks in order; for each PASS summarize what held and
     * for the FIRST failing check pinpoint it with a concrete remedy. `opts.now` (epoch ms) refines the validity pinpoint.
     */
    @JvmStatic
    fun explainVerification(pcActn: Any?, verifyResult: Any?, opts: Any?): Map<String, Any?> {
        if (!ExplainJs.isObject(pcActn) || !ExplainJs.isObject(verifyResult)) return deniedVerification("the PCActn or the verifier result is missing")
        return try {
            explainVerificationInner(pcActn, verifyResult, opts)
        } catch (e: RuntimeException) {
            deniedVerification("the PCActn or the verifier result is malformed")
        } catch (e: StackOverflowError) {
            deniedVerification("the PCActn or the verifier result is malformed")
        }
    }

    private fun explainVerificationInner(p: Any?, vr: Any?, opts: Any?): Map<String, Any?> {
        val statuses = nn(get(vr, "checks"), LinkedHashMap<String, Any?>())
        val ordered = ArrayList(VERIFY_CHECK_ORDER)
        val seen = HashSet(VERIFY_CHECK_ORDER)
        for (n in ExplainJs.keys(statuses)) if (!seen.contains(n)) ordered.add(n)

        val decisiveName = ordered.firstOrNull { "fail" == get(statuses, it) }

        val checks = ArrayList<Map<String, Any?>>()
        var decisive: Map<String, Any?>? = null
        for (name in ordered) {
            val status = nn(get(statuses, name), "skipped")
            val title = CHECK_TITLE[name] ?: name
            var remedy: String? = null
            var hop: Int? = null
            val detail = when (status) {
                "fail" -> {
                    val pin = pinpoint(name, p, vr, rd(opts, "now"))
                    remedy = pin.remedy
                    hop = pin.hop
                    pin.detail
                }
                "pass" -> passDetail(name, p)
                "not-enforced" -> "not enforced by this verifier (no hook / opt-out)"
                "unsupported" -> "the PCActn carries a feature this verifier does not implement (never a pass)"
                else -> "not reached (a terminal earlier check stopped evaluation)"
            }
            val entry = obj()
            entry["name"] = name
            entry["status"] = status
            entry["title"] = title
            entry["detail"] = detail
            if (remedy != null) entry["remedy"] = remedy
            if (hop != null) entry["hop"] = ExplainJs.n(hop.toLong())
            if (name == decisiveName) { entry["decisive"] = true; decisive = entry }
            checks.add(entry)
        }

        val hasChecks = get(vr, "checks") is Map<*, *>
        val claimedAllow = true == get(vr, "allow") && hasChecks
        val contradicted = claimedAllow && decisiveName != null
        val verdict = if (claimedAllow && !contradicted) "allow" else "deny"
        val dec = decisive
        val summary = when {
            verdict == "allow" -> "All " + checks.count { "pass" == it["status"] } + " evaluated checks passed (no check failed)."
            true == get(vr, "allow") && !hasChecks ->
                "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial)."
            contradicted ->
                "Denied: the verifier result says allow but the \"" + (if (dec != null) s(dec["title"]) else decisiveName) +
                    "\" check failed (inconsistent result, treated as a denial)."
            dec != null -> "Denied at the \"" + s(dec["title"]) + "\" check: " + s(dec["detail"])
            else -> "Denied: " + (get(vr, "reason") as? String ?: "a check failed")
        }
        return verificationResult(verdict, verdict == "allow", checks.map { cleanCheck(it) }, dec?.let { cleanCheck(it) }, cleanText(summary))
    }

    private val GLYPH = mapOf("pass" to "✓", "fail" to "✗", "not-enforced" to "·", "unsupported" to "?", "skipped" to "–")

    /** Render a verification explanation. */
    @JvmStatic
    fun verificationToText(e: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        lines.add("PCA verification — " + s(e["verdict"]).uppercase(Locale.ROOT))
        lines.add(s(e["summary"]))
        lines.add("")
        for (co in e["checks"] as List<*>) {
            val c = co as Map<*, *>
            val mark = if (truthy(c["decisive"])) " ◀ DECISIVE" else ""
            val st = c["status"]
            val glyph = (st as? String)?.let { GLYPH[it] } ?: "undefined"
            lines.add("  " + glyph + " " + padEnd(s(c["name"]), 16) + " " + s(c["detail"]) + mark)
            if (truthy(c["decisive"]) && truthy(c["remedy"])) lines.add("      ↳ fix: " + s(c["remedy"]))
        }
        return lines.joinToString("\n")
    }

    // =========================================================================================================================
    // explainDecision
    // =========================================================================================================================

    private fun g(m: Map<String, Any?>, k: String): Any? = if (m.containsKey(k)) m[k] else UNDEF

    private fun caveatRemedy(type: String, rest: Map<String, Any?>): String = when (type) {
        "expires" -> "the grant expired at " + num(g(rest, "at")) + " (epoch ms); obtain a fresh grant or re-mint with a later 'expires'."
        "not_before" -> "the grant is not valid until " + num(g(rest, "at")) + " (epoch ms); retry after that time."
        "rate" -> "rate limit " + num(g(rest, "max")) + "/" + num(g(rest, "per_secs")) + "s reached; wait for the window to clear or raise the 'rate' caveat."
        "max_blast_radius" -> "the action's blast radius exceeds the caveat max " + num(g(rest, "max")) + "; narrow the action or raise 'max_blast_radius'."
        "reversibility_max" -> "the action is more severe than the allowed class '" + s(g(rest, "class")) + "'; only that class or lower is permitted."
        "delegation_depth" -> "delegation depth exceeds max " + num(g(rest, "max")) + "; act from a shallower hop or raise 'delegation_depth'."
        else -> "caveat '$type' is not satisfied; check its parameters against the action/context."
    }

    private fun caveatDetail(type: String, rest: Map<String, Any?>, satisfied: Any?): String {
        val bound = valueSummary(rest)
        val verb = if (truthy(satisfied)) "held" else "NARROWED/DENIED"
        return if (bound.isNotEmpty()) "$type($bound) $verb" else "$type $verb"
    }

    private val FAILED_CAVEATS = Pattern.compile("caveat\\(s\\) not satisfied: ([^\\n\\r\\u2028\\u2029]+)\\z")

    private fun failedCaveatTypesFromReasons(reasons: List<Any?>): Set<String> {
        val out = HashSet<String>()
        for (r in reasons) {
            val mm = FAILED_CAVEATS.matcher(str(r))
            if (mm.find()) for (t in mm.group(1).split(",")) { val tt = ExplainJs.jsTrim(t); if (tt.isNotEmpty()) out.add(tt) }
        }
        return out
    }

    private fun riskBand(r: Any?, theta1: Any?, theta2: Any?, tier: Any?): String {
        if (theta1 === UNDEF || theta2 === UNDEF) return "effective tier t=" + s(tier)
        val rn = ExplainJs.toNum(r)
        if (rn <= ExplainJs.toNum(theta1)) return "r " + num(r) + " ≤ θ1 " + num(theta1) + " → claim band (t=1)"
        if (rn <= ExplainJs.toNum(theta2)) return "θ1 " + num(theta1) + " < r " + num(r) + " ≤ θ2 " + num(theta2) + " → standard band (t=2)"
        return "r " + num(r) + " > θ2 " + num(theta2) + " → strong band (t=3)"
    }

    private fun noDecision(reason: String): Map<String, Any?> {
        val d = obj()
        d["admit"] = false
        d["needStepUp"] = false
        d["releaseGuardianShare"] = false
        d["r"] = ExplainJs.n(1)
        d["requiredThreshold"] = linkedMapOf<String, Any?>("t" to ExplainJs.n(3), "proof" to "human", "optimisticAllowed" to false)
        d["budget"] = linkedMapOf<String, Any?>("B" to ExplainJs.n(0), "tau" to ExplainJs.n(0), "asOf" to ExplainJs.n(0))
        d["reasons"] = arrayListOf<Any?>(reason)
        return d
    }

    /**
     * Explain a Policy-VM decision: which predicate granted the action, which caveat narrowed or denied it, the risk band and
     * the admission path. `opts` may carry `envelope` and `context` ({action, caveat, chain}).
     */
    @JvmStatic
    fun explainDecision(pcActn: Any?, decision: Any?, opts: Any?): Map<String, Any?> {
        if (!(decision is Map<*, *> || decision is List<*>) || !ExplainJs.isObject(get(decision, "requiredThreshold"))) {
            return explainDecisionInner(noDecision("no policy decision supplied (default-deny)"), opts)
        }
        return try {
            explainDecisionInner(decision, opts)
        } catch (e: RuntimeException) {
            explainDecisionInner(noDecision("the policy decision could not be explained (default-deny)"), LinkedHashMap<String, Any?>())
        } catch (e: StackOverflowError) {
            explainDecisionInner(noDecision("the policy decision could not be explained (default-deny)"), LinkedHashMap<String, Any?>())
        }
    }

    private class PredResult(val allowed: Boolean, val value: Any?, val index: Int?)

    private fun explainDecisionInner(decision: Any?, opts: Any?): Map<String, Any?> {
        val envO = rd(opts, "envelope")
        val env = envO ?: UNDEF
        val ctx = nn(get(opts, "context"), LinkedHashMap<String, Any?>())
        val reasons = ArrayList<Any?>()
        val reasonsRaw = get(decision, "reasons")
        if (reasonsRaw is List<*>) reasons.addAll(reasonsRaw)

        val admitted = true == get(decision, "admit")
        val rgs = get(decision, "releaseGuardianShare")
        val disposition = if (admitted) "auto-admit" else if (true == rgs) "step-up" else "denied"
        val verdict = if (admitted) "allow" else "deny"

        val grant = obj()
        put(grant, "granted", rgs)
        val chain = get(ctx, "chain")
        val rootCap = opt(chain, "0")
        if (truthy(rootCap)) put(grant, "capabilityId", get(rootCap, "id"))
        val ctxAction = get(ctx, "action")
        val ctxCaveat = get(ctx, "caveat")
        if (truthy(env) && truthy(ctxAction)) {
            val pr = evalPredicates(rd(env, "predicates"), ctxAction)
            if (pr.allowed) {
                grant["granted"] = true
                grant["predicate"] = pr.value
                grant["predicateIndex"] = ExplainJs.n(pr.index!!.toLong())
                grant["where"] = whereSummary(get(pr.value, "where"))
            } else {
                grant["granted"] = false
                grant["reason"] = pr.value ?: "no predicate permits this action"
            }
        } else if (!truthy(rgs)) {
            for (r in reasons) {
                val rs = strictStr(r)
                if (rs.contains("predicate") || rs.contains("not permitted")) { grant["reason"] = rs; break }
            }
        }

        val caveats = ArrayList<Map<String, Any?>>()
        val failedFromReasons = failedCaveatTypesFromReasons(reasons)
        val canEval = env !== UNDEF && ctxCaveat !== UNDEF && ctxAction !== UNDEF

        val grantCaveats = nn(opt(env, "caveats"), ArrayList<Any?>())
        // for-of: a string iterates its code points (each a malformed caveat), any other non-array is not iterable
        val grantCaveatsList: List<*> = if (grantCaveats is String) grantCaveats.codePoints().toArray().map { String(Character.toChars(it)) }
            else grantCaveats as? List<*> ?: throw IllegalArgumentException("TypeError: not iterable")
        val chain0 = opt(chain, "0")
        var rootCount = 0
        if (chain0 !== UNDEF && chain0 != null) {
            val cv0 = rd(chain0, "caveats")
            if (cv0 === UNDEF || cv0 == null) throw IllegalArgumentException("TypeError: caveats.length")
            rootCount = Math.max(0, len(cv0))
        }
        val delegated = ArrayList<Any?>()
        if (chain is List<*> && chain.size > 1) {
            val leaf = chain[chain.size - 1]
            val lc = nn(opt(leaf, "caveats"), ArrayList<Any?>())
            if (lc !is List<*>) throw IllegalArgumentException("TypeError: slice")
            if (rootCount < lc.size) delegated.addAll(lc.subList(rootCount, lc.size))
        }
        for (cv in grantCaveatsList) caveats.add(classify(cv, false, canEval, ctxCaveat, ctxAction, failedFromReasons, rgs))
        for (cv in delegated) caveats.add(classify(cv, true, canEval, ctxCaveat, ctxAction, failedFromReasons, rgs))

        val rt = get(decision, "requiredThreshold")
        val r = get(decision, "r")
        var riskPolicy: Any? = UNDEF
        if (env !== UNDEF) {
            riskPolicy = rd(env, "risk_policy")
            if (riskPolicy === UNDEF || riskPolicy == null) throw IllegalArgumentException("TypeError: risk_policy is undefined")
        }
        val theta1 = opt(riskPolicy, "theta1")
        val theta2 = opt(riskPolicy, "theta2")
        val tier = get(rt, "t")
        val proof = get(rt, "proof")
        val optimistic = get(rt, "optimisticAllowed")
        val risk = obj()
        put(risk, "r", r)
        put(risk, "tier", tier)
        put(risk, "proof", proof)
        put(risk, "optimisticAllowed", optimistic)
        risk["band"] = riskBand(r, theta1, theta2, tier)
        if (env !== UNDEF) {
            put(risk, "theta1", theta1)
            put(risk, "theta2", theta2)
        }

        val kappa = if (env === UNDEF) UNDEF else get(riskPolicy, "kappa")
        val costVal: Double? = if (kappa !== UNDEF) cost(r, kappa) else null
        var budgetDepleted = false
        for (rr in reasons) if (strictStr(rr).contains("budget depleted")) { budgetDepleted = true; break }
        val path = when {
            admitted -> "auto-admitted at t=" + s(tier) + " (" + s(proof) + "); metered"
            !truthy(rgs) -> "guardian share withheld — policy not satisfied (no autonomous or guardian path)"
            budgetDepleted -> "trust budget cannot cover the cost — step-up to t=3 (human recharge) required"
            else -> "step-up to t=" + s(tier) + " (" + s(proof) + ") co-signature required"
        }
        val admission = obj()
        admission["admit"] = admitted
        put(admission, "needStepUp", get(decision, "needStepUp"))
        put(admission, "releaseGuardianShare", rgs)
        put(admission, "budget", get(decision, "budget"))
        admission["path"] = path
        if (costVal != null) admission["cost"] = costVal
        if (kappa !== UNDEF) put(admission, "kappa", kappa)

        var decisive: LinkedHashMap<String, Any?>? = null
        if (!admitted) {
            val d = obj()
            decisive = d
            if (!truthy(grant["granted"])) {
                d["reason"] = grant["reason"] ?: "action not permitted by the envelope predicates (default-deny)"
                d["remedy"] = "grant a predicate that permits this verb+resource (and satisfies its where bound)."
            } else {
                val firstFailed = caveats.firstOrNull { !truthy(it["satisfied"]) }
                if (firstFailed != null) {
                    d["reason"] = "caveat '" + firstFailed["type"] + "' narrowed the authority away: " + firstFailed["detail"]
                    if (truthy(firstFailed["remedy"])) d["remedy"] = firstFailed["remedy"]
                } else if (budgetDepleted) {
                    d["reason"] = "risk " + num(r) + " is admissible but the trust budget cannot cover cost κ·r" + (if (costVal != null) "=" + num(costVal) else "")
                    d["remedy"] = "recharge the budget with a human co-sign, or lower the action risk."
                } else {
                    d["reason"] = "risk " + num(r) + " exceeds the auto threshold → step-up to t=" + s(tier) + " (" + s(proof) + ")"
                    d["remedy"] = if (ExplainJs.numOf(tier) == 3.0) "obtain a human step-up co-signature." else "obtain the guardian/principal co-signature for this tier."
                }
            }
        }

        val summary = when {
            admitted -> "Auto-admitted: " + (if (truthy(grant["predicate"])) "predicate #" + s(grant["predicateIndex"]) else "policy") +
                " grants it, all caveats held, risk r=" + num(r) + " is in the t=" + s(tier) + " band and the budget covers it."
            decisive != null -> (if ("deny" == verdict && "denied" == disposition) "Denied" else "Needs step-up") + ": " + s(decisive["reason"])
            else -> "Not auto-admitted (t=" + s(tier) + ")."
        }

        val cleanedCaveats = caveats.map { c -> LinkedHashMap(c).also { it["detail"] = cleanText(c["detail"]) } }
        val cleanedDecisive = decisive?.let { d -> LinkedHashMap(d).also { it["reason"] = cleanText(d["reason"]) } }

        val out = obj()
        out["kind"] = "decision"
        out["verdict"] = verdict
        out["disposition"] = disposition
        out["grant"] = grant
        out["caveats"] = ArrayList<Any?>(cleanedCaveats)
        out["risk"] = risk
        out["admission"] = admission
        if (cleanedDecisive != null) out["decisive"] = cleanedDecisive
        out["reasons"] = ArrayList<Any?>(reasons.map { cleanText(it) })
        out["summary"] = cleanText(summary)
        return out
    }

    /** `r.includes(...)` on a reason: only strings have it (anything else is a TypeError, caught by the caller). */
    private fun strictStr(r: Any?): String = r as? String ?: throw IllegalArgumentException("TypeError: includes is not a function")

    private fun evalPredicates(predicates: Any?, actionCtx: Any?): PredResult = try {
        if (predicates !is List<*> || predicates.isEmpty()) PredResult(false, "envelope grants no predicates", null)
        else {
            val ac = mapOrEmpty(actionCtx)
            var hit: PredResult? = null
            for (i in predicates.indices) {
                val pi = predicates[i]
                if (pi != null && Predicates.evaluatePredicates(listOf(pi), ac)) { hit = PredResult(true, pi, i); break }
            }
            hit ?: PredResult(false, Predicates.denialReason(predicates, ac), null)
        }
    } catch (e: RuntimeException) {
        PredResult(false, "predicate evaluation error (fail closed)", null)
    } catch (e: StackOverflowError) {
        PredResult(false, "predicate evaluation error (fail closed)", null)
    }

    private fun cost(r: Any?, kappa: Any?): Double {
        val k = ExplainJs.numOf(kappa)
        val kk = if (k != null && !k.isNaN() && !k.isInfinite() && k > 0) k else 0.0
        val rr = ExplainJs.numOf(r)
        val rv = if (rr != null && !rr.isNaN() && !rr.isInfinite()) rr else 1.0
        return kk * (if (rv < 0) 0.0 else if (rv > 1) 1.0 else rv)
    }

    private fun classify(
        cv: Any?, delegated: Boolean, canEval: Boolean, caveatCtx: Any?, actionCtx: Any?, failedFromReasons: Set<String>, rgs: Any?,
    ): Map<String, Any?> {
        val type = typeOf(cv)
        val rest = caveatRest(cv)
        val satisfied: Any? =
            if (canEval && truthy(caveatCtx) && truthy(actionCtx)) evalCaveat(cv, caveatCtx, actionCtx)
            else if (failedFromReasons.contains(type)) false else rgs
        val o = obj()
        o["type"] = type
        put(o, "satisfied", satisfied)
        o["value"] = rest
        o["detail"] = caveatDetail(type, rest, satisfied)
        o["delegated"] = delegated
        if (!truthy(satisfied)) o["remedy"] = caveatRemedy(type, rest)
        return o
    }

    /** `evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the camelCase reference context mapped onto the native evaluator's. */
    private fun evalCaveat(cv: Any?, caveatCtx: Any?, actionCtx: Any?): Boolean {
        val inner = mapOrEmpty(get(actionCtx, "action"))
        val c = obj()
        c["now"] = nullIfUndef(get(caveatCtx, "now"))
        c["action"] = inner
        c["delegation_depth"] = nullIfUndef(get(caveatCtx, "delegationDepth"))
        c["blast_radius"] = nullIfUndef(get(caveatCtx, "blastRadius"))
        c["reversibility_class"] = nullIfUndef(get(caveatCtx, "reversibilityClass"))
        c["recent_action_times"] = nullIfUndef(get(caveatCtx, "recentActionTimes"))
        val tool = obj()
        tool["tool"] = nullIfUndef(get(inner, "verb"))
        tool["args"] = nullIfUndef(get(inner, "params"))
        return Authorize.evaluateAgentCaveats(arrayListOf<Any?>(cv ?: false), c, mapOrEmpty(actionCtx), tool).ok
    }

    private fun nullIfUndef(o: Any?): Any? = if (o === UNDEF) null else o

    /** Render a decision explanation. */
    @JvmStatic
    fun decisionToText(e: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        lines.add("PCA decision — " + s(e["verdict"]).uppercase(Locale.ROOT) + " (" + s(e["disposition"]) + ")")
        lines.add(s(e["summary"]))
        lines.add("")
        val gr = e["grant"]
        val pred = get(gr, "predicate")
        if (truthy(get(gr, "granted")) && truthy(pred)) {
            val pv = get(pred, "verb")
            val verbs = if (pv is List<*>) pv.joinToString("|") { if (it == null) "" else s(it) } else s(pv)
            val res = get(pred, "resource")
            lines.add("  authority : predicate #" + s(get(gr, "predicateIndex")) + " of grant " + shorten(get(gr, "capabilityId")) + " grants " + verbs + " on " + s(nn(res, "*")))
            lines.add("              where " + s(get(gr, "where")))
        } else {
            lines.add("  authority : NOT granted — " + s(nn(get(gr, "reason"), "no predicate permits this action")))
        }
        val cvs = e["caveats"] as List<*>
        if (cvs.isEmpty()) lines.add("  caveats   : none")
        else {
            for (co in cvs) {
                val c = co as Map<*, *>
                val mark = if (truthy(c["satisfied"])) "✓" else "✗"
                val src = if (truthy(c["delegated"])) " [delegated]" else ""
                lines.add("  caveat " + mark + "  : " + s(c["detail"]) + src)
                if (!truthy(c["satisfied"]) && truthy(c["remedy"])) lines.add("              ↳ fix: " + s(c["remedy"]))
            }
        }
        val risk = e["risk"]
        lines.add("  risk      : " + s(get(risk, "band")) + "; proof=" + s(get(risk, "proof")) + ", optimistic=" + s(get(risk, "optimisticAllowed")))
        val a = e["admission"]
        val cost = get(a, "cost")
        val costStr = if (cost !== UNDEF) ", cost κ·r=" + num(cost) + " (κ=" + num(get(a, "kappa")) + ")" else ""
        lines.add("  budget    : " + s(get(a, "path")) + costStr + "; B after=" + num(rd(get(a, "budget"), "B")))
        val dec = e["decisive"]
        if (dec != null) {
            lines.add("")
            lines.add("  ◀ DECISIVE: " + s(get(dec, "reason")))
            if (truthy(get(dec, "remedy"))) lines.add("      ↳ fix: " + s(get(dec, "remedy")))
        }
        return lines.joinToString("\n")
    }

    // =========================================================================================================================
    // explainChain
    // =========================================================================================================================

    private fun isBudgetAlloc(cv: Any?): Boolean {
        if (cv !is Map<*, *> || "budget_alloc" != cv["type"]) return false
        val l = cv["limit"]
        return ExplainJs.isFiniteNumber(l) && ExplainJs.numOf(l)!! >= 0
    }

    private fun hopNarrowedSummary(isRoot: Boolean, added: List<*>): String {
        val bits = ArrayList<String>()
        for (cv in added) {
            val type = typeOf(cv)
            val rest = caveatRest(cv)
            if (type == "envelope") {
                val preds = rest["predicates"]
                val inner = rest["caveats"]
                bits.add("envelope (" + (if (preds is List<*>) preds.size else 0) + " predicate(s), " + (if (inner is List<*>) inner.size else 0) + " caveat(s))")
            } else if (isBudgetAlloc(cv)) {
                bits.add("budget_alloc(B_sub=" + num((cv as Map<*, *>)["limit"]) + ")")
            } else {
                val bound = valueSummary(rest)
                bits.add(if (bound.isNotEmpty()) "+$type($bound)" else "+$type")
            }
        }
        if (bits.isEmpty()) return if (isRoot) "root grant (no caveats)" else "rebind only (no new caveats)"
        return (if (isRoot) "grants " else "narrows: ") + bits.joinToString(", ")
    }

    /** The per-node budget subtree carried by a chain (one node per well-formed `budget_alloc` caveat, root to leaf). */
    @JvmStatic
    fun budgetAllocNodes(chain: Any?): List<Any?> {
        val out = ArrayList<Any?>()
        if (chain !is List<*> || chain.isEmpty()) return out
        val leaf = chain[chain.size - 1]
        val lc = rd(leaf, "caveats") as? List<*> ?: return out
        var hop = 0
        for (ci in lc.indices) {
            while (hop < chain.size - 1) {
                val cvs = rd(chain[hop], "caveats")
                val n = if (cvs === UNDEF || cvs == null) 0 else Math.max(0, len(cvs))
                if (n <= ci) hop++ else break
            }
            val cv = lc[ci]
            if (!isBudgetAlloc(cv)) continue
            val introducing = chain[hop]
            val d = obj()
            d["d"] = "atlas-pca/budget-node/v1"
            d["cap"] = rd(introducing, "id")
            d["i"] = ExplainJs.n(ci.toLong())
            val node = obj()
            node["nodePath"] = Pca.hashCanonical(d)
            put(node, "capId", rd(introducing, "id"))
            put(node, "holder", rd(introducing, "holder"))
            node["depth"] = ExplainJs.n(hop.toLong())
            node["caveatIndex"] = ExplainJs.n(ci.toLong())
            node["limit"] = (cv as Map<*, *>)["limit"]
            out.add(node)
        }
        return out
    }

    /**
     * Render a capability delegation chain as an ordered attenuation trace. With `opts.verify === true` the chain is also
     * checked (`opts.expectedRootIssuer` pins the root issuer); otherwise the trace shows what the chain only CLAIMS.
     */
    @JvmStatic
    fun explainChain(chain: Any?, opts: Any?): Map<String, Any?> {
        val out = explainChainInner(chain)
        if (true != rd(opts, "verify")) return out
        var ok = false
        var reason: String? = "chain is not an array"
        try {
            if (chain is List<*>) {
                val l = chain as List<Any?>
                val exp = get(opts, "expectedRootIssuer")
                val r = if (exp is String) Pca.verifyChain(l, exp, true) else Pca.verifyChain(l, "", false)
                ok = r.isEmpty()
                reason = if (ok) null else r
            }
        } catch (e: RuntimeException) {
            reason = "chain could not be verified"
        }
        val v = obj()
        v["ok"] = ok
        if (reason != null) v["reason"] = cleanText(reason)
        val res = LinkedHashMap(out)
        res["verification"] = v
        return res
    }

    private fun explainChainInner(chain: Any?): Map<String, Any?> {
        val safe: List<Any?> = if (chain is List<*>) ArrayList<Any?>(chain) else ArrayList()
        val hops = ArrayList<Any?>()
        for (i in safe.indices) {
            val cap = safe[i]
            if (!truthy(cap)) continue
            val isRoot = i == 0
            val parent = if (i > 0) safe[i - 1] else UNDEF
            val pc = if (truthy(parent)) get(parent, "caveats") else UNDEF
            val parentLen = if (pc is List<*>) pc.size else 0
            val oc = get(cap, "caveats")
            val own: List<*> = if (oc is List<*>) oc else emptyList<Any?>()
            val added: List<*> = if (isRoot) own else if (own.size >= parentLen) own.subList(parentLen, own.size) else emptyList<Any?>()
            val budgetCv = added.firstOrNull { isBudgetAlloc(it) }
            val hop = obj()
            hop["index"] = ExplainJs.n(i.toLong())
            hop["isRoot"] = isRoot
            put(hop, "issuer", get(cap, "issuer"))
            put(hop, "holder", get(cap, "holder"))
            hop["issuerShort"] = shorten(get(cap, "issuer"))
            hop["holderShort"] = shorten(get(cap, "holder"))
            hop["alg"] = nn(get(cap, "alg"), "ed25519")
            hop["addedCaveats"] = ArrayList<Any?>(added)
            hop["addedCaveatTypes"] = ArrayList<Any?>(added.map { typeOf(it) })
            hop["narrowed"] = cleanText(hopNarrowedSummary(isRoot, added))
            if (budgetCv != null) hop["budgetAlloc"] = (budgetCv as Map<*, *>)["limit"]
            hops.add(hop)
        }
        val root = if (safe.isEmpty()) UNDEF else safe[0]
        val leaf = if (safe.isEmpty()) UNDEF else safe[safe.size - 1]
        val nodes = budgetAllocNodes(safe)
        val summary = if (safe.isEmpty()) "empty chain (no authority)"
        else shorten(opt(root, "issuer")) + " (principal) delegated through " + (safe.size - 1) + " hop(s) to the acting holder " +
            shorten(opt(leaf, "holder")) + "; " + nodes.size + " budget node(s)."
        val out = obj()
        out["kind"] = "chain"
        out["depth"] = ExplainJs.n(safe.size.toLong())
        out["hops"] = hops
        put(out, "rootIssuer", opt(root, "issuer"))
        put(out, "leafHolder", opt(leaf, "holder"))
        out["budgetNodes"] = nodes
        out["summary"] = summary
        return out
    }

    /** Render a chain explanation. */
    @JvmStatic
    fun chainToText(e: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        lines.add("PCA delegation chain — " + s(e["depth"]) + " hop(s) (attenuation trace)")
        val v = e["verification"]
        when {
            v == null -> lines.add("UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.")
            truthy(get(v, "ok")) -> lines.add("verified: signatures, links and caveat rules hold.")
            else -> lines.add("NOT VALID: " + s(nn(get(v, "reason"), "the chain failed verification")))
        }
        lines.add(s(e["summary"]))
        lines.add("")
        for (ho in e["hops"] as List<*>) {
            val h = ho as Map<*, *>
            val tag = if (truthy(h["isRoot"])) "root " else "deleg"
            lines.add("  #" + s(h["index"]) + " " + tag + " " + s(h["issuerShort"]) + " ──▶ " + s(h["holderShort"]) + "   " + s(h["narrowed"]))
        }
        val nodes = e["budgetNodes"] as List<*>
        if (nodes.isNotEmpty()) {
            val tree = nodes.map { "depth " + s((it as Map<*, *>)["depth"]) + " B_sub=" + num(it["limit"]) }
            lines.add("")
            lines.add("  budget subtree: " + tree.joinToString(" → "))
        }
        return lines.joinToString("\n")
    }
}
