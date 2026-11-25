package net.atlasauth.pca.siem

import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.regex.Pattern
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * A SIEM export for PCA authorization decisions: every verify / deny becomes a security event in OCSF, ArcSight CEF or Elastic
 * Common Schema, citing the cryptographic proof digest and the full delegation chain. Everything is pure and read-only over
 * the decision record (a JSON tree: `pcactn`, `verify`, `decision`, `now`, `session`), and
 * mirrors the TypeScript exports of the same name. Shipping never throws into the caller's authorization path.
 */
@Suppress("UNCHECKED_CAST")
object Siem {
    /** A JavaScript `undefined`: an absent member (JSON null stays Kotlin null). */
    private val UNDEF = Any()

    // ---- severity ----

    private class Severity(val id: Int, val name: String, val cef: Int)

    private val SEV_INFO = Severity(1, "Informational", 1)
    private val SEV_LOW = Severity(2, "Low", 3)
    private val SEV_MEDIUM = Severity(3, "Medium", 5)
    private val SEV_HIGH = Severity(4, "High", 8)

    /** Normative checks whose failure means a real security event (tamper / forged authority), not a policy veto. */
    private val SECURITY_CHECKS = arrayOf("wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay")

    // ---- JavaScript-flavoured reads ----

    /** `o?.[k]`: UNDEF for a non-object or an absent member, JSON null when the member is null. */
    private fun g(o: Any?, k: String): Any? = if (o is Map<*, *>) (if (o.containsKey(k)) o[k] else UNDEF) else UNDEF

    /** JS truthiness; the absent-member sentinel is undefined, so falsy. */
    private fun truthy(v: Any?): Boolean = v !== UNDEF && Js.truthy(v)

    private fun nullish(v: Any?): Boolean = v == null || v === UNDEF

    private fun str(v: Any?, fallback: String): String = if (v is String && v.isNotEmpty()) v else fallback

    private fun finiteNum(v: Any?): Double? {
        if (v === UNDEF) return null
        val d = Js.num(v)
        return if (d != null && !d.isNaN() && !d.isInfinite()) d else null
    }

    /** Abbreviate a long b64u key for display in narratives / CEF names. */
    private fun shortKey(key: Any?): String {
        if (key !is String || key.isEmpty()) return "(none)"
        return if (key.length <= 13) key else key.substring(0, 12) + "…"
    }

    private fun numJ(d: Double): Json.Num = Json.Num(if (d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L) "-0" else JsFmt.num(d))

    private fun intJ(v: Long): Json.Num = Json.Num(v.toString())

    private fun intJ(v: Int): Json.Num = Json.Num(v.toString())

    private fun put(m: MutableMap<String, Any?>, k: String, v: Any?) { if (v !== UNDEF) m[k] = v }

    private fun putOpt(m: MutableMap<String, Any?>, k: String, v: Any?) { if (v != null && v !== UNDEF) m[k] = v }

    private fun map(): LinkedHashMap<String, Any?> = LinkedHashMap()

    // ---- normalization ----

    private class Hop(val index: Int, val isRoot: Boolean, val issuer: String, val holder: String, val addedCaveats: Int) {
        fun asChain(): Map<String, Any?> {
            val m = map()
            m["index"] = intJ(index); m["is_root"] = isRoot; m["issuer"] = issuer; m["holder"] = holder; m["added_caveats"] = intJ(addedCaveats)
            return m
        }

        fun asView(): Map<String, Any?> {
            val m = map()
            m["index"] = intJ(index); m["isRoot"] = isRoot; m["issuer"] = issuer; m["holder"] = holder; m["addedCaveats"] = intJ(addedCaveats)
            return m
        }
    }

    private class Normalized {
        var now = 0.0
        var outcome = ""
        var reason = ""
        var cryptographicallyVerifiable = false
        var checks: Any? = null
        var agentHolder = ""
        var principal: String? = null
        var session = ""
        var hops: List<Hop> = ArrayList()
        var depth = 0
        var chainString = ""
        var verb = ""
        var resource = ""
        var paramsDigest = ""
        var reversibilityClass = ""
        var grantRef = ""
        var counter = 0.0
        var nonce: String? = null
        var planRoot = ""
        var signatureSuite = ""
        var leafSignature = ""
        var proofDigest = ""
        var riskScore: Double? = null
        var tier: Any? = UNDEF
        var proofStrength: Any? = UNDEF
        var caution: Double? = null
        var bondRef: String? = null
        var humanApproved = false
        val approvers = ArrayList<Any?>()
        val guardianCosigners = ArrayList<Any?>()
        val roles = ArrayList<Any?>()
        var severity: Severity = SEV_INFO
        var iat = 0.0
        var exp = 0.0
    }

    private fun safeDigest(p: Any?): String {
        if (p === UNDEF) return "(undigestible)"
        return try { Pca.hashCanonical(p) } catch (e: RuntimeException) { "(undigestible)" } catch (e: StackOverflowError) { "(undigestible)" }
    }

    private fun firstReasonOr(decision: Any?, fallback: String): String {
        val rs = g(decision, "reasons")
        if (rs is List<*> && rs.isNotEmpty()) {
            val first = rs[0]
            if (first is String && first.isNotEmpty()) return first
        }
        return fallback
    }

    /** Returns {outcome, reason}. */
    private fun resolveOutcome(verify: Any?, decision: Any?): Array<String> {
        if (!Js.truthy(verify) || g(verify, "allow") != true) return arrayOf("deny", str(g(verify, "reason"), "proof failed verification"))
        if (!Js.truthy(decision)) return arrayOf("allow", "proof verified; no policy decision supplied")
        if (truthy(g(decision, "admit"))) return arrayOf("allow", firstReasonOr(decision, "auto-admitted within policy and budget"))
        if (truthy(g(decision, "releaseGuardianShare"))) return arrayOf("step-up", firstReasonOr(decision, "policy satisfied but a co-signature is required"))
        return arrayOf("deny", firstReasonOr(decision, "policy did not release authority (default-deny)"))
    }

    private fun buildHops(chain: List<*>): List<Hop> {
        val hops = ArrayList<Hop>()
        for (i in chain.indices) {
            val cap = chain[i]
            if (!Js.truthy(cap)) continue
            val parent = if (i > 0) chain[i - 1] else null
            val pc = if (Js.truthy(parent)) g(parent, "caveats") else UNDEF
            val parentLen = if (pc is List<*>) pc.size else 0
            val oc = g(cap, "caveats")
            val ownLen = if (oc is List<*>) oc.size else 0
            hops.add(Hop(i, i == 0, str(g(cap, "issuer"), "(none)"), str(g(cap, "holder"), "(none)"), if (i == 0) ownLen else Math.max(0, ownLen - parentLen)))
        }
        return hops
    }

    private fun readOverride(n: Normalized, threshold: Any?, thresholdCheck: Any?) {
        val shares = if (Js.truthy(threshold)) g(threshold, "shares") else UNDEF
        val list: List<*> = if (shares is List<*>) shares else ArrayList<Any?>()
        // `threshold` sits outside the signed body: its shares prove nothing until a threshold verifier passed.
        if ("pass" != thresholdCheck) return
        for (s in list) {
            if (!Js.truthy(s) || g(s, "role") !is String) continue
            val role = g(s, "role") as String
            n.roles.add(role)
            val pk = g(s, "publicKey")
            if (role == "principal" && pk is String) n.approvers.add(pk)
            if (role == "guardian" && pk is String) n.guardianCosigners.add(pk)
        }
        n.humanApproved = n.approvers.isNotEmpty()
    }

    private fun isNumber(v: Any?, want: Double): Boolean {
        val d = if (v === UNDEF) null else Js.num(v)
        return d != null && d == want
    }

    private fun severityFor(outcome: String, checks: Any?, tier: Any?): Severity {
        if (outcome == "deny") {
            var securityFailure = false
            for (k in SECURITY_CHECKS) if ("fail" == g(checks, k)) securityFailure = true
            return if (securityFailure) SEV_HIGH else SEV_MEDIUM
        }
        if (outcome == "step-up") return SEV_MEDIUM
        return if (isNumber(tier, 3.0)) SEV_MEDIUM else if (isNumber(tier, 2.0)) SEV_LOW else SEV_INFO
    }

    private fun shownSignature(sig: String, mode: Any?): String {
        if ("full" == mode) return sig
        if ("omit" == mode) return "(omitted)"
        return if (sig.length <= 16) sig else sig.substring(0, 16) + "…"
    }

    /** One total pass: extract everything the exporters need. Never throws; degrades to best-effort values. */
    private fun normalize(record: Any?, opts: Any?): Normalized {
        val p = g(record, "pcactn")
        val vraw = g(record, "verify")
        val verify: Any? = if (nullish(vraw)) null else vraw
        val checksRaw = if (verify == null) UNDEF else g(verify, "checks")
        val checks: Any? = if (nullish(checksRaw)) map() else checksRaw
        val nowD = finiteNum(g(record, "now"))
        val now = nowD ?: System.currentTimeMillis().toDouble()
        val chainRaw = g(p, "cap_chain")
        val chain: List<*> = if (chainRaw is List<*>) chainRaw else ArrayList<Any?>()
        val hops = buildHops(chain)
        val leaf: Any? = if (chain.isEmpty()) UNDEF else chain[chain.size - 1]
        val root: Any? = if (chain.isEmpty()) UNDEF else chain[0]

        val decision = g(record, "decision").let { if (it === UNDEF) null else it }
        val or = resolveOutcome(if (vraw === UNDEF) null else vraw, decision)
        val n = Normalized()
        n.outcome = or[0]
        n.reason = or[1]
        val rt = g(g(decision, "requiredThreshold"), "t")
        readOverride(n, g(p, "threshold"), g(checks, "threshold"))

        val grantRef = str(g(p, "grant_ref"), "(none)")
        val rootIssuer = g(root, "issuer")
        n.principal = if (rootIssuer is String && rootIssuer.isNotEmpty()) rootIssuer else null
        n.agentHolder = str(g(leaf, "holder"), "(none)")
        val parts = ArrayList<String>()
        parts.add(shortKey(n.principal ?: "(principal?)"))
        for (h in hops) parts.add(shortKey(h.holder))

        n.now = now
        n.cryptographicallyVerifiable = "pass" == g(checks, "wire") && "pass" == g(checks, "leaf_signature")
        n.checks = checks
        n.session = str(g(record, "session"), grantRef)
        n.hops = hops
        n.depth = if (hops.isNotEmpty()) hops.size - 1 else 0
        n.chainString = parts.joinToString(" -> ")
        val action = g(p, "action")
        n.verb = str(g(action, "verb"), "(unknown verb)")
        n.resource = str(g(action, "resource"), "(unknown resource)")
        n.paramsDigest = str(g(action, "params_digest"), "(none)")
        n.reversibilityClass = str(g(action, "reversibility_class"), "(unknown)")
        n.grantRef = grantRef
        n.counter = finiteNum(g(p, "counter")) ?: -1.0
        n.nonce = g(p, "nonce") as? String
        n.planRoot = str(g(g(p, "plan"), "root"), "(none)")
        n.signatureSuite = str(g(p, "alg"), "ed25519")
        n.leafSignature = shownSignature(str(g(p, "sig"), "(unsigned)"), g(opts, "signature"))
        n.proofDigest = safeDigest(p)
        n.riskScore = finiteNum(g(decision, "r"))
        n.tier = rt
        n.proofStrength = g(g(decision, "requiredThreshold"), "proof")
        n.caution = finiteNum(g(p, "caution"))
        n.bondRef = g(p, "bond_ref") as? String
        n.severity = severityFor(n.outcome, checks, rt)
        n.iat = finiteNum(g(p, "iat")) ?: now
        n.exp = finiteNum(g(p, "exp")) ?: now
        return n
    }

    private fun humanOverride(n: Normalized): Map<String, Any?> {
        val m = map()
        m["human_approved"] = true
        m["approvers"] = ArrayList(n.approvers)
        m["guardian_cosigners"] = ArrayList(n.guardianCosigners)
        m["roles"] = ArrayList(n.roles)
        return m
    }

    private fun chainJson(n: Normalized): List<Any?> = n.hops.map { it.asChain() }

    /** The PCA-specific block every schema carries verbatim (the cryptographic edge). */
    private fun pcaExtensions(n: Normalized): Map<String, Any?> {
        val m = map()
        m["proof_digest"] = n.proofDigest
        m["leaf_signature"] = n.leafSignature
        m["signature_suite"] = n.signatureSuite
        m["cryptographically_verifiable"] = n.cryptographicallyVerifiable
        m["plan_root"] = n.planRoot
        m["params_digest"] = n.paramsDigest
        m["grant_ref"] = n.grantRef
        m["counter"] = numJ(n.counter)
        putOpt(m, "nonce", n.nonce)
        m["reversibility_class"] = n.reversibilityClass
        n.riskScore?.let { m["risk_score"] = numJ(it) }
        put(m, "risk_tier", n.tier)
        put(m, "required_proof", n.proofStrength)
        n.caution?.let { m["caution"] = numJ(it) }
        putOpt(m, "bond_ref", n.bondRef)
        m["delegation_depth"] = intJ(n.depth)
        m["delegation_chain"] = chainJson(n)
        m["checks"] = n.checks
        if (n.humanApproved) m["human_override"] = humanOverride(n)
        return m
    }

    // ---- OCSF ----

    private const val OCSF_CLASS_UID = 3003
    private const val OCSF_SCHEMA_VERSION = "1.1.0"

    private fun user(typeId: Int, type: String, uid: String, name: String): Map<String, Any?> {
        val m = map()
        m["type_id"] = intJ(typeId); m["type"] = type; m["uid"] = uid; m["name"] = name
        return m
    }

    private fun observable(name: String, type: String, typeId: Int, value: String): Map<String, Any?> {
        val m = map()
        m["name"] = name; m["type"] = type; m["type_id"] = intJ(typeId); m["value"] = value
        return m
    }

    /** Map a PCA decision to an OCSF 1.x Authorize Session event (Identity and Access Management, class 3003). */
    @JvmOverloads fun toOcsfEvent(record: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val n = normalize(record, opts)
        val activityId: Int
        val activityName: String
        val actionId: Int
        val actionName: String
        val statusId: Int
        val statusName: String
        val statusDetail: String
        when (n.outcome) {
            "allow" -> { activityId = 1; activityName = "Allow"; actionId = 1; actionName = "Allowed"; statusId = 1; statusName = "Success"; statusDetail = n.reason }
            "deny" -> { activityId = 2; activityName = "Deny"; actionId = 2; actionName = "Denied"; statusId = 2; statusName = "Failure"; statusDetail = n.reason }
            else -> { activityId = 3; activityName = "Step-Up"; actionId = 99; actionName = "Other"; statusId = 99; statusName = "Other"; statusDetail = "step-up / co-signature required: " + n.reason }
        }
        val className = "Authorize Session"
        val e = map()
        e["activity_id"] = intJ(activityId)
        e["activity_name"] = activityName
        e["category_uid"] = intJ(3)
        e["category_name"] = "Identity & Access Management"
        e["class_uid"] = intJ(OCSF_CLASS_UID)
        e["class_name"] = className
        e["type_uid"] = intJ(OCSF_CLASS_UID * 100L + activityId)
        e["type_name"] = "$className: $activityName"
        e["action_id"] = intJ(actionId)
        e["action"] = actionName
        e["severity_id"] = intJ(n.severity.id)
        e["severity"] = n.severity.name
        e["status_id"] = intJ(statusId)
        e["status"] = statusName
        e["status_detail"] = statusDetail
        e["time"] = numJ(n.iat)
        val actor = map()
        actor["user"] = user(99, "Agent", n.agentHolder, shortKey(n.agentHolder))
        actor["invoked_by"] = n.principal ?: "(none)"
        val session = map()
        session["uid"] = n.session
        putOpt(session, "issuer", n.principal)
        actor["session"] = session
        actor["app_name"] = "PCA"
        e["actor"] = actor
        e["user"] = user(1, "User", n.principal ?: "(none)", shortKey(n.principal))
        val res = map()
        res["type"] = "pca.resource"; res["name"] = n.resource; res["uid"] = n.resource
        e["resources"] = arrayListOf<Any?>(res)
        val api = map()
        api["operation"] = n.verb
        val svc = map()
        svc["name"] = "PCA"
        api["service"] = svc
        e["api"] = api
        val md = map()
        md["version"] = OCSF_SCHEMA_VERSION
        val product = map()
        product["name"] = "PCA"; product["vendor_name"] = "Atlas"; product["version"] = OCSF_SCHEMA_VERSION
        md["product"] = product
        md["logged_time"] = numJ(n.now)
        md["uid"] = n.proofDigest
        md["labels"] = arrayListOf<Any?>("pca", "outcome:" + n.outcome, "suite:" + n.signatureSuite)
        e["metadata"] = md
        e["observables"] = arrayListOf<Any?>(
            observable("actor.user.uid", "User Name", 4, n.agentHolder),
            observable("pca.proof.digest", "Hash", 8, n.proofDigest),
            observable("resources.uid", "Resource UID", 10, n.resource),
        )
        e["count"] = intJ(1)
        e["message"] = narrative(n)
        e["unmapped"] = pcaExtensions(n)
        return e
    }

    // ---- CEF ----

    /** Escape a CEF header field: backslash and pipe are reserved. */
    private fun cefHeaderEscape(s: String): String = s.replace("\\", "\\\\").replace("|", "\\|").replace(Regex("[\\r\\n]+"), " ")

    /** Escape a CEF extension value: backslash, equals and newlines are reserved. */
    private fun cefExtValueEscape(s: String): String = s.replace("\\", "\\\\").replace("=", "\\=").replace(Regex("\\r\\n|\\r|\\n")) { "\\n" }

    private fun ext(out: MutableList<String>, k: String, v: String) { out.add(k + "=" + cefExtValueEscape(v)) }

    /** Entries of `Object.entries(v)` rendered `key:value` (an object, an array or the characters of a string). */
    private fun checkPairs(v: Any?): List<String> {
        val out = ArrayList<String>()
        if (v is Map<*, *>) {
            for ((k, x) in v) out.add(k.toString() + ":" + JsFmt.str(x))
        } else if (v is List<*>) {
            for (i in v.indices) out.add("$i:" + (if (v[i] == null) "null" else JsFmt.str(v[i])))
        } else if (v is String) {
            for (i in v.indices) out.add("$i:" + v[i])
        }
        return out
    }

    /**
     * Map a PCA decision to a single ArcSight CEF line: `CEF:0|Atlas|PCA|<wireVer>|pca-authz-<outcome>|<name>|<sev>|ext...`, with the
     * proof digest, the delegation chain, the risk tier and proof strength as custom fields.
     */
    @JvmOverloads fun toCef(record: Any?, opts: Map<String, Any?>? = null): String {
        val n = normalize(record, opts)
        val wireVer = finiteNum(g(g(record, "pcactn"), "ver"))
        val deviceVersion = if (wireVer != null) JsFmt.num(wireVer) else "2"
        val signatureId = "pca-authz-" + n.outcome
        val name = "PCA authorization ${n.outcome}: ${n.verb} on ${n.resource}"
        val header = listOf("CEF:0", cefHeaderEscape("Atlas"), cefHeaderEscape("PCA"), cefHeaderEscape(deviceVersion),
            cefHeaderEscape(signatureId), cefHeaderEscape(name), n.severity.cef.toString()).joinToString("|")
        val principal = n.principal ?: "(none)"
        val x = ArrayList<String>()
        ext(x, "act", n.outcome)
        ext(x, "outcome", n.outcome)
        ext(x, "suser", principal)
        ext(x, "suid", principal)
        ext(x, "duser", n.agentHolder)
        ext(x, "duid", n.agentHolder)
        ext(x, "destinationServiceName", n.verb)
        ext(x, "rt", JsFmt.num(n.now))
        ext(x, "start", JsFmt.num(n.iat))
        ext(x, "end", JsFmt.num(n.exp))
        ext(x, "externalId", n.nonce ?: JsFmt.num(n.counter))
        ext(x, "request", n.resource)
        ext(x, "requestMethod", n.verb)
        ext(x, "cs1Label", "pcaProofDigest")
        ext(x, "cs1", n.proofDigest)
        ext(x, "cs2Label", "pcaDelegationChain")
        ext(x, "cs2", n.chainString)
        ext(x, "cs3Label", "pcaProofStrength")
        ext(x, "cs3", if (nullish(n.proofStrength)) "n/a" else JsFmt.str(n.proofStrength))
        ext(x, "cs4Label", "pcaSignatureSuite")
        ext(x, "cs4", n.signatureSuite)
        ext(x, "cs5Label", "pcaVerifyChecks")
        ext(x, "cs5", checkPairs(n.checks).joinToString(";"))
        ext(x, "cs6Label", "pcaGrantRef")
        ext(x, "cs6", n.grantRef)
        ext(x, "cn1Label", "pcaRiskScore")
        ext(x, "cn1", n.riskScore?.let { JsFmt.num(it) } ?: "")
        ext(x, "cn2Label", "pcaDelegationDepth")
        ext(x, "cn2", n.depth.toString())
        ext(x, "cn3Label", "pcaRiskTier")
        ext(x, "cn3", if (nullish(n.tier)) "" else JsFmt.str(n.tier))
        ext(x, "flexString1Label", "pcaHumanApproved")
        ext(x, "flexString1", if (n.humanApproved) "true" else "false")
        ext(x, "cat", "authorization")
        ext(x, "msg", n.reason)
        return header + "|" + x.joinToString(" ")
    }

    // ---- ECS ----

    private const val ECS_VERSION = "8.11.0"

    private fun dedupe(input: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (v in input) if (!out.contains(v)) out.add(v)
        return out
    }

    /** Map a PCA decision to an Elastic Common Schema event (category iam; the PCA edge under `pca.*`). */
    @JvmOverloads fun toEcs(record: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val n = normalize(record, opts)
        val users = ArrayList<Any?>()
        users.add(n.agentHolder)
        if (n.principal != null && n.principal!!.isNotEmpty()) users.add(n.principal)
        users.addAll(n.approvers)
        val hashes = arrayListOf<Any?>(n.proofDigest, n.leafSignature)

        val type = if (n.outcome == "allow") "allowed" else if (n.outcome == "deny") "denied" else "info"
        val outcome = if (n.outcome == "allow") "success" else if (n.outcome == "deny") "failure" else "unknown"
        val event = map()
        event["kind"] = "event"
        event["category"] = arrayListOf<Any?>("iam")
        event["type"] = arrayListOf<Any?>(type)
        event["action"] = n.verb
        event["outcome"] = outcome
        event["module"] = "pca"
        event["dataset"] = "pca.authorization"
        event["provider"] = "pca"
        event["id"] = n.proofDigest
        event["severity"] = intJ(n.severity.cef)
        event["reason"] = n.reason
        n.riskScore?.let { event["risk_score"] = numJ(it) }

        val e = map()
        e["@timestamp"] = isoOf(n.iat)
        e["ecs.version"] = ECS_VERSION
        e["event"] = event
        val user = map()
        user["id"] = n.agentHolder
        user["name"] = shortKey(n.agentHolder)
        user["roles"] = arrayListOf<Any?>("agent")
        val eff = map()
        eff["id"] = n.principal ?: "(none)"
        eff["name"] = shortKey(n.principal)
        user["effective"] = eff
        e["user"] = user
        val service = map()
        service["name"] = "pca"; service["type"] = "authorization"
        e["service"] = service
        val related = map()
        related["user"] = dedupe(users)
        related["hash"] = dedupe(hashes)
        e["related"] = related
        e["message"] = narrative(n)

        val pca = map()
        pca["outcome"] = n.outcome
        val proof = map()
        proof["digest"] = n.proofDigest
        proof["leaf_signature"] = n.leafSignature
        proof["signature_suite"] = n.signatureSuite
        proof["cryptographically_verifiable"] = n.cryptographicallyVerifiable
        proof["plan_root"] = n.planRoot
        proof["params_digest"] = n.paramsDigest
        pca["proof"] = proof
        val risk = map()
        n.riskScore?.let { risk["score"] = numJ(it) }
        put(risk, "tier", n.tier)
        put(risk, "required_proof", n.proofStrength)
        n.caution?.let { risk["caution"] = numJ(it) }
        pca["risk"] = risk
        val delegation = map()
        delegation["depth"] = intJ(n.depth)
        delegation["chain"] = n.chainString
        delegation["hops"] = n.hops.map { it.asView() }
        pca["delegation"] = delegation
        pca["grant_ref"] = n.grantRef
        pca["counter"] = numJ(n.counter)
        putOpt(pca, "nonce", n.nonce)
        pca["reversibility_class"] = n.reversibilityClass
        putOpt(pca, "bond_ref", n.bondRef)
        pca["checks"] = n.checks
        if (n.humanApproved) pca["human_override"] = humanOverride(n)
        e["pca"] = pca
        return e
    }

    private const val EPOCH_ISO = "1970-01-01T00:00:00.000Z"

    /** `new Date(ms).toISOString()`, or the epoch for a time outside the Date range. */
    internal fun isoOf(ms: Double): String {
        if (ms.isNaN() || ms.isInfinite()) return EPOCH_ISO
        val t0 = if (ms < 0) Math.ceil(ms) else Math.floor(ms)
        if (Math.abs(t0) > 8.64e15) return EPOCH_ISO
        val t = t0.toLong()
        val days = Math.floorDiv(t, 86_400_000L)
        val msOfDay = Math.floorMod(t, 86_400_000L)
        // civil-from-days (proleptic Gregorian)
        val z = days + 719468
        val era = Math.floorDiv(z, 146097L)
        val doe = z - era * 146097
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val d = (doy - (153 * mp + 2) / 5 + 1).toInt()
        val m = (if (mp < 10) mp + 3 else mp - 9).toInt()
        val y = (yoe + era * 400 + (if (m <= 2) 1 else 0)).toInt()
        val year = if (y in 0..9999) String.format(Locale.ROOT, "%04d", y) else (if (y < 0) "-" else "+") + String.format(Locale.ROOT, "%06d", Math.abs(y))
        val h = (msOfDay / 3_600_000L).toInt()
        val mi = ((msOfDay / 60_000L) % 60).toInt()
        val s = ((msOfDay / 1000L) % 60).toInt()
        val milli = (msOfDay % 1000L).toInt()
        return String.format(Locale.ROOT, "%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, m, d, h, mi, s, milli)
    }

    /** One-sentence plain-English narration of the whole event (shared across schemas). */
    private fun narrative(n: Normalized): String {
        val word = if (n.outcome == "allow") "ALLOWED" else if (n.outcome == "deny") "DENIED" else "STEP-UP"
        return "Agent " + shortKey(n.agentHolder) + " " + word + " to " + n.verb + " on " + n.resource + " (" +
            n.hops.size + "-hop chain rooted at principal " + shortKey(n.principal) + "; " +
            (if (n.cryptographicallyVerifiable) "cryptographically verifiable proof" else "proof not cryptographically verifiable") +
            (if (n.humanApproved) "; human-signed step-up" else "") + "). " + n.reason
    }

    // ---- sinks ----

    /** A single serialized event ready to ship: the structured object (OCSF / ECS; null for CEF) plus a one-line payload. */
    class SiemEvent(val format: String?, val `object`: Map<String, Any?>?, val line: String) {
        fun toMap(): Map<String, Any?> {
            val m = map()
            m["format"] = format
            if (`object` != null) m["object"] = `object`
            m["line"] = line
            return m
        }
    }

    class SinkResult(val ok: Boolean, val error: String?) {
        fun toMap(): Map<String, Any?> {
            val m = map()
            m["ok"] = ok
            if (error != null) m["error"] = error
            return m
        }

        companion object {
            fun success() = SinkResult(true, null)
            fun failure(error: String) = SinkResult(false, error)
        }
    }

    /** A pluggable SIEM destination; [deliver] should not throw and must not block the caller's authorization path. */
    interface SiemSink {
        fun name(): String
        fun format(): String?
        fun deliver(events: List<SiemEvent>): SinkResult
    }

    /** Serialize a decision record into the given schema ("ocsf", "cef" or "ecs"; anything but cef / ocsf is ECS). */
    fun formatDecision(record: Any?, format: String?, opts: Map<String, Any?>?): SiemEvent {
        if ("cef" == format) return SiemEvent(format, null, toCef(record, opts))
        val obj = if ("ocsf" == format) toOcsfEvent(record, opts) else toEcs(record, opts)
        return SiemEvent(format, obj, JsFmt.stringify(obj))
    }

    private fun contentType(format: String?): String? = when (format) {
        "ocsf", "ecs" -> "application/x-ndjson"
        "cef" -> "text/plain; charset=utf-8"
        else -> null
    }

    // JavaScript whitespace (what \s matches), spelled out because the Java \s is ASCII only.
    private const val WS = " \\t\\n\\u000B\\f\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"

    // \b before a word character, spelled out because the Java \b is Unicode-aware.
    private const val WB = "(?<![A-Za-z0-9_])"
    private val URL_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*:\\/\\/)[^$WS/@]*:[^$WS/@]*@", Pattern.CASE_INSENSITIVE)
    private val AUTH_HEADER = Pattern.compile(WB + "(authorization[\"']?[" + WS + "]*[:=][" + WS + "]*)[^\\n\"']*", Pattern.CASE_INSENSITIVE)
    private val SCHEME = Pattern.compile(WB + "(Bearer|Basic|Splunk|Token)[" + WS + "]+[\\w.~+/=-]{6,}", Pattern.CASE_INSENSITIVE)
    private val KEYED = Pattern.compile(WB + "((?:token|secret|password|passwd|pwd|api[_-]?key|dd-api-key|key|signature|sig|credential)[\"']?[" + WS + "]*[:=][" + WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + WS + "\"'&,;]+)", Pattern.CASE_INSENSITIVE)
    private val LONG_RUN = Pattern.compile("[A-Za-z0-9_-]{32,}")

    /**
     * Remove credentials from an error message before it is returned or handed to `onError`: URL userinfo, token / key style pairs,
     * bearer credentials and long token-like runs; at most 300 characters.
     */
    fun scrubError(message: String?): String {
        var t = message ?: "null"
        t = URL_USERINFO.matcher(t).replaceAll("$1[redacted]@")
        t = AUTH_HEADER.matcher(t).replaceAll("$1[redacted]")
        t = SCHEME.matcher(t).replaceAll("$1 [redacted]")
        t = KEYED.matcher(t).replaceAll("$1[redacted]")
        t = LONG_RUN.matcher(t).replaceAll("[redacted]")
        return if (t.length > 300) t.substring(0, 300) + "..." else t
    }

    private fun messageOf(e: Throwable): String = e.message ?: e.toString()

    /** The minimal shape of a fetch response this package reads. */
    class FetchLikeResponse(val ok: Boolean, val status: Int, val statusText: String?)

    /** The request an HTTP sink sends. */
    class FetchInit internal constructor(val method: String, val headers: Map<String, String>, val body: String)

    /** An injectable fetch: [defaultFetch] by default, or a mock in tests. */
    fun interface FetchLike { fun fetch(url: String, init: FetchInit): FetchLikeResponse }

    class HttpSinkOptions(var format: String?) {
        var headers: Map<String, String>? = null
        var fetch: FetchLike? = null
        var contentType: String? = null
        var name: String? = null
        var timeoutMs: Double? = null
        var serialize: Map<String, Any?>? = null
    }

    private val client by lazy { OkHttpClient() }

    /** A fetch over OkHttp: one POST, the status line mapped to [FetchLikeResponse]. */
    fun defaultFetch(): FetchLike = FetchLike { url, init ->
        val ct = init.headers.entries.firstOrNull { it.key.equals("content-type", ignoreCase = true) }?.value
        val b = Request.Builder().url(url).method(init.method, init.body.toRequestBody(ct?.toMediaTypeOrNull()))
        for ((k, v) in init.headers) if (!k.equals("content-type", ignoreCase = true)) b.header(k, v)
        client.newBuilder().callTimeout(30, TimeUnit.SECONDS).build().newCall(b.build()).execute().use { r ->
            FetchLikeResponse(r.code in 200..299, r.code, null)
        }
    }

    /**
     * An HTTP sink that batches events into one POST: NDJSON for OCSF / ECS, the raw CEF lines for CEF (the body is the lines joined by newlines).
     * Delivery never throws: a network error, a timeout or a non-2xx status is returned as a failure result.
     */
    fun httpSink(url: String, options: HttpSinkOptions): SiemSink {
        val format = options.format
        val name = options.name ?: "http:$format"
        return object : SiemSink {
            override fun name(): String = name
            override fun format(): String? = format
            override fun deliver(events: List<SiemEvent>): SinkResult {
                try {
                    val doFetch = options.fetch ?: defaultFetch()
                    val body = events.joinToString("\n") { it.line }
                    val headers = LinkedHashMap<String, String>()
                    val ct = options.contentType ?: contentType(format)
                    if (ct != null) headers["content-type"] = ct
                    options.headers?.let { headers.putAll(it) }
                    val t = options.timeoutMs ?: 10_000.0
                    val ms = if (!t.isNaN() && !t.isInfinite() && t > 0) t.toLong() else 10_000L
                    val init = FetchInit("POST", headers, body)
                    val f = CompletableFuture<FetchLikeResponse>()
                    val th = Thread {
                        try { f.complete(doFetch.fetch(url, init)) } catch (e: Throwable) { f.completeExceptionally(e) }
                    }
                    th.isDaemon = true
                    th.start()
                    val res: FetchLikeResponse = try {
                        f.get(ms, TimeUnit.MILLISECONDS)
                    } catch (te: TimeoutException) {
                        th.interrupt()
                        return SinkResult.failure("delivery timed out")
                    } catch (ee: ExecutionException) {
                        val c = ee.cause ?: ee
                        return SinkResult.failure(scrubError(messageOf(c)))
                    }
                    if (res.ok) return SinkResult.success()
                    return SinkResult.failure(scrubError("HTTP " + res.status + (if (!res.statusText.isNullOrEmpty()) " " + res.statusText else "")))
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return SinkResult.failure(scrubError(messageOf(ie)))
                } catch (e: RuntimeException) {
                    return SinkResult.failure(scrubError(messageOf(e)))
                }
            }
        }
    }

    class ConsoleSinkOptions {
        var format: String? = null
        var logger: ((String) -> Unit)? = null
        var name: String? = null
    }

    /** A sink that writes each event's serialized line to a logger (default standard output). Never throws. */
    @JvmOverloads fun consoleSink(options: ConsoleSinkOptions? = null): SiemSink {
        val format = options?.format ?: "ocsf"
        val logger: (String) -> Unit = options?.logger ?: { println(it) }
        val name = options?.name ?: "console:$format"
        return object : SiemSink {
            override fun name(): String = name
            override fun format(): String? = format
            override fun deliver(events: List<SiemEvent>): SinkResult {
                try {
                    for (e in events) logger(e.line)
                    return SinkResult.success()
                } catch (e: RuntimeException) {
                    return SinkResult.failure(scrubError(messageOf(e)))
                }
            }
        }
    }

    // ---- export orchestration ----

    /** Called (log and drop) when delivery fails; wrapped so it can never throw back into the caller. */
    fun interface OnError { fun accept(error: Exception, sink: String, count: Int) }

    class ExportOptions {
        var onError: OnError? = null
        var serialize: Map<String, Any?>? = null
    }

    class ExportResult internal constructor(val ok: Boolean, val delivered: Int, val format: String?, val error: String?, val skipped: Int) {
        fun toMap(): Map<String, Any?> {
            val m = map()
            m["ok"] = ok
            m["delivered"] = intJ(delivered)
            if (format != null) m["format"] = format
            if (error != null) m["error"] = error
            if (skipped > 0) m["skipped"] = intJ(skipped)
            return m
        }
    }

    private fun safeOnError(options: ExportOptions?, error: Exception, sink: String, count: Int) {
        val cb = options?.onError ?: return
        try { cb.accept(error, sink, count) } catch (e: RuntimeException) { /* an onError that throws must not touch the auth path */ }
    }

    /** Export one PCA decision to a sink. Fail-safe: errors are reported via onError and returned, never thrown. */
    @JvmOverloads fun exportDecision(record: Any?, sink: SiemSink?, options: ExportOptions? = null): ExportResult = exportBatch(listOf(record), sink, options)

    /** Export a batch of PCA decisions to a sink in one delivery. Fail-safe, exactly like [exportDecision]. */
    @JvmOverloads fun exportBatch(records: List<*>, sink: SiemSink?, options: ExportOptions? = null): ExportResult {
        val format = sink?.format()
        var count = 0
        try {
            val events = ArrayList<SiemEvent>()
            var skipped = 0
            for (r in records) {
                try {
                    events.add(formatDecision(r, format, options?.serialize))
                } catch (e: RuntimeException) {
                    skipped++
                    safeOnError(options, Exception(scrubError("record could not be serialized: " + messageOf(e))), sink!!.name(), 1)
                }
            }
            count = events.size
            if (events.isEmpty() && skipped > 0) return ExportResult(false, 0, format, "no record could be serialized", skipped)
            val res = sink!!.deliver(events)
            if (res.ok) return ExportResult(true, events.size, format, null, skipped)
            val err = Exception(scrubError(res.error ?: "sink reported a delivery failure"))
            safeOnError(options, err, sink.name(), events.size)
            return ExportResult(false, 0, format, err.message, skipped)
        } catch (e: Exception) {
            val err = Exception(scrubError(messageOf(e)))
            safeOnError(options, err, sink?.name() ?: "(unknown sink)", count)
            return ExportResult(false, 0, format, err.message, 0)
        }
    }
}
