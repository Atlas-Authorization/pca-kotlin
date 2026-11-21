package net.atlasauth.pca.intent

import net.atlasauth.pca.compliance.ComplianceJs
import net.atlasauth.pca.research.PolicySim
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The approval half of natural-language policy authoring (generate, then review): the model's completion is parsed strictly and grounded in the catalog
 * ([IntentCompilers.parseNLPolicy]), the draft is content-addressed and bound to the instruction, the model and the prompt, a reviewer whose key you pinned
 * signs it ([approveDraft]), and only a verified, unexpired approval loads as policy ([loadApprovedPolicy]) or mints an agent ([agentFromApprovedNL]). The model is
 * an injected `complete(prompt) -> text` function. Nothing here trusts what a draft says about itself: digest, grounding and lints are recomputed.
 * An approval v1 (the draft digest without the instruction, model and prompt) still loads, flagged `legacy_unbound_instruction`.
 */
@Suppress("UNCHECKED_CAST")
object NlApproval {
    const val NL_APPROVAL_DOMAIN = "atlas-pca/nl-approval/v1\u0000"

    /** Domain of an approval v2 (it binds the instruction, the model and the prompt). */
    const val NL_APPROVAL_DOMAIN_V2 = "atlas-pca/nl-approval/v2\u0000"

    /** Model output larger than this many UTF-8 bytes is refused outright. */
    const val MAX_NL_OUTPUT_BYTES = 16_384L

    /** An approval may not be valid for longer than this. */
    const val MAX_NL_APPROVAL_TTL_MS = 24L * 3_600_000L
    private const val DEFAULT_NL_APPROVAL_TTL_MS = 3_600_000L

    private val J = ComplianceJs

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap<String, Any?>().also { for ((k, v) in kv) it[k] = v }

    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *> && o.containsKey(k)) o[k] else J.UNDEF

    /** The catalog vocabulary digest: the lenient canonical rows `[verb, reversibility, amountField | null]` sorted by verb. Not the digest of the catalog itself. */
    @JvmStatic fun catalogDigest(catalog: Catalog): String {
        val rows = catalog.all().map { listOf<Any?>(it.verb, it.reversibility, it.amountField) }.sortedWith { a, b -> (a[0] as String).compareTo(b[0] as String) }
        return Pca.hashCanonicalLenient(obj("v" to Json.Num("1"), "rows" to rows))
    }

    /** What an approval v2 adds to a draft digest, all recomputable from public inputs: the instruction, the model id and the exact prompt. */
    @JvmStatic @JvmOverloads fun draftBinding(instruction: String, catalog: Catalog, model: String? = null): Map<String, Any?> = obj(
        "instruction_digest" to Pca.hashCanonicalLenient(obj("d" to "atlas-pca/nl-instruction/v1", "text" to instruction)),
        "model" to model,
        "prompt_digest" to Pca.hashCanonicalLenient(obj("d" to "atlas-pca/nl-prompt/v1", "text" to IntentCompilers.nlPrompt(instruction, catalog))),
    )

    /** `[...list].sort()` of each connector's actions and the connectors in sorted order (the default string sort). */
    private fun sortedPerms(permissions: Any?): Map<String, Any?> {
        val m = permissions as? Map<String, Any?> ?: throw IllegalArgumentException("Cannot convert undefined or null to object")
        val out = LinkedHashMap<String, Any?>()
        for (c in m.keys.sorted()) {
            val v = m[c]
            // spreading a string iterates its code points
            val acts: List<*> = if (v is String) v.codePoints().toArray().map { String(Character.toChars(it)) } else v as? List<*> ?: throw IllegalArgumentException("object is not iterable")
            out[c] = acts.sortedBy { J.tpl(it) }
        }
        return out
    }

    /** The digest an approval v2 signs: the v1 content plus `{instruction_digest, model, prompt_digest}`; connector and action lists are sorted before hashing. */
    @JvmStatic fun draftDigestV2(permissions: Any?, limits: Any?, catalogDigest: Any?, binding: Any?): String = Pca.hashCanonicalLenient(
        obj(
            "v" to Json.Num("2"), "permissions" to sortedPerms(permissions), "limits" to limits, "catalog_digest" to catalogDigest,
            "instruction_digest" to (binding as? Map<*, *>)?.get("instruction_digest"), "model" to (binding as? Map<*, *>)?.get("model"),
            "prompt_digest" to (binding as? Map<*, *>)?.get("prompt_digest"),
        ),
    )

    /** The digest a v1 (pre-0.5) reviewer signed: `{permissions, limits, catalog digest}`. Kept so old approvals still load. */
    @JvmStatic fun draftDigest(permissions: Any?, limits: Any?, catalogDigest: Any?): String =
        Pca.hashCanonicalLenient(obj("v" to Json.Num("1"), "permissions" to sortedPerms(permissions), "limits" to limits, "catalog_digest" to catalogDigest))

    private fun lintsOf(permissions: Map<String, Any?>, limits: Map<String, Any?>, catalog: Catalog): List<Any?> =
        if (permissions.isNotEmpty()) PolicySim.lintPolicy(Facade.compilePolicy(permissions, limits, catalog, null, null, 0L), catalog) else emptyList()

    /** Ask the model for a policy, ground it against the catalog and lint the compiled result: `{permissions, limits, unknownVerbs, droppedLimits, raw, lints}`. */
    @JvmStatic @JvmOverloads
    fun policyFromNL(instruction: String, complete: (String) -> String, catalog: Catalog? = null): Map<String, Any?> {
        val cat = catalog ?: Catalog.DEFAULT
        val raw = complete(IntentCompilers.nlPrompt(instruction, cat))
        val parsed = IntentCompilers.parseNLPolicy(raw, cat)
        val out = LinkedHashMap(parsed)
        out["raw"] = raw
        out["lints"] = lintsOf(parsed["permissions"] as Map<String, Any?>, parsed["limits"] as Map<String, Any?>, cat)
        return out
    }

    /** Ask the model for a DRAFT (never enforced). Throws when the completion throws or exceeds [MAX_NL_OUTPUT_BYTES] UTF-8 bytes. */
    @JvmStatic @JvmOverloads
    fun draftPolicyFromNL(instruction: String, complete: (String) -> String, catalog: Catalog? = null, model: String? = null): Map<String, Any?> {
        val cat = catalog ?: Catalog.DEFAULT
        val raw = complete(IntentCompilers.nlPrompt(instruction, cat))
        if (Json.utf8(raw).size > MAX_NL_OUTPUT_BYTES) throw IllegalArgumentException("draftPolicyFromNL: model output exceeds $MAX_NL_OUTPUT_BYTES bytes or is not a string")
        val p = IntentCompilers.parseNLPolicy(raw, cat)
        val perms = p["permissions"] as Map<String, Any?>
        val limits = p["limits"] as Map<String, Any?>
        val lints = lintsOf(perms, limits, cat)
        val cd = catalogDigest(cat)
        val binding = draftBinding(instruction, cat, model)
        return obj(
            "status" to "draft", "instruction" to instruction, "permissions" to perms, "limits" to limits, "catalog_digest" to cd, "binding" to binding,
            "digest" to draftDigestV2(perms, limits, cd, binding), "unknownVerbs" to p["unknownVerbs"], "droppedLimits" to p["droppedLimits"], "lints" to lints,
            "analyzerOk" to (perms.isNotEmpty() && lints.none { (it as? Map<*, *>)?.get("level") == "error" }),
        )
    }

    private fun approvalMessage(a: Map<String, Any?>): ByteArray {
        val domain = if (IntentJs.num(a["v"]) == 2.0) NL_APPROVAL_DOMAIN_V2 else NL_APPROVAL_DOMAIN
        val body = obj("v" to a["v"], "digest" to a["digest"], "catalog_digest" to a["catalog_digest"], "reviewer" to a["reviewer"], "approved_at" to a["approved_at"], "expires_at" to a["expires_at"])
        return Pca.concat(Json.utf8(domain), Pca.canonicalBytesLenient(body))
    }

    private fun num(n: Double) = Json.Num(J.numStr(n))

    /**
     * The human step: sign the exact draft as `reviewer`. Refuses a draft the analyzer rejected or that proposed verbs outside the catalog. `now` (null: the
     * system clock) and `ttlMs` (null: one hour) must be finite, the ttl in (0, 24 hours]. An approval v2.
     */
    @JvmStatic @JvmOverloads
    fun approveDraft(draft: Any?, reviewer: Keys.EdKey, now: Any? = null, ttlMs: Any? = null): Map<String, Any?> = signApproval(draft, reviewer, now, ttlMs, legacy = false)

    /** Pre-0.5 approval (v1): signs the draft WITHOUT the instruction, model or prompt. Only for the legacy-load compatibility window. */
    @JvmStatic @JvmOverloads
    fun approveDraftLegacyV1(draft: Any?, reviewer: Keys.EdKey, now: Any? = null, ttlMs: Any? = null): Map<String, Any?> = signApproval(draft, reviewer, now, ttlMs, legacy = true)

    private fun signApproval(draft: Any?, reviewer: Keys.EdKey, nowRaw: Any?, ttlRaw: Any?, legacy: Boolean): Map<String, Any?> {
        if (draft == null) throw IllegalArgumentException("Cannot read properties of null (reading 'analyzerOk')")
        if (!J.truthy(get(draft, "analyzerOk"))) throw IllegalArgumentException("approveDraft: the draft did not pass the static analyzer")
        val uv = get(draft, "unknownVerbs")
        val any = when {
            uv is List<*> -> uv.isNotEmpty()
            uv is String -> uv.isNotEmpty()
            uv == null || uv === J.UNDEF -> throw IllegalArgumentException("Cannot read properties of ${if (uv == null) "null" else "undefined"} (reading 'length')")
            else -> false
        }
        if (any) throw IllegalArgumentException("approveDraft: the draft proposed verbs that are not in the catalog")
        val now = if (nowRaw == null) System.currentTimeMillis().toDouble() else nowRaw.let { if (IntentJs.isFinite(it)) IntentJs.num(it)!! else Double.NaN }
        val ttl = if (ttlRaw == null) DEFAULT_NL_APPROVAL_TTL_MS.toDouble() else ttlRaw.let { if (IntentJs.isFinite(it)) IntentJs.num(it)!! else Double.NaN }
        if (now.isNaN() || ttl.isNaN() || ttl <= 0 || ttl > MAX_NL_APPROVAL_TTL_MS) throw IllegalArgumentException("approveDraft: invalid time or ttl")
        val digest: Any? = if (legacy) draftDigest(get(draft, "permissions"), get(draft, "limits"), get(draft, "catalog_digest")) else get(draft, "digest")
        val body = obj(
            "v" to Json.Num(if (legacy) "1" else "2"), "digest" to digest, "catalog_digest" to get(draft, "catalog_digest"), "reviewer" to reviewer.id(),
            "approved_at" to num(now), "expires_at" to num(now + ttl),
        )
        val out = LinkedHashMap(body)
        out["sig"] = Keys.b64u(reviewer.sign(approvalMessage(body)))
        return out
    }

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private fun isInt(n: Any?): Boolean = IntentJs.isInt(n)

    private fun isObject(x: Any?): Boolean = x is Map<*, *> || x is List<*>

    /**
     * The only door from a draft to policy: recomputes the digest, the grounding and the lints from the draft's contents and checks the approval (shape, digest,
     * pinned reviewer, ttl, window, signature). `reviewers` are the b64u keys allowed to approve (empty or absent: everything is refused), `catalog` defaults to the
     * built-in one, `now` (null: the system clock) is compared as JavaScript compares it. Returns `{ok: true, permissions, limits, reviewer, instruction,
     * legacy_unbound_instruction}` or `{ok: false, reason}` with the rejection code. Never throws.
     */
    @JvmStatic @JvmOverloads
    fun loadApprovedPolicy(draft: Any?, approval: Any?, reviewers: Any?, catalog: Catalog? = null, now: Any? = null): Map<String, Any?> = try {
        load(draft, approval, reviewers, catalog ?: Catalog.DEFAULT, now)
    } catch (e: RuntimeException) {
        fail("malformed_approval")
    } catch (e: StackOverflowError) {
        fail("malformed_approval")
    }

    private fun load(draft: Any?, a: Any?, reviewers: Any?, cat: Catalog, nowRaw: Any?): Map<String, Any?> {
        val now: Double = if (nowRaw == null) System.currentTimeMillis().toDouble() else J.toNumber(nowRaw)
        if (reviewers !is List<*> || reviewers.isEmpty()) return fail("no_reviewers_pinned")
        if (draft !is Map<*, *> || draft["status"] != "draft" || !isObject(draft["permissions"]) || !isObject(draft["limits"])) return fail("not_a_draft")
        val cd = catalogDigest(cat)
        if (draft["catalog_digest"] != cd) return fail("catalog_mismatch")
        if (draft["instruction"] !is String) return fail("not_a_draft")
        val instruction = draft["instruction"] as String
        val legacyDraft = !draft.containsKey("binding")
        val binding = draft["binding"]
        if (!legacyDraft && !isObject(binding)) return fail("not_a_draft")
        val permissions = draft["permissions"] as? Map<String, Any?> ?: return fail("malformed_approval")
        val limits = draft["limits"]
        if (legacyDraft) {
            if (draftDigest(permissions, limits, cd) != draft["digest"]) return fail("tampered_draft")
        } else {
            val bm = binding as? Map<String, Any?> ?: emptyMap()
            val want = draftBinding(instruction, cat, bm["model"] as? String)
            if (bm["instruction_digest"] != want["instruction_digest"] || bm["prompt_digest"] != want["prompt_digest"] || !bm.containsKey("model") || bm["model"] != want["model"]) return fail("tampered_draft")
            if (draftDigestV2(permissions, limits, cd, want) != draft["digest"]) return fail("tampered_draft")
        }
        for ((c, acts) in permissions) {
            if (acts !is List<*> || acts.any { it !is String || cat.get("$c.$it") == null }) return fail("unknown_verbs")
        }
        val uv = draft["unknownVerbs"]
        if (uv is List<*> && uv.isNotEmpty()) return fail("unknown_verbs")
        if (permissions.isEmpty()) return fail("empty_permissions")
        if (lintsOf(permissions, limits as? Map<String, Any?> ?: emptyMap(), cat).any { (it as? Map<*, *>)?.get("level") == "error" }) return fail("analyzer_error")
        val ap = a as? Map<String, Any?>
        val v = ap?.get("v")
        if (ap == null || (IntentJs.num(v) != 1.0 && IntentJs.num(v) != 2.0) || ap["sig"] !is String || ap["reviewer"] !is String || ap["digest"] !is String || ap["catalog_digest"] !is String ||
            !isInt(ap["approved_at"]) || !isInt(ap["expires_at"])
        ) return fail("malformed_approval")
        val legacy = IntentJs.num(v) == 1.0
        if (legacyDraft && !legacy) return fail("digest_mismatch") // a v2 approval promises the instruction is bound; a binding-less draft cannot honour that
        if (ap["digest"] != (if (legacy) draftDigest(permissions, limits, cd) else draft["digest"]) || ap["catalog_digest"] != cd) return fail("digest_mismatch")
        if (!reviewers.contains(ap["reviewer"])) return fail("reviewer_not_pinned")
        val approvedAt = IntentJs.num(ap["approved_at"])!!
        val expiresAt = IntentJs.num(ap["expires_at"])!!
        if (expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_NL_APPROVAL_TTL_MS) return fail("ttl_too_long")
        if (!(now.isFinite() && approvedAt <= now)) return fail("not_yet_valid")
        if (!(now < expiresAt)) return fail("expired")
        if (!Pca.verifyB64u(ap["reviewer"] as String, approvalMessage(ap), ap["sig"] as String)) return fail("bad_signature")
        return obj("ok" to true, "permissions" to permissions, "limits" to limits, "reviewer" to ap["reviewer"], "instruction" to instruction, "legacy_unbound_instruction" to legacy)
    }

    /** An agent minted from an approved draft: the handle, the approving reviewer and whether the approval is the legacy v1 form. */
    class ApprovedAgent internal constructor(val agent: Facade.Handle, val reviewer: String, val legacyUnboundInstruction: Boolean)

    /**
     * The ONLY natural-language-to-agent path: mints an agent from a draft a pinned reviewer signed. Throws `agentFromApprovedNL: <rejection code>` otherwise;
     * `goal` must equal the approved instruction for an approval v2 (a legacy v1 approval cannot check it). `now` is the clock of the load and of the grant.
     */
    @JvmStatic @JvmOverloads
    fun agentFromApprovedNL(
        draft: Any?, approval: Any?, reviewers: Any?, principal: Keys.SuiteKey, goal: String, catalog: Catalog? = null, now: Any? = null, aud: String? = null, holder: Keys.SuiteKey? = null,
    ): ApprovedAgent {
        val loaded = loadApprovedPolicy(draft, approval, reviewers, catalog, now)
        if (loaded["ok"] != true) throw IllegalArgumentException("agentFromApprovedNL: ${loaded["reason"]}")
        val legacy = loaded["legacy_unbound_instruction"] == true
        if (!legacy && goal != loaded["instruction"]) throw IllegalArgumentException("agentFromApprovedNL: goal_mismatch")
        val nowMs = if (now == null) null else IntentJs.num(now)?.toLong()
        val handle = Facade.agent(
            Facade.AgentOptions(
                principal = principal, goal = goal, permissions = loaded["permissions"] as Map<String, Any?>, limits = loaded["limits"] as? Map<String, Any?>, holder = holder, catalog = catalog,
                aud = aud, now = nowMs,
            ),
        )
        return ApprovedAgent(handle, loaded["reviewer"] as String, legacy)
    }
}
