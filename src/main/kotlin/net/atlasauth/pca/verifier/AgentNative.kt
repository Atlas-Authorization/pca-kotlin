package net.atlasauth.pca.verifier

import java.security.SecureRandom

/**
 * Agent-native authority primitives (the TypeScript `agent-native` module): uncertainty attestation, rationale binding, the
 * semantic firewall, capability introspection and authority leases. Pure and deterministic: no clocks (callers pass `now`), no
 * randomness except the default rationale salt. The verifying and evaluating functions are total and fail closed; only the authoring
 * helpers ([bindRationale], [toolSchemaCaveat], [grantLease], [predicatesCaveat]) throw [IllegalArgumentException]. Values are JSON
 * trees (maps, lists, strings, numbers, booleans, null), the same shape as the reference, so artefacts round-trip with every other
 * implementation. `signCaution` / `signHeartbeat` live in [SignersMore], `validateArgSchema` / `evaluateToolSchema` in [Authorize].
 *
 * [renewCapabilityLease] is the reference's pure `renewLease(lease, heartbeat, now)`; the grants registry keeps its own `renewLease`.
 */
@Suppress("UNCHECKED_CAST")
object AgentNative {
    // ---- constants ----

    const val CAVEAT_ENVELOPE = "envelope"
    const val CAVEAT_EXPIRES = "expires"
    const val CAVEAT_NOT_BEFORE = "not_before"
    const val CAVEAT_RATE = "rate"
    const val CAVEAT_MAX_BLAST_RADIUS = "max_blast_radius"
    const val CAVEAT_REVERSIBILITY_MAX = "reversibility_max"
    const val CAVEAT_DELEGATION_DEPTH = "delegation_depth"
    const val CAVEAT_PREDICATES = "predicates"
    const val CAVEAT_TOOL_SCHEMA = "tool_schema"
    const val CAVEAT_MAX_SPEND = "max_spend"
    const val MAX_CAUTION_REASON_LEN = SignersMore.MAX_CAUTION_REASON_LEN
    const val MIN_SALT_BYTES = 16
    const val MIN_SALT_DISTINCT_BYTES = 8
    const val MAX_RATIONALE_LEN = 8192
    const val MAX_SCHEMA_DEPTH = Authorize.MAX_SCHEMA_DEPTH
    const val MAX_SCHEMA_NODES = Authorize.MAX_SCHEMA_NODES
    const val MAX_OBJECT_PROPS = Authorize.MAX_OBJECT_PROPS
    const val MAX_ENUM_VALUES = Authorize.MAX_ENUM_VALUES
    const val DEFAULT_MAX_ARRAY_ITEMS = Authorize.DEFAULT_MAX_ARRAY_ITEMS
    const val ABSOLUTE_MAX_ARRAY_ITEMS = Authorize.ABSOLUTE_MAX_ARRAY_ITEMS
    const val DEFAULT_MAX_STRING_LEN = Authorize.DEFAULT_MAX_STRING_LEN
    const val ABSOLUTE_MAX_STRING_LEN = Authorize.ABSOLUTE_MAX_STRING_LEN
    const val MAX_VALUE_NODES = Authorize.MAX_VALUE_NODES

    /** Max tolerated skew between a heartbeat's `at` (or the clock vs the last renewal) and server `now`. */
    const val HEARTBEAT_SKEW_MS = 30_000L

    /** Longest lease ttl accepted (7 days). */
    const val MAX_LEASE_TTL_MS = 7L * 24 * 3_600_000L

    /** Every constant above by its reference name (the corpus `constants` case). */
    fun constants(): Map<String, Any?> = linkedMapOf(
        "CAVEAT_ENVELOPE" to CAVEAT_ENVELOPE, "CAVEAT_EXPIRES" to CAVEAT_EXPIRES, "CAVEAT_NOT_BEFORE" to CAVEAT_NOT_BEFORE,
        "CAVEAT_RATE" to CAVEAT_RATE, "CAVEAT_MAX_BLAST_RADIUS" to CAVEAT_MAX_BLAST_RADIUS,
        "CAVEAT_REVERSIBILITY_MAX" to CAVEAT_REVERSIBILITY_MAX, "CAVEAT_DELEGATION_DEPTH" to CAVEAT_DELEGATION_DEPTH,
        "CAVEAT_PREDICATES" to CAVEAT_PREDICATES, "CAVEAT_TOOL_SCHEMA" to CAVEAT_TOOL_SCHEMA, "CAVEAT_MAX_SPEND" to CAVEAT_MAX_SPEND,
        "MAX_CAUTION_REASON_LEN" to MAX_CAUTION_REASON_LEN, "MIN_SALT_BYTES" to MIN_SALT_BYTES,
        "MIN_SALT_DISTINCT_BYTES" to MIN_SALT_DISTINCT_BYTES, "MAX_RATIONALE_LEN" to MAX_RATIONALE_LEN,
        "MAX_SCHEMA_DEPTH" to MAX_SCHEMA_DEPTH, "MAX_SCHEMA_NODES" to MAX_SCHEMA_NODES, "MAX_OBJECT_PROPS" to MAX_OBJECT_PROPS,
        "MAX_ENUM_VALUES" to MAX_ENUM_VALUES, "DEFAULT_MAX_ARRAY_ITEMS" to DEFAULT_MAX_ARRAY_ITEMS,
        "ABSOLUTE_MAX_ARRAY_ITEMS" to ABSOLUTE_MAX_ARRAY_ITEMS, "DEFAULT_MAX_STRING_LEN" to DEFAULT_MAX_STRING_LEN,
        "ABSOLUTE_MAX_STRING_LEN" to ABSOLUTE_MAX_STRING_LEN, "MAX_VALUE_NODES" to MAX_VALUE_NODES,
        "HEARTBEAT_SKEW_MS" to HEARTBEAT_SKEW_MS, "MAX_LEASE_TTL_MS" to MAX_LEASE_TTL_MS,
    )

    // ---- helpers ----

    /** A finite JSON number as a double (a Boolean or a String is never a number), else null. */
    private fun fin(o: Any?): Double? {
        val d: Double = when (o) {
            is Json.Num -> o.raw.toDoubleOrNull() ?: return null
            is Double, is Float, is Int, is Long, is Short, is Byte, is java.math.BigDecimal, is java.math.BigInteger -> (o as Number).toDouble()
            else -> return null
        }
        return if (d.isFinite()) d else null
    }

    private fun nonEmpty(x: Any?): Boolean = x is String && x.isNotEmpty()

    private fun msgOf(domain: String, body: Any?): ByteArray = Pca.canonBytes(Issue.obj("d" to domain, "b" to body))

    private fun clamp01(x: Double): Double = Math.min(1.0, Math.max(0.0, x))

    /** `Number.isInteger(x)` on a JSON value (a non-number is false). */
    private fun isInteger(o: Any?): Boolean {
        val d = IntentJs.num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.floor(d)
    }

    private fun isNonNegInteger(o: Any?): Boolean = isInteger(o) && IntentJs.num(o)!! >= 0 && !IntentJs.isNegZero(IntentJs.num(o)!!)

    private fun cloneLenient(x: Any?): Any? = Json.parseLenient(Json.canonicalize(x))

    private fun hash(v: Any?): String = Pca.hashCanonical(v)

    /** JavaScript `===` on JSON scalars (numbers by double value, null equals null). */
    private fun jsEq(a: Any?, b: Any?): Boolean {
        val fa = IntentJs.num(a)
        val fb = IntentJs.num(b)
        if (fa != null || fb != null) return fa != null && fb != null && fa == fb
        if (a == null || b == null) return a == null && b == null
        if (a is Boolean || b is Boolean) return a is Boolean && b is Boolean && a == b
        return a is String && b is String && a == b
    }

    // ======================================================================================================================
    // 1. Uncertainty attestation (monotone self-escalation)
    // ======================================================================================================================

    private val CAUTION_KEYS = listOf("action_digest", "caution", "reason", "holder", "sig")

    /**
     * Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by `claim.holder`, bound to
     * [expectedActionDigest] (when given, i.e. not null) and signed by [expectedHolder] (when given). Total.
     */
    fun verifyCaution(claim: Any?, expectedActionDigest: Any? = null, expectedHolder: Any? = null): Boolean =
        verifyCautionImpl(claim, expectedActionDigest != null, expectedActionDigest, expectedHolder != null, expectedHolder)

    private fun verifyCautionImpl(claimO: Any?, hasDigest: Boolean, digest: Any?, hasHolder: Boolean, holder: Any?): Boolean = try {
        if (claimO !is Map<*, *>) false
        else if (claimO["sig"] !is String) false
        else if (!claimO.keys.all { it in CAUTION_KEYS }) false
        else if (SignersMore.cautionBodyError(claimO) != null) false
        else if (hasDigest && claimO["action_digest"] != digest) false
        else if (hasHolder && claimO["holder"] != holder) false
        else {
            val body = LinkedHashMap<String, Any?>()
            for ((k, v) in claimO) if (k != "sig") body[k as String] = v
            Pca.verifyB64u(claimO["holder"] as String, msgOf("atlas-pca/caution/v1", body), claimO["sig"] as String)
        }
    } catch (e: RuntimeException) {
        false
    } catch (e: StackOverflowError) {
        false
    }

    /**
     * `max(agentDeclaredCaution, serverRisk)`: always at least [serverRisk] (clamped to [0,1]) and non-decreasing in the declared
     * value. An unusable declaration (null, NaN, an infinity, a non-number) is ignored; an unusable [serverRisk] fails closed to 1.
     */
    fun combineCaution(agentDeclaredCaution: Any?, serverRisk: Any?): Double {
        val sv = fin(serverRisk)
        val s = if (sv == null) 1.0 else clamp01(sv)
        val d = fin(agentDeclaredCaution) ?: return s
        return Math.max(clamp01(d), s)
    }

    /**
     * As [combineCaution] for a signed claim: only a valid claim bound to THIS action (and, when [expectedHolder] is not null, to
     * THIS holder) is honoured. Returns `{effectiveRisk, honoured, escalated}`.
     */
    fun combineSignedCaution(claim: Any?, actionDigest: Any?, serverRisk: Any?, expectedHolder: Any? = null): Map<String, Any?> {
        val sv = fin(serverRisk)
        val s = if (sv == null) 1.0 else clamp01(sv)
        val ok = claim != null && verifyCautionImpl(claim, true, actionDigest, expectedHolder != null, expectedHolder)
        val eff = combineCaution(if (ok) (claim as Map<*, *>)["caution"] else null, s)
        return Issue.obj("effectiveRisk" to eff, "honoured" to ok, "escalated" to (eff > s))
    }

    /** Exhaustive-grid check of the monotonicity property: `{ok: true}`, or `{ok: false, counterexample: [d, s]}`. */
    fun checkCautionMonotone(grid: Any?): Map<String, Any?> {
        if (grid !is List<*>) throw IllegalArgumentException("checkCautionMonotone: grid must be an array")
        val g = grid.mapNotNull { fin(it) }
        for (s in g) {
            for (d in g) {
                val e = combineCaution(d, s)
                if (e < clamp01(s)) return Issue.obj("ok" to false, "counterexample" to listOf<Any?>(d, s))
                for (d2 in g) if (d2 >= d && combineCaution(d2, s) < e) return Issue.obj("ok" to false, "counterexample" to listOf<Any?>(d2, s))
            }
        }
        return Issue.obj("ok" to true)
    }

    // ======================================================================================================================
    // 2. Rationale binding (commit / reveal)
    // ======================================================================================================================

    /**
     * Entropy floor of a commitment salt: base64url (no padding, canonical) that decodes to at least 16 bytes with at least 8
     * distinct byte values, at most 256 characters.
     */
    fun isStrongSalt(salt: Any?): Boolean {
        if (salt !is String || salt.isEmpty() || salt.length > 256) return false
        for (c in salt) if (!((c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '_' || c == '-')) return false
        val b = Pca.decodeB64uStrict(salt, -1) ?: return false
        return b.size >= MIN_SALT_BYTES && b.toSet().size >= MIN_SALT_DISTINCT_BYTES
    }

    private fun commitDigest(actionDigest: String, salt: Any?, rationale: String): String =
        hash(Issue.obj("d" to "atlas-pca/rationale/v1", "a" to actionDigest, "s" to salt, "r" to rationale))

    /** [bindRationale] with a fresh 32-byte random salt. */
    fun bindRationale(action: Any?, rationale: Any?): Map<String, Any?> = bindRationale(action, rationale, Pca.b64(ByteArray(32).also { SecureRandom().nextBytes(it) }))

    /**
     * The agent commits to its stated reason: returns `{commitment: {v, action_digest, commitment}, reveal: {rationale, salt}}`.
     * Publish the commitment, KEEP the reveal. Throws on a non-string or oversized rationale, a weak salt ([isStrongSalt]) or a
     * non-canonicalizable action.
     */
    fun bindRationale(action: Any?, rationale: Any?, salt: Any?): Map<String, Any?> {
        if (rationale !is String) throw IllegalArgumentException("bindRationale: rationale must be a string")
        if (rationale.length > MAX_RATIONALE_LEN) throw IllegalArgumentException("bindRationale: rationale too long")
        if (!isStrongSalt(salt)) throw IllegalArgumentException("bindRationale: salt must be b64u of >=$MIN_SALT_BYTES bytes with >=$MIN_SALT_DISTINCT_BYTES distinct values")
        val ad = hash(action)
        return Issue.obj(
            "commitment" to Issue.obj("v" to 1L, "action_digest" to ad, "commitment" to commitDigest(ad, salt, rationale)),
            "reveal" to Issue.obj("rationale" to rationale, "salt" to salt),
        )
    }

    private fun isOne(v: Any?): Boolean = (v is Json.Num || v is Number) && IntentJs.num(v) == 1.0

    /** Does the revealed rationale open the commitment? A reveal with a weak salt is rejected even if it hashes correctly. Total. */
    fun verifyRationale(commitment: Any?, reveal: Any?): Boolean = verifyRationaleImpl(commitment, reveal, false, null)

    /** As [verifyRationale], additionally requiring the commitment to be for this very [action]. */
    fun verifyRationale(commitment: Any?, reveal: Any?, action: Any?): Boolean = verifyRationaleImpl(commitment, reveal, true, action)

    private fun verifyRationaleImpl(commitment: Any?, reveal: Any?, hasAction: Boolean, action: Any?): Boolean = try {
        if (commitment !is Map<*, *> || reveal !is Map<*, *>) false
        else if (!isOne(commitment["v"]) || !nonEmpty(commitment["action_digest"]) || !nonEmpty(commitment["commitment"])) false
        else {
            val rat = reveal["rationale"]
            if (rat !is String || rat.length > MAX_RATIONALE_LEN || !isStrongSalt(reveal["salt"])) false
            else if (hasAction && hash(action) != commitment["action_digest"]) false
            else commitDigest(commitment["action_digest"] as String, reveal["salt"], rat) == commitment["commitment"]
        }
    } catch (e: RuntimeException) {
        false
    } catch (e: StackOverflowError) {
        false
    }

    private fun audit(verdict: String, slashable: Boolean, evidence: Map<String, Any?>): Map<String, Any?> =
        Issue.obj("verdict" to verdict, "slashable" to slashable, "evidence" to evidence)

    /**
     * After-the-fact audit. [judge] returns exactly `true` for a consistent rationale (anything else is a false one); a throwing
     * judge is `judge_error`. [reveal] may be null (never opened). Returns `{verdict, slashable, evidence}`; `malformed`,
     * `wrong_action` and `judge_error` are never slashable. Total.
     */
    fun auditRationale(commitment: Any?, action: Any?, reveal: Any?, judge: (String, Any?) -> Any?): Map<String, Any?> {
        val cm = commitment as? Map<*, *>
        val evidence = Issue.obj(
            "commitment" to (if (cm != null && cm["commitment"] is String) cm["commitment"] else ""),
            "action_digest" to (if (cm != null && cm["action_digest"] is String) cm["action_digest"] else ""),
        )
        return try {
            if (cm == null || !isOne(cm["v"]) || !nonEmpty(cm["action_digest"]) || !nonEmpty(cm["commitment"])) audit("malformed", false, evidence)
            else if (hash(action) != cm["action_digest"]) audit("wrong_action", false, evidence)
            else if (reveal == null || !verifyRationaleImpl(commitment, reveal, true, action)) audit("unopened", true, evidence)
            else {
                val rationale = (reveal as Map<*, *>)["rationale"] as String
                val opened = LinkedHashMap(evidence)
                opened["rationale"] = rationale
                val ok = try {
                    judge(rationale, action) == true
                } catch (e: RuntimeException) {
                    return audit("judge_error", false, opened)
                } catch (e: StackOverflowError) {
                    return audit("judge_error", false, opened)
                }
                audit(if (ok) "consistent" else "false_rationale", !ok, opened)
            }
        } catch (e: RuntimeException) {
            audit("malformed", false, evidence)
        } catch (e: StackOverflowError) {
            audit("malformed", false, evidence)
        }
    }

    // ======================================================================================================================
    // 3. Semantic firewall
    // ======================================================================================================================

    private fun bindingOf(tool: Any?, signatureDigest: Any?, schema: Any?): String =
        hash(Issue.obj("tool" to tool, "signature_digest" to signatureDigest, "schema" to schema))

    /**
     * Build a `tool_schema` caveat for one tool: authority exists only for that exact tool, signature and (nested) argument schema.
     * Throws when the signature names no tool, the schema is invalid ([Authorize.validateArgSchema]) or anything is not
     * canonicalizable. The schema is deep-cloned in canonical form.
     */
    fun toolSchemaCaveat(toolSignature: Any?, argSchema: Any?): Map<String, Any?> {
        val tool = if (toolSignature is String) toolSignature else if (toolSignature is Map<*, *> && toolSignature["name"] is String) toolSignature["name"] as String else ""
        if (tool.isEmpty()) throw IllegalArgumentException("toolSchemaCaveat: tool name required")
        val err = Authorize.validateArgSchema(argSchema)
        if (err != null) throw IllegalArgumentException("toolSchemaCaveat: $err")
        val schema = cloneLenient(argSchema)
        val sig = hash(toolSignature)
        return Issue.obj(
            "type" to CAVEAT_TOOL_SCHEMA, "tool" to tool, "signature_digest" to sig, "schema" to schema,
            "schema_digest" to hash(schema), "binding_digest" to bindingOf(tool, sig, schema),
        )
    }

    /** Evaluator for a `tool_schema` caveat; `ctx = {toolCall}`. Anything else is unsatisfied. */
    fun toolSchemaEvaluator(caveat: Any?, ctx: Any?): Boolean {
        if (ctx !is Map<*, *> || ctx["toolCall"] !is Map<*, *>) return false
        return Authorize.evaluateToolSchema(caveat, ctx["toolCall"]).ok
    }

    /** The delegated-narrowing caveat `{type: "predicates", allow}` (deep-cloned canonical form; throws on a non-finite number). */
    fun predicatesCaveat(allow: Any?): Map<String, Any?> = Issue.obj("type" to CAVEAT_PREDICATES, "allow" to cloneLenient(allow))

    /**
     * The action's spend in USD as `max_spend` reads it: an own `action.action.params.amount` (finite, >= 0) with an own `currency`,
     * when present, of "usd" / "USD". Null when there is no readable spend.
     */
    fun actionSpendUsd(action: Any?): Double? {
        val act = (action as? Map<*, *>)?.get("action") as? Map<*, *> ?: return null
        val params = act["params"] as? Map<*, *> ?: return null
        if (!params.containsKey("amount")) return null
        val amount = fin(params["amount"])
        if (amount == null || amount < 0) return null
        if (params.containsKey("currency") && params["currency"] != "usd" && params["currency"] != "USD") return null
        return amount
    }

    /** The stock evaluator reads the camel-case context members (`blastRadius`, ...); the shared caveat engine here names them in snake case. */
    private fun stockContext(ctx: Map<*, *>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in listOf("now", "action")) if (ctx.containsKey(k)) m[k] = ctx[k]
        for ((camel, snake) in listOf("recentActionTimes" to "recent_action_times", "blastRadius" to "blast_radius", "reversibilityClass" to "reversibility_class", "delegationDepth" to "delegation_depth")) {
            if (ctx.containsKey(camel)) m[snake] = ctx[camel]
        }
        return m
    }

    /**
     * Superset of the stock caveat evaluator: adds `predicates` (needs `ctx.action`), `max_spend` (needs `ctx.action`) and
     * `tool_schema` (needs `ctx.toolCall`); anything else defers to the stock evaluator (unknown types fail closed). Total.
     */
    fun agentNativeCaveatEvaluator(caveat: Any?, ctx: Any?): Boolean = try {
        if (caveat !is Map<*, *> || ctx !is Map<*, *>) false
        else when (caveat["type"]) {
            CAVEAT_TOOL_SCHEMA -> toolSchemaEvaluator(caveat, ctx)
            CAVEAT_PREDICATES -> {
                val a = ctx["action"]
                val allow = caveat["allow"]
                if (a !is Map<*, *> || allow !is List<*>) false else allow.any { Predicates.predicateMatches(it, a as Map<String, Any?>) }
            }
            CAVEAT_MAX_SPEND -> {
                val lim = fin(caveat["usd"])
                val spend = actionSpendUsd(ctx["action"])
                lim != null && spend != null && spend <= lim
            }
            else -> Caveats.evaluateCaveats(listOf(caveat), stockContext(ctx)).ok
        }
    } catch (e: RuntimeException) {
        false
    } catch (e: StackOverflowError) {
        false
    }

    // ======================================================================================================================
    // 4. Capability introspection
    // ======================================================================================================================

    private val REV = listOf("reversible", "rate_limited", "irreversible")
    private val UNDECIDED = Any()

    private fun sortedUnique(items: Collection<Any?>): MutableList<Any?> {
        val s = LinkedHashSet<String>()
        for (o in items) s.add(o as String)
        return s.sortedWith { a, b -> Json.compareUtf8(a, b) }.toMutableList<Any?>()
    }

    private fun intersectVerbs(a: List<Any?>, b: List<Any?>): MutableList<Any?> {
        if (a.contains("*")) return sortedUnique(b)
        if (b.contains("*")) return sortedUnique(a)
        return sortedUnique(a.filter { b.contains(it) })
    }

    /** Intersect two resource patterns: null = empty, [UNDECIDED] = cannot decide symbolically (regex). */
    private fun interRes(a: String, b: String): Any? {
        if (a == b) return a
        if (a.startsWith("re:") || b.startsWith("re:")) return UNDECIDED
        if (a == "*") return b
        if (b == "*") return a
        val ap = a.endsWith("*")
        val bp = b.endsWith("*")
        if (ap && bp) {
            val pa = a.dropLast(1)
            val pb = b.dropLast(1)
            return if (pb.startsWith(pa)) b else if (pa.startsWith(pb)) a else null
        }
        if (ap) return if (b.startsWith(a.dropLast(1))) b else null
        if (bp) return if (a.startsWith(b.dropLast(1))) a else null
        return null
    }

    /** Collapse a conjunction of resource patterns; null = unsatisfiable. */
    private fun collapseResources(list: List<Any?>): MutableList<Any?>? {
        var lit: String? = null
        val res = LinkedHashSet<String>()
        for (po in list) {
            val p = po as String
            if (p.startsWith("re:")) { res.add(p); continue }
            if (lit == null) lit = p
            else {
                val r = interRes(lit, p)
                if (r == null || r === UNDECIDED) return null
                lit = r as String
            }
        }
        val out = ArrayList<Any?>()
        if (lit != null && lit != "*") out.add(lit)
        out.addAll(res.sortedWith { a, b -> Json.compareUtf8(a, b) })
        if (out.isEmpty()) out.add("*")
        return out
    }

    private fun scope(verbs: List<Any?>, resources: List<Any?>, where: List<Any?>): LinkedHashMap<String, Any?> =
        Issue.obj("verbs" to verbs, "resources" to resources, "where" to where)

    private fun universe(): LinkedHashMap<String, Any?> = scope(arrayListOf<Any?>("*"), arrayListOf<Any?>("*"), arrayListOf())

    private fun scopeOfPredicate(p: Any?): LinkedHashMap<String, Any?>? {
        if (p !is Map<*, *>) return null
        val verb = p["verb"]
        val verbs: List<Any?> = when {
            verb is String -> listOf(verb)
            verb is List<*> -> { if (!verb.all { it is String }) return null; verb.toList() }
            else -> return null
        }
        if (p.containsKey("resource") && p["resource"] !is String) return null
        val where: List<Any?> = if (!p.containsKey("where")) arrayListOf() else (p["where"] as? List<Any?>) ?: return null
        return scope(sortedUnique(verbs), arrayListOf<Any?>(if (p.containsKey("resource")) p["resource"] else "*"), where)
    }

    private fun intersectScopes(a: List<Map<String, Any?>>, b: List<Map<String, Any?>>): List<Map<String, Any?>> {
        val out = LinkedHashMap<String, Map<String, Any?>>()
        for (x in a) {
            for (y in b) {
                val verbs = intersectVerbs(x["verbs"] as List<Any?>, y["verbs"] as List<Any?>)
                if (verbs.isEmpty()) continue
                val resources = collapseResources((x["resources"] as List<Any?>) + (y["resources"] as List<Any?>)) ?: continue
                val s = scope(verbs, resources, (x["where"] as List<Any?>) + (y["where"] as List<Any?>))
                out[hash(s)] = s
            }
        }
        return out.keys.sorted().map { out[it]!! }
    }

    private fun scopeMatches(s: Map<String, Any?>, verb: Any?, resource: Any?, params: Any?): Boolean {
        val verbs = s["verbs"] as List<Any?>
        if (!verbs.contains("*") && !verbs.contains(verb)) return false
        val action = Issue.obj("verb" to verb, "resource" to resource)
        if (params != null) action["params"] = params
        val ctx = Issue.obj("action" to action)
        for (r in s["resources"] as List<Any?>) if (!Predicates.predicateMatches(Issue.obj("verb" to "*", "resource" to r), ctx)) return false
        if (params != null && (s["where"] as List<Any?>).isNotEmpty()) return Predicates.predicateMatches(Issue.obj("verb" to "*", "where" to s["where"]), ctx)
        return true
    }

    /** Is this caveat one the verifier (stock evaluator + this module's superset) can satisfy at all? */
    private fun wellFormedCaveat(cv: Map<*, *>): Boolean = when (cv["type"]) {
        CAVEAT_EXPIRES, CAVEAT_NOT_BEFORE -> fin(cv["at"]) != null
        CAVEAT_RATE -> { val m = fin(cv["max"]); val p = fin(cv["per_secs"]); m != null && p != null && p > 0 }
        CAVEAT_MAX_BLAST_RADIUS, CAVEAT_DELEGATION_DEPTH -> fin(cv["max"]) != null
        CAVEAT_REVERSIBILITY_MAX -> cv["class"].let { it is String && REV.contains(it) }
        CAVEAT_PREDICATES -> cv["allow"] is List<*> && (cv["allow"] as List<*>).all { scopeOfPredicate(it) != null }
        CAVEAT_TOOL_SCHEMA -> nonEmpty(cv["tool"])
        "budget_alloc" -> { val l = fin(cv["limit"]); l != null && l >= 0 }
        CAVEAT_MAX_SPEND -> { val l = fin(cv["usd"]); l != null && l >= 0 }
        else -> false
    }

    /** The mutable state of one [describeEnvelope] fold. */
    private class Fold(val chainLen: Int) {
        var scopes: List<Map<String, Any?>>? = null
        var tools: MutableList<Any?>? = null
        var seenEnvelope = false
        val bad = LinkedHashSet<String>()
        val toolSchemas = ArrayList<Any?>()
        var expiresAt: Double? = null
        var notBefore: Double? = null
        var maxBlast: Double? = null
        var depthRem: Double? = null
        var budgetAlloc: Double? = null
        var maxSpend: Double? = null
        var maxRate: DoubleArray? = null
        var revMax: String? = null

        fun fold(cvO: Any?, inEnvelope: Boolean) {
            if (cvO !is Map<*, *> || cvO["type"] !is String) { bad.add("<malformed>"); return }
            val type = cvO["type"] as String
            if (type == CAVEAT_ENVELOPE) {
                // only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied
                if (seenEnvelope || inEnvelope) bad.add(CAVEAT_ENVELOPE)
                seenEnvelope = true
                return
            }
            if (!wellFormedCaveat(cvO)) { bad.add(type); return }
            when (type) {
                CAVEAT_PREDICATES -> {
                    val next = (cvO["allow"] as List<Any?>).map { scopeOfPredicate(it)!! }
                    scopes = intersectScopes(scopes ?: listOf(universe()), next)
                }
                CAVEAT_TOOL_SCHEMA -> {
                    toolSchemas.add(cvO)
                    val consistent = Authorize.validateArgSchema(cvO["schema"]) == null &&
                        hash(cvO["schema"]) == cvO["schema_digest"] &&
                        bindingOf(cvO["tool"], IntentRevocation.jsText(cvO["signature_digest"], cvO.containsKey("signature_digest")), cvO["schema"]) == cvO["binding_digest"]
                    val cur = tools
                    if (!consistent) { tools = ArrayList(); bad.add(CAVEAT_TOOL_SCHEMA) }
                    else if (cur == null) tools = arrayListOf(cvO["tool"])
                    else tools = cur.filter { it == cvO["tool"] }.toMutableList()
                }
                CAVEAT_EXPIRES -> { val at = fin(cvO["at"])!!; expiresAt = expiresAt?.let { Math.min(it, at) } ?: at }
                CAVEAT_NOT_BEFORE -> { val at = fin(cvO["at"])!!; notBefore = notBefore?.let { Math.max(it, at) } ?: at }
                CAVEAT_RATE -> {
                    val m = fin(cvO["max"])!!
                    val p = fin(cvO["per_secs"])!!
                    val cur = maxRate
                    // the lower sustained rate (max / per_secs) binds; ties go to the smaller max
                    if (cur == null || m / p < cur[0] / cur[1] || (m / p == cur[0] / cur[1] && m < cur[0])) maxRate = doubleArrayOf(m, p)
                }
                CAVEAT_MAX_BLAST_RADIUS -> { val m = fin(cvO["max"])!!; maxBlast = maxBlast?.let { Math.min(it, m) } ?: m }
                CAVEAT_REVERSIBILITY_MAX -> {
                    val i = REV.indexOf(cvO["class"] as String)
                    val j = revMax?.let { REV.indexOf(it) } ?: REV.size
                    if (i < j) revMax = REV[i]
                }
                CAVEAT_DELEGATION_DEPTH -> {
                    val rem = fin(cvO["max"])!! - (chainLen - 1)
                    depthRem = depthRem?.let { Math.min(it, rem) } ?: rem
                }
                "budget_alloc" -> { val l = fin(cvO["limit"])!!; budgetAlloc = budgetAlloc?.let { Math.min(it, l) } ?: l }
                CAVEAT_MAX_SPEND -> { val l = fin(cvO["usd"])!!; maxSpend = maxSpend?.let { Math.min(it, l) } ?: l }
            }
        }
    }

    private fun emptyEnvelope(): LinkedHashMap<String, Any?> = Issue.obj(
        "ok" to false, "hasEnvelope" to false, "scopes" to ArrayList<Any?>(), "verbs" to ArrayList<Any?>(), "resources" to ArrayList<Any?>(),
        "opaqueResourceConstraints" to ArrayList<Any?>(), "tools" to ArrayList<Any?>(), "toolSchemas" to ArrayList<Any?>(),
        "unsatisfiable" to ArrayList<Any?>(), "caveats" to ArrayList<Any?>(), "remainingBudgetHints" to LinkedHashMap<String, Any?>(),
    )

    /**
     * What an attenuated chain permits NOW: the intersection across every hop of the root `envelope.predicates`, each appended
     * `predicates` / `tool_schema` caveat and the built-in caveats, exactly the set the verifier would accept. Returns the
     * `AuthorityEnvelope` as a JSON map: `{ok, reason?, hasEnvelope, scopes, verbs, resources, opaqueResourceConstraints, tools,
     * toolSchemas, unsatisfiable, caveats, remainingBudgetHints}`. `scopes` / `verbs` / `resources` / `tools` are null when
     * unrestricted. A caveat the verifier cannot satisfy makes the envelope unsatisfiable (nothing is permitted). [policy] may carry
     * `allowedSuites`, `pqPins`, `trustedRoot`. A chain that does not verify gives `ok: false` with the verifier's reason.
     * Deterministic (`now` supplied) and total.
     */
    fun describeEnvelope(chain: Any?, now: Any? = null, expectedRootIssuer: String? = null, policy: Map<String, Any?>? = null): Map<String, Any?> {
        val empty = emptyEnvelope()
        try {
            val ch = (chain as? List<Any?>) ?: emptyList()
            val allowed = (policy?.get("allowedSuites") as? List<*>)?.map { it as String }
            val pins = policy?.get("pqPins") as? Map<String, Any?>
            val trusted = policy?.get("trustedRoot") as? Map<String, Any?>
            val why = Pca.verifyChain(ch, expectedRootIssuer ?: "", expectedRootIssuer != null, allowed, pins, trusted)
            if (why.isNotEmpty()) { empty["reason"] = why; return empty }

            val root = ch[0] as Map<String, Any?>
            val leaf = ch[ch.size - 1] as Map<String, Any?>
            val env0 = Authorize.readEnvelope(root)
            val env = emptyEnvelope()
            env["ok"] = true
            env["hasEnvelope"] = env0 != null
            env["caveats"] = leaf["caveats"]
            val f = Fold(ch.size)

            if (env0 != null) {
                val base = ArrayList<Map<String, Any?>>()
                for (p in env0["predicates"] as List<Any?>) {
                    val s = scopeOfPredicate(p)
                    if (s == null) f.bad.add("envelope.predicates") else base.add(s)
                }
                f.scopes = intersectScopes(base, listOf(universe()))
            }
            if (env0 != null) for (cv in env0["caveats"] as List<Any?>) f.fold(cv, true)
            for (cv in leaf["caveats"] as List<Any?>) f.fold(cv, false)

            val opaque = LinkedHashSet<String>()
            val scopes = f.scopes
            if (scopes != null) {
                val vs = LinkedHashSet<String>()
                val rs = LinkedHashSet<String>()
                for (s in scopes) {
                    for (v in s["verbs"] as List<Any?>) vs.add(v as String)
                    for (r in s["resources"] as List<Any?>) { rs.add(r as String); if (r.startsWith("re:")) opaque.add(r) }
                }
                env["scopes"] = ArrayList<Any?>(scopes)
                env["verbs"] = sortedUnique(vs)
                env["resources"] = sortedUnique(rs)
            } else {
                env["scopes"] = null
                env["verbs"] = null
                env["resources"] = null
            }
            env["opaqueResourceConstraints"] = sortedUnique(opaque)
            env["tools"] = f.tools?.let { sortedUnique(it) }
            env["toolSchemas"] = f.toolSchemas
            val unsat = sortedUnique(f.bad)
            env["unsatisfiable"] = unsat
            if (unsat.isNotEmpty()) {
                env["scopes"] = ArrayList<Any?>()
                env["verbs"] = ArrayList<Any?>()
                env["resources"] = ArrayList<Any?>()
                env["tools"] = ArrayList<Any?>()
                env["reason"] = "unsatisfiable caveat(s): " + unsat.joinToString(", ")
            }
            val h = env["remainingBudgetHints"] as MutableMap<String, Any?>
            f.expiresAt?.let { h["expiresAt"] = it }
            val nowF = fin(now)
            if (f.expiresAt != null && nowF != null) h["expiresIn"] = f.expiresAt!! - nowF
            f.maxRate?.let { h["maxRate"] = Issue.obj("max" to it[0], "per_secs" to it[1]) }
            f.maxBlast?.let { h["maxBlastRadius"] = it }
            f.revMax?.let { h["reversibilityMax"] = it }
            f.depthRem?.let { h["delegationDepthRemaining"] = it }
            f.notBefore?.let { h["notBefore"] = it }
            f.budgetAlloc?.let { h["budgetAlloc"] = it }
            f.maxSpend?.let { h["maxSpendUsd"] = it }
            return env
        } catch (e: RuntimeException) {
            return emptyEnvelope().also { it["reason"] = "introspection error (fail closed)" }
        } catch (e: StackOverflowError) {
            return emptyEnvelope().also { it["reason"] = "introspection error (fail closed)" }
        }
    }

    /**
     * Pre-flight an agent can run before attempting. False is definitive (the verifier will refuse); true means the symbolic
     * envelope allows it. When [params] is given the `where` conditions are evaluated too (fail closed); [now] and [params] are null
     * when not given. Total.
     */
    fun envelopePermits(envO: Any?, verb: Any?, resource: Any?, now: Any? = null, params: Any? = null): Boolean = try {
        val env = envO as? Map<String, Any?>
        if (env == null) false
        else if (!IntentRevocation.truthy(env["ok"]) || (env["unsatisfiable"] as List<*>).isNotEmpty()) false
        else if (!env.containsKey("scopes")) false
        else if (env["scopes"] != null && (env["scopes"] as List<*>).none { scopeMatches(it as Map<String, Any?>, verb, resource, params) }) false
        else {
            val h = env["remainingBudgetHints"] as Map<String, Any?>
            val depth = if (h.containsKey("delegationDepthRemaining")) IntentJs.num(h["delegationDepthRemaining"]) else null
            val maxSpend = if (h.containsKey("maxSpendUsd")) IntentJs.num(h["maxSpendUsd"]) else null
            if (h.containsKey("delegationDepthRemaining") && !(depth != null && depth.isFinite() && depth >= 0)) false
            else if (maxSpend != null && params != null && actionSpendUsd(Issue.obj("action" to Issue.obj("params" to params))).let { it == null || !(it <= maxSpend) }) false
            else if (now != null) {
                val n = fin(now)
                val exp = if (h.containsKey("expiresAt")) IntentJs.num(h["expiresAt"]) else null
                val nb = if (h.containsKey("notBefore")) IntentJs.num(h["notBefore"]) else null
                !(n == null || (h.containsKey("expiresAt") && !(exp != null && exp.isFinite() && n < exp)) || (h.containsKey("notBefore") && !(nb != null && nb.isFinite() && n >= nb)))
            } else true
        }
    } catch (e: RuntimeException) {
        false
    } catch (e: StackOverflowError) {
        false
    }

    private fun firewall(ok: Boolean, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        return m
    }

    /** Pre-flight for a tool call: the tool must be in `env.tools` and satisfy EVERY `tool_schema` caveat. Returns `{ok, reason?}`. */
    fun envelopePermitsToolCall(envO: Any?, call: Any?): Map<String, Any?> = try {
        val env = envO as Map<String, Any?>
        if (!IntentRevocation.truthy(env["ok"]) || (env["unsatisfiable"] as List<*>).isNotEmpty()) {
            firewall(false, if (env["reason"] != null) env["reason"].toString() else "envelope not usable")
        } else {
            var out: Map<String, Any?>? = null
            val tools = env["tools"]
            if (tools != null) {
                if (call == null) throw IllegalStateException("call is null") // the reference reads call.tool: evaluation error
                val c = call as? Map<*, *> // any other value has no tool member (undefined)
                val has = c != null && c.containsKey("tool")
                if (!(has && (tools as List<*>).contains(c!!["tool"]))) {
                    out = firewall(false, "tool " + Authorize.show(IntentRevocation.jsText(if (has) c!!["tool"] else null, has)) + " not authorized")
                }
            }
            if (out == null) {
                for (tc in env["toolSchemas"] as List<Any?>) {
                    val r = Authorize.evaluateToolSchema(tc, call)
                    if (!r.ok) { out = firewall(false, r.reason); break }
                }
            }
            out ?: firewall(true, null)
        }
    } catch (e: RuntimeException) {
        firewall(false, "evaluation error (fail closed)")
    } catch (e: StackOverflowError) {
        firewall(false, "evaluation error (fail closed)")
    }

    // ======================================================================================================================
    // 5. Authority lease
    // ======================================================================================================================

    /**
     * Issue a lease `{cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at, hard_expires_at?,
     * max_renewals?}` from `{cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}`. Throws unless the ids are non-empty,
     * `now` finite, 0 < ttl_ms <= [MAX_LEASE_TTL_MS], `hard_expires_at` (if any) finite and after `now`, and `max_renewals` (if
     * any) a non-negative integer.
     */
    fun grantLease(argsO: Any?): Map<String, Any?> {
        if (argsO !is Map<*, *>) throw IllegalArgumentException("grantLease: cap_id and holder required")
        if (!nonEmpty(argsO["cap_id"]) || !nonEmpty(argsO["holder"])) throw IllegalArgumentException("grantLease: cap_id and holder required")
        val now = fin(argsO["now"])
        val ttl = fin(argsO["ttl_ms"])
        if (now == null || ttl == null || ttl <= 0 || ttl > MAX_LEASE_TTL_MS) throw IllegalArgumentException("grantLease: invalid now/ttl_ms")
        var hard: Double? = null
        if (argsO.containsKey("hard_expires_at")) {
            hard = fin(argsO["hard_expires_at"])
            if (hard == null || hard <= now) throw IllegalArgumentException("grantLease: hard_expires_at must be finite and in the future")
        }
        if (argsO.containsKey("max_renewals") && !isNonNegInteger(argsO["max_renewals"])) throw IllegalArgumentException("grantLease: invalid max_renewals")
        val exp = if (hard == null) now + ttl else Math.min(now + ttl, hard)
        val l = Issue.obj(
            "cap_id" to argsO["cap_id"], "holder" to argsO["holder"], "issued_at" to argsO["now"], "renewed_at" to argsO["now"],
            "ttl_ms" to argsO["ttl_ms"], "renewals" to 0L, "last_seq" to 0L, "expires_at" to exp,
        )
        if (hard != null) l["hard_expires_at"] = argsO["hard_expires_at"]
        if (argsO.containsKey("max_renewals")) l["max_renewals"] = argsO["max_renewals"]
        return l
    }

    /** Structural + invariant check of a lease record: an error or null. */
    private fun leaseError(lo: Any?): String? {
        if (lo !is Map<*, *>) return "malformed lease"
        if (!nonEmpty(lo["cap_id"]) || !nonEmpty(lo["holder"])) return "malformed lease"
        val issued = fin(lo["issued_at"])
        val renewed = fin(lo["renewed_at"])
        val ttl = fin(lo["ttl_ms"])
        val exp = fin(lo["expires_at"])
        if (issued == null || renewed == null || ttl == null || exp == null) return "malformed lease"
        if (ttl <= 0 || ttl > MAX_LEASE_TTL_MS) return "malformed lease"
        if (!isNonNegInteger(lo["renewals"]) || !isNonNegInteger(lo["last_seq"])) return "malformed lease"
        if (lo.containsKey("max_renewals") && !isNonNegInteger(lo["max_renewals"])) return "malformed lease"
        if (lo.containsKey("hard_expires_at")) {
            val hard = fin(lo["hard_expires_at"]) ?: return "malformed lease"
            if (exp > hard) return "lease exceeds hard expiry"
        }
        // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
        if (exp > renewed + ttl) return "malformed lease"
        return null
    }

    private fun dead(reason: String?): Map<String, Any?> = Issue.obj("live" to false, "expiresIn" to 0L, "reason" to reason)

    /**
     * Live iff the record is well-formed, the clock has not rolled back more than the skew window past the last renewal and
     * `now < expires_at`. Returns `{live, expiresIn, reason?}`; every dead state has `expiresIn` 0. Total.
     */
    fun leaseState(lease: Any?, now: Any?): Map<String, Any?> {
        val n = fin(now) ?: return dead("invalid clock")
        val e = leaseError(lease)
        if (e != null) return dead(e)
        val l = lease as Map<*, *>
        if (n < fin(l["renewed_at"])!! - HEARTBEAT_SKEW_MS) return dead("clock before last renewal")
        val expiresIn = fin(l["expires_at"])!! - n
        if (expiresIn <= 0) return dead("lease lapsed")
        return Issue.obj("live" to true, "expiresIn" to expiresIn)
    }

    private val HB_KEYS = listOf("cap_id", "seq", "at", "holder", "lease_issued_at", "sig")

    private fun renewFail(reason: String): Map<String, Any?> = Issue.obj("ok" to false, "reason" to reason)

    /**
     * The reference's pure `renewLease(lease, heartbeat, now)` (the grants registry keeps its own `renewLease`): renew on a valid,
     * fresh, in-order, holder-signed heartbeat for THIS lease grant. A lapsed, malformed or clock-anomalous lease is dead for
     * good. Never extends past `hard_expires_at`, never shortens, consumes the renewal budget. Returns `{ok: true, lease}` or
     * `{ok: false, reason}`. Total.
     */
    fun renewCapabilityLease(leaseO: Any?, hbO: Any?, nowO: Any?): Map<String, Any?> = try {
        val st = leaseState(leaseO, nowO)
        if (st["live"] != true) {
            renewFail(if (st["reason"] == "lease lapsed") "lease lapsed" else "lease not live: ${st["reason"]}")
        } else {
            val lease = leaseO as Map<String, Any?>
            val now = fin(nowO)!!
            val hb = hbO as? Map<String, Any?>
            val seq = hb?.get("seq")
            val at = fin(hb?.get("at"))
            if (hb == null || !hb.keys.all { it in HB_KEYS } || hb["sig"] !is String) renewFail("malformed heartbeat")
            else if (!jsEq(hb["cap_id"], lease["cap_id"]) || !jsEq(hb["holder"], lease["holder"]) || !jsEq(hb["lease_issued_at"], lease["issued_at"])) renewFail("heartbeat not for this lease")
            else if (!IntentJs.isSafeInteger(seq) || IntentJs.num(seq)!! <= fin(lease["last_seq"])!!) renewFail("stale or replayed heartbeat")
            else if (at == null || !now.isFinite() || !(Math.abs(at - now) <= HEARTBEAT_SKEW_MS)) renewFail("heartbeat outside skew window")
            else {
                val body = LinkedHashMap(hb)
                body.remove("sig")
                if (!Pca.verifyB64u(lease["holder"] as String, msgOf("atlas-pca/lease-hb/v2", body), hb["sig"] as String)) renewFail("bad heartbeat signature")
                else if (lease.containsKey("max_renewals") && fin(lease["renewals"])!! >= fin(lease["max_renewals"])!!) renewFail("renewal budget exhausted")
                else {
                    var exp = now + fin(lease["ttl_ms"])!!
                    if (lease.containsKey("hard_expires_at")) exp = Math.min(exp, fin(lease["hard_expires_at"])!!)
                    if (exp.isNaN() || exp.isInfinite()) renewFail("malformed lease")
                    else {
                        val next = LinkedHashMap(lease)
                        next["renewals"] = fin(lease["renewals"])!! + 1
                        next["last_seq"] = seq
                        next["renewed_at"] = Math.max(now, fin(lease["renewed_at"])!!)
                        next["expires_at"] = Math.max(exp, fin(lease["expires_at"])!!)
                        Issue.obj("ok" to true, "lease" to next)
                    }
                }
            }
        }
    } catch (e: RuntimeException) {
        renewFail("malformed heartbeat")
    } catch (e: StackOverflowError) {
        renewFail("malformed heartbeat")
    }
}
