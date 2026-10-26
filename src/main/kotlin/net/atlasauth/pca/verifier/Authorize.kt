package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * `authorize`: the full authorization pipeline for a resource server or tool guard (0.5, additive). Mirrors the
 * TypeScript `authorize()` and the Python `atlas_pca.authorize` check by check.
 *
 * [Pca.verifyPcactn] answers "is this a validly signed PCActn for this audience". [authorize] answers "may THIS operation
 * run now", in this order:
 *  1. configuration: `audience`, `resolveGrant`, `stateStore` and `isRevoked` are REQUIRED, and the call must name the
 *     [Operation] it will execute (verb, resource, params). A missing one denies with its name (`missing`); nothing is
 *     ever downgraded to "not enforced".
 *  2. the core checks ([Pca.verifyPcactn]: wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion,
 *     leaf_signature, counter format, intent), then `revocation` (`isRevoked`), then `zk_compliance` (a carried proof
 *     cannot be verified here: fail closed).
 *  3. `operation`: the signed `action.verb` / `action.resource` equal the operation's, and the signed
 *     `action.params_digest` opens to exactly the operation's params. Those params are what the predicates and caveats
 *     read, so a $400 operation is judged as $400 even when the agent signed $50 (and then refused for the mismatch).
 *  4. `grant_ref`, `params_digest`, `plan_root_authorized` (`plan = "single-step"` or a context plan), `attestation` (a
 *     grant whose `agent_binding` pins the agent needs an attestation verifier this SDK does not have: fail closed),
 *     `reversibility` (when the context names an authoritative class).
 *  5. policy: the envelope predicates (default deny), the envelope's caveats and the ROOT caveats outside the envelope
 *     (`policy`), and the caveats delegation hops appended (`delegated_caveats`). `predicates` and `tool_schema` caveats
 *     are enforced against the operation; unknown caveat types fail closed.
 *  6. replay (check `replay`): only when everything above passes, the counter is consumed through [StateStore.claim], one atomic
 *     compare-and-set per action (key = [stateKey]). A replayed or older counter denies.
 *
 * Not ported: the risk score, trust budget, threshold co-sign, revocation epochs and beacons. Never throws: any internal
 * error is a denial.
 */
object Authorize {
    const val ENVELOPE_CAVEAT = "envelope"
    const val SINGLE_STEP = "single-step"

    /** The checks that must be `pass` (not merely "not failed"); [Input.require] can add names, never remove these. */
    val DEFAULT_REQUIRED_CHECKS: List<String> = listOf(
        "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation",
        "params_digest", "policy",
    )

    /** A failing one of these is an authentication failure (401); everything else is insufficient authority (403). */
    private val AUTHN_CHECKS = listOf(
        "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref",
    )

    // ---- the operation ----

    /**
     * What the handler / tool WILL execute, from the server's own routing and parsed input, never from the PCActn.
     * `params` is a JSON object tree (values: [Json.Num], Int, Long, String, Boolean, null, maps and lists).
     */
    data class Operation(val verb: String, val resource: String, val params: Map<String, Any?>) {
        companion object {
            /** From a parsed JSON object `{verb, resource, params}`; null when any member is missing or mistyped. */
            @Suppress("UNCHECKED_CAST")
            fun fromJson(o: Any?): Operation? {
                if (o !is Map<*, *>) return null
                val v = o["verb"]
                val r = o["resource"]
                val p = o["params"]
                if (v !is String || r !is String || p !is Map<*, *>) return null
                return Operation(v, r, p as Map<String, Any?>)
            }
        }
    }

    /** The operation an allowing decision is bound to. `id` is the digest of the presented PCActn. */
    data class AuthorizedOperation(val verb: String, val resource: String, val paramsDigest: String, val id: String)

    /**
     * Outcome of [authorize]. `allow` is the one thing a caller must branch on. `status` is 200, 401 (no / undecodable /
     * unauthenticated proof) or 403. `checks` maps each check to `pass`, `fail` or `not-enforced`; `reason` is the
     * decisive one (an `operation` failure first). `missing` names configuration components that were absent (the call
     * was refused before any verification).
     */
    class Result internal constructor(
        val allow: Boolean,
        val status: Int,
        val checks: Map<String, String>,
        val reasons: List<String>,
        val reason: String?,
        val operation: AuthorizedOperation? = null,
        val pcactn: Map<String, Any?>? = null,
        val verdict: Pca.Verdict? = null,
        val missing: List<String>? = null,
    ) {
        override fun toString(): String = "Authorize.Result(allow=$allow, status=$status, reason=$reason, checks=$checks)"
    }

    // ---- the replay store ----

    /** What [StateStore.claim] returns. `ok` is true only when THIS call consumed the counter. */
    data class ClaimResult(val ok: Boolean, val lastCounter: Long? = null)

    /**
     * The replay-store contract: ONE atomic operation of your backend. If a counter is stored for `key` and `counter` is
     * not strictly greater, return `ClaimResult(false, stored)`; otherwise store `counter` and return `ClaimResult(true)`.
     * A claim that cannot decide must return null, `ok = false` or throw ([authorize] then denies).
     */
    interface StateStore {
        fun claim(key: String, counter: Long): ClaimResult?
    }

    /** In-process reference store (one lock). Correct for ONE process only; use [PcaJdbcStateStore] or your database for several. */
    class MemoryStateStore : StateStore {
        private val last = HashMap<String, Long>()

        override fun claim(key: String, counter: Long): ClaimResult = synchronized(last) {
            val prev = last[key]
            if (prev != null && counter <= prev) return ClaimResult(false, prev)
            last[key] = counter
            ClaimResult(true)
        }
    }

    /** The store key of a holder's counter stream (the TypeScript `pcaStateKey` default scope). */
    fun stateKey(grantId: String, leafHolder: String): String = "$grantId:$leafHolder"

    // ---- the input ----

    /**
     * Everything [authorize] needs besides the proof.
     *  - `operation`    what will execute (see [Operation]); null denies.
     *  - `audience`     this resource server's id (the PCActn's signed `aud` must equal it).
     *  - `resolveGrant` `(grantRef) -> grant` from your own store (null = unknown grant).
     *  - `stateStore`   the replay store ([MemoryStateStore], [PcaJdbcStateStore] or your database).
     *  - `isRevoked`    `(pcactn, grant) -> false` when not revoked; anything else (true, null, another value, an
     *                   exception) denies.
     *  - `now`          epoch milliseconds (default: the wall clock).
     *  - `plan`         `"single-step"`: accept a one-node plan whose node is exactly this operation. Otherwise `context`
     *                   must return the principal-authorized `plan` (a list of nodes) with `plan_authorized: true`.
     *  - `context`      `(pcactn) -> map?` with optional `plan`, `plan_authorized`, `subject`, `env`, `blast_radius`,
     *                   `recent_action_times`, `reversibility_class` (the server's authoritative class; the agent may only
     *                   declare a stricter one).
     *  - `intentPolicy` / `intentV2` / `allowedSuites`: forwarded to [Pca.verifyPcactn] (`intentV2` is called with the
     *                   proof; a context without `params` gets the operation's).
     *  - `require`      extra check names that must pass (the defaults always apply).
     */
    class Input(
        val operation: Operation?,
        val audience: String?,
        val resolveGrant: ((String) -> Map<String, Any?>?)?,
        val stateStore: StateStore?,
        val isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)?,
        val now: Long? = null,
        val plan: String? = null,
        val context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        val intentPolicy: Pca.IntentPolicy? = null,
        val intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        val allowedSuites: List<String>? = null,
        val require: List<String> = emptyList(),
    )

    /**
     * The `authorize` components a guard adds on top of its `audience` / `resolveGrant` (plan defaults to single-step).
     * [run] builds the [Input] for one operation.
     */
    class AuthorizeOptions(
        val stateStore: StateStore?,
        val isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)?,
        val plan: String? = SINGLE_STEP,
        val context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        val require: List<String> = emptyList(),
    ) {
        fun run(
            pcactn: Any?, operation: Operation?, audience: String?, resolveGrant: ((String) -> Map<String, Any?>?)?,
            now: Long? = null, intentPolicy: Pca.IntentPolicy? = null, intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        ): Result = authorize(
            pcactn,
            Input(
                operation = operation, audience = audience, resolveGrant = resolveGrant, stateStore = stateStore,
                isRevoked = isRevoked, now = now, plan = plan, context = context, intentPolicy = intentPolicy,
                intentV2 = intentV2, require = require,
            ),
        )
    }

    // ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ----

    private fun validateRiskPolicy(p: Any?): String? {
        if (p !is Map<*, *>) return "risk_policy must be an object"
        val w = p["weights"] as? Map<*, *> ?: return "risk_policy.weights missing"
        for (k in listOf("alpha", "beta", "gamma", "delta", "epsilon", "zeta")) {
            val v = fin(w[k])
            if (v == null || v < 0) return "risk_policy.weights.$k must be finite and >= 0"
        }
        val vals = HashMap<String, Double>()
        for (k in listOf("theta1", "theta2", "kappa", "lambda", "rho", "bMax")) {
            vals[k] = fin(p[k]) ?: return "risk_policy.$k must be finite"
        }
        if (vals["theta1"]!! < 0 || vals["theta2"]!! < vals["theta1"]!!) return "risk_policy requires 0 <= theta1 <= theta2"
        if (vals["kappa"]!! <= 0) return "risk_policy.kappa must be > 0"
        if (vals["lambda"]!! < 0 || vals["rho"]!! < 0 || vals["bMax"]!! < 0) return "risk_policy lambda/rho/bMax must be >= 0"
        return null
    }

    /** The grant's policy envelope: its FIRST `envelope` caveat without `type`, or null when absent or malformed. */
    fun readEnvelope(grant: Any?): Map<String, Any?>? = try {
        val cs = (grant as? Map<*, *>)?.get("caveats") as? List<*>
        val cv = cs?.firstOrNull { it is Map<*, *> && it["type"] == ENVELOPE_CAVEAT } as? Map<*, *>
        if (cv == null) null
        else {
            val e = LinkedHashMap<String, Any?>()
            for ((k, v) in cv) if (k != "type") e[k as String] = v
            when {
                e["goal_commit"] !is String -> null
                e["predicates"] !is List<*> || e["caveats"] !is List<*> -> null
                e["agent_binding"] !is Map<*, *> && e["agent_binding"] !is List<*> -> null
                validateRiskPolicy(e["risk_policy"]) != null -> null
                else -> e
            }
        }
    } catch (e: RuntimeException) {
        null
    }

    /** Every root caveat except the first `envelope` one (TypeScript `rootCaveats`); a non-list is returned as is. */
    fun rootCaveats(grant: Any?): Any? = Caveats.rootCaveats(grant)

    /** TypeScript `requiresAttestation`: any agent pin in `agent_binding` requires a bound attestation. */
    private fun requiresAttestation(binding: Any?): Boolean {
        val b = binding as? Map<*, *> ?: emptyMap<String, Any?>()
        fun ne(x: Any?) = x is List<*> && x.isNotEmpty()
        val hasMin = b.containsKey("min_measurement") && b["min_measurement"] != ""
        val op = b["operator"]
        return ne(b["model_allowlist"]) || hasMin || (op is String && op != "") || ne(b["weights_allowlist"]) ||
            ne(b["system_prompt_allowlist"]) || ne(b["tool_manifest_allowlist"]) || b["require_hardware"] == true ||
            b["require_measured_weights"] == true
    }

    // ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) ----

    const val MAX_SCHEMA_DEPTH = 8
    const val MAX_SCHEMA_NODES = 256
    const val MAX_OBJECT_PROPS = 64
    const val MAX_ENUM_VALUES = 256
    const val DEFAULT_MAX_ARRAY_ITEMS = 256
    const val ABSOLUTE_MAX_ARRAY_ITEMS = 4096
    const val DEFAULT_MAX_STRING_LEN = 65_536
    const val ABSOLUTE_MAX_STRING_LEN = 1_048_576
    const val MAX_VALUE_NODES = 10_000

    /** The verdict of [evaluateToolSchema]: `reason` names the failing path on rejection. */
    data class ToolSchemaResult(val ok: Boolean, val reason: String?)

    private val SAFE_NAME = Regex("[A-Za-z0-9_]{1,64}")
    private val SPEC_KEYS: Map<String, List<String>> = mapOf(
        "string" to listOf("type", "enum", "const", "minLength", "maxLength", "prefix"),
        "number" to listOf("type", "enum", "const", "min", "max"),
        "integer" to listOf("type", "enum", "const", "min", "max"),
        "boolean" to listOf("type", "enum", "const"),
        "object" to listOf("type", "props", "required"),
        "array" to listOf("type", "items", "minItems", "maxItems"),
    )

    private class Budget(var n: Int = 0)

    /** A finite JSON number as a double (a Boolean is never a number), else null. */
    private fun fin(o: Any?): Double? {
        val d: Double = when (o) {
            is Json.Num -> o.raw.toDoubleOrNull() ?: return null
            is Int, is Long, is Double, is Float, is Short, is Byte, is java.math.BigDecimal, is java.math.BigInteger -> (o as Number).toDouble()
            else -> return null
        }
        return if (d.isFinite()) d else null
    }

    private fun isInt(x: Any?): Boolean = fin(x)?.let { it == Math.floor(it) } ?: false

    private fun nonNegInt(x: Any?, max: Int): Boolean = fin(x)?.let { it == Math.floor(it) && it >= 0 && it <= max } ?: false

    private fun onlyKeys(o: Map<*, *>, allowed: List<String>): Boolean = o.keys.all { it in allowed }

    /** JavaScript `===` on the scalars a schema can hold (numbers compare as doubles; a bool is never a number). */
    private fun jsEq(a: Any?, b: Any?): Boolean {
        val fa = fin(a)
        val fb = fin(b)
        if (fa != null || fb != null) return fa != null && fb != null && fa == fb
        if (a is Boolean || b is Boolean) return a is Boolean && b is Boolean && a == b
        if (a is String && b is String) return a == b
        return false
    }

    /** Validate a `tool_schema` argument schema (closed; shape, depth, node count, bounds). Null when valid. */
    fun validateArgSchema(schema: Any?): String? {
        if (schema !is Map<*, *>) return "schema must be an object"
        if (!onlyKeys(schema, listOf("props", "required"))) return "unknown schema key"
        return objectSchemaError(schema["props"], schema.containsKey("required"), schema["required"], 1, Budget())
    }

    private fun objectSchemaError(props: Any?, hasRequired: Boolean, required: Any?, depth: Int, budget: Budget): String? {
        if (depth > MAX_SCHEMA_DEPTH) return "schema too deep"
        if (++budget.n > MAX_SCHEMA_NODES) return "schema too large"
        if (props !is Map<*, *>) return "props must be an object"
        if (props.size > MAX_OBJECT_PROPS) return "too many props"
        for ((k, spec) in props) {
            val n = k as String
            if (!SAFE_NAME.matches(n)) return "invalid property name '${if (n.length > 32) n.substring(0, 32) else n}'"
            val e = specError(spec, depth + 1, budget)
            if (e != null) return "$n: $e"
        }
        if (hasRequired) {
            if (required !is List<*> || required.size > MAX_OBJECT_PROPS) return "required must be a short array"
            for (r in required) if (r !is String || !props.containsKey(r)) return "required names an undeclared property"
        }
        return null
    }

    private fun specError(spec: Any?, depth: Int, budget: Budget): String? {
        if (depth > MAX_SCHEMA_DEPTH) return "schema too deep"
        if (++budget.n > MAX_SCHEMA_NODES) return "schema too large"
        val t = (spec as? Map<*, *>)?.get("type")
        if (spec !is Map<*, *> || t !is String || !SPEC_KEYS.containsKey(t)) return "unknown type"
        if (!onlyKeys(spec, SPEC_KEYS.getValue(t))) return "unknown spec key"
        if (t == "object") {
            budget.n-- // counted once by objectSchemaError
            return objectSchemaError(spec["props"], spec.containsKey("required"), spec["required"], depth, budget)
        }
        if (t == "array") {
            if (spec.containsKey("minItems") && !nonNegInt(spec["minItems"], ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad minItems"
            if (spec.containsKey("maxItems") && !nonNegInt(spec["maxItems"], ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad maxItems"
            if (spec.containsKey("minItems") && spec.containsKey("maxItems") && fin(spec["minItems"])!! > fin(spec["maxItems"])!!) return "minItems > maxItems"
            return specError(spec["items"], depth + 1, budget)
        }
        val ok = { v: Any? ->
            when (t) {
                "string" -> v is String && v.length <= 1024
                "boolean" -> v is Boolean
                else -> fin(v) != null && (t == "number" || isInt(v))
            }
        }
        if (spec.containsKey("const") && !ok(spec["const"])) return "bad const"
        if (spec.containsKey("enum")) {
            val en = spec["enum"]
            if (en !is List<*> || en.isEmpty() || en.size > MAX_ENUM_VALUES || !en.all(ok)) return "bad enum"
        }
        if (t == "string") {
            if (spec.containsKey("minLength") && !nonNegInt(spec["minLength"], ABSOLUTE_MAX_STRING_LEN)) return "bad minLength"
            if (spec.containsKey("maxLength") && !nonNegInt(spec["maxLength"], ABSOLUTE_MAX_STRING_LEN)) return "bad maxLength"
            if (spec.containsKey("minLength") && spec.containsKey("maxLength") && fin(spec["minLength"])!! > fin(spec["maxLength"])!!) return "minLength > maxLength"
            if (spec.containsKey("prefix") && (spec["prefix"] !is String || (spec["prefix"] as String).length > 512)) return "bad prefix"
        } else if (t == "number" || t == "integer") {
            if (spec.containsKey("min") && fin(spec["min"]) == null) return "bad min"
            if (spec.containsKey("max") && fin(spec["max"]) == null) return "bad max"
            if (spec.containsKey("min") && spec.containsKey("max") && fin(spec["min"])!! > fin(spec["max"])!!) return "min > max"
        }
        return null
    }

    /** JavaScript `JSON.stringify` of a key, cut to 48 UTF-16 code units plus an ellipsis (the TypeScript `show`). */
    private fun show(k: String): String {
        val s = if (k.length > 48) k.substring(0, 48) + "…" else k
        val sb = StringBuilder("\"")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append(String.format("\\u%04x", c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(c).append(s[i + 1]); i++ }
                Character.isSurrogate(c) -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
            i++
        }
        return sb.append('"').toString()
    }

    private fun checkValue(spec: Map<*, *>, v: Any?, path: String, depth: Int, budget: Budget): String? {
        if (depth > MAX_SCHEMA_DEPTH + 1) return "$path: too deep"
        if (++budget.n > MAX_VALUE_NODES) return "$path: too many values"
        val t = spec["type"]
        when (t) {
            "object" -> {
                if (v !is Map<*, *>) return "$path: expected object"
                return checkObject(spec["props"] as Map<*, *>, spec["required"], v, path, depth, budget)
            }
            "array" -> {
                if (v !is List<*>) return "$path: expected array"
                val mx = minOf(if (spec.containsKey("maxItems")) fin(spec["maxItems"])!! else DEFAULT_MAX_ARRAY_ITEMS.toDouble(), ABSOLUTE_MAX_ARRAY_ITEMS.toDouble())
                if (v.size > mx) return "$path: exceeds maxItems"
                if (spec.containsKey("minItems") && v.size < fin(spec["minItems"])!!) return "$path: below minItems"
                for (i in v.indices) {
                    val e = checkValue(spec["items"] as Map<*, *>, v[i], "$path[$i]", depth + 1, budget)
                    if (e != null) return e
                }
                return null
            }
            "string" -> {
                if (v !is String) return "$path: wrong type (expected string)"
                val n = v.length // UTF-16 code units, like JavaScript
                val mx = minOf(if (spec.containsKey("maxLength")) fin(spec["maxLength"])!! else DEFAULT_MAX_STRING_LEN.toDouble(), ABSOLUTE_MAX_STRING_LEN.toDouble())
                if (n > mx) return "$path: exceeds maxLength"
                if (spec.containsKey("minLength") && n < fin(spec["minLength"])!!) return "$path: below minLength"
                if (spec.containsKey("prefix") && !v.startsWith(spec["prefix"] as String)) return "$path: violates prefix"
            }
            "number", "integer" -> {
                val f = fin(v)
                if (f == null || (t == "integer" && f != Math.floor(f))) return "$path: wrong type (expected $t)"
                if (spec.containsKey("min") && f < fin(spec["min"])!!) return "$path: below min"
                if (spec.containsKey("max") && f > fin(spec["max"])!!) return "$path: above max"
            }
            "boolean" -> if (v !is Boolean) return "$path: wrong type (expected boolean)"
            else -> return "$path: unknown type"
        }
        if (spec.containsKey("const") && !jsEq(spec["const"], v)) return "$path: violates const"
        if (spec.containsKey("enum") && (spec["enum"] as List<*>).none { jsEq(it, v) }) return "$path: violates enum"
        return null
    }

    private fun checkObject(props: Map<*, *>, required: Any?, obj: Map<*, *>, path: String, depth: Int, budget: Budget): String? {
        for (k in obj.keys) if (!props.containsKey(k)) return "$path: unexpected argument ${show(k as String)}"
        for (r in (required as? List<*>).orEmpty()) if (!obj.containsKey(r)) return "$path: missing required argument '$r'"
        for ((k, x) in obj) {
            val e = checkValue(props[k] as Map<*, *>, x, "$path.$k", depth + 1, budget)
            if (e != null) return e
        }
        return null
    }

    /**
     * Evaluate a tool call `{tool, args, tool_signature_digest?}` against a `tool_schema` caveat (the TypeScript
     * `evaluateToolSchema`): the caveat must be self-consistent (schema valid, `schema_digest` and `binding_digest`
     * recomputed), the tool and the signed tool binding must match, and the arguments must satisfy the closed recursive
     * schema. Never throws.
     */
    fun evaluateToolSchema(caveat: Any?, call: Any?): ToolSchemaResult = try {
        evaluateToolSchemaUnchecked(caveat, call)
    } catch (e: RuntimeException) {
        ToolSchemaResult(false, "evaluation error (fail closed)")
    } catch (e: StackOverflowError) {
        ToolSchemaResult(false, "evaluation error (fail closed)")
    }

    private fun evaluateToolSchemaUnchecked(caveat: Any?, call: Any?): ToolSchemaResult {
        val tool = (caveat as? Map<*, *>)?.get("tool")
        if (caveat !is Map<*, *> || caveat["type"] != "tool_schema" || tool !is String || tool == "")
            return ToolSchemaResult(false, "malformed tool_schema caveat")
        val verr = validateArgSchema(caveat["schema"])
        if (verr != null) return ToolSchemaResult(false, "malformed tool_schema caveat: $verr")
        if (Pca.hashCanonical(caveat["schema"]) != caveat["schema_digest"]) return ToolSchemaResult(false, "schema digest mismatch")
        val sig = jsString(caveat["signature_digest"], caveat.containsKey("signature_digest"))
        val binding = linkedMapOf<String, Any?>("tool" to tool, "signature_digest" to sig, "schema" to caveat["schema"])
        if (Pca.hashCanonical(binding) != caveat["binding_digest"]) return ToolSchemaResult(false, "binding digest mismatch")
        val ctool = (call as? Map<*, *>)?.get("tool")
        val args = (call as? Map<*, *>)?.get("args")
        if (call !is Map<*, *> || ctool !is String || args !is Map<*, *>) return ToolSchemaResult(false, "malformed call")
        if (ctool != tool) return ToolSchemaResult(false, "tool ${show(ctool)} not authorized")
        if (call.containsKey("tool_signature_digest") && call["tool_signature_digest"] != caveat["signature_digest"])
            return ToolSchemaResult(false, "signed tool_binding differs from the authorized tool signature")
        val schema = caveat["schema"] as Map<*, *>
        val e = checkObject(schema["props"] as Map<*, *>, schema["required"], args, "args", 1, Budget())
        return if (e != null) ToolSchemaResult(false, e) else ToolSchemaResult(true, null)
    }

    // ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) ----

    private fun agentCaveatSatisfied(cv: Any?, ctx: Map<String, Any?>, actionCtx: Map<String, Any?>, toolCall: Map<String, Any?>): Boolean = try {
        if (cv !is Map<*, *>) false
        else when (cv["type"]) {
            "tool_schema" -> evaluateToolSchema(cv, toolCall).ok
            "predicates" -> {
                val allow = cv["allow"]
                allow is List<*> && allow.any { Predicates.predicateMatches(it, actionCtx) }
            }
            // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
            else -> Caveats.evaluateCaveats(listOf(cv), LinkedHashMap(ctx)).ok
        }
    } catch (e: RuntimeException) {
        false
    } catch (e: StackOverflowError) {
        false
    }

    /**
     * Evaluate caveats with the agent-native evaluator: the stock types of [Caveats.evaluateCaveats], plus `predicates`
     * (`allow`: the action must match one predicate; needs `actionCtx` = `{action: {...}, subject?, env?}`) and
     * `tool_schema` (needs `toolCall` = `{tool, args, tool_signature_digest?}`). `ctx` is the stock context (`now`,
     * `action`, `blast_radius`, ...). Unknown types fail closed. Never throws.
     */
    fun evaluateAgentCaveats(
        caveats: Any?, ctx: Map<String, Any?>, actionCtx: Map<String, Any?>? = null, toolCall: Map<String, Any?>? = null,
    ): Caveats.Result = try {
        SafeRegex.withBudget {
            if (caveats !is List<*>) Caveats.Result(false, listOf("<malformed caveats>"))
            else {
                val failed = ArrayList<String>()
                for (cv in caveats) {
                    if (!agentCaveatSatisfied(cv, ctx, actionCtx ?: emptyMap(), toolCall ?: emptyMap()))
                        failed.add(((cv as? Map<*, *>)?.get("type") as? String) ?: "<malformed>")
                }
                Caveats.Result(failed.isEmpty(), failed)
            }
        }
    } catch (e: RuntimeException) {
        Caveats.Result(false, listOf("<evaluation error>"))
    }

    // ---- authorize ----

    private val CLASS_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "costly" to 1, "irreversible" to 2)

    private fun classRank(c: Any?): Int = if (c is String) CLASS_RANK[c] ?: 2 else 2

    /** JavaScript `String(v)` of a JSON value (`present = false` is `undefined`). */
    private fun jsString(v: Any?, present: Boolean = true): String = IntentRevocation.jsText(IntentJs.normalize(v), present)

    private fun refuse(status: Int, check: String, reason: String, missing: List<String>? = null, pcactn: Map<String, Any?>? = null): Result =
        Result(false, status, linkedMapOf(check to "fail"), listOf(reason), reason, missing = missing, pcactn = pcactn)

    /** Names of the required components that are absent (empty = complete). */
    fun missingAuthorizeComponents(audience: String?, resolveGrant: Any?, stateStore: Any?, isRevoked: Any?): List<String> {
        val missing = ArrayList<String>()
        if (audience == null || audience == "") missing.add("audience")
        if (resolveGrant == null) missing.add("resolveGrant")
        if (stateStore == null) missing.add("stateStore")
        if (isRevoked == null) missing.add("isRevoked")
        return missing
    }

    private fun validOperation(op: Operation?): Boolean = op != null && op.verb != "" && op.resource != "" && (op.params as Any?) is Map<*, *>

    private fun decisive(checks: Map<String, String>, reasons: List<String>): String {
        val names = checks.keys.sortedBy { if (it == "operation") 0 else 1 } // stable: a binding failure first
        for (n in names) {
            if (checks[n] != "fail") continue
            val hit = reasons.firstOrNull { it.startsWith("$n:") }
            if (hit != null) return hit
        }
        return reasons.firstOrNull() ?: "denied"
    }

    /** The presented proof as a parsed object, or the reason it is unusable (`absent` / `undecodable`). */
    @Suppress("UNCHECKED_CAST")
    private fun coerce(pcactn: Any?): Pair<Map<String, Any?>?, String?> {
        if (pcactn is Map<*, *>) return Pair(pcactn as Map<String, Any?>, null)
        val text: String = when (pcactn) {
            null -> return Pair(null, "absent")
            is String -> pcactn
            is ByteArray -> {
                if (pcactn.size > Pca.MAX_ARTIFACT_BYTES) return Pair(null, "undecodable")
                try {
                    StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(pcactn)).toString()
                } catch (e: CharacterCodingException) {
                    return Pair(null, "undecodable")
                }
            }
            else -> return Pair(null, "undecodable")
        }
        if (Pca.artifactTooLarge(text)) return Pair(null, "undecodable")
        val obj = try { Json.parse(text) } catch (e: RuntimeException) { return Pair(null, "undecodable") }
        return if (obj is Map<*, *>) Pair(obj as Map<String, Any?>, null) else Pair(null, "undecodable")
    }

    /**
     * Authorize ONE operation (see the object doc for the pipeline). `pcactn` is the presented PCActn: a parsed object
     * (a [Json.parse] tree), its JSON text or its UTF-8 bytes (strict profile). Never throws: an internal error denies.
     */
    fun authorize(pcactn: Any?, input: Input): Result = try {
        authorizeUnchecked(pcactn, input)
    } catch (e: Exception) {
        refuse(403, "authorize", "authorize: error (fail closed): ${e.javaClass.simpleName}")
    } catch (e: StackOverflowError) {
        refuse(403, "authorize", "authorize: error (fail closed): StackOverflowError")
    }

    @Suppress("UNCHECKED_CAST")
    private fun authorizeUnchecked(pcactn: Any?, input: Input): Result {
        val missing = ArrayList(missingAuthorizeComponents(input.audience, input.resolveGrant, input.stateStore, input.isRevoked))
        if (input.plan != null && input.plan != SINGLE_STEP) missing.add("plan (only 'single-step' or null)")
        if (missing.isNotEmpty())
            return refuse(403, "authorize_config", "authorize_config: missing required component(s): ${missing.joinToString(", ")} (fail closed)", missing = missing)
        val audience = input.audience!!
        val resolveGrant = input.resolveGrant!!
        val stateStore = input.stateStore!!
        val isRevoked = input.isRevoked!!
        val operation = input.operation
        if (operation == null || !validOperation(operation))
            return refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)")
        // a private copy: the params that are verified cannot change under the verifier
        val opParams = Json.parse(Json.canonicalize(operation.params)) as Map<String, Any?>
        val opVerb = operation.verb
        val opResource = operation.resource

        val (p, err) = coerce(pcactn)
        if (p == null) return refuse(401, "wire", if (err == "absent") "wire: no PCActn presented" else "wire: PCActn could not be decoded")
        val grantRef = p["grant_ref"] as? String ?: return refuse(401, "malformed", "malformed: grant_ref is not a string", pcactn = p)
        val grant: Map<String, Any?>? = try {
            resolveGrant(grantRef)
        } catch (e: Exception) {
            return refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn = p)
        }
        if (grant == null) return refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn = p)

        val now = input.now ?: System.currentTimeMillis()
        var ctx: Map<String, Any?> = emptyMap()
        val contextFn = input.context
        if (contextFn != null) {
            val got: Any? = try {
                contextFn(p)
            } catch (e: Exception) {
                return refuse(403, "context", "context: the context callback failed (fail closed)", pcactn = p)
            }
            if (got != null && got !is Map<*, *>)
                return refuse(403, "context", "context: the context callback must return a map (fail closed)", pcactn = p)
            if (got != null) ctx = got as Map<String, Any?>
        }

        var v2: IntentV2.Context? = null
        val v2Fn = input.intentV2
        if (v2Fn != null) {
            v2 = try {
                v2Fn(p)
            } catch (e: Exception) {
                return refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn = p)
            }
        }
        if (v2 != null && v2.wellFormed && v2.get("params") == null) v2 = v2.withParams(opParams)

        // ---- 1. the core checks
        val core = Pca.verifyPcactn(p, grant, now, Pca.Audience.Of(audience), input.allowedSuites, input.intentPolicy, v2)
        if (core.checks["wire"] == false) {
            val r = if (core.reason.isNotEmpty()) core.reason else "wire: malformed PCActn"
            return Result(false, 401, linkedMapOf("wire" to "fail", "malformed" to "fail"), listOf(r), r, pcactn = p, verdict = core)
        }
        val checks = LinkedHashMap<String, String>()
        for ((k, ok) in core.checks) checks[k] = if (ok) "pass" else "fail"
        val reasons = ArrayList<String>()
        if (!core.allow && core.reason.isNotEmpty()) reasons.add(core.reason)

        fun mark(name: String, status: String) { checks[name] = status }
        fun fail(name: String, why: String) {
            checks[name] = "fail"
            reasons.add("$name: $why")
        }

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        val revoked: Any? = try { isRevoked(p, grant) } catch (e: Exception) { null }
        if (revoked == false) mark("revocation", "pass")
        else fail("revocation", if (revoked == true) "the grant is revoked" else "the revocation check failed (fail closed)")
        if (p.containsKey("zk_compliance"))
            fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)")

        val action = p["action"] as? Map<String, Any?> ?: emptyMap()
        val signedDigest = action["params_digest"]
        val opDigest = Pca.paramsDigest(opParams)

        // ---- 3. the operation binding
        if (action["verb"] != opVerb || action["resource"] != opResource)
            fail("operation", "the proof is for ${jsString(action["verb"])} on ${jsString(action["resource"])}, but this operation is $opVerb on $opResource")
        else if (opDigest != signedDigest)
            fail("operation", "the proof's params_digest does not match the params of this $opVerb operation")
        else mark("operation", "pass")

        // ---- 4. grant_ref, params, plan, attestation, reversibility
        if (grantRef == grant["id"]) mark("grant_ref", "pass") else fail("grant_ref", "does not reference the supplied grant")
        if (opDigest == signedDigest) mark("params_digest", "pass") else fail("params_digest", "supplied params do not hash to action.params_digest")

        val pl = p["plan"] as? Map<String, Any?> ?: emptyMap()
        val nodeId = pl["node_id"]
        var planNodes: Any? = ctx["plan"]
        var planAuthorized: Any? = ctx["plan_authorized"]
        if (input.plan == SINGLE_STEP && planNodes == null) {
            planNodes = listOf(
                linkedMapOf(
                    "id" to jsString(nodeId), "verb" to opVerb, "resource" to opResource, "params_digest" to opDigest,
                    "reversibility_class" to action["reversibility_class"],
                ),
            )
            planAuthorized = true
        }
        if (planNodes != null) {
            val known: String? = try {
                Pca.merkleRoot(
                    (planNodes as List<*>).map {
                        val n = it as Map<String, Any?>
                        Pca.planLeaf(n["id"], n, Pca.conditionsDigest(n["pre"], n["post"]))
                    },
                )
            } catch (e: Exception) {
                null
            }
            if (known == null || known != pl["root"]) fail("plan_root_authorized", "known plan does not match plan.root")
            else if (planAuthorized != true) fail("plan_root_authorized", "the plan root has not been authorized by the principal")
            else mark("plan_root_authorized", "pass")
        } else mark("plan_root_authorized", "not-enforced")

        val env = readEnvelope(grant)
        if (requiresAttestation(env?.get("agent_binding")))
            fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)")

        val declared = action["reversibility_class"]
        var effective = declared
        val serverClass = ctx["reversibility_class"]
        if (serverClass != null) {
            val dr = classRank(declared)
            val sr = classRank(serverClass)
            if (dr < sr) fail("reversibility", "declared class '${jsString(declared)}' is less restrictive than the authoritative '${jsString(serverClass)}'")
            else mark("reversibility", "pass")
            effective = if (dr > sr) declared else serverClass
        }

        // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
        val chain = p["cap_chain"] as? List<Any?> ?: emptyList()
        val depth = maxOf(0, chain.size - 1)
        val inner = linkedMapOf<String, Any?>("verb" to action["verb"], "resource" to action["resource"], "params" to opParams)
        if (effective != null) inner["reversibility_class"] = effective
        val actionCtx = linkedMapOf<String, Any?>("action" to inner)
        if (ctx["subject"] != null) actionCtx["subject"] = ctx["subject"]
        val predEnv = v2Env(p, grant, v2, now, ctx["env"])
        if (predEnv != null) actionCtx["env"] = predEnv
        val toolCall = linkedMapOf<String, Any?>("tool" to (inner["verb"] as? String ?: ""), "args" to opParams)
        if (p["tool_binding"] is String) toolCall["tool_signature_digest"] = p["tool_binding"]
        var revClass = effective
        if (revClass == null && nodeId is String && planNodes is List<*>)
            revClass = planNodes.firstOrNull { it is Map<*, *> && it["id"] == nodeId }?.let { (it as Map<*, *>)["reversibility_class"] }
        val cctx = linkedMapOf<String, Any?>("now" to now, "action" to inner, "delegation_depth" to depth)
        if (ctx["blast_radius"] != null) cctx["blast_radius"] = ctx["blast_radius"]
        if (revClass != null) cctx["reversibility_class"] = revClass
        if (ctx["recent_action_times"] != null) cctx["recent_action_times"] = ctx["recent_action_times"]

        if (chain.isNotEmpty()) {
            val leaf = chain[chain.size - 1] as? Map<String, Any?> ?: emptyMap()
            val gcs = grant["caveats"] as? List<*> ?: emptyList<Any?>()
            val lcs = leaf["caveats"]
            val extra: Any? = if (lcs is List<*>) (if (gcs.size >= lcs.size) emptyList() else lcs.subList(gcs.size, lcs.size)) else null
            val r = evaluateAgentCaveats(extra, cctx, actionCtx, toolCall)
            if (r.ok) mark("delegated_caveats", "pass")
            else fail("delegated_caveats", "delegation caveat(s) not satisfied: ${r.failed.joinToString(", ")}")
        }

        val policyWhy: List<String> = try {
            SafeRegex.withBudget {
                val why = ArrayList<String>()
                if (env == null) {
                    why.add("grant carries no valid envelope")
                } else {
                    val pr = envelopePredicates(env["predicates"], actionCtx)
                    if (pr != null) why.add(pr)
                    val ec = evaluateAgentCaveats(env["caveats"], cctx, actionCtx, toolCall)
                    if (!ec.ok) why.add("caveat(s) not satisfied: ${ec.failed.joinToString(", ")}")
                    val rc = evaluateAgentCaveats(rootCaveats(grant), cctx, actionCtx, toolCall)
                    if (!rc.ok) why.add("root caveat(s) not satisfied: ${rc.failed.joinToString(", ")}")
                }
                why
            }
        } catch (e: Exception) {
            listOf("policy evaluation error (fail closed)")
        }
        if (policyWhy.isNotEmpty()) {
            checks["policy"] = "fail"
            for (w in policyWhy) reasons.add("policy: $w")
        } else mark("policy", "pass")

        // ---- required checks (default-deny), then the replay counter. `replay` passes tentatively; a refused claim flips it.
        checks["replay"] = "pass"
        // `counter` is the old name of `replay`
        for (name in DEFAULT_REQUIRED_CHECKS + input.require.map { if (it == "counter") "replay" else it }) {
            val st = checks[name]
            if (st != "pass" && st != "fail") {
                checks[name] = "fail"
                reasons.add("$name: required check is ${st ?: "absent"} (default-deny: not enforced by this resource server)")
            }
        }

        fun deny(): Result {
            val status = if (AUTHN_CHECKS.any { checks[it] == "fail" }) 401 else 403
            return Result(false, status, checks, reasons, decisive(checks, reasons), pcactn = p, verdict = core)
        }

        if (checks.values.any { it == "fail" }) return deny()

        val holder = (chain.lastOrNull() as? Map<*, *>)?.get("holder")
        val grantId = grant["id"]
        val counter = p["counter"]
        if (holder !is String || grantId !is String || !Json.isSafeInt(counter)) {
            fail("replay", "no counter stream for this proof (fail closed)")
            return deny()
        }
        val n = Json.asLong(counter)
        val claimed: ClaimResult? = try { stateStore.claim(stateKey(grantId, holder), n) } catch (e: Exception) { null }
        if (claimed == null || !claimed.ok) {
            val last = claimed?.lastCounter
            when {
                claimed == null -> fail("replay", "the replay store failed (fail closed)")
                last != null -> fail("replay", "$n is not greater than last seen $last (replay)")
                else -> fail("replay", "$n was already claimed (replay)")
            }
            return deny()
        }
        return Result(
            true, 200, checks, reasons, null,
            operation = AuthorizedOperation(opVerb, opResource, signedDigest as String, Pca.hashCanonical(p)), pcactn = p, verdict = core,
        )
    }

    /** The envelope predicates (default deny): null when the action matches one, else the refusal (TypeScript wording). */
    /** The envelope predicates (default deny): null when the action matches one, else the refusal (TypeScript wording). */
    private fun envelopePredicates(predicates: Any?, actionCtx: Map<String, Any?>): String? = try {
        Predicates.denialReason(predicates, actionCtx)
    } catch (e: RuntimeException) {
        "predicate evaluation error (fail closed)"
    }

    /** The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (TypeScript `v2Env`). */
    private fun v2Env(p: Map<String, Any?>, grant: Map<String, Any?>, v2: IntentV2.Context?, now: Long, env: Any?): Any? {
        if (!p.containsKey("intent_session")) return env
        val rest = LinkedHashMap<String, Any?>()
        if (env is Map<*, *>) for ((k, v) in env) rest[k as String] = v
        for (k in listOf("acc", "mon", "canon", "world", "prov", "class")) rest.remove(k)
        for ((k, v) in IntentV2.decide(p, grant, v2, now).env) if (v != null) rest[k] = v
        return rest
    }

    /**
     * True only if `result` allowed exactly this operation (verb, resource, params digest). Call it where the side effect
     * runs, with the values it is about to use.
     */
    fun isAuthorizedFor(result: Result?, operation: Operation?): Boolean = try {
        val b = if (result != null && result.allow) result.operation else null
        b != null && operation != null && validOperation(operation) && b.verb == operation.verb &&
            b.resource == operation.resource && b.paramsDigest == Pca.paramsDigest(Json.parse(Json.canonicalize(operation.params)))
    } catch (e: Exception) {
        false
    }
}
