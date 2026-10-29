package net.atlasauth.pca.verifier

import java.security.MessageDigest
import java.text.Normalizer

/** A refusal of the action kit: a stable `code` (`bad_registry`, `unknown_trait`, `duplicate_def`, `empty_pack`, `not_in_pack`). */
class ActionKitError(val code: String, message: String) : RuntimeException(message)

/**
 * Action kit (native port of the small deterministic core of packages/pca-actions): strict ActionDef parse, normalize and
 * canonical digest, the trait registry with its closure and floor algebra, rule 22 (FloorDecision and the schema floor
 * integrity check), the pack Merkle root and inclusion proof, and T(d) / eff(d). Integers and sets only; every function is
 * pure. Values are the parsed JSON model of this package (Map / List / String / Boolean / Json.Num / Int / null), profiles
 * are maps with Int numbers. The shared vectors pin every output byte for byte. ActionSchema v2 parsing and the v2 parameter
 * types and formats live in [ActionSchema].
 */
@Suppress("UNCHECKED_CAST")
object Actions {
    const val ACTION_DEF_KIND = "pca-action-def"
    const val DEF_DIGEST_DOMAIN = "atlas-pca/action-def/v1"
    const val TRAITS_DIGEST_DOMAIN = "atlas-pca/action-traits/v1"
    const val ROLES_DIGEST_DOMAIN = "atlas-pca/action-roles/v1"
    const val PACK_DIGEST_DOMAIN = "atlas-pca/action-pack/v1"

    private const val MAX_VERB_BYTES = 128
    private const val MAX_TITLE_BYTES = 120
    private const val MAX_DESCRIPTION_BYTES = 1024
    private const val MAX_DEF_PARAMS = 64
    private const val MAX_DEF_ALIASES = 16
    private const val MAX_DEF_TRAITS = 32
    private const val MAX_DEF_CONTEXT = 16
    private const val MAX_DEF_SIDE_EFFECTS = 16
    private const val MAX_TRAIT_IMPLIES_DEPTH = 8
    private const val MAX_REGISTRY_TRAITS = 512
    private const val PPM_MAX = 1_000_000L

    private val EFFECTS = listOf("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign")
    private val REVERSIBILITY = listOf("reversible", "rate_limited", "irreversible")
    private val REV_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "irreversible" to 2)
    private val BLAST_RADII = listOf("one", "bounded", "tenant", "global")
    private val BLAST_PPM = mapOf("one" to 50_000, "bounded" to 300_000, "tenant" to 700_000, "global" to 1_000_000)
    private val RESOURCE_SCOPES = listOf("one", "set", "tenant", "global")
    private val SCOPE_BLAST = mapOf("one" to "one", "set" to "bounded", "tenant" to "tenant", "global" to "global")
    private val PARAM_TYPES = listOf("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref")
    private val SENSITIVITY_RANK = mapOf("free" to 0, "material" to 1, "critical" to 2)
    private val PROVENANCE_LEVELS = listOf("first_party", "tool", "agent")
    private val CORE_ROLES = listOf(
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    )
    private val PARAM_TAGS = listOf("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql")
    private val PARAM_FORMATS = listOf("email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256")
    private val UNIT_KINDS = listOf("money", "count", "bytes", "duration", "ratio")
    internal val CAVEAT_KINDS = listOf("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap")
    internal val CONTEXT_KEYS = listOf("approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested")
    internal val PARAM_RULE_IDS = listOf(
        "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
        "pay_has_idempotency", "recipient_param_declared", "secret_not_logged",
    )
    private val IDEMPOTENCY_MODES = listOf("key_param", "natural", "none")
    private val REVIEW_STATES = listOf("authored", "unreviewed", "suggested", "confirmed")
    private val BINDING_KINDS = listOf("mcp", "openapi", "http", "graphql", "grpc", "asyncapi")
    private val ID_CLASSES = listOf("digits", "hex", "alnum", "slug", "uuid", "any_safe")

    private val ID_ROLE_RE = Regex("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val CUSTOM_ROLE_RE = Regex("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}")
    private val ID_FORMAT_RE = Regex("id:[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val TAINT_RE = Regex("session_taint_max:[a-z_]{1,16}")
    private val VERB_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}")
    private val ALIAS_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}")
    private val PARAM_NAME_RE = Regex("[A-Za-z0-9_]{1,64}(?:\\.[A-Za-z0-9_]{1,64}){0,2}")
    private val TRAIT_ID_RE = Regex("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}")
    private val RESOURCE_TYPE_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}")
    private val UNIT_ID_RE = Regex("[a-z0-9_]+(?:\\.[a-z0-9_]+)*")
    private val CCY_RE = Regex("[A-Z]{3}")
    private val RESERVED = listOf("__proto__", "constructor", "prototype")
    private val INT_ROLES = listOf("money.amount", "money.fee", "count.limit", "bytes.size")
    private val PARAM_KEYS = setOf(
        "type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags",
        "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description",
    )
    private val DEF_KEYS = setOf(
        "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
        "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since",
    )

    // ---- small helpers ------------------------------------------------------------------------------------------------------

    private fun isInt(v: Any?): Boolean = IntentJs.isInt(v)
    private fun isNonNeg(v: Any?): Boolean = IntentJs.isNonNeg(v)
    private fun iv(v: Any?): Long = IntentJs.num(v)!!.toLong()
    private fun isStr(v: Any?, max: Int = 256): Boolean = v is String && v.isNotEmpty() && IntentJs.u8len(v) <= max
    private fun isIn(x: Any?, options: Collection<String>): Boolean = x is String && x in options
    private fun isMap(x: Any?): Boolean = x is Map<*, *>
    private fun isNum(x: Any?, n: Double): Boolean = (x is Json.Num || x is Int || x is Long) && IntentJs.num(x) == n
    private fun sortUniq(xs: Collection<String>): List<String> = xs.toSortedSet().toList()
    private fun strs(x: Any?): List<String> = (x as? List<Any?>)?.map { it as String } ?: emptyList()
    internal fun isContextKey(k: Any?): Boolean = k is String && (k in CONTEXT_KEYS || TAINT_RE.matches(k))
    private fun distinct(xs: List<*>): Boolean = HashSet<Any?>(xs).size == xs.size
    private fun strList(v: Any?, mx: Int, ok: (String) -> Boolean): Boolean =
        v is List<*> && v.size <= mx && v.all { it is String && ok(it) } && distinct(v)
    private fun keysOf(m: Map<*, *>): String = m.keys.map { it as String }.sorted().joinToString(",")
    private fun isRole(r: Any?): Boolean = r is String && (r in CORE_ROLES || ID_ROLE_RE.matches(r) || CUSTOM_ROLE_RE.matches(r))
    private fun isFormat(f: Any?): Boolean = f is String && (f in PARAM_FORMATS || ID_FORMAT_RE.matches(f))
    private fun hasLone(s: String): Boolean = Json.hasLoneSurrogate(s)
    private fun nfc(s: String): Boolean = Normalizer.normalize(s, Normalizer.Form.NFC) == s

    // ---- strict JSON profile + ActionDef validation -------------------------------------------------------------------------

    /** Strict JSON profile: NFC strings without lone surrogates, safe integers only, depth <= 32. Null = ok. */
    fun jsonProfileError(v: Any?, depth: Int = 0): String? {
        if (depth > 32) return "nesting deeper than 32"
        return when (v) {
            null, is Boolean -> null
            is Json.Num, is Int, is Long, is Double -> if (isInt(v)) null else "numbers must be safe integers (no floats, no -0)"
            is String -> if (hasLone(v)) "string has a lone surrogate" else if (!nfc(v)) "string is not NFC" else null
            is List<*> -> {
                for (x in v) jsonProfileError(x, depth + 1)?.let { return it }
                null
            }
            is Map<*, *> -> {
                for ((k, x) in v) {
                    val key = k as String
                    if (hasLone(key) || !nfc(key)) return "member name is not NFC / has a lone surrogate"
                    jsonProfileError(x, depth + 1)?.let { return it }
                }
                null
            }
            else -> "only JSON values are allowed"
        }
    }

    private const val ID_DIGITS = "0123456789"
    private const val ID_LOWER = "abcdefghijklmnopqrstuvwxyz"
    private fun idClassChars(c: String): String = when (c) {
        "digits" -> ID_DIGITS
        "hex" -> ID_DIGITS + "abcdef"
        "alnum" -> ID_DIGITS + ID_LOWER + ID_LOWER.uppercase()
        "slug" -> ID_DIGITS + ID_LOWER + "-_"
        "uuid" -> ID_DIGITS + "abcdef-"
        else -> ID_DIGITS + ID_LOWER + ID_LOWER.uppercase() + "._-:/"
    }

    private fun inClass(s: String, c: String): Boolean {
        val chars = idClassChars(c)
        return s.all { it in chars }
    }

    private fun idPatternError(p: Any?): String? {
        if (p == "*") return null
        if (p !is Map<*, *>) return "resource.id must be '*', {exact} or {prefix, class, len}"
        val keys = keysOf(p)
        if (keys == "exact") {
            val e = p["exact"]
            return if (e is String && e.length in 1..128 && inClass(e, "any_safe")) null else "resource.id.exact must be 1..128 safe characters"
        }
        if (keys != "class,len,prefix") return "resource.id must be '*', {exact} or {prefix, class, len}"
        val prefix = p["prefix"]
        if (prefix !is String || prefix.length > 32 || !inClass(prefix, "any_safe")) return "resource.id.prefix must be up to 32 safe characters"
        if (!isIn(p["class"], ID_CLASSES)) return "resource.id.class is not an id class"
        val ln = p["len"]
        if (ln !is List<*> || ln.size != 2 || !ln.all { isInt(it) && iv(it) in 1..128 }) return "resource.id.len must be [min, max] in 1..128"
        if (iv(ln[0]) > iv(ln[1])) return "resource.id.len: min > max"
        if (p["class"] == "uuid" && (prefix != "" || iv(ln[0]) != 36L || iv(ln[1]) != 36L)) return "a uuid id has no prefix and length exactly [36, 36]"
        return null
    }

    private fun paramNameError(name: String): String? {
        if (!PARAM_NAME_RE.matches(name)) return "param name '$name' is malformed"
        if (name.split(".").any { it in RESERVED }) return "param name '$name' is reserved"
        return null
    }

    private fun paramError(name: String, pO: Any?, names: Set<String>): String? {
        if (pO !is Map<*, *>) return "$name: declaration must be an object"
        val p = pO as Map<String, Any?>
        for (k in p.keys) if (k !in PARAM_KEYS) return "$name: unknown member '$k'"
        if (!isIn(p["type"], PARAM_TYPES)) return "$name: unknown type"
        val t = p["type"] as String
        if (p.containsKey("role") && !isRole(p["role"])) return "$name: unknown role"
        if (p["role"] is String && p["role"] in INT_ROLES && t != "integer") return "$name: role requires an integer parameter"
        if (p.containsKey("required") && p["required"] !is Boolean) return "$name: required must be a boolean"
        if (p.containsKey("values")) {
            val vs = p["values"]
            if (vs !is List<*> || vs.isEmpty() || vs.size > 256 || !vs.all { isStr(it) }) return "$name: values must be 1..256 non-empty strings"
            if (!distinct(vs)) return "$name: values must be distinct"
            if (t != "string" && t != "set") return "$name: values apply to string and set only"
        }
        if (t == "set" && !p.containsKey("values")) return "$name: a set needs values"
        val intLike = t == "integer" || t == "duration" || (t == "array" && p["items"] == "integer")
        for (k in listOf("min", "max")) if (p.containsKey(k) && (!isInt(p[k]) || !intLike)) return "$name: $k must be a safe integer on an integer parameter"
        if (isInt(p["min"]) && isInt(p["max"]) && iv(p["min"]) > iv(p["max"])) return "$name: min > max"
        if (p.containsKey("max_len") && (!isInt(p["max_len"]) || iv(p["max_len"]) < 1 || iv(p["max_len"]) > 16_777_216 || t !in listOf("string", "array", "object_ref")))
            return "$name: max_len must be 1..16777216 on a string or array"
        if (p.containsKey("items") && (t != "array" || !isStr(p["items"], 64))) return "$name: items applies to array only"
        for (k in listOf("min_items", "max_items")) if (p.containsKey(k) && (!isNonNeg(p[k]) || (t != "set" && t != "array"))) return "$name: $k must be a non-negative integer on a set or array"
        if (isInt(p["min_items"]) && isInt(p["max_items"]) && iv(p["min_items"]) > iv(p["max_items"])) return "$name: min_items > max_items"
        if (p.containsKey("format") && (!isFormat(p["format"]) || (t != "string" && t != "object_ref"))) return "$name: format must be a known format on a string parameter"
        if (p.containsKey("unit")) {
            val u = p["unit"]
            if (t != "integer") return "$name: unit applies to integer parameters only"
            if (u !is Map<*, *> || !isIn(u["kind"], UNIT_KINDS)) return "$name: unit.kind is not a known kind"
            if (u["kind"] == "money") {
                if (u.keys.any { it !in listOf("kind", "ccy", "exp") }) return "$name: unit has unknown members"
                if (!isInt(u["exp"]) || iv(u["exp"]) < 0 || iv(u["exp"]) > 18) return "$name: unit.exp must be an integer in 0..18"
                val c = u["ccy"]
                if (c is String) {
                    if (!CCY_RE.matches(c)) return "$name: unit.ccy must be an ISO 4217 style code"
                } else if (c !is Map<*, *> || c.keys.joinToString(",") != "from" || c["from"] !is String || c["from"] !in names) {
                    return "$name: unit.ccy.from must name a declared parameter"
                }
            } else if (u.keys.joinToString(",") != "kind") return "$name: unit has unknown members"
        }
        if (p.containsKey("tags")) {
            val tg = p["tags"]
            if (tg !is List<*> || tg.size > PARAM_TAGS.size || !tg.all { isIn(it, PARAM_TAGS) } || !distinct(tg)) return "$name: tags must be distinct known tags"
        }
        if (p.containsKey("provenance_min") && !isIn(p["provenance_min"], PROVENANCE_LEVELS)) return "$name: unknown provenance_min"
        if (p.containsKey("sensitivity") && !isIn(p["sensitivity"], SENSITIVITY_RANK.keys)) return "$name: unknown sensitivity"
        if (p.containsKey("accumulates")) {
            val a = p["accumulates"]
            if (t != "integer") return "$name: accumulates applies to integer parameters only"
            if (a !is List<*> || a.isEmpty() || a.size > 8 || !a.all { it is String && it.length <= 64 && UNIT_ID_RE.matches(it) } || !distinct(a))
                return "$name: accumulates must be 1..8 distinct unit ids"
        }
        if (p.containsKey("default") && p["default"] == null) return "$name: default must not be null (absent = no default)"
        if (p.containsKey("principal_neutral_default") && p["principal_neutral_default"] !is Boolean) return "$name: principal_neutral_default must be a boolean"
        if (p["principal_neutral_default"] == true && !p.containsKey("default")) return "$name: principal_neutral_default needs a default"
        if (p.containsKey("description") && !isStr(p["description"], MAX_DESCRIPTION_BYTES)) return "$name: description must be a string up to $MAX_DESCRIPTION_BYTES bytes"
        return null
    }

    private fun bindingsError(b: Any?): String? {
        if (b !is Map<*, *>) return "bindings must be an object"
        val shapes = mapOf(
            "mcp" to (listOf("tool") to listOf<String>()), "openapi" to (listOf("operationId") to listOf("method", "path")),
            "http" to (listOf("method", "path") to listOf<String>()), "graphql" to (listOf("op", "field") to listOf<String>()),
            "grpc" to (listOf("service", "method") to listOf<String>()), "asyncapi" to (listOf("channel", "op") to listOf<String>()),
        )
        for ((kO, v) in b) {
            val k = kO as String
            if (k !in BINDING_KINDS) return "bindings: unknown kind '$k'"
            val (req, opt) = shapes[k]!!
            if (v !is Map<*, *>) return "bindings.$k must be an object"
            for (m in v.keys) if (m !in req && m !in opt) return "bindings.$k: unknown member '$m'"
            for (m in req) if (!isStr(v[m], 256)) return "bindings.$k.$m must be a non-empty string"
            for (m in opt) if (v.containsKey(m) && !isStr(v[m], 256)) return "bindings.$k.$m must be a non-empty string"
        }
        if (b.containsKey("graphql") && (b["graphql"] as Map<*, *>)["op"] !in listOf("query", "mutation", "subscription")) return "bindings.graphql.op is not a GraphQL operation kind"
        if (b.containsKey("asyncapi") && (b["asyncapi"] as Map<*, *>)["op"] !in listOf("send", "receive")) return "bindings.asyncapi.op must be send or receive"
        return null
    }

    private fun reviewError(r: Any?): String? {
        if (r !is Map<*, *>) return "review must be an object"
        for (k in r.keys) if (k !in listOf("state", "attestation", "suggested_by")) return "review: unknown member '$k'"
        if (!isIn(r["state"], REVIEW_STATES)) return "review.state is not a review state"
        if (r.containsKey("attestation")) {
            val a = r["attestation"]
            if (a !is Map<*, *>) return "review.attestation must be an object"
            for (k in a.keys) if (k !in listOf("def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig")) return "review.attestation: unknown member '$k'"
            if (!isStr(a["def_digest"], 64) || !isStr(a["traits_digest"], 64) || !isStr(a["facts_digest"], 64) || !isStr(a["reviewer_kid"], 128) || !isNonNeg(a["ts"]))
                return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required"
            if (!strList(a["final_traits"], MAX_DEF_TRAITS) { TRAIT_ID_RE.matches(it) }) return "review.attestation.final_traits must be distinct trait ids"
            val d = a["dismissed"]
            if (d !is List<*> || d.size > MAX_DEF_TRAITS || !d.all {
                    it is Map<*, *> && keysOf(it) == "reason,trait" && it["trait"] is String && TRAIT_ID_RE.matches(it["trait"] as String) && isStr(it["reason"], 256)
                }) return "review.attestation.dismissed must be {trait, reason} entries"
            if (a.containsKey("sig") && !isStr(a["sig"], 4096)) return "review.attestation.sig must be a string"
        }
        return null
    }

    /** Null if `x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never throws. */
    fun validateDef(x: Any?): String? {
        try {
            jsonProfileError(x)?.let { return "not strict JSON: $it" }
            if (x !is Map<*, *>) return "def must be an object"
            val d = x as Map<String, Any?>
            for (k in d.keys) if (k !in DEF_KEYS) return "unknown member '$k'"
            if (!isNum(d["v"], 1.0)) return "unsupported def version"
            if (d["kind"] != ACTION_DEF_KIND) return "kind must be '$ACTION_DEF_KIND'"
            val verb = d["verb"]
            if (verb !is String || !VERB_RE.matches(verb) || IntentJs.u8len(verb) > MAX_VERB_BYTES) return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)"
            if (d.containsKey("aliases") && (!strList(d["aliases"], MAX_DEF_ALIASES) { ALIAS_RE.matches(it) && IntentJs.u8len(it) <= MAX_VERB_BYTES } || (d["aliases"] as List<*>).contains(verb)))
                return "aliases must be distinct verb-shaped names other than the verb"
            if (!isStr(d["title"], MAX_TITLE_BYTES)) return "title must be a non-empty string up to $MAX_TITLE_BYTES bytes"
            if (d.containsKey("description") && !isStr(d["description"], MAX_DESCRIPTION_BYTES)) return "description must be a string"
            if (!strList(d["effects"], EFFECTS.size) { it in EFFECTS } || (d["effects"] as List<*>).isEmpty()) return "effects must be 1..12 distinct known effects"
            val r = d["resource"]
            if (r !is Map<*, *> || keysOf(r) != "id,scope,type") return "resource must be {type, id, scope}"
            val rt = r["type"]
            if (rt !is String || !RESOURCE_TYPE_RE.matches(rt) || rt.length > 128) return "resource.type is malformed"
            idPatternError(r["id"])?.let { return it }
            if (!isIn(r["scope"], RESOURCE_SCOPES)) return "resource.scope is not a scope"
            val params = d["params"]
            if (params !is Map<*, *>) return "params must be an object"
            val names = params.keys.map { it as String }
            if (names.size > MAX_DEF_PARAMS) return "more than $MAX_DEF_PARAMS parameters"
            val nameSet = names.toSet()
            for (n in names) {
                paramNameError(n)?.let { return it }
                for (m in names) if (m != n && m.startsWith("$n.")) return "param '$n' is both a value and the parent of '$m'"
            }
            for (n in names) paramError(n, params[n], nameSet)?.let { return it }
            if (d.containsKey("reversibility")) {
                val rv = d["reversibility"]
                if (rv !is String) {
                    if (rv !is Map<*, *> || rv.keys.any { it !in listOf("by", "map", "default") }) return "reversibility must be a class or {by, map, default?}"
                    if (rv["by"] !is String || rv["by"] !in nameSet) return "reversibility.by must name a declared parameter"
                    val m = rv["map"]
                    if (m !is Map<*, *> || m.isEmpty() || m.size > 256 || !m.entries.all { isStr(it.key, 128) && isIn(it.value, REVERSIBILITY) }) return "reversibility.map must map values to reversibility classes"
                    if (rv.containsKey("default") && !isIn(rv["default"], REVERSIBILITY)) return "reversibility.default is not a class"
                } else if (rv !in REVERSIBILITY) return "unknown reversibility class"
            }
            if (d.containsKey("blast")) {
                val b = d["blast"]
                if (b !is Map<*, *> || b.keys.any { it !in listOf("radius", "ppm") } || !isIn(b["radius"], BLAST_RADII)) return "blast must be {radius, ppm?}"
                if (b.containsKey("ppm") && !(isInt(b["ppm"]) && iv(b["ppm"]) in 0..PPM_MAX)) return "blast.ppm must be an integer in 0..1000000"
            }
            if (d.containsKey("side_effects")) {
                val s = d["side_effects"]
                if (s !is List<*> || s.size > MAX_DEF_SIDE_EFFECTS || !s.all { it is Map<*, *> && keysOf(it) == "kind,target" && isStr(it["target"], 128) && isIn(it["kind"], EFFECTS) })
                    return "side_effects must be {target, kind} entries"
            }
            if (d.containsKey("idempotency")) {
                val i = d["idempotency"]
                if (i !is Map<*, *> || i.keys.any { it !in listOf("mode", "param") } || !isIn(i["mode"], IDEMPOTENCY_MODES)) return "idempotency must be {mode, param?}"
                val bad = if (i["mode"] == "key_param") (i["param"] !is String || i["param"] !in nameSet) else i.containsKey("param")
                if (bad) return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise"
            }
            if (d.containsKey("context") && !strList(d["context"], MAX_DEF_CONTEXT) { isContextKey(it) }) return "context must be distinct known context keys"
            if (d.containsKey("traits") && !strList(d["traits"], MAX_DEF_TRAITS) { TRAIT_ID_RE.matches(it) }) return "traits must be distinct trait ids"
            if (d.containsKey("audience") && d["audience"] != "resource") return "audience must be 'resource'"
            if (d.containsKey("compensates") && (d["compensates"] !is String || !VERB_RE.matches(d["compensates"] as String))) return "compensates must be a verb"
            if (d.containsKey("bindings")) bindingsError(d["bindings"])?.let { return it }
            if (d.containsKey("examples")) {
                val ex = d["examples"]
                if (ex !is List<*> || ex.size > 32) return "examples must be an array of up to 32 entries"
                for (e in ex) {
                    if (e !is Map<*, *> || e.keys.any { it !in listOf("params", "under", "expect") } || e["params"] !is Map<*, *> || e["expect"] !in listOf("allow", "escalate", "deny"))
                        return "example must be {params, under?, expect}"
                }
            }
            reviewError(d["review"])?.let { return it }
            if (d.containsKey("source")) {
                val s = d["source"]
                if (s !is Map<*, *> || s.keys.any { it !in listOf("kind", "uri", "spec_digest", "licence", "imported_at") } || !isStr(s["kind"], 64) ||
                    !isStr(s["uri"], 2048) || !isStr(s["spec_digest"], 128) || !isStr(s["licence"], 128) || (s.containsKey("imported_at") && !isNonNeg(s["imported_at"])))
                    return "source must be {kind, uri, spec_digest, licence, imported_at?}"
            }
            if (d.containsKey("since") && !isStr(d["since"], 64)) return "since must be a string"
            return null
        } catch (e: RuntimeException) {
            return "malformed def: " + e.message
        }
    }

    // ---- profile lattice + trait registry -------------------------------------------------------------------------------------

    /** A canonical profile (sorted, distinct sets). */
    fun profile(
        risk: Int = 0, rev: String = "reversible", blastPpm: Int = 0, esc: Int = 0,
        caveats: Collection<String> = emptyList(), context: Collection<String> = emptyList(), prules: Collection<String> = emptyList(),
    ): Map<String, Any?> = linkedMapOf(
        "risk" to risk, "rev" to rev, "blast_ppm" to blastPpm, "esc" to esc,
        "caveats" to sortUniq(caveats), "context" to sortUniq(context), "prules" to sortUniq(prules),
    )

    val BOTTOM: Map<String, Any?> = profile()

    private fun intIn(x: Any?, lo: Long, hi: Long): Boolean = isInt(x) && iv(x) in lo..hi

    /** Null if `p` is a well-formed canonical profile, else the reason. */
    fun profileError(p: Any?): String? {
        if (p !is Map<*, *>) return "profile must be an object"
        for (k in p.keys) if (k !in listOf("risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules")) return "profile: unknown member '$k'"
        if (!intIn(p["risk"], 0, 3)) return "profile.risk must be an integer in 0..3"
        if (!isIn(p["rev"], REVERSIBILITY)) return "profile.rev is not a reversibility class"
        if (!intIn(p["blast_ppm"], 0, PPM_MAX)) return "profile.blast_ppm must be an integer in 0..1000000"
        if (!intIn(p["esc"], 0, 3)) return "profile.esc must be an integer in 0..3"
        for (name in listOf("caveats", "context", "prules")) {
            val a = p[name]
            val ok: (Any?) -> Boolean = when (name) {
                "caveats" -> ({ x: Any? -> isIn(x, CAVEAT_KINDS) })
                "context" -> ({ x: Any? -> isContextKey(x) })
                else -> ({ x: Any? -> isIn(x, PARAM_RULE_IDS) })
            }
            if (a !is List<*> || a.size > 64 || !a.all { ok(it) }) return "profile.$name must be an array of known $name entries"
            for (i in 1 until a.size) if (!((a[i - 1] as String) < (a[i] as String))) return "profile.$name must be sorted and distinct"
        }
        return null
    }

    private fun rank(rev: Any?): Int = REV_RANK[rev as String]!!

    fun join(p: Map<String, Any?>, q: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "risk" to maxOf(iv(p["risk"]), iv(q["risk"])).toInt(),
        "rev" to (if (rank(p["rev"]) >= rank(q["rev"])) p["rev"] else q["rev"]),
        "blast_ppm" to maxOf(iv(p["blast_ppm"]), iv(q["blast_ppm"])).toInt(),
        "esc" to maxOf(iv(p["esc"]), iv(q["esc"])).toInt(),
        "caveats" to sortUniq(strs(p["caveats"]) + strs(q["caveats"])),
        "context" to sortUniq(strs(p["context"]) + strs(q["context"])),
        "prules" to sortUniq(strs(p["prules"]) + strs(q["prules"])),
    )

    fun joinAll(ps: Collection<Map<String, Any?>>): Map<String, Any?> = ps.fold(BOTTOM) { a, b -> join(a, b) }

    private fun subset(a: Any?, b: Any?): Boolean {
        val bl = b as List<*>
        return (a as List<*>).all { it in bl }
    }

    /** p <= q in the profile order. */
    fun leq(p: Map<String, Any?>, q: Map<String, Any?>): Boolean =
        iv(p["risk"]) <= iv(q["risk"]) && rank(p["rev"]) <= rank(q["rev"]) && iv(p["blast_ppm"]) <= iv(q["blast_ppm"]) && iv(p["esc"]) <= iv(q["esc"]) &&
            subset(p["caveats"], q["caveats"]) && subset(p["context"], q["context"]) && subset(p["prules"], q["prules"])

    /** Null if `defs` form a valid registry, else the first reason (ids, distinct, `pca.` reserved, implies resolve, T5, no cycle, depth <= 8). */
    fun registryError(defs: Any?, core: Boolean = false): String? {
        if (defs !is List<*> || defs.size > MAX_REGISTRY_TRAITS) return "a registry holds at most $MAX_REGISTRY_TRAITS traits"
        val by = LinkedHashMap<String, Map<String, Any?>>()
        for (t in defs) {
            if (t !is Map<*, *>) return "trait must be an object"
            val tid = t["id"]
            if (tid !is String || !TRAIT_ID_RE.matches(tid)) return "trait id '$tid' is malformed"
            if (tid.startsWith("pca.") && !core) return "trait '$tid': the pca. namespace is reserved for core traits"
            if (by.containsKey(tid)) return "trait '$tid' is defined twice"
            val im = t["implies"]
            if (im !is List<*> || im.size > 8 || !distinct(im) || im.any { it !is String }) return "trait '$tid': implies must be up to 8 distinct trait ids"
            profileError(t["floor"])?.let { return "trait '$tid': $it" }
            val cp = t["card_phrase"]
            if (cp !is String || cp.isEmpty() || cp.length > 120) return "trait '$tid': card_phrase must be a non-empty string up to 120 characters"
            by[tid] = t as Map<String, Any?>
        }
        for (t in by.values) {
            for (u in strs(t["implies"])) {
                val ud = by[u] ?: return "trait '${t["id"]}' implies unknown trait '$u'"
                if (!leq(ud["floor"] as Map<String, Any?>, t["floor"] as Map<String, Any?>)) return "trait '${t["id"]}': floor is below the floor of implied '$u'"
            }
        }
        val depth = HashMap<String, Int>()
        val visiting = HashSet<String>()
        fun walk(i: String): Int {
            depth[i]?.let { return it }
            if (!visiting.add(i)) return -1
            var d = 1
            for (u in strs(by[i]!!["implies"])) {
                val du = walk(u)
                if (du < 0) return -1
                d = maxOf(d, du + 1)
            }
            visiting.remove(i)
            depth[i] = d
            return d
        }
        for (t in by.values) {
            val d = walk(t["id"] as String)
            if (d < 0) return "trait '${t["id"]}': implies cycle"
            if (d > MAX_TRAIT_IMPLIES_DEPTH) return "trait '${t["id"]}': implies depth $d exceeds $MAX_TRAIT_IMPLIES_DEPTH"
        }
        return null
    }

    /** Build a registry (id -> trait def); throws [ActionKitError] `bad_registry`. */
    fun buildRegistry(defs: List<Map<String, Any?>>, core: Boolean = false): Map<String, Map<String, Any?>> {
        registryError(defs, core)?.let { throw ActionKitError("bad_registry", it) }
        val out = LinkedHashMap<String, Map<String, Any?>>()
        for (t in defs) out[t["id"] as String] = t
        return out
    }

    /** Core registry extended with custom traits (which must not use `pca.` and must extend what they imply). */
    fun extendRegistry(base: Map<String, Map<String, Any?>>, custom: Any?): Map<String, Map<String, Any?>> {
        if (custom !is List<*>) throw ActionKitError("bad_registry", "custom traits must be an array")
        for (c in custom) {
            if (c !is Map<*, *> || c["id"] !is String || base.containsKey(c["id"]) || (c["id"] as String).startsWith("pca.")) throw ActionKitError("bad_registry", "custom trait may not redefine a core trait")
        }
        return buildRegistry(base.values.toList() + custom.map { it as Map<String, Any?> }, core = true)
    }

    /** cl(S): the closure of a set of trait ids under `implies`, sorted. Throws `unknown_trait`. */
    fun closure(reg: Map<String, Map<String, Any?>>, ids: Collection<Any?>): List<String> {
        val seen = HashSet<String>()
        val stack = ArrayList<Any?>(ids)
        while (stack.isNotEmpty()) {
            val i = stack.removeAt(stack.size - 1)
            if (i is String && i in seen) continue
            val t = if (i is String) reg[i] else null
            if (t == null) throw ActionKitError("unknown_trait", "unknown trait '$i'")
            seen.add(i as String)
            stack.addAll(t["implies"] as List<*>)
        }
        return seen.sorted()
    }

    /** F(S): the join of the floors of the closure of S (empty = bottom). */
    fun floorOf(reg: Map<String, Map<String, Any?>>, ids: Collection<Any?>): Map<String, Any?> =
        joinAll(closure(reg, ids).map { reg[it]!!["floor"] as Map<String, Any?> })

    /**
     * FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a required caveat is missing from G, a required context key
     * is missing from the call, or rho.esc > G.preauth_esc; else allow.
     */
    fun floorDecision(g: Map<String, Any?>, call: Map<String, Any?>, rho: Map<String, Any?>): String {
        if (iv(rho["esc"]) > iv(g["max_esc"])) return "deny"
        if (!subset(rho["caveats"], g["caveats"]) || !subset(rho["context"], call["context"]) || iv(rho["esc"]) > iv(g["preauth_esc"])) return "escalate"
        return "allow"
    }

    // [id, implies, own floor, card phrase] - the 22 core traits
    private val TABLE: List<Triple<String, List<String>, Pair<Map<String, Any?>, String>>> = listOf(
        Triple("money_moving", listOf(), profile(3, "rate_limited", 700_000, 2, listOf("amount_cap", "count_cap", "window"), listOf("idempotency"), listOf("money_has_currency", "money_amount_bounded", "pay_has_idempotency")) to "moves money"),
        Triple("destructive", listOf(), profile(2, "rate_limited", 0, 1, listOf("resource_scope"), listOf(), listOf("id_not_wildcard")) to "deletes or destroys data"),
        Triple("irreversible", listOf(), profile(2, "irreversible", 0, 1, listOf(), listOf("fresh_revocation")) to "cannot be undone"),
        Triple("external_communication", listOf(), profile(2, "irreversible", 0, 0, listOf("recipient_scope", "rate_cap"), listOf(), listOf("recipient_param_declared")) to "sends to people outside your organisation"),
        Triple("data_export", listOf(), profile(2, "reversible", 0, 0, listOf("resource_scope", "count_cap"), listOf(), listOf("export_bounded")) to "exports data"),
        Triple("privilege_change", listOf(), profile(3, "reversible", 0, 3, listOf("resource_scope", "short_expiry")) to "changes who can do what"),
        Triple("code_execution", listOf(), profile(3, "irreversible", 0, 2, listOf("resource_scope"), listOf("sandbox_attested")) to "runs code or commands"),
        Triple("credential_access", listOf(), profile(3, "reversible", 0, 3, listOf(), listOf(), listOf("secret_not_logged")) to "reads or handles credentials"),
        Triple("bulk", listOf(), profile(2, "reversible", 0, 0, listOf("count_cap"), listOf(), listOf("array_bounded")) to "acts on many items at once"),
        Triple("pii_access", listOf(), profile(1, "reversible", 0, 0, listOf("resource_scope")) to "touches personal data"),
        Triple("public_exposure", listOf(), profile(2, "irreversible", 0, 1) to "makes content public"),
        Triple("persistence", listOf(), profile(2, "reversible", 0, 0, listOf("short_expiry"), listOf("revocable")) to "creates standing access or infrastructure"),
        Triple("infra_mutation", listOf(), profile(2, "rate_limited", 0, 0, listOf("resource_scope")) to "changes infrastructure"),
        Triple("cost_incurring", listOf(), profile(1, "reversible", 0, 0, listOf("amount_cap")) to "incurs cost"),
        Triple("legal_binding", listOf(), profile(3, "irreversible", 0, 3) to "legally or cryptographically binds you"),
        Triple("impersonation", listOf("external_communication"), profile(2, "reversible", 0, 1) to "acts as a person"),
        Triple("network_egress", listOf(), profile(1, "reversible", 0, 0, listOf("recipient_scope")) to "reaches out to the network"),
        Triple("financial_data_read", listOf(), profile(1, "reversible", 0, 0, listOf("resource_scope")) to "reads financial data"),
        Triple("regulated_data", listOf(), profile(2, "reversible", 0, 1) to "handles regulated data"),
        Triple("scheduled", listOf(), profile(2, "reversible", 0, 0, listOf("short_expiry", "count_cap")) to "runs later or repeatedly"),
        Triple("unreviewed", listOf(), profile(3, "irreversible", 1_000_000, 2, listOf("approval_ref", "resource_scope"), listOf("dry_run_first")) to "has not been reviewed yet"),
        Triple("agent_spawning", listOf(), profile(2, "reversible", 0, 0, listOf("count_cap")) to "starts another agent"),
    )

    /** The 22 core trait definitions. A floor is the own floor joined with the floors of the implied traits (T5 by construction). */
    val CORE_TRAIT_DEFS: List<Map<String, Any?>> by lazy {
        val floors = HashMap<String, Map<String, Any?>>()
        val out = ArrayList<Map<String, Any?>>()
        for ((name, implies, ownPhrase) in TABLE) {
            val id = "pca.$name"
            val imp = implies.map { "pca.$it" }
            var fl = ownPhrase.first
            for (u in imp) fl = join(fl, floors[u]!!)
            floors[id] = fl
            out.add(linkedMapOf("id" to id, "implies" to imp, "floor" to fl, "card_phrase" to ownPhrase.second))
        }
        out
    }

    val CORE_REGISTRY: Map<String, Map<String, Any?>> by lazy { buildRegistry(CORE_TRAIT_DEFS, core = true) }

    private val EFFECT_TRAITS: Map<String, List<String>> = mapOf(
        "read" to listOf(), "create" to listOf(), "update" to listOf(), "delete" to listOf("pca.destructive"), "send" to listOf("pca.external_communication"),
        "pay" to listOf("pca.money_moving"), "exec" to listOf("pca.code_execution"), "privilege" to listOf("pca.privilege_change"), "export" to listOf("pca.data_export"),
        "publish" to listOf("pca.public_exposure"), "provision" to listOf("pca.persistence", "pca.scheduled"), "sign" to listOf("pca.legal_binding"),
    )
    private val TAG_TRAITS: Map<String, List<String>> = mapOf(
        "pii" to listOf("pca.pii_access"), "phi" to listOf("pca.pii_access", "pca.regulated_data"), "pci" to listOf("pca.regulated_data"),
        "secret" to listOf("pca.credential_access"), "credential" to listOf("pca.credential_access"),
    )
    private val ROLE_TRAITS: Map<String, List<String>> = mapOf(
        "credential.secret" to listOf("pca.credential_access"), "credential.token" to listOf("pca.credential_access"),
        "credential.key" to listOf("pca.credential_access"), "url.target" to listOf("pca.network_egress"),
    )
    private val ROLE_SENSITIVITY_FLOOR: Map<String, String> = mapOf(
        "money.amount" to "critical", "money.currency" to "material", "money.fee" to "material", "party.payee" to "critical", "party.payer" to "material",
        "contact.email" to "material", "contact.phone" to "material", "contact.address" to "material", "person.name" to "material", "person.dob" to "material",
        "person.national_id" to "critical", "credential.secret" to "critical", "credential.token" to "critical", "credential.key" to "critical",
        "code.command" to "critical", "query.sql" to "critical", "text.message" to "material",
    )
    private val TAG_SENSITIVITY_FLOOR: Map<String, String> = mapOf(
        "pii" to "material", "phi" to "material", "pci" to "material", "secret" to "critical", "credential" to "critical",
        "free_text_outbound" to "material", "code" to "material", "path" to "material", "sql" to "material",
    )

    /** Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`. */
    fun traitsDigest(reg: Map<String, Map<String, Any?>>): String {
        val ts = reg.values.sortedBy { it["id"] as String }.map {
            linkedMapOf("id" to it["id"], "implies" to strs(it["implies"]).sorted(), "floor" to it["floor"], "card_phrase" to it["card_phrase"])
        }
        return Pca.hashCanonical(linkedMapOf("d" to TRAITS_DIGEST_DOMAIN, "traits" to ts))
    }

    /** Digest of the implication and sensitivity tables the trait expansion reads. */
    fun tablesDigest(): String = Pca.hashCanonical(
        linkedMapOf(
            "d" to ROLES_DIGEST_DOMAIN, "roles" to CORE_ROLES, "effect_traits" to EFFECT_TRAITS, "role_traits" to ROLE_TRAITS,
            "tag_traits" to TAG_TRAITS, "role_sensitivity" to ROLE_SENSITIVITY_FLOOR, "tag_sensitivity" to TAG_SENSITIVITY_FLOOR,
        ),
    )

    // ---- normalize + digest ---------------------------------------------------------------------------------------------------

    private fun isReadOnly(effects: List<*>): Boolean = effects.isNotEmpty() && effects.all { it == "read" }
    private fun maxSens(a: String, b: String): String = if (SENSITIVITY_RANK[a]!! >= SENSITIVITY_RANK[b]!!) a else b

    private fun sensitivityFloor(p: Map<String, Any?>): String {
        var f = "free"
        val role = p["role"]
        if (role is String && ROLE_SENSITIVITY_FLOOR.containsKey(role)) f = maxSens(f, ROLE_SENSITIVITY_FLOOR[role]!!)
        for (t in strs(p["tags"])) if (TAG_SENSITIVITY_FLOOR.containsKey(t)) f = maxSens(f, TAG_SENSITIVITY_FLOOR[t]!!)
        return f
    }

    private fun effectiveParamSensitivity(p: Map<String, Any?>): String = maxSens((p["sensitivity"] as String?) ?: "free", sensitivityFloor(p))

    private fun declaredReversibility(d: Map<String, Any?>): Any? =
        if (d.containsKey("reversibility")) d["reversibility"] else if (isReadOnly(d["effects"] as List<*>)) "reversible" else "irreversible"

    private fun maxRev(xs: List<Any?>): String {
        var out = "reversible"
        for (b in xs) if (b is String && REV_RANK.containsKey(b) && REV_RANK[b]!! > REV_RANK[out]!!) out = b
        return out
    }

    /** Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have. */
    fun worstReversibility(r: Any?, params: Map<String, Map<String, Any?>>): String {
        if (r is String) return r
        r as Map<String, Any?>
        val d = (r["by"] as? String)?.let { params[it] }
        val mapped = (r["map"] as Map<String, Any?>).values.toList()
        var domain: List<Any?>? = null
        if (d != null) {
            if (d["type"] == "boolean") domain = listOf("true", "false")
            else if (d["type"] == "string" && d["values"] != null) domain = d["values"] as List<Any?>
        }
        val covered = domain != null && domain.all { (r["map"] as Map<*, *>).containsKey(it) }
        return maxRev(if (covered) mapped else mapped + (if (r.containsKey("default")) r["default"] else "irreversible"))
    }

    private fun normalizeParam(p: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(p)
        out["required"] = if (p.containsKey("required")) p["required"] else true
        if (p.containsKey("tags")) out["tags"] = sortUniq(strs(p["tags"]))
        if (p.containsKey("values")) out["values"] = ArrayList(p["values"] as List<Any?>)
        out["sensitivity"] = effectiveParamSensitivity(p)
        if (p.containsKey("accumulates")) out["accumulates"] = sortUniq(strs(p["accumulates"]))
        else {
            val u = p["unit"]
            if (p["role"] == "money.amount" && u is Map<*, *> && u["kind"] == "money" && u["ccy"] is String) out["accumulates"] = listOf("money." + (u["ccy"] as String).lowercase())
        }
        return out
    }

    private fun jsonCopy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = jsonCopy(x) }
        is List<*> -> ArrayList<Any?>().also { l -> for (x in v) l.add(jsonCopy(x)) }
        else -> v
    }

    /** The authoring-independent form of a def (assumes [validateDef] passed): defaults filled, sets sorted, review / examples / source / since removed. */
    fun normalize(d: Map<String, Any?>): Map<String, Any?> {
        val rev = declaredReversibility(d)
        val resource = d["resource"] as Map<String, Any?>
        val blast = d["blast"] as Map<String, Any?>?
        val radius = if (blast != null) blast["radius"] as String else SCOPE_BLAST[resource["scope"]]!!
        val params = LinkedHashMap<String, Any?>()
        val dp = d["params"] as Map<String, Map<String, Any?>>
        for (k in dp.keys.sorted()) params[k] = normalizeParam(dp[k]!!)
        val nrev: Any? = if (rev is String) rev else {
            rev as Map<String, Any?>
            LinkedHashMap<String, Any?>().also { m ->
                m["by"] = rev["by"]
                m["map"] = LinkedHashMap(rev["map"] as Map<String, Any?>)
                if (rev.containsKey("default")) m["default"] = rev["default"]
            }
        }
        val idemIn = d["idempotency"] as Map<String, Any?>?
        val idem = linkedMapOf<String, Any?>("mode" to (idemIn?.get("mode") ?: "none"))
        if (idemIn != null && idemIn.containsKey("param")) idem["param"] = idemIn["param"]
        val sideEffects = ((d["side_effects"] as List<Any?>?) ?: emptyList()).map { it as Map<String, Any?> }
            .map { linkedMapOf<String, Any?>("target" to it["target"], "kind" to it["kind"]) }
            .sortedWith(compareBy<Map<String, Any?>>({ it["target"] as String }, { it["kind"] as String }))
        val out = linkedMapOf<String, Any?>(
            "v" to 1, "kind" to d["kind"], "verb" to d["verb"], "aliases" to sortUniq(strs(d["aliases"])), "title" to d["title"],
            "effects" to sortUniq(strs(d["effects"])),
            "resource" to linkedMapOf("type" to resource["type"], "id" to resource["id"], "scope" to resource["scope"]),
            "params" to params, "reversibility" to nrev,
            "blast" to linkedMapOf("radius" to radius, "ppm" to maxOf(BLAST_PPM[radius]!!.toLong(), if (blast != null && blast.containsKey("ppm")) iv(blast["ppm"]) else 0L).toInt()),
            "side_effects" to sideEffects, "idempotency" to idem, "context" to sortUniq(strs(d["context"])), "traits" to sortUniq(strs(d["traits"])),
            "bindings" to jsonCopy(d["bindings"] ?: LinkedHashMap<String, Any?>()),
        )
        if (d.containsKey("description")) out["description"] = d["description"]
        if (d.containsKey("audience")) out["audience"] = d["audience"]
        if (d.containsKey("compensates")) out["compensates"] = d["compensates"]
        return out
    }

    /** base64url(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it. */
    fun defDigest(d: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf("d" to DEF_DIGEST_DOMAIN, "def" to normalize(d)))

    // ---- pack Merkle root + inclusion proof -------------------------------------------------------------------------------------

    internal fun leaf(digest: String): Map<String, Any?> = linkedMapOf("d" to PACK_DIGEST_DOMAIN, "def" to digest)

    private fun sortedDigests(digests: List<String>): List<String> {
        val s = digests.toSortedSet().toList()
        if (s.size != digests.size) throw ActionKitError("duplicate_def", "a pack lists a def digest twice")
        if (s.isEmpty()) throw ActionKitError("empty_pack", "a pack has at least one def")
        return s
    }

    /** Merkle root over the sorted def digests (RFC 6962 shape, domain separated leaves). */
    fun packRoot(digests: List<String>): String = Pca.merkleRoot(sortedDigests(digests).map { leaf(it) })

    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }

    private fun node(l: ByteArray, r: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").also { it.update(0x01.toByte()); it.update(l); it.update(r) }.digest()

    private fun subRoot(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        val k = split(hs.size)
        return node(subRoot(hs.subList(0, k)), subRoot(hs.subList(k, hs.size)))
    }

    /** RFC 6962 inclusion proof of `digest` in the pack made of `digests`: {index, size, path: [{side, hash}]} leaf to root. */
    fun packProof(digests: List<String>, digest: String): Map<String, Any?> {
        val s = sortedDigests(digests)
        val i = s.indexOf(digest)
        if (i < 0) throw ActionKitError("not_in_pack", "the digest is not in the pack")
        var seg: List<ByteArray> = s.map { Pca.leafHash(leaf(it)) }
        var idx = i
        val path = ArrayList<Map<String, Any?>>()
        while (seg.size > 1) {
            val k = split(seg.size)
            if (idx < k) {
                path.add(linkedMapOf("side" to "R", "hash" to Pca.b64(subRoot(seg.subList(k, seg.size)))))
                seg = seg.subList(0, k)
            } else {
                path.add(linkedMapOf("side" to "L", "hash" to Pca.b64(subRoot(seg.subList(0, k)))))
                seg = seg.subList(k, seg.size)
                idx -= k
            }
        }
        path.reverse()
        return linkedMapOf("index" to i, "size" to s.size, "path" to path)
    }

    /** Does `proof` show `digest` is in the pack with root `root`? */
    fun verifyPackProof(root: String, proof: Map<String, Any?>?, digest: String): Boolean = Pca.verifyInclusion(root, proof, leaf(digest))

    // ---- T(d), decl(d), eff(d) --------------------------------------------------------------------------------------------------

    /** Traits implied by effects, roles, tags, scope and reversibility. `params`: maps with type / role / tags / max_items. */
    fun impliedFromFacts(effects: List<*>, params: List<Map<String, Any?>>, scope: String?, worstRev: String): List<String> {
        val out = ArrayList<String>()
        for (e in effects) out.addAll(EFFECT_TRAITS[e as String] ?: throw IllegalArgumentException("unknown effect $e"))
        val ro = isReadOnly(effects)
        for (p in params) {
            val r = p["role"]
            if (r is String) {
                ROLE_TRAITS[r]?.let { out.addAll(it) }
                if (ro && r.startsWith("money.")) out.add("pca.financial_data_read")
            }
            for (t in strs(p["tags"])) TAG_TRAITS[t]?.let { out.addAll(it) }
            if (p["type"] == "array" && p["max_items"] == null) out.add("pca.bulk")
        }
        if (scope != null && scope != "one") out.add("pca.bulk")
        if (worstRev == "irreversible") out.add("pca.irreversible")
        return sortUniq(out)
    }

    /** The author view of a def's traits: declared plus implied by its own facts. A hint; it never reaches enforcement without a valid confirmation. */
    fun hintTraits(d: Map<String, Any?>): List<String> {
        val n = normalize(d)
        val params = n["params"] as Map<String, Map<String, Any?>>
        val ids = ArrayList(strs(n["traits"]))
        ids.addAll(impliedFromFacts(n["effects"] as List<*>, params.values.toList(), (n["resource"] as Map<String, Any?>)["scope"] as String, worstReversibility(n["reversibility"], params)))
        return sortUniq(ids)
    }

    /** Every trait id of the registry, sorted: what an unconfirmed action is treated as having. */
    fun topTraits(reg: Map<String, Map<String, Any?>>): List<String> = reg.keys.sorted()

    // ---- confirmation: the only thing that sets an action's traits below the top ---------------------------------------------------

    const val REVIEW_DOMAIN = "atlas-pca/action-review/v2"
    const val VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1"

    /** Digest of what a schema verb says: the verb as presented minus `traits`, `floors`, `confirmation` and `def`. A confirmation signs it. */
    fun factsDigest(verb: Map<String, Any?>): String =
        Pca.hashCanonical(linkedMapOf("d" to VERB_FACTS_DOMAIN, "verb" to verb.filterKeys { it !in listOf("traits", "floors", "confirmation", "def") }))
    private val KEY_ROLES = listOf("reviewer", "importer", "model", "publisher")

    /** Null if the pin set `{keys: [{kid, pk, roles, not_before?, not_after?}], traits_digests?}` is sound. Any error means nothing is confirmed. */
    fun reviewerPinsError(p: Any?): String? {
        if (p !is Map<*, *> || p["keys"] !is List<*>) return "pins must be {keys: [...]}"
        val kids = HashSet<String>()
        val machinePks = HashSet<Any?>()
        val keys = p["keys"] as List<*>
        for (k in keys) {
            val kid = if (k is Map<*, *>) k["kid"] else null
            if (k !is Map<*, *> || kid !is String || kid.isEmpty() || kid.length > 128) return "a pinned key needs a kid"
            if (!kids.add(kid)) return "kid '$kid' is pinned twice"
            if (Pca.decodeB64uStrict(k["pk"], 32) == null) return "key '$kid': pk is not canonical base64url (32 bytes)"
            val roles = k["roles"]
            if (roles !is List<*> || roles.isEmpty() || !roles.all { it is String && it in KEY_ROLES } || !distinct(roles)) return "key '$kid': roles must be distinct known roles"
            if ("reviewer" in roles && ("importer" in roles || "model" in roles)) return "key '$kid': an importer or model key cannot hold the reviewer role"
            for (t in listOf("not_before", "not_after")) if (k.containsKey(t) && !isNonNeg(k[t])) return "key '$kid': $t must be a non-negative integer"
            if ("importer" in roles || "model" in roles) machinePks.add(k["pk"])
        }
        // the same key material under a second kid must not smuggle a machine key into the reviewer role
        for (k in keys) if ("reviewer" in ((k as Map<*, *>)["roles"] as List<*>) && k["pk"] in machinePks) return "key '${k["kid"]}': the same key material is pinned as an importer or model key"
        return null
    }

    // JavaScript's String.prototype.trim whitespace set (not Kotlin's, which differs at U+001C..U+001F)
    private fun jsBlank(s: String): Boolean = s.all { it in "\t\n\u000B\u000C\r \u00A0\u1680\u2028\u2029\u202F\u205F\u3000\uFEFF" || it in '\u2000'..'\u200A' }

    /**
     * Null iff the attestation `a` is a valid human confirmation of `defDigest`: an accepted registry digest, signed final traits accepted by
     * `finalOk`, sound dismissals, a key pinned with the `reviewer` role whose window covers `ts`, and a good Ed25519 signature over
     * `REVIEW_DOMAIN \0 strictCanonical(body)`. Throws on anything malformed (callers treat a throw as unconfirmed).
     */
    private fun attestationError(a: Any?, defDigest: Any?, reg: Map<String, Map<String, Any?>>, pins: Any?, factsErr: (Any?) -> String? = { null }, finalOk: (List<String>) -> Boolean): String? {
        if (pins == null) return "no reviewer keys are pinned"
        reviewerPinsError(pins)?.let { return "bad pins: $it" }
        pins as Map<*, *>
        if (a !is Map<*, *>) return "no confirmation"
        val sig = a["sig"]
        if (sig !is String) return "the confirmation is unsigned"
        if (defDigest !is String || a["def_digest"] != defDigest) return "the confirmation covers a different def digest"
        val extra = pins["traits_digests"]
        if (extra != null && extra !is List<*>) return "bad pins: traits_digests must be an array"
        if (a["traits_digest"] != traitsDigest(reg) && (extra == null || a["traits_digest"] !in (extra as List<Any?>))) return "the confirmation was made against a different trait registry"
        factsErr(a["facts_digest"])?.let { return it }
        val ft = a["final_traits"]
        val dm = a["dismissed"]
        val ts = a["ts"]
        val kid = a["reviewer_kid"]
        if (ft !is List<*> || dm !is List<*> || !isInt(ts) || kid !is String || !ft.all { it is String }) return "malformed confirmation"
        val fin = ft.map { it as String }
        if (!finalOk(fin)) return "the final traits do not match"
        val dismissed = ArrayList<Pair<String, String>>()
        for (d in dm) {
            if (d !is Map<*, *>) return "a dismissed trait is also final, or has no reason"
            val t = d["trait"]
            val r = d["reason"]
            if (t !is String || r !is String || t in fin || jsBlank(r)) return "a dismissed trait is also final, or has no reason"
            dismissed.add(t to r)
        }
        val key = (pins["keys"] as List<*>).firstOrNull { it is Map<*, *> && it["kid"] == kid } as Map<*, *>? ?: return "no pinned key '$kid'"
        if ("reviewer" !in (key["roles"] as List<*>)) return "key '$kid' does not hold the reviewer role"
        if ((key.containsKey("not_before") && iv(ts) < iv(key["not_before"])) || (key.containsKey("not_after") && iv(ts) > iv(key["not_after"]))) return "the confirmation time is outside the key validity"
        val body = linkedMapOf<String, Any?>(
            "def_digest" to defDigest, "traits_digest" to a["traits_digest"], "facts_digest" to a["facts_digest"], "final_traits" to sortUniq(fin),
            "dismissed" to dismissed.sortedBy { it.first }.map { linkedMapOf("trait" to it.first, "reason" to it.second) },
            "reviewer_kid" to kid, "ts" to ts,
        )
        return if (IntentJs.verifyEd(key["pk"], IntentJs.message(REVIEW_DOMAIN + "\u0000", body), sig)) null else "the confirmation signature is invalid"
    }

    /** Null iff the verb's `confirmation` is valid for the reviewer `pins` (and covers only traits the verb carries). Never throws. */
    fun verbConfirmationError(v: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any?): String? = try {
        val carried = (v["traits"] as? List<*>) ?: emptyList<Any?>()
        attestationError(v["confirmation"], v["def"], reg, pins, { f -> if (f is String && f == factsDigest(v)) null else "the verb facts differ from the facts the reviewer confirmed" }) { fin -> fin.all { it in carried } }
    } catch (e: Exception) {
        "malformed confirmation: ${e.message}"
    }

    /** True iff the def is `confirmed` with an attestation valid under `pins` (see [attestationError]); every failure is false. Never throws. */
    fun isConfirmed(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any?): Boolean = try {
        val r = d["review"] as? Map<*, *>
        r != null && r["state"] == "confirmed" &&
            attestationError(r["attestation"], defDigest(d), reg, pins) { fin -> sortUniq(fin) == sortUniq(strs(d["traits"])) } == null
    } catch (e: Exception) {
        false
    }

    /** T(d): the hint traits when the def is validly confirmed, else the top of the registry ("unconfirmed means maximally dangerous"). */
    fun traitsOf(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any? = null): List<String> =
        if (isConfirmed(d, reg, pins)) hintTraits(d) else topTraits(reg)

    fun declProfile(d: Map<String, Any?>): Map<String, Any?> {
        val n = normalize(d)
        val params = n["params"] as Map<String, Map<String, Any?>>
        val critical = params.values.any { SENSITIVITY_RANK[effectiveParamSensitivity(it)]!! >= SENSITIVITY_RANK["critical"]!! }
        return profile(
            risk = if (critical) 2 else if (isReadOnly(n["effects"] as List<*>)) 0 else 1,
            rev = worstReversibility(n["reversibility"], params),
            blastPpm = iv((n["blast"] as Map<String, Any?>)["ppm"]).toInt(),
            context = strs(n["context"]),
        )
    }

    /** {confirmed, traits, closure, floor, decl, eff}: eff = decl join F(T(d)); an unconfirmed def has every trait of the registry. */
    fun effective(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any? = null): Map<String, Any?> {
        closure(reg, hintTraits(d)) // an unknown declared trait is refused whether or not the def is confirmed
        val confirmed = isConfirmed(d, reg, pins)
        val tr = if (confirmed) hintTraits(d) else topTraits(reg)
        val fl = floorOf(reg, tr)
        val dp = declProfile(d)
        return linkedMapOf("confirmed" to confirmed, "traits" to tr, "closure" to closure(reg, tr), "floor" to fl, "decl" to dp, "eff" to join(dp, fl))
    }

    // ---- rule 22: whole-document integrity of the carried traits and floors ----------------------------------------------------

    private const val PFX = "action.params."

    /**
     * Recomputes from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at least the floor of
     * the traits' closure and of the declared reversibility, and that an unconfirmed verb carries every trait of the registry. Null = consistent; else `<code>: <reason>`. Never throws.
     */
    fun schemaVerbFloorError(v: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any? = null): String? {
        try {
            if (v["effects"] !is List<*> || v["traits"] !is List<*> || !v.containsKey("floors")) return "schema_floor_forged: not a v2 verb"
            val ps = (v["params"] as Map<String, Map<String, Any?>>).map { (path, p) -> path.substring(PFX.length) to p }
            val byName = LinkedHashMap<String, Map<String, Any?>>()
            for ((name, p) in ps) {
                val e = linkedMapOf<String, Any?>("type" to p["type"])
                if (p.containsKey("values")) e["values"] = p["values"]
                byName[name] = e
            }
            val rb = v["reversibility_by"] as Map<String, Any?>?
            val decl: Any? = if (rb != null) {
                linkedMapOf<String, Any?>("by" to (rb["param"] as String).substring(PFX.length), "map" to rb["map"]).also { if (rb.containsKey("default")) it["default"] = rb["default"] }
            } else if (v.containsKey("reversibility")) v["reversibility"] else if (v["kind"] == "read") "reversible" else "irreversible"
            val worst = worstReversibility(decl, byName)
            val traits = v["traits"] as List<*>
            for (t in impliedFromFacts(v["effects"] as List<*>, ps.map { it.second }, null, worst)) if (t !in traits) return "schema_traits_forged: missing implied trait $t"
            // unconfirmed means maximally dangerous: no valid confirmation by a pinned reviewer => the verb must carry EVERY trait of the registry
            if (verbConfirmationError(v, reg, pins) != null) for (t in topTraits(reg)) if (t !in traits) return "schema_traits_forged: unconfirmed action must carry every trait (missing $t)"
            val fl = floorOf(reg, traits)
            val floors = v["floors"] as Map<String, Any?>
            if (!leq(fl, floors)) return "schema_floor_forged: floors are below the floor of the carried traits"
            if ((REV_RANK[floors["rev"]] ?: -1) < (REV_RANK[worst] ?: -1)) return "schema_floor_forged: floors.rev is below the declared reversibility"
            return null
        } catch (e: ActionKitError) {
            return "${e.code}: ${e.message}"
        } catch (e: RuntimeException) {
            return "schema_floor_forged: ${e.message}"
        }
    }

    /** Core + the document's own `trait_defs` (checked); when it carries `traits_digest` the registry must hash to it. Throws [ActionKitError]. */
    fun registryOfSchema(doc: Map<String, Any?>): Map<String, Map<String, Any?>> {
        val td = doc["trait_defs"]
        val reg = if (td is List<*> && td.isNotEmpty()) extendRegistry(CORE_REGISTRY, td) else CORE_REGISTRY
        if (doc.containsKey("traits_digest") && doc["traits_digest"] != traitsDigest(reg)) throw ActionKitError("traits_digest_mismatch", "the document's traits_digest does not match its trait registry")
        return reg
    }

    /** Rule 22's integrity half for a whole v2 document. Null = consistent. Never throws. */
    fun schemaFloorError(doc: Map<String, Any?>, pins: Any? = null): String? {
        try {
            val reg = registryOfSchema(doc)
            for (v in doc["verbs"] as List<*>) {
                val m = v as Map<String, Any?>
                schemaVerbFloorError(m, reg, pins)?.let { return "${m["verb"]}: $it" }
            }
            return null
        } catch (e: ActionKitError) {
            return "${e.code}: ${e.message}"
        } catch (e: RuntimeException) {
            return "bad_registry: ${e.message}"
        }
    }
}
