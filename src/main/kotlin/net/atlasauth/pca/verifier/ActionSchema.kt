package net.atlasauth.pca.verifier

/**
 * Rule 14: signed action schemas and the closed-world conformance check (packages/pca/src/action-schema.ts). A schema
 * `pca-action-schema` v1 is signed by a site key listed in the verifier's discovery key list; the suite is pinned by the
 * KEY ENTRY. Anything the schema does not declare is the fail-closed cell: an undeclared verb or parameter, a missing
 * required one, a wrong type or a value outside its domain is a terminal deny (never a question).
 */
object ActionSchema {
    const val ACTION_SCHEMA_DOMAIN = "atlas-pca/action-schema/v1\u0000"
    const val ACTION_SCHEMA_REF_DOMAIN = "atlas-pca/action-schema-ref/v1"
    const val ACTION_SCHEMA_KIND = "pca-action-schema"
    const val MAX_SCHEMA_VERBS = 256
    const val MAX_SCHEMA_PARAMS = 64
    const val MAX_SCHEMA_VALUES = 256
    const val DEFAULT_MAX_LEN = 1024
    const val DEFAULT_MAX_ITEMS = 64
    internal val PARAM_PATH_RE = Regex("action\\.params\\.[A-Za-z0-9_]{1,64}")
    internal val UNIT_ID_RE = Regex("[a-z0-9_]+(?:\\.[a-z0-9_]+)*")
    private val DATE_RE = Regex("([0-9]{4})-([0-9]{2})-([0-9]{2})")
    internal val RESERVED_NAMES = setOf("__proto__", "constructor", "prototype")
    internal val SENSITIVITIES = listOf("free", "material", "critical")
    internal val SCHEMA_REVERSIBILITY = listOf("reversible", "rate_limited", "irreversible")
    internal val PARAM_TYPES = listOf("string", "integer", "boolean", "date", "set", "array")
    private val DOC_KEYS = listOf("v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig")
    private val VERB_KEYS = listOf("verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description")
    private val PARAM_KEYS = listOf(
        "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items",
        "min_items", "max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description",
    )
    private val SIG_KEYS = listOf("alg", "kid", "value", "pq_value")

    /** A conformance verdict: `ok`, else the violation `code` (and `path` for a parameter). */
    class Conform internal constructor(val ok: Boolean, val code: String?, val path: String?, val reason: String?) {
        internal companion object {
            val OK = Conform(true, null, null, null)
        }
    }

    internal fun isStr(v: Any?, max: Int = 256): Boolean =
        v is String && v.isNotEmpty() && !Json.hasLoneSurrogate(v) && IntentJs.u8len(v) <= max

    private fun isIn(xs: List<String>, v: Any?): Boolean = v is String && v in xs
    private fun distinct(xs: List<*>): Boolean = HashSet<Any?>(xs).size == xs.size

    private fun paramDeclError(path: String, dO: Any?, units: Any?): String? {
        if (!PARAM_PATH_RE.matches(path)) return "parameter path '$path' is not action.params.<name>"
        if (path.substring("action.params.".length) in RESERVED_NAMES) return "parameter name '$path' is reserved (__proto__ / constructor / prototype)"
        if (dO !is Map<*, *>) return "$path: declaration must be an object"
        val d = IntentJs.obj(dO)
        for (k in d.keys) if (k !in PARAM_KEYS) return "$path: unknown member '$k'"
        val type = d["type"]
        if (!isIn(PARAM_TYPES, type)) return "$path: unknown type"
        if (!isStr(d["semantic"], 128)) return "$path: semantic must be a non-empty string"
        if (!isIn(SENSITIVITIES, d["sensitivity"])) return "$path: unknown sensitivity"
        if (d.containsKey("required") && d["required"] !is Boolean) return "$path: required must be a boolean"
        if (d.containsKey("values")) {
            val vs = d["values"]
            val ok = vs is List<*> && vs.isNotEmpty() && vs.size <= MAX_SCHEMA_VALUES && vs.all { isStr(it) }
            if (!ok) return "$path: values must be 1..$MAX_SCHEMA_VALUES strings"
            if (!distinct(vs as List<*>)) return "$path: values must be distinct"
            if ("string" != type && "set" != type) return "$path: values apply to string and set only"
        }
        if ("set" == type && !d.containsKey("values")) return "$path: a set needs values"
        val intItems = "array" == type && "integer" == d["items"]
        for (k in listOf("min", "max")) {
            if (d.containsKey(k) && (!IntentJs.isInt(d[k]) || ("integer" != type && !intItems))) return "$path: $k must be a safe integer on an integer parameter"
        }
        if (IntentJs.isInt(d["min"]) && IntentJs.isInt(d["max"]) && IntentJs.num(d["min"])!! > IntentJs.num(d["max"])!!) return "$path: min > max"
        if (d.containsKey("unit") && ("integer" != type || d["unit"] !is String || units !is Map<*, *> || !units.containsKey(d["unit"])))
            return "$path: unit must name a declared unit of an integer parameter"
        if (d.containsKey("max_len") && (!IntentJs.isInt(d["max_len"]) || IntentJs.num(d["max_len"])!! < 1)) return "$path: max_len must be a positive safe integer"
        if (d.containsKey("items") && ("array" != type || !isStr(d["items"], 64))) return "$path: items applies to array only"
        for (k in listOf("min_items", "max_items")) {
            if (d.containsKey(k) && (!IntentJs.isNonNeg(d[k]) || ("set" != type && "array" != type))) return "$path: $k must be a non-negative safe integer on a set or array"
        }
        if (IntentJs.isInt(d["min_items"]) && IntentJs.isInt(d["max_items"]) && IntentJs.num(d["min_items"])!! > IntentJs.num(d["max_items"])!!) return "$path: min_items > max_items"
        if (d.containsKey("default") && d["default"] == null) return "$path: default must not be null (absent = no default)"
        if (d.containsKey("principal_neutral_default") && d["principal_neutral_default"] !is Boolean) return "$path: principal_neutral_default must be a boolean"
        if (d["principal_neutral_default"] == true && !d.containsKey("default")) return "$path: principal_neutral_default needs a default"
        if (d.containsKey("accumulates_into")) {
            if ("integer" != type) return "$path: accumulates_into applies to integer parameters only"
            val ai = d["accumulates_into"]
            if (ai !is List<*> || ai.isEmpty() || ai.size > 8) return "$path: accumulates_into must be 1..8 unit ids"
            for (u in ai) if (u !is String || u.length > 64 || !UNIT_ID_RE.matches(u)) return "$path: accumulates_into entries must be unit ids"
            if (!distinct(ai)) return "$path: accumulates_into must be distinct"
        }
        if (d.containsKey("issued_by_site") && d["issued_by_site"] !is Boolean) return "$path: issued_by_site must be a boolean"
        if (d.containsKey("description") && !isStr(d["description"], 1024)) return "$path: description must be a string"
        return null
    }

    private fun exactKeys(o: Any?, vararg keys: String): Boolean {
        if (o !is Map<*, *>) return false
        if (o.size != keys.size) return false
        return keys.all { o.containsKey(it) }
    }

    private fun verbDeclError(vO: Any?, units: Any?): String? {
        if (vO !is Map<*, *>) return "verb entry must be an object"
        val v = IntentJs.obj(vO)
        for (k in v.keys) if (k !in VERB_KEYS) return "verb entry: unknown member '$k'"
        if (!isStr(v["verb"], 128)) return "verb entry: verb must be a non-empty string"
        val at = "verb '${v["verb"]}'"
        if ("read" != v["kind"] && "write" != v["kind"]) return "$at: kind must be read or write"
        if (v["params"] !is Map<*, *>) return "$at: params must be an object"
        val params = IntentJs.obj(v["params"])
        if (params.size > MAX_SCHEMA_PARAMS) return "$at: more than $MAX_SCHEMA_PARAMS parameters"
        for ((k, d) in params) {
            val err = paramDeclError(k, d, units)
            if (err != null) return "$at: $err"
        }
        if (v.containsKey("reversibility") && !isIn(SCHEMA_REVERSIBILITY, v["reversibility"])) return "$at: unknown reversibility"
        if (v.containsKey("reversibility_by")) {
            val rO = v["reversibility_by"]
            val ok = rO is Map<*, *> && rO.keys.all { it in listOf("param", "map", "default") }
            if (!ok) return "$at: reversibility_by must be {param, map, default?}"
            val r = IntentJs.obj(rO)
            if (r["param"] !is String || !params.containsKey(r["param"])) return "$at: reversibility_by.param must be a declared parameter"
            val map = r["map"]
            val mapOk = map is Map<*, *> && map.isNotEmpty() && map.values.all { isIn(SCHEMA_REVERSIBILITY, it) }
            if (!mapOk) return "$at: reversibility_by.map must map values to reversibility classes"
            if (r.containsKey("default") && !isIn(SCHEMA_REVERSIBILITY, r["default"])) return "$at: reversibility_by.default is not a reversibility class"
        }
        if (v.containsKey("mcp") && (!exactKeys(v["mcp"], "tool") || !isStr(IntentJs.get(v["mcp"], "tool"), 128))) return "$at: mcp must be {tool}"
        if (v.containsKey("openapi") && (!exactKeys(v["openapi"], "operationId") || !isStr(IntentJs.get(v["openapi"], "operationId"), 128))) return "$at: openapi must be {operationId}"
        for (k in listOf("harm", "effects", "returns")) if (v.containsKey(k) && v[k] !is Map<*, *>) return "$at: $k must be an object"
        if (v.containsKey("world") && v["world"] !is List<*>) return "$at: world must be an array"
        if (v.containsKey("description") && !isStr(v["description"], 1024)) return "$at: description must be a string"
        return null
    }

    /** Structural validation of a signed schema. Null = well-formed. Never throws. */
    fun shapeError(docO: Any?): String? {
        try {
            if (docO !is Map<*, *>) return "schema is not an object"
            val doc = IntentJs.obj(docO)
            for (k in doc.keys) if (k !in DOC_KEYS) return "unknown member '$k'"
            if (!OracleFacts.isOne(doc["v"])) return "unsupported schema version"
            if (ACTION_SCHEMA_KIND != doc["kind"]) return "kind must be '$ACTION_SCHEMA_KIND'"
            if (!isStr(doc["site"], 2048) || !isStr(doc["aud"], 256) || !isStr(doc["version"], 128)) return "site, aud and version must be non-empty strings"
            if (doc.containsKey("units")) {
                if (doc["units"] !is Map<*, *>) return "units must be an object"
                for ((id, u) in IntentJs.obj(doc["units"])) {
                    if (!UNIT_ID_RE.matches(id) || id.length > 64) return "unit id '$id' is malformed"
                    if (u !is Map<*, *> || !isStr(IntentJs.get(u, "kind"), 64)) return "unit '$id' must be an object with a kind"
                    for (k in u.keys) if (k !in listOf("kind", "currency", "exponent")) return "unit '$id': unknown member"
                    if (IntentJs.own(u, "currency") && !isStr(IntentJs.get(u, "currency"), 16)) return "unit '$id': currency must be a string"
                    if (IntentJs.own(u, "exponent") && !(IntentJs.isNonNeg(IntentJs.get(u, "exponent")) && IntentJs.num(IntentJs.get(u, "exponent"))!! <= 18))
                        return "unit '$id': exponent must be an integer in [0, 18]"
                }
            }
            if (doc.containsKey("state") && doc["state"] !is List<*>) return "state must be an array"
            val verbs = doc["verbs"]
            if (verbs !is List<*> || verbs.isEmpty() || verbs.size > MAX_SCHEMA_VERBS) return "verbs must be 1..$MAX_SCHEMA_VERBS entries"
            val seen = HashSet<String>()
            for (v in verbs) {
                val e = verbDeclError(v, doc["units"])
                if (e != null) return e
                val name = IntentJs.get(v, "verb") as String
                if (!seen.add(name)) return "verb '$name' is declared twice"
            }
            val s = doc["sig"]
            if (s !is Map<*, *>) return "sig must be an object"
            val sig = IntentJs.obj(s)
            for (k in sig.keys) if (k !in SIG_KEYS) return "sig: unknown member '$k'"
            val se = IntentJs.suiteError(sig["alg"], sig.containsKey("alg"))
            if (se != null) return "sig.alg: $se"
            if (!isStr(sig["kid"], 128)) return "sig.kid must be a non-empty string"
            if (!IntentJs.b64any(sig["value"])) return "sig.value is not canonical base64url"
            if (sig.containsKey("pq_value") && !IntentJs.b64any(sig["pq_value"])) return "sig.pq_value is not canonical base64url"
            IntentJs.canonBytes(body(doc))
            return null
        } catch (e: RuntimeException) {
            return "malformed schema: " + e.message
        }
    }

    private fun body(doc: Map<String, Any?>): Map<String, Any?> = LinkedHashMap(doc).also { it.remove("sig") }

    /**
     * Verify a site-signed schema against the discovery key list: shape, `sig.kid` names a listed key, `sig.alg` equals that
     * key's suite, and the signature verifies (a PQ key only as pinned by the key entry). Null = valid.
     */
    fun verify(docO: Any?, keys: Any?): String? {
        try {
            val bad = shapeError(docO)
            if (bad != null) return bad
            val doc = IntentJs.obj(docO)
            val sig = IntentJs.obj(doc["sig"])
            if (keys !is List<*>) return "the schema keys must be an array"
            val key = keys.firstOrNull { it is Map<*, *> && IntentJs.get(it, "kid") is String && IntentJs.get(it, "kid") == sig["kid"] }?.let { IntentJs.obj(it) }
                ?: return "no schema key with kid '${sig["kid"]}'"
            if (key.containsKey("pq_pk") && key["pq_pk"] !is String) return "the schema key pq_pk must be a string"
            if (Pca.decodeB64uStrict(key["pk"], 32) == null) return "schema key pk is not canonical base64url (32 bytes)"
            val kse = IntentJs.suiteError(key["alg"], key.containsKey("alg"))
            if (kse != null) return "schema key: $kse"
            val ka = IntentJs.suiteOf(key)
            if (ka == null || ka != IntentJs.suiteOf(sig)) return "sig.alg does not match the pinned key suite"
            val pk = key["pk"] as String
            val pin = if (key.containsKey("pq_pk")) IntentJs.pin(pk, key["pq_pk"]) else null
            val msg = IntentJs.message(ACTION_SCHEMA_DOMAIN, body(doc))
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key["pq_pk"], msg, sig["value"], sig["pq_value"], pin)) return "schema signature invalid"
            return null
        } catch (e: RuntimeException) {
            return "schema verification error: " + e.message
        }
    }

    /** The schema's content address (over the whole signed document). */
    fun digest(doc: Any?): String = IntentJs.ref(ACTION_SCHEMA_REF_DOMAIN, "s", doc)

    /** The verb entry named `verb`, or null. */
    internal fun schemaVerb(doc: Any?, verb: String): Map<String, Any?>? {
        val verbs = IntentJs.get(doc, "verbs") as? List<*> ?: return null
        return verbs.firstOrNull { it is Map<*, *> && verb == it["verb"] }?.let { IntentJs.obj(it) }
    }

    private fun isCalendarDate(s: String): Boolean {
        val m = DATE_RE.matchEntire(s) ?: return false
        val y = m.groupValues[1].toInt()
        val mo = m.groupValues[2].toInt()
        val d = m.groupValues[3].toInt()
        if (y < 1 || mo < 1 || mo > 12 || d < 1) return false
        val leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        val dim = intArrayOf(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        return d <= dim[mo - 1]
    }

    private fun strOk(x: Any?, maxLen: Double): Boolean = x is String && !Json.hasLoneSurrogate(x) && IntentJs.u8len(x) <= maxLen

    /** `d[k] ?? dflt` as a number. */
    private fun numOr(d: Map<String, Any?>, k: String, dflt: Double): Double = d[k]?.let { IntentJs.num(it) } ?: dflt

    /** The value check of one declared parameter: null = in the domain, else (code, reason). */
    internal fun paramValueViolation(d: Map<String, Any?>, x: Any?): Pair<String, String>? {
        val maxLen = numOr(d, "max_len", DEFAULT_MAX_LEN.toDouble())
        when (d["type"] as? String ?: "") {
            "string" -> {
                if (x !is String || Json.hasLoneSurrogate(x)) return "bad_type" to "expected a string"
                if (IntentJs.u8len(x) > maxLen) return "out_of_domain" to "longer than the declared max_len"
                if (d.containsKey("values") && !(d["values"] as List<*>).contains(x)) return "out_of_domain" to "not one of the declared values"
                return null
            }
            "integer" -> {
                if (!IntentJs.isInt(x)) return "bad_type" to "expected a safe integer"
                val v = IntentJs.num(x)!!
                if (d.containsKey("min") && v < IntentJs.num(d["min"])!!) return "out_of_domain" to "below min"
                if (d.containsKey("max") && v > IntentJs.num(d["max"])!!) return "out_of_domain" to "above max"
                return null
            }
            "boolean" -> return if (x is Boolean) null else "bad_type" to "expected a boolean"
            "date" -> {
                if (x !is String) return "bad_type" to "expected a YYYY-MM-DD string"
                return if (isCalendarDate(x)) null else "out_of_domain" to "not a calendar date YYYY-MM-DD"
            }
            "set" -> {
                if (x !is List<*>) return "bad_type" to "expected an array of strings"
                for (e in x) if (e !is String) return "bad_type" to "expected an array of strings"
                if (!distinct(x)) return "out_of_domain" to "set members must be distinct"
                val values = d["values"] as List<*>
                for (e in x) if (!values.contains(e)) return "out_of_domain" to "set member not among the declared values"
                if (x.size < numOr(d, "min_items", 0.0) || x.size > numOr(d, "max_items", values.size.toDouble())) return "out_of_domain" to "set size outside the declared bounds"
                return null
            }
            "array" -> {
                if (x !is List<*>) return "bad_type" to "expected an array"
                val ints = "integer" == d["items"]
                for (e in x) {
                    if (if (ints) !IntentJs.isInt(e) else !strOk(e, maxLen))
                        return "bad_type" to (if (ints) "array items must be safe integers" else "array items must be strings within max_len UTF-8 bytes")
                    if (ints && ((d.containsKey("min") && IntentJs.num(e)!! < IntentJs.num(d["min"])!!) || (d.containsKey("max") && IntentJs.num(e)!! > IntentJs.num(d["max"])!!)))
                        return "out_of_domain" to "array item outside min/max"
                }
                if (x.size < numOr(d, "min_items", 0.0) || x.size > numOr(d, "max_items", DEFAULT_MAX_ITEMS.toDouble())) return "out_of_domain" to "array length outside the declared bounds"
                return null
            }
            else -> return "bad_type" to "unknown declared type"
        }
    }

    /**
     * Map an action to the declared domain or to the fail-closed cell (rule 14 step 5). First failure wins:
     * params_not_object; unknown_verb; undeclared_param (params keys in UTF-8 byte order); then for every declared path in
     * UTF-8 byte order: missing_param (absent and required, default true), else bad_type / out_of_domain.
     */
    fun conform(doc: Any?, verb: String, params: Any?): Conform {
        if (params !is Map<*, *>) return Conform(false, "params_not_object", null, "params must be a JSON object")
        val v = schemaVerb(doc, verb) ?: return Conform(false, "unknown_verb", null, "verb '$verb' is not declared by the schema")
        val declared = IntentJs.obj(v["params"])
        val p = IntentJs.obj(params)
        for (k in IntentJs.sortedUtf8(p.keys)) {
            val path = "action.params.$k"
            if (!declared.containsKey(path)) return Conform(false, "undeclared_param", path, "parameter '$path' is not declared for '$verb'")
        }
        for (path in IntentJs.sortedUtf8(declared.keys)) {
            val d = IntentJs.obj(declared[path])
            val name = path.substring("action.params.".length)
            if (!p.containsKey(name)) {
                if (d["required"] != false) return Conform(false, "missing_param", path, "required parameter '$path' is missing")
                continue
            }
            val bad = paramValueViolation(d, p[name])
            if (bad != null) return Conform(false, bad.first, path, "'$path': ${bad.second}")
        }
        return Conform.OK
    }

    /** The integer parameters of a verb entry that feed `unit` (`accumulates_into`), in UTF-8 byte order. */
    internal fun accumulationParams(v: Map<String, Any?>, unit: String): List<String> {
        val params = IntentJs.obj(v["params"])
        val out = ArrayList<String>()
        for ((p, d) in params) {
            val ai = IntentJs.get(d, "accumulates_into")
            if ("integer" == IntentJs.get(d, "type") && ai is List<*> && ai.contains(unit)) out.add(p)
        }
        return IntentJs.sortedUtf8(out)
    }

    /**
     * `env.canon`: for every PRESENT parameter of type boolean (`"true"` / `"false"`), set (strict canonical JSON of its
     * members sorted by UTF-8 bytes) and array (strict canonical JSON as sent).
     */
    fun canonProjection(doc: Any?, verb: String, params: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        val v = schemaVerb(doc, verb) ?: return out
        val declared = IntentJs.obj(v["params"])
        for (path in IntentJs.sortedUtf8(declared.keys)) {
            val type = IntentJs.get(declared[path], "type")
            val name = path.substring("action.params.".length)
            if (!params.containsKey(name)) continue
            val x = params[name]
            if ("boolean" == type) out[name] = if (x == true) "true" else "false"
            else if ("set" == type) out[name] = IntentJs.canon(IntentJs.sortedUtf8((x as List<*>).map { it as String }))
            else if ("array" == type) out[name] = IntentJs.canon(x)
        }
        return out
    }
}
