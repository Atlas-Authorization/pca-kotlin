package net.atlasauth.pca.actions

import java.util.Locale
import java.util.regex.Pattern
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json

/**
 * Authoring forms of an action definition: param and resource shorthands, the expansion of an authoring entry into a def, the loader of an authoring
 * document, and typed param constructors. The shorthands and the expansion are the reference's, so one action has one digest however it was written.
 * Input is an already parsed document (Map / List / String / Boolean / Json.Num / null); YAML text is not parsed here (a YAML front end hands its parsed
 * value to [loadActionsValue]); [loadActionsText] parses YAML or JSON text (see [ActionsText]) and reports source positions.
 */
@Suppress("UNCHECKED_CAST")
object ActionAuthor {
    /** Largest authoring file the loader reads. */
    const val MAX_AUTHOR_BYTES = 1 shl 20
    const val IDEMPOTENCY_PARAM = "idempotency_key"

    /** Effects whose repeat is not harmless: an absent idempotency declaration gets a key parameter. */
    val AUTO_IDEMPOTENT_EFFECTS: List<String> = listOf("send", "pay", "create", "provision", "publish")

    private val RESOURCE_SCOPES = listOf("one", "set", "tenant", "global")
    private val ID_CLASSES = listOf("digits", "hex", "alnum", "slug", "uuid", "any_safe")
    private val BLAST_RADII = listOf("one", "bounded", "tenant", "global")
    private val PROVENANCE_LEVELS = listOf("first_party", "tool", "agent")
    private val ENTRY_KEYS = setOf(
        "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
        "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since",
    )
    private val FILE_KEYS = setOf("ns", "since", "actions")

    /** Stands for a JavaScript undefined member value: never a JSON value, so the strict-JSON check refuses it exactly as the reference does. */
    private val UNDEFINED = Any()

    private val SHORTHAND_RE = Pattern.compile("([a-z_]+(?::[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3})?)(?:\\(([^\\n\\r\\u2028\\u2029]*)\\))?(\\?)?")
    private val INT_ARG_RE = Pattern.compile("-?[0-9]{1,15}")
    private val INT_RANGE_RE = Pattern.compile("(-?[0-9]{1,15})\\.\\.(-?[0-9]{1,15})")
    private val SCOPE_AT_RE = Pattern.compile("@([a-z]+)\\z")
    private val ID_CLASS_RE = Pattern.compile("\\{([a-z_]+),([0-9]{1,3})\\.\\.([0-9]{1,3})\\}")
    private val NS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}")

    private fun err(code: String, msg: String) = ActionKitError(code, msg)

    private fun num(s: String): Json.Num {
        // Number("-0") is -0 (refused later by the strict-JSON profile): keep the sign of a negative zero
        val v = s.toLong()
        return if (v == 0L && s.startsWith("-")) Json.Num("-0") else Json.Num(v.toString())
    }

    // ---- param shorthands --------------------------------------------------------------------------------------------------------

    private class Args {
        val pos = ArrayList<String>()
        val named = LinkedHashMap<String, String>()
    }

    private fun splitArgs(s: String): Args {
        val a = Args()
        for (raw in s.split(",")) {
            val x = J.jsTrim(raw)
            if (x.isEmpty()) continue
            val eq = x.indexOf('=')
            if (eq > 0) a.named[J.jsTrim(x.substring(0, eq))] = J.jsTrim(x.substring(eq + 1)) else a.pos.add(x)
        }
        return a
    }

    private fun intArg(s: String?, what: String): Json.Num? {
        if (s == null) return null
        if (!INT_ARG_RE.matcher(s).matches()) throw err("bad_shorthand", "$what must be an integer, got '$s'")
        return num(s)
    }

    private fun only(a: Args, pos: Int, names: List<String>, shorthand: String) {
        if (a.pos.size > pos) throw err("bad_shorthand", "'$shorthand' takes at most $pos positional argument(s)")
        for (k in a.named.keys) if (!names.contains(k)) throw err("bad_shorthand", "'$shorthand' has no option '$k'")
    }

    private fun listArg(s: String, shorthand: String): MutableList<Any?> {
        val xs = ArrayList<Any?>()
        for (x in s.split("|")) xs.add(J.jsTrim(x))
        for (x in xs) if ("" == x) throw err("bad_shorthand", "'$shorthand' needs values separated by |")
        return xs
    }

    private fun bare(name: String, inner: String?) {
        if (inner != null) throw err("bad_shorthand", "'$name' takes no arguments")
    }

    /**
     * Expand one param shorthand. Forms: email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N) int(MIN..MAX) count(MAX)
     * money(CCY|@param, max=N, min=N, exp=N, provenance=first_party|tool|agent) id:<type> enum(a|b) set(a|b) array(items, max=N). A trailing `?` makes the
     * param optional.
     */
    fun parseParamShorthand(src: String): MutableMap<String, Any?> {
        val m = SHORTHAND_RE.matcher(J.jsTrim(src))
        if (!m.matches()) throw err("bad_shorthand", "unknown param shorthand '$src'")
        val name = m.group(1)
        val inner: String? = m.group(2)
        val optional = "?" == m.group(3)
        val a = splitArgs(inner ?: "")
        val p: MutableMap<String, Any?>
        when (name) {
            "email" -> { bare(name, inner); p = J.obj("type", "string", "role", "contact.email", "format", "email", "tags", J.list("pii"), "max_len", J.n(254)) }
            "phone" -> { bare(name, inner); p = J.obj("type", "string", "role", "contact.phone", "format", "phone_e164", "tags", J.list("pii"), "max_len", J.n(16)) }
            "url" -> { bare(name, inner); p = J.obj("type", "string", "role", "url.target", "format", "url", "max_len", J.n(2048)) }
            "uuid" -> { bare(name, inner); p = J.obj("type", "string", "format", "uuid", "max_len", J.n(36)) }
            "ccy" -> { bare(name, inner); p = J.obj("type", "string", "role", "money.currency", "format", "iso_currency", "max_len", J.n(3)) }
            "country" -> { bare(name, inner); p = J.obj("type", "string", "format", "iso_country", "max_len", J.n(2)) }
            "secret" -> { bare(name, inner); p = J.obj("type", "string", "role", "credential.secret", "tags", J.list("secret"), "max_len", J.n(512)) }
            "bool" -> { bare(name, inner); p = J.obj("type", "boolean") }
            "date" -> { bare(name, inner); p = J.obj("type", "date") }
            "datetime" -> { bare(name, inner); p = J.obj("type", "datetime") }
            "duration" -> {
                only(a, 1, emptyList(), "duration")
                val max = intArg(if (a.pos.isEmpty()) null else a.pos[0], "duration max (ms)")
                p = J.obj("type", "duration")
                if (max != null) { p["min"] = J.n(0); p["max"] = max }
            }
            "text", "string" -> {
                only(a, 1, emptyList(), name)
                val n = intArg(if (a.pos.isEmpty()) null else a.pos[0], "$name length")
                p = J.obj("type", "string")
                if (n != null) p["max_len"] = n
            }
            "message" -> {
                only(a, 1, emptyList(), "message")
                val n = intArg(if (a.pos.isEmpty()) null else a.pos[0], "message length")
                p = J.obj("type", "string", "role", "text.message", "tags", J.list("free_text_outbound"), "max_len", n ?: J.n(1024))
            }
            "int" -> {
                only(a, 1, emptyList(), "int")
                val r = if (a.pos.isEmpty()) null else INT_RANGE_RE.matcher(a.pos[0])
                if (a.pos.isNotEmpty() && !r!!.matches()) throw err("bad_shorthand", "int takes MIN..MAX, for example int(0..100)")
                p = J.obj("type", "integer")
                if (r != null) { p["min"] = num(r.group(1)); p["max"] = num(r.group(2)) }
            }
            "count" -> {
                only(a, 1, emptyList(), "count")
                val max = intArg(if (a.pos.isEmpty()) null else a.pos[0], "count max")
                p = J.obj("type", "integer", "role", "count.limit", "min", J.n(1))
                if (max != null) p["max"] = max
                p["unit"] = J.obj("kind", "count")
            }
            "money" -> {
                only(a, 1, listOf("max", "min", "exp", "provenance"), "money")
                if (a.pos.isEmpty()) throw err("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)")
                val c = a.pos[0]
                val ccy: Any? = if (c.startsWith("@")) J.obj("from", c.substring(1)) else c
                val max = intArg(a.named["max"], "money max")
                // an amount defaults to provenance first_party (the value must not come from an untrusted tool or agent output)
                val prov = if (a.named.containsKey("provenance")) a.named["provenance"] else "first_party"
                if (!PROVENANCE_LEVELS.contains(prov)) throw err("bad_shorthand", "money provenance must be one of " + PROVENANCE_LEVELS.joinToString(", "))
                val min = intArg(a.named["min"], "money min")
                p = J.obj("type", "integer", "role", "money.amount", "min", min ?: J.n(1))
                if (max != null) p["max"] = max
                val exp = intArg(a.named["exp"], "money exp")
                p["unit"] = J.obj("kind", "money", "ccy", ccy, "exp", exp ?: J.n(2))
                p["provenance_min"] = prov
            }
            "enum", "set" -> {
                if (inner == null) throw err("bad_shorthand", "$name needs values: $name(a|b|c)")
                p = J.obj("type", if (name == "enum") "string" else "set", "values", listArg(inner, name))
            }
            "array" -> {
                only(a, 1, listOf("max", "min"), "array")
                val items = if (a.pos.isEmpty()) null else a.pos[0]
                if ("string" != items && "integer" != items) throw err("bad_shorthand", "array(items): items is string or integer")
                val max = intArg(a.named["max"], "array max")
                val min = intArg(a.named["min"], "array min")
                p = J.obj("type", "array", "items", items)
                if (min != null) p["min_items"] = min
                if (max != null) p["max_items"] = max
            }
            else -> {
                if (name.startsWith("id:")) {
                    bare(name, inner)
                    p = J.obj("type", "string", "role", "id." + name.substring(3), "max_len", J.n(64))
                } else throw err("bad_shorthand", "unknown param shorthand '$name'")
            }
        }
        if (optional) p["required"] = false
        return p
    }

    // ---- resource shorthand ------------------------------------------------------------------------------------------------------

    /**
     * `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.
     * A prefix pattern is scope one (class alnum, length 8..32 after the prefix); `*` is scope set; a bare type is tenant. Returns `{type, id, scope}`.
     */
    fun parseResourceShorthand(src: String): MutableMap<String, Any?> {
        var s = J.jsTrim(src)
        var scope: String? = null
        val at = SCOPE_AT_RE.matcher(s)
        if (at.find()) {
            if (!RESOURCE_SCOPES.contains(at.group(1))) throw err("bad_shorthand", "unknown resource scope '@" + at.group(1) + "'")
            scope = at.group(1)
            s = s.substring(0, at.start())
        }
        val colon = s.indexOf(':')
        if (colon < 0) return J.obj("type", s, "id", "*", "scope", scope ?: "tenant")
        val type = s.substring(0, colon)
        val idsrc = s.substring(colon + 1)
        if (idsrc == "*") return J.obj("type", type, "id", "*", "scope", scope ?: "set")
        val star = idsrc.indexOf('*')
        if (star < 0) return J.obj("type", type, "id", J.obj("exact", idsrc), "scope", scope ?: "one")
        val prefix = idsrc.substring(0, star)
        val rest = idsrc.substring(star + 1)
        var cls = "alnum"
        var lo = J.n(8)
        var hi = J.n(32)
        if (rest.isNotEmpty()) {
            val r = ID_CLASS_RE.matcher(rest)
            if (!r.matches() || !ID_CLASSES.contains(r.group(1))) throw err("bad_shorthand", "resource id '$idsrc': expected prefix*{class,min..max}")
            cls = r.group(1)
            lo = Json.Num(r.group(2).toInt().toString())
            hi = Json.Num(r.group(3).toInt().toString())
        }
        return J.obj("type", type, "id", J.obj("prefix", prefix, "class", cls, "len", J.list(lo, hi)), "scope", scope ?: "one")
    }

    // ---- action expansion --------------------------------------------------------------------------------------------------------

    private fun asList(v: Any?): Any? = if (v is String) J.list(v) else v

    /** The title an action gets when it names none: the action word and its nouns, "acme.invoice.send" gives "Send invoice". */
    fun defaultTitle(verb: String): String {
        val all = verb.split(".")
        val seg = ArrayList<String>()
        for (i in 1 until all.size) seg.add(all[i])
        val act = if (seg.isEmpty()) verb else seg[seg.size - 1]
        val parts = ArrayList<String>()
        parts.add(act)
        for (i in 0 until seg.size - 1) parts.add(seg[i])
        val t = parts.joinToString(" ").replace('_', ' ')
        return if (t.isEmpty()) t else t.substring(0, 1).uppercase(Locale.ROOT) + t.substring(1)
    }

    private fun isOne(v: Any?): Boolean {
        val d = J.num(v)
        return d != null && d == 1.0
    }

    /**
     * Expand one authoring entry (shorthands or full def members) to an action def. Throws ActionKitError `bad_action` for a malformed entry.
     * Returns `{def, notes}` (notes: the auto-added idempotency key).
     */
    fun expandAction(entryO: Any?, since: String?): MutableMap<String, Any?> {
        if (entryO !is Map<*, *>) throw err("bad_action", "an action must be an object")
        val entry = J.m(entryO)
        for (k in entry.keys) if (!ENTRY_KEYS.contains(k)) throw err("bad_action", "unknown member '$k'")
        if (entry.containsKey("v") && !isOne(entry["v"])) throw err("bad_action", "unsupported def version")
        if (entry.containsKey("kind") && Actions.ACTION_DEF_KIND != entry["kind"]) throw err("bad_action", "kind must be '" + Actions.ACTION_DEF_KIND + "'")
        if (entry["verb"] !is String) throw err("bad_action", "verb is required")
        val verb = entry["verb"] as String
        val notes = ArrayList<Any?>()
        if (entry.containsKey("kind")) {
            // the full form (a `kind` member) is taken exactly as written: no shorthands, no defaults, validateDef decides
            val full = LinkedHashMap<String, Any?>()
            full["v"] = J.n(1)
            full.putAll(entry)
            val je0 = Actions.jsonProfileError(full, 0)
            if (je0 != null) throw err("bad_action", "not strict JSON: $je0")
            return J.obj("def", full, "notes", notes)
        }
        val out = J.obj("v", J.n(1), "kind", Actions.ACTION_DEF_KIND, "verb", verb)
        if (entry.containsKey("aliases")) out["aliases"] = asList(entry["aliases"])
        out["title"] = entry["title"] ?: defaultTitle(verb)
        if (entry.containsKey("description")) out["description"] = entry["description"]
        out["effects"] = if (entry.containsKey("effects")) asList(entry["effects"]) else UNDEFINED
        val res = entry["resource"]
        out["resource"] = if (!entry.containsKey("resource")) UNDEFINED else if (res is String) parseResourceShorthand(res) else res
        val params = LinkedHashMap<String, Any?>()
        if (entry.containsKey("params")) {
            if (entry["params"] !is Map<*, *>) throw err("bad_action", "params must be an object")
            for ((k, v) in J.m(entry["params"])) params[k] = if (v is String) parseParamShorthand(v) else v
        }
        if (entry.containsKey("reversibility")) out["reversibility"] = entry["reversibility"]
        if (entry.containsKey("blast")) out["blast"] = if (entry["blast"] is String) J.obj("radius", entry["blast"]) else entry["blast"]
        if (entry["blast"] is String && !BLAST_RADII.contains(entry["blast"])) throw err("bad_action", "unknown blast radius '" + entry["blast"] + "'")
        if (entry.containsKey("side_effects")) out["side_effects"] = entry["side_effects"]
        // idempotency: a string is the mode; absent on a non-idempotent effect gets the key parameter (the linter notes it)
        val effs = out["effects"]
        val effects: List<Any?> = if (effs is List<*>) J.a(effs) else ArrayList()
        var idemDefined = entry.containsKey("idempotency")
        var idem: Any? = entry["idempotency"]
        if (idem is String) idem = if (idem == "key_param") J.obj("mode", "key_param", "param", IDEMPOTENCY_PARAM) else J.obj("mode", idem)
        if (!idemDefined) {
            var auto = false
            for (e in effects) if (e is String && AUTO_IDEMPOTENT_EFFECTS.contains(e)) auto = true
            if (auto) {
                idem = J.obj("mode", "key_param", "param", IDEMPOTENCY_PARAM)
                idemDefined = true
                notes.add(J.obj("verb", verb, "message", "$IDEMPOTENCY_PARAM auto-added"))
            }
        }
        if (idem is Map<*, *> && "key_param" == J.get(idem, "mode") && IDEMPOTENCY_PARAM == J.get(idem, "param") && !params.containsKey(IDEMPOTENCY_PARAM)) {
            params[IDEMPOTENCY_PARAM] = J.obj("type", "string", "max_len", J.n(64))
        }
        if (idemDefined) out["idempotency"] = idem
        out["params"] = params
        for (k in arrayOf("context", "traits")) if (entry.containsKey(k)) out[k] = asList(entry[k])
        for (k in arrayOf("audience", "compensates", "bindings", "examples", "source")) if (entry.containsKey(k)) out[k] = entry[k]
        out["review"] = entry["review"] ?: J.obj("state", "authored")
        val sin: Any? = entry["since"] ?: since
        if (sin != null) out["since"] = sin
        val je = Actions.jsonProfileError(out, 0)
        if (je != null) throw err("bad_action", "not strict JSON: $je")
        return J.obj("def", out, "notes", notes)
    }

    // ---- the document loader -----------------------------------------------------------------------------------------------------

    private fun hasProtoKey(v: Any?, depth: Int): Boolean {
        if (depth > 40 || v == null || !(v is Map<*, *> || v is List<*>)) return depth > 40
        if (v is List<*>) {
            for (x in v) if (hasProtoKey(x, depth + 1)) return true
            return false
        }
        for ((k, x) in J.m(v)) if (k == "__proto__" || hasProtoKey(x, depth + 1)) return true
        return false
    }

    private fun result(): MutableMap<String, Any?> =
        J.obj("defs", ArrayList<Any?>(), "notes", ArrayList<Any?>(), "errors", ArrayList<Any?>(), "locs", LinkedHashMap<String, Any?>(), "rules", LinkedHashMap<String, Any?>())

    private fun withError(res: MutableMap<String, Any?>, message: String): MutableMap<String, Any?> {
        res["errors"] = J.list(J.obj("message", message))
        return res
    }

    /** Expand an already parsed document (`{ns, since?, actions: [...]}`, or one raw def). Never throws. Returns `{defs, notes, errors, locs, rules[, ns]}`. */
    fun loadActionsValue(docO: Any?): MutableMap<String, Any?> {
        val res = result()
        if (hasProtoKey(docO, 0)) return withError(res, "the document contains a '__proto__' member or nests deeper than 40")
        if (docO !is Map<*, *>) return withError(res, "the document must be an object")
        val doc = J.m(docO)
        val entries: List<Any?>
        var since: String? = null
        if (Actions.ACTION_DEF_KIND == doc["kind"]) entries = J.list(doc)
        else {
            for (k in doc.keys) if (!FILE_KEYS.contains(k)) return withError(res, "unknown top-level member '$k' (expected ns, since, actions)")
            val ns = doc["ns"]
            if (ns !is String || !NS_RE.matcher(ns).matches()) return withError(res, "ns must be a lowercase identifier")
            res["ns"] = ns
            if (doc["since"] is String) since = doc["since"] as String
            else if (doc.containsKey("since")) return withError(res, "since must be a string")
            if (doc["actions"] !is List<*>) return withError(res, "actions must be a list")
            entries = J.a(doc["actions"])
        }
        val defs = J.a(res["defs"])
        val notes = J.a(res["notes"])
        val errors = J.a(res["errors"])
        val rulesOut = J.m(res["rules"])
        var index = 0
        for (e in entries) {
            val verb: String? = if (e is Map<*, *> && J.get(e, "verb") is String) J.get(e, "verb") as String else null
            try {
                // `rules` is the action's business rules block: validated against the def, kept out of the def (and its digest)
                var hasRules = false
                var rules: Any? = null
                var entry: Any? = e
                if (e is Map<*, *> && J.m(e).containsKey("rules")) {
                    hasRules = true
                    val rest = LinkedHashMap<String, Any?>(J.m(e))
                    rules = rest.remove("rules")
                    entry = rest
                }
                val ex = expandAction(entry, since)
                val def = J.m(ex["def"])
                val bad = Actions.validateDef(def)
                if (bad != null) { errors.add(errorOf(index, verb, bad)); index++; continue }
                if (hasRules) {
                    val re = ActionBusinessRules.businessRulesError(def, rules)
                    if (re != null) { errors.add(errorOf(index, verb, re)); index++; continue }
                    rulesOut[def["verb"] as String] = rules
                }
                defs.add(def)
                notes.addAll(J.a(ex["notes"]))
            } catch (ke: ActionKitError) {
                errors.add(errorOf(index, verb, ke.message))
            } catch (re: RuntimeException) {
                errors.add(errorOf(index, verb, "malformed action: " + re.message))
            }
            index++
        }
        return res
    }

    private fun errorOf(index: Int, verb: String?, message: String?): MutableMap<String, Any?> {
        val m = J.obj("index", J.n(index.toLong()))
        if (verb != null && verb.isNotEmpty()) m["verb"] = verb
        m["message"] = message
        return m
    }

    /** Load an authoring file (YAML 1.2 core schema or JSON, [fmt] "yaml" or "json") with source positions; see [ActionsText]. Input above [MAX_AUTHOR_BYTES] is refused. Never throws. */
    fun loadActionsText(text: String, fmt: String = "yaml"): MutableMap<String, Any?> = ActionsText.loadActionsText(text, fmt)

    // ---- the typed builder ---------------------------------------------------------------------------------------------------------

    /** Typed param constructors; each returns the same param the matching shorthand expands to (`x` members are merged over it; may be null). */
    object P {
        private fun merge(p: MutableMap<String, Any?>, x: Map<String, Any?>?): MutableMap<String, Any?> {
            if (x != null) p.putAll(x)
            return p
        }

        fun email(x: Map<String, Any?>?) = merge(parseParamShorthand("email"), x)
        fun phone(x: Map<String, Any?>?) = merge(parseParamShorthand("phone"), x)
        fun url(x: Map<String, Any?>?) = merge(parseParamShorthand("url"), x)
        fun uuid(x: Map<String, Any?>?) = merge(parseParamShorthand("uuid"), x)
        fun ccy(x: Map<String, Any?>?) = merge(parseParamShorthand("ccy"), x)
        fun country(x: Map<String, Any?>?) = merge(parseParamShorthand("country"), x)
        fun secret(x: Map<String, Any?>?) = merge(parseParamShorthand("secret"), x)
        fun bool(x: Map<String, Any?>?) = merge(parseParamShorthand("bool"), x)
        fun date(x: Map<String, Any?>?) = merge(parseParamShorthand("date"), x)
        fun datetime(x: Map<String, Any?>?) = merge(parseParamShorthand("datetime"), x)
        fun duration(maxMs: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (maxMs == null) "duration" else "duration($maxMs)"), x)
        fun message(maxLen: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (maxLen == null) "message" else "message($maxLen)"), x)
        fun text(maxLen: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (maxLen == null) "text" else "text($maxLen)"), x)
        fun intRange(min: Long?, max: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (min == null || max == null) "int" else "int($min..$max)"), x)
        fun count(max: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (max == null) "count" else "count($max)"), x)

        /** `ccy`: a literal ISO code, or a map `{from: param}` naming the currency param. `o`: `{max?, min?, exp?}` (may be null). */
        fun money(ccy: Any?, o: Map<String, Any?>?, x: Map<String, Any?>?): MutableMap<String, Any?> {
            val b = StringBuilder("money(").append(if (ccy is String) ccy else "@" + J.get(ccy, "from"))
            if (o != null && o["max"] != null) b.append(", max=").append(J.jsStr(o["max"]))
            if (o != null && o["min"] != null) b.append(", min=").append(J.jsStr(o["min"]))
            if (o != null && o["exp"] != null) b.append(", exp=").append(J.jsStr(o["exp"]))
            return merge(parseParamShorthand(b.append(")").toString()), x)
        }

        fun id(type: String, x: Map<String, Any?>?) = merge(parseParamShorthand("id:$type"), x)
        fun enumOf(values: List<String>, x: Map<String, Any?>?) = merge(parseParamShorthand("enum(" + values.joinToString("|") + ")"), x)
        fun setOf(values: List<String>, x: Map<String, Any?>?) = merge(parseParamShorthand("set(" + values.joinToString("|") + ")"), x)
        fun array(items: String, max: Long?, x: Map<String, Any?>?) = merge(parseParamShorthand(if (max == null) "array($items)" else "array($items, max=$max)"), x)
        fun optional(d: Map<String, Any?>): MutableMap<String, Any?> { val c = LinkedHashMap<String, Any?>(d); c["required"] = false; return c }
    }

    /**
     * The typed constructor over the JSON form: `action("acme.invoice.send", spec)`. Same expansion as the loader (so the same digest); throws
     * ActionKitError on a malformed spec.
     */
    fun action(verb: String, spec: Map<String, Any?>?): MutableMap<String, Any?> {
        val entry = LinkedHashMap<String, Any?>()
        entry["verb"] = verb
        if (spec != null) entry.putAll(spec)
        val def = J.m(expandAction(entry, null)["def"])
        val bad = Actions.validateDef(def)
        if (bad != null) throw err("bad_action", "$verb: $bad")
        return def
    }
}
