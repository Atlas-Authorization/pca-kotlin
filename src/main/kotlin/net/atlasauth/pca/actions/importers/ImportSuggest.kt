package net.atlasauth.pca.actions.importers

import java.util.TreeSet
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The deterministic suggestion layer: a versioned rule set proposes traits, param roles and param tags for a draft def. Union only: a
 * suggestion can ADD a trait, a role (to a param that has none) or a tag, never remove or replace anything, and it never marks a def
 * confirmed. A suggested def is still `pca.unreviewed` for floor purposes until a pinned reviewer signs it.
 * Defs, rule sets and suggestions are JSON trees (Map / List / String / Boolean / Json.Num).
 */
@Suppress("UNCHECKED_CAST")
object ImportSuggest {
    const val SUGGEST_RULES_KIND: String = "pca-suggest-rules"
    const val SUGGEST_RULES_DOMAIN: String = "atlas-pca/suggest-rules/v1"

    private val RULE_ID_RE = Regex("SR-[0-9]{3,4}")
    private val VERSION_RE = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
    private val TRAIT_ID_RE = Regex("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}")
    private val MATCH_KEYS: List<Any?> = listOf("methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects")
    private val PARAM_TAGS = listOf("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql")
    private val PARAM_TYPES: List<Any?> = listOf("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref")
    private const val MAX_RULES = 1024
    private const val MAX_LIST = 64

    // a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    private val NESTED_QUANTIFIER = Regex("\\([^)]*[+*][^)]*\\)[+*{]|\\([^)]*\\|[^)]*\\)[+*{]")
    private val BACKREF = Regex("\\\\[1-9]")
    private val LOOKAROUND = Regex("\\(\\?[<=!]")

    private val CORE_ROLES = listOf(
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    )
    private val ID_ROLE_RE = Regex("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val CUSTOM_ROLE_RE = Regex("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}")

    private fun isRole(r: Any?): Boolean = r is String && (r in CORE_ROLES || ID_ROLE_RE.matches(r) || CUSTOM_ROLE_RE.matches(r))

    private fun isStrList(v: Any?, max: Int): Boolean {
        if (v !is List<*>) return false
        if (v.isEmpty() || v.size > max) return false
        for (x in v) if (x !is String || x.isEmpty() || x.length > 64) return false
        return true
    }

    // ---- JavaScript regular expression to java.util.regex (the bounded subset the rules use) ----

    private const val JS_SPACE = "\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF"

    private fun hex(s: String, from: Int, n: Int): Boolean {
        if (from + n > s.length) return false
        for (i in from until from + n) if (Character.digit(s[i], 16) < 0 || s[i].code > 0x7f) return false
        return true
    }

    /** The end of a `{n}`, `{n,}` or `{n,m}` quantifier starting at [i], or -1. */
    private fun quantEnd(s: String, i: Int): Int {
        var j = i + 1
        var d = 0
        while (j < s.length && s[j] >= '0' && s[j] <= '9') { j++; d++ }
        if (d == 0) return -1
        if (j < s.length && s[j] == ',') { j++; while (j < s.length && s[j] >= '0' && s[j] <= '9') j++ }
        return if (j < s.length && s[j] == '}') j + 1 else -1
    }

    /** Compile a JavaScript pattern (no flags); an IllegalArgumentException where the engine would raise SyntaxError. */
    internal fun jsRegex(s: String): Pattern {
        val o = StringBuilder()
        val n = s.length
        var i = 0
        var depth = 0
        var inClass = false
        var canQuant = false
        while (i < n) {
            val c = s[i]
            if (inClass) {
                if (c == ']') { o.append(']'); inClass = false; canQuant = true; i++; continue }
                if (c == '\\') {
                    if (i + 1 >= n) throw IllegalArgumentException("\\ at end of pattern")
                    val e = s[i + 1]
                    i += 2
                    if (e == 's') o.append(JS_SPACE)
                    else if (e == 'S') o.append("[^").append(JS_SPACE).append(']')
                    else if (e == 'd' || e == 'D' || e == 'w' || e == 'W') o.append('\\').append(e)
                    else if (e == 'b') o.append("\\x08")
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.append('\\').append(e)
                    else if (e == 'v') o.append("\\u000B")
                    else if (e == '0') o.append("\\x00")
                    else if (e == 'x' && hex(s, i, 2)) { o.append("\\x").append(s, i, i + 2); i += 2 }
                    else if (e == 'u' && hex(s, i, 4)) { o.append("\\u").append(s, i, i + 4); i += 4 }
                    else if (e.code < 128 && !Character.isLetterOrDigit(e)) o.append('\\').append(e)
                    else o.append(e)
                    continue
                }
                if (c == '[' || c == '&' || c == '^') o.append('\\').append(c) else o.append(c)
                i++
                continue
            }
            when (c) {
                '\\' -> {
                    if (i + 1 >= n) throw IllegalArgumentException("\\ at end of pattern")
                    val e = s[i + 1]
                    i += 2
                    canQuant = true
                    if (e == 'b' || e == 'B') { o.append('\\').append(e); canQuant = false }
                    else if (e == 'd' || e == 'D' || e == 'w' || e == 'W') o.append('\\').append(e)
                    else if (e == 's') o.append('[').append(JS_SPACE).append(']')
                    else if (e == 'S') o.append("[^").append(JS_SPACE).append(']')
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.append('\\').append(e)
                    else if (e == 'v') o.append("\\u000B")
                    else if (e == '0') o.append("\\x00")
                    else if (e >= '1' && e <= '9') o.append('\\').append(e)
                    else if (e == 'x' && hex(s, i, 2)) { o.append("\\x").append(s, i, i + 2); i += 2 }
                    else if (e == 'u' && hex(s, i, 4)) { o.append("\\u").append(s, i, i + 4); i += 4 }
                    else if (e == 'c' && i < n && Character.isLetter(s[i]) && s[i].code < 128) { o.append("\\c").append(s[i]); i++ }
                    else if (e == 'c') o.append("\\\\c")
                    else if (e.code < 128 && !Character.isLetterOrDigit(e)) o.append('\\').append(e)
                    else o.append(e)
                }
                '(' -> {
                    if (i + 1 < n && s[i + 1] == '?') {
                        if (i + 2 < n && (s[i + 2] == ':' || s[i + 2] == '=' || s[i + 2] == '!')) { o.append("(?").append(s[i + 2]); i += 3 }
                        else throw IllegalArgumentException("invalid group")
                    } else { o.append('('); i++ }
                    depth++
                    canQuant = false
                }
                ')' -> {
                    if (depth == 0) throw IllegalArgumentException("unmatched )")
                    depth--; o.append(')'); canQuant = true; i++
                }
                '|' -> { o.append('|'); canQuant = false; i++ }
                '*', '+', '?' -> {
                    if (!canQuant) throw IllegalArgumentException("nothing to repeat")
                    o.append(c); i++
                    if (i < n && s[i] == '?') { o.append('?'); i++ }
                    canQuant = false
                }
                '{' -> {
                    val e = quantEnd(s, i)
                    if (e < 0) { o.append("\\{"); canQuant = true; i++ }
                    else {
                        if (!canQuant) throw IllegalArgumentException("nothing to repeat")
                        o.append(s, i, e); i = e
                        if (i < n && s[i] == '?') { o.append('?'); i++ }
                        canQuant = false
                    }
                }
                '}' -> { o.append("\\}"); canQuant = true; i++ }
                ']' -> { o.append("\\]"); canQuant = true; i++ }
                '[' -> {
                    if (s.startsWith("[]", i)) { o.append("(?!)"); i += 2; canQuant = true }
                    else if (s.startsWith("[^]", i)) { o.append("[\\s\\S]"); i += 3; canQuant = true }
                    else {
                        inClass = true; i++
                        if (i < n && s[i] == '^') { o.append("[^"); i++ } else o.append('[')
                    }
                }
                '.' -> { o.append("[^\\n\\r\\u2028\\u2029]"); canQuant = true; i++ }
                '^' -> { o.append('^'); canQuant = false; i++ }
                '$' -> { o.append("\\z"); canQuant = false; i++ }
                else -> { o.append(c); canQuant = true; i++ }
            }
        }
        if (inClass || depth != 0) throw IllegalArgumentException("unterminated pattern")
        try { return Pattern.compile(o.toString()) } catch (e: PatternSyntaxException) { throw IllegalArgumentException(e.message) }
    }

    // ---- rule set validation, digest, signature ----

    private val RULE_MEMBERS = listOf("v", "kind", "version", "rules", "digest", "sig")
    private val RULE_KEYS = listOf("id", "match", "adds", "note")

    /** Null if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names. */
    fun suggestRulesError(r: Any?, known: Set<String>?): String? {
        if (r !is Map<*, *>) return "rules must be an object"
        val o = Jx.m(r)
        for (k in Jx.keys(o)) if (!RULE_MEMBERS.contains(k)) return "unknown member '$k'"
        val one = Jx.num(o["v"])
        if (one == null || one != 1.0 || SUGGEST_RULES_KIND != o["kind"]) return "not a suggest-rules document (v 1)"
        val version = o["version"]
        if (version !is String || !VERSION_RE.matches(version)) return "version must be semver"
        if (o["rules"] !is List<*> || Jx.a(o["rules"]).isEmpty() || Jx.a(o["rules"]).size > MAX_RULES) return "rules must be 1..$MAX_RULES entries"
        val ids = LinkedHashSet<String>()
        for (x in Jx.a(o["rules"])) {
            if (x !is Map<*, *>) return "a rule must be an object"
            val rule = Jx.m(x)
            for (k in Jx.keys(rule)) if (!RULE_KEYS.contains(k)) return "rule: unknown member '$k'"
            val rid = rule["id"]
            if (rid !is String || !RULE_ID_RE.matches(rid) || ids.contains(rid)) return "rule ids must be unique SR-nnn"
            val w: String = rid
            ids.add(w)
            val note = rule["note"]
            if (note !is String || note.isEmpty() || note.length > 200) return "$w: note must be 1..200 characters"
            if (rule["match"] !is Map<*, *> || Jx.m(rule["match"]).isEmpty()) return "$w: match must be a non-empty object"
            val m = Jx.m(rule["match"])
            for (k in Jx.keys(m)) if (!MATCH_KEYS.contains(k)) return "$w: unknown match member '$k'"
            for (k in listOf("methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"))
                if (m.containsKey(k) && !isStrList(m[k], MAX_LIST)) return "$w: match.$k must be 1..$MAX_LIST short strings"
            if (m.containsKey("methods")) for (s in Jx.a(m["methods"])) if ((s as String) != s.uppercase()) return "$w: methods are uppercase"
            if (m.containsKey("param_types")) {
                var bad = !isStrList(m["param_types"], MAX_LIST)
                if (!bad) for (t in Jx.a(m["param_types"])) if (!PARAM_TYPES.contains(t)) { bad = true; break }
                if (bad) return "$w: match.param_types is not a list of param types"
            }
            if (m.containsKey("effects") && !isStrList(m["effects"], 12)) return "$w: match.effects must be a list of effects"
            if (m.containsKey("path_re")) {
                val pr = m["path_re"]
                if (pr !is String || pr.isEmpty() || pr.length > 128) return "$w: path_re must be 1..128 characters"
                if (NESTED_QUANTIFIER.containsMatchIn(pr) || BACKREF.containsMatchIn(pr) || LOOKAROUND.containsMatchIn(pr))
                    return "$w: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)"
                try { jsRegex(pr) } catch (e: IllegalArgumentException) { return "$w: path_re is not a regular expression" }
            }
            val hasParam = m.containsKey("param_names") || m.containsKey("param_names_all") || m.containsKey("param_formats") || m.containsKey("roles")
            if (m.containsKey("param_types") && !m.containsKey("param_names") && !m.containsKey("param_formats") && !m.containsKey("param_names_all")) return "$w: param_types needs param_names, param_names_all or param_formats"
            if (!isStrList(rule["adds"], 16)) return "$w: adds must be 1..16 entries"
            for (ao in Jx.a(rule["adds"])) {
                val a = ao as String
                if (a.startsWith("tag:")) {
                    if (!PARAM_TAGS.contains(a.substring(4))) return "$w: unknown tag '$a'"
                    if (!hasParam) return "$w: a tag needs a param matcher"
                } else if (isRole(a)) {
                    if (!hasParam) return "$w: a role needs a param matcher"
                } else if (TRAIT_ID_RE.matches(a)) {
                    if (known != null && !known.contains(a)) return "$w: unknown trait '$a'"
                } else return "$w: '$a' is not a trait, role or tag:"
            }
        }
        return null
    }

    /** b64u sha256 of the strict canonical rule set (without digest and sig). */
    fun rulesDigest(r: Map<String, Any?>): String {
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "kind", "version", "rules")) if (r.containsKey(k)) body[k] = r[k]
        return Pca.hashCanonical(Jx.obj("d", SUGGEST_RULES_DOMAIN, "rules", body))
    }

    fun sealRules(r: Map<String, Any?>): MutableMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>(r)
        out["digest"] = rulesDigest(r)
        return out
    }

    private fun rulesMessage(digest: String): ByteArray {
        val dom = (SUGGEST_RULES_DOMAIN + "\u0000").toByteArray(Charsets.UTF_8)
        val body = Json.canonicalizeStrict(Jx.obj("digest", digest)).toByteArray(Charsets.UTF_8)
        return dom + body
    }

    /** Sign a rule set as the rules publisher (a release step; the signature covers the digest). [secret]: the Ed25519 seed. */
    fun signRules(r: Map<String, Any?>, kid: String, secret: ByteArray): Map<String, Any?> {
        val bad = suggestRulesError(r, null)
        if (bad != null) throw ActionKitError("bad_rules", bad)
        val sealed = sealRules(r)
        sealed["sig"] = Jx.obj("alg", "ed25519", "kid", kid, "value", Keys.b64u(Keys.edFromSeed(secret).sign(rulesMessage(sealed["digest"] as String))))
        return sealed
    }

    /** Verify a signed rule set against pinned publisher keys (`[{kid, pk}]`): shape, digest, signature. Never throws. */
    fun verifyRules(doc: Any?, pins: List<Map<String, Any?>>): Map<String, Any?> {
        try {
            val bad = suggestRulesError(doc, null)
            if (bad != null) return Jx.obj("ok", false, "reason", bad)
            val d = Jx.m(doc)
            if (rulesDigest(d) != d["digest"]) return Jx.obj("ok", false, "reason", "digest does not match the rules")
            if (!Jx.truthy(d["sig"])) return Jx.obj("ok", false, "reason", "the rule set is not signed")
            val sig = d["sig"]
            val kid = Jx.get(sig, "kid")
            var key: Map<String, Any?>? = null
            for (p in pins) if (kid != null && kid == p["kid"]) { key = p; break }
            if (key == null) return Jx.obj("ok", false, "reason", "no pinned rules key '" + (if (Jx.has(sig, "kid")) Jx.jsStr(kid) else "undefined") + "'")
            val value = Jx.get(sig, "value")
            val pk = key["pk"]
            val ok = pk is String && value is String && Pca.verifyB64u(pk, rulesMessage(d["digest"] as String), value)
            return if (ok) Jx.obj("ok", true) else Jx.obj("ok", false, "reason", "rules signature invalid")
        } catch (e: RuntimeException) {
            return Jx.obj("ok", false, "reason", "rules verification error: " + e.message)
        }
    }

    // ---- facts ----

    /** Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` to `charg`). */
    fun stem(t: String): String {
        var s = t
        if (s.length > 4 && s.endsWith("ies")) s = s.substring(0, s.length - 3) + "y"
        else if ((s.endsWith("sses") || s.endsWith("xes") || s.endsWith("zes") || s.endsWith("ches") || s.endsWith("shes")) && s.length > 4) s = s.substring(0, s.length - 2)
        else if (s.length > 3 && s.endsWith("s") && !s.endsWith("ss")) s = s.substring(0, s.length - 1)
        if (s.length > 5 && s.endsWith("ing")) s = s.substring(0, s.length - 3)
        else if (s.length > 4 && s.endsWith("ed")) s = s.substring(0, s.length - 2)
        if (s.length > 3 && s.endsWith("e")) s = s.substring(0, s.length - 1)
        return s
    }

    private const val SEP = "|"

    /** What the rules read of a def: methods, binding locations, stemmed name tokens (with and without path segments), params and effects. */
    class Facts internal constructor() {
        @JvmField val methods: MutableSet<String> = LinkedHashSet()
        @JvmField val locs: MutableList<String> = ArrayList()
        @JvmField val tokens: MutableList<String> = ArrayList()
        @JvmField val strict: MutableList<String> = ArrayList()
        @JvmField val params: MutableList<FParam> = ArrayList()
        @JvmField val effects: MutableSet<String> = LinkedHashSet()

        fun toJson(): Map<String, Any?> {
            val ps = ArrayList<Any?>()
            for (p in params) {
                val m = Jx.obj("name", p.name, "tokens", ArrayList<Any?>(p.tokens), "type", p.type)
                if (p.format != null) m["format"] = p.format
                if (p.role != null) m["role"] = p.role
                ps.add(m)
            }
            return Jx.obj(
                "methods", ArrayList<Any?>(TreeSet(methods)), "locs", ArrayList<Any?>(locs), "tokens", ArrayList<Any?>(tokens), "strict", ArrayList<Any?>(strict),
                "params", ps, "effects", ArrayList<Any?>(TreeSet(effects)),
            )
        }
    }

    class FParam internal constructor(@JvmField val name: String, @JvmField val tokens: List<String>, @JvmField val type: String?, @JvmField val format: String?, @JvmField val role: String?)

    private fun stems(toks: List<String>): List<String> {
        val o = ArrayList<String>()
        for (t in toks) o.add(stem(t))
        return o
    }

    private fun up(s: Any?): String = Jx.jsStr(s).uppercase()

    fun factsOf(d: Map<String, Any?>): Facts {
        val b0 = d["bindings"]
        val b: Any? = b0 ?: LinkedHashMap<String, Any?>()
        val f = Facts()
        val src = ArrayList<List<String>>()
        val isPath = ArrayList<Boolean>()
        val verbSegs = Jx.jsStr(d["verb"]).split(".")
        val vt = ArrayList<String>()
        for (i in 1 until verbSegs.size) vt.addAll(ImportCommon.tokensOf(verbSegs[i]))
        src.add(vt); isPath.add(false)
        if (d["aliases"] is List<*>) for (a in Jx.a(d["aliases"])) { src.add(ImportCommon.tokensOf(a)); isPath.add(false) }
        src.add(ImportCommon.tokensOf(d["title"])); isPath.add(false)
        val oa = Jx.get(b, "openapi")
        if (Jx.truthy(oa)) {
            src.add(ImportCommon.tokensOf(Jx.get(oa, "operationId"))); isPath.add(false)
            if (Jx.truthy(Jx.get(oa, "method"))) f.methods.add(up(Jx.get(oa, "method")))
            if (Jx.truthy(Jx.get(oa, "path"))) {
                val p = Jx.jsStr(Jx.get(oa, "path"))
                f.locs.add(p)
                src.add(pathTokens(p)); isPath.add(true)
            }
        }
        val http = Jx.get(b, "http")
        if (Jx.truthy(http)) {
            f.methods.add(up(Jx.get(http, "method")))
            val p = Jx.jsStr(Jx.get(http, "path"))
            f.locs.add(p)
            src.add(pathTokens(p)); isPath.add(true)
        }
        val mcp = Jx.get(b, "mcp")
        if (Jx.truthy(mcp)) { f.locs.add(Jx.jsStr(Jx.get(mcp, "tool"))); src.add(ImportCommon.tokensOf(Jx.get(mcp, "tool"))); isPath.add(false) }
        val gql = Jx.get(b, "graphql")
        if (Jx.truthy(gql)) { f.methods.add(up(Jx.get(gql, "op"))); f.locs.add(Jx.jsStr(Jx.get(gql, "field"))); src.add(ImportCommon.tokensOf(Jx.get(gql, "field"))); isPath.add(false) }
        val grpc = Jx.get(b, "grpc")
        if (Jx.truthy(grpc)) {
            f.locs.add(Jx.jsStr(Jx.get(grpc, "service")) + "/" + Jx.jsStr(Jx.get(grpc, "method")))
            src.add(ImportCommon.tokensOf(Jx.get(grpc, "service"))); isPath.add(false)
            src.add(ImportCommon.tokensOf(Jx.get(grpc, "method"))); isPath.add(false)
        }
        val asy = Jx.get(b, "asyncapi")
        if (Jx.truthy(asy)) { f.methods.add(up(Jx.get(asy, "op"))); f.locs.add(Jx.jsStr(Jx.get(asy, "channel"))); src.add(ImportCommon.tokensOf(Jx.get(asy, "channel"))); isPath.add(false) }
        for (i in 0 until src.size) {
            if (f.tokens.isNotEmpty()) f.tokens.add(SEP)
            f.tokens.addAll(stems(src[i]))
            if (!isPath[i]) { if (f.strict.isNotEmpty()) f.strict.add(SEP); f.strict.addAll(stems(src[i])) }
        }
        val params: Map<String, Any?> = if (d["params"] is Map<*, *>) Jx.m(d["params"]) else LinkedHashMap()
        for (name in TreeSet(params.keys)) {
            val p = params[name]
            val fm = Jx.get(p, "format")
            val ro = Jx.get(p, "role")
            f.params.add(FParam(name, stems(ImportCommon.tokensOf(name)), Jx.get(p, "type") as String?, if (Jx.truthy(fm)) Jx.jsStr(fm) else null, if (Jx.truthy(ro)) Jx.jsStr(ro) else null))
        }
        val clipped = ArrayList<String>()
        for (l in f.locs) clipped.add(if (l.length > 512) l.substring(0, 512) else l)
        f.locs.clear()
        f.locs.addAll(clipped)
        if (d["effects"] is List<*>) for (e in Jx.a(d["effects"])) f.effects.add(Jx.jsStr(e))
        return f
    }

    private fun pathTokens(p: String): List<String> {
        val out = ArrayList<String>()
        for (s in p.split("/")) if (s.isNotEmpty() && s.indexOf('{') < 0 && s.indexOf('}') < 0) out.addAll(ImportCommon.tokensOf(s))
        return out
    }

    /** True iff the stemmed pattern occurs as a contiguous run in [hay]. */
    private fun hasSeq(hay: List<String>, pat: List<String>): Boolean {
        if (pat.isEmpty()) return false
        var i = 0
        while (i + pat.size <= hay.size) {
            var ok = true
            for (j in pat.indices) if (hay[i + j] != pat[j]) { ok = false; break }
            if (ok) return true
            i++
        }
        return false
    }

    private fun patOf(s: String): List<String> = stems(ImportCommon.tokensOf(s))

    fun emptySuggestion(): Map<String, Any?> = Jx.obj("traits", ArrayList<Any?>(), "roles", LinkedHashMap<String, Any?>(), "tags", LinkedHashMap<String, Any?>(), "fired", ArrayList<Any?>())

    private val INT_ROLES = setOf("money.amount", "money.fee", "count.limit", "bytes.size")

    private fun roleFits(role: String, type: String?): Boolean {
        if (INT_ROLES.contains(role)) return "integer" == type
        if (role.startsWith("time.")) return "date" == type || "datetime" == type || "integer" == type
        return "string" == type
    }

    private fun strs(o: Any?): List<String> {
        val out = ArrayList<String>()
        if (o is List<*>) for (x in o) out.add(Jx.jsStr(x))
        return out
    }

    /**
     * Run the rules over a def. Only trait ids in [registry] (when given) can be suggested; anything else is dropped (the closed
     * vocabulary). Pure and deterministic. Returns `{traits, roles, tags, fired}`.
     */
    fun suggestWithRules(d: Map<String, Any?>, rules: Map<String, Any?>, registry: Map<String, Map<String, Any?>>?): Map<String, Any?> {
        val f = factsOf(d)
        val traits = TreeSet<String>()
        val roles = LinkedHashMap<String, Any?>()
        val tags = LinkedHashMap<String, TreeSet<String>>()
        val fired = ArrayList<Any?>()
        val stemsAll = f.tokens
        for (ro in Jx.a(rules["rules"])) {
            val rule = Jx.m(ro)
            val m = Jx.m(rule["match"])
            if (Jx.truthy(m["methods"])) { var any = false; for (x in strs(m["methods"])) if (f.methods.contains(x)) { any = true; break }; if (!any) continue }
            if (Jx.truthy(m["effects"])) { var any = false; for (x in strs(m["effects"])) if (f.effects.contains(x)) { any = true; break }; if (!any) continue }
            if (Jx.truthy(m["name_tokens"])) { var any = false; for (p in strs(m["name_tokens"])) if (hasSeq(stemsAll, patOf(p))) { any = true; break }; if (!any) continue }
            if (Jx.truthy(m["name_tokens_strict"])) { var any = false; for (p in strs(m["name_tokens_strict"])) if (hasSeq(f.strict, patOf(p))) { any = true; break }; if (!any) continue }
            if (Jx.truthy(m["path_re"])) {
                val re = jsRegex(Jx.jsStr(m["path_re"]))
                var any = false
                for (l in f.locs) if (re.matcher(l).find()) { any = true; break }
                if (!any) continue
            }
            if (Jx.truthy(m["roles"])) {
                val rs = strs(m["roles"])
                var any = false
                for (p in f.params) if (p.role != null && rs.contains(p.role)) { any = true; break }
                if (!any) continue
            }
            val matched = ArrayList<FParam>()
            val paramCond = m.containsKey("param_names") || m.containsKey("param_formats")
            val ptypes: List<String>? = if (Jx.truthy(m["param_types"])) strs(m["param_types"]) else null
            if (paramCond) {
                val pats = ArrayList<List<String>>()
                if (Jx.truthy(m["param_names"])) for (n in strs(m["param_names"])) pats.add(patOf(n))
                for (p in f.params) {
                    if (ptypes != null && !ptypes.contains(p.type)) continue
                    if (Jx.truthy(m["param_names"])) { var any = false; for (q in pats) if (hasSeq(p.tokens, q)) { any = true; break }; if (!any) continue }
                    if (Jx.truthy(m["param_formats"]) && (p.format == null || !strs(m["param_formats"]).contains(p.format))) continue
                    matched.add(p)
                }
                if (matched.isEmpty()) continue
            }
            if (Jx.truthy(m["param_names_all"])) {
                var ok = true
                for (n in strs(m["param_names_all"])) {
                    val q = patOf(n)
                    var has = false
                    for (p in f.params) if (hasSeq(p.tokens, q) && (ptypes == null || ptypes.contains(p.type) || "string" == p.type)) { has = true; break }
                    if (!has) { ok = false; break }
                }
                if (!ok) continue
            }
            fired.add(rule["id"])
            for (a in strs(rule["adds"])) {
                if (a.startsWith("tag:")) {
                    for (p in matched) tags.getOrPut(p.name) { TreeSet() }.add(a.substring(4))
                } else if (!isRole(a)) {
                    if (registry == null || registry.containsKey(a)) traits.add(a)
                } else {
                    for (p in matched) if (p.role == null && roles[p.name] == null && roleFits(a, p.type)) roles[p.name] = a
                }
            }
        }
        traits.remove("pca.unreviewed")
        val tagOut = LinkedHashMap<String, Any?>()
        for (k in TreeSet(tags.keys)) tagOut[k] = ArrayList<Any?>(TreeSet(tags[k]!!))
        return Jx.obj("traits", ArrayList<Any?>(traits), "roles", roles, "tags", tagOut, "fired", fired)
    }

    private fun sortedUnion(vararg ls: List<*>?): MutableList<Any?> {
        val s = TreeSet<String>()
        for (l in ls) if (l != null) for (x in l) s.add(Jx.jsStr(x))
        return ArrayList<Any?>(s)
    }

    /** Union two suggestions (the restrictive direction, so no intersection is needed). */
    fun unionSuggestions(a: Map<String, Any?>, b: Map<String, Any?>): Map<String, Any?> {
        val roles = LinkedHashMap<String, Any?>(Jx.m(b["roles"]))
        roles.putAll(Jx.m(a["roles"]))
        val tags = LinkedHashMap<String, Any?>()
        val ks = LinkedHashSet<String>(Jx.m(a["tags"]).keys)
        ks.addAll(Jx.m(b["tags"]).keys)
        for (k in ks) tags[k] = sortedUnion(Jx.m(a["tags"])[k] as List<*>?, Jx.m(b["tags"])[k] as List<*>?)
        val fired = ArrayList<Any?>(Jx.a(a["fired"]))
        fired.addAll(Jx.a(b["fired"]))
        return Jx.obj("traits", sortedUnion(Jx.a(a["traits"]), Jx.a(b["traits"])), "roles", roles, "tags", tags, "fired", fired)
    }

    /**
     * Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is
     * removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested`.
     * [by]: `{rules?: {version, digest, fired}, models?: [...]}`.
     */
    fun applySuggestion(d: Map<String, Any?>, s: Map<String, Any?>, by: Map<String, Any?>): Map<String, Any?> {
        val params = LinkedHashMap<String, Any?>()
        val addedRoles = LinkedHashMap<String, Any?>()
        val addedTags = LinkedHashMap<String, Any?>()
        val sroles = Jx.m(s["roles"])
        val stags = Jx.m(s["tags"])
        for ((name, pv) in Jx.m(d["params"])) {
            val p = Jx.m(pv)
            var q: Map<String, Any?> = p
            val role = sroles[name]
            if (role != null && p["role"] == null && roleFits(role as String, p["type"] as String?)) { q = LinkedHashMap(q); q["role"] = role; addedRoles[name] = role }
            val t = stags[name]
            if (t != null) {
                val have: List<Any?> = if (p["tags"] is List<*>) Jx.a(p["tags"]) else ArrayList()
                val fresh = ArrayList<Any?>()
                for (x in Jx.a(t)) if (!have.contains(x)) fresh.add(x)
                if (fresh.isNotEmpty()) { q = LinkedHashMap(q); q["tags"] = sortedUnion(have, fresh); addedTags[name] = fresh }
            }
            params[name] = q
        }
        val dtraits: List<Any?> = if (d["traits"] is List<*>) Jx.a(d["traits"]) else ArrayList()
        val freshTraits = ArrayList<Any?>()
        for (t in Jx.a(s["traits"])) if (!dtraits.contains(t)) freshTraits.add(t)
        // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
        var idempotency = d["idempotency"]
        if (Jx.a(s["traits"]).contains("pca.money_moving") && (idempotency == null || "none" == Jx.get(idempotency, "mode"))) {
            idempotency = Jx.obj("mode", "key_param", "param", "idempotency_key")
            if (!params.containsKey("idempotency_key")) params["idempotency_key"] = Jx.obj("type", "string", "max_len", Jx.n(64), "required", false)
        }
        val review = Jx.m(d["review"])
        val prev: Map<String, Any?> = if (review["suggested_by"] is Map<*, *>) Jx.m(review["suggested_by"]) else LinkedHashMap()
        val prevAdded: Map<String, Any?> = if (prev["added"] != null) Jx.m(prev["added"]) else Jx.obj("traits", ArrayList<Any?>(), "roles", LinkedHashMap<String, Any?>(), "tags", LinkedHashMap<String, Any?>())
        val addedRolesAll = LinkedHashMap<String, Any?>(Jx.m(prevAdded["roles"]))
        addedRolesAll.putAll(addedRoles)
        val prevTags = Jx.m(prevAdded["tags"])
        val tagKeys = TreeSet<String>(prevTags.keys)
        tagKeys.addAll(addedTags.keys)
        val tagsAll = LinkedHashMap<String, Any?>()
        for (k in tagKeys) tagsAll[k] = sortedUnion(prevTags[k] as List<*>?, addedTags[k] as List<*>?)
        val added = Jx.obj("traits", sortedUnion(Jx.a(prevAdded["traits"]), freshTraits), "roles", addedRolesAll, "tags", tagsAll)
        val rules = if (by["rules"] != null) by["rules"] else prev["rules"]
        val models = ArrayList<Any?>()
        if (prev["models"] is List<*>) models.addAll(Jx.a(prev["models"]))
        if (by["models"] is List<*>) models.addAll(Jx.a(by["models"]))
        val suggestedBy = LinkedHashMap<String, Any?>()
        if (rules != null) suggestedBy["rules"] = rules
        if (models.isNotEmpty()) suggestedBy["models"] = models
        suggestedBy["added"] = added
        val st = review["state"]
        val state: Any? = if ("unreviewed" == st || "suggested" == st) "suggested" else st
        val out = LinkedHashMap<String, Any?>(d)
        out["params"] = params
        if (idempotency != null) out["idempotency"] = idempotency
        if (freshTraits.isNotEmpty() || dtraits.isNotEmpty()) out["traits"] = sortedUnion(dtraits, Jx.a(s["traits"]))
        val nr = LinkedHashMap<String, Any?>(review)
        nr["state"] = state
        nr["suggested_by"] = suggestedBy
        out["review"] = nr
        return out
    }
}
