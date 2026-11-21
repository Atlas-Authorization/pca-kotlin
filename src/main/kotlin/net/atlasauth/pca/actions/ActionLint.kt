package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Json

import java.util.Locale
import java.util.TreeSet
import java.util.regex.Pattern
import net.atlasauth.pca.policyci.ActionLintRules
import net.atlasauth.pca.verifier.Actions

/**
 * The 24 stable lint rules (14 errors LD-001..014, 10 warnings LW-001..010), SARIF output and the rule-list digest. Pure: defs in,
 * findings out, deterministic order. A def that does not pass validation is reported as LD-000 and not linted further. The rule list
 * and its digest are those of [ActionLintRules] (one copy).
 */
@Suppress("UNCHECKED_CAST")
object ActionLint {
    const val LINT_RULES_DIGEST_DOMAIN = ActionLintRules.LINT_RULES_DIGEST_DOMAIN
    val STRUCTURE_RULE: Array<String> = arrayOf("LD-000", "error", "the def is not well formed and cannot be loaded")
    val NOTE_RULE: Array<String> = arrayOf("LN-001", "note", "an informational note from the loader")

    /** The digest a policy gate pins: the ordered (id, severity, title) list. */
    fun lintRulesDigest(): String = ActionLintRules.lintRulesDigest()

    private val DESTROY_RE = Pattern.compile("^(?:delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(?:_|\\z)")
    private val SEND_RE = Pattern.compile("^(?:send|email|notify|sms|message|post_to|broadcast|invite)(?:_|\\z)")
    private val EXPORT_RE = Pattern.compile("^(?:export|download|dump|backup|extract)(?:_|\\z)")
    private val NAME_GROUPS: List<List<String>> = listOf(listOf("create_", "new_", "add_", "make_"), listOf("delete_", "remove_", "destroy_"))
    private val OWN_RULES = listOf("money_has_currency", "money_amount_bounded", "pay_has_idempotency")

    // the vocabularies the validator checks against (the same lists as the action kit core)
    private val EFFECTS = listOf("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign")
    private val CORE_ROLES = listOf(
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    )
    private val PARAM_FORMATS = listOf("email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256")
    private val ID_ROLE_RE = Regex("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val CUSTOM_ROLE_RE = Regex("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}")
    private val ID_FORMAT_RE = Regex("id:[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val CRITICAL_ROLES = setOf(
        "money.amount", "party.payee", "person.national_id", "credential.secret", "credential.token", "credential.key", "code.command", "query.sql",
    )
    private val CRITICAL_TAGS = setOf("secret", "credential")

    private fun isRole(r: Any?): Boolean = r is String && (r in CORE_ROLES || ID_ROLE_RE.matches(r) || CUSTOM_ROLE_RE.matches(r))
    private fun isFormat(f: Any?): Boolean = f is String && (f in PARAM_FORMATS || ID_FORMAT_RE.matches(f))

    /** Is the param's sensitivity critical after the role and tag floors? */
    private fun isCritical(q: Map<String, Any?>): Boolean {
        if ("critical" == q["sensitivity"]) return true
        val role = q["role"]
        if (role is String && role in CRITICAL_ROLES) return true
        val tg = q["tags"]
        if (tg is List<*>) for (t in tg) if (t is String && t in CRITICAL_TAGS) return true
        return false
    }

    private fun lastSeg(verb: String): String {
        val i = verb.lastIndexOf('.')
        return if (i < 0) verb else verb.substring(i + 1)
    }

    private fun bindingKeys(d: Map<String, Any?>): List<String> {
        val out = ArrayList<String>()
        val b = d["bindings"] ?: return out
        if (J.get(b, "mcp") != null) out.add("mcp:" + J.get(J.get(b, "mcp"), "tool"))
        if (J.get(b, "openapi") != null) out.add("openapi:" + J.get(J.get(b, "openapi"), "operationId"))
        if (J.get(b, "http") != null) out.add("http:" + (J.get(J.get(b, "http"), "method") as String).uppercase(Locale.ROOT) + " " + J.get(J.get(b, "http"), "path"))
        if (J.get(b, "graphql") != null) out.add("graphql:" + J.get(J.get(b, "graphql"), "op") + "." + J.get(J.get(b, "graphql"), "field"))
        if (J.get(b, "grpc") != null) out.add("grpc:" + J.get(J.get(b, "grpc"), "service") + "/" + J.get(J.get(b, "grpc"), "method"))
        if (J.get(b, "asyncapi") != null) out.add("asyncapi:" + J.get(J.get(b, "asyncapi"), "op") + " " + J.get(J.get(b, "asyncapi"), "channel"))
        return out
    }

    private fun vocabularyIssues(x: Any?, reg: Map<String, Map<String, Any?>>): List<String> {
        val out = ArrayList<String>()
        if (x !is Map<*, *>) return out
        val effects = J.get(x, "effects")
        if (effects is List<*>) for (e in effects) if (!EFFECTS.contains(e)) out.add("unknown effect '" + J.jsStr(e) + "'")
        val params = J.get(x, "params")
        if (params is Map<*, *>) {
            for ((k, q) in J.m(params)) {
                if (q !is Map<*, *>) continue
                val qm = J.m(q)
                if (qm.containsKey("role") && !isRole(qm["role"])) out.add(k + ": unknown role '" + J.jsStr(qm["role"]) + "'")
                if (qm.containsKey("format") && !isFormat(qm["format"])) out.add(k + ": unknown format '" + J.jsStr(qm["format"]) + "'")
            }
        }
        val ctx = J.get(x, "context")
        if (ctx is List<*>) for (c in ctx) if (!Actions.isContextKey(c)) out.add("unknown context key '" + J.jsStr(c) + "' (known: " + Actions.CONTEXT_KEYS.joinToString(", ") + ", session_taint_max:<level>)")
        val tr = J.get(x, "traits")
        if (tr is List<*>) for (t in tr) if (t is String && !reg.containsKey(t)) out.add("unknown trait '$t'")
        return out
    }

    private fun severityOf(rule: String): String {
        if (rule == STRUCTURE_RULE[0]) return "error"
        for (r in ActionLintRules.LINT_RULES) if (r[0] == rule) return r[1]
        throw IllegalArgumentException("unknown rule $rule")
    }

    private fun add(out: MutableList<MutableMap<String, Any?>>, rule: String, verb: String?, message: String, param: String?) {
        val f = J.obj("rule", rule, "severity", severityOf(rule))
        if (verb != null) f["verb"] = verb
        if (param != null) f["param"] = param
        f["message"] = message
        out.add(f)
    }

    private fun pick(np: Map<String, Any?>, names: List<String>, pred: (Map<String, Any?>) -> Boolean): List<String> {
        val out = ArrayList<String>()
        for (k in names) if (pred(J.m(np[k]))) out.add(k)
        return out
    }

    private fun tags(q: Map<String, Any?>): List<Any?> = if (q["tags"] is List<*>) J.a(q["tags"]) else emptyList()

    private fun roleStarts(q: Map<String, Any?>, pfx: String): Boolean = q["role"] is String && (q["role"] as String).startsWith(pfx)

    private fun isReadOnly(effects: Any?): Boolean {
        if (effects !is List<*> || effects.isEmpty()) return false
        for (e in effects) if ("read" != e) return false
        return true
    }

    private fun u8(s: String): Int = Json.utf8(s).size

    private fun groupOf(grp: List<String>, verb: String): String? {
        for (p in grp) if (lastSeg(verb).startsWith(p)) return p
        return null
    }

    /**
     * Lint a pack's defs (raw values, so a malformed one is still reported). `opts`: {customTraits?, stability?, ns?}; `attestationVerified`
     * is the registry layer's signature check (null: an attestation needs a `sig` member to count). Findings are sorted by verb, rule, param, message.
     */
    fun lintDefs(raw: List<*>, opts: Map<String, Any?>?, attestationVerified: ((Map<String, Any?>) -> Boolean)?): MutableList<Any?> {
        val out = ArrayList<MutableMap<String, Any?>>()
        var reg: Map<String, Map<String, Any?>> = Actions.CORE_REGISTRY
        val custom = opts?.get("customTraits")
        if (custom is List<*> && custom.isNotEmpty()) {
            try {
                reg = Actions.extendRegistry(Actions.CORE_REGISTRY, custom)
            } catch (e: RuntimeException) {
                add(out, "LD-007", null, "invalid custom traits: " + e.message, null)
            }
        }
        val defs = ArrayList<MutableMap<String, Any?>>()
        for (x in raw) {
            val verb: String? = if (x is Map<*, *> && J.m(x)["verb"] is String) J.m(x)["verb"] as String else null
            val vocab = vocabularyIssues(x, reg)
            if (vocab.isNotEmpty()) { for (v in vocab) add(out, "LD-007", verb, v, null); continue }
            val bad = Actions.validateDef(x)
            if (bad != null) { add(out, STRUCTURE_RULE[0], verb, bad, null); continue }
            defs.add(J.m(x))
        }
        val byVerb = HashMap<String, MutableMap<String, Any?>>()
        val names = HashMap<String, String>()
        for (d in defs) {
            if (byVerb.containsKey(d["verb"] as String)) add(out, "LD-009", d["verb"] as String, "verb '" + d["verb"] + "' is defined twice", null)
            byVerb[d["verb"] as String] = d
        }
        for (d in defs) {
            val ns = ArrayList<Any?>()
            ns.add(d["verb"])
            if (d["aliases"] is List<*>) ns.addAll(J.a(d["aliases"]))
            for (nO in ns) {
                val n = nO as String
                val owner = names[n]
                if (owner != null && owner != d["verb"]) add(out, "LD-009", d["verb"] as String, "'$n' is also a name of '$owner'", null)
                else if (!names.containsKey(n)) names[n] = d["verb"] as String
            }
        }
        val bound = HashMap<String, String>()
        for (d in defs) {
            for (k in bindingKeys(d)) {
                val owner = bound[k]
                if (owner != null && owner != d["verb"]) add(out, "LD-014", d["verb"] as String, "binding $k is also bound by '$owner'", null)
                else bound[k] = d["verb"] as String
            }
        }
        for (grp in NAME_GROUPS) {
            val used = LinkedHashMap<String, Int>()
            for (d in defs) {
                val g = groupOf(grp, d["verb"] as String)
                if (g != null) used[g] = (used[g] ?: 0) + 1
            }
            if (used.size > 1) {
                val es = ArrayList<Map.Entry<String, Int>>(used.entries)
                es.sortWith { a, b -> if (a.value != b.value) b.value.compareTo(a.value) else a.key.compareTo(b.key) }
                val win = es[0].key
                for (d in defs) {
                    val g = groupOf(grp, d["verb"] as String)
                    if (g != null && g != win) add(out, "LW-008", d["verb"] as String, "uses '$g' where its siblings use '$win'", null)
                }
            }
        }
        val fileNs = opts?.get("ns") as String?
        if (fileNs != null) for (d in defs) {
            val first = (d["verb"] as String).split(".")[0]
            if (first != fileNs) add(out, "LW-008", d["verb"] as String, "verb namespace '$first' differs from the file namespace '$fileNs'", null)
        }

        for (d in defs) lintOne(out, d, J.m(Actions.normalize(d)), reg, byVerb, opts, attestationVerified)

        out.sortWith { a, b ->
            var c = cmp(a["verb"] as String?, b["verb"] as String?)
            if (c == 0) c = cmp(a["rule"] as String?, b["rule"] as String?)
            if (c == 0) c = cmp(a["param"] as String?, b["param"] as String?)
            if (c == 0) c = cmp(a["message"] as String?, b["message"] as String?)
            c
        }
        return ArrayList<Any?>(out)
    }

    private fun cmp(a: String?, b: String?): Int = (a ?: "").compareTo(b ?: "")

    private fun lintOne(
        out: MutableList<MutableMap<String, Any?>>,
        d: Map<String, Any?>,
        n: Map<String, Any?>,
        reg: Map<String, Map<String, Any?>>,
        byVerb: Map<String, Map<String, Any?>>,
        opts: Map<String, Any?>?,
        att: ((Map<String, Any?>) -> Boolean)?,
    ) {
        val verb = d["verb"] as String
        val np = J.m(n["params"])
        val pn = ArrayList<String>(TreeSet(np.keys))
        val eff = ActionEffective.effective(d, reg, att)
        val hint = J.m(eff["hint"])
        val tset = HashSet<Any?>(J.a(hint["traits"]))
        val cl = HashSet<Any?>(J.a(hint["closure"]))
        val effects = J.a(d["effects"])
        val last = lastSeg(verb)
        val idem = J.m(n["idempotency"])

        if (DESTROY_RE.matcher(last).find() && !effects.contains("delete")) add(out, "LD-001", verb, "the verb says '$last' but effects do not include delete", null)
        for (k in pick(np, pn) { q -> "money.amount" == q["role"] || "money.fee" == q["role"] }) {
            val u = J.m(np[k])["unit"]
            if (u == null || "money" != J.get(u, "kind")) add(out, "LD-002", verb, "a money parameter needs a unit of kind money with a currency", k)
            else if (J.get(u, "ccy") !is String) {
                val from = J.get(J.get(u, "ccy"), "from") as String?
                val c = if (from != null) np[from] else null
                if (c == null || "money.currency" != J.get(c, "role") || "iso_currency" != J.get(c, "format")) add(out, "LD-002", verb, "the currency parameter '$from' needs role money.currency and format iso_currency", k)
            }
        }
        for (k in pick(np, pn) { q -> "money.currency" == q["role"] }) if ("iso_currency" != J.m(np[k])["format"]) add(out, "LD-002", verb, "a currency parameter needs the iso_currency format", k)
        for (k in pick(np, pn) { q -> "integer" == q["type"] || "duration" == q["type"] }) {
            val q = J.m(np[k])
            if (roleStarts(q, "id.")) continue
            if ("count.limit" == q["role"] && q["max"] != null) continue
            if (q["min"] == null || q["max"] == null) add(out, "LD-003", verb, "a numeric parameter needs both min and max (has " + (if (q["min"] == null) "no min" else "min") + ", " + (if (q["max"] == null) "no max" else "max") + ")", k)
        }
        if ((effects.contains("pay") || tset.contains("pca.money_moving")) && "none" == idem["mode"]) add(out, "LD-004", verb, "a money-moving action needs idempotency key_param or natural", null)
        val pii = pick(np, pn) { q -> tags(q).contains("pii") || roleStarts(q, "contact.") || roleStarts(q, "person.") }
        if (pii.isNotEmpty()) {
            val expected = TreeSet<String>()
            if (d["side_effects"] is List<*>) for (s in J.a(d["side_effects"])) {
                val k = J.get(s, "kind")
                if ("send" == k || "export" == k) expected.add(k as String)
            }
            if (SEND_RE.matcher(last).find()) expected.add("send")
            if (EXPORT_RE.matcher(last).find()) expected.add("export")
            for (e in expected) if (!effects.contains(e)) add(out, "LD-005", verb, "personal data can " + (if (e == "send") "be sent" else "be exported") + " (" + pii.joinToString(", ") + ") but effects do not include " + e, null)
        }
        for (c in J.a(eff["clamps"])) add(out, "LD-006", verb, "declared " + (if ("rev" == J.get(c, "field")) "reversibility" else "blast") + " " + J.jsStr(J.get(c, "declared")) + " is below the floor " + J.jsStr(J.get(c, "floor")), null)
        val res = J.m(n["resource"])
        if ("*" == res["id"] && "one" == res["scope"]) add(out, "LD-008", verb, "resource id '*' with scope one names every resource at once", null)
        if (!isReadOnly(effects) && ActionUndo.mayBeReversible(d)) {
            val comp = d["compensates"]
            if (comp == null) add(out, "LD-010", verb, "a write declared reversible must name its compensating action (compensates)", null)
            else if (comp !is String || !byVerb.containsKey(comp)) add(out, "LD-010", verb, "compensates '$comp', which is not in the pack", null)
            else {
                val s = ActionUndo.compensationShape(d, byVerb[comp]!!)
                if (true != s["ok"]) add(out, "LD-010", verb, "compensates '$comp', which cannot undo it: " + s["reason"], null)
            }
        }
        val review = J.m(d["review"])
        if ("confirmed" == review["state"]) {
            val a = review["attestation"]
            if (a == null) add(out, "LD-011", verb, "confirmed without an attestation", null)
            else if (Actions.defDigest(d) != J.get(a, "def_digest")) add(out, "LD-011", verb, "the attestation covers a different digest of this def", null)
            else if (Actions.traitsDigest(reg) != J.get(a, "traits_digest")) add(out, "LD-011", verb, "the attestation was made against a different trait registry", null)
            else if (if (att != null) !att(d) else !J.has(a, "sig")) add(out, "LD-011", verb, "the attestation is not signed by a pinned reviewer", null)
        }
        val dismissed = HashSet<Any?>()
        if ("confirmed" == review["state"] && J.get(review["attestation"], "dismissed") is List<*>) for (x in J.a(J.get(review["attestation"], "dismissed"))) dismissed.add(J.get(x, "trait"))
        val prov = review["provenance"]
        if (prov != null && J.get(prov, "union") is List<*>) for (t in J.a(J.get(prov, "union"))) if (!cl.contains(t) && !dismissed.contains(t)) add(out, "LD-011", verb, "the union-added trait $t was removed without a signed dismissal", null)
        for (r in ActionEffective.prulesViolations(d, strs(J.m(hint["eff"])["prules"]))) if (!OWN_RULES.contains(r)) add(out, "LD-012", verb, "structural rule $r is required by the action's traits and violated", null)
        if (isReadOnly(effects)) {
            val enforced = d["context"] is List<*> && J.a(d["context"]).contains("sandbox_attested")
            for (k in pick(np, pn) { q -> "code.command" == q["role"] || "query.sql" == q["role"] }) if (!enforced) add(out, "LD-013", verb, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k)
            for (k in pick(np, pn) { q -> tags(q).contains("credential") }) add(out, "LD-013", verb, "a read-only action handles a credential", k)
        }

        val desc = d["description"]
        if (desc == null) add(out, "LW-001", verb, "description is missing", null)
        else if (u8(desc as String) > 400) add(out, "LW-001", verb, "description is longer than 400 bytes", null)
        val title = d["title"] as String
        val first = firstWord(title).lowercase(Locale.ROOT)
        val sEnd = first.length >= 2 && first.endsWith("s") && first[first.length - 2] != 's'
        if (first.endsWith("ing") || first.endsWith("ed") || (sEnd && !(first.endsWith("us") || first.endsWith("is"))) || listOf("a", "an", "the").contains(first)) add(out, "LW-001", verb, "title '$title' is not imperative", null)
        for (k in pick(np, pn) { q -> "string" == q["type"] && q["max_len"] == null && q["values"] == null }) add(out, "LW-002", verb, "a string parameter without max_len (the default is 1024; say it)", k)
        if (cl.contains("pca.external_communication")) {
            for (k in pick(np, pn) { q -> "string" == q["type"] && q["values"] == null && q["format"] == null && (q["role"] == null || roleStarts(q, "text.")) && !tags(q).contains("free_text_outbound") }) {
                if (k == idem["param"]) continue
                add(out, "LW-003", verb, "free text flows into an outbound action without tags: [free_text_outbound]", k)
            }
        }
        val stability = opts?.get("stability") as String?
        if ("stable" == stability && ("unreviewed" == review["state"] || "suggested" == review["state"])) add(out, "LW-004", verb, "a " + review["state"] + " def in a stable pack", null)
        val dis = if (review["attestation"] == null) null else J.get(review["attestation"], "dismissed")
        if (dis is List<*>) for (x in dis) if (J.jsTrim(J.get(x, "reason") as String).length < 5) add(out, "LW-005", verb, "dismissed trait " + J.get(x, "trait") + " has no reason", null)
        for (k in pick(np, pn) { q -> "array" == q["type"] && q["max_items"] == null }) add(out, "LW-006", verb, "an array parameter without max_items", k)
        for (k in pick(np, pn) { q -> isCritical(q) && q["provenance_min"] == null }) add(out, "LW-007", verb, "a critical parameter without provenance_min", k)
        val exNone = d["examples"] !is List<*> || J.a(d["examples"]).isEmpty()
        if ((tset.contains("pca.money_moving") || tset.contains("pca.destructive") || tset.contains("pca.privilege_change")) && exNone) add(out, "LW-009", verb, "no example for a money-moving, destructive or privilege-changing action", null)
        if (d["since"] == null) add(out, "LW-010", verb, "since is missing", null)
    }

    private fun strs(xs: Any?): List<String> {
        val l = ArrayList<String>()
        for (x in J.a(xs)) l.add(x as String)
        return l
    }

    /** The first whitespace-separated token of a title (`title.split(/\s+/)[0]`: empty when the title starts with white space). */
    private fun firstWord(t: String): String {
        var i = 0
        while (i < t.length && !J.jsSpace(t[i])) i++
        return t.substring(0, i)
    }

    /** Does the run fail? Errors always; warnings under `strict`. */
    fun lintFails(fs: List<*>, strict: Boolean): Boolean {
        for (f in fs) {
            val s = J.get(f, "severity")
            if ("error" == s || (strict && "warning" == s)) return true
        }
        return false
    }

    /** Plain text, one line per finding. */
    fun lintText(fs: List<*>): String {
        if (fs.isEmpty()) return "0 errors, 0 warnings"
        var e = 0
        var w = 0
        for (f in fs) {
            val s = J.get(f, "severity")
            if ("error" == s) e++ else if ("warning" == s) w++
        }
        val lines = ArrayList<String>()
        for (f in fs) {
            val file = J.get(f, "file")
            val verb = J.get(f, "verb")
            val param = J.get(f, "param")
            val hasFile = file != null && "" != file
            val hasVerb = verb != null && "" != verb
            val hasParam = param != null && "" != param
            val loc = if (hasFile) J.jsStr(file) + (if (J.get(f, "line") != null) ":" + J.jsStr(J.get(f, "line")) + ":" + (if (J.get(f, "column") != null) J.jsStr(J.get(f, "column")) else "1") else "") + ": " else ""
            lines.add(
                J.jsStr(J.get(f, "severity")).padEnd(7) + " " + J.jsStr(J.get(f, "rule")) + "  " + loc + (if (hasVerb) J.jsStr(verb) else "") + (if (hasParam) " [" + J.jsStr(param) + "]" else "") +
                    (if (hasVerb || hasParam) ": " else "") + J.jsStr(J.get(f, "message")),
            )
        }
        val notes = fs.size - e - w
        return lines.joinToString("\n") + "\n" + e + " error" + (if (e == 1) "" else "s") + ", " + w + " warning" + (if (w == 1) "" else "s") + (if (notes > 0) ", " + notes + " note" + (if (notes == 1) "" else "s") else "")
    }

    private fun level(s: String?): String = if ("error" == s) "error" else if ("warning" == s) "warning" else "note"

    /** SARIF 2.1.0 so findings appear as pull request annotations. `tool`: {name?, version?}. */
    fun toSarif(fs: List<*>, tool: Map<String, Any?>?): MutableMap<String, Any?> {
        val rules = ArrayList<Array<String>>()
        rules.add(STRUCTURE_RULE)
        rules.add(NOTE_RULE)
        rules.addAll(ActionLintRules.LINT_RULES)
        val rs = ArrayList<Any?>()
        for (r in rules) rs.add(J.obj("id", r[0], "shortDescription", J.obj("text", r[2]), "defaultConfiguration", J.obj("level", level(r[1]))))
        val name = tool?.get("name")
        val version = tool?.get("version")
        val driver = J.obj("name", name ?: "pca actions lint")
        if (version != null && "" != version) driver["version"] = version
        driver["rules"] = rs
        val results = ArrayList<Any?>()
        for (f in fs) {
            val file = J.get(f, "file")
            val verb = J.get(f, "verb")
            val param = J.get(f, "param")
            val hasFile = file != null && "" != file
            val hasVerb = verb != null && "" != verb
            val loc = LinkedHashMap<String, Any?>()
            if (hasFile) {
                val pl = J.obj("artifactLocation", J.obj("uri", file))
                if (J.get(f, "line") != null) pl["region"] = J.obj("startLine", J.get(f, "line"), "startColumn", J.get(f, "column") ?: J.n(1))
                loc["physicalLocation"] = pl
            }
            if (hasVerb) loc["logicalLocations"] = J.list(J.obj("name", verb, "kind", "member"))
            val text = (if (hasVerb) J.jsStr(verb) + (if (param != null && "" != param) " [" + J.jsStr(param) + "]" else "") + ": " else "") + J.jsStr(J.get(f, "message"))
            results.add(J.obj("ruleId", J.get(f, "rule"), "level", level(J.get(f, "severity") as String?), "message", J.obj("text", text), "locations", J.list(loc)))
        }
        return J.obj("\$schema", "https://json.schemastore.org/sarif-2.1.0.json", "version", "2.1.0", "runs", J.list(J.obj("tool", J.obj("driver", driver), "results", results)))
    }
}
