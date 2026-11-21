package net.atlasauth.pca.actions

import java.util.Locale
import java.util.TreeMap
import java.util.TreeSet
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions

/**
 * Everything an action def yields: the signed schema verb (v2) and document, the operation binding, risk inputs, policy predicates,
 * Goal IR ontology terms, the policy card, the escalation tier and MCP annotations. Pure and deterministic.
 */
@Suppress("UNCHECKED_CAST")
object ActionDerive {
    const val MAX_PARAM_PATH_DEPTH = 3
    val ESC_TIERS: List<String> = listOf("auto", "confirm", "cosign", "stepup")
    val RISK_NAMES: List<String> = listOf("low", "elevated", "high", "critical")

    /** Reversibility score per effective class (1 = fully reversible). */
    val REVERSIBILITY_SCORE: Map<String, Double> = linkedMapOf("reversible" to 1.0, "rate_limited" to 0.4, "irreversible" to 0.0)

    private fun isReadOnly(effects: Any?): Boolean {
        if (effects !is List<*> || effects.isEmpty()) return false
        for (e in effects) if ("read" != e) return false
        return true
    }

    // ---- flattened params ----

    private fun walk(out: MutableMap<String, Any?>, prefix: String, depth: Int, v: Any?) {
        if (v is Map<*, *> && depth < MAX_PARAM_PATH_DEPTH && v.isNotEmpty()) {
            for ((k, x) in J.m(v)) walk(out, if (prefix.isEmpty()) k else "$prefix.$k", depth + 1, x)
        } else out[prefix] = v
    }

    /** Nested plain objects become dotted keys (up to [MAX_PARAM_PATH_DEPTH] segments); arrays and scalars are leaves. */
    fun flattenParams(params: Map<String, Any?>): MutableMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in params) walk(out, k, 1, v)
        return out
    }

    /** The unique param carrying `role`, or throws `no_param` / `ambiguous_param`. */
    fun paramByRole(d: Map<String, Any?>, role: String): String {
        val hits = TreeSet<String>()
        for ((k, v) in J.m(d["params"])) if (role == J.get(v, "role")) hits.add(k)
        if (hits.isEmpty()) throw ActionKitError("no_param", "'" + d["verb"] + "' has no parameter with role " + role)
        if (hits.size > 1) throw ActionKitError("ambiguous_param", "'" + d["verb"] + "' has several parameters with role " + role)
        return hits.first()
    }

    /** read if effects = {read}; irreversible if so declared; external_send if effects meet {send, publish, export}; else reversible. */
    fun effectClass(d: Map<String, Any?>): String {
        val n = Actions.normalize(d)
        if (isReadOnly(n["effects"])) return "read"
        if ("irreversible" == Actions.worstReversibility(n["reversibility"], n["params"] as Map<String, Map<String, Any?>>)) return "irreversible"
        for (e in J.a(n["effects"])) if ("send" == e || "publish" == e || "export" == e) return "external_send"
        return "reversible"
    }

    // ---- signed schema (v2) ----

    private fun unitId(p: Map<String, Any?>): String? {
        val u = p["unit"] ?: return null
        if ("money" != J.get(u, "kind")) return J.get(u, "kind") as String?
        val c = J.get(u, "ccy")
        return if (c is String) "money." + c.lowercase(Locale.ROOT) else null
    }

    private fun unitDecl(p: Map<String, Any?>): MutableMap<String, Any?> {
        val u = p["unit"]
        if ("money" != J.get(u, "kind")) return J.obj("kind", J.get(u, "kind"))
        val m = J.obj("kind", "money", "currency", J.get(u, "ccy"))
        if (J.has(u, "exp")) m["exponent"] = J.get(u, "exp")
        return m
    }

    private fun toParamDecl(n: Map<String, Any?>): MutableMap<String, Any?> {
        val d = J.obj("type", n["type"], "semantic", n["role"] ?: ("generic." + n["type"]), "sensitivity", n["sensitivity"])
        if (true != n["required"]) d["required"] = false
        if (n.containsKey("values")) d["values"] = ArrayList(J.a(n["values"]))
        for (k in arrayOf("min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description")) {
            if (n.containsKey(k)) d[k] = n[k]
        }
        val uid = unitId(n)
        if (uid != null) d["unit"] = uid
        if (n.containsKey("accumulates")) d["accumulates_into"] = ArrayList(J.a(n["accumulates"]))
        if (n.containsKey("role")) d["role"] = n["role"]
        if (n.containsKey("tags")) d["tags"] = ArrayList(J.a(n["tags"]))
        return d
    }

    /** The signed v2 verb declaration of a def and the unit entries it needs: `{verb, units}`. */
    fun toSchemaVerb(
        d: Map<String, Any?>,
        reg: Map<String, Map<String, Any?>>,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val n = Actions.normalize(d)
        val eff = ActionEffective.effective(d, reg, attestationVerified)
        val params = LinkedHashMap<String, Any?>()
        val units = LinkedHashMap<String, Any?>()
        for ((k, pv) in J.m(n["params"])) {
            val p = J.m(pv)
            params["action.params.$k"] = toParamDecl(p)
            val id = unitId(p)
            if (id != null) units[id] = unitDecl(p)
        }
        val v = J.obj(
            "verb", n["verb"], "kind", if (isReadOnly(n["effects"])) "read" else "write", "params", params, "effects", ArrayList(J.a(n["effects"])),
            "traits", eff["traits"], "def", Actions.defDigest(d), "floors", eff["eff"],
        )
        val att = J.get(d["review"], "attestation")
        if (true == eff["confirmed"] && att is Map<*, *> && att["sig"] != null) v["confirmation"] = att
        val rev = n["reversibility"]
        if (rev is String) v["reversibility"] = rev
        else {
            val rb = J.obj("param", "action.params." + J.get(rev, "by"), "map", LinkedHashMap(J.m(J.get(rev, "map"))))
            if (J.get(rev, "default") != null) rb["default"] = J.get(rev, "default")
            v["reversibility_by"] = rb
        }
        val b = n["bindings"]
        if (J.get(b, "mcp") != null) v["mcp"] = J.obj("tool", J.get(J.get(b, "mcp"), "tool"))
        if (J.get(b, "openapi") != null) v["openapi"] = J.obj("operationId", J.get(J.get(b, "openapi"), "operationId"))
        if (n.containsKey("description")) v["description"] = n["description"]
        return J.obj("verb", v, "units", units)
    }

    /** The unsigned v2 schema document of a set of defs (verbs sorted by name; units merged, a conflicting redefinition refused). `meta`: {site, aud, version, pack?}. */
    fun toSchemaDoc(
        defs: List<*>,
        reg: Map<String, Map<String, Any?>>,
        meta: Map<String, Any?>,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val verbs = ArrayList<Any?>()
        val units = LinkedHashMap<String, Any?>()
        val seen = HashSet<String>()
        val sorted = ArrayList<Any?>(defs)
        sorted.sortWith { a, b -> (J.get(a, "verb") as String).compareTo(J.get(b, "verb") as String) }
        for (d in sorted) {
            val verb = J.get(d, "verb") as String
            if (!seen.add(verb)) throw ActionKitError("duplicate_verb", "verb '$verb' appears twice")
            val o = toSchemaVerb(J.m(d), reg, attestationVerified)
            verbs.add(o["verb"])
            for ((uk, u) in J.m(o["units"])) {
                val prev = units[uk]
                if (prev != null && !(J.get(prev, "kind") == J.get(u, "kind") && J.get(prev, "currency") == J.get(u, "currency") && J.sameJsonMember(prev, u, "exponent"))) {
                    throw ActionKitError("unit_conflict", "unit '$uk' is declared with two different definitions")
                }
                units[uk] = u
            }
        }
        val custom = TreeMap<String, Map<String, Any?>>()
        for (t in reg.values) if (!(t["id"] as String).startsWith("pca.")) custom[t["id"] as String] = t
        val doc = J.obj("v", J.n(2), "kind", "pca-action-schema", "site", meta["site"], "aud", meta["aud"], "version", meta["version"])
        if (units.isNotEmpty()) doc["units"] = units
        doc["verbs"] = verbs
        doc["traits_digest"] = Actions.traitsDigest(reg)
        if (custom.isNotEmpty()) {
            val td = ArrayList<Any?>()
            for (t in custom.values) td.add(J.obj("id", t["id"], "implies", ArrayList<Any?>(t["implies"] as List<*>), "floor", t["floor"], "card_phrase", t["card_phrase"]))
            doc["trait_defs"] = td
        }
        if (meta["pack"] != null) doc["pack"] = meta["pack"]
        return doc
    }

    // ---- operation binding ----

    /** The PcaOperation of a call to this def: `{ok: true, op: {verb, resource, params}}` or `{ok: false, reason}`. `callParams` are the call's params. */
    fun operationOf(d: Map<String, Any?>, callParams: Map<String, Any?>): MutableMap<String, Any?> {
        val flat = flattenParams(callParams)
        val dp = J.m(d["params"])
        val declared = ArrayList<String>(TreeSet(dp.keys))
        val params = LinkedHashMap<String, Any?>()
        for (k in declared) if (flat.containsKey(k)) params[k] = flat[k]
        val res = J.m(d["resource"])
        val type = res["type"] as String
        val id = res["id"]
        val scope = res["scope"] as String?
        val resource: String
        if ("*" != id && J.has(id, "exact")) resource = type + ":" + J.get(id, "exact")
        else {
            var idParam: String? = null
            for (n in declared) if (("id.$type") == J.get(dp[n], "role")) { idParam = n; break }
            val v = if (idParam != null) params[idParam] else null
            if (v is String) {
                if (!ActionIdPattern.idMatches(id, v)) return J.obj("ok", false, "reason", "the id '" + v + "' does not match the resource pattern of " + d["verb"])
                resource = "$type:$v"
            } else if ("one" != scope) resource = "$type:*"
            else return J.obj("ok", false, "reason", d["verb"].toString() + " needs a parameter with role id." + type + " to name its resource")
        }
        return J.obj("ok", true, "op", J.obj("verb", d["verb"], "resource", resource, "params", params))
    }

    // ---- risk ----

    private fun unit01(x: Double): Double = Math.min(1.0, Math.max(0.0, x))

    /** Risk inputs for a call. `eff` is an [ActionEffective.effective] result; `params` the call's params (or null); `opts` {kappa?, taint?}. */
    fun riskOf(d: Map<String, Any?>, eff: Map<String, Any?>, params: Map<String, Any?>?, opts: Map<String, Any?>?): MutableMap<String, Any?> {
        val e = J.m(eff["eff"])
        var blast = unit01(J.num(e["blast_ppm"])!! / 1_000_000)
        val money = TreeSet<String>()
        for ((k, v) in J.m(d["params"])) if ("money.amount" == J.get(v, "role")) money.add(k)
        if (money.isNotEmpty()) {
            val flat: Map<String, Any?> = if (params != null) flattenParams(params) else LinkedHashMap()
            val amount = flat[money.first()]
            val kappa = opts?.get("kappa")
            val a = J.num(amount)
            val k = J.num(kappa)
            val ok = amount != null && amount !is String && a != null && !a.isNaN() && !a.isInfinite() && a >= 0 && k != null && k > 0
            blast = if (ok) unit01(a!! / k!!) else 1.0
        }
        val out = J.obj("reversibility", REVERSIBILITY_SCORE[e["rev"] as String], "blastRadius", blast, "confidence", J.n(1))
        val td = J.num(opts?.get("taint"))
        if (td != null && !td.isNaN() && !td.isInfinite()) out["taint"] = unit01(td)
        return out
    }

    // ---- predicates ----

    /** The resource matcher of a def's pattern (`<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`). */
    fun resourceMatcher(d: Map<String, Any?>): String {
        val r = J.m(d["resource"])
        val id = r["id"]
        val type = r["type"].toString()
        if ("*" == id) return "$type:*"
        return if (J.has(id, "exact")) type + ":" + J.get(id, "exact") else type + ":" + J.get(id, "prefix") + "*"
    }

    /** The policy predicate scaffold; `limits.max_amount` adds a per-call ceiling on the `money.amount` parameter (a def with none throws). */
    fun predicatesOf(d: Map<String, Any?>, limits: Map<String, Any?>?): MutableMap<String, Any?> {
        val out = J.obj("verb", d["verb"], "resource", resourceMatcher(d))
        if (limits != null && limits.containsKey("max_amount")) {
            val m = limits["max_amount"]
            if (!J.isInt(m) || J.num(m)!! < 0) throw ActionKitError("bad_limit", "max_amount must be a non-negative safe integer")
            val name = paramByRole(d, "money.amount")
            out["where"] = J.list(J.obj("field", "action.params.$name", "op", "lte", "value", m), J.obj("field", "action.params.$name", "op", "gte", "value", J.n(0)))
        }
        return out
    }

    // ---- Goal IR ontology terms ----

    private fun sorted(vals: Any?): MutableList<Any?> {
        val l = ArrayList<String>()
        for (x in J.a(vals)) l.add(x as String)
        l.sort()
        return ArrayList<Any?>(l)
    }

    private fun ontParam(d: Map<String, Any?>, p: Map<String, Any?>): MutableMap<String, Any?> {
        val u = p["unit"]
        if (u != null) {
            val kind = J.get(u, "kind")
            if ("money" == kind) {
                val c = J.get(u, "ccy")
                if (c is String) return J.obj("kind", "money", "ccys", J.list(c))
                val from = J.get(c, "from") as String?
                val cp = if (from != null) J.get(J.m(d["params"]), from) else null
                val vals = J.get(cp, "values")
                return J.obj("kind", "money", "ccys", if (vals != null) sorted(vals) else ArrayList<Any?>())
            }
            return J.obj("kind", if ("duration" == kind) "duration" else if ("bytes" == kind) "bytes" else if ("ratio" == kind) "ratio" else "count")
        }
        val role = p["role"]
        val format = p["format"]
        if (role is String && role.startsWith("id.")) return J.obj("kind", "id", "of", role.substring(3))
        if (format is String && format.startsWith("id:")) return J.obj("kind", "id", "of", format.substring(3))
        return when (p["type"] as String) {
            "duration" -> J.obj("kind", "duration")
            "datetime", "date" -> J.obj("kind", "instant")
            "integer" -> J.obj("kind", "count")
            "boolean" -> J.obj("kind", "enum", "values", J.list("false", "true"))
            "set" -> J.obj("kind", "enum", "values", sorted(p["values"] ?: ArrayList<Any?>()))
            "string" -> if (p["values"] != null) J.obj("kind", "enum", "values", sorted(p["values"])) else J.obj("kind", "text")
            else -> J.obj("kind", "text")
        }
    }

    /** Ontology terms for a set of defs; the effect class is DERIVED ([effectClass]). */
    fun toOntology(
        defs: List<*>,
        reg: Map<String, Map<String, Any?>>,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val types = LinkedHashMap<String, String>()
        val units = LinkedHashMap<String, Any?>()
        val aliases = LinkedHashMap<String, Any?>()
        val traits = LinkedHashMap<String, Any?>()
        val verbs = ArrayList<Any?>()
        val sortedDefs = ArrayList<Any?>(defs)
        sortedDefs.sortWith { a, b -> (J.get(a, "verb") as String).compareTo(J.get(b, "verb") as String) }
        for (dO in sortedDefs) {
            val d = J.m(dO)
            val res = J.m(d["resource"])
            val id = res["id"]
            val prefix = if ("*" == id || J.has(id, "exact")) "" else J.get(id, "prefix") as String
            if (!types.containsKey(res["type"] as String)) types[res["type"] as String] = prefix
            val params = LinkedHashMap<String, Any?>()
            val dp = J.m(d["params"])
            for (name in TreeSet(dp.keys)) {
                params[name] = ontParam(d, J.m(dp[name]))
                val u = J.get(dp[name], "unit")
                if (u != null && "money" == J.get(u, "kind") && J.get(u, "ccy") is String) {
                    val m = J.obj("kind", "money")
                    if (J.has(u, "exp")) m["exponent"] = J.get(u, "exp")
                    units[J.get(u, "ccy") as String] = m
                } else if (u != null && "money" != J.get(u, "kind")) units[J.get(u, "kind") as String] = J.obj("kind", J.get(u, "kind"))
            }
            verbs.add(J.obj("id", d["verb"], "effect", effectClass(d), "resource_type", res["type"], "params", params))
            if (d["aliases"] != null) for (a in J.a(d["aliases"])) {
                val al = a as String
                if (aliases.containsKey(al) && aliases[al] != d["verb"]) throw ActionKitError("alias_collision", "alias '$al' names two verbs")
                aliases[al] = d["verb"]
            }
            traits[d["verb"] as String] = ActionEffective.effective(d, reg, attestationVerified)["traits"]
        }
        val tl = ArrayList<Any?>()
        for ((k, v) in types) tl.add(J.obj("id", k, "id_prefix", v))
        return J.obj("types", tl, "units", units, "verbs", verbs, "aliases", aliases, "traits", traits)
    }

    // ---- policy card + escalation + MCP annotations ----

    private fun sentence(s: String): String = if (s.isNotEmpty() && ".!?".indexOf(s[s.length - 1]) >= 0) s else "$s."

    private fun joinList(xs: List<String>): String {
        if (xs.size <= 1) return if (xs.isEmpty()) "" else xs[0]
        return xs.subList(0, xs.size - 1).joinToString(", ") + " and " + xs[xs.size - 1]
    }

    /** The policy card of a def: deterministic text from its title and the phrases of its trait closure (riskiest first). */
    fun cardOf(d: Map<String, Any?>, eff: Map<String, Any?>, reg: Map<String, Map<String, Any?>>): MutableMap<String, Any?> {
        val ordered = ArrayList<Map<String, Any?>>()
        for (id in Actions.closure(reg, J.a(eff["traits"]))) ordered.add(reg[id]!!)
        ordered.sortWith { a, b ->
            val ra = J.num(J.m(a["floor"])["risk"])!!.toInt()
            val rb = J.num(J.m(b["floor"])["risk"])!!.toInt()
            if (rb != ra) rb.compareTo(ra) else (a["id"] as String).compareTo(b["id"] as String)
        }
        val phrases = ArrayList<String>(LinkedHashSet(ordered.map { it["card_phrase"] as String }))
        val e = J.m(eff["eff"])
        val title = d["title"] as String
        val text = sentence(title) + " " + (if (true == eff["confirmed"])
            (if (phrases.isNotEmpty()) "This action " + joinList(phrases) + "." else "This action only reads.")
        else
            "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it " + joinList(phrases) + ".")
        return J.obj(
            "verb", d["verb"], "title", title, "text", text, "risk", RISK_NAMES[J.num(e["risk"])!!.toInt()], "escalation", ESC_TIERS[J.num(e["esc"])!!.toInt()],
            "reversibility", e["rev"], "blast_ppm", e["blast_ppm"], "needs", ArrayList(J.a(e["caveats"])), "context", ArrayList(J.a(e["context"])),
        )
    }

    /** The minimum escalation tier of the effective profile: `{tier, name}`. */
    fun escalationOf(eff: Map<String, Any?>): MutableMap<String, Any?> {
        val t = J.num(J.m(eff["eff"])["esc"])!!.toInt()
        return J.obj("tier", J.n(t.toLong()), "name", ESC_TIERS[t])
    }

    /** Advisory MCP tool annotations (read-only / destructive / idempotent / open-world). */
    fun mcpAnnotationsOf(d: Map<String, Any?>, eff: Map<String, Any?>): MutableMap<String, Any?> {
        val cl = J.a(eff["closure"])
        val confirmed = true == eff["confirmed"]
        val ro = isReadOnly(d["effects"])
        val mode = J.get(d["idempotency"], "mode")
        val idem = mode != null && "none" != mode
        return J.obj(
            "readOnlyHint", confirmed && ro, "destructiveHint", cl.contains("pca.destructive"), "idempotentHint", confirmed && (idem || ro),
            "openWorldHint", cl.contains("pca.network_egress") || cl.contains("pca.external_communication"),
        )
    }
}
