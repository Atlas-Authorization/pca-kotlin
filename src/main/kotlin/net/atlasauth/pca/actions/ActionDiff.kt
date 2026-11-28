package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions

/** The few action-kit helpers the diff ports need that the core keeps private (same tables and rules as the core). */
internal object ActionDiffSupport {
    private val REV_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "irreversible" to 2)
    private val SENSITIVITY_RANK = mapOf("free" to 0, "material" to 1, "critical" to 2)
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

    /** The reversibility rank (reversible 0, rate_limited 1, irreversible 2). */
    fun revRank(r: String): Int = REV_RANK[r]!!

    /** The sensitivity floor a core role implies (null when the role has none). */
    fun roleSensitivityFloor(role: String): String? = ROLE_SENSITIVITY_FLOOR[role]

    private fun maxSens(a: String, b: String): String = if (SENSITIVITY_RANK[a]!! >= SENSITIVITY_RANK[b]!!) a else b

    /** A parameter's sensitivity after the role and tag floors. */
    fun effectiveParamSensitivity(p: Map<String, Any?>): String {
        var f = "free"
        val role = p["role"]
        if (role is String && ROLE_SENSITIVITY_FLOOR.containsKey(role)) f = maxSens(f, ROLE_SENSITIVITY_FLOOR[role]!!)
        val tags = p["tags"]
        if (tags is List<*>) for (t in tags) if (t is String && TAG_SENSITIVITY_FLOOR.containsKey(t)) f = maxSens(f, TAG_SENSITIVITY_FLOOR[t]!!)
        return maxSens((p["sensitivity"] as String?) ?: "free", f)
    }

    /** `list.indexOf(v)` for a JSON value that may not be a string (-1). */
    fun indexIn(list: List<String>, v: Any?): Int = if (v is String) list.indexOf(v) else -1
}

/**
 * The semantic diff of two versions of one action def: is the NEW definition no more permissive than the OLD one? Classes: equal (only
 * text differs), narrow (every call the new def accepts is accepted by the old one and every old restriction still holds), widen, and
 * incomparable (one dimension widens while another narrows, or the change has no order). Conservative: a def that cannot be ordered
 * is incomparable, never narrow. Only equal and narrow let a pin follow the change without the principal.
 */
@Suppress("UNCHECKED_CAST")
object ActionDiff {
    private const val DEFAULT_MAX_LEN = 1024.0
    private const val DEFAULT_MAX_ITEMS = 64.0
    private const val INF = Double.POSITIVE_INFINITY
    private val PROVENANCE = listOf("first_party", "tool", "agent")
    private val SENSITIVITY = listOf("free", "material", "critical")

    private enum class Rel { EQ, NARROW, WIDEN, INC }

    private fun set(xs: Any?): Set<Any?> = LinkedHashSet<Any?>(if (xs is List<*>) J.a(xs) else emptyList<Any?>())

    private fun setRel(o: Collection<Any?>, n: Collection<Any?>): Rel {
        val os = LinkedHashSet<Any?>(o)
        val ns = LinkedHashSet<Any?>(n)
        var added = false
        var removed = false
        for (x in ns) if (!os.contains(x)) added = true
        for (x in os) if (!ns.contains(x)) removed = true
        return if (added && removed) Rel.INC else if (added) Rel.NARROW else if (removed) Rel.WIDEN else Rel.EQ
    }

    private fun setRel(o: Any?, n: Any?): Rel = setRel(set(o), set(n))

    private fun rankRel(o: Double, n: Double): Rel = if (n == o) Rel.EQ else if (n > o) Rel.NARROW else Rel.WIDEN

    private fun nz(v: Any?, dflt: Double): Double = J.num(v) ?: dflt

    private fun allIn(inner: Any?, outer: Any?): Boolean = J.a(outer).containsAll(J.a(inner))

    /** Is every value of `inner`'s domain also a value of `outer`'s? Same declared type required. Sound, not complete. */
    private fun domainContains(outer: Map<String, Any?>, inner: Map<String, Any?>): Boolean {
        val ot = outer["type"]
        if (ot != inner["type"]) return false
        when (ot as String) {
            "string", "object_ref" -> {
                if (nz(inner["max_len"], DEFAULT_MAX_LEN) > nz(outer["max_len"], DEFAULT_MAX_LEN)) return false
                if (outer["values"] != null && (inner["values"] == null || !allIn(inner["values"], outer["values"]))) return false
                return outer["format"] == null || inner["format"] == outer["format"]
            }
            "integer" -> return nz(inner["min"], -INF) >= nz(outer["min"], -INF) && nz(inner["max"], INF) <= nz(outer["max"], INF)
            "duration" -> return Math.max(nz(inner["min"], 0.0), 0.0) >= Math.max(nz(outer["min"], 0.0), 0.0) && nz(inner["max"], INF) <= nz(outer["max"], INF)
            "set" -> {
                val ov: List<Any?> = if (outer["values"] == null) emptyList() else J.a(outer["values"])
                val iv: List<Any?> = if (inner["values"] == null) emptyList() else J.a(inner["values"])
                if (!ov.containsAll(iv)) return false
                val oMax = Math.min(nz(outer["max_items"], ov.size.toDouble()), ov.size.toDouble())
                val iMax = Math.min(nz(inner["max_items"], iv.size.toDouble()), iv.size.toDouble())
                return nz(inner["min_items"], 0.0) >= nz(outer["min_items"], 0.0) && iMax <= oMax
            }
            "array" -> {
                val oi: Any = outer["items"] ?: "string"
                val ii: Any = inner["items"] ?: "string"
                if (oi != ii) return false
                if (nz(inner["min_items"], 0.0) < nz(outer["min_items"], 0.0) || nz(inner["max_items"], DEFAULT_MAX_ITEMS) > nz(outer["max_items"], DEFAULT_MAX_ITEMS)) return false
                if ("integer" == outer["items"]) return nz(inner["min"], -INF) >= nz(outer["min"], -INF) && nz(inner["max"], INF) <= nz(outer["max"], INF)
                return nz(inner["max_len"], DEFAULT_MAX_LEN) <= nz(outer["max_len"], DEFAULT_MAX_LEN)
            }
            else -> return true
        }
    }

    private fun callsContained(outer: Map<String, Any?>, inner: Map<String, Any?>): Boolean {
        for ((k, v) in inner) {
            val op = outer[k]
            if (op == null || !domainContains(J.m(op), J.m(v))) return false
        }
        for ((k, v) in outer) {
            if (J.get(v, "required") != true) continue
            val ip = inner[k]
            if (ip == null || J.get(ip, "required") != true) return false
        }
        return true
    }

    private fun callSetRel(oldP: Map<String, Any?>, newP: Map<String, Any?>): Rel {
        val sub = callsContained(oldP, newP)
        val sup = callsContained(newP, oldP)
        return if (sub && sup) Rel.EQ else if (sub) Rel.NARROW else if (sup) Rel.WIDEN else Rel.INC
    }

    private fun provRank(p: Any?): Int = if (p == null) PROVENANCE.size - 1 else ActionDiffSupport.indexIn(PROVENANCE, p)

    private fun sens(p: Map<String, Any?>): String = if (p["sensitivity"] is String) p["sensitivity"] as String else ActionDiffSupport.effectiveParamSensitivity(p)

    private fun paramAttrRels(o: Map<String, Any?>, n: Map<String, Any?>): List<Pair<String, Rel>> {
        val out = ArrayList<Pair<String, Rel>>()
        if (o["role"] != n["role"]) out.add(Pair("role", Rel.INC))
        out.add(Pair("sensitivity", rankRel(SENSITIVITY.indexOf(sens(o)).toDouble(), SENSITIVITY.indexOf(sens(n)).toDouble())))
        out.add(Pair("tags", setRel(o["tags"], n["tags"])))
        out.add(Pair("provenance_min", rankRel((-provRank(o["provenance_min"])).toDouble(), (-provRank(n["provenance_min"])).toDouble())))
        if (!J.sameJsonMember(o, n, "unit")) out.add(Pair("unit", Rel.INC))
        out.add(Pair("accumulates", setRel(o["accumulates"], n["accumulates"])))
        if (!J.sameJsonMember(o, n, "default") || o["principal_neutral_default"] != n["principal_neutral_default"]) out.add(Pair("default", Rel.INC))
        return out
    }

    private val SCOPE_RANK = mapOf("one" to 0, "set" to 1, "tenant" to 2, "global" to 3)
    private val IDEM_RANK = mapOf("none" to 0, "natural" to 1, "key_param" to 2)

    /** The semantic diff of `next` against `prev` (versions of the same verb): `{class, reasons}`. Throws `diff_verb` for two different verbs. */
    fun diffDefs(
        prev: Map<String, Any?>,
        next: Map<String, Any?>,
        reg: Map<String, Map<String, Any?>> = Actions.CORE_REGISTRY,
        attestationVerified: ((Map<String, Any?>) -> Boolean)? = null,
    ): MutableMap<String, Any?> {
        if (prev["verb"] != next["verb"]) {
            throw ActionKitError("diff_verb", "diff compares two versions of one verb, not '${prev["verb"]}' and '${next["verb"]}'")
        }
        val o = Actions.normalize(prev)
        val n = Actions.normalize(next)
        val rels = ArrayList<Pair<String, Rel>>()
        val text = o["title"] != n["title"] || o["description"] != n["description"] || o["compensates"] != n["compensates"]
        rels.add(Pair("effects", setRel(o["effects"], n["effects"])))
        val op = J.m(o["params"])
        val np = J.m(n["params"])
        rels.add(Pair("params.accepted_calls", callSetRel(op, np)))
        for (name in java.util.TreeSet<String>(op.keys)) {
            if (np.containsKey(name)) for (r in paramAttrRels(J.m(op[name]), J.m(np[name]))) rels.add(Pair("params.$name.${r.first}", r.second))
        }
        val eo = ActionEffective.effective(prev, reg, attestationVerified)
        val en = ActionEffective.effective(next, reg, attestationVerified)
        val ho = J.m(eo["hint"])
        val hn = J.m(en["hint"])
        rels.add(Pair("traits", setRel(Actions.closure(reg, J.a(ho["traits"])), Actions.closure(reg, J.a(hn["traits"])))))
        rels.add(Pair("profile", profRel(J.m(ho["eff"]), J.m(hn["eff"]))))
        rels.add(Pair("confirmation", rankRel(if (eo["confirmed"] == true) 0.0 else 1.0, if (en["confirmed"] == true) 0.0 else 1.0)))
        rels.add(Pair("effective.traits", setRel(Actions.closure(reg, J.a(eo["traits"])), Actions.closure(reg, J.a(en["traits"])))))
        rels.add(Pair("effective.profile", profRel(J.m(eo["eff"]), J.m(en["eff"]))))
        rels.add(Pair("reversibility", rankRel(
            ActionDiffSupport.revRank(Actions.worstReversibility(o["reversibility"], op as Map<String, Map<String, Any?>>)).toDouble(),
            ActionDiffSupport.revRank(Actions.worstReversibility(n["reversibility"], np as Map<String, Map<String, Any?>>)).toDouble(),
        )))
        rels.add(Pair("blast", rankRel(J.num(J.get(o["blast"], "ppm"))!!, J.num(J.get(n["blast"], "ppm"))!!)))
        val oi = o["idempotency"]
        val ni = n["idempotency"]
        val idem = if ("key_param" == J.get(oi, "mode") && "key_param" == J.get(ni, "mode") && J.get(oi, "param") != J.get(ni, "param")) Rel.INC
            else rankRel(IDEM_RANK[J.get(oi, "mode") as String]!!.toDouble(), IDEM_RANK[J.get(ni, "mode") as String]!!.toDouble())
        rels.add(Pair("idempotency", idem))
        rels.add(Pair("context", setRel(o["context"], n["context"])))
        rels.add(Pair("side_effects", setRel(sideEffects(o), sideEffects(n))))
        val ores = J.m(o["resource"])
        val nres = J.m(n["resource"])
        val resId = if (J.sameJson(ores["id"], true, nres["id"], true)) Rel.EQ
            else if (ActionIdPattern.idPatternContains(ores["id"], nres["id"])) Rel.NARROW
            else if (ActionIdPattern.idPatternContains(nres["id"], ores["id"])) Rel.WIDEN
            else Rel.INC
        rels.add(Pair("resource.id", if (ores["type"] != nres["type"]) Rel.INC else resId))
        rels.add(Pair("resource.scope", rankRel((-SCOPE_RANK[ores["scope"] as String]!!).toDouble(), (-SCOPE_RANK[nres["scope"] as String]!!).toDouble())))
        val ar = setRel(o["aliases"], n["aliases"])
        rels.add(Pair("aliases", if (ar == Rel.NARROW) Rel.WIDEN else if (ar == Rel.WIDEN) Rel.NARROW else ar))
        rels.add(Pair("bindings", if (J.sameJson(o["bindings"], true, n["bindings"], true)) Rel.EQ else Rel.INC))

        val diffs = ArrayList<Pair<String, Rel>>()
        for (r in rels) if (r.second != Rel.EQ) diffs.add(r)
        val reasons = ArrayList<String>()
        for (r in diffs) reasons.add(r.first + ": " + (if (r.second == Rel.INC) "incomparable" else r.second.name.lowercase()))
        if (text) reasons.add("text: title, description or compensates changed")
        reasons.sort()
        val inc = has(diffs, Rel.INC)
        val nar = has(diffs, Rel.NARROW)
        val wid = has(diffs, Rel.WIDEN)
        val cls = if (inc || (nar && wid)) "incomparable" else if (wid) "widen" else if (nar) "narrow" else "equal"
        return J.obj("class", cls, "reasons", J.objs(reasons))
    }

    private fun has(diffs: List<Pair<String, Rel>>, r: Rel): Boolean { for (d in diffs) if (d.second == r) return true; return false }

    private fun profRel(a: Map<String, Any?>, b: Map<String, Any?>): Rel =
        if (ActionEffective.leq(a, b)) (if (ActionEffective.leq(b, a)) Rel.EQ else Rel.NARROW) else if (ActionEffective.leq(b, a)) Rel.WIDEN else Rel.INC

    private fun sideEffects(d: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (s in J.a(d["side_effects"])) out.add("${J.get(s, "target")}|${J.get(s, "kind")}")
        return out
    }

    /** Does a pin follow this change on its own (no principal)? */
    fun diffIsFree(cls: String): Boolean = "equal" == cls || "narrow" == cls
}
