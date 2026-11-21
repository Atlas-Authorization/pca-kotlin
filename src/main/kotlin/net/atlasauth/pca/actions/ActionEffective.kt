package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions

/**
 * From an action def to its trait set T(d), declared profile decl(d) and effective profile `eff_R(d) = decl(d) join F_R(T(d))`, plus the
 * structural param rules and the profile lattice over profile maps (`{risk, rev, blast_ppm, esc, caveats, context, prules}`).
 */
@Suppress("UNCHECKED_CAST")
object ActionEffective {
    val PARAM_RULE_IDS: List<String> = listOf(
        "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
        "pay_has_idempotency", "recipient_param_declared", "secret_not_logged",
    )

    private val REV_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "irreversible" to 2)

    // ---- profile lattice ----
    private fun rank(rev: Any?): Int = REV_RANK[rev as String]!!

    private fun l(o: Any?): Long = J.num(o)!!.toLong()

    /** The least upper bound of two profiles. */
    fun join(p: Map<String, Any?>, q: Map<String, Any?>): Map<String, Any?> = Actions.join(p, q)

    fun leq(p: Map<String, Any?>, q: Map<String, Any?>): Boolean = Actions.leq(p, q)

    fun profileEq(p: Map<String, Any?>, q: Map<String, Any?>): Boolean = leq(p, q) && leq(q, p)

    // ---- effective ----

    /** What a verifier decides about a `confirmed` review: true iff its attestation is valid. Null = never confirmed. */
    fun isConfirmed(d: Map<String, Any?>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): Boolean = attestationVerified != null && attestationVerified(d)

    /** The hint traits: declared plus implied by the def's own facts. */
    fun hintTraits(d: Map<String, Any?>): List<String> = Actions.hintTraits(d)

    /** T(d): the top of the registry unless a signed confirmation counts. */
    fun traitsOf(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): List<String> =
        if (isConfirmed(d, attestationVerified)) hintTraits(d) else Actions.topTraits(reg)

    private fun view(decl: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, traits: List<String>): MutableMap<String, Any?> {
        val floor = Actions.floorOf(reg, traits)
        return J.obj("traits", J.objs(traits), "closure", J.objs(Actions.closure(reg, traits)), "floor", floor, "eff", join(decl, floor))
    }

    /** `{traits, closure, floor, eff, confirmed, decl, hint: {traits, closure, floor, eff}, clamps}`. */
    fun effective(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): MutableMap<String, Any?> {
        val decl = Actions.declProfile(d)
        val hint = view(decl, reg, hintTraits(d))
        val confirmed = isConfirmed(d, attestationVerified)
        val main = if (confirmed) hint else view(decl, reg, Actions.topTraits(reg))
        val clamps = ArrayList<Any?>()
        val hf = J.m(hint["floor"])
        if (d["reversibility"] != null && rank(decl["rev"]) < rank(hf["rev"])) clamps.add(J.obj("field", "rev", "declared", decl["rev"], "floor", hf["rev"]))
        if (d["blast"] != null && l(decl["blast_ppm"]) < l(hf["blast_ppm"])) clamps.add(J.obj("field", "blast_ppm", "declared", decl["blast_ppm"], "floor", hf["blast_ppm"]))
        val out = LinkedHashMap<String, Any?>(main)
        out["confirmed"] = confirmed
        out["decl"] = decl
        out["hint"] = hint
        out["clamps"] = clamps
        return out
    }

    /** The hint profile after adding trait `t` to the declared traits (never lower). Analysis only. */
    fun effWithTrait(d: Map<String, Any?>, t: String, reg: Map<String, Map<String, Any?>>): Map<String, Any?> {
        val c = LinkedHashMap<String, Any?>(d)
        val tr = ArrayList<Any?>(if (d["traits"] is List<*>) J.a(d["traits"]) else emptyList<Any?>())
        tr.add(t)
        c["traits"] = tr
        return J.m(J.m(effective(c, reg, null)["hint"])["eff"])
    }

    // ---- structural param rules ----

    private fun withRole(params: Map<String, Any?>, pred: (String) -> Boolean): List<Pair<String, Map<String, Any?>>> {
        val out = ArrayList<Pair<String, Map<String, Any?>>>()
        for ((k, v) in params) {
            val r = J.m(v)["role"]
            if (r is String && pred(r)) out.add(Pair(k, J.m(v)))
        }
        return out
    }

    /** The rules the def violates, among `ids`; null = all of them. */
    fun prulesViolations(d: Map<String, Any?>, ids: List<String>?): List<String> {
        val n = Actions.normalize(d)
        val params = J.m(n["params"])
        val res = J.m(n["resource"])
        val bad = ArrayList<String>()
        for (id in ids ?: PARAM_RULE_IDS) {
            var ok = true
            when (id) {
                "money_has_currency" -> {
                    for (e in withRole(params) { it == "money.amount" || it == "money.fee" }) {
                        val u = e.second["unit"]
                        if (u !is Map<*, *> || "money" != J.get(u, "kind")) { ok = false; break }
                        val ccy = J.get(u, "ccy")
                        if (ccy is String) continue
                        val from = J.get(ccy, "from")
                        val c = if (from is String) params[from] else null
                        if (c !is Map<*, *> || "money.currency" != J.get(c, "role") || "iso_currency" != J.get(c, "format")) { ok = false; break }
                    }
                }
                "money_amount_bounded" -> {
                    for (e in withRole(params) { it == "money.amount" }) {
                        val p = e.second
                        if ("integer" != p["type"] || p["min"] == null || p["max"] == null) { ok = false; break }
                    }
                }
                "id_not_wildcard" -> ok = !("*" == res["id"] && "one" == res["scope"])
                "recipient_param_declared" -> ok = "resource" == n["audience"] || withRole(params) { it == "party.payee" || it.startsWith("contact.") }.isNotEmpty()
                "array_bounded" -> {
                    for (p in params.values) if ("array" == J.get(p, "type") && J.get(p, "max_items") == null) { ok = false; break }
                }
                "export_bounded" -> {
                    ok = "one" == res["scope"]
                    if (!ok) for (e in withRole(params) { it == "count.limit" }) if (e.second["max"] != null) { ok = true; break }
                }
                "secret_not_logged" -> {
                    for (e in withRole(params) { it.startsWith("credential.") }) {
                        val tg = e.second["tags"]
                        if (tg !is List<*> || !J.a(tg).contains("secret")) { ok = false; break }
                    }
                }
                "pay_has_idempotency" -> ok = !J.a(n["effects"]).contains("pay") || "none" != J.get(n["idempotency"], "mode")
                else -> {}
            }
            if (!ok) bad.add(id)
        }
        return bad
    }

    fun prulesViolations(d: Map<String, Any?>): List<String> = prulesViolations(d, null)

    /** The rules the effective profile requires but the def does not satisfy (the load-time check). */
    fun requiredPrulesViolated(d: Map<String, Any?>, eff: Map<String, Any?>): List<String> {
        val ids = ArrayList<String>()
        for (x in J.a(eff["prules"])) ids.add(x as String)
        return prulesViolations(d, ids)
    }
}
