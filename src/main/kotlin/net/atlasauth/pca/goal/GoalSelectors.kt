package net.atlasauth.pca.goal

import java.util.regex.Pattern
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Pca

/**
 * Trait selectors and role-addressed parameters for the Goal IR. A selector goal (SelGoal) names a verb selector (a verb, or a class: every
 * verb of the pinned catalog with all of the traits and none of the excluded ones) in its grants, may select by trait in prohibitions and
 * bounds, and may name a parameter by ROLE. [expandSelGoal] lowers it, against the PINNED catalog, to an ordinary Goal (one grant per
 * verb, each with that verb's own parameter path); the proved core compiler then does the rest.
 *
 * Fail-closed: a grant verb with no unique parameter of a role the condition names is DROPPED (reported); a prohibition whose role term
 * is unresolved for a verb applies to that verb UNCONDITIONALLY; a bound whose role-addressed value cannot be resolved for every selected
 * verb is a type error; an allow selector is positive (no `none_of`, at least one trait); an UNCONFIRMED verb carries the marker
 * `pca.unreviewed`: a class ALLOW never covers it, a class PROHIBITION or a bound over a trait selector ALWAYS covers it; an unknown
 * trait id is a type error. A catalog is {known, verbs: [{verb, traits, roles}]}.
 */
@Suppress("UNCHECKED_CAST")
object GoalSelectors {
    /** The marker trait every unconfirmed verb carries. */
    const val UNREVIEWED = "pca.unreviewed"

    /** Ids are `[0-9A-Za-z_]`: the expanded id `<gid>.<verb>` then sorts exactly as (gid, verb). */
    @JvmField
    val SEL_ID_RE: Pattern = Pattern.compile("[0-9A-Za-z_]{1,64}")

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    private fun mx(o: Any?): Map<String, Any?> = G.m(o) ?: throw NullPointerException("object expected")

    private fun list(o: Any?): List<Any?> = G.arr(o, "")

    // ---------------- the pinned catalog ----------------

    /**
     * The catalog of a pack of action defs (verb ids and parameter paths are the defs' own). [reg] null: the core registry;
     * [pins] (the review pins) may be null.
     */
    @JvmStatic
    fun selCatalogOfDefs(defs: List<Any?>, reg: Map<String, Map<String, Any?>>?, pins: Map<String, Any?>?): Map<String, Any?> {
        val r = reg ?: Actions.CORE_REGISTRY
        val verbs = ArrayList<Any?>()
        for (dO in defs) {
            val d = mx(dO)
            val params = mx(d["params"])
            val names = ArrayList<String>(params.keys)
            names.sortWith(Comparator { a, b -> a.compareTo(b) })
            val roles = LinkedHashMap<String, Any?>()
            for (name in names) {
                val role = G.get(params[name], "role")
                if (role != null) {
                    val rk = G.jsStr(role)
                    val ps = roles.getOrPut(rk) { ArrayList<Any?>() } as MutableList<Any?>
                    ps.add(name)
                }
            }
            verbs.add(G.map("verb" to d["verb"], "traits" to ArrayList<Any?>(list(Actions.effective(d, r, pins)["closure"])), "roles" to roles))
        }
        verbs.sortWith(Comparator { a, b -> G.cmp(G.get(a, "verb") as String, G.get(b, "verb") as String) })
        return G.map("known" to ArrayList<Any?>(r.keys.sorted()), "verbs" to verbs)
    }

    /** The catalog of a shipped domain ontology (core registry, no review pins); null for an unknown domain. */
    @JvmStatic
    fun selCatalogOfDomain(domain: String): Map<String, Any?>? = GoalOntologies.selCatalog(domain)

    /** Digest of the catalog (what `catDigest` of a SelGoal must equal). */
    @JvmStatic
    fun selCatalogDigest(c: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-sel-catalog/v1", "catalog" to c))

    /** Digest of the whole signed selector goal. */
    @JvmStatic
    fun selGoalDigest(g: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-ir-sel/v1", "goal" to g))

    // ---------------- the verbs of a class selector ----------------

    private fun hasAll(ts: List<Any?>, req: List<Any?>): Boolean {
        for (t in req) if (!ts.contains(t)) return false
        return true
    }

    private fun hasNone(ts: List<Any?>, ex: List<Any?>): Boolean {
        for (t in ex) if (ts.contains(t)) return false
        return true
    }

    /** The verbs of the catalog, in catalog order, whose trait closure contains every `allOf` trait and none of the `noneOf` traits. */
    @JvmStatic
    fun classVerbs(cat: Map<String, Any?>, allOf: List<Any?>, noneOf: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (vo in list(cat["verbs"])) {
            val v = mx(vo)
            val ts = list(v["traits"])
            if (hasAll(ts, allOf) && hasNone(ts, noneOf)) out.add(v["verb"])
        }
        return out
    }

    /** The verbs a class ALLOW covers: the class, minus every unconfirmed verb. */
    @JvmStatic
    fun allowClassVerbs(cat: Map<String, Any?>, allOf: List<Any?>, noneOf: List<Any?>): List<Any?> {
        val none = ArrayList<Any?>(noneOf)
        none.add(UNREVIEWED)
        return classVerbs(cat, allOf, none)
    }

    /** The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says. */
    @JvmStatic
    fun floatClassVerbs(cat: Map<String, Any?>, allOf: List<Any?>, noneOf: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (vo in list(cat["verbs"])) {
            val v = mx(vo)
            val ts = list(v["traits"])
            if (ts.contains(UNREVIEWED) || (hasAll(ts, allOf) && hasNone(ts, noneOf))) out.add(v["verb"])
        }
        return out
    }

    // ---------------- role resolution ----------------

    private fun declOf(ont: Map<String, Any?>, verb: Any?): Map<String, Any?>? {
        for (v in list(ont["verbs"])) if (G.get(v, "verb") == verb) return mm(v)
        return null
    }

    private fun infoOf(cat: Map<String, Any?>, verb: Any?): Map<String, Any?>? {
        for (v in list(cat["verbs"])) if (G.get(v, "verb") == verb) return mm(v)
        return null
    }

    /** The one parameter of [verb] carrying [role], as {path, ty}; none, several or undeclared: null. */
    @JvmStatic
    fun resolveRole(ont: Map<String, Any?>, cat: Map<String, Any?>, verb: String, role: String): Map<String, Any?>? {
        val info = infoOf(cat, verb)
        val decl = declOf(ont, verb)
        if (info == null || decl == null) return null
        val roles = mx(info["roles"])
        val paths: List<Any?> = if (roles.containsKey(role)) list(roles[role]) else ArrayList<Any?>()
        if (paths.size != 1) return null
        for (p in list(decl["params"])) if (G.get(p, "path") == paths[0]) return G.map("path" to G.get(p, "path"), "ty" to G.get(p, "ty"))
        return null
    }

    private fun resolveTerm(ont: Map<String, Any?>, cat: Map<String, Any?>, verb: String, t: Map<String, Any?>?): Map<String, Any?>? {
        return when (G.kind(t)) {
            "param" -> G.map("k" to "param", "path" to G.get(t, "path"), "ty" to G.get(t, "ty"))
            "lit" -> G.map("k" to "lit", "v" to G.get(t, "v"))
            "hist" -> G.map("k" to "hist", "bid" to G.get(t, "bid"), "u" to G.get(t, "u"))
            "role" -> {
                val r = resolveRole(ont, cat, verb, G.jsStr(G.get(t, "role")))
                if (r == null) null else G.map("k" to "param", "path" to r["path"], "ty" to r["ty"])
            }
            else -> null
        }
    }

    /** null as soon as one role term is unresolved for the verb. */
    private fun resolveCond(ont: Map<String, Any?>, cat: Map<String, Any?>, verb: String, c: Map<String, Any?>?): Map<String, Any?>? {
        val k = G.kind(c)
        return when (k) {
            "true" -> G.map("k" to "true")
            "cmp" -> {
                val l = resolveTerm(ont, cat, verb, mm(G.get(c, "l")))
                val r = resolveTerm(ont, cat, verb, mm(G.get(c, "r")))
                if (l != null && r != null) G.map("k" to "cmp", "op" to G.get(c, "op"), "l" to l, "r" to r) else null
            }
            "and", "or" -> {
                val a = resolveCond(ont, cat, verb, mm(G.get(c, "a")))
                val b = resolveCond(ont, cat, verb, mm(G.get(c, "b")))
                if (a != null && b != null) G.map("k" to k, "a" to a, "b" to b) else null
            }
            "not" -> {
                val a = resolveCond(ont, cat, verb, mm(G.get(c, "c")))
                if (a != null) G.map("k" to "not", "c" to a) else null
            }
            else -> null
        }
    }

    // ---------------- the expansion ----------------

    /** An expanded grant with the source grant id it came from. */
    private class EG(val src: Any?, val g: Map<String, Any?>)

    private fun grantVerbs(cat: Map<String, Any?>, s: Map<String, Any?>?): List<Any?> =
        if ("verb" == G.kind(s)) G.list(G.get(s, "verb")) else allowClassVerbs(cat, list(G.get(s, "all_of")), list(G.get(s, "none_of")))

    private fun expandGrants(ont: Map<String, Any?>, cat: Map<String, Any?>, gs: List<Any?>, report: MutableList<Any?>?): List<EG> {
        val out = ArrayList<EG>()
        for (gro in gs) {
            val gr = mx(gro)
            val sel = mm(gr["sel"])
            val verbs = grantVerbs(cat, sel)
            val dropped = ArrayList<Any?>()
            for (vo in verbs) {
                val v = vo as String
                val c = resolveCond(ont, cat, v, mm(gr["cond"]))
                if (c == null) {
                    dropped.add(G.map("verb" to v, "reason" to "role_unresolved"))
                    continue
                }
                val gid = if ("class" == G.kind(sel)) G.jsStr(gr["gid"]) + "." + v else G.jsStr(gr["gid"])
                out.add(EG(gr["gid"], G.map("gid" to gid, "verb" to v, "res" to gr["res"], "cond" to c)))
            }
            report?.add(G.map("gid" to gr["gid"], "verbs" to verbs, "dropped" to dropped))
        }
        return out
    }

    private fun prohVerbs(ont: Map<String, Any?>, cat: Map<String, Any?>, t: Map<String, Any?>?): List<Any?> {
        val k = G.kind(t)
        var out: List<Any?> = ArrayList<Any?>()
        if (k == "verb") (out as ArrayList<Any?>).add(G.get(t, "verb"))
        else if (k == "effect") {
            for (v in list(ont["verbs"])) if (G.get(v, "cls") == G.get(t, "cls")) (out as ArrayList<Any?>).add(G.get(v, "verb"))
        } else out = floatClassVerbs(cat, list(G.get(t, "all_of")), list(G.get(t, "none_of")))
        return out
    }

    private fun expandProhibits(ont: Map<String, Any?>, cat: Map<String, Any?>, ps: List<Any?>, report: MutableList<Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        for (po in ps) {
            val p = mx(po)
            val target = mm(p["target"])
            val verbs = prohVerbs(ont, cat, target)
            val unconditional = ArrayList<Any?>()
            for (vo in verbs) {
                val v = vo as String
                val c = resolveCond(ont, cat, v, mm(p["cond"]))
                if (c == null) unconditional.add(v)
                out.add(
                    G.map(
                        "pid" to (if ("verb" == G.kind(target)) p["pid"] else G.jsStr(p["pid"]) + "." + v),
                        "target" to G.map("k" to "verb", "verb" to v), "res" to p["res"], "cond" to (c ?: G.map("k" to "true")),
                    ),
                )
            }
            report?.add(G.map("pid" to p["pid"], "verbs" to verbs, "unconditional" to unconditional))
        }
        return out
    }

    private fun idsOf(es: List<EG>, srcs: List<Any?>): List<Any?> {
        val r = ArrayList<Any?>()
        for (e in es) if (srcs.contains(e.src)) r.add(e.g["gid"])
        return r
    }

    private fun gidsOfVerbs(es: List<EG>, vs: List<Any?>): List<Any?> {
        val r = ArrayList<Any?>()
        for (e in es) if (vs.contains(e.g["verb"])) r.add(e.g["gid"])
        return r
    }

    private fun verbsOfGids(es: List<EG>, gids: List<Any?>): List<Any?> {
        val r = ArrayList<Any?>()
        for (e in es) if (gids.contains(e.g["gid"])) r.add(e.g["verb"])
        return r
    }

    /** The verbs a bound's role-addressed value must resolve for. */
    private fun boundRoleVerbs(ont: Map<String, Any?>, cat: Map<String, Any?>, es: List<EG>, s: Map<String, Any?>?): List<Any?> {
        val k = G.kind(s)
        if (k == "gids") return verbsOfGids(es, idsOf(es, list(G.get(s, "gids"))))
        if (k == "effect") {
            val r = ArrayList<Any?>()
            for (v in list(ont["verbs"])) if (G.get(v, "cls") == G.get(s, "cls")) r.add(G.get(v, "verb"))
            return r
        }
        if (k == "trait") return verbsOfGids(es, gidsOfVerbs(es, floatClassVerbs(cat, list(G.get(s, "all_of")), list(G.get(s, "none_of")))))
        return ArrayList<Any?>()
    }

    /** One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the type is one. {term, how} or null. */
    private fun boundValue(ont: Map<String, Any?>, cat: Map<String, Any?>, vs: List<Any?>, t: Map<String, Any?>?): Map<String, Any?>? {
        when (G.kind(t)) {
            "param" -> return G.map("term" to G.map("k" to "param", "path" to G.get(t, "path"), "ty" to G.get(t, "ty")), "how" to "literal")
            "lit" -> return G.map("term" to G.map("k" to "lit", "v" to G.get(t, "v")), "how" to "literal")
            "hist" -> return G.map("term" to G.map("k" to "hist", "bid" to G.get(t, "bid"), "u" to G.get(t, "u")), "how" to "literal")
            "role" -> {
                val rs = ArrayList<Map<String, Any?>>()
                for (v in vs) {
                    val r = resolveRole(ont, cat, v as String, G.jsStr(G.get(t, "role"))) ?: return null
                    rs.add(r)
                }
                if (rs.isEmpty()) return null
                var samePath = true
                var sameTy = true
                val ty0 = G.stringify(rs[0]["ty"])
                for (r in rs) {
                    if (r["path"] != rs[0]["path"]) samePath = false
                    if (G.stringify(r["ty"]) != ty0) sameTy = false
                }
                if (samePath && sameTy) return G.map("term" to G.map("k" to "param", "path" to rs[0]["path"], "ty" to rs[0]["ty"]), "how" to "shared_path")
                if (sameTy) return G.map("term" to G.map("k" to "param", "path" to "@" + G.jsStr(G.get(t, "role")), "ty" to rs[0]["ty"]), "how" to "role_key")
                return null
            }
            else -> return null
        }
    }

    private fun expandBounds(ont: Map<String, Any?>, cat: Map<String, Any?>, es: List<EG>, bs: List<Any?>, report: MutableList<Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        for (bo in bs) {
            val b = mx(bo)
            val sel = mm(b["sel"])
            val bv = boundValue(ont, cat, boundRoleVerbs(ont, cat, es, sel), mm(b["value"]))
            if (bv == null) continue // a type error (selReasons), never reached when the goal is well typed
            val k = G.kind(sel)
            var gids: List<Any?>? = null
            if (k == "gids") gids = idsOf(es, list(G.get(sel, "gids")))
            else if (k == "trait") gids = gidsOfVerbs(es, floatClassVerbs(cat, list(G.get(sel, "all_of")), list(G.get(sel, "none_of"))))
            if (k == "effect") {
                out.add(mkBound(b, bv, G.map("k" to "effect", "cls" to G.get(sel, "cls"))))
                report?.add(G.map("bid" to b["bid"], "gids" to ArrayList<Any?>(), "dropped" to false, "value" to bv["how"]))
                continue
            }
            if (gids == null || gids.isEmpty()) {
                if (gids == null) throw IrError("unknown bound selector")
                report?.add(G.map("bid" to b["bid"], "gids" to ArrayList<Any?>(), "dropped" to true, "value" to bv["how"]))
                continue
            }
            out.add(mkBound(b, bv, G.map("k" to "gids", "gids" to gids)))
            report?.add(G.map("bid" to b["bid"], "gids" to gids, "dropped" to false, "value" to bv["how"]))
        }
        return out
    }

    private fun mkBound(b: Map<String, Any?>, bv: Map<String, Any?>, sel: Map<String, Any?>): Map<String, Any?> =
        G.map(
            "bid" to b["bid"], "sel" to sel, "agg" to b["agg"], "value" to bv["term"], "key" to b["key"], "window" to b["window"],
            "scope" to b["scope"], "cap" to b["cap"], "onExceed" to b["onExceed"],
        )

    /** Lower a selector goal to an ordinary Goal against the PINNED catalog: {goal, report}. Pure and total; typing is [selReasons] plus the core typechecker. */
    @JvmStatic
    fun expandSelGoal(sg: Map<String, Any?>, ont: Map<String, Any?>, cat: Map<String, Any?>): Map<String, Any?> {
        val gReport = ArrayList<Any?>()
        val pReport = ArrayList<Any?>()
        val bReport = ArrayList<Any?>()
        val es = expandGrants(ont, cat, list(sg["grants"]), gReport)
        val prohibits = expandProhibits(ont, cat, list(sg["prohibits"]), pReport)
        val bounds = expandBounds(ont, cat, es, list(sg["bounds"]), bReport)
        val grants = ArrayList<Any?>()
        for (e in es) grants.add(e.g)
        val deleg = LinkedHashMap<String, Any?>(mx(sg["deleg"]))
        deleg["mayTouch"] = idsOf(es, list(deleg["mayTouch"]))
        val holes = ArrayList<Any?>()
        for (ho in list(sg["holes"])) {
            val h = LinkedHashMap<String, Any?>(mx(ho))
            h["affects"] = idsOf(es, list(h["affects"]))
            holes.add(h)
        }
        val goal = G.map(
            "v" to G.num(1), "principal" to sg["principal"], "ontDigest" to sg["ontDigest"], "nlDigest" to sg["nlDigest"], "sources" to sg["sources"],
            "grants" to grants, "prohibits" to prohibits, "bounds" to bounds, "validity" to sg["validity"], "deleg" to deleg, "escalateOn" to sg["escalateOn"],
            "wildcardAck" to idsOf(es, list(sg["wildcardAck"])), "holes" to holes,
        )
        return G.map("goal" to goal, "report" to G.map("grants" to gReport, "prohibits" to pReport, "bounds" to bReport))
    }

    // ---------------- typing of the selector layer ----------------

    private fun allKnown(known: List<Any?>, ids: List<Any?>): Boolean {
        for (i in ids) if (i !is String || i.isEmpty() || !known.contains(i)) return false
        return true
    }

    private fun grantSelOk(cat: Map<String, Any?>, g: Map<String, Any?>?): Boolean {
        val s = mm(G.get(g, "sel"))
        return "verb" == G.kind(s) || (list(G.get(s, "all_of")).isNotEmpty() && list(G.get(s, "none_of")).isEmpty() && allKnown(list(cat["known"]), list(G.get(s, "all_of"))))
    }

    private fun prohSelOk(cat: Map<String, Any?>, p: Map<String, Any?>?): Boolean {
        val t = mm(G.get(p, "target"))
        return "trait" != G.kind(t) || (allKnown(list(cat["known"]), list(G.get(t, "all_of"))) && allKnown(list(cat["known"]), list(G.get(t, "none_of"))))
    }

    private fun boundSelOk(cat: Map<String, Any?>, gs: List<Any?>, b: Map<String, Any?>?): Boolean {
        val s = mm(G.get(b, "sel"))
        val k = G.kind(s)
        if (k == "gids") {
            for (i in list(G.get(s, "gids"))) {
                var found = false
                for (g in gs) if (G.get(g, "gid") == i) found = true
                if (!found) return false
            }
            return true
        }
        if (k == "effect") return true
        return allKnown(list(cat["known"]), list(G.get(s, "all_of"))) && allKnown(list(cat["known"]), list(G.get(s, "none_of")))
    }

    /**
     * The type reasons of the selector layer, in the order of the formal model, preceded by the checks about the wire rather than the
     * semantics: the pin (`catalog_digest_mismatch`) and the id grammar (`bad_id`). An empty list is well typed at this layer.
     */
    @JvmStatic
    fun selReasons(sg: Map<String, Any?>, ont: Map<String, Any?>, cat: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        if (sg["catDigest"] != selCatalogDigest(cat)) out.add("catalog_digest_mismatch")
        val ids = ArrayList<Any?>()
        for (g in list(sg["grants"])) ids.add(G.get(g, "gid"))
        for (p in list(sg["prohibits"])) ids.add(G.get(p, "pid"))
        for (b in list(sg["bounds"])) ids.add(G.get(b, "bid"))
        var idsOk = true
        for (i in ids) if (i !is String || !SEL_ID_RE.matcher(i).matches()) idsOk = false
        if (!idsOk) out.add("bad_id")
        var catOk = true
        for (v in list(cat["verbs"])) if (declOf(ont, G.get(v, "verb")) == null) catOk = false
        if (!catOk) out.add("catalog_mismatch")
        var g1 = true
        var p1 = true
        var b1 = true
        for (g in list(sg["grants"])) if (!grantSelOk(cat, mm(g))) g1 = false
        if (!g1) out.add("bad_grant_selector")
        for (p in list(sg["prohibits"])) if (!prohSelOk(cat, mm(p))) p1 = false
        if (!p1) out.add("bad_prohibit_selector")
        for (b in list(sg["bounds"])) if (!boundSelOk(cat, list(sg["grants"]), mm(b))) b1 = false
        if (!b1) out.add("bad_bound_selector")
        val es = expandGrants(ont, cat, list(sg["grants"]), null)
        var rb = true
        for (b in list(sg["bounds"])) if (boundValue(ont, cat, boundRoleVerbs(ont, cat, es, mm(mx(b)["sel"])), mm(mx(b)["value"])) == null) rb = false
        if (!rb) out.add("unresolved_role_bound")
        return out
    }

    /**
     * CompileX: selector reasons first (fail closed), then expansion and the core compiler. [compileGoal] is the injected proved
     * compiler (goal, ontology) -> {ok: true, policy} | {ok: false, reasons}. Returns {ok, policy, goal, report} or {ok: false, reasons}.
     */
    @JvmStatic
    fun compileSelGoal(
        sg: Map<String, Any?>,
        ont: Map<String, Any?>,
        cat: Map<String, Any?>,
        compileGoal: (Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>,
    ): Map<String, Any?> {
        val rs = selReasons(sg, ont, cat)
        if (rs.isNotEmpty()) return G.map("ok" to false, "reasons" to rs)
        val ex = expandSelGoal(sg, ont, cat)
        val goal = mx(ex["goal"])
        val c = compileGoal(goal, ont)
        return if (c["ok"] == true) G.map("ok" to true, "policy" to c["policy"], "goal" to goal, "report" to ex["report"]) else G.map("ok" to false, "reasons" to c["reasons"])
    }

    // ---------------- acts ----------------

    /**
     * Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
     * supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first.
     */
    @JvmStatic
    fun withRoleParams(act: Map<String, Any?>, cat: Map<String, Any?>): Map<String, Any?> {
        val params = LinkedHashMap<String, Any?>()
        for ((k, v) in mx(act["params"])) if (!k.startsWith("@")) params[k] = v
        val info = infoOf(cat, act["verb"])
        if (info != null) {
            for ((k, v) in mx(info["roles"])) {
                val paths = list(v)
                if (paths.size == 1 && params.containsKey(G.jsStr(paths[0]))) params["@$k"] = params[G.jsStr(paths[0])]
            }
        }
        val r = LinkedHashMap<String, Any?>(act)
        r["params"] = params
        return r
    }

    // ---------------- the policy card ----------------

    private fun phrase(reg: Map<String, Map<String, Any?>>, id: Any?): String {
        val t = if (id is String) reg[id] else null
        val cp = if (t == null) null else t["card_phrase"] as String?
        return cp ?: G.jsStr(id)
    }

    private fun selectorText(all: List<Any?>, none: List<Any?>, reg: Map<String, Map<String, Any?>>): String {
        val ap = ArrayList<String>()
        for (x in all) ap.add(phrase(reg, x))
        val a = if (all.isNotEmpty()) "every action that " + ap.joinToString(" and ") else "every action"
        if (none.isEmpty()) return a
        val np = ArrayList<String>()
        for (x in none) np.add(phrase(reg, x))
        return a + ", except those that " + np.joinToString(" or ")
    }

    private fun qs(s: Any?): String = G.q(G.jsStr(s))

    private fun qlist(xs: List<Any?>): String {
        val o = ArrayList<String>()
        for (x in xs) o.add(qs(x))
        return o.joinToString(", ")
    }

    /** The card of a selector goal: one line per selector clause in the words of the trait phrases, then the card of the expansion. [reg] null: the core registry. {lines, warnings}. */
    @JvmStatic
    fun renderSelCard(sg: Map<String, Any?>, ont: Map<String, Any?>, cat: Map<String, Any?>, reg: Map<String, Map<String, Any?>>?): Map<String, Any?> {
        val rg = reg ?: Actions.CORE_REGISTRY
        val ex = expandSelGoal(sg, ont, cat)
        val report = mx(ex["report"])
        val lines = ArrayList<Any?>()
        val warnings = ArrayList<Any?>()
        val grants = list(sg["grants"])
        for (i in grants.indices) {
            val g = mx(grants[i])
            val r = mx(list(report["grants"])[i])
            val sel = mm(g["sel"])
            val verbs = list(r["verbs"])
            if ("class" == G.kind(sel)) lines.add("ALLOW " + qs(g["gid"]) + ": " + selectorText(list(G.get(sel, "all_of")), ArrayList<Any?>(), rg) + " [" + verbs.size + " verb(s) in the pinned catalog: " + qlist(verbs) + "]")
            for (d in list(r["dropped"])) warnings.add("grant " + qs(g["gid"]) + " does not cover " + qs(G.get(d, "verb")) + ": it has no unique parameter for a role the condition names")
        }
        val prohibits = list(sg["prohibits"])
        for (i in prohibits.indices) {
            val p = mx(prohibits[i])
            val r = mx(list(report["prohibits"])[i])
            val t = mm(p["target"])
            val verbs = list(r["verbs"])
            if ("trait" == G.kind(t)) lines.add("NEVER " + qs(p["pid"]) + ": " + selectorText(list(G.get(t, "all_of")), list(G.get(t, "none_of")), rg) + ", today " + verbs.size + " verb(s) [" + qlist(verbs) + "]; it also covers every verb added to the catalog later")
            for (v in list(r["unconditional"])) warnings.add("prohibition " + qs(p["pid"]) + " applies to " + qs(v) + " without its condition: the verb has no unique parameter for a role the condition names")
        }
        val bounds = list(sg["bounds"])
        val breports = list(report["bounds"])
        for (i in bounds.indices) {
            val b = mx(bounds[i])
            val r = if (i < breports.size) mm(breports[i]) else null
            val sel = mm(b["sel"])
            if ("trait" == G.kind(sel) && r != null) lines.add("LIMIT " + qs(b["bid"]) + ": over " + selectorText(list(G.get(sel, "all_of")), list(G.get(sel, "none_of")), rg) + " (" + list(r["gids"]).size + " grant(s))")
            if (r != null && r["dropped"] == true) warnings.add("limit " + qs(b["bid"]) + " selects no grant and bounds nothing")
            if (r != null && "role_key" == r["value"]) warnings.add("limit " + qs(b["bid"]) + " sums a role the verbs carry on different parameters: the action must supply the role key")
        }
        val core = GoalCard.renderCard(mx(ex["goal"]))
        val l2 = ArrayList<Any?>(lines)
        l2.addAll(list(core["lines"]))
        val w2 = ArrayList<Any?>(warnings)
        w2.addAll(list(core["warnings"]))
        return G.map("lines" to l2, "warnings" to w2)
    }

    /** The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`). [reg] null: core. */
    @JvmStatic
    fun traitClosure(ids: List<Any?>, reg: Map<String, Map<String, Any?>>?): List<String> = Actions.closure(reg ?: Actions.CORE_REGISTRY, ids)

    // ---------------- the carrier form (the differential with the extracted model) ----------------

    private const val ROLE_MARK = "\u0001role:"

    private fun carryTerm(t: Map<String, Any?>?): Map<String, Any?> = when (G.kind(t)) {
        "role" -> G.map("k" to "param", "path" to ROLE_MARK + G.jsStr(G.get(t, "role")), "ty" to G.map("k" to "s"))
        "param" -> G.map("k" to "param", "path" to G.get(t, "path"), "ty" to G.get(t, "ty"))
        "lit" -> G.map("k" to "lit", "v" to G.get(t, "v"))
        else -> G.map("k" to "hist", "bid" to G.get(t, "bid"), "u" to G.get(t, "u"))
    }

    private fun carryCond(c: Map<String, Any?>?): Map<String, Any?> {
        val k = G.kind(c)
        return when (k) {
            "true" -> G.map("k" to "true")
            "cmp" -> G.map("k" to "cmp", "op" to G.get(c, "op"), "l" to carryTerm(mm(G.get(c, "l"))), "r" to carryTerm(mm(G.get(c, "r"))))
            "and", "or" -> G.map("k" to k, "a" to carryCond(mm(G.get(c, "a"))), "b" to carryCond(mm(G.get(c, "b"))))
            "not" -> G.map("k" to "not", "c" to carryCond(mm(G.get(c, "c"))))
            else -> throw IrError("unknown condition")
        }
    }

    private fun join(xs: List<Any?>, sep: String): String {
        val o = ArrayList<String>()
        for (x in xs) o.add(if (x == null) "" else G.jsStr(x))
        return o.joinToString(sep)
    }

    private fun sel2(all: List<Any?>, none: List<Any?>): String = join(all, "\u0002") + "\u0001" + join(none, "\u0002")

    /** An ordinary Goal carrying a selector goal (selectors ride in strings and role-marked params), so the extracted model decodes it with its existing Goal decoder. */
    @JvmStatic
    fun selCarrier(sg: Map<String, Any?>): Map<String, Any?> {
        val grants = ArrayList<Any?>()
        for (go in list(sg["grants"])) {
            val g = mx(go)
            val s = mm(g["sel"])
            val verb = if ("verb" == G.kind(s)) "V\u0001" + G.jsStr(G.get(s, "verb")) else "C\u0001" + sel2(list(G.get(s, "all_of")), list(G.get(s, "none_of")))
            grants.add(G.map("gid" to g["gid"], "verb" to verb, "res" to g["res"], "cond" to carryCond(mm(g["cond"]))))
        }
        val prohibits = ArrayList<Any?>()
        for (po in list(sg["prohibits"])) {
            val p = mx(po)
            val t = mm(p["target"])
            val k = G.kind(t)
            val verb = if (k == "verb") "V\u0001" + G.jsStr(G.get(t, "verb"))
            else if (k == "effect") "E\u0001" + G.jsStr(G.get(t, "cls"))
            else "T\u0001" + sel2(list(G.get(t, "all_of")), list(G.get(t, "none_of")))
            prohibits.add(G.map("pid" to p["pid"], "res" to p["res"], "cond" to carryCond(mm(p["cond"])), "target" to G.map("k" to "verb", "verb" to verb)))
        }
        val bounds = ArrayList<Any?>()
        for (bo in list(sg["bounds"])) {
            val b = mx(bo)
            val s = mm(b["sel"])
            val k = G.kind(s)
            val sel = if (k == "gids") G.map("k" to "gids", "gids" to G.get(s, "gids"))
            else if (k == "effect") G.map("k" to "effect", "cls" to G.get(s, "cls"))
            else G.map("k" to "effect", "cls" to "T\u0001" + sel2(list(G.get(s, "all_of")), list(G.get(s, "none_of"))))
            bounds.add(
                G.map(
                    "bid" to b["bid"], "key" to b["key"], "window" to b["window"], "scope" to b["scope"], "cap" to b["cap"], "onExceed" to b["onExceed"],
                    "agg" to b["agg"], "value" to carryTerm(mm(b["value"])), "sel" to sel,
                ),
            )
        }
        return G.map(
            "v" to G.num(1), "principal" to sg["principal"], "ontDigest" to sg["ontDigest"], "nlDigest" to sg["nlDigest"], "sources" to sg["sources"],
            "grants" to grants, "prohibits" to prohibits, "bounds" to bounds, "validity" to sg["validity"], "deleg" to sg["deleg"], "escalateOn" to sg["escalateOn"],
            "wildcardAck" to sg["wildcardAck"], "holes" to sg["holes"],
        )
    }

    private fun tok(t: String, v: Any?): List<Any?> {
        val x = ArrayList<Any?>(2)
        x.add(t)
        x.add(v)
        return x
    }

    private fun strs(out: MutableList<Any?>, xs: List<Any?>) {
        out.add(tok("i", G.num(xs.size)))
        for (x in xs) out.add(tok("s", x))
    }

    /** The catalog tape `DecCatalog` reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*. */
    @JvmStatic
    fun encodeSelCatalog(c: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        strs(out, list(c["known"]))
        val verbs = list(c["verbs"])
        out.add(tok("i", G.num(verbs.size)))
        for (vo in verbs) {
            val v = mx(vo)
            out.add(tok("s", v["verb"]))
            strs(out, list(v["traits"]))
            val roles = mx(v["roles"])
            out.add(tok("i", G.num(roles.size)))
            for ((k, rv) in roles) {
                out.add(tok("s", k))
                strs(out, list(rv))
            }
        }
        return out
    }
}
