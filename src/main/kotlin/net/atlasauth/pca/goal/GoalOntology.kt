package net.atlasauth.pca.goal

import java.math.BigInteger
import java.text.Normalizer
import java.util.regex.Pattern
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The intent-fidelity ontology: the signed authoring vocabulary (types, units, relations, verbs, aliases, templates), its
 * well-formedness checker, the projection onto the Goal IR ontology, template instantiation and locale-aware amount parsing.
 * An ontology, a template and a slot value are parsed-JSON maps (numbers are Json.Num), like the reference objects.
 */
@Suppress("UNCHECKED_CAST")
object GoalOntology {
    @JvmField
    val EFFECT_CLASSES: List<String> = listOf("read", "reversible", "external_send", "irreversible")

    private val INVISIBLE: Pattern = Pattern.compile("[\\u200B-\\u200F\\u2060\\uFEFF]")
    private val NON_PRINTABLE: Pattern = Pattern.compile("[^\\x20-\\x7e]")
    private val ID_TAIL: Pattern = Pattern.compile("[A-Za-z0-9_-]+")
    private const val FOREVER = G.MAX_SAFE

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    /** A required object (a missing one throws, like the reference's property access on undefined). */
    // a JS primitive has no own members (property reads give undefined), only null/undefined throw
    private fun mx(o: Any?): Map<String, Any?> = G.m(o) ?: if (o is String || o is Boolean || o is Number || o is Json.Num || o is List<*>) emptyMap() else throw NullPointerException("object expected")

    /** Map lookup by a value that may not be a string (then absent). */
    private fun gm(m: Map<String, Any?>?, k: Any?): Any? = if (k is String) m!![k] else null

    private fun norm(s: String): String =
        INVISIBLE.matcher(Normalizer.normalize(s, Normalizer.Form.NFKC).toLowerCase(java.util.Locale.ROOT)).replaceAll("")

    // for-of: a string iterates its code points
    private fun list(o: Any?): List<Any?> = if (o is String) o.codePoints().toArray().map { String(Character.toChars(it)) } else G.arr(o, "")

    private fun strOf(o: Any?): String = o as? String ?: throw IrError("string expected")

    // ---------------- digest and signing ----------------

    @JvmStatic
    fun ontologyDigest(o: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-intent-ontology/v1", "ontology" to o))

    @JvmStatic
    fun signOntology(o: Map<String, Any?>, seed: ByteArray): Map<String, Any?> = GoalSign.signPayload("ontology", o, seed)

    @JvmStatic
    fun verifyOntology(s: Map<String, Any?>?, pins: List<*>): Boolean = GoalSign.verifyPayload(s, "ontology", pins)

    /** The declared canonical verb for [word] (the word itself when it is a verb id, else its alias); null when neither. Case and homoglyph variants are NOT guessed. */
    @JvmStatic
    fun resolveVerb(o: Map<String, Any?>, word: String): String? {
        val w = AttestUtil.jsTrim(word)
        for (v in list(o["verbs"])) if (w == G.get(v, "id")) return w
        val al = mm(o["aliases"])
        if (al != null && al.containsKey(w)) {
            val hit = al[w]
            return if (hit is String) hit else null
        }
        return null
    }

    // ---------------- projection onto the IR ontology ----------------

    /** The currency a goal is written in: the first money quantity in its conditions or bound caps (null for a goal without money). */
    @JvmStatic
    fun goalCcy(g: Map<String, Any?>): String? {
        val found = arrayOfNulls<String>(1)
        for (gr in list(g["grants"])) condCcy(mm(G.get(gr, "cond")), found)
        for (p in list(g["prohibits"])) condCcy(mm(G.get(p, "cond")), found)
        for (c in list(g["escalateOn"])) condCcy(mm(c), found)
        for (b in list(g["bounds"])) {
            if (found[0] == null) {
                val u = mm(G.get(G.get(b, "cap"), "u"))
                if (u != null && "money" == u["k"]) found[0] = u["ccy"] as String?
            }
        }
        return found[0]
    }

    private fun termCcy(x: Map<String, Any?>?, found: Array<String?>) {
        if (x == null || "lit" != x["k"]) return
        val v = mm(x["v"])
        val items: List<Any?> = if ("set" == G.kind(v)) list(v!!["items"]) else G.list(v)
        for (it in items) {
            if (found[0] == null && "q" == G.kind(it)) {
                val u = mm(G.get(G.get(it, "q"), "u"))
                if (u != null && "money" == u["k"]) found[0] = u["ccy"] as String?
            }
        }
    }

    private fun condCcy(x: Map<String, Any?>?, found: Array<String?>) {
        val k = G.kind(x)
        if (k == "cmp") {
            termCcy(mm(G.get(x, "l")), found)
            termCcy(mm(G.get(x, "r")), found)
        } else if (k == "and" || k == "or") {
            condCcy(mm(G.get(x, "a")), found)
            condCcy(mm(G.get(x, "b")), found)
        } else if (k == "not") condCcy(mm(G.get(x, "c")), found)
    }

    private fun paramTy(p: Map<String, Any?>, ccy: String?): Map<String, Any?> {
        val kind = p["kind"]
        if ("id" == kind || "enum" == kind || "text" == kind) return G.map("k" to "s")
        if ("money" == kind) {
            val ccys = G.l(p["ccys"]) ?: throw IrError("money parameter lists no currency")
            val c: String? = if (ccy != null && ccys.contains(ccy)) ccy else if (ccys.contains("USD")) "USD" else ccys.firstOrNull() as String?
            // an empty currency list leaves `ccy` undefined (omitted), as the reference does
            return G.map("k" to "q", "u" to (if (c == null) G.map("k" to "money") else G.map("k" to "money", "ccy" to c)))
        }
        return G.map("k" to "q", "u" to G.map("k" to kind))
    }

    /** The Goal IR ontology (verbs with effect class and typed parameters, relation tables) of an intent ontology. [ccy] and [rels] may be null. */
    @JvmStatic
    fun toIrOntology(o: Map<String, Any?>, ccy: String?, rels: List<Any?>?): Map<String, Any?> {
        val verbs = ArrayList<Any?>()
        for (vo in list(o["verbs"])) {
            val v = mx(vo)
            val params = mx(v["params"])
            val keys = ArrayList<String>(params.keys)
            keys.sortWith(Comparator { a, b -> a.compareTo(b) })
            val ps = ArrayList<Any?>()
            for (path in keys) ps.add(G.map("path" to path, "ty" to paramTy(mx(params[path]), ccy)))
            verbs.add(G.map("verb" to v["id"], "cls" to v["effect"], "params" to ps))
        }
        return G.map("verbs" to verbs, "rels" to (rels ?: ArrayList<Any?>()))
    }

    /** The IR ontology a goal is typed and decided against: money parameters in the goal's own currency. */
    @JvmStatic
    fun ontologyForGoal(o: Map<String, Any?>, g: Map<String, Any?>, rels: List<Any?>?): Map<String, Any?> = toIrOntology(o, goalCcy(g), rels)

    /** Relation anchors a goal mentions, declared with no members. */
    @JvmStatic
    fun goalAnchors(g: Map<String, Any?>): List<Any?> {
        val out = LinkedHashMap<String, Map<String, Any?>>()
        for (gr in list(g["grants"])) anchorSel(mm(G.get(gr, "res")), out)
        for (p in list(g["prohibits"])) anchorSel(mm(G.get(p, "res")), out)
        val keys = ArrayList<String>(out.keys)
        keys.sortWith(Comparator { a, b -> a.compareTo(b) })
        val r = ArrayList<Any?>()
        for (k in keys) r.add(out[k])
        return r
    }

    private fun anchorSel(s: Map<String, Any?>?, out: MutableMap<String, Map<String, Any?>>) {
        val k = G.kind(s)
        if (k == "related") {
            out[G.jsStr(G.get(s, "rel")) + "\u0000" + G.jsStr(G.get(s, "anchor"))] =
                G.map("rel" to G.get(s, "rel"), "anchor" to G.get(s, "anchor"), "members" to ArrayList<Any?>())
        } else if (k == "all_of") for (p in list(G.get(s, "parts"))) anchorSel(mm(p), out)
    }

    // ---------------- template references ----------------

    private fun d(x: String): List<String> = if (x.startsWith("$")) listOf(x.substring(1)) else emptyList()

    private fun refsRes(s: Map<String, Any?>?): ArrayList<String> {
        val k = G.kind(s)
        val out = ArrayList<String>()
        if (k == "exact") out.addAll(d(strOf(G.get(s, "id"))))
        else if (k == "oneof") for (i in list(G.get(s, "ids"))) out.addAll(d(strOf(i)))
        else if (k == "related") out.addAll(d(strOf(G.get(s, "anchor"))))
        else if (k == "all_of") for (p in list(G.get(s, "parts"))) out.addAll(refsRes(mm(p)))
        return out
    }

    private fun refsTerm(x: Map<String, Any?>?): List<String> = if ("slot" == G.kind(x)) listOf(strOf(G.get(x, "slot"))) else emptyList()

    private fun refsCond(c: Map<String, Any?>?): ArrayList<String> {
        val k = G.kind(c)
        val out = ArrayList<String>()
        if (k == "cmp") {
            out.addAll(refsTerm(mm(G.get(c, "l"))))
            out.addAll(refsTerm(mm(G.get(c, "r"))))
        } else if (k == "and" || k == "or") {
            out.addAll(refsCond(mm(G.get(c, "a"))))
            out.addAll(refsCond(mm(G.get(c, "b"))))
        } else if (k == "not") out.addAll(refsCond(mm(G.get(c, "c"))))
        return out
    }

    private fun refsGrant(g: Map<String, Any?>): ArrayList<String> {
        val r = refsRes(mm(g["res"]))
        r.addAll(refsCond(mm(g["cond"])))
        return r
    }

    private fun refsBound(b: Map<String, Any?>): List<String> {
        val cs = b["cap_slot"]
        return if (G.truthy(cs)) listOf(G.jsStr(cs)) else emptyList()
    }

    private fun slotRefs(t: Map<String, Any?>): ArrayList<String> {
        val r = ArrayList<String>()
        for (g in list(t["grants"])) r.addAll(refsGrant(mx(g)))
        for (p in list(t["prohibits"])) r.addAll(refsGrant(mx(p)))
        for (b in list(t["bounds"])) r.addAll(refsBound(mx(b)))
        return r
    }

    // ---------------- the well-formedness checker ----------------

    private fun bad(issues: MutableList<Any?>, code: String, where: Any?, msg: String) {
        issues.add(if (where == null) G.map("code" to code, "msg" to msg) else G.map("code" to code, "where" to where, "msg" to msg))
    }

    private fun isInteger(v: Any?): Boolean {
        val x = G.dbl(v)
        return x != null && !x.isNaN() && !x.isInfinite() && x == Math.floor(x)
    }

    private fun findBy(listO: Any?, key: String, v: Any?): Map<String, Any?>? {
        for (x in list(listO)) if (x is Map<*, *> && x[key] == v) return mm(x)
        return null
    }

    private fun strIncludes(listO: Any?, v: Any?): Boolean {
        val l = G.l(listO)
        return l != null && l.contains(v)
    }

    private fun nonEmpty(listO: Any?): Boolean {
        if (listO is String) return listO.isNotEmpty()
        val l = G.l(listO)
        return l != null && l.isNotEmpty()
    }

    /** Object.entries: an array or string lists index keys; other primitives have none; null / undefined throw. */
    private fun entriesOf(o: Any?): Map<String, Any?> = when (o) {
        is Map<*, *> -> mx(o)
        is List<*> -> o.withIndex().associateTo(LinkedHashMap()) { it.index.toString() to it.value }
        is String -> o.codePoints().toArray().withIndex().associateTo(LinkedHashMap()) { it.index.toString() to String(Character.toChars(it.value)) }
        null -> throw NullPointerException("object expected")
        else -> emptyMap()
    }

    /** Every defect of an intent ontology as {code, where, msg}; an empty list means well formed. */
    @JvmStatic
    fun checkOntology(o: Map<String, Any?>): List<Any?> {
        val issues = ArrayList<Any?>()
        val typeIds = HashSet<Any?>()
        val prefixes = HashSet<Any?>()
        for (to in list(o["types"])) {
            val t = mx(to)
            if (typeIds.contains(t["id"])) bad(issues, "dup_type", t["id"], "duplicate type id")
            typeIds.add(t["id"])
            val pre = t["id_prefix"]
            if (!G.truthy(pre) || prefixes.contains(pre)) bad(issues, "dup_prefix", t["id"], "id prefix empty or reused")
            prefixes.add(pre)
        }
        val units = entriesOf(o["units"])
        for ((u, uv) in units) {
            val dd = mx(uv)
            val money = "money" == dd["kind"]
            if (money) {
                val ex = dd["exponent"]
                val x = G.dbl(ex)
                if (!(isInteger(ex) && x!! >= 0 && x <= 4)) bad(issues, "unit_exponent", u, "money unit needs an integer exponent 0..4")
            }
            if (!money && dd.containsKey("exponent")) bad(issues, "unit_exponent", u, "only money units carry an exponent")
        }
        val relIds = HashSet<Any?>()
        for (ro in list(o["relations"])) {
            val r = mx(ro)
            if (relIds.contains(r["id"])) bad(issues, "dup_relation", r["id"], "duplicate relation")
            relIds.add(r["id"])
            if (!typeIds.contains(r["from"]) || !typeIds.contains(r["to"])) bad(issues, "relation_type", r["id"], "relation endpoint type is not declared")
        }
        val verbIds = HashSet<Any?>()
        val verbs = LinkedHashMap<Any?, Map<String, Any?>>()
        for (vo in list(o["verbs"])) {
            val v = mx(vo)
            val vid = G.jsStr(v["id"])
            if (verbIds.contains(v["id"])) bad(issues, "dup_verb", v["id"], "duplicate verb")
            verbIds.add(v["id"])
            verbs[v["id"]] = v
            if (!EFFECT_CLASSES.contains(v["effect"])) bad(issues, "no_effect_class", v["id"], "verb has no valid effect class")
            if (!typeIds.contains(v["resource_type"])) bad(issues, "verb_resource_type", v["id"], "resource type is not declared")
            for ((p, pv) in entriesOf(v["params"])) {
                val pt = mx(pv)
                val kind = pt["kind"]
                if ("money" == kind) {
                    if (!nonEmpty(pt["ccys"])) bad(issues, "param_ccy", "$vid.$p", "money parameter lists no currency")
                    val cc0 = pt["ccys"]
                    if (cc0 is Boolean || cc0 is Number || cc0 is Json.Num || cc0 is Map<*, *>) throw IllegalArgumentException(
                        (if (cc0 is Boolean) "boolean " + cc0 else if (cc0 is Map<*, *>) "object" else "number " + G.jsStr(cc0)) + " is not iterable (cannot read property Symbol(Symbol.iterator))")
                    val cs = if (cc0 is String) list(cc0) else G.l(cc0)
                    if (cs != null) for (c in cs) {
                        val ud = if (c is String) mm(units[c]) else null
                        if (ud == null || "money" != ud["kind"]) bad(issues, "unit_unknown", "$vid.$p", "currency " + G.jsStr(c) + " is not a declared money unit")
                    }
                } else if ("enum" == kind) {
                    if (!nonEmpty(pt["values"])) bad(issues, "param_enum", "$vid.$p", "enum parameter has no values")
                } else if ("id" == kind) {
                    if (!G.truthy(pt["of"]) || !typeIds.contains(pt["of"])) bad(issues, "param_type", "$vid.$p", "id parameter type is not declared")
                } else if ("text" != kind) {
                    var any = false
                    for (ud in units.values) if (G.get(ud, "kind") == kind) any = true
                    if (!any) bad(issues, "unit_unknown", "$vid.$p", "no declared unit of kind " + (if (pt.containsKey("kind")) G.jsStr(kind) else "undefined"))
                }
            }
        }
        // Alias map: a function, keys normalized and collision-free, targets canonical, no chains or cycles.
        val aliases = mx(o["aliases"])
        val seen = LinkedHashMap<String, String>()
        for ((k, target) in aliases) {
            if (k != norm(k) || (NON_PRINTABLE.matcher(k).find() && k != Normalizer.normalize(k, Normalizer.Form.NFKC))) bad(issues, "alias_key", k, "alias key is not in normalized form")
            if (INVISIBLE.matcher(k).find()) bad(issues, "alias_key", k, "alias key contains invisible characters")
            val n = norm(k)
            if (seen.containsKey(n) && seen[n] != k) bad(issues, "alias_collision", k, "collides with " + seen[n] + " after normalization")
            seen[n] = k
            if (!verbIds.contains(target)) bad(issues, "alias_target", k, "alias target is not a canonical verb")
            if (target is String && aliases.containsKey(target)) bad(issues, "alias_chain", k, "alias target is itself an alias (chain or cycle)")
            if (verbIds.contains(k) && k != target) bad(issues, "alias_shadow", k, "alias shadows a canonical verb")
        }
        // Templates.
        val tids = HashSet<Any?>()
        for (to in list(o["templates"])) {
            val t = mx(to)
            val w = "template:" + G.jsStr(t["id"])
            if (tids.contains(t["id"])) bad(issues, "dup_template", w, "duplicate template id")
            tids.add(t["id"])
            val slots = list(t["slots"])
            val slotNames = LinkedHashSet<Any?>()
            for (s in slots) slotNames.add(G.get(s, "name"))
            if (slotNames.size != slots.size) bad(issues, "dup_slot", w, "duplicate slot")
            val refs = slotRefs(t)
            for (r in refs) if (!slotNames.contains(r)) bad(issues, "slot_undeclared", w, "slot $r is used but not declared")
            for (so in slots) {
                val s = mx(so)
                val sw = w + "." + G.jsStr(s["name"])
                val sk = s["kind"]
                if (("id" == sk || "id_list" == sk) && (!G.truthy(s["of"]) || !typeIds.contains(s["of"]))) bad(issues, "slot_type", sw, "id slot type is not declared")
                if ("money" == sk) {
                    val cc = s["ccy"]
                    var ud = if (cc is String) mm(units[cc]) else mm(units[""])
                    if (cc == null) ud = mm(units[""])
                    if (ud == null || "money" != ud["kind"]) bad(issues, "slot_ccy", sw, "money slot currency is not a declared unit")
                }
                if (("enum" == sk || "enum_list" == sk) && !nonEmpty(s["values"])) bad(issues, "slot_enum", sw, "enum slot has no values")
                if (!G.truthy(s["mandatory"]) && !s.containsKey("default")) bad(issues, "slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)")
                if (!refs.contains(G.jsStr(s["name"]))) bad(issues, "slot_unused", sw, "declared slot is never used")
            }
            val tgrants = list(t["grants"])
            if (tgrants.isEmpty()) bad(issues, "empty_allow", w, "template has no grant (empty Allow set)")
            val gids = LinkedHashSet<Any?>()
            for (g in tgrants) gids.add(G.get(g, "gid"))
            if (gids.size != tgrants.size) bad(issues, "dup_gid", w, "duplicate grant id")
            for (go in tgrants) {
                val g = mx(go)
                val v = verbs[g["verb"]]
                val gw = w + "." + G.jsStr(g["gid"])
                if (v == null) {
                    bad(issues, "grant_verb", gw, "grant verb is not in the ontology")
                    continue
                }
                checkResource(o, mm(g["res"]), v, gw, issues)
                checkCond(mm(g["cond"]), v, t, gw, issues)
                val gres = mm(g["res"])
                if ("any" == G.kind(gres) && !("read" == v["effect"] && list(t["bounds"]).isNotEmpty())) bad(issues, "unbounded", gw, "wildcard resource in a template")
                if ("read" != v["effect"] && "related" == G.kind(gres) && list(t["bounds"]).isEmpty()) bad(issues, "unbounded", gw, "non-read grant on a related set needs an aggregate bound")
            }
            for (po in list(t["prohibits"])) {
                val p = mx(po)
                val tg = mx(p["target"])
                val pw = w + "." + G.jsStr(p["pid"])
                if ("verb" == G.kind(tg) && !verbs.containsKey(tg["verb"])) bad(issues, "prohibit_verb", pw, "prohibit verb is not in the ontology")
                if ("effect" == G.kind(tg) && !EFFECT_CLASSES.contains(tg["cls"])) bad(issues, "prohibit_effect", pw, "unknown effect class")
            }
            for (bo in list(t["bounds"])) {
                val b = mx(bo)
                val bw = w + "." + G.jsStr(b["bid"])
                val over = b["over"]
                if ("all" != over) {
                    var unknown = false
                    for (x in list(over)) if (!gids.contains(x)) unknown = true
                    if (unknown) bad(issues, "bound_over", bw, "bound selects an unknown grant")
                }
                val cslot = b["cap_slot"]
                if (G.truthy(cslot) && !slotNames.contains(cslot)) bad(issues, "slot_undeclared", w, "cap slot " + G.jsStr(cslot) + " is not declared")
                if (G.truthy(cslot)) {
                    val cs = findBy(slots, "name", cslot)
                    val ck = if (cs == null) null else cs["kind"]
                    val agg = b["agg"]
                    if (cs != null && !("money" == ck || "count" == ck)) bad(issues, "bound_cap", bw, "cap slot must be money or count")
                    if (cs != null && "count" == agg && "count" != ck) bad(issues, "bound_cap", bw, "count bound needs a count slot")
                    if (cs != null && "sum" == agg && "money" != ck) bad(issues, "bound_cap", bw, "sum bound over money needs a money slot")
                }
                if ("sum" == b["agg"] && !G.truthy(b["param"])) bad(issues, "bound_value", bw, "sum bound has no value parameter")
            }
            // non-empty and bounded after instantiation with the declared example
            val g = instantiateTemplate(o, strOf(t["id"]), mm(t["example"]), "p", "", null)
            val holes = list(g["holes"])
            if (holes.isNotEmpty()) {
                val hs = ArrayList<String>()
                for (h in holes) hs.add(G.jsStr(G.get(h, "hid")))
                bad(issues, "example_holes", w, "example leaves holes: " + hs.joinToString(","))
            } else if (list(g["grants"]).size != tgrants.size) bad(issues, "empty_allow", w, "example instantiation dropped a grant")
            else if (!hasAllowWitness(o, g)) bad(issues, "empty_allow", w, "instantiated template has an empty Allow set")
        }
        return issues
    }

    private fun prefixOf(o: Map<String, Any?>, typeId: Any?): String? {
        val t = findBy(o["types"], "id", typeId)
        return if (t == null) null else t["id_prefix"] as String?
    }

    private fun idOk(id: String, pre: String?): Boolean = id.startsWith("$") || (pre != null && id.startsWith(pre))

    private fun checkResource(o: Map<String, Any?>, s: Map<String, Any?>?, v: Map<String, Any?>, w: String, issues: MutableList<Any?>) {
        val prefix = prefixOf(o, v["resource_type"])
        val k = G.kind(s)
        if (k == "exact" && !idOk(strOf(G.get(s, "id")), prefix)) bad(issues, "resource_type", w, "exact resource id has the wrong type prefix")
        else if (k == "oneof") {
            val ids = list(G.get(s, "ids"))
            if (ids.isEmpty()) bad(issues, "resource_empty", w, "one_of is empty")
            for (i in ids) if (!idOk(strOf(i), prefix)) bad(issues, "resource_type", w, "one_of member has the wrong type prefix")
        } else if (k == "related") {
            val r = findBy(o["relations"], "id", G.get(s, "rel"))
            if (r == null) bad(issues, "relation_unknown", w, "relation " + G.jsStr(G.get(s, "rel")) + " is not declared")
            else {
                if (r["to"] != v["resource_type"]) bad(issues, "relation_type", w, "relation target type differs from the verb resource type")
                val anchorPre = prefixOf(o, r["from"])
                if (!idOk(strOf(G.get(s, "anchor")), anchorPre)) bad(issues, "resource_type", w, "relation anchor has the wrong type prefix")
            }
        } else if (k == "all_of") {
            val parts = list(G.get(s, "parts"))
            if (parts.size < 2) bad(issues, "all_of_arity", w, "all_of needs at least two parts")
            for (x in parts) checkResource(o, mm(x), v, w, issues)
        }
    }

    private fun checkCond(c: Map<String, Any?>?, v: Map<String, Any?>, t: Map<String, Any?>, w: String, issues: MutableList<Any?>) {
        val k = G.kind(c)
        if (k == "and" || k == "or") {
            checkCond(mm(G.get(c, "a")), v, t, w, issues)
            checkCond(mm(G.get(c, "b")), v, t, w, issues)
            return
        }
        if (k == "not") {
            checkCond(mm(G.get(c, "c")), v, t, w, issues)
            return
        }
        if (k != "cmp") return
        val l = mm(G.get(c, "l"))
        val p = if ("param" == G.kind(l)) mm(gm(mx(v["params"]), G.get(l, "path"))) else null
        if ("param" != G.kind(l) || p == null) {
            bad(issues, "cond_param", w, "left side of a comparison must be a declared parameter of the verb")
            return
        }
        val op = G.get(c, "op")
        val ordered = "lt" == op || "lte" == op || "gt" == op || "gte" == op
        val pk = p["kind"]
        if (ordered && ("text" == pk || "enum" == pk || "id" == pk)) bad(issues, "cond_order", w, "ordering on a text/enum/id parameter")
        val x = mm(G.get(c, "r"))
        val xk = G.kind(x)
        val inOp = "in" == op || "nin" == op
        if (xk == "slot") {
            val s = findBy(t["slots"], "name", G.get(x, "slot")) ?: return
            val sk = s["kind"]
            val okKind = if ("money" == pk) "money" == sk
            else pk == sk || ("enum" == pk && ("enum" == sk || "enum_list" == sk)) || ("id" == pk && ("id" == sk || "id_list" == sk)) || ("text" == pk && "text_list" == sk)
            if (!okKind) bad(issues, "cond_type", w, "slot " + G.jsStr(s["name"]) + " (" + G.jsStr(sk) + ") does not type-check against parameter kind " + G.jsStr(pk))
            if ("money" == pk && "money" == sk && !strIncludes(p["ccys"], if (s["ccy"] == null) "" else s["ccy"])) bad(issues, "cond_unit", w, "slot currency is not accepted by the parameter")
            val isList = "id_list" == sk || "enum_list" == sk || "text_list" == sk
            if (isList != inOp) bad(issues, "cond_type", w, "list slots pair with in/nin and scalar slots with the other operators")
        } else if (xk == "lit") {
            val lv = mm(G.get(x, "v"))
            if ("set" == G.kind(lv)) {
                val items = list(G.get(lv, "items"))
                if (items.isEmpty()) bad(issues, "cond_type", w, "empty literal list")
                for (i in items) litCheck(mm(i), p, w, issues)
                if (!inOp) bad(issues, "cond_type", w, "a literal set pairs with in/nin")
            } else {
                litCheck(lv, p, w, issues)
                if (inOp) bad(issues, "cond_type", w, "in/nin needs a list")
            }
        } else bad(issues, "cond_term", w, "unsupported right-hand term")
    }

    private fun litCheck(l: Map<String, Any?>?, p: Map<String, Any?>, w: String, issues: MutableList<Any?>) {
        val k = G.kind(l)
        val pk = p["kind"]
        if (k == "q") {
            val u = mx(G.get(G.get(l, "q"), "u"))
            if (u["k"] != pk) bad(issues, "cond_type", w, "literal kind differs from the parameter kind")
            if ("money" == u["k"] && !strIncludes(p["ccys"], u["ccy"])) bad(issues, "cond_unit", w, "literal currency is not accepted by the parameter")
        } else if (k == "s") {
            if ("enum" != pk && "id" != pk && "text" != pk) bad(issues, "cond_type", w, "literal kind differs from the parameter kind")
            if ("enum" == pk && !strIncludes(p["values"], G.get(l, "s"))) bad(issues, "cond_enum", w, "enum literal is not a member")
        } else bad(issues, "cond_type", w, "nested literal set")
    }

    private fun hasAllowWitness(o: Map<String, Any?>, g: Map<String, Any?>): Boolean {
        val ont = ontologyForGoal(o, g, null)
        for (gr in list(g["grants"])) if (GoalExamples.allowWitness(g, mx(gr), ont) == null) return false
        return true
    }

    // ---------------- template instantiation ----------------

    private fun quantityOf(s: Map<String, Any?>, v: Any?): Map<String, Any?>? {
        if (v is String || v is List<*>) return null
        if (v !is Map<*, *>) throw IrError("slot value is not an object")
        val m = mx(v)
        val kind = s["kind"]
        if (m.containsKey("minor") && "money" == kind && m["ccy"] == s["ccy"]) {
            val n = G.safeInt(m["minor"])
            if (n != null && n >= 0) return G.map("u" to G.map("k" to "money", "ccy" to m["ccy"]), "n" to G.num(n))
        }
        if (m.containsKey("n") && "count" == kind) {
            val n = G.safeInt(m["n"])
            if (n != null && n >= 0) return G.map("u" to G.map("k" to "count"), "n" to G.num(n))
        }
        if (m.containsKey("ms") && "duration" == kind) {
            val n = G.safeInt(m["ms"])
            if (n != null && n >= 0) return G.map("u" to G.map("k" to "duration"), "n" to G.num(n))
        }
        if (m.containsKey("epoch_ms") && "instant" == kind) {
            val n = G.safeInt(m["epoch_ms"])
            if (n != null) return G.map("u" to G.map("k" to "instant"), "n" to G.num(n))
        }
        return null
    }

    private fun sv(s: Any?): Map<String, Any?> = G.map("k" to "s", "s" to s)

    private fun idLike(v: String): Boolean = ID_TAIL.matcher(v).matches()

    private fun noInvisible(x: String): Boolean = x == Normalizer.normalize(x, Normalizer.Form.NFKC) && !INVISIBLE.matcher(x).find()

    /** Typed value(s) of a slot (a List of values), or a reason String when it is missing or invalid (the slot then becomes a Hole). */
    @JvmStatic
    fun slotLits(o: Map<String, Any?>, s: Map<String, Any?>, v: Any?): Any? {
        if (v == null) return "missing"
        val kind = G.jsStr(s["kind"])
        when (kind) {
            "money", "count", "duration", "instant" -> {
                val q = quantityOf(s, v) ?: return "ill-typed"
                val max = if (s["max"] == null) null else G.dbl(s["max"])
                if (max != null) {
                    val qn = if (kind == "instant") 0.0 else G.toNum(q["n"])
                    if (qn > max) return "above the template maximum"
                }
                return G.list(G.map("k" to "q", "q" to q))
            }
            "id" -> {
                val pre = prefixOf(o, s["of"])
                return if (v is String && pre != null && pre.isNotEmpty() && v.startsWith(pre) && v.length > pre.length && idLike(v)) G.list(sv(v)) else "ill-typed"
            }
            "id_list" -> {
                val pre = prefixOf(o, s["of"])
                if (v !is List<*> || v.isEmpty()) return "ill-typed"
                val out = ArrayList<Any?>()
                for (x in v) {
                    val xs = strOf(x)
                    if (!(pre != null && pre.isNotEmpty() && xs.startsWith(pre) && idLike(xs))) return "ill-typed"
                    out.add(sv(x))
                }
                return out
            }
            "enum" -> return if (v is String && strIncludes(s["values"], v)) G.list(sv(v)) else "ill-typed"
            "enum_list" -> {
                if (v !is List<*> || v.isEmpty()) return "ill-typed"
                val out = ArrayList<Any?>()
                for (x in v) {
                    if (!strIncludes(s["values"], x)) return "ill-typed"
                    out.add(sv(x))
                }
                return out
            }
            "text_list" -> {
                if (v !is List<*> || v.isEmpty()) return "ill-typed"
                val out = ArrayList<Any?>()
                for (x in v) {
                    if (x !is String || x.isEmpty() || !noInvisible(x)) return "ill-typed"
                    out.add(sv(x))
                }
                return out
            }
            else -> return null
        }
    }

    private fun isListSlot(t: Map<String, Any?>, name: String): Boolean {
        val s = findBy(t["slots"], "name", name)
        val k = if (s == null) null else s["kind"]
        return s != null && k is String && k.endsWith("_list")
    }

    /**
     * Template -> Goal (canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a hole
     * is dropped (the most restrictive completion). [sources] may be null.
     */
    @JvmStatic
    fun instantiateTemplate(
        o: Map<String, Any?>,
        templateId: String,
        values: Map<String, Any?>?,
        principal: String,
        nl: String,
        sources: List<String>?,
    ): Map<String, Any?> {
        val t = findBy(o["templates"], "id", templateId) ?: throw IrError("unknown template $templateId")
        val bound = LinkedHashMap<String, List<Any?>?>()
        val holes = ArrayList<Any?>()
        for (so in list(t["slots"])) {
            val s = mx(so)
            val name = G.jsStr(s["name"])
            var v = if (values == null) null else values[name]
            if (v == null) v = s["default"]
            val r = slotLits(o, s, v)
            if (r is String) {
                holes.add(
                    G.map(
                        "hid" to name,
                        "q" to "What is the " + name.replace("_", " ") + " (" + G.jsStr(s["kind"]) + (if (G.truthy(s["ccy"])) " " + G.jsStr(s["ccy"]) else "") + ")? (" + r + ")",
                        "domain" to ArrayList<Any?>(), "affects" to ArrayList<Any?>(), "global" to false,
                    ),
                )
            } else bound[name] = r as List<Any?>?
        }
        val verbOf = LinkedHashMap<Any?, Map<String, Any?>>()
        for (vo in list(o["verbs"])) verbOf[G.get(vo, "id")] = mx(vo)
        val inst = Inst(o, t, bound, verbOf)
        val dropped = HashSet<String>()
        val grants = ArrayList<Any?>()
        val tbounds = list(t["bounds"])
        val keepBound = ArrayList<Any?>()
        for (b in tbounds) if (inst.deps(refsBound(mx(b)))) keepBound.add(b)
        for (bo in tbounds) {
            if (keepBound.contains(bo)) continue
            val b = mx(bo)
            for (go in list(t["grants"])) {
                val gid = G.get(go, "gid")
                if ("all" == b["over"] || list(b["over"]).contains(gid)) dropped.add(G.jsStr(gid))
            }
        }
        for (go in list(t["grants"])) {
            val g = mx(go)
            val gid = G.jsStr(g["gid"])
            if (dropped.contains(gid) || !inst.deps(refsGrant(g))) dropped.add(gid)
            else grants.add(G.map("gid" to g["gid"], "verb" to g["verb"], "res" to inst.subRes(mx(g["res"])), "cond" to inst.subCond(mx(g["cond"]), g["verb"] as String?)))
        }
        val prohibits = ArrayList<Any?>()
        for (po in list(t["prohibits"])) {
            val p = mx(po)
            val tg = mx(p["target"])
            var verb: String?
            if ("verb" == G.kind(tg)) verb = tg["verb"] as String?
            else {
                verb = null
                for (vo in list(o["verbs"])) if (G.get(vo, "effect") == tg["cls"]) {
                    verb = G.get(vo, "id") as String?
                    break
                }
            }
            if (inst.deps(refsGrant(p))) prohibits.add(G.map("pid" to p["pid"], "target" to tg, "res" to inst.subRes(mx(p["res"])), "cond" to inst.subCond(mx(p["cond"]), verb)))
            else prohibits.add(G.map("pid" to p["pid"], "target" to tg, "res" to G.map("k" to "any", "reason" to "hole"), "cond" to G.map("k" to "true")))
        }
        val kept = HashSet<String>()
        for (g in grants) kept.add(G.jsStr(G.get(g, "gid")))
        val bounds = ArrayList<Any?>()
        for (bo in keepBound) {
            val b = mx(bo)
            val gids = ArrayList<Any?>()
            if ("all" == b["over"]) for (g in grants) gids.add(G.get(g, "gid"))
            else for (x in list(b["over"])) if (kept.contains(G.jsStr(x))) gids.add(x)
            if (gids.isEmpty()) continue
            val capSlot = b["cap_slot"]
            val capLit = if (G.truthy(capSlot)) inst.single(G.jsStr(capSlot)) else null
            val cap = if (capLit != null && "q" == G.kind(capLit)) mm(capLit["q"]) else mm(b["cap"])
            var verb: String? = null
            for (g in grants) if (G.get(g, "gid") == gids[0]) {
                verb = G.get(g, "verb") as String?
                break
            }
            if (verb == null) throw IrError("bound without a surviving grant")
            val value: Map<String, Any?>
            if ("sum" == b["agg"]) {
                val param = b["param"] as? String ?: throw IrError("parameter undefined is not declared by any verb")
                val cu = mx(cap!!["u"])
                value = G.map("k" to "param", "path" to param, "ty" to inst.tyOf(verb, param, if ("money" == cu["k"]) cu["ccy"] as String? else null))
            } else value = G.map("k" to "lit", "v" to G.map("k" to "q", "q" to G.map("u" to G.map("k" to "count"), "n" to G.num(1))))
            bounds.add(
                G.map(
                    "bid" to b["bid"], "sel" to G.map("k" to "gids", "gids" to gids), "agg" to b["agg"], "value" to value, "key" to "",
                    "window" to G.map("k" to "lifetime"), "scope" to G.map("k" to "session"), "cap" to cap, "onExceed" to b["onExceed"],
                ),
            )
        }
        val srcs = ArrayList<Any?>()
        if (sources != null) srcs.addAll(sources)
        return GoalNormalize.canonicalizeGoal(
            G.map(
                "v" to G.num(1), "principal" to principal, "ontDigest" to ontologyDigest(o), "nlDigest" to GoalDigests.nlDigest(nl), "sources" to srcs,
                "grants" to grants, "prohibits" to prohibits, "bounds" to bounds,
                "validity" to G.map("notBefore" to G.num(0), "notAfter" to G.num(FOREVER), "maxIdle" to G.num(0)),
                "deleg" to G.map("maxDepth" to G.num(0), "narrowOnly" to true, "mayTouch" to ArrayList<Any?>()),
                "escalateOn" to ArrayList<Any?>(), "wildcardAck" to ArrayList<Any?>(), "holes" to holes,
            ),
        )
    }

    /** The substitution state of one instantiation. */
    private class Inst(
        val o: Map<String, Any?>,
        val t: Map<String, Any?>,
        val bound: Map<String, List<Any?>?>,
        val verbOf: Map<Any?, Map<String, Any?>>,
    ) {
        fun deps(refs: List<String>): Boolean {
            for (r in refs) if (!bound.containsKey(r)) return false
            return true
        }

        fun single(name: String): Map<String, Any?>? = mm(bound[name]!![0])

        fun sub(id: String): String = if (id.startsWith("$")) single(id.substring(1))!!["s"] as String else id

        fun subPart(r: Map<String, Any?>): Map<String, Any?> {
            val k = G.kind(r)
            if (k == "exact") return G.map("k" to "exact", "id" to sub(strOf(r["id"])))
            if (k == "oneof") {
                val ids = ArrayList<Any?>()
                for (i in list(r["ids"])) ids.add(sub(strOf(i)))
                return G.map("k" to "oneof", "ids" to ids)
            }
            val c = LinkedHashMap<String, Any?>(r)
            c["anchor"] = sub(strOf(r["anchor"]))
            return c
        }

        fun subRes(r: Map<String, Any?>): Map<String, Any?> {
            val k = G.kind(r)
            if (k == "any") return r
            if (k == "all_of") {
                val ps = ArrayList<Any?>()
                for (p in list(r["parts"])) ps.add(subPart(mx(p)))
                return G.map("k" to "all_of", "parts" to ps)
            }
            return subPart(r)
        }

        fun tyOf(verb: String?, path: String, ccy: String?): Map<String, Any?> {
            var p: Map<String, Any?>? = null
            val v = if (verb != null) verbOf[verb] else null
            if (v != null) p = mm(mx(v["params"])[path])
            if (p == null) for (vo in list(o["verbs"])) {
                val x = mm(mx(G.get(vo, "params"))[path])
                if (x != null) {
                    p = x
                    break
                }
            }
            if (p == null) throw IrError("parameter $path is not declared by any verb")
            return paramTy(p, ccy)
        }

        fun lit(x: Map<String, Any?>?): Map<String, Any?>? {
            val k = G.kind(x)
            if (k == "slot") {
                val slot = strOf(x!!["slot"])
                val l = bound[slot]
                return G.map("k" to "lit", "v" to (if (isListSlot(t, slot)) G.map("k" to "set", "items" to l) else l!![0]))
            }
            return if (k == "lit") G.map("k" to "lit", "v" to x!!["v"]) else null
        }

        fun ccyOf(x: Map<String, Any?>?): String? {
            if (x != null && "lit" == x["k"]) {
                val v = mm(x["v"])
                if ("q" == G.kind(v)) {
                    val u = mm(G.get(v!!["q"], "u"))
                    if (u != null && "money" == u["k"]) return u["ccy"] as String?
                }
            }
            return null
        }

        fun term(x: Map<String, Any?>?, v: Map<String, Any?>?, verb: String?, hint: String?): Map<String, Any?> {
            if (v != null) return v
            val path = strOf(x!!["path"])
            return G.map("k" to "param", "path" to path, "ty" to tyOf(verb, path, hint))
        }

        fun subCond(c: Map<String, Any?>, verb: String?): Map<String, Any?> {
            val k = G.kind(c)
            if (k == "true") return c
            if (k == "and") return G.map("k" to "and", "a" to subCond(mx(c["a"]), verb), "b" to subCond(mx(c["b"]), verb))
            if (k == "or") return G.map("k" to "or", "a" to subCond(mx(c["a"]), verb), "b" to subCond(mx(c["b"]), verb))
            if (k == "not") return G.map("k" to "not", "c" to subCond(mx(c["c"]), verb))
            val l = mm(c["l"])
            val r = mm(c["r"])
            val lv = lit(l)
            val rv = lit(r)
            var hint = ccyOf(lv)
            if (hint == null) hint = ccyOf(rv)
            val tl = term(l, lv, verb, hint)
            val tr = term(r, rv, verb, hint)
            return G.map("k" to "cmp", "op" to c["op"], "l" to tl, "r" to tr)
        }
    }

    // ---------------- locale-aware human number parsing ----------------

    private fun amountFail(reason: String): Map<String, Any?> = G.map("ok" to false, "reason" to reason)

    private val NOT_AMOUNT_CHAR: Pattern = Pattern.compile("[^0-9.,]")
    private val AMOUNT: Pattern = Pattern.compile("[0-9][0-9.,]*")
    private val DOUBLE_SEP: Pattern = Pattern.compile("[.,]{2}")
    private val DIGITS: Pattern = Pattern.compile("[0-9]+")

    private fun count(t: String, sep: Char): Int {
        var n = 0
        for (i in 0 until t.length) if (t[i] == sep) n++
        return n
    }

    /** Java String.split(regex, -1) on a single literal separator character. */
    private fun splitAll(t: String, sep: Char): List<String> {
        val out = ArrayList<String>()
        var start = 0
        for (i in 0 until t.length) if (t[i] == sep) {
            out.add(t.substring(start, i))
            start = i + 1
        }
        out.add(t.substring(start))
        return out
    }

    /**
     * "1,000.50", "1.000,50", "$20", "20 dollars": {ok: true, minor} or {ok: false, reason}. Ambiguous literals ("1,000" with no locale
     * hint, "1.000") are NOT guessed. [locale] is "en" (',' is thousands), "de" ('.' is thousands) or null.
     */
    @JvmStatic
    fun parseHumanAmount(text: String, exponent: Int, locale: String?): Map<String, Any?> {
        val t = NOT_AMOUNT_CHAR.matcher(AttestUtil.jsTrim(Normalizer.normalize(text, Normalizer.Form.NFKC))).replaceAll("")
        if (!AMOUNT.matcher(t).matches() || DOUBLE_SEP.matcher(t).find()) return amountFail("not a number")
        val lastDot = t.lastIndexOf('.')
        val lastComma = t.lastIndexOf(',')
        var dec: Char? = null
        var thou: Char? = null
        if (lastDot >= 0 && lastComma >= 0) {
            dec = if (lastDot > lastComma) '.' else ','
            thou = if (dec == '.') ',' else '.'
        } else if (lastDot >= 0 || lastComma >= 0) {
            val sep = if (lastDot >= 0) '.' else ','
            val parts = splitAll(t, sep)
            val groupLike = parts.size > 2 || parts[parts.size - 1].length == 3
            if (!groupLike) dec = sep
            else if (parts.size > 2) thou = sep
            else if (locale != null && locale.isNotEmpty()) {
                if ((locale == "en") == (sep == ',')) thou = sep else dec = sep
            } else return amountFail("ambiguous separator")
        }
        var intPart = t
        var frac = ""
        if (dec != null) {
            val i = t.lastIndexOf(dec)
            intPart = t.substring(0, i)
            frac = t.substring(i + 1)
        }
        if (thou != null) {
            val groups = splitAll(intPart, thou)
            var badGroup = false
            for (i in 1 until groups.size) if (groups[i].length != 3) badGroup = true
            if (badGroup || groups[0].isEmpty() || groups[0].length > 3) return amountFail("malformed grouping")
            intPart = groups.joinToString("")
        }
        if (frac.length > exponent) return amountFail("more decimals than the currency allows")
        val sb = StringBuilder(intPart).append(frac)
        for (i in frac.length until exponent) sb.append('0')
        val digits = sb.toString()
        if (!DIGITS.matcher(digits).matches()) return amountFail("out of range")
        val v = BigInteger(digits)
        if (v.compareTo(BigInteger.valueOf(G.MAX_SAFE)) > 0) return amountFail("out of range")
        return G.map("ok" to true, "minor" to G.num(v.toLong()))
    }

    private const val JSWS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]"
    private val LEAD_SYMBOL: Pattern = Pattern.compile("^[\$\u20AC\u00A3]" + JSWS + "*")

    /**
     * The strict front-end contract over [parseHumanAmount]: {minor} | {hole: "AMBIGUOUS_NUMBER"} | {error: "BAD_NUMBER"}.
     * Only digits, '.' and ',' after one optional leading currency symbol; a decimal separator that contradicts the locale is refused.
     */
    @JvmStatic
    fun parseMoney(text: String, exponent: Int, locale: String?): Map<String, Any?> {
        val t = LEAD_SYMBOL.matcher(AttestUtil.jsTrim(text)).replaceFirst("")
        if (!AMOUNT.matcher(t).matches()) return G.map("error" to "BAD_NUMBER")
        val both = t.indexOf('.') >= 0 && t.indexOf(',') >= 0
        if (locale != null && both && t[Math.max(t.lastIndexOf('.'), t.lastIndexOf(','))] != (if (locale == "en") '.' else ',')) return G.map("error" to "BAD_NUMBER")
        if (locale == null && !both && count(t, '.') + count(t, ',') > 1) return G.map("hole" to "AMBIGUOUS_NUMBER")
        val r = parseHumanAmount(t, exponent, locale)
        if (r["ok"] == true) return G.map("minor" to r["minor"])
        return if ("ambiguous separator" == r["reason"]) G.map("hole" to "AMBIGUOUS_NUMBER") else G.map("error" to "BAD_NUMBER")
    }
}
