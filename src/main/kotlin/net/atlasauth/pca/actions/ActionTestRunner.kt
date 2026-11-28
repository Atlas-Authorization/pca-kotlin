package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.Actions

/**
 * Executable examples and generic property checks of an action pack: every def's examples run through the real pipeline in process (derive the schema,
 * conform the params, expand the floors, decide), plus T2 monotonicity over trait additions and subsets, digest stability across the JSON and YAML forms,
 * and the schema round trip (the example conforms; every mutation of it is refused). The example policy (`under`) is a small allow selector evaluated
 * here; it can only pre-authorize. Examples and property checks describe the action AS REVIEWED (its hint view): they are authoring tests, not enforcement.
 */
@Suppress("UNCHECKED_CAST")
object ActionTestRunner {
    private val SEL_KEYS = listOf("trait", "verb", "where", "caveats", "context")
    private val CAVEAT_KINDS = listOf("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap")

    private fun hintOf(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>): Map<String, Any?> {
        val e = ActionEffective.effective(d, reg, null)
        val out = LinkedHashMap(e)
        out.putAll(J.m(e["hint"]))
        out["confirmed"] = true
        return out
    }

    /** The example policy as a list of selectors, or the reason it is malformed (a String). */
    private fun parseUnder(under: Any?, present: Boolean): Any {
        if (!present) return ArrayList<Any?>()
        if (under !is Map<*, *>) return "under must be {allow: selector | [selector]}"
        for (k in J.m(under).keys) if (k != "allow") return "under must be {allow: selector | [selector]}"
        val allow = J.m(under)["allow"]
        val list: List<Any?> = if (allow is List<*>) J.a(allow) else J.list(allow)
        val out = ArrayList<Any?>()
        for (s in list) {
            if (s !is Map<*, *>) return "an allow selector has trait, verb, where, caveats, context"
            val m = J.m(s)
            for (k in m.keys) if (!SEL_KEYS.contains(k)) return "an allow selector has trait, verb, where, caveats, context"
            if (m.containsKey("trait") == m.containsKey("verb")) return "an allow selector names exactly one of trait and verb"
            if (m.containsKey("where") && m["where"] !is Map<*, *>) return "where must be an object"
            if (m.containsKey("caveats")) {
                var ok = m["caveats"] is List<*>
                if (ok) for (c in J.a(m["caveats"])) if (!CAVEAT_KINDS.contains(c)) ok = false
                if (!ok) return "caveats must be known caveat kinds"
            }
            out.add(m)
        }
        return out
    }

    private fun domainOf(v: String): String = v.substring(v.lastIndexOf('@') + 1).lowercase()

    /** The caveats of the grant a matching allow selector stands for, or null when it does not match this call. */
    private fun grantOf(sel: Map<String, Any?>, d: Map<String, Any?>, flat: Map<String, Any?>, eff: Map<String, Any?>): List<String>? {
        if (sel.containsKey("trait")) {
            val t = sel["trait"] as String
            if (!J.a(eff["closure"]).contains(if (t.contains(".")) t else "pca.$t")) return null
        }
        if (sel.containsKey("verb") && sel["verb"] != d["verb"]) return null
        val caveats = LinkedHashSet<String>()
        if (sel["caveats"] is List<*>) for (c in J.a(sel["caveats"])) caveats.add(c as String)
        val where = sel["where"]
        if (where is Map<*, *>) for ((key, cond) in J.m(where)) {
            val dom = key.endsWith(".domain")
            val name = if (dom) key.substring(0, key.length - ".domain".length) else key
            val pd = J.m(d["params"])[name] ?: return null
            val v = flat[name]
            if (v == null && !flat.containsKey(name)) return null
            if (cond is List<*>) {
                if (v !is String || !cond.contains(if (dom) domainOf(v) else v)) return null
            } else if (cond is Map<*, *>) {
                val n = J.num(v)
                val cm = J.m(cond)
                if (n == null || (cm.containsKey("max") && n > J.num(cm["max"])!!) || (cm.containsKey("min") && n < J.num(cm["min"])!!)) return null
            } else return null
            val role = if (J.get(pd, "role") != null) J.get(pd, "role") as String else ""
            if (role.startsWith("contact.") || role == "party.payee") caveats.add("recipient_scope")
            else if (role == "money.amount") caveats.add("amount_cap")
            else if (role == "count.limit") caveats.add("count_cap")
            else if (role.startsWith("id.")) caveats.add("resource_scope")
        }
        return ArrayList(caveats)
    }

    private fun floorDecision(grantCaveats: List<String>, maxEsc: Int, preauth: Int, context: Set<String>, rho: Map<String, Any?>): String {
        val esc = J.num(rho["esc"])!!.toLong()
        if (esc > maxEsc) return "deny"
        for (c in J.a(rho["caveats"])) if (!grantCaveats.contains(c)) return "escalate"
        for (c in J.a(rho["context"])) if (!context.contains(c)) return "escalate"
        return if (esc > preauth) "escalate" else "allow"
    }

    /** Decide one example: `{got, why}`. */
    fun decideExample(d: Map<String, Any?>, ex: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, defs: List<*>): Map<String, Any?> {
        val doc = ActionDerive.toSchemaDoc(defs, reg, J.obj("site", "https://example.invalid", "aud", "example", "version", "0"), null)
        val params = J.m(ex["params"])
        val flat = ActionDerive.flattenParams(params)
        val c = ActionSchema.conform(doc, d["verb"] as String, flat)
        if (!c.ok) return J.obj("got", "deny", "why", "schema_violation ${c.code}" + (if (c.path != null && c.path.isNotEmpty()) " (${c.path})" else ""))
        val op = ActionDerive.operationOf(d, params)
        if (op["ok"] != true) return J.obj("got", "deny", "why", op["reason"])
        val sels = parseUnder(ex["under"], ex.containsKey("under"))
        if (sels is String) return J.obj("got", "deny", "why", "bad example policy: $sels")
        val eff = hintOf(d, reg)
        val callCtx = HashSet<String>()
        val idem = d["idempotency"]
        if (idem != null && "natural" == J.get(idem, "mode")) callCtx.add("idempotency")
        if (idem != null && "key_param" == J.get(idem, "mode") && J.get(idem, "param") != null && flat.containsKey(J.get(idem, "param") as String)) callCtx.add("idempotency")
        val grantCaveats = LinkedHashSet<String>()
        var pre = 0
        for (s0 in J.a(sels)) {
            val s = J.m(s0)
            val g = grantOf(s, d, flat, eff) ?: continue
            pre = 3
            grantCaveats.addAll(g)
            if (s["context"] is List<*>) for (k in J.a(s["context"])) callCtx.add(k as String)
        }
        val rho = J.m(eff["eff"])
        val gc = ArrayList(grantCaveats)
        val got = floorDecision(gc, 3, pre, callCtx, rho)
        val why: String
        if (got == "allow") why = "floor satisfied"
        else {
            val need = ArrayList<String>()
            for (k in J.a(rho["caveats"])) if (!gc.contains(k)) need.add(k as String)
            for (k in J.a(rho["context"])) if (!callCtx.contains(k)) need.add(k as String)
            why = "floor needs " + (if (need.isEmpty()) "escalation tier " + J.jsStr(rho["esc"]) else need.joinToString(", "))
        }
        return J.obj("got", got, "why", why)
    }

    // ---- mutations of a conforming example ---------------------------------------------------------------------------------------

    private fun mutations(d: Map<String, Any?>, flat: Map<String, Any?>): List<Pair<String, Map<String, Any?>>> {
        val out = ArrayList<Pair<String, Map<String, Any?>>>()
        val extra = LinkedHashMap(flat)
        extra["zz_undeclared"] = "x"
        out.add("extra param" to extra)
        val keys = ArrayList(flat.keys)
        keys.sort()
        val ps = J.m(d["params"])
        for (k in keys) {
            val pd = ps[k] ?: continue
            val p = J.m(pd)
            if (p["required"] != false) {
                val w = LinkedHashMap(flat)
                w.remove(k)
                out.add("missing $k" to w)
            }
            val v = flat[k]
            val sw = LinkedHashMap(flat)
            sw[k] = if (v is String) J.n(12345) else if (J.num(v) != null || v is Boolean) "x" else LinkedHashMap<String, Any?>()
            out.add("type swap $k" to sw)
            if (J.num(v) != null && "integer" == p["type"]) {
                if (p.containsKey("max")) { val m = LinkedHashMap(flat); m[k] = J.n((J.num(p["max"])!! + 1).toLong()); out.add("above max $k" to m) }
                if (p.containsKey("min")) { val m = LinkedHashMap(flat); m[k] = J.n((J.num(p["min"])!! - 1).toLong()); out.add("below min $k" to m) }
            }
            if (v is String && "string" == p["type"]) {
                if (p["values"] != null) { val m = LinkedHashMap(flat); m[k] = "not_a_listed_value_zz"; out.add("outside values $k" to m) }
                if (p.containsKey("max_len")) { val m = LinkedHashMap(flat); m[k] = "x".repeat((J.num(p["max_len"])!! + 1).toInt()); out.add("too long $k" to m) }
            }
        }
        return out
    }

    private fun coreTraitIds(): List<String> = ArrayList(Actions.CORE_REGISTRY.keys)

    /**
     * Run examples and property checks for a set of defs (one pack). `propLimit` bounds the trait subsets tried per def (null = 256). The digest check across the
     * YAML form hands `{ns, actions: [def]}` to `yamlLoader` (a YAML front end: stringify, parse, load; null = the document is loaded as it is, which is
     * what a lossless YAML round trip yields). Returns `{examples, props, ok}`.
     */
    fun runDefTests(defs: List<*>, reg: Map<String, Map<String, Any?>>, propLimit: Int?, yamlLoader: ((Map<String, Any?>) -> Map<String, Any?>)?): Map<String, Any?> {
        val examples = ArrayList<Any?>()
        val props = ArrayList<Any?>()
        val limit = propLimit ?: 256
        for (d0 in defs) {
            val d = J.m(d0)
            val verb = d["verb"] as String
            if (d["examples"] is List<*>) {
                var index = 0
                for (ex0 in J.a(d["examples"])) {
                    val ex = J.m(ex0)
                    val r = decideExample(d, ex, reg, defs)
                    examples.add(J.obj("verb", verb, "index", J.n(index.toLong()), "expect", ex["expect"], "got", r["got"], "ok", r["got"] == ex["expect"], "why", r["why"]))
                    index++
                }
            }
            // T2: adding any core trait never lowers the effective profile
            val eff = hintOf(d, reg)
            val effP = J.m(eff["eff"])
            val lowered = ArrayList<String>()
            for (t in coreTraitIds()) if (!ActionEffective.leq(effP, ActionEffective.effWithTrait(d, t, reg))) lowered.add(t)
            props.add(J.obj("verb", verb, "name", "adding a trait never lowers the profile", "ok", lowered.isEmpty(), "detail", lowered.joinToString(", ")))

            // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
            val ts = J.a(eff["traits"])
            var bad = 0
            val total = Math.min(1L shl Math.min(ts.size, 20), limit.toLong())
            val top = Actions.floorOf(reg, ts)
            var mask = 0
            while (mask < total) {
                val sub = ArrayList<Any?>()
                for (i in 0 until ts.size) if (((mask shr (i and 31)) and 1) != 0) sub.add(ts[i])
                if (!ActionEffective.leq(Actions.floorOf(reg, sub), top)) bad++
                mask++
            }
            props.add(J.obj("verb", verb, "name", "floors are monotone over trait subsets", "ok", bad == 0, "detail", "$total subsets, $bad violations"))

            // one digest across the JSON and YAML forms
            val want = Actions.defDigest(d)
            val viaJson = ActionAuthor.loadActionsValue(d)
            val doc = J.obj("ns", verb.split(".")[0], "actions", J.list(d))
            val viaYaml = if (yamlLoader != null) yamlLoader(doc) else ActionAuthor.loadActionsValue(doc)
            val okJ = digestOk(viaJson, want)
            val okY = digestOk(viaYaml, want)
            props.add(
                J.obj(
                    "verb", verb, "name", "one digest across JSON and YAML forms", "ok", okJ && okY,
                    "detail", if (okJ && okY) "" else "json " + (if (okJ) "ok" else firstMessage(viaJson)) + "; yaml " + (if (okY) "ok" else firstMessage(viaYaml)),
                ),
            )

            // schema round trip: each example conforms, every mutation is refused
            if (d["examples"] !is List<*> || J.a(d["examples"]).isEmpty()) {
                props.add(J.obj("verb", verb, "name", "schema round trip", "ok", true, "detail", "skipped: no examples"))
                continue
            }
            val sdoc = ActionDerive.toSchemaDoc(defs, reg, J.obj("site", "https://example.invalid", "aud", "example", "version", "0"), null)
            val accepted = LinkedHashSet<String>()
            var tried = 0
            for (ex0 in J.a(d["examples"])) {
                val flat = ActionDerive.flattenParams(J.m(J.get(ex0, "params")))
                if (!ActionSchema.conform(sdoc, verb, flat).ok) continue // a deliberately non-conforming example is a deny example
                for (m in mutations(d, flat)) {
                    tried++
                    if (ActionSchema.conform(sdoc, verb, m.second).ok) accepted.add(m.first)
                }
            }
            props.add(J.obj("verb", verb, "name", "schema round trip", "ok", accepted.isEmpty(), "detail", if (accepted.isEmpty()) "$tried mutations refused" else "accepted: " + accepted.joinToString(", ")))
        }
        var ok = true
        for (e in examples) if (J.get(e, "ok") != true) ok = false
        for (q in props) if (J.get(q, "ok") != true) ok = false
        return J.obj("examples", examples, "props", props, "ok", ok)
    }

    private fun digestOk(r: Map<String, Any?>, want: String): Boolean =
        J.a(r["errors"]).isEmpty() && J.a(r["defs"]).isNotEmpty() && Actions.defDigest(J.m(J.a(r["defs"])[0])) == want

    private fun firstMessage(r: Map<String, Any?>): String {
        val errs = J.a(r["errors"])
        return if (errs.isEmpty()) "digest differs" else J.get(errs[0], "message").toString()
    }

    /** The report as plain lines, one PASS or FAIL per example and property, then a count. */
    fun testText(r: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        for (e in J.a(r["examples"])) {
            lines.add((if (J.get(e, "ok") == true) "PASS" else "FAIL") + "  " + J.get(e, "verb") + " example " + (J.num(J.get(e, "index"))!!.toLong() + 1) + ": expected " + J.get(e, "expect") + ", got " + J.get(e, "got") + " (" + J.get(e, "why") + ")")
        }
        for (q in J.a(r["props"])) {
            val detail = J.get(q, "detail") as String?
            lines.add((if (J.get(q, "ok") == true) "PASS" else "FAIL") + "  " + J.get(q, "verb") + " " + J.get(q, "name") + (if (detail != null && detail.isNotEmpty()) ": $detail" else ""))
        }
        val f = lines.count { it.startsWith("FAIL") }
        lines.add("${lines.size - f} passed, $f failed")
        return lines.joinToString("\n")
    }
}
