package net.atlasauth.pca.verifier

/**
 * TYPED MISSING CONTEXT and the STORED-WINS merge: when a permit condition cannot be decided because a value is absent, the decision
 * names what is missing and who may supply it (escalate), or denies when only the agent could say it. Request-supplied context never
 * replaces a value bound by the grant or chain. Port of packages/pca/src/missing-context.ts; replays
 * packages/pca/conformance/missing-context-vectors.json. Everything is total: any failure is a deny.
 */
object MissingContext {
    val SUPPLIERS = listOf("principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted")
    private val FORBIDDEN = setOf("__proto__", "constructor", "prototype")
    private val SUPPLIER_PATH = Regex("^(action\\.params|subject|env)(\\.[A-Za-z_][A-Za-z0-9_]*)*$")

    class Missing(val path: String, val supplier: String)

    class Bound(val context: Map<String, Any?>, val conflicts: List<String>, val dropped: List<String>)

    class Typed(val decision: String, val reason: String?, val missing: List<Missing>)

    /** The longest table key equal to [path] or a prefix of it at a segment boundary; none is `principal`. */
    @JvmStatic
    fun supplierOf(path: String, table: Map<String, Any?>): String {
        var best: String? = null
        for (k in table.keys) if ((path == k || path.startsWith("$k.")) && (best == null || k.length > best.length)) best = k
        return if (best == null) "principal" else table[best] as String
    }

    /** Null = a well-formed table. */
    @JvmStatic
    fun supplierTableError(t: Any?): String? {
        val m = K3Sig.map(t) ?: return "the supplier table must be an object"
        for ((k, v) in m) {
            if (!SUPPLIER_PATH.matches(k) || k.split(".").any { it in FORBIDDEN }) return "bad supplier path '$k'"
            if (v !is String || v !in SUPPLIERS) return "bad supplier for '$k'"
        }
        return null
    }

    private fun isObj(v: Any?): Boolean = v is Map<*, *>

    private fun copy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = copy(x) }
        is List<*> -> ArrayList<Any?>().also { o -> for (x in v) o.add(copy(x)) }
        else -> v
    }

    /** Flatten a plain-object tree into dotted leaf paths (sorted keys). Arrays and non-objects are leaves. */
    private fun leaves(v: Any?, prefix: String, out: MutableMap<String, Any?>, depth: Int = 0) {
        if (depth > 16) { out[prefix] = v; return }
        if (v is Map<*, *> && v.isNotEmpty()) {
            for (k in v.keys.map { it as String }.sorted()) if (k !in FORBIDDEN) leaves(v[k], "$prefix.$k", out, depth + 1)
        } else out[prefix] = v
    }

    @Suppress("UNCHECKED_CAST")
    private fun setPath(root: MutableMap<String, Any?>, segs: List<String>, value: Any?) {
        var cur = root
        for (i in 0 until segs.size - 1) {
            val s = segs[i]
            if (!cur.containsKey(s) || !isObj(cur[s])) cur[s] = LinkedHashMap<String, Any?>()
            cur = cur[s] as MutableMap<String, Any?>
        }
        cur[segs.last()] = value
    }

    private fun sameValue(a: Any?, b: Any?): Boolean = Pca.hashCanonical(mapOf("v" to a)) == Pca.hashCanonical(mapOf("v" to b))

    /** Merge [supplied] into [bound]. Bound wins; see the module comment. May throw on a malformed bound context (callers fail closed). */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun bindContext(bound: Map<String, Any?>, supplied: Any?, table: Map<String, Any?> = emptyMap()): Bound {
        val ctx = copy(bound) as MutableMap<String, Any?>
        val conflicts = ArrayList<String>()
        val dropped = ArrayList<String>()
        val sup = K3Sig.map(supplied) ?: return Bound(ctx, conflicts, dropped)
        val flat = LinkedHashMap<String, Any?>()
        val act = K3Sig.map(sup["action"])
        val ap = act?.get("params")
        if (act != null && isObj(ap)) leaves(ap, "action.params", flat)
        if (isObj(sup["subject"])) leaves(sup["subject"], "subject", flat)
        if (isObj(sup["env"])) leaves(sup["env"], "env", flat)
        for (path in flat.keys.sorted()) {
            val value = flat[path]
            if (supplierOf(path, table) == "agent_declared_untrusted") { dropped.add(path); continue }
            val r = Predicates.resolvePath(ctx, path)
            if (r.found) {
                if (!sameValue(r.value, value)) conflicts.add(path)
                continue
            }
            val segs = path.split(".")
            var blocked = false
            for (i in 2 until segs.size) {
                val r2 = Predicates.resolvePath(ctx, segs.subList(0, i).joinToString("."))
                if (r2.found && !isObj(r2.value)) blocked = true
            }
            if (blocked) { conflicts.add(path); continue }
            if (path.startsWith("action.params")) {
                val a = if (ctx.containsKey("action") && ctx["action"] != null) ctx["action"] else linkedMapOf<String, Any?>("verb" to "", "resource" to "")
                if (a !is MutableMap<*, *>) throw IllegalStateException("action is not an object")
                val am = a as MutableMap<String, Any?>
                if (!isObj(am["params"])) am["params"] = LinkedHashMap<String, Any?>()
                ctx["action"] = am
            }
            setPath(ctx, segs, copy(value))
        }
        return Bound(ctx, conflicts, dropped)
    }

    private fun isGroup(c: Any?): Boolean = c is Map<*, *> && (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not"))

    private fun collect(c: Any?, ctx: Map<String, Any?>, out: MutableSet<String>, ill: BooleanArray, depth: Int = 0) {
        if (depth > 64 || (c !is Map<*, *> && c !is List<*>)) { ill[0] = true; return }
        if (isGroup(c)) {
            val m = c as Map<*, *>
            val kids: Any? = if (m.containsKey("all_of")) m["all_of"] else if (m.containsKey("any_of")) m["any_of"] else listOf(m["not"])
            if (kids !is List<*> || kids.isEmpty()) { ill[0] = true; return }
            for (k in kids) collect(k, ctx, out, ill, depth + 1)
            return
        }
        if (Predicates.evaluateConditionTri(c, ctx) != Predicates.Tri.UNKNOWN) return
        val m = c as? Map<*, *>
        var absent = false
        if (m != null) {
            for (p in listOf(m["field"], m["ref"])) if (p is String && p.isNotEmpty() && !Predicates.resolvePath(ctx, p).found) { out.add(p); absent = true }
            val f = m["field"]
            if (f is String && (f == "action.params" || f.startsWith("action.params."))) {
                val p = (ctx["action"] as? Map<*, *>)?.get("params")
                if (p !is Map<*, *> && p !is List<*>) { out.add(f); absent = true }
            }
        }
        if (!absent) ill[0] = true
    }

    /** Decide a permit condition list (implicit AND) over the bound context plus whatever the request supplied. */
    @JvmStatic
    fun decideWithMissing(where: Any?, bound: Any?, supplied: Any? = null, suppliers: Any? = null): Typed {
        fun deny(reason: String, missing: List<Missing> = emptyList()) = Typed("deny", reason, missing)
        try {
            val bm = K3Sig.map(bound)
            if (bm == null || K3Sig.map(bm["action"]) == null) return deny("bad_context")
            val table = suppliers ?: emptyMap<String, Any?>()
            supplierTableError(table)?.let { return deny("bad supplier table: $it") }
            val tbl = K3Sig.map(table)!!
            if (where !is List<*> || where.isEmpty()) return deny("condition_false")
            val b = bindContext(bm, supplied, tbl)
            if (b.conflicts.isNotEmpty()) return deny("context_shadow: ${b.conflicts.joinToString(",")}")
            val t = Predicates.evaluateConditionTri(mapOf("all_of" to where), b.context)
            if (t == Predicates.Tri.TRUE) return Typed("allow", null, emptyList())
            if (t == Predicates.Tri.FALSE) return deny("condition_false")
            val paths = HashSet<String>()
            val ill = BooleanArray(1)
            for (c in where) collect(c, b.context, paths, ill)
            if (paths.isEmpty() || ill[0]) return deny("ill_typed_context")
            val missing = paths.sorted().map { Missing(it, supplierOf(it, tbl)) }
            val untrusted = missing.filter { it.supplier == "agent_declared_untrusted" }
            if (untrusted.isNotEmpty()) return deny("missing_context_untrusted: ${untrusted.joinToString(",") { it.path }}", missing)
            return Typed("escalate", "escalate: missing_context ${missing.joinToString(",") { "${it.supplier}:${it.path}" }}", missing)
        } catch (e: RuntimeException) {
            return deny("evaluation error (fail closed)")
        }
    }
}
