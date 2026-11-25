package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.Catalog

/**
 * Deriving the outcome space from the vocabulary of the policies and the structured intent slots, and compiling slots into
 * the policy they literally describe. Slots, policies and options are JSON trees (Map / List / String / Json.Num).
 */
object IntentDerive {
    private class Domain(val lo: Double, val hi: Double, val dist: String)

    /** Built-in numeric domains for common fields. */
    private val DEFAULT_DOMAINS: Map<String, Domain> = linkedMapOf(
        "action.params.amount" to Domain(0.0, 100000.0, "loguniform"),
        "env.hour" to Domain(0.0, 23.0, "uniform"),
        "action.params.count" to Domain(0.0, 1000.0, "loguniform"),
    )

    private class FieldLits {
        val nums = LinkedHashSet<Double>()
        val exacts = LinkedHashSet<String>()
        val prefixes = LinkedHashSet<String>()
    }

    private fun lits(m: MutableMap<String, FieldLits>, path: String): FieldLits = m.getOrPut(path) { FieldLits() }

    private fun addNum(f: FieldLits, x: Double) {
        if (x.isNaN() || x.isInfinite()) return
        f.nums.add(Math.floor(x) + 0.0)
        f.nums.add(Math.ceil(x) + 0.0)
    }

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    private fun collectCond(c: Any?, m: MutableMap<String, FieldLits>, approx: MutableSet<String>) {
        if (c !is Map<*, *>) return
        if (has(c, "all_of") || has(c, "any_of") || has(c, "not")) {
            if (has(c, "all_of") && get(c, "all_of") is List<*>) for (x in get(c, "all_of") as List<*>) collectCond(x, m, approx)
            else if (has(c, "any_of") && get(c, "any_of") is List<*>) for (x in get(c, "any_of") as List<*>) collectCond(x, m, approx)
            else if (has(c, "not")) collectCond(get(c, "not"), m, approx)
            return
        }
        val field = get(c, "field") as? String ?: return
        val op = get(c, "op")
        if (has(c, "ref")) approx.add("cross-field ref on $field")
        if ("like" == op || "matches" == op || "is_a" == op || "member_of" == op) approx.add("$op on $field")
        if ("exists" == op) {
            lits(m, field)
            return
        }
        val f = lits(m, field)
        val value = get(c, "value")
        val vals: List<Any?> = if (value is List<*>) ArrayList(value) else listOf(value)
        for (v in vals) {
            if (IntentOmega.isNumber(v)) addNum(f, IntentOmega.dbl(v))
            else if (v is String) (if ("prefix" == op) f.prefixes else f.exacts).add(v)
        }
    }

    private fun addResource(r: Any?, m: MutableMap<String, FieldLits>, approx: MutableSet<String>) {
        if (r !is String || r == "*") return
        if (r.startsWith("re:")) {
            approx.add("re: resource matcher")
            return
        }
        val f = lits(m, "action.resource")
        if (r.endsWith("*")) f.prefixes.add(r.substring(0, r.length - 1)) else f.exacts.add(r)
    }

    /** The verbs a predicate names, or null for the wildcard. */
    private fun verbsOf(p: Any?): List<String>? {
        val v = get(p, "verb")
        if (v is String) return if (v == "*") null else listOf(v)
        val out = ArrayList<String>()
        if (v is List<*>) {
            for (x in v) if (x is String && x == "*") return null
            for (x in v) if (x is String) out.add(x)
        }
        return out
    }

    /** Derive the space; [opts] members: policies, slots, domains, extraVerbs (all optional but policies). */
    @JvmOverloads
    fun deriveOmega(opts: Map<String, Any?>, catalog: Catalog = Catalog.DEFAULT): Omega {
        val approx = TreeSet<String>()
        val preds = ArrayList<Any?>()
        for (p in opts["policies"] as List<*>) preds.addAll(IntentPolicy.normalizePolicy(p)["predicates"] as List<*>)
        val explicit = TreeSet<String>()
        val extra = opts["extraVerbs"]
        if (extra is List<*>) for (x in extra) explicit.add(x as String)
        var wildcard = false
        for (p in preds) {
            val vs = verbsOf(p)
            if (vs == null) wildcard = true else explicit.addAll(vs)
        }
        val slots = opts["slots"]
        if (get(slots, "verbs") is List<*>) for (x in get(slots, "verbs") as List<*>) explicit.add(x as String)
        if (wildcard) {
            val connectors = LinkedHashSet<String>()
            for (v in explicit) connectors.add(v.split(".")[0])
            val pool = catalog.all().filter { connectors.isEmpty() || connectors.contains(it.connector) }
            for (s in pool) explicit.add(s.verb)
        }
        val constraints = ArrayList<Any?>()
        if (get(slots, "constraints") is List<*>) constraints.addAll(get(slots, "constraints") as List<*>)
        val domains = if (get(opts, "domains") is Map<*, *>) IntentOmega.obj(opts["domains"]) else null
        val out = ArrayList<VerbSpace>()
        for (verb in explicit) {
            val m = LinkedHashMap<String, FieldLits>()
            for (p in preds) {
                val pv = verbsOf(p)
                if (pv != null && !pv.contains(verb)) continue
                addResource(get(p, "resource"), m, approx)
                if (get(p, "where") is List<*>) for (c in get(p, "where") as List<*>) collectCond(c, m, approx)
            }
            for (sc in constraints) {
                if (has(sc, "verb") && verb != get(sc, "verb")) continue
                val f = lits(m, get(sc, "path") as String)
                if (has(sc, "max") && IntentOmega.isNumber(get(sc, "max"))) addNum(f, IntentOmega.dbl(get(sc, "max")))
                if (has(sc, "min") && IntentOmega.isNumber(get(sc, "min"))) addNum(f, IntentOmega.dbl(get(sc, "min")))
                strings(get(sc, "oneOf"), f.exacts)
                strings(get(sc, "noneOf"), f.exacts)
                strings(get(sc, "prefixOneOf"), f.prefixes)
            }
            val dims = ArrayList<Dim>()
            for (path in TreeSet(m.keys)) {
                val f = m[path]!!
                if (f.nums.size > 0 || (f.exacts.isEmpty() && f.prefixes.isEmpty() && DEFAULT_DOMAINS.containsKey(path))) {
                    val cuts = IntentOmega.sortedNums(f.nums)
                    val dom = DEFAULT_DOMAINS[path]
                    var dlo: Double? = dom?.lo
                    var dhi: Double? = dom?.hi
                    var ddist: String? = dom?.dist
                    if (domains != null && domains[path] is Map<*, *>) {
                        val o = IntentOmega.obj(domains[path])
                        dlo = IntentOmega.dbl(o["lo"])
                        dhi = IntentOmega.dbl(o["hi"])
                        ddist = o["dist"] as? String
                    }
                    val maxCut = if (cuts.isEmpty()) 0.0 else cuts[cuts.size - 1]
                    val minCut = if (cuts.isEmpty()) 0.0 else cuts[0]
                    val lo = dlo ?: Math.min(0.0, minCut - 1)
                    val hi = dhi ?: Math.max(Math.max(10.0, 2 * maxCut), maxCut + 10)
                    val dist = ddist ?: (if (lo >= 0) "loguniform" else "uniform")
                    val kept = cuts.filter { it >= lo && it <= hi }
                    dims.add(NumDim(path, lo, hi, IntentOmega.toArray(kept), dist))
                } else {
                    val values = ArrayList<CatValue>()
                    for (v in TreeSet(f.exacts)) values.add(CatValue("exact", v))
                    for (v in TreeSet(f.prefixes)) values.add(CatValue("prefix", v))
                    values.add(CatValue("other", IntentOmega.OTHER))
                    dims.add(CatDim(path, values))
                }
            }
            val spec = catalog.get(verb)
            out.add(VerbSpace(verb, spec?.reversibility ?: "irreversible", 0.0, dims))
        }
        for (v in out) v.weight = 1.0 / out.size
        return Omega(out, ArrayList(approx))
    }

    private fun strings(o: Any?, into: MutableCollection<String>) {
        if (o is List<*>) for (x in o) into.add(x as String)
    }

    // ---- slots ----

    private fun leaf(field: String?, op: String, value: Any?): MutableMap<String, Any?> = linkedMapOf("field" to field, "op" to op, "value" to value)

    private fun slotConds(sc: Any?): List<Any?> {
        val out = ArrayList<Any?>()
        val path = get(sc, "path") as String?
        if (has(sc, "min")) out.add(leaf(path, "gte", get(sc, "min")))
        if (has(sc, "max")) out.add(leaf(path, "lte", get(sc, "max")))
        val anyOf = ArrayList<Any?>()
        val oneOf = get(sc, "oneOf")
        if (oneOf is List<*> && oneOf.isNotEmpty()) anyOf.add(leaf(path, "in", ArrayList<Any?>(oneOf)))
        val pre = get(sc, "prefixOneOf")
        if (pre is List<*>) for (p in pre) anyOf.add(leaf(path, "prefix", p))
        if (anyOf.size == 1) out.add(anyOf[0])
        else if (anyOf.size > 1) out.add(linkedMapOf<String, Any?>("any_of" to anyOf))
        val none = get(sc, "noneOf")
        if (none is List<*> && none.isNotEmpty()) out.add(leaf(path, "nin", ArrayList<Any?>(none)))
        return out
    }

    /** Compile slots into the policy they literally describe (one predicate per slot verb). */
    fun slotsToPolicy(slots: Any?): MutableMap<String, Any?> {
        val predicates = ArrayList<Any?>()
        for (verb in get(slots, "verbs") as List<*>) {
            val where = ArrayList<Any?>()
            for (c in get(slots, "constraints") as List<*>) if (!has(c, "verb") || verb == get(c, "verb")) where.addAll(slotConds(c))
            val p = LinkedHashMap<String, Any?>()
            p["verb"] = verb
            p["resource"] = "*"
            if (where.isNotEmpty()) p["where"] = where
            predicates.add(p)
        }
        return linkedMapOf("predicates" to predicates, "caveats" to ArrayList<Any?>())
    }
}
