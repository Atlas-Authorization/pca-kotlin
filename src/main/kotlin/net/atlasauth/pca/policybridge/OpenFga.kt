package net.atlasauth.pca.policybridge

import java.util.TreeSet

/**
 * OpenFGA / Zanzibar ReBAC model and tuples to PCA predicates: one permit per (user, object, relation) triple that holds, evaluated at
 * translation time over the whole tuple set (direct, computedUserset, union, intersection, difference and tupleToUserset, bounded and
 * cycle-guarded). Userset-valued tuples are reported and not expanded; anything unmodeled grants nothing.
 */
object OpenFga {
    private const val MAX_DEPTH = 32

    /** A translation with no tuples argument (the reference's `undefined`). */
    fun openfgaToPca(model: Any?): Map<String, Any?> = translate(model, null, false)

    /** A translation over [tuples]; anything but a list is an error (the reference's `null`). */
    fun openfgaToPca(model: Any?, tuples: Any?): Map<String, Any?> = translate(model, tuples, true)

    // ---- resolution plan ----

    private enum class PK { DIRECT, COMPUTED, UNION, INTERSECTION, DIFFERENCE, TTU }

    private class Plan(val kind: PK) {
        var relation: String? = null
        var tupleset: String? = null
        var computed: String? = null
        var children: List<Plan>? = null
        var base: Plan? = null
        var subtract: Plan? = null
    }

    private class Built(val ok: Boolean, val plan: Plan?, val partial: Boolean, val reason: String?) {
        companion object {
            fun fail(reason: String) = Built(false, null, false, reason)
        }
    }

    private class Tuple(val user: String, val relation: String, val obj: String)

    private fun describePlan(plan: Plan): String = when (plan.kind) {
        PK.DIRECT -> "direct"
        PK.COMPUTED -> "computed " + plan.relation
        PK.UNION -> "union[" + describeAll(plan.children!!) + "]"
        PK.INTERSECTION -> "intersection[" + describeAll(plan.children!!) + "]"
        PK.DIFFERENCE -> "difference(" + describePlan(plan.base!!) + " - " + describePlan(plan.subtract!!) + ")"
        PK.TTU -> plan.computed + " from " + plan.tupleset
    }

    private fun describeAll(ps: List<Plan>): String = ps.joinToString(", ") { describePlan(it) }

    private fun hasOwn(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null
    private fun isRewrite(v: Any?): Boolean = v is Map<*, *> || v is List<*>

    private fun childNodes(container: Any?): List<*>? = get(container, "child") as? List<*>

    /** The `.relation` string of a `{ relation }` object, or null. */
    private fun relationOf(v: Any?): String? {
        val rel = get(v, "relation")
        return if (rel is String && rel.isNotEmpty()) rel else null
    }

    private fun buildPlan(node: Any?): Built {
        if (hasOwn(node, "this")) return Built(true, Plan(PK.DIRECT), false, null)

        if (hasOwn(node, "computedUserset")) {
            val rel = relationOf(get(node, "computedUserset")) ?: return Built.fail("computedUserset without a relation")
            val p = Plan(PK.COMPUTED)
            p.relation = rel
            return Built(true, p, false, null)
        }

        if (hasOwn(node, "union")) {
            val children = childNodes(get(node, "union")) ?: return Built.fail("union without children")
            val subs = ArrayList<Plan>()
            var partial = false
            for (child in children) {
                if (!isRewrite(child)) { partial = true; continue }
                val sub = buildPlan(child)
                if (!sub.ok || sub.plan == null) { partial = true; continue }
                if (sub.partial) partial = true
                subs.add(sub.plan)
            }
            if (subs.isEmpty()) return Built(false, null, partial, "union with no modeled children")
            val p = Plan(PK.UNION)
            p.children = subs
            return Built(true, p, partial, null)
        }

        if (hasOwn(node, "intersection")) {
            val children = childNodes(get(node, "intersection")) ?: return Built.fail("intersection without children")
            val subs = ArrayList<Plan>()
            for (child in children) {
                if (!isRewrite(child)) return Built.fail("intersection child is not a rewrite")
                val sub = buildPlan(child)
                if (!sub.ok || sub.plan == null) return Built.fail("intersection child unmodeled (" + (sub.reason ?: "unsupported") + ")")
                subs.add(sub.plan)
            }
            if (subs.isEmpty()) return Built.fail("intersection with no children")
            val p = Plan(PK.INTERSECTION)
            p.children = subs
            return Built(true, p, false, null)
        }

        if (hasOwn(node, "difference")) {
            val diff = get(node, "difference")
            if (!(diff is Map<*, *> || diff is List<*>)) return Built.fail("malformed difference")
            val baseNode = get(diff, "base")
            val subNode = get(diff, "subtract")
            if (!isRewrite(baseNode) || !isRewrite(subNode)) return Built.fail("difference needs both base and subtract")
            val base = buildPlan(baseNode)
            val subtract = buildPlan(subNode)
            if (!base.ok || base.plan == null) return Built.fail("difference base unmodeled (" + (base.reason ?: "?") + ")")
            if (!subtract.ok || subtract.plan == null) return Built.fail("difference subtract unmodeled (" + (subtract.reason ?: "?") + ")")
            val p = Plan(PK.DIFFERENCE)
            p.base = base.plan
            p.subtract = subtract.plan
            return Built(true, p, base.partial || subtract.partial, null)
        }

        if (hasOwn(node, "tupleToUserset")) {
            val ttu = get(node, "tupleToUserset")
            if (!(ttu is Map<*, *> || ttu is List<*>)) return Built.fail("malformed tupleToUserset")
            val tuplesetRel = relationOf(get(ttu, "tupleset")) ?: return Built.fail("tupleToUserset without a tupleset relation")
            val computedRel = relationOf(get(ttu, "computedUserset")) ?: return Built.fail("tupleToUserset without a computedUserset relation")
            val p = Plan(PK.TTU)
            p.tupleset = tuplesetRel
            p.computed = computedRel
            return Built(true, p, false, null)
        }

        return Built.fail("unknown rewrite node")
    }

    // ---- model / tuple parsing ----

    /** type to (relation to rewrite node), in the reference's iteration order; null when the model is unusable. */
    private fun parseModel(model: Any?, report: Map<String, Any?>): Map<String, Map<String, Any?>>? {
        if (!(model is Map<*, *> || model is List<*>)) {
            PolicyBridge.list(report, "errors").add("model is not an object")
            return null
        }
        val defs = get(model, "type_definitions")
        if (defs !is List<*>) {
            PolicyBridge.list(report, "errors").add("model.type_definitions is missing or not an array")
            return null
        }
        val out = LinkedHashMap<String, Map<String, Any?>>()
        for (def in defs) {
            if (!(def is Map<*, *> || def is List<*>)) continue
            val type = get(def, "type")
            if (type !is String || type.isEmpty()) continue
            val relMap = LinkedHashMap<String, Any?>()
            val rels = PbJs.entries(get(def, "relations"))
            if (rels != null) {
                for ((k, v) in rels) if (isRewrite(v)) relMap[k] = v
            }
            out[type] = relMap
        }
        return out
    }

    private fun parseTuples(tuples: Any?, given: Boolean, report: Map<String, Any?>): List<Tuple> {
        if (tuples !is List<*>) {
            if (given) PolicyBridge.list(report, "errors").add("tuples is not an array")
            return ArrayList()
        }
        val out = ArrayList<Tuple>()
        for (t in tuples) {
            if (t !is Map<*, *>) continue
            val user = t["user"]
            val relation = t["relation"]
            val obj = t["object"]
            if (user is String && relation is String && obj is String) out.add(Tuple(user, relation, obj))
        }
        return out
    }

    private fun isWildcard(user: String): Boolean = user.endsWith(":*") && user.length > 2 && user.indexOf('#') < 0

    private fun escapeGlob(t: String): String {
        val sb = StringBuilder()
        for (c in t) {
            if (c == '*' || c == '?' || c == '\\') sb.append('\\')
            sb.append(c)
        }
        return sb.toString()
    }

    private fun typeOf(obj: String): String {
        val i = obj.indexOf(':')
        return if (i < 0) obj else obj.substring(0, i)
    }

    private fun objectOfUserset(p: String): String {
        val i = p.indexOf('#')
        return if (i < 0) p else p.substring(0, i)
    }

    private fun key(a: String, b: String): String = a + "\u0000" + b

    // ---- translation ----

    private fun translate(model: Any?, tuples: Any?, tuplesGiven: Boolean): Map<String, Any?> {
        val report = PolicyBridge.newReport("openfga")
        val predicates = ArrayList<Any?>()

        val typeRelations = parseModel(model, report)
        val tupleList = parseTuples(tuples, tuplesGiven, report)
        if (typeRelations == null) return PolicyBridge.result(predicates, ArrayList(), report)

        val direct = HashMap<String, MutableSet<String>>()
        val usersSeen = HashSet<String>()
        val wildcardTypes = HashSet<String>()
        val objectsSeen = HashSet<String>()
        var usersetTuples = 0
        for (t in tupleList) {
            objectsSeen.add(t.obj)
            direct.getOrPut(key(t.obj, t.relation)) { LinkedHashSet() }.add(t.user)
            if (t.user.indexOf('#') >= 0) usersetTuples++
            else if (isWildcard(t.user)) wildcardTypes.add(t.user.substring(0, t.user.length - 2))
            else usersSeen.add(t.user)
        }
        if (usersetTuples > 0) {
            PolicyBridge.list(report, "skipped").add("$usersetTuples userset-valued tuple(s) (user contains '#') not expanded to concrete users")
        }

        val plans = HashMap<String, Plan>()
        for ((type, rels) in typeRelations) {
            for ((relation, rewrite) in rels) {
                val built = buildPlan(rewrite)
                if (!built.ok || built.plan == null) {
                    PolicyBridge.list(report, "skipped").add("relation $type#$relation: " + (built.reason ?: "unsupported rewrite") + " — skipped")
                    continue
                }
                if (built.partial) {
                    PolicyBridge.list(report, "skipped").add("relation $type#$relation: some union children unsupported and dropped (under-approximated)")
                }
                plans[key(type, relation)] = built.plan
                PolicyBridge.list(report, "translated").add("relation $type#$relation (" + describePlan(built.plan) + ")")
            }
        }

        val ev = Evaluator(direct, plans)

        val sortedUsers = TreeSet(usersSeen)
        val sortedObjects = TreeSet(objectsSeen)
        val sortedWildcards = TreeSet(wildcardTypes)
        for (obj in sortedObjects) {
            val type = typeOf(obj)
            val relations = typeRelations[type]
            if (relations == null) {
                PolicyBridge.list(report, "skipped").add("object $obj: type \"$type\" not defined in model — ignored")
                continue
            }
            for (relation in TreeSet(relations.keys)) {
                if (!plans.containsKey(key(type, relation))) continue
                for (user in sortedUsers) {
                    if (ev.holdsRel(user, obj, relation, 0, HashSet())) {
                        val where = ArrayList<Any?>()
                        where.add(PbJs.obj("field", "subject.id", "op", "eq", "value", user))
                        predicates.add(PbJs.obj("verb", relation, "resource", obj, "where", where))
                    }
                }
                // A public tuple (`type:*`) grants every subject of that type, including ones no tuple names; decide for a subject
                // that no tuple names. The named ones were decided above (a difference or intersection may exclude them).
                for (wtype in sortedWildcards) {
                    if (!ev.holdsRel("$wtype:\u0000anyone", obj, relation, 0, HashSet())) continue
                    val named = ArrayList<Any?>()
                    for (u in sortedUsers) if (typeOf(u) == wtype) named.add(u)
                    val where = ArrayList<Any?>()
                    where.add(PbJs.obj("field", "subject.id", "op", "like", "value", escapeGlob(wtype) + ":*"))
                    if (named.isNotEmpty()) where.add(PbJs.obj("not", PbJs.obj("field", "subject.id", "op", "in", "value", named)))
                    predicates.add(PbJs.obj("verb", relation, "resource", obj, "where", where))
                }
            }
        }

        return PolicyBridge.result(predicates, ArrayList(), report)
    }

    /** Bounded, cycle-guarded evaluation of the plans over the direct tuples. */
    private class Evaluator(private val direct: Map<String, Set<String>>, private val plans: Map<String, Plan>) {
        fun holdsRel(user: String, obj: String, relation: String, depth: Int, visited: Set<String>): Boolean {
            val k = key(obj, relation)
            if (depth > MAX_DEPTH || visited.contains(k)) return false
            val plan = plans[key(typeOf(obj), relation)] ?: return false
            val next = HashSet(visited)
            next.add(k)
            return evalPlan(user, obj, relation, plan, depth, next)
        }

        fun evalPlan(user: String, obj: String, relation: String, plan: Plan, depth: Int, visited: Set<String>): Boolean {
            when (plan.kind) {
                PK.DIRECT -> {
                    val set = direct[key(obj, relation)]
                    return set != null && (set.contains(user) || set.contains(typeOf(user) + ":*"))
                }
                PK.COMPUTED -> return holdsRel(user, obj, plan.relation!!, depth + 1, visited)
                PK.UNION -> {
                    for (c in plan.children!!) if (evalPlan(user, obj, relation, c, depth, visited)) return true
                    return false
                }
                PK.INTERSECTION -> {
                    for (c in plan.children!!) if (!evalPlan(user, obj, relation, c, depth, visited)) return false
                    return true
                }
                PK.DIFFERENCE ->
                    return evalPlan(user, obj, relation, plan.base!!, depth, visited) && !evalPlan(user, obj, relation, plan.subtract!!, depth, visited)
                PK.TTU -> {
                    val related = direct[key(obj, plan.tupleset!!)] ?: return false
                    for (p in related) if (holdsRel(user, objectOfUserset(p), plan.computed!!, depth + 1, visited)) return true
                    return false
                }
            }
        }
    }
}
