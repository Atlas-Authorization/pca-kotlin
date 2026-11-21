package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentAcc
import net.atlasauth.pca.verifier.IntentHistory
import net.atlasauth.pca.verifier.Json

/**
 * Trajectory intent as ordinary intent: the augmented outcome space adds to every verb one numeric dimension per accumulator (the value the
 * accumulator would have after the action) and one categorical dimension per monitor (its state), the lift of a candidate action into it, the
 * per-step admission rule, and the accumulators the wallet always adds. Psi, histories and schemas are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentTrajectory {
    const val ACC_DIM_PREFIX = "env.acc."
    const val MON_DIM_PREFIX = "env.mon."

    @JvmStatic fun accDimPath(id: String): String = ACC_DIM_PREFIX + id + ".post"

    @JvmStatic fun monDimPath(id: String): String = MON_DIM_PREFIX + id + ".state"

    private fun lm() = LinkedHashMap<String, Any?>()

    private fun m(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun utf8Cmp() = Comparator<String> { a, b -> Json.compareUtf8(a, b) }

    /** The v2 dimension kind of a path: param, acc, mon, canon, world, rel, prov, class or other. */
    @JvmStatic
    fun dimKindOf(path: String): String {
        if (path.startsWith("action.params.")) return "param"
        if (path.startsWith(ACC_DIM_PREFIX)) return "acc"
        if (path.startsWith(MON_DIM_PREFIX)) return "mon"
        if (path.startsWith("env.canon.")) return "canon"
        if (path.startsWith("env.world.")) return "world"
        if (path.startsWith("env.rel.")) return "rel"
        if (path.startsWith("env.prov.")) return "prov"
        if (path.startsWith("env.class.")) return "class"
        return "other"
    }

    private fun schemaVerb(schema: Any?, verb: String): Map<String, Any?>? {
        if (schema == null) return null
        for (v in IntentOmega.arr(m(schema)["verbs"])) if (verb == m(v)["verb"]) return m(v)
        return null
    }

    private fun predicateVerbs(verb: Any?): List<String> {
        val out = ArrayList<String>()
        if (verb is List<*>) for (x in verb) out.add(x as String) else out.add(verb as String)
        return out
    }

    private fun selects(a: Map<String, Any?>, verb: String, schema: Any?): Boolean {
        val sel = m(a["sel"])
        val vs = sel["verbs"]
        if (vs is List<*> && vs.contains(verb)) return true
        if (sel["accumulates_into"] != null) {
            val v = schemaVerb(schema, verb)
            return v != null && ActionSchema.accumulationParams(v, sel["accumulates_into"] as String).isNotEmpty()
        }
        return false
    }

    /**
     * The augmented space from the outcome space and Psi ({accumulators, monitors}). `opts`: cuts? (accumulator id to cuts), scope? ("all" | "selected"),
     * schema? ({verbs}). Wallet-held accumulators are not dimensions.
     */
    @JvmStatic
    fun augmentOmega(omega: Omega, psi: Map<String, Any?>, opts: Map<String, Any?>?): Omega {
        val o: Map<String, Any?> = opts ?: lm()
        val selected = "selected" == o["scope"]
        val cutsByAcc = if (o["cuts"] == null) lm() else m(o["cuts"])
        val verbs = ArrayList<VerbSpace>()
        for (vs in omega.verbs) {
            val extra = ArrayList<Dim>()
            for (ao in IntentOmega.arr(psi["accumulators"])) {
                val a = m(ao)
                if ("wallet" == m(a["holder"])["kind"]) continue
                if (selected && !selects(a, vs.verb, o["schema"])) continue
                if (a["domain_max"] == null) throw IllegalArgumentException("augmentOmega: accumulator '${a["id"]}' needs domain_max (A_ψ) to be a dimension of Ω̃")
                val dm = IntentOmega.dbl(a["domain_max"])
                val cuts = TreeSet<Double>()
                val accId = a["id"]
                val cb = if (accId is String) cutsByAcc[accId] else null
                if (cb != null) {
                    for (c in IntentOmega.arr(cb)) {
                        val x = if (IntentOmega.isNumber(c)) IntentOmega.dbl(c) else Double.NaN
                        if (x == Math.floor(x) && Math.abs(x) <= 9007199254740991.0 && x >= 0 && x <= dm) cuts.add(x + 0.0)
                    }
                }
                val cs = DoubleArray(cuts.size)
                var i = 0
                for (c in cuts) cs[i++] = c
                extra.add(NumDim(accDimPath(a["id"] as String), 0.0, dm, cs, "loguniform"))
            }
            for (mo in IntentOmega.arr(psi["monitors"])) {
                val mon = m(mo)
                if (selected) {
                    val q = mon["q"]
                    val keep = if (q == null) true else predicateVerbs(m(q)["verb"]).contains(vs.verb) || predicateVerbs(m(q)["verb"]).contains("*")
                    if (!keep) continue
                }
                val values = ArrayList<CatValue>()
                for (s in IntentAcc.monitorStates(mon)) values.add(CatValue("exact", s))
                extra.add(CatDim(monDimPath(mon["id"] as String), values))
            }
            val dims = ArrayList<Dim>()
            for (d in vs.dims) if (dimKindOf(d.path) != "acc" && dimKindOf(d.path) != "mon") dims.add(d)
            dims.addAll(extra)
            dims.sortWith(Comparator { a, b -> Json.compareUtf8(a.path, b.path) })
            verbs.add(VerbSpace(vs.verb, vs.reversibility, vs.weight, dims))
        }
        return Omega(verbs, ArrayList(omega.approximate))
    }

    /**
     * lift(history, action, t) as an outcome of the augmented space, or null when the verb is not in it. `cand`: verb, resource, params, t.
     * Throws where the accumulator or monitor computation does.
     */
    @JvmStatic
    fun liftAction(omegaTilde: Omega, psi: Map<String, Any?>, history: List<Any?>, cand: Map<String, Any?>, schema: Any?): Outcome? {
        val vs = omegaTilde.verbs.firstOrNull { it.verb == cand["verb"] } ?: return null
        val decl = schemaVerb(schema, cand["verb"] as String)
        val params = m(cand["params"])
        val values = lm()
        for (d in vs.dims) {
            val k = dimKindOf(d.path)
            if (k == "param") {
                val name = d.path.substring("action.params.".length)
                val x = if (params.containsKey(name)) params[name] else null
                if (IntentOmega.isNumber(x)) values[d.path] = IntentOmega.dbl(x)
                else if (x is String) values[d.path] = x
            } else if (k == "canon") {
                val name = d.path.substring("env.canon.".length)
                val pd = if (decl == null) null else m(decl["params"])["action.params.$name"]
                if (pd != null && params.containsKey(name)) values[d.path] = IntentSchema.canonValue(m(pd), params[name])
            } else if (k == "acc") {
                val id = d.path.substring(ACC_DIM_PREFIX.length, d.path.length - ".post".length)
                for (ao in IntentOmega.arr(psi["accumulators"])) {
                    if (id == m(ao)["id"]) {
                        val post = IntentHistory.accPost(m(ao), history, cand["verb"] as String, params, cand["t"], schema)
                        values[d.path] = post.toDouble()
                        break
                    }
                }
            } else if (k == "mon") {
                val id = d.path.substring(MON_DIM_PREFIX.length, d.path.length - ".state".length)
                for (mo in IntentOmega.arr(psi["monitors"])) {
                    if (id == m(mo)["id"]) {
                        values[d.path] = IntentHistory.monitorState(m(mo), history)
                        break
                    }
                }
            } else if (d.path == "action.resource") values[d.path] = cand["resource"]
        }
        return Outcome(cand["verb"] as String, values)
    }

    /** The space and per-dimension cell of a lifted outcome, or null when it lies outside the space. */
    class LiftedCell(@JvmField val vs: VerbSpace, @JvmField val cell: IntArray)

    @JvmStatic
    fun liftedCell(omegaTilde: Omega, o: Outcome): LiftedCell? {
        val vs = omegaTilde.verbs.firstOrNull { it.verb == o.verb } ?: return null
        val cell = IntentOmega.cellOf(vs, o) ?: return null
        return LiftedCell(vs, cell)
    }

    /** The result of one step: whether it was admitted, the new history, and the lifted outcome. */
    class Step(@JvmField val admitted: Boolean, @JvmField val history: List<Any?>, @JvmField val lifted: Outcome?)

    /** The trajectory-grant step rule: admit the action iff its lift lies in a cell `inGrant` accepts; the history gains a reserved event on admission. */
    @JvmStatic
    fun stepTrajectory(omegaTilde: Omega, psi: Map<String, Any?>, history: List<Any?>, cand: Map<String, Any?>, inGrant: (String, IntArray) -> Boolean, schema: Any?): Step {
        val lifted = liftAction(omegaTilde, psi, history, cand, schema)
        val c = if (lifted == null) null else liftedCell(omegaTilde, lifted)
        val ok = c != null && inGrant(cand["verb"] as String, c.cell)
        val next = ArrayList<Any?>(history)
        if (ok) {
            val ev = lm()
            ev["id"] = cand["id"]
            ev["verb"] = cand["verb"]
            ev["resource"] = cand["resource"]
            ev["params"] = cand["params"]
            ev["t"] = cand["t"]
            ev["status"] = "reserved"
            next.add(ev)
        }
        return Step(ok, next, lifted)
    }

    private fun sanitize(u: String): String {
        val s = u.replace(Regex("[^A-Za-z0-9_]"), "_")
        return if (s.length > 58) s.substring(0, 58) else s
    }

    private fun spendAcc(id: String, spendDomainMax: Double, holder: Map<String, Any?>, sel: Map<String, Any?>, extraKey: String, extraVal: Any?): Map<String, Any?> {
        val a = lm()
        a["id"] = id
        a["agg"] = "sum"
        a[extraKey] = extraVal
        a["sel"] = sel
        val win = lm()
        win["kind"] = "task"
        a["win"] = win
        a["key"] = null
        a["domain_max"] = spendDomainMax
        a["holder"] = holder
        return a
    }

    /**
     * The accumulators the wallet always adds: a per-task spend sum for every accumulation unit any verb feeds, a per-verb spend sum for every
     * untagged `money.amount` integer parameter, and the wallet-held question counter. `holder` defaults to site_local.
     */
    @JvmStatic
    fun defaultAccumulators(schema: Any?, spendDomainMax: Double, questionCap: Double?, holderIn: Map<String, Any?>?): List<Map<String, Any?>> {
        val holder: Map<String, Any?> = holderIn ?: linkedMapOf<String, Any?>("kind" to "site_local")
        val units = TreeSet<String>(utf8Cmp())
        val untagged = ArrayList<Pair<String, String>>()
        for (vo in IntentOmega.arr(m(schema)["verbs"])) {
            val v = m(vo)
            for ((pk, pv) in m(v["params"])) {
                val d = m(pv)
                val into: List<Any?> = if (d["accumulates_into"] is List<*>) IntentOmega.arr(d["accumulates_into"]) else ArrayList()
                for (u in into) units.add(u as String)
                if ("integer" == d["type"] && "money.amount" == d["semantic"] && into.isEmpty()) untagged.add((v["verb"] as String) to pk)
            }
        }
        val out = ArrayList<Map<String, Any?>>()
        for (u in units) {
            val a = spendAcc("spend_" + sanitize(u), spendDomainMax, holder, linkedMapOf<String, Any?>("accumulates_into" to u), "unit", u)
            out.add(a)
        }
        untagged.sortWith(Comparator { x, y -> Json.compareUtf8(x.first + x.second, y.first + y.second) })
        for (u in untagged) {
            val id = "spend_" + sanitize(u.first) + "_" + sanitize(u.second.substring("action.params.".length))
            out.add(spendAcc(if (id.length > 64) id.substring(0, 64) else id, spendDomainMax, holder, linkedMapOf<String, Any?>("verbs" to arrayListOf<Any?>(u.first)), "val", u.second))
        }
        val q = lm()
        q["id"] = "questions"
        q["agg"] = "count"
        q["sel"] = linkedMapOf<String, Any?>("event" to "intent_required")
        q["win"] = linkedMapOf<String, Any?>("kind" to "task")
        q["key"] = null
        q["cap"] = questionCap ?: 6.0
        q["holder"] = linkedMapOf<String, Any?>("kind" to "wallet")
        out.add(q)
        return out
    }

    /** The fact line for an accumulator dimension of a cell (`fmt`: amount renderer, default the integer; `thisAction` may be null). */
    @JvmStatic
    fun describeAccCell(d: NumDim, cellIndex: Int, label: String, thisAction: Double?, fmt: ((Double) -> String)?): String {
        val f: (Double) -> String = fmt ?: { x -> AttestUtil.jsNumString(x) }
        val cells = IntentOmega.numCells(d)
        if (cellIndex < 0 || cellIndex >= cells.size) throw IllegalArgumentException("describeAccCell: no such cell")
        val c = cells[cellIndex]
        val range = if (c.lo == c.hi) "exactly " + f(c.lo) else "between " + f(c.lo) + " and " + f(c.hi)
        return label + ": " + range + (if (thisAction != null) " (this action: " + f(thisAction) + ")" else "")
    }

    /** The per-session harm range of a trajectory Monte Carlo estimate: [0, L_max * H_max]. */
    @JvmStatic
    fun trajectoryHarmRange(maxSessionLength: Double, harmMax: Double): Double {
        if (!(maxSessionLength == Math.floor(maxSessionLength) && Math.abs(maxSessionLength) <= 9007199254740991.0 && maxSessionLength >= 0) || !(harmMax >= 0)) throw IllegalArgumentException("trajectoryHarmRange: bad arguments")
        return maxSessionLength * harmMax
    }
}
