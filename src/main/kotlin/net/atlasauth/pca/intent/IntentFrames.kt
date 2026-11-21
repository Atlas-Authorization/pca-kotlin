package net.atlasauth.pca.intent

import java.util.TreeMap
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates

/**
 * Frame and side-effect constraints: the monitored state of a site, a per-verb write set, and postconditions over the pre- and post-state and
 * the site's effect record. By default intent is frame-closed: a monitored variable outside the write set must not change unless the site's log
 * attributes the change to another actor. A violation is a negative runtime observation (it vetoes the cell). Specs, snapshots and reports are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentFrames {
    const val FRAME_STATE_DOMAIN = "atlas-pca/intent-frame-state/v1"

    private val INDEX = Regex("0|[1-9][0-9]{0,8}")

    private fun lm() = LinkedHashMap<String, Any?>()

    /** Digest of a state value (site-local: the lenient canonical form; an absent value is null). */
    @JvmStatic
    fun stateDigest(value: Any?): String {
        val m = lm()
        m["d"] = FRAME_STATE_DOMAIN
        m["v"] = value
        return Pca.b64(Pca.sha(Json.canonicalize(IntentJs.normalize(m)).toByteArray(Charsets.UTF_8)))
    }

    /** Snapshot already-read values: variable to {digest, value?}. */
    @JvmStatic
    fun snapshotState(values: Map<String, Any?>, keepValues: Boolean): Map<String, Any?> {
        val out = lm()
        for ((k, v) in values) {
            val s = lm()
            s["digest"] = stateDigest(v)
            if (keepValues) s["value"] = v
            out[k] = s
        }
        return out
    }

    /** Read every monitored variable through its reader (sorted by name) and snapshot it: the middleware hook, called before and after the action. */
    @JvmStatic
    fun captureState(readers: Map<String, () -> Any?>, keepValues: Boolean): Map<String, Any?> {
        val sorted = TreeMap<String, () -> Any?>(Comparator { a, b -> Json.compareUtf8(a, b) })
        sorted.putAll(readers)
        val values = lm()
        for ((k, r) in sorted) values[k] = r()
        return snapshotState(values, keepValues)
    }

    private fun step(cur: Any?, s: String): Pair<Boolean, Any?> {
        if (cur is Map<*, *>) {
            if (!cur.containsKey(s)) return false to null
            return true to cur[s]
        }
        if (cur is List<*> && INDEX.matches(s) && s.toInt() < cur.size) return true to cur[s.toInt()]
        return false to null
    }

    private fun get(root: Any?, path: String): Any? {
        var cur = root
        for (s in path.split(".")) {
            val r = step(cur, s)
            if (!r.first) return null
            cur = r.second
        }
        return cur
    }

    private fun present(root: Any?, path: String): Boolean {
        var cur = root
        for (s in path.split(".")) {
            val r = step(cur, s)
            if (!r.first) return false
            cur = r.second
        }
        return true
    }

    /** W(action): the declared write list, or the parameter-selected list (an unknown parameter value: the default, else empty). */
    @JvmStatic
    fun writeSetOf(spec: Map<String, Any?>, action: Map<String, Any?>): List<String> {
        val writes = IntentOmega.obj(spec["writes"])
        val verb = action["verb"]
        val d = if (verb is String && writes.containsKey(verb)) writes[verb] else null
        val out = ArrayList<String>()
        if (d == null) return out
        if (d is List<*>) { for (x in d) out.add(x as String); return out }
        val dm = IntentOmega.obj(d)
        val param = dm["param"] as String
        val v = get(action["params"] ?: lm(), if (param.startsWith("action.params.")) param.substring("action.params.".length) else param)
        val key = if (v is String) v else if (v is Boolean) v.toString() else if (IntentOmega.isNumber(v)) AttestUtil.jsNumString(IntentOmega.dbl(v)) else null
        val map = IntentOmega.obj(dm["map"])
        val chosen = if (key != null && map.containsKey(key)) map[key] else dm["default"]
        if (chosen != null) for (x in IntentOmega.arr(chosen)) out.add(x as String)
        return out
    }

    private fun envReads(c: Any?, out: MutableList<String>) {
        if (c !is Map<*, *>) return
        if (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not")) {
            if (c.containsKey("all_of") && c["all_of"] is List<*>) for (x in c["all_of"] as List<*>) envReads(x, out)
            else if (c.containsKey("any_of") && c["any_of"] is List<*>) for (x in c["any_of"] as List<*>) envReads(x, out)
            else if (c.containsKey("not")) envReads(c["not"], out)
            return
        }
        val f = c["field"]
        if (f is String) {
            if (f.startsWith("env.")) out.add(f)
            val ref = c["ref"]
            if (ref is String && ref.startsWith("env.")) out.add(ref)
        }
    }

    private fun nest(s: Map<String, Any?>): Map<String, Any?> {
        val root = lm()
        for ((k, ev) in s) {
            val v = IntentOmega.obj(ev)
            if (!v.containsKey("value")) continue
            val segs = k.split(".")
            var cur: MutableMap<String, Any?> = root
            for (i in 0 until segs.size - 1) {
                if (cur[segs[i]] !is Map<*, *>) cur[segs[i]] = lm()
                cur = cur[segs[i]] as MutableMap<String, Any?>
            }
            cur[segs[segs.size - 1]] = v["value"]
        }
        return root
    }

    private fun uniqSorted(xs: List<String>): List<String> = LinkedHashSet(xs).toList().sortedWith(Comparator { a, b -> Json.compareUtf8(a, b) })

    /**
     * Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions. `opts`: effect?,
     * attributions? ([{var, actor}]), self?. Returns {status, outOfFrame, attributed, postViolated, missing, unmonitored}; never throws.
     */
    @JvmStatic
    fun checkFrame(specO: Any?, actionO: Any?, preO: Any?, postO: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val outOfFrame = ArrayList<String>()
        val attributed = ArrayList<String>()
        val postViolated = ArrayList<String>()
        val missing = ArrayList<String>()
        var unmonitored = false
        try {
            if (specO !is Map<*, *> || specO["state"] !is List<*> || actionO !is Map<*, *> || preO !is Map<*, *> || postO !is Map<*, *>) {
                throw IllegalArgumentException("spec, action, pre and post must be objects (spec.state an array)")
            }
            val spec = IntentOmega.obj(specO)
            val action = IntentOmega.obj(actionO)
            val pre = IntentOmega.obj(preO)
            val post = IntentOmega.obj(postO)
            val state = IntentOmega.arr(spec["state"])
            unmonitored = state.isEmpty()
            val w = LinkedHashSet(writeSetOf(spec, action))
            val sortedState = state.map { it as String }.sortedWith(Comparator { a, b -> Json.compareUtf8(a, b) })
            val attrs = if (opts != null && opts["attributions"] != null) IntentOmega.arr(opts["attributions"]) else ArrayList<Any?>()
            val self = opts?.get("self")
            for (v in sortedState) {
                if (w.contains(v)) continue
                val a = pre[v]
                val b = post[v]
                if (a == null || b == null) { missing.add(v); continue }
                if (IntentOmega.obj(a)["digest"] == IntentOmega.obj(b)["digest"]) continue
                var other = false
                for (xo in attrs) {
                    val x = IntentOmega.obj(xo)
                    if (x["var"] == v && x["actor"] != self) other = true
                }
                (if (other) attributed else outOfFrame).add(v)
            }
            val env = lm()
            env["pre"] = nest(pre)
            env["post"] = nest(post)
            env["effect"] = if (opts != null && opts["effect"] != null) opts["effect"] else lm()
            val act = lm()
            act["verb"] = action["verb"]
            act["resource"] = action["resource"]
            act["params"] = action["params"] ?: lm()
            val ctx = lm()
            ctx["action"] = act
            ctx["env"] = env
            val envRoot = lm()
            envRoot["env"] = env
            val posts = if (spec["post"] == null) ArrayList<Any?>() else IntentOmega.arr(spec["post"])
            for (pco in posts) {
                val pc = IntentOmega.obj(pco)
                if (pc["verb"] != action["verb"]) continue
                var pending = false
                val deltas = if (pc["deltas"] == null) ArrayList<Any?>() else IntentOmega.arr(pc["deltas"])
                for (dO in deltas) {
                    val d = IntentOmega.obj(dO)
                    val x = get(env["pre"], d["path"] as String)
                    val y = get(env["post"], d["path"] as String)
                    if (!IntentOmega.isNumber(x) || !IntentOmega.isNumber(y)) {
                        missing.add("${pc["id"]}:${d["path"]}")
                        pending = true
                    } else if (IntentOmega.dbl(y) != IntentOmega.dbl(x) + IntentOmega.dbl(d["by"])) {
                        postViolated.add(pc["id"] as String)
                        pending = true
                        break
                    }
                }
                if (pending) continue
                val reads = ArrayList<String>()
                val where = if (pc["where"] == null) ArrayList<Any?>() else IntentOmega.arr(pc["where"])
                for (c in where) envReads(c, reads)
                val absent = ArrayList<String>()
                for (r in reads) if (!present(envRoot, r)) absent.add(r)
                if (absent.isNotEmpty()) {
                    for (r in absent) missing.add("${pc["id"]}:$r")
                    continue
                }
                if (where.isNotEmpty()) {
                    val pred = lm()
                    pred["verb"] = action["verb"]
                    pred["where"] = where
                    if (!Predicates.evaluatePredicates(listOf(pred), ctx)) postViolated.add(pc["id"] as String)
                }
            }
        } catch (e: RuntimeException) {
            missing.add("error: " + (if (e is IllegalArgumentException && e.message.toString().startsWith("spec, action")) e.message else "error"))
        }
        val miss = uniqSorted(missing)
        val pv = uniqSorted(postViolated)
        val rep = lm()
        rep["status"] = if (outOfFrame.isNotEmpty() || pv.isNotEmpty()) "violated" else if (miss.isNotEmpty()) "pending" else "ok"
        rep["outOfFrame"] = ArrayList<Any?>(outOfFrame)
        rep["attributed"] = ArrayList<Any?>(attributed)
        rep["postViolated"] = ArrayList<Any?>(pv)
        rep["missing"] = ArrayList<Any?>(miss)
        rep["unmonitored"] = unmonitored
        return rep
    }

    /** Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell; ok and pending change nothing. */
    @JvmStatic
    fun applyFrameReport(l: IntentLearner, o: Outcome, report: Any?): Map<String, Any?> {
        val r = lm()
        if (report !is Map<*, *> || "violated" != report["status"]) return r
        r["signal"] = "postcondition-violation"
        r["divergence"] = IntentMapKit.applyDivergence(l, o, 0)
        return r
    }
}
