package net.atlasauth.pca.verifier

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runner of the pca-goal conformance vectors (the `conformance/goal` directory; `packages/pca-conformance/vectors/goal` in the monorepo):
 * an independent port of the reference semantics (goal digests, three-valued decisions with witnesses, and the helper functions:
 * canonical form, unit confusion, model polarity, meet, PEP, goal commitment, claim gate). Same corpus, same canonical outputs as the
 * Go, Rust and Python runners: ZERO disagreements, and the corpus size is pinned so a truncated vendoring fails.
 */
@Suppress("UNCHECKED_CAST")
class GoalVectorsTest {
    // ---- canonical form of the goal corpus (quote, backslash, \b \t \n \f \r short escapes, other controls as \u00xx; keys by UTF-8 bytes) ----
    private fun canon(v: Any?): String {
        val sb = StringBuilder()
        canonInto(sb, v)
        return sb.toString()
    }

    private fun canonString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\t' -> sb.append("\\t")
                c == '\n' -> sb.append("\\n")
                c == '\u000c' -> sb.append("\\f")
                c == '\r' -> sb.append("\\r")
                c.code < 0x20 -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    private fun canonInto(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is Json.Num -> sb.append(v.raw)
            is Int, is Long -> sb.append(v.toString())
            is String -> canonString(sb, v)
            is List<*> -> {
                sb.append('[')
                for ((i, e) in v.withIndex()) {
                    if (i > 0) sb.append(',')
                    canonInto(sb, e)
                }
                sb.append(']')
            }
            is Map<*, *> -> {
                val ks = v.keys.map { it as String }.sortedWith { a, b -> Json.compareUtf8(a, b) }
                sb.append('{')
                for ((i, k) in ks.withIndex()) {
                    if (i > 0) sb.append(',')
                    canonString(sb, k)
                    sb.append(':')
                    canonInto(sb, v[k])
                }
                sb.append('}')
            }
            else -> throw IllegalStateException("canon: ${v.javaClass}")
        }
    }

    private fun b64(h: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(h)
    private fun sha(s: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
    private fun hashCanon(v: Any?): String = b64(sha(canon(v)))
    private fun goalDigest(g: Any?): String = hashCanon(linkedMapOf("d" to "atlas-pca/goal-ir/v1", "goal" to g))

    private fun str(v: Any?): String = v as? String ?: ""
    private fun arr(v: Any?): List<Any?> = v as? List<Any?> ?: emptyList()
    private fun obj(v: Any?): Map<String, Any?> = v as? Map<String, Any?> ?: emptyMap()
    private fun ival(v: Any?): Long = (v as? Json.Num)?.raw?.toLongOrNull() ?: 0L
    private fun same(a: Any?, b: Any?): Boolean = canon(a) == canon(b)
    private fun has(xs: List<Any?>, x: Any?): Boolean = xs.any { same(it, x) }
    private fun b2k(b: Boolean): Int = if (b) 2 else 0

    // ---- Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow) ----
    private fun eqV(x: Map<String, Any?>, y: Map<String, Any?>): Int {
        if (str(x["k"]) == "q") {
            if (str(y["k"]) != "q" || !same(obj(x["q"])["u"], obj(y["q"])["u"])) return 1
            return b2k(ival(obj(x["q"])["n"]) == ival(obj(y["q"])["n"]))
        }
        if (str(x["k"]) == "s") return if (str(y["k"]) == "s") b2k(same(x["s"], y["s"])) else 1
        return 1
    }

    private fun ltV(x: Map<String, Any?>, y: Map<String, Any?>): Int {
        if (str(x["k"]) != "q" || str(y["k"]) != "q" || !same(obj(x["q"])["u"], obj(y["q"])["u"])) return 1
        return b2k(ival(obj(x["q"])["n"]) < ival(obj(y["q"])["n"]))
    }

    private fun cmp(op: String, x: Map<String, Any?>?, y: Map<String, Any?>?): Int {
        if (x == null || y == null) return 1
        when (op) {
            "eq" -> return eqV(x, y)
            "ne" -> return 2 - eqV(x, y)
            "lt" -> return ltV(x, y)
            "gte" -> return 2 - ltV(x, y)
            "gt" -> return ltV(y, x)
            "lte" -> return 2 - ltV(y, x)
        }
        var t = 1
        if (str(y["k"]) == "set") {
            t = 0
            for (it in arr(y["items"])) t = maxOf(t, eqV(x, obj(it)))
        }
        return if (op == "in") t else 2 - t
    }

    private fun term(t: Map<String, Any?>, act: Map<String, Any?>, h: Map<String, Any?>): Map<String, Any?>? {
        when (str(t["k"])) {
            "param" -> return obj(act["params"])[str(t["path"])] as? Map<String, Any?>
            "lit" -> return obj(t["v"])
        }
        val q = obj(h["aggs"])[str(t["bid"])] ?: return null
        return linkedMapOf("k" to "q", "q" to q)
    }

    private fun cond(c: Map<String, Any?>, act: Map<String, Any?>, h: Map<String, Any?>): Int =
        when (str(c["k"])) {
            "true" -> 2
            "cmp" -> cmp(str(c["op"]), term(obj(c["l"]), act, h), term(obj(c["r"]), act, h))
            "and" -> minOf(cond(obj(c["a"]), act, h), cond(obj(c["b"]), act, h))
            "or" -> maxOf(cond(obj(c["a"]), act, h), cond(obj(c["b"]), act, h))
            else -> 2 - cond(obj(c["c"]), act, h)
        }

    // ---- resource selectors, verbs, bounds ----
    private fun partIds(o: Map<String, Any?>, p: Map<String, Any?>): List<Any?> {
        when (str(p["k"])) {
            "exact" -> return listOf(p["id"])
            "oneof" -> return arr(p["ids"])
        }
        for (r in arr(o["rels"])) {
            val rr = obj(r)
            if (same(rr["rel"], p["rel"]) && same(rr["anchor"], p["anchor"])) return arr(rr["members"])
        }
        return emptyList()
    }

    /** Null means "any resource". */
    private fun resolve(o: Map<String, Any?>, s: Map<String, Any?>): List<Any?>? {
        if (str(s["k"]) == "any") return null
        if (str(s["k"]) != "all_of") return partIds(o, s)
        var acc: List<Any?>? = null
        for (p in arr(s["parts"]).reversed()) {
            val ids = partIds(o, obj(p))
            val cur = acc
            acc = if (cur == null) ids else ids.filter { has(cur, it) }
        }
        return acc
    }

    private fun resOk(p: List<Any?>?, r: Any?): Boolean = p == null || has(p, r)
    private fun verbsOfClass(o: Map<String, Any?>, cls: Any?): List<Any?> = arr(o["verbs"]).map { obj(it) }.filter { same(it["cls"], cls) }.map { it["verb"] }
    private fun prohVerbs(o: Map<String, Any?>, p: Map<String, Any?>): List<Any?> {
        val t = obj(p["target"])
        return if (str(t["k"]) == "verb") listOf(t["verb"]) else verbsOfClass(o, t["cls"])
    }

    private class Sel(val gids: List<Any?>, val verbs: List<Any?>)

    private fun lsel(o: Map<String, Any?>, b: Map<String, Any?>): Sel {
        val s = obj(b["sel"])
        return if (str(s["k"]) == "gids") Sel(arr(s["gids"]), emptyList()) else Sel(emptyList(), verbsOfClass(o, s["cls"]))
    }

    private fun applies(s: Sel, gid: Any?, verb: Any?): Boolean = has(s.gids, gid) || has(s.verbs, verb)

    private fun floorDiv(a: Long, b: Long): Long {
        var q = a / b
        if ((a % b != 0L) && ((a < 0) != (b < 0))) q--
        return q
    }

    private fun inScope(b: Map<String, Any?>, a: Map<String, Any?>, x: Map<String, Any?>): Boolean {
        val s = obj(b["scope"])
        return when (str(s["k"])) {
            "session" -> same(a["sess"], x["sess"])
            "principal" -> same(a["prin"], x["prin"])
            "org" -> same(a["org"], x["org"])
            else -> has(arr(s["agents"]), a["agent"]) && has(arr(s["agents"]), x["agent"])
        }
    }

    private fun inWindow(w: Map<String, Any?>, a: Map<String, Any?>, x: Map<String, Any?>): Boolean {
        val at = ival(a["t"])
        val xt = ival(x["t"])
        val ms = ival(w["ms"])
        return when (str(w["k"])) {
            "sliding" -> xt > at - ms && xt <= at
            "period" -> ms > 0 && floorDiv(at - ival(w["t0"]), ms) == floorDiv(xt - ival(w["t0"]), ms)
            else -> true
        }
    }

    /** Is the bound exceeded: 2 yes, 0 no, 1 unknown. */
    private fun exceeded(b: Map<String, Any?>, s: Sel, a: Map<String, Any?>, h: Map<String, Any?>): Int {
        val items = ArrayList<Map<String, Any?>>()
        for (m in arr(h["adms"])) {
            val x = obj(obj(m)["act"])
            if (applies(s, obj(m)["gid"], x["verb"]) && inScope(b, a, x) && inWindow(obj(b["window"]), a, x)) items.add(x)
        }
        items.add(a)
        val cap = ival(obj(b["cap"])["n"])
        when (str(b["agg"])) {
            "count" -> return b2k(items.size.toLong() > cap)
            "distinct" -> {
                val vs = HashSet<String>()
                for (x in items) {
                    val params = obj(x["params"])
                    val key = str(b["key"])
                    if (!params.containsKey(key)) return 1
                    vs.add(canon(params[key]))
                }
                return b2k(vs.size.toLong() > cap)
            }
        }
        var sum = 0L
        var mx = Long.MIN_VALUE
        for (x in items) {
            val v = term(obj(b["value"]), x, h)
            if (v == null || str(v["k"]) != "q" || !same(obj(v["q"])["u"], obj(b["cap"])["u"])) return 1
            val n = ival(obj(v["q"])["n"])
            sum += n
            if (n > mx) mx = n
        }
        return b2k((if (str(b["agg"]) == "sum") sum else mx) > cap)
    }

    private fun boundDec(b: Map<String, Any?>, s: Sel, a: Map<String, Any?>, h: Map<String, Any?>): Int {
        val e = exceeded(b, s, a, h)
        return if (e == 2) (if (str(b["onExceed"]) == "deny") 0 else 1) else if (e == 1) 1 else 2
    }

    /** Holes drop the grants they affect (all of them when global) and are then cleared. */
    private fun strip(g: Map<String, Any?>): Map<String, Any?> {
        val holes = arr(g["holes"]).map { obj(it) }
        val out = LinkedHashMap<String, Any?>(g)
        out["holes"] = emptyList<Any?>()
        out["grants"] = arr(g["grants"]).filter { gr -> holes.none { it["global"] == true || has(arr(it["affects"]), obj(gr)["gid"]) } }
        return out
    }

    private fun grantDec(g: Map<String, Any?>, o: Map<String, Any?>, gr: Map<String, Any?>, a: Map<String, Any?>, h: Map<String, Any?>): Int {
        val delegOk = ival(a["depth"]) == 0L || has(arr(obj(g["deleg"])["mayTouch"]), gr["gid"])
        var m = minOf(b2k(same(a["verb"], gr["verb"]) && delegOk), b2k(resOk(resolve(o, obj(gr["res"])), a["res"])), cond(obj(gr["cond"]), a, h))
        for (b in arr(g["bounds"])) {
            val bb = obj(b)
            val s = lsel(o, bb)
            if (applies(s, gr["gid"], a["verb"])) m = minOf(m, boundDec(bb, s, a, h))
        }
        return m
    }

    private fun decide(goal: Map<String, Any?>, o: Map<String, Any?>, a: Map<String, Any?>, h: Map<String, Any?>): Map<String, Any?> {
        val g = strip(goal)
        val v = obj(g["validity"])
        val at = ival(a["t"])
        val depth = ival(a["depth"])
        var d = 2
        if (at < ival(v["notBefore"]) || at > ival(v["notAfter"])) d = 0
        else if (ival(v["maxIdle"]) > 0 && ival(h["last"]) >= 0 && at - ival(h["last"]) > ival(v["maxIdle"])) d = 0
        else if (depth < 0 || depth > ival(obj(g["deleg"])["maxDepth"])) d = 0
        for (p in arr(g["prohibits"])) {
            val pp = obj(p)
            val m = minOf(b2k(has(prohVerbs(o, pp), a["verb"])), b2k(resOk(resolve(o, obj(pp["res"])), a["res"])), cond(obj(pp["cond"]), a, h))
            d = minOf(d, if (m == 2) 0 else if (m == 1) 1 else 2)
        }
        for (c in arr(g["escalateOn"])) d = minOf(d, if (cond(obj(c), a, h) == 0) 2 else 1)
        val grants = arr(g["grants"]).map { obj(it) }
        val per = grants.map { grantDec(g, o, it, a, h) }
        d = minOf(d, per.maxOrNull() ?: 0)
        if (d != 2) return linkedMapOf("decision" to (if (d == 1) "escalate" else "deny"), "witness" to null)
        val gr = grants[per.indexOf(2)]
        val bids = arr(g["bounds"]).map { obj(it) }.filter { applies(lsel(o, it), gr["gid"], a["verb"]) }.map { it["bid"] }
        return linkedMapOf("decision" to "allow", "witness" to linkedMapOf("gid" to gr["gid"], "bids" to bids))
    }

    // ---- lowering (the policy digest) ----
    private val neg = mapOf("eq" to "ne", "ne" to "eq", "lt" to "gte", "gte" to "lt", "gt" to "lte", "lte" to "gt", "in" to "nin", "nin" to "in")

    private fun nnf(c: Map<String, Any?>, pos: Boolean): Map<String, Any?> =
        when (str(c["k"])) {
            "true" -> linkedMapOf("k" to (if (pos) "true" else "false"))
            "cmp" -> linkedMapOf("k" to "atom", "op" to (if (pos) c["op"] else (neg[str(c["op"])] ?: c["op"])), "l" to c["l"], "r" to c["r"])
            "and" -> linkedMapOf("k" to (if (pos) "and" else "or"), "a" to nnf(obj(c["a"]), pos), "b" to nnf(obj(c["b"]), pos))
            "or" -> linkedMapOf("k" to (if (pos) "or" else "and"), "a" to nnf(obj(c["a"]), pos), "b" to nnf(obj(c["b"]), pos))
            else -> nnf(obj(c["c"]), !pos)
        }

    private fun pat(p: List<Any?>?): Map<String, Any?> = if (p == null) linkedMapOf("k" to "star") else linkedMapOf("k" to "set", "ids" to p)

    private fun lower(o: Map<String, Any?>, goal: Map<String, Any?>): Map<String, Any?> {
        val g = strip(goal)
        val ceils = arr(g["bounds"]).map { x ->
            val b = obj(x)
            val s = lsel(o, b)
            linkedMapOf<String, Any?>(
                "bid" to b["bid"], "selGids" to s.gids, "selVerbs" to s.verbs, "agg" to b["agg"], "value" to b["value"], "key" to b["key"],
                "window" to b["window"], "scope" to b["scope"], "cap" to b["cap"], "onExceed" to b["onExceed"],
            )
        }
        val preds = arr(g["grants"]).map { x ->
            val gr = obj(x)
            linkedMapOf<String, Any?>("gid" to gr["gid"], "verb" to gr["verb"], "res" to pat(resolve(o, obj(gr["res"]))), "cond" to nnf(obj(gr["cond"]), true))
        }
        val prohs = arr(g["prohibits"]).map { x ->
            val p = obj(x)
            linkedMapOf<String, Any?>("pid" to p["pid"], "verbs" to prohVerbs(o, p), "res" to pat(resolve(o, obj(p["res"]))), "cond" to nnf(obj(p["cond"]), true))
        }
        return linkedMapOf(
            "preds" to preds, "prohs" to prohs, "ceils" to ceils, "escs" to arr(g["escalateOn"]).map { nnf(obj(it), true) },
            "validity" to g["validity"], "deleg" to g["deleg"],
        )
    }

    // ---- helper functions ----
    private val rank = mapOf("deny" to 0, "escalate" to 1, "allow" to 2)

    private fun meet(d: String, s: String): String {
        val r = rank[s]
        return if (r != null && r < (rank[d] ?: 0)) s else d
    }

    private fun polarity(ws: List<Any?>): List<Any?> {
        val set = HashSet<String>()
        fun walk(c: Map<String, Any?>) {
            when (str(c["k"])) {
                "and", "or" -> {
                    walk(obj(c["a"]))
                    walk(obj(c["b"]))
                }
                "not" -> walk(obj(c["c"]))
                "cmp" -> for (k in listOf("l", "r")) {
                    val t = obj(c[k])
                    if (str(t["k"]) == "param") {
                        for (p in listOf("env.class.", "env.prov.", "env.judge.", "env.world.")) if (str(t["path"]).startsWith(p)) set.add(str(t["path"]))
                    }
                }
            }
        }
        for (w in ws) walk(obj(w))
        return ArrayList<Any?>(set.sortedWith { a, b -> Json.compareUtf8(a, b) })
    }

    private fun units(schema: Map<String, Any?>, terms: Map<String, Any?>): List<Any?> {
        val ks = ArrayList<String>()
        for (k in terms.keys) {
            if (!schema.containsKey(k) || !same(schema[k], terms[k])) ks.add(k)
        }
        return ArrayList<Any?>(ks.sortedWith { a, b -> Json.compareUtf8(a, b) })
    }

    private fun runFn(v: Map<String, Any?>): Any? {
        val i = obj(v["input"])
        when (str(v["fn"])) {
            "canon" -> return linkedMapOf("canon" to canon(v["input"]), "digest" to goalDigest(v["input"]))
            "units" -> return units(obj(i["schema"]), obj(i["terms"]))
            "polarity" -> return polarity(arr(v["input"]))
            "meet" -> return meet(str(i["decision"]), str(i["signal"]))
            "pep" -> {
                val d = str(i["decision"])
                if (d == "allow") return true
                if (d == "deny") return false
                val ans = obj(i["answer"])
                val ctx = obj(i["ctx"])
                if (i["answer"] == null || ans["valid"] != true) return false
                for (k in listOf("policy_digest", "action_digest", "history_head")) if (!same(ans[k], ctx[k])) return false
                return true
            }
            "commit" -> return linkedMapOf(
                "commit" to b64(sha("pca-goal:v3:commit:" + str(i["goal_digest"]) + ":" + str(i["policy_digest"]) + ":" + str(i["salt"]))),
                "opens_other_goal" to false,
            )
            "claim" -> {
                if (i["replayed_ppm"] != null && ival(i["replayed_ppm"]) < ival(i["min_ppm"])) return meet(str(i["base"]), "escalate")
                return str(i["base"])
            }
        }
        throw IllegalStateException("unknown fn ${v["fn"]}")
    }

    @Test
    fun everyGoalVectorAgreesWithTheReference() {
        val dir = ParityVectors.goalDir()
        val names = (dir.listFiles { f -> f.name.endsWith(".json") && f.name != "index.json" } ?: emptyArray<File>()).map { it.name }.sorted()
        val index = Json.parseLenient(File(dir, "index.json").readText(Charsets.UTF_8)) as Map<String, Any?>
        assertEquals("pca-goal-vectors/2", index["format"])
        assertEquals("every case of the index is present", (index["cases"] as List<*>).size, names.size)
        assertTrue("only ${names.size} goal vectors", names.size >= 240)
        val bad = ArrayList<String>()
        var probes = 0
        var fns = 0
        for (n in names) {
            val v = Json.parseLenient(File(dir, n).readText(Charsets.UTF_8)) as Map<String, Any?>
            if (str(v["kind"]) == "fn") {
                fns++
                if (canon(runFn(v)) != canon(v["expect"])) bad.add(str(v["id"]))
                continue
            }
            if (goalDigest(v["goal"]) != str(v["goal_digest"])) bad.add(str(v["id"]) + ":goal_digest")
            if (obj(v["compile"])["ok"] != true) continue
            if (hashCanon(lower(obj(v["ontology"]), obj(v["goal"]))) != str(v["policy_digest"])) bad.add(str(v["id"]) + ":policy_digest")
            for ((i, p) in arr(v["probes"]).withIndex()) {
                probes++
                val pp = obj(p)
                val got = decide(obj(v["goal"]), obj(v["ontology"]), obj(pp["action"]), obj(pp["history"]))
                if (canon(got) != canon(pp["expect"])) bad.add("${str(v["id"])}#$i")
            }
        }
        assertTrue("$fns helper vectors", fns >= 40)
        assertTrue("$probes probes", probes > 6000)
        assertTrue("${bad.size} disagreements: ${bad.take(20)}", bad.isEmpty())
    }

    @Test
    fun theHelperSemantics() {
        assertEquals("deny", meet("deny", "ok"))
        assertEquals("escalate", meet("allow", "escalate"))
        assertEquals("deny", meet("escalate", "deny"))
        assertEquals("allow", meet("allow", "ok"))
        val t: Map<String, Any?> = linkedMapOf("k" to "true")
        val u: Map<String, Any?> = linkedMapOf(
            "k" to "cmp", "op" to "lt",
            "l" to linkedMapOf("k" to "lit", "v" to linkedMapOf("k" to "s", "s" to "a")),
            "r" to linkedMapOf("k" to "lit", "v" to linkedMapOf("k" to "s", "s" to "b")),
        )
        fun not(c: Map<String, Any?>): Map<String, Any?> = linkedMapOf("k" to "not", "c" to c)
        fun bin(k: String, x: Map<String, Any?>, y: Map<String, Any?>): Map<String, Any?> = linkedMapOf("k" to k, "a" to x, "b" to y)
        val none = emptyMap<String, Any?>()
        fun c(x: Map<String, Any?>) = cond(x, none, none)
        val f = not(t)
        assertEquals(2, c(t)); assertEquals(1, c(u)); assertEquals(0, c(f))
        assertEquals(0, c(bin("and", bin("and", t, u), f)))
        assertEquals(1, c(bin("and", t, u)))
        assertEquals(2, c(bin("or", bin("or", f, u), t)))
        assertEquals(1, c(bin("or", f, u)))
        assertEquals(1, c(not(u)))
        assertEquals(-1L, floorDiv(-1, 5))
        assertEquals("{\"a\":[1,\"x\\n\"],\"b\":null}", canon(ParityVectors.parse("{\"b\":null,\"a\":[1,\"x\\n\"]}")))
    }
}
