package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json

import java.math.BigDecimal
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Runtime drift monitoring, tighten-only. A monitor compares the action stream to the goal's expected profile (verbs, resources,
 * magnitude, rate, novelty). Anomalies convert allow to escalate; the strike counter is a ratchet; at `lockdown` strikes every
 * allow becomes escalate. [applyDrift] can never relax a decision.
 */
object GoalDrift {
    /** Defaults: windowMs 60000, maxPerWindow 20, maxNovel 3, magnitudeFactor 3, warmup 5, lockdown 5. */
    @JvmStatic
    fun defaults(): MutableMap<String, Any?> = G.map(
        "windowMs" to G.num(60000), "maxPerWindow" to G.num(20), "maxNovel" to G.num(3), "magnitudeFactor" to G.num(3), "warmup" to G.num(5), "lockdown" to G.num(5),
    )

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    /** The verbs of the goal's grants. */
    @JvmStatic
    fun expectedVerbs(g: Map<String, Any?>): Set<String> {
        val out = LinkedHashSet<String>()
        for (gr in G.arr(g["grants"], "grants")) out.add(G.get(gr, "verb") as String)
        return out
    }

    private fun resIds(s: Map<String, Any?>?, out: MutableSet<String>) {
        when (G.kind(s)) {
            "exact" -> out.add(s!!["id"] as String)
            "oneof" -> for (i in G.arr(s!!["ids"], "ids")) out.add(i as String)
            "all_of" -> for (p in G.arr(s!!["parts"], "parts")) resIds(mm(p), out)
            else -> {}
        }
    }

    private fun knownResources(g: Map<String, Any?>): Set<String> {
        val out = LinkedHashSet<String>()
        for (gr in G.arr(g["grants"], "grants")) resIds(mm(G.get(gr, "res")), out)
        return out
    }

    private fun numStr(o: Any?): String {
        val d = G.dbl(o) ?: return G.jsStr(o)
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return BigDecimal(d).toPlainString()
        return G.jsStr(o)
    }

    private fun freshState(): MutableMap<String, Any?> =
        G.map("strikes" to G.num(0), "times" to ArrayList<Any?>(), "novel" to ArrayList<Any?>(), "seen" to LinkedHashMap<String, Any?>())

    private fun hmac(key: ByteArray, text: String): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(if (key.isEmpty()) ByteArray(1) else key, "HmacSHA256"))
        return m.doFinal(Json.utf8(text))
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder()
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    /** Node's Buffer.from(s, 'hex'): decoding stops at the first non-hex pair. */
    private fun hexLenient(s: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i + 1 < s.length) {
            val hi = Character.digit(s[i], 16)
            val lo = Character.digit(s[i + 1], 16)
            if (hi < 0 || lo < 0 || s[i].code > 127 || s[i + 1].code > 127) break
            out.write(hi * 16 + lo)
            i += 2
        }
        return out.toByteArray()
    }

    /** One drift monitor over a goal. */
    class Monitor(private val goal: Map<String, Any?>, opts: Map<String, Any?>?) {
        private val o: MutableMap<String, Any?> = defaults()
        private var st: MutableMap<String, Any?> = freshState()

        init {
            if (opts != null) o.putAll(opts)
        }

        private fun opt(k: String): Double = G.toNum(o[k])

        /** Observe an action at time [t]: {anomalous, strikes, lockdown, reasons}. */
        fun observe(a: Map<String, Any?>, t: Any?): Map<String, Any?> {
            val reasons = ArrayList<Any?>()
            if (!expectedVerbs(goal).contains(a["verb"])) reasons.add("verb " + G.jsStr(a["verb"]) + " outside the goal profile")
            val known = knownResources(goal)
            val novel = G.l(st["novel"])!! as MutableList<Any?>
            if (known.isNotEmpty() && !known.contains(a["res"]) && !novel.contains(a["res"])) novel.add(a["res"])
            if (novel.size > opt("maxNovel")) reasons.add("novel resources beyond the allowance")
            val times = ArrayList<Any?>()
            for (x in G.arr(st["times"], "times")) if (G.toNum(x) > G.toNum(t) - opt("windowMs")) times.add(x)
            times.add(t)
            st["times"] = times
            if (times.size > opt("maxPerWindow")) reasons.add("rate above the profile")
            val params = mm(a["params"]) ?: throw IrError("params expected")
            val seen = mm(st["seen"])!! as MutableMap<String, Any?>
            for ((p, value) in params) {
                val l = mm(value)
                if (G.kind(l) != "q") continue
                val hist: List<Any?> = if (seen[p] == null) ArrayList() else G.l(seen[p])!!
                val v = mm(l!!["q"])!!["n"]
                if (hist.size >= opt("warmup")) {
                    var sum = 0.0
                    for (x in hist) sum += G.toNum(x)
                    val mean = sum / hist.size
                    if (mean > 0 && G.toNum(v) > mean * opt("magnitudeFactor")) reasons.add(p + " magnitude " + numStr(o["magnitudeFactor"]) + "x above the running mean")
                }
                val next = ArrayList<Any?>(hist)
                next.add(v)
                seen[p] = ArrayList<Any?>(next.subList(Math.max(0, next.size - 50), next.size))
            }
            if (reasons.isNotEmpty()) st["strikes"] = G.num(G.safeInt(st["strikes"])!! + 1)
            val strikes = G.safeInt(st["strikes"])!!
            return G.map("anomalous" to reasons.isNotEmpty(), "strikes" to G.num(strikes), "lockdown" to (strikes >= opt("lockdown")), "reasons" to reasons)
        }

        fun state(): Map<String, Any?> = st

        /** Sealed state: {state, mac} (HMAC-SHA256 over the state's JSON text, hex). */
        fun seal(key: ByteArray): Map<String, Any?> = G.map("state" to st, "mac" to hex(hmac(key, G.stringify(st))))

        companion object {
            /** Restore; a state that fails its MAC locks down (fail closed). */
            @JvmStatic
            fun restore(goal: Map<String, Any?>, sealed: Map<String, Any?>, key: ByteArray, opts: Map<String, Any?>?): Monitor {
                val m = Monitor(goal, opts)
                val want = hmac(key, G.stringify(sealed["state"]))
                val got = hexLenient(sealed["mac"].toString())
                if (got.size == want.size && MessageDigest.isEqual(got, want)) {
                    m.st = (mm(sealed["state"]) ?: throw NullPointerException("state")) as MutableMap<String, Any?>
                } else {
                    m.st = freshState()
                    m.st["strikes"] = G.num(m.opt("lockdown").toLong())
                }
                return m
            }
        }
    }

    /** Tighten-only: allow becomes escalate on an anomaly or lockdown; nothing else changes. */
    @JvmStatic
    fun applyDrift(d: String, signal: Map<String, Any?>): String =
        if ("allow" == d && (G.truthy(signal["anomalous"]) || G.truthy(signal["lockdown"]))) "escalate" else d

    /** Decide, observe, tighten: {decision, signal}. [c] = {act, rels, hist?}. */
    @JvmStatic
    fun guardedDecide(goal: Map<String, Any?>, ont: Map<String, Any?>, mon: Monitor, c: Map<String, Any?>, t: Any?): Map<String, Any?> {
        val base = GoalExamples.decideCase(goal, ont, c)["decision"] as String
        val signal = mon.observe(mm(c["act"])!!, t)
        return G.map("decision" to applyDrift(base, signal), "signal" to signal)
    }
}
