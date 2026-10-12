package net.atlasauth.pca.verifier

import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Characterization snapshot of every observable verifier output over the conformance corpus (core + full adversarial) and
 * tools/pca-audit/native-mutation/inputs.jsonl.gz: verdict, diagnostic reason, rejection message, canonical forms.
 * Regenerate: java -cp ... net.atlasauth.pca.verifier.ReasonSnapshot test-data/reasons.tsv.gz
 */
object ReasonSnapshot {
    const val DIR = "conformance/"
    const val INPUTS = "../../tools/pca-audit/native-mutation/inputs.jsonl.gz"

    fun esc(s: String?): String {
        if (s == null) return "<null>"
        val b = StringBuilder()
        for (c in s) {
            when {
                c == '\\' -> b.append("\\\\")
                c == '\n' -> b.append("\\n")
                c == '\t' -> b.append("\\t")
                c == '\r' -> b.append("\\r")
                c.code < 0x20 || c.code in 0xd800..0xdfff -> b.append(String.format("\\u%04x", c.code))
                else -> b.append(c)
            }
        }
        return b.toString()
    }

    @Suppress("UNCHECKED_CAST")
    fun loadJson(name: String): Map<String, Any?> {
        if (name.endsWith(".gz"))
            GZIPInputStream(Files.newInputStream(Path.of(DIR + name))).use { return Json.parseLenient(String(it.readAllBytes(), StandardCharsets.UTF_8)) as Map<String, Any?> }
        return Json.parseLenient(Files.readString(Path.of(DIR + name))) as Map<String, Any?>
    }

    fun fmt(g: Pca.Verdict): String = "${g.allow}|${g.checks}|${esc(g.reason)}"

    @Suppress("UNCHECKED_CAST")
    fun verify(v: Map<String, Any?>): Pca.Verdict {
        val ctx = v["context"] as Map<String, Any?>
        val aud = ctx["aud"]
        val audience = if (aud is String) Pca.Audience.Of(aud) else Pca.Audience.Unset
        val allowed = (ctx["allowed_suites"] as? List<*>)?.map { it.toString() }
        val grant = v["grant"] as Map<String, Any?>
        return if (v.containsKey("pcactn_json")) Pca.verifyPcactnJson(v["pcactn_json"] as String, grant, Json.asLong(ctx["now"]), audience, allowed)
        else Pca.verifyPcactn(v["pcactn"], grant, Json.asLong(ctx["now"]), audience, allowed)
    }

    private fun guard(f: () -> String): String = try { f() } catch (t: Throwable) { "THROW:${t.javaClass.simpleName}:${esc(t.message)}" }

    fun parseOutcome(inp: String, lenient: Boolean): String = try {
        esc(Json.canonicalizeStrict(if (lenient) Json.parseLenient(inp) else Json.parse(inp)))
    } catch (t: Throwable) { "err|${t.javaClass.simpleName}|${esc(t.message)}" }

    @Suppress("UNCHECKED_CAST")
    fun compute(doc: Map<String, Any?>, tag: String, k: Int, step: Int): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val vs = doc["vectors"] as List<Any?>
        var i = k
        while (i < vs.size) {
            val v = vs[i] as Map<String, Any?>
            out["$tag:v:${v["name"]}"] = guard { fmt(verify(v)) }
            i += step
        }
        val prim = doc["primitives"] as? Map<String, Any?>
        if (k == 0 && prim != null) {
            (prim["json_parse"] as? List<Any?>)?.forEachIndexed { n, x ->
                val inp = (x as Map<String, Any?>)["input"] as String
                out["$tag:jp:$n:${esc(if (inp.length > 80) inp.substring(0, 80) else inp)}"] = parseOutcome(inp, false) + "|len=" + parseOutcome(inp, true)
            }
            (prim["canonical"] as? List<Any?>)?.forEachIndexed { n, x ->
                val value = (x as Map<String, Any?>)["value"]
                val s = guard { Json.canonicalizeStrict(value) + "|" + Pca.hashStrict(value) }
                val l = guard { Json.canonicalize(value) + "|" + Pca.hashCanonical(value) }
                out["$tag:cn:$n"] = esc(s) + "|" + esc(l)
            }
            (prim["b64u"] as? List<Any?>)?.forEachIndexed { n, x ->
                val b = x as Map<String, Any?>
                val len = if (b.containsKey("len")) Json.asLong(b["len"]).toInt() else -1
                val r = Pca.decodeB64uStrict(b["input"], len)
                out["$tag:b6:$n"] = if (r == null) "null" else Pca.b64(r)
            }
            (prim["chain_pin"] as? List<Any?>)?.forEach { x ->
                val cv = x as Map<String, Any?>
                val why = guard {
                    Pca.verifyChain(cv["chain"] as List<Any?>, cv["expected_root_issuer"] as? String ?: "", cv["expected_root_issuer"] is String,
                        (cv["allowed_suites"] as? List<*>)?.map { it.toString() }, cv["pq_pins"] as? Map<String, Any?>, cv["trusted_root"] as? Map<String, Any?>)
                }
                out["$tag:cp:${cv["name"]}"] = esc(why)
            }
        }
        return out
    }

    @Volatile private var inputsCache: List<Map<String, Any?>>? = null

    @Suppress("UNCHECKED_CAST")
    fun inputs(): List<Map<String, Any?>> {
        inputsCache?.let { return it }
        val l = ArrayList<Map<String, Any?>>()
        GZIPInputStream(Files.newInputStream(Path.of(INPUTS))).use { inp ->
            for (line in String(inp.readAllBytes(), StandardCharsets.UTF_8).split("\n")) if (line.isNotEmpty()) l.add(Json.parseLenient(line) as Map<String, Any?>)
        }
        inputsCache = l
        return l
    }

    @Suppress("UNCHECKED_CAST")
    fun computeInputs(k: Int, step: Int): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val all = inputs()
        var i = k
        while (i < all.size) {
            val c = all[i]
            val raw = c["raw"] as String
            var v: String
            if (c["kind"] == "verify") {
                v = guard {
                    val allowed = (c["allowed_suites"] as? List<*>)?.map { it.toString() }
                    val grant = Json.parseLenient(c["grant"] as String) as Map<String, Any?>
                    fmt(Pca.verifyPcactnJson(raw, grant, Json.asLong(c["now"]), Pca.Audience.Of(c["aud"] as String), allowed))
                }
            } else {
                v = parseOutcome(raw, false) + "|len=" + parseOutcome(raw, true)
            }
            if (v.length > 600) v = v.substring(0, 600) + "#" + v.length
            out["in:${c["id"]}"] = v
            i += step
        }
        return out
    }

    @Volatile private var cache: Map<String, String>? = null

    fun load(): Map<String, String> {
        cache?.let { return it }
        val m = HashMap<String, String>()
        GZIPInputStream(Files.newInputStream(Path.of("test-data/reasons.tsv.gz"))).use { inp ->
            for (l in String(inp.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                val t = l.indexOf('\t')
                if (t > 0) m[l.substring(0, t)] = l.substring(t + 1)
            }
        }
        cache = m
        return m
    }

    @JvmStatic
    fun main(a: Array<String>) {
        var err: Throwable? = null
        val t = Thread(null, { try { run(a) } catch (e: Throwable) { err = e } }, "big", 1L shl 29)
        t.start(); t.join()
        err?.let { throw it }
    }

    private fun run(a: Array<String>) {
        val all = LinkedHashMap<String, String>()
        all.putAll(compute(loadJson("vectors.json"), "core", 0, 1))
        all.putAll(compute(loadJson("vectors-adversarial.json.gz"), "adv", 0, 1))
        all.putAll(computeInputs(0, 1))
        GZIPOutputStream(File(a[0]).outputStream()).use { os ->
            for ((k, v) in all) os.write((esc(k) + "\t" + v + "\n").toByteArray(StandardCharsets.UTF_8))
        }
        println("wrote ${all.size} lines")
    }
}
