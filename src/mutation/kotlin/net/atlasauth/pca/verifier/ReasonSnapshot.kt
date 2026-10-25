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
        val ip = if (ctx["intent_policy_json"] is String) Pca.IntentPolicy.fromJsonText(ctx["intent_policy_json"] as String)
            else Pca.IntentPolicy.fromJson(ctx["intent_policy"])
        val v2 = if (ctx.containsKey("intent_v2")) IntentV2.Context.fromJson(ctx["intent_v2"]) else null
        return if (v.containsKey("pcactn_json")) Pca.verifyPcactnJson(v["pcactn_json"] as String, grant, Json.asLong(ctx["now"]), audience, allowed, ip, v2)
        else Pca.verifyPcactn(v["pcactn"], grant, Json.asLong(ctx["now"]), audience, allowed, ip, v2)
    }

    /** The pinned verdict text of one Intent Layer v2 primitive (reasons included). */
    @Suppress("UNCHECKED_CAST")
    fun intentPrimitive(kind: String, input: Any?): String = when (kind) {
        "intent_schema" -> {
            val inp = IntentJs.normalize(input) as Map<String, Any?>
            val sig = ActionSchema.verify(inp["schema"], inp["keys"])
            val c = ActionSchema.conform(inp["schema"], inp["verb"] as String, inp["params"])
            "$sig|${if (sig == null) ActionSchema.digest(inp["schema"]) else ""}|${c.ok}|${c.code}|${c.path}|${c.reason}"
        }
        "intent_revocation" -> IntentRevocation.checkPrimitive(input).toString()
        "intent_world" -> {
            val r = OracleFacts.decideIntentWorld(input)
            "${r.ok}|${r.reason}|" + (if (r.ok) Json.canonicalize(r.world) + "|" + r.singleSource else "")
        }
        "intent_provenance" -> {
            val r = ParamProvenance.decide(input)
            "${r.outcome}|${r.reason}|${r.friction}|${Json.canonicalize(r.labels)}|${Json.canonicalize(r.classes)}|${Json.canonicalize(r.env)}"
        }
        "intent_wb_active" -> IntentWB.active(input).toList().toString()
        "intent_read_purpose" -> ParamProvenance.decideReadPurpose(input).let { "${it.outcome}|${it.minimise}|${it.uncovered}" }
        "intent_map_commit" -> IntentMap.commitLeaves((input as Map<String, Any?>)["leaves"])
        "intent_map" -> {
            val d = IntentMap.decidePrimitive(input)
            "${d.ok}|${d.reason}|" + (if (d.ok) "${d.cell}|${d.pPpm}|${d.residualRiskPpm}" else "")
        }
        else -> {
            val r = IntentClassifier.decide(input)
            "${r.ok}|${r.reason}|" + (if (r.ok) Json.canonicalize(r.classes) else "")
        }
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
            // Intent Layer v2 primitives: the verdict with its reason (rules 13 step 7, 14, 16, 17, 18)
            for (kind in listOf("intent_schema", "intent_revocation", "intent_world", "intent_provenance", "intent_classifier", "intent_wb_active", "intent_map_commit", "intent_map", "intent_read_purpose")) {
                (prim[kind] as? List<Any?>)?.forEach { x ->
                    val e = x as Map<String, Any?>
                    out["$tag:iv2:$kind:${e["name"]}"] = esc(guard { intentPrimitive(kind, (e["input_json"] as? String)?.let { Json.parseLenient(it) } ?: e["input"]) })
                }
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
                    fmt(Pca.verifyPcactnJson(raw, grant, Json.asLong(c["now"]), Pca.Audience.Of(c["aud"] as String), allowed,
                        if (c["intent_policy_json"] is String) Pca.IntentPolicy.fromJsonText(c["intent_policy_json"] as String)
                        else Pca.IntentPolicy.fromJson(c["intent_policy"]),
                        if (c.containsKey("intent_v2")) IntentV2.Context.fromJson(c["intent_v2"]) else null))
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
