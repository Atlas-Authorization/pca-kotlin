package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

/**
 * Replays a TypeScript-reference differential oracle (test-data/<module>.json.gz: a header line, then one case per line, each
 * {fn, name, args, out}). `out` is the reference's JSON result; {"$throws": msg, code?} means the reference threw, so the native must
 * throw too (and carry the same code when the native exception exposes a `code`). Bytes are {"$bytes": b64url}. Objects compare by
 * JSON value (numbers as JavaScript prints them), strings and codes exactly.
 */
object OracleCases {
    /** The cases of one fn; fails when the oracle has none (a renamed fn must not pass vacuously). */
    fun of(module: String, fn: String): List<Map<String, Any?>> =
        BaseOracle.cases("$module.json.gz", fn).also { assertFalse("no oracle cases for $module/$fn", it.isEmpty()) }

    /** Replay every case of [fn] through [f]; reports every divergent case at once. */
    fun each(module: String, fn: String, f: (List<Any?>) -> Any?) {
        // the generated RSA DPoP cases replay through the same function table when present (DpopDiffTest.rsaCorpusIsPresent enforces presence)
        val extra = if (module == "ref-dpop" && java.nio.file.Files.exists(BaseOracle.corpusPath("${BaseOracle.RSA}.json.gz"))) BaseOracle.cases("${BaseOracle.RSA}.json.gz", fn) else emptyList()
        val bad = (of(module, fn) + extra).mapNotNull { diff(it, it["out"], f) }
        assertTrue("${bad.size} divergent case(s) of $fn:\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    /** The shared JS-engine-crash definition: a V8 TypeError text the reference leaked on hostile input; the native must refuse, its message is not compared. */
    private val ENGINE_CRASH = Regex("Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack")

    /** True when [want] is {"$throws": msg} and msg is an engine-crash text (never a Node error code or any other message). */
    fun engineCrash(want: Any?): Boolean = want is Map<*, *> && (want["\$throws"] as? String)?.let { ENGINE_CRASH.containsMatchIn(it) } == true

    private fun codeOf(t: Throwable): String? = try {
        t.javaClass.methods.firstOrNull { it.name == "getCode" && it.parameterCount == 0 }?.invoke(t) as? String
    } catch (e: Exception) {
        null
    }

    fun diff(c: Map<String, Any?>, want: Any?, f: (List<Any?>) -> Any?): String? {
        var got: Any? = null
        var err: Throwable? = null
        try { got = f(c["args"].let { if (it is List<*>) it as List<Any?> else listOf(it) }) } catch (t: Throwable) { err = t }
        if (want is Map<*, *> && want.containsKey("\$throws")) {
            if (err == null) return "${c["name"]}\n  want: throw $want\n  got:  ${safe(toJson(got))}"
            if (engineCrash(want)) return null
            val code = want["code"]
            val gotCode = codeOf(err)
            return if (code == null || gotCode == null || code == gotCode) null else "${c["name"]}\n  want code: $code\n  got code:  $gotCode"
        }
        if (err != null) return "${c["name"]}\n  want: ${safe(want)}\n  got:  THROWS $err"
        val norm = IntentJs.normalize(toJson(got))
        return if (IntentJs.jsonEquals(want, norm)) null else "${c["name"]}\n  want: ${safe(want)}\n  got:  ${safe(norm)}"
    }

    private fun safe(o: Any?): String = try { Json.canonicalize(o) } catch (e: RuntimeException) { o.toString() }

    /** ByteArray -> {"$bytes": b64url}; Kotlin numbers -> JSON numbers; recursive over maps and lists. */
    fun toJson(v: Any?): Any? = when (v) {
        is ByteArray -> linkedMapOf<String, Any?>("\$bytes" to Keys.b64u(v))
        is Int, is Long, is Short -> Json.Num(v.toString())
        is Float -> Json.Num(Json.esNumber(v.toDouble()))
        is Double -> if (v == 0.0) Json.Num("0") else if (v.isNaN() || v.isInfinite()) linkedMapOf<String, Any?>("\$num" to (if (v.isNaN()) "NaN" else if (v > 0) "Infinity" else "-Infinity")) else Json.Num(Json.esNumber(v))
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k.toString()] = toJson(x) }
        is List<*> -> v.map { toJson(it) }
        else -> v
    }

    /** A tree with every {"$num": "NaN" | "Infinity" | "-Infinity"} replaced by that number, carried as a JSON number with JavaScript's text. */
    @Suppress("UNCHECKED_CAST")
    fun decNum(v: Any?): Any? = when (v) {
        is Map<*, *> -> if (v.size == 1 && v["\$num"] is String) Json.Num(v["\$num"] as String) else (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { decNum(it.value) }
        is List<*> -> v.map { decNum(it) }
        else -> v
    }

    /** The case's {label} / {pubLabel} / {len} key descriptor: the 32-byte seed sha256("atlas-pca-conformance/<label>"), its raw public key, or n zero bytes. */
    fun seed(label: String): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(Charsets.UTF_8))
}
