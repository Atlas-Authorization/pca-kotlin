package net.atlasauth.pca.verifier

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Replays every case of the reference oracle for the QRNG entropy module (HTTP source with an injected transport, SP 800-90B health
 * tests, HKDF mixing, secureSeed, the Ed25519 key helper): 562 cases, every fn dispatched, an unhandled fn fails the test. A reference
 * throw needs the native to throw (an argument a typed API cannot even receive counts as that refusal). Messages that start with "QRNG",
 * "HttpQrngSource", "mixEntropy" or "secureSeed" are compared exactly; JavaScript runtime texts are not.
 */
@Suppress("UNCHECKED_CAST")
class EntropyDiffTest {
    private val mod = "ref-entropy"
    private val exactPrefixes = listOf("QRNG", "HttpQrngSource", "mixEntropy", "secureSeed")

    private class Unrepresentable(m: String) : RuntimeException(m)

    /** A rejection that is not an Error object (the reference's bare string). */
    private class StringReject(val text: String) : RuntimeException(text)

    /** A transport failure with no message (the reference's non-Error throw: "unknown error"). */
    private class NoMessage : RuntimeException(null as String?)

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun dec(v: Any?): Any? = when (v) {
        is List<*> -> v.map { dec(it) }
        is Map<*, *> -> when {
            v.size == 1 && v["\$num"] is String -> when (v["\$num"]) { "NaN" -> Double.NaN; "Infinity" -> Double.POSITIVE_INFINITY; else -> Double.NEGATIVE_INFINITY }
            v.size == 1 && v["\$bytes"] is String -> Keys.unb64u(v["\$bytes"] as String)
            else -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = dec(x) }
        }
        else -> v
    }

    private fun bytes(o: Any?): ByteArray? = if (o == null || o is ByteArray) o as ByteArray? else throw Unrepresentable("not bytes")
    private fun str(o: Any?): String = o as? String ?: throw Unrepresentable("not a string")
    private fun dbl(o: Any?): Double = IntentJs.num(o) ?: throw Unrepresentable("not a number")

    /** An int the typed API can hold: an integral number that fits. */
    private fun integer(o: Any?): Int? {
        if (o == null) return null
        val d = IntentJs.num(o)
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || Math.abs(d) > Int.MAX_VALUE) throw Unrepresentable("not an int")
        return d.toInt()
    }

    /** For a positive-integer config field: anything the typed API cannot hold becomes -1, which the constructor refuses with the reference's message. */
    private fun posInt(o: Any?): Int? = try { integer(o) } catch (e: Unrepresentable) { -1 }

    private fun num(d: Double): Any = if (d.isNaN()) mapOf("\$num" to "NaN") else if (d.isInfinite()) mapOf("\$num" to if (d > 0) "Infinity" else "-Infinity") else d

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    // ---- the pure functions ----

    private fun call(fn: String, a: List<Any?>): Any? {
        val a0 = a.getOrNull(0)
        val a1 = a.getOrNull(1)
        val a2 = a.getOrNull(2)
        return when (fn) {
            "constants" -> linkedMapOf<String, Any?>(
                "MAX_HKDF_OUTPUT" to Entropy.MAX_HKDF_OUTPUT, "MIN_LOCAL_BYTES" to Entropy.MIN_LOCAL_BYTES, "DEFAULT_SEED_BYTES" to Entropy.DEFAULT_SEED_BYTES,
                "DEFAULT_MAX_QRNG_BYTES" to Entropy.DEFAULT_MAX_QRNG_BYTES, "DEFAULT_TIMEOUT_MS" to Entropy.DEFAULT_TIMEOUT_MS,
            )
            "repetitionCutoff" -> num(Entropy.repetitionCutoff(dbl(a0)))
            "proportionCutoff" -> num(Entropy.proportionCutoff(dbl(a0), dbl(a1)))
            "healthTestBytes" -> {
                if (a.size > 1 && a1 !is Map<*, *>) throw Unrepresentable("opts is not an object")
                val o: Map<String, Any?> = if (a1 == null) emptyMap() else m(a1)
                val v = Entropy.healthTestBytes(bytes(a0)!!, if (o.containsKey("h")) dbl(o["h"]) else 8.0, if (o.containsKey("window")) dbl(o["window"]) else 512.0)
                linkedMapOf<String, Any?>("ok" to v.ok).also { if (!v.ok) it["test"] = v.test }
            }
            "parseAnuUint8" -> Entropy.parseAnuUint8(a0)
            "parseHex" -> Entropy.parseHex(str(a0))
            "parseBase64" -> Entropy.parseBase64(net.atlasauth.pca.jose.Js.template(a0)) // the reference tests the string form (null is "null", 55 is "55")
            "mixEntropy" -> {
                val o: Map<String, Any?> = if (a2 == null) emptyMap() else m(a2)
                var ctx: String? = null
                if (o.containsKey("context")) {
                    val c = o["context"] ?: throw Unrepresentable("null context") // the reference reads .length of null
                    ctx = c as? String // a number has no length: no context
                }
                Entropy.mixEntropy(bytes(a0)!!, bytes(a1)!!, integer(o["length"]), ctx)
            }
            "nullQrng", "unavailableSource" -> {
                val src = if (fn == "nullQrng") (if (a0 == null) Entropy.NullQrngSource() else Entropy.NullQrngSource(str(a0))) else Entropy.unavailableSource(a0 as String?)
                val out = linkedMapOf<String, Any?>("name" to src.name)
                try { src.fetch(integer(a1)!!); out["ok"] = true } catch (e: Exception) { out["\$throws"] = e.message }
                out
            }
            "entropyError" -> {
                val e = EntropyError(str(a0), str(a1))
                linkedMapOf<String, Any?>("name" to e.javaClass.simpleName, "code" to e.code, "message" to e.message, "isError" to (e is Throwable))
            }
            else -> throw AssertionError("unhandled fn $fn")
        }
    }

    // ---- the structured cases: built from specs, compared as whole result maps ----

    private fun clsOf(e: Throwable): String = when (e) { is EntropyError -> "EntropyError"; is StringReject -> "string"; else -> "Error" }

    private fun errRec(e: Throwable): Map<String, Any?> {
        val r = linkedMapOf<String, Any?>("cls" to clsOf(e), "message" to ((if (e is StringReject) e.text else e.message) ?: ""))
        if (e is EntropyError) r["code"] = e.code
        return r
    }

    private fun seedOptions(o: Map<String, Any?>, reqs: MutableList<Int>, locals: MutableList<Int>, errs: MutableList<Any?>): Entropy.SecureSeedOptions {
        val so = Entropy.SecureSeedOptions()
        so.length = integer(o["length"])
        so.localBytes = integer(o["localBytes"])
        so.quantumBytes = integer(o["quantumBytes"])
        so.context = o["context"]?.let { str(it) }
        so.requireQuantum = o["requireQuantum"] == true
        val ht = o["healthTest"]
        if (ht == false) so.healthTest = null
        else if (ht is Map<*, *>) so.healthTest = Entropy.HealthTestOptions(if (ht.containsKey("h")) dbl(ht["h"]) else 8.0, if (ht.containsKey("window")) dbl(ht["window"]) else 512.0)
        val src = o["source"]
        if (src is Map<*, *>) {
            val sp = m(src)
            val nm = (sp["name"] ?: "test-src") as String
            val kind = sp["kind"] as String
            val msg = sp["message"] as String?
            so.source = object : Entropy.QrngSource {
                override val name: String = nm
                override fun fetch(numBytes: Int): ByteArray {
                    reqs.add(numBytes)
                    return when (kind) {
                        "bytes" -> sp["value"] as ByteArray
                        "reject", "throwSync" -> throw RuntimeException(msg)
                        "rejectString" -> throw StringReject(msg!!)
                        // the reference resolves to a string; a typed source cannot, so the library's own refusal text is raised directly
                        "nonbytes" -> throw IllegalStateException("QRNG: source returned non-bytes, expected $numBytes")
                        else -> throw AssertionError("bad source spec $kind")
                    }
                }
            }
        }
        val lo = o["local"]
        if (lo is Map<*, *>) {
            so.randomBytesImpl = { n ->
                locals.add(n)
                when (lo["kind"]) {
                    "fixed" -> lo["value"] as ByteArray
                    "throw" -> throw RuntimeException(lo["message"] as String)
                    else -> null
                }
            }
        }
        val hook = (o["hook"] ?: "none") as String
        if (hook != "none") so.onQrngError = { e -> errs.add(errRec(e)); if (hook == "throw") throw RuntimeException("hook boom") }
        return so
    }

    private fun runSeed(o: Map<String, Any?>, keypair: Boolean): MutableMap<String, Any?> {
        val reqs = ArrayList<Int>()
        val locals = ArrayList<Int>()
        val errs = ArrayList<Any?>()
        val got = LinkedHashMap<String, Any?>()
        try {
            val so = seedOptions(o, reqs, locals, errs)
            if (keypair) {
                val kp = Entropy.generateKeyPairWithEntropy(so)
                got["publicKey"] = kp.publicKey
                got["secretKeySha256"] = hex(MessageDigest.getInstance("SHA-256").digest(kp.secretKey))
                got["usedQuantum"] = kp.usedQuantum
            } else {
                val r = Entropy.secureSeed(so)
                got["seed"] = r.seed
                got["usedQuantum"] = r.usedQuantum
                got["quantumByteCount"] = r.quantumByteCount
                got["source"] = r.source
            }
        } catch (e: Unrepresentable) {
            got["\$throws"] = e.message; got["\$unrep"] = true
        } catch (e: RuntimeException) {
            got["\$throws"] = e.message
            if (e is EntropyError) got["code"] = e.code
        }
        got["qrngErrors"] = errs
        got["localRequested"] = locals.firstOrNull()
        got["requests"] = reqs
        return got
    }

    private fun runHttp(cfg: Map<String, Any?>, n: Any?, tr: Map<String, Any?>): MutableMap<String, Any?> {
        val log = ArrayList<Any?>()
        val c = HttpQrngSource.Config()
        c.url = cfg["url"] as? String
        c.apiKey = cfg["apiKey"] as String?
        c.apiKeyHeader = cfg["apiKeyHeader"] as String?
        if (cfg.containsKey("format")) {
            c.format = when (cfg["format"] as String) { "anu-uint8" -> HttpQrngSource.Format.ANU_UINT8; "hex" -> HttpQrngSource.Format.HEX; else -> HttpQrngSource.Format.BASE64 }
        }
        if (cfg.containsKey("timeoutMs")) c.timeoutMs = posInt(cfg["timeoutMs"])
        if (cfg.containsKey("maxBytes")) c.maxBytes = posInt(cfg["maxBytes"])
        c.lengthParam = cfg["lengthParam"] as String?
        c.extraParams = cfg["extraParams"]?.let { ep -> LinkedHashMap<String, String>().also { out -> for ((k, v) in m(ep)) out[k] = v as String } }
        c.allowInsecureLoopback = cfg["allowInsecureLoopback"] == true
        cfg["buildUrl"]?.let { bu -> val suffix = m(bu)["suffix"] as String; c.buildUrl = { base, k -> "$base/$k$suffix" } }
        val kind = tr["kind"] as String
        if (kind != "none") {
            val st = integer(tr["status"]) ?: 200
            val okFlag = if (tr["ok"] != null) tr["ok"] == true else st in 200..299
            c.transport = HttpQrngSource.Transport { req ->
                log.add(linkedMapOf<String, Any?>("url" to req.url, "headers" to LinkedHashMap(req.headers), "redirect" to req.redirect, "signal" to (req.timeoutMs > 0)))
                when (kind) {
                    "throw" -> throw RuntimeException(tr["message"] as String)
                    "throwString" -> throw NoMessage()
                    "hang" -> { Thread.sleep(Long.MAX_VALUE); throw IllegalStateException("unreachable") }
                }
                object : HttpQrngSource.Response {
                    override val ok: Boolean = okFlag
                    override val status: Int = st
                    override fun json(): Any? {
                        if (kind == "jsonThrows") throw RuntimeException("bad json")
                        if (kind == "json") return tr["body"]
                        throw IllegalStateException("json unused")
                    }
                    override fun text(): String {
                        if (kind == "textThrows") throw RuntimeException("read failed")
                        if (kind == "text") return tr["text"] as String
                        throw IllegalStateException("text unused")
                    }
                }
            }
        }
        val src = try {
            HttpQrngSource(c)
        } catch (e: IllegalArgumentException) {
            return linkedMapOf<String, Any?>("\$throws" to e.message)
        }
        return try {
            if (n == null) throw Unrepresentable("null count")
            linkedMapOf<String, Any?>("name" to src.name, "bytes" to src.fetch(integer(n)!!), "requests" to log)
        } catch (e: Exception) {
            val out = linkedMapOf<String, Any?>("\$throws" to e.message)
            if (e is Unrepresentable) out["\$unrep"] = true
            if (e is EntropyError) out["code"] = e.code
            out["name"] = src.name
            out["requests"] = log
            val key = c.apiKey
            out["leaksKey"] = !key.isNullOrEmpty() && e.message?.contains(key) == true
            out
        }
    }

    private fun exact(msg: String): Boolean = exactPrefixes.any { msg.startsWith(it) }

    /** Compares the whole result map; the reference's class names and JavaScript runtime texts are not part of the contract. */
    private fun compare(c: Map<String, Any?>, got: MutableMap<String, Any?>): String? {
        val want = LinkedHashMap(m(c["out"]))
        want.remove("cls")
        val wc = want["code"]
        if (wc is String && wc.startsWith("ERR_")) want.remove("code")
        val unrep = got.remove("\$unrep") != null
        val wt = want["\$throws"]
        if (wt is String && got["\$throws"] != null && (unrep || OracleCases.engineCrash(want) || !exact(wt))) want["\$throws"] = got["\$throws"]
        if (got["\$throws"] is String && want["\$throws"] == null) return "${c["name"]}\n  want: ${Json.canonicalize(want)}\n  got:  THROWS ${got["\$throws"]}"
        val norm = IntentJs.normalize(OracleCases.toJson(got))
        return if (IntentJs.jsonEquals(want, norm)) null else "${c["name"]}\n  want: ${Json.canonicalize(want)}\n  got:  ${Json.canonicalize(norm)}"
    }

    private val handled = setOf(
        "constants", "repetitionCutoff", "proportionCutoff", "healthTestBytes", "parseAnuUint8", "parseHex", "parseBase64", "mixEntropy", "secureSeed",
        "generateKeyPairWithEntropy", "httpQrng", "nullQrng", "unavailableSource", "entropyError",
    )

    /** The oracle holds exactly the fns this test dispatches (a new fn in the corpus fails here, never passes unreplayed). */
    @Test fun everyFnIsHandled() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        assertEquals(562, handled.sumOf { OracleCases.of(mod, it).size })
    }

    @Test fun replayAllCases() {
        val bad = ArrayList<String>()
        for (fn in handled) for (c in OracleCases.of(mod, fn)) {
            val args = dec(c["args"]) as List<Any?>
            val d = when (fn) {
                "secureSeed", "generateKeyPairWithEntropy" -> compare(c, runSeed(m(args[0]), fn == "generateKeyPairWithEntropy"))
                "httpQrng" -> compare(c, runHttp(m(args[0]), args[1], m(args[2])))
                "nullQrng", "unavailableSource" -> compare(c, call(fn, args) as MutableMap<String, Any?>)
                else -> OracleCases.diff(c, c["out"]) { call(fn, args) }
            }
            if (d != null) bad.add(d)
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    /** The platform CSPRNG path and a failing source round-trip through secureSeed without any injection. */
    @Test fun platformCsprngSeeds() {
        val a = Entropy.secureSeed()
        val b = Entropy.secureSeed()
        assertEquals(32, a.seed.size)
        assertFalse(a.seed.contentEquals(b.seed))
        val o = Entropy.SecureSeedOptions()
        o.source = Entropy.unavailableSource(null)
        assertFalse(Entropy.secureSeed(o).usedQuantum)
        o.requireQuantum = true
        try { Entropy.secureSeed(o); fail("must refuse") } catch (e: EntropyError) { assertEquals("quantum_required", e.code) }
    }
}
