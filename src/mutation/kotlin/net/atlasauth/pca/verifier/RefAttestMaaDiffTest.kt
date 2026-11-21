package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Azure MAA key trust against the reference (ref-attest-maa, 261 cases): the JWKS evaluation over real and forged certificates, the release-signed pins,
 * multi-vantage corroboration, the guarded certificates fetch over a scripted transport, the rotation-safe trust store (cache, rotation, staleness, corrupt
 * state, signed re-pin, built-in pins) and the durable state store. A refusal compares by `code`; a certificate rejection compares by its reason where the
 * reason is the reference's own wording, and by presence where the reference reports the text of its X.509 library.
 */
@Suppress("UNCHECKED_CAST")
class RefAttestMaaDiffTest {
    private val mod = "ref-attest-maa"
    private val blobs: Map<String, Any?> by lazy { OracleBlobs.load("$mod.json.gz") }

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private val FIXED = listOf(
        Regex("cert \\d+: (not yet valid|expired|unparsable validity)"), Regex("key older than maxKeyAgeMs"), Regex("subject is not a single CN"), Regex("wildcard CN rejected"),
        Regex("subject CN does not equal the issuer URL"), Regex("not a genuine self-signed cert"), Regex("chained key ignored \\(no chainRootSpkiSha256 configured\\)"),
        Regex("chain link \\d+ is not signed by the next cert"), Regex("chain profile: .*"), Regex("chain does not end in a self-signed root"), Regex("chain root is not pinned"),
        Regex("chained leaf CN not allowed"), Regex("chain does not pass through a pinned intermediate"), Regex("no x5c"), Regex("RSA key size .*"), Regex("RSA public exponent .*"),
        Regex("EC curve .*"), Regex("key type .*"),
    )

    /** A refusal compares by code; a certificate rejection keeps the reference's own wording and reduces the X.509 library's text to its presence. */
    private fun norm(v: Any?): Any? = when (v) {
        is Map<*, *> -> {
            val m = LinkedHashMap<String, Any?>()
            for ((k, x) in v) m[k as String] = norm(x)
            if (m["ok"] == false && m.containsKey("code")) m.remove("reason")
            val r = m["reason"]
            if (m.containsKey("kid") && r is String && FIXED.none { it.matches(r) }) m["reason"] = "<library>"
            m
        }
        is List<*> -> v.map { norm(it) }
        else -> v
    }

    private fun num(o: Any?): Double = IntentJs.num(o)!!

    // ---- scripted transport ----

    private class Script(val steps: List<Any?>) {
        val log = ArrayList<String>()
        private var i = 0

        fun fetch(): AttestMaaKeys.MaaFetch = AttestMaaKeys.MaaFetch { url ->
            log.add("$url [redirect:error]")
            var s = steps[Math.min(i++, steps.size - 1)]
            if (s is Map<*, *> && s.containsKey("keys") && !s.containsKey("body")) s = linkedMapOf("body" to s)
            respOf(s as Map<String, Any?>)
        }

        private fun respOf(r: Map<String, Any?>): AttestMaaKeys.MaaHttpResponse {
            if (r.containsKey("\$throws")) throw IllegalStateException(r["\$throws"] as String)
            val b = r["body"]
            val bytes: ByteArray = when {
                r["bodyBytes"] != null -> Pca.decodeB64uStrict((r["bodyBytes"] as Map<*, *>)["\$bytes"], -1)!!
                b is Map<*, *> && b.containsKey("\$text") -> (b["\$text"] as String).toByteArray(Charsets.UTF_8)
                else -> Json.canonicalize(b).toByteArray(Charsets.UTF_8)
            }
            return AttestMaaKeys.MaaHttpResponse(
                if (r["status"] != null) IntentJs.num(r["status"])!!.toInt() else 200, bytes, r["url"] as String?, r["contentLength"]?.let { IntentJs.lng(it).toString() },
            )
        }
    }

    private fun fetchCerts(a: List<Any?>): Any? {
        val sc = map(a[0])
        val s = Script(listOf(sc["response"]))
        val opts = map(sc["opts"] ?: emptyMap<String, Any?>())
        val out = LinkedHashMap<String, Any?>()
        try {
            out["jwks"] = AttestMaaKeys.fetchMaaCerts(sc["issuer"] as String, s.fetch(), opts["timeoutMs"], opts["maxBytes"])
            out["ok"] = true
        } catch (e: RuntimeException) {
            out.remove("jwks")
            out["ok"] = false
            out["error"] = e.message
        }
        out["requests"] = s.log
        return out
    }

    private fun trust(a: List<Any?>): Any? {
        val sc = map(a[0])
        val store = AttestMaaKeys.MemoryMaaKeyStateStore()
        for ((k, v) in (sc["initial"] as Map<String, Any?>? ?: emptyMap())) store.set(k, v)
        val s = Script(sc["fetches"] as List<Any?>)
        val t = AttestMaaKeys.createMaaKeyTrust(map(sc["policy"]), store, s.fetch())
        val results = (sc["calls"] as List<Any?>).map { co ->
            val c = map(co)
            t.getTrustAnchors(c["issuer"] as String, c["nowMs"], c["repin"] as Map<String, Any?>?)
        }
        return linkedMapOf("results" to results, "store" to store.snapshot(), "fetches" to s.log)
    }

    private fun kvStore(a: List<Any?>): Any? {
        val kv = MemoryAtomicKv()
        val st = AttestMaaKeys.durableMaaKeyStateStore(kv)
        val results = (map(a[0])["steps"] as List<Any?>).map { so ->
            val step = map(so)
            if (step.containsKey("set")) {
                val l = step["set"] as List<Any?>
                st.set(l[0] as String, l[1])
                null
            } else st.get(step["get"] as String)
        }
        val state = LinkedHashMap<String, Any?>()
        for (k in kv.keys()) state[k] = kv.get(k)
        return linkedMapOf("results" to results, "kv" to state)
    }

    private fun buildTrust(a: List<Any?>): Any? {
        val sc = map(a[0])
        AttestMaaKeys.createMaaKeyTrust(map(sc["policy"]), AttestMaaKeys.MemoryMaaKeyStateStore(), if (sc["noFetch"] == true) null else AttestMaaKeys.MaaFetch { throw IllegalStateException("unused") })
        return linkedMapOf("built" to true)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "BUILTIN_CHAIN_LEAF_CN" to AttestMaaPins.BUILTIN_CHAIN_LEAF_CN, "BUILTIN_MAA_PINS_ISSUER_ID" to AttestMaaPins.BUILTIN_MAA_PINS_ISSUER_ID,
            "BUILTIN_MAA_PINS_ISSUER_KEYS" to AttestMaaPins.BUILTIN_MAA_PINS_ISSUER_KEYS,
        )
        "evaluateMaaJwks" -> AttestMaaKeys.evaluateMaaJwks(a[0], a[1] as String, map(a[2]), num(a[3]))
        "loadBuiltinMaaPins" -> AttestMaaPins.loadBuiltinMaaPins(map(a[0]))
        "corroborate" -> AttestMaaKeys.corroborateMaaKeySets(a[0], a[1], a[2] as Map<String, Any?>?)
        "fetchCerts" -> fetchCerts(a)
        "trust" -> trust(a)
        "kvStore" -> kvStore(a)
        "buildTrust" -> buildTrust(a)
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf("constants", "evaluateMaaJwks", "loadBuiltinMaaPins", "corroborate", "fetchCerts", "trust", "kvStore", "buildTrust")
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val case = LinkedHashMap(c)
                case["args"] = OracleBlobs.hydrate(OracleCases.decNum(c["args"]), blobs)
                OracleCases.diff(case, norm(OracleBlobs.hydrate(c["out"], blobs))) { x -> norm(OracleCases.toJson(call(fn, x))) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(261, total)
    }
}
