package net.atlasauth.pca.fetch

import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/**
 * Replays the reference oracle over the request guard's construction guards and its refusals before any verification: status, challenge,
 * content type and the deny body's keys (`error`, `verdict`, `decision`).
 */
@Suppress("UNCHECKED_CAST")
class FetchDiffTest {
    private val M = "ref-fetch"
    private val AUD = "rs_fetch"

    @Test fun constructScenario() = OracleCases.each(M, "constructScenario") { a ->
        val resolve: (String) -> Map<String, Any?>? = { null }
        when (a[0]) {
            "ok" -> Fetch.withPCA(Fetch.Options(PcaGuardConfig(AUD, resolve, null, null, true))) { _, _ -> Fetch.FetchResponse(200, emptyMap(), "ok") }
            "noaudience" -> Fetch.withPCA(Fetch.Options(PcaGuardConfig("", resolve, null, null, true))) { _, _ -> Fetch.FetchResponse(200, emptyMap(), "ok") }
            "nooperation" -> Fetch.withPCA(Fetch.Options(PcaGuardConfig(AUD, resolve, null, null, false))) { _, _ -> Fetch.FetchResponse(200, emptyMap(), "ok") }
            else -> throw IllegalArgumentException("unknown kind")
        }
        linkedMapOf("built" to true)
    }

    @Test fun requestScenario() {
        val bad = OracleCases.of(M, "requestScenario").mapNotNull { c ->
            val spec = (c["args"] as List<Any?>)[0] as Map<String, Any?>
            val throwing = spec["resolve"] == "throws"
            val cfg = PcaGuardConfig(AUD, { if (throwing) throw IllegalStateException("store down") else null }, null, null, true)
            var ran = false
            val f = Fetch.withPCA(Fetch.Options(cfg)) { _, _ -> ran = true; Fetch.FetchResponse(200, emptyMap(), "{\"ok\":true}") }
            val headers = LinkedHashMap<String, String>()
            (spec["headers"] as Map<String, Any?>?)?.forEach { (k, v) -> headers[k] = v as String }
            val body = (spec["body"] as String?)?.toByteArray(Charsets.UTF_8)
            val res = f(Fetch.FetchRequest("POST", "http://localhost/refunds", headers, body))
            val parsed = try { Json.parse(res.body) as? Map<String, Any?> } catch (e: RuntimeException) { null }
            val want = c["out"] as Map<String, Any?>
            val got = linkedMapOf<String, Any?>(
                "status" to Json.Num(res.status.toString()), "handlerRan" to ran, "decision" to parsed?.get("decision"),
                "challenge" to if (res.status == 401) res.headers["WWW-Authenticate"]?.startsWith("PCA realm=\"") == true else null,
                "contentType" to res.headers["content-type"], "errorIsString" to (parsed?.get("error") is String),
                "bodyKeys" to parsed?.keys?.sorted(),
            )
            val diffs = listOf("status", "handlerRan", "decision", "challenge", "contentType", "errorIsString", "bodyKeys").filter { got[it] != want[it] }
            if (diffs.isEmpty()) null else "${c["name"]}: $diffs want $want got $got"
        }
        org.junit.Assert.assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }
}
