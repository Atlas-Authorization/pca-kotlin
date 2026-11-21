package net.atlasauth.pca.webbotauth

import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of Web Bot Auth (RFC 9421 message signatures, signed directory, Content-Digest, proof binding). */
@Suppress("UNCHECKED_CAST")
class WebBotAuthDiffTest {
    private val m = "ref-webbotauth"

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun list(o: Any?) = o as List<Any?>

    private fun isBytes(o: Any?) = o is Map<*, *> && o.containsKey("\$bytes")

    private fun bytes(o: Any?): ByteArray = Keys.unb64u(map(o)["\$bytes"] as String)

    private fun numOf(o: Any?): Double = Js.num(o)!!

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "tag" to WebBotAuth.WEB_BOT_AUTH_TAG,
            "alg" to WebBotAuth.WEB_BOT_AUTH_ALG,
            "path" to WebBotAuth.WELL_KNOWN_DIRECTORY_PATH,
            "ct" to WebBotAuth.DIRECTORY_CONTENT_TYPE,
            "label" to WebBotAuth.DEFAULT_SIGNATURE_LABEL,
            "exp" to Json.Num(WebBotAuth.DEFAULT_EXPIRES_SEC.toString()),
            "agent" to WebBotAuth.SIGNATURE_AGENT_HEADER,
            "pca" to WebBotAuth.PCA_HEADER,
            "comp" to WebBotAuth.PCA_PROOF_COMPONENT,
            "cd" to ContentDigest.CONTENT_DIGEST_HEADER,
            "algs" to ArrayList<Any?>(ContentDigest.CONTENT_DIGEST_ALGS),
            "dtag" to SignedDirectory.DIRECTORY_SIGNATURE_TAG,
        )
    }

    @Test fun jwkThumbprint() = OracleCases.each(m, "jwkThumbprint") { a -> WebBotAuth.jwkThumbprint(bytes(a[0])) }

    @Test fun signRequest() = OracleCases.each(m, "signRequest") { a -> WebBotAuth.signRequest(map(a[0])) }

    // ---- verify

    /** The oracle's key-resolver spec: keyid to {"$bytes"} | JWK | null | {"$throw": true}; an unlisted keyid resolves to null. */
    private fun resolver(spec: Map<String, Any?>) = WebBotAuth.KeyResolver { kid ->
        val v = spec[kid]
        if (v is Map<*, *> && v["\$throw"] == true) throw IllegalStateException("resolver down")
        if (isBytes(v)) bytes(v) else v
    }

    private fun cache(spec: Any?): WebBotAuth.ReplayCache = when {
        spec == "always" -> WebBotAuth.ReplayCache { _, _, _ -> true }
        spec == "never" -> WebBotAuth.ReplayCache { _, _, _ -> false }
        spec == "throw" -> WebBotAuth.ReplayCache { _, _, _ -> throw IllegalStateException("cache down") }
        spec == "memory" -> WebBotAuth.memoryReplayCache()
        spec is String && spec.startsWith("memory:") -> WebBotAuth.memoryReplayCache(spec.substring(7).toInt())
        else -> throw IllegalArgumentException("unknown cache spec $spec")
    }

    private fun vopts(op: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(op)
        if (out["resolveKey"] is Map<*, *>) out["resolveKey"] = resolver(map(out["resolveKey"]))
        if (out["maxLifetimeSec"] == "Infinity") out["maxLifetimeSec"] = Double.POSITIVE_INFINITY
        if (out.containsKey("replayCache")) out["replayCache"] = cache(out["replayCache"])
        return out
    }

    private val libReason = Regex("(?s)^(invalid PCActn in PCA-Action): .*$")

    private fun norm(r: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(r)
        val reason = out["reason"]
        if (reason is String) out["reason"] = reason.replace(libReason, "$1")
        return out
    }

    @Test fun verifySignedRequest() = OracleCases.each(m, "verifySignedRequest") { a ->
        val times = if (a.size > 2) numOf(a[2]).toInt() else 1
        val vo = vopts(map(a[1]))
        val rs = (0 until times).map { norm(WebBotAuth.verifySignedRequest(map(a[0]), vo)) }
        if (times == 1) rs[0] else rs
    }

    @Test fun verifySignedRequestWithProof() = OracleCases.each(m, "verifySignedRequestWithProof") { a ->
        norm(WebBotAuth.verifySignedRequestWithProof(map(a[0]), vopts(map(a[1]))))
    }

    // ---- directory + replay cache

    private fun dirKeys(o: Any?): List<Map<String, Any?>> = list(o).map { k ->
        val e = LinkedHashMap(map(k))
        e["publicKey"] = bytes(e["publicKey"])
        e
    }

    @Test fun directory() {
        OracleCases.each(m, "buildKeyDirectory") { a -> WebBotAuth.buildKeyDirectory(dirKeys(a[0])) }
        OracleCases.each(m, "resolveFromDirectory") { a -> WebBotAuth.resolveFromDirectory(map(a[0]), a[1] as String) }
        OracleCases.each(m, "directoryHandler") { a ->
            val h = WebBotAuth.directoryHandler(dirKeys(a[0]))
            list(a[1]).map { p -> h(p as String) }
        }
    }

    @Test fun memoryReplayCache() = OracleCases.each(m, "memoryReplayCache") { a ->
        val c = if (a[0] == null) WebBotAuth.memoryReplayCache() else WebBotAuth.memoryReplayCache(numOf(a[0]).toInt())
        list(a[1]).map { op ->
            val o = list(op)
            try {
                c.claim(o[0] as String, numOf(o[1]), numOf(o[2]))
            } catch (e: Exception) {
                "throw"
            }
        }
    }

    // ---- proof binding

    @Test fun proof() {
        OracleCases.each(m, "proofHeaders") { a -> WebBotAuth.proofHeaders(a[0]) }
        OracleCases.each(m, "decodeProofHeader") { a -> WebBotAuth.decodeProofHeader(a[0] as String?) }
        OracleCases.each(m, "signRequestWithProof") { a -> WebBotAuth.signRequestWithProof(map(a[0])) }
    }

    // ---- Content-Digest

    private fun body(o: Any?): Any? = if (isBytes(o)) bytes(o) else o

    @Test fun contentDigest() {
        OracleCases.each(m, "contentDigestBytes") { a -> ContentDigest.contentDigestBytes(body(a[0]), a[1] as String?) }
        OracleCases.each(m, "contentDigestHeader") { a ->
            if (a.size > 1) ContentDigest.contentDigestHeader(body(a[0]), a[1] as List<String>) else ContentDigest.contentDigestHeader(body(a[0]))
        }
        OracleCases.each(m, "parseContentDigest") { a -> ContentDigest.parseContentDigest(a[0] as String) }
        OracleCases.each(m, "verifyContentDigest") { a ->
            val req = if (a.size > 2 && a[2] != null && map(a[2])["require"] != null) map(a[2])["require"] as List<String> else null
            ContentDigest.verifyContentDigest(a[0] as String?, body(a[1]), req)
        }
    }

    // ---- signed directory

    @Test fun signedDirectory() {
        OracleCases.each(m, "parseKeyDirectory") { a -> SignedDirectory.parseKeyDirectory(a[0] as String) }
        OracleCases.each(m, "signDirectoryResponse") { a -> SignedDirectory.signDirectoryResponse(map(a[0])) }
        OracleCases.each(m, "verifyDirectoryResponse") { a -> SignedDirectory.verifyDirectoryResponse(map(a[0])) }
    }

    /** The oracle's scripted fetch: records the URL and headers, answers {status, headers, body} (or throws for "throw"). */
    @Test fun fetchKeyDirectory() = OracleCases.each(m, "fetchKeyDirectory") { a ->
        val spec = map(a[1])
        val res = spec["response"]
        var called: Any? = null
        val fetcher = DirectoryFetch.Fetcher { url, headers, _ ->
            called = linkedMapOf<String, Any?>("url" to url, "headers" to LinkedHashMap<String, Any?>(headers), "redirect" to "error")
            if (res == "throw") throw IllegalStateException("network down")
            val r = map(res)
            val hs: Map<String, Any?> = if (r["headers"] == null) LinkedHashMap() else map(r["headers"])
            object : DirectoryFetch.Response {
                override fun status(): Int = numOf(r["status"]).toInt()
                override fun header(name: String): String? = hs[name.lowercase(Locale.ROOT)] as String?
                override fun text(): String = r["body"] as String
            }
        }
        val options = LinkedHashMap<String, Any?>()
        if (spec["options"] != null) options.putAll(map(spec["options"]))
        options["fetch"] = fetcher
        val out = LinkedHashMap<String, Any?>()
        try {
            out["directory"] = DirectoryFetch.fetchKeyDirectory(a[0] as String, options)
        } catch (e: Exception) {
            out["error"] = true
            val msg = e.message ?: ""
            out["message"] = if (msg.startsWith("directory ") || msg == "Invalid URL") msg.replace(Regex("(?s)^(directory signature): .*$"), "$1") else "other"
        }
        out["called"] = called
        out
    }
}
