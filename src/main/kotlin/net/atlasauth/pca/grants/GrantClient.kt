package net.atlasauth.pca.grants

import java.io.IOException
import java.net.URLEncoder
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import net.atlasauth.pca.verifier.FreshAt as FreshAtVerify

/**
 * Thin OkHttp client for the grant management resource. It also carries the newest `pca-fresh-at` token it has seen: a token that does not
 * verify under [freshSigner] (when set) is ignored, and a token never replaces a fresher one. Calls block: run them off the main thread.
 */
class GrantClient @JvmOverloads constructor(
    baseUrl: String,
    private val http: OkHttpClient = OkHttpClient(),
    private val freshSigner: String? = null,
    private val headers: (() -> Map<String, String>)? = null,
) {
    class ApiError(val status: Int, val code: String, message: String) : RuntimeException(message)

    private val baseUrl: String = if (baseUrl.endsWith("/")) baseUrl.substring(0, baseUrl.length - 1) else baseUrl
    private var latest: Map<String, Any?>? = null

    /** The newest consistency token seen on any response (attach it to later requests for read-your-writes), or null. */
    @Synchronized
    fun freshAt(): Map<String, Any?>? = latest

    /** Fold the newest token into a local state; null when none was seen. */
    @Synchronized
    fun foldFreshAt(state: Map<String, Any?>): Map<String, Any?>? = latest?.let { FreshAt.mergeFreshAt(it, state) }

    @Throws(IOException::class)
    private fun call(method: String, path: String, body: Any?): Map<String, Any?> {
        val b = Request.Builder().url(baseUrl + path).header("content-type", "application/json")
        synchronized(this) { latest?.let { b.header("pca-fresh-at", Json.canonicalize(it)) } }
        headers?.let { for ((k, v) in it()) b.header(k, v) }
        val rb: RequestBody? = if (body != null) Json.canonicalize(body).toRequestBody("application/json".toMediaType()) else if (method == "GET") null else ByteArray(0).toRequestBody(null)
        b.method(method, rb)
        http.newCall(b.build()).execute().use { res ->
            res.header("pca-fresh-at")?.let { fold(it) }
            val text = res.body?.string() ?: ""
            var parsed: Map<String, Any?>? = null
            try {
                parsed = K3Sig.map(Json.parseLenient(text))
            } catch (e: RuntimeException) {
                // a non-JSON body is treated as an empty object
            }
            val json: Map<String, Any?> = parsed ?: LinkedHashMap()
            if (res.code < 200 || res.code > 299) {
                val code = json["error"]
                val msg = json["message"]
                throw ApiError(res.code, code as? String ?: "error", msg as? String ?: "HTTP ${res.code}")
            }
            return json
        }
    }

    @Synchronized
    private fun fold(tok: String) {
        try { // a malformed header is ignored: freshness is only ever tightened by a valid token
            val t = K3Sig.map(Json.parseLenient(tok)) ?: return
            if (freshSigner != null && !FreshAtVerify.verify(t, freshSigner)) return
            for (k in COUNTERS) if (!K3Sig.isSafeInt(t[k])) return
            val cur = latest
            var newer = cur == null
            if (!newer) {
                newer = true
                for (k in COUNTERS) newer = newer && Json.asLong(t[k]) >= Json.asLong(cur!![k])
            }
            if (newer) latest = t // monotone fold: never replace a fresher token with an older one
        } catch (e: RuntimeException) {
            // ignored
        }
    }

    @Throws(IOException::class)
    @JvmOverloads
    fun list(q: Map<String, String?>? = null): Map<String, Any?> {
        val sb = StringBuilder()
        if (q != null) for ((k, v) in q) {
            if (v == null) continue
            sb.append(if (sb.isEmpty()) "?" else "&").append(URLEncoder.encode(k, "UTF-8")).append('=').append(URLEncoder.encode(v, "UTF-8"))
        }
        return call("GET", GrantHttp.GRANTS_PATH + sb, null)
    }

    @Throws(IOException::class)
    fun inspect(id: String): Map<String, Any?> = call("GET", GrantHttp.GRANTS_PATH + "/" + enc(id), null)

    @Throws(IOException::class)
    fun amend(id: String, req: Map<String, Any?>): Map<String, Any?> = call("POST", GrantHttp.GRANTS_PATH + "/" + enc(id) + "/amend", req)

    /** [scope] null means grant; [sig] null sends no body (an admin revoke). */
    @Throws(IOException::class)
    @JvmOverloads
    fun revoke(id: String, scope: String? = null, sig: String? = null): Map<String, Any?> {
        val body = if (!sig.isNullOrEmpty()) LinkedHashMap<String, Any?>().also { it["sig"] = sig } else null
        return call("DELETE", GrantHttp.GRANTS_PATH + "/" + enc(id) + "?scope=" + (scope ?: "grant"), body)
    }

    @Throws(IOException::class)
    fun requestNeeds(id: String, needs: List<Any?>): Map<String, Any?> = call("POST", GrantHttp.GRANTS_PATH + "/" + enc(id) + "/needs", GrantHttp.obj("needs" to needs))

    @Throws(IOException::class)
    @JvmOverloads
    fun approveNeeds(needId: String, approved: List<Any?>, sig: String, stepUpRef: String? = null): Map<String, Any?> {
        val body = GrantHttp.obj("approved" to approved, "sig" to sig)
        if (!stepUpRef.isNullOrEmpty()) body["step_up_ref"] = stepUpRef
        return call("POST", GrantHttp.NEEDS_PATH + "/" + enc(needId) + "/approve", body)
    }

    @Throws(IOException::class)
    fun denyNeeds(needId: String): Map<String, Any?> = call("POST", GrantHttp.NEEDS_PATH + "/" + enc(needId) + "/deny", null)

    companion object {
        private val COUNTERS = listOf("revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version")

        /** JavaScript encodeURIComponent. */
        internal fun enc(s: String): String =
            URLEncoder.encode(s, "UTF-8").replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(").replace("%29", ")").replace("%7E", "~")
    }
}
