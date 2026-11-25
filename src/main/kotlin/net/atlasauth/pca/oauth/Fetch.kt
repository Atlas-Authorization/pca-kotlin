package net.atlasauth.pca.oauth

import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request

/** An injectable HTTP GET (the reference's injectable `fetch`): the default uses OkHttp, tests pass a scripted one. */
fun interface Fetch {
    /** The parts of a response the protocol bridges read. [contentLength] is the header value or null. */
    class Response(val ok: Boolean, val status: Int, val contentLength: String?, val text: String)

    /** GET [url]; [timeoutMs] 0 means no timeout. Throws on a network failure. */
    fun get(url: String, headers: Map<String, String>, timeoutMs: Long): Response

    companion object {
        private val client by lazy { OkHttpClient() }

        /** The default fetch over OkHttp. */
        fun http(): Fetch = Fetch { url, headers, timeoutMs ->
            val c = if (timeoutMs > 0) client.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build() else client
            val b = Request.Builder().url(url).get()
            for ((k, v) in headers) b.header(k, v)
            c.newCall(b.build()).execute().use { r -> Response(r.isSuccessful, r.code, r.header("content-length"), r.body?.string() ?: "") }
        }
    }
}
