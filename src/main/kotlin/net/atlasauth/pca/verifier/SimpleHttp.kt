package net.atlasauth.pca.verifier

import java.net.HttpURLConnection
import java.net.URL

/** One blocking HTTP request over [HttpURLConnection] (on the JDK and on Android alike): the default transport of the client-side helpers. */
internal object SimpleHttp {
    /** Send [method] to [url] with [headers] and an optional text [body]; answer the status and the (success or error) body text. Throws on a network failure. */
    fun request(method: String, url: String, headers: Map<String, String>, body: String?, timeoutMs: Int = 30_000): Pair<Int, String> {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = timeoutMs
            c.readTimeout = timeoutMs
            for ((k, v) in headers) c.setRequestProperty(k, v)
            if (body != null) {
                c.doOutput = true
                c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = c.responseCode
            val stream = if (code >= 400) c.errorStream else c.inputStream
            val text = stream?.use { String(it.readBytes(), Charsets.UTF_8) } ?: ""
            return Pair(code, text)
        } finally {
            c.disconnect()
        }
    }
}
