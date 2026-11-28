package net.atlasauth.pca.frost

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * The HTTP transport of the networked FROST signer: JSON over HTTP (`POST /round1`, `POST /round2`, base64url text) between a [FrostNet.GuardianSignerService]
 * served by [startSignerHttpServer] and a coordinator holding [httpSignerTransport]. With the service in its own OS process this is genuine process-level trust
 * domain separation. It is PLAINTEXT: authenticated, encrypted channels with a PKI are the deployment's, so bind it to loopback or put it behind a TLS terminator
 * you control. A handler error maps to a refusal response, never a stack or a share; a request body over 1 MiB is refused.
 */
object FrostNetHttp {
    private const val MAX_BODY = 1 shl 20

    /** A running signer server: its base `url`, the bound `port`, and [close]. */
    class SignerHttpServer internal constructor(val url: String, val port: Int, private val server: HttpServer) {
        fun close() = server.stop(0)
    }

    private fun readBody(ex: HttpExchange): Any? {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
            val n = ex.requestBody.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_BODY) throw IllegalArgumentException("request body too large")
            out.write(buf, 0, n)
        }
        val raw = String(out.toByteArray(), Charsets.UTF_8)
        return if (raw.isEmpty()) LinkedHashMap<String, Any?>() else Json.parseLenient(raw)
    }

    private fun send(ex: HttpExchange, code: Int, body: Any?) {
        val bytes = Json.utf8(FrostDkgChannel.stringify(body))
        ex.responseHeaders.add("content-type", "application/json")
        ex.sendResponseHeaders(code, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    /** Serve `service` on `host` (default 127.0.0.1) and `port` (default an ephemeral one). Routes: `POST /round1`, `POST /round2`. */
    @JvmStatic @JvmOverloads
    fun startSignerHttpServer(service: FrostNet.GuardianSignerService, port: Int = 0, host: String = "127.0.0.1"): SignerHttpServer {
        val server = HttpServer.create(InetSocketAddress(host, port), 0)
        server.createContext("/") { ex ->
            try {
                if (ex.requestMethod != "POST") {
                    send(ex, 405, linkedMapOf("ok" to false, "reason" to "method not allowed"))
                } else when (ex.requestURI.path) {
                    "/round1" -> send(ex, 200, service.round1(readBody(ex)))
                    "/round2" -> send(ex, 200, service.round2(readBody(ex)))
                    else -> send(ex, 404, linkedMapOf("ok" to false, "reason" to "not found"))
                }
            } catch (e: Exception) {
                send(ex, 400, linkedMapOf("ok" to false, "identifier" to IntentJs.ofLong(service.identifier), "refused" to true, "reason" to (e.message ?: "bad request")))
            } finally {
                ex.close()
            }
        }
        server.start()
        return SignerHttpServer("http://$host:${server.address.port}", server.address.port, server)
    }

    /** The transport to a signer HTTP server over loopback; one instance per remote signer. `timeoutMs` bounds each call (default 10 s). */
    @JvmStatic @JvmOverloads
    fun httpSignerTransport(baseUrl: String, identifier: Long, timeoutMs: Long = 10_000): SignerTransport {
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(timeoutMs)).build()
        fun post(path: String, body: Map<String, Any?>): Map<String, Any?> {
            val req = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(Duration.ofMillis(timeoutMs)).header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(FrostDkgChannel.stringify(body))).build()
            val res = client.send(req, HttpResponse.BodyHandlers.ofString())
            return Json.parseLenient(res.body()) as Map<String, Any?>
        }
        return object : SignerTransport {
            override val identifier: Long = identifier
            override fun round1(req: Map<String, Any?>): Map<String, Any?> = post("/round1", req)
            override fun round2(req: Map<String, Any?>): Map<String, Any?> = post("/round2", req)
        }
    }
}
