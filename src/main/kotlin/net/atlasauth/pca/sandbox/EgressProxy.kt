package net.atlasauth.pca.sandbox

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The egress forward proxy of the PCA sandbox (raw `java.net` sockets, one thread per connection, no dependencies, so it also runs on
 * Android): the server side of [Egress.EgressPolicy].
 *
 * Set it as a non-WASM tool's only route out. Every request is claimed against the admissions; a refusal answers 403 and is receipted. The
 * upstream address is resolved here and checked with [Egress.isPrivateAddress] BEFORE connecting, and the connection goes to the checked
 * address, so an admitted hostname cannot be re-pointed at an internal service (no DNS rebinding window). Fail closed: anything the parser
 * does not fully understand is refused.
 *
 * Stricter than the TypeScript server: a request body must carry Content-Length (Transfer-Encoding on a request is refused with 400, so
 * there is no chunked-framing ambiguity), a header line with a bare CR, LF or NUL is refused, the connection is closed after every
 * response, and a resolved address that is not an IP literal counts as private. HTTPS upstreams are verified (system trust, host name
 * checked) unless a [SSLSocketFactory] is given.
 */
class EgressProxy @JvmOverloads constructor(
    private val policy: Egress.EgressPolicy,
    private val log: Receipts.ReceiptLog,
    private val runtimeClass: String = "egress_default_deny",
    /** Permit upstreams that resolve to private/loopback addresses (tests, internal APIs). Default false (SSRF guard). */
    private val allowPrivate: Boolean = false,
    private val maxBodyBytes: Int = 1 shl 20,
    private val upstreamTimeoutMs: Int = 10_000,
    /** The interface to listen on (default loopback only) and the port (0 = any free port). */
    private val host: String = "127.0.0.1",
    private val wantPort: Int = 0,
    /** How to verify https upstreams (default: the platform trust). */
    private val sslFactory: SSLSocketFactory? = null,
) {
    private class Refused(val status: Int, reason: String) : RuntimeException(reason)

    private class Head(val line: String, val headers: List<Pair<String, String>>, val rest: ByteArray)

    private val lock = Any()
    private val conns = ArrayList<Thread>()
    private var server: ServerSocket? = null
    private var acceptor: Thread? = null

    /** The port the proxy listens on (valid after [start]). */
    @Volatile var port: Int = 0
        private set

    /** Start listening; returns this. */
    fun start(): EgressProxy {
        val s = ServerSocket(wantPort, 50, InetAddress.getByName(host))
        server = s
        port = s.localPort
        val t = Thread {
            try {
                while (true) {
                    val sock = s.accept()
                    val c = Thread { handle(sock) }
                    c.isDaemon = true
                    synchronized(lock) {
                        conns.removeAll { !it.isAlive }
                        conns.add(c)
                    }
                    c.start()
                }
            } catch (e: IOException) {
                // closed
            }
        }
        t.isDaemon = true
        acceptor = t
        t.start()
        return this
    }

    /** Stop listening and wait for the open connections to finish (each is bounded by the upstream timeout). */
    fun close() {
        try {
            server?.close()
        } catch (e: IOException) {
            // already closed
        }
        acceptor?.join(1000)
        val open = synchronized(lock) { ArrayList(conns) }
        for (t in open) t.join(upstreamTimeoutMs + 1000L)
    }

    // ---- receipts and claims ----

    @Suppress("UNCHECKED_CAST")
    private fun receipt(method: String, url: String, d: Map<String, Any?>, outcome: String, reason: String) {
        val a = (d["admission"] as? Map<String, Any?>) ?: emptyMap()
        val allow = d["allow"] == true
        val subject = linkedMapOf<String, Any?>(
            "op_id" to (if (allow) d["op_id"] else ""),
            "verb" to (if (allow) (a["verb"] ?: "") else ""),
            "resource" to (if (allow) (a["resource"] ?: "") else "$method $url".take(256)),
            "params_digest" to (if (allow) (a["params_digest"] ?: "") else ""),
        )
        synchronized(lock) {
            log.append(runtimeClass, linkedMapOf("kind" to "egress", "subject" to subject, "outcome" to outcome, "reason" to reason))
        }
    }

    private fun claim(method: String, url: String, body: ByteArray?): Map<String, Any?> = synchronized(lock) { policy.claim(method, url, body) }

    // ---- resolving and connecting ----

    /** The first resolved address, after every resolved address passed the private-address rule (a literal is checked as is). */
    private fun resolve(h: String): InetAddress {
        val all = InetAddress.getAllByName(h)
        if (all.isEmpty() || (!allowPrivate && all.any { Egress.isPrivateAddress(it.hostAddress) })) throw SecurityException("EACCES")
        return all[0]
    }

    private fun openUpstream(h: String, p: Int, tls: Boolean): Socket {
        val addr = resolve(h)
        val raw = Socket()
        try {
            raw.connect(InetSocketAddress(addr, p), upstreamTimeoutMs)
            raw.soTimeout = upstreamTimeoutMs
            if (!tls) return raw
            val f = sslFactory ?: (SSLSocketFactory.getDefault() as SSLSocketFactory)
            val ssl = f.createSocket(raw, h, p, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS" // the certificate must name the host
            if (!Egress.isIPv4(h) && !Egress.isIPv6(h)) params.serverNames = listOf(SNIHostName(h))
            ssl.sslParameters = params
            ssl.startHandshake()
            return ssl
        } catch (e: Exception) {
            try { raw.close() } catch (x: IOException) { /* best effort */ }
            throw e
        }
    }

    // ---- HTTP framing ----

    private fun indexOfHeadEnd(b: ByteArray): Int {
        var i = 0
        while (i + 3 < b.size) {
            if (b[i] == '\r'.code.toByte() && b[i + 1] == '\n'.code.toByte() && b[i + 2] == '\r'.code.toByte() && b[i + 3] == '\n'.code.toByte()) return i
            i++
        }
        return -1
    }

    private fun readHead(input: InputStream): Head {
        val bos = ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var all = ByteArray(0)
        var idx: Int
        while (true) {
            idx = indexOfHeadEnd(all)
            if (idx >= 0) break
            if (all.size > MAX_HEAD) throw Refused(431, "head_too_large")
            val n = input.read(chunk)
            if (n < 0) throw EOFException()
            bos.write(chunk, 0, n)
            all = bos.toByteArray()
        }
        if (idx + 4 > MAX_HEAD) throw Refused(431, "head_too_large")
        val head = String(all, 0, idx, Charsets.ISO_8859_1)
        val rest = all.copyOfRange(idx + 4, all.size)
        val lines = head.split("\r\n")
        if (lines[0].any { it == '\r' || it == '\n' || it == '\u0000' }) throw Refused(400, "bad_request_line")
        val headers = ArrayList<Pair<String, String>>()
        for (ln in lines.drop(1)) {
            if (ln.any { it == '\r' || it == '\n' || it == '\u0000' }) throw Refused(400, "bad_header")
            val c = ln.indexOf(':')
            if (c <= 0) throw Refused(400, "bad_header")
            val k = ln.substring(0, c)
            if (k.any { it == ' ' || it == '\t' }) throw Refused(400, "bad_header")
            headers.add(Pair(k.lowercase(Locale.ROOT), ln.substring(c + 1).trim { it == ' ' || it == '\t' }))
        }
        return Head(lines[0], headers, rest)
    }

    private fun unique(headers: List<Pair<String, String>>, name: String): String? {
        val vals = headers.filter { it.first == name }.map { it.second }.distinct()
        if (vals.size > 1) throw Refused(400, "duplicate_" + name.replace('-', '_'))
        return vals.firstOrNull()
    }

    private fun reply(out: Socket, status: Int, body: String = "") {
        try {
            val b = body.toByteArray(Charsets.UTF_8)
            val head = "HTTP/1.1 $status ${REASONS[status] ?: "Error"}\r\nconnection: close\r\ncontent-length: ${b.size}\r\n" +
                (if (b.isEmpty()) "" else "content-type: application/json\r\n") + "\r\n"
            out.getOutputStream().write(head.toByteArray(Charsets.ISO_8859_1) + b)
            out.getOutputStream().flush()
        } catch (e: IOException) {
            // the client is gone
        }
    }

    private fun deny(out: Socket, method: String, url: String, reason: String, status: Int = 403) {
        receipt(method, url, linkedMapOf("allow" to false, "reason" to reason), "refused", reason)
        reply(out, status, "{\"error\":\"egress_denied\",\"reason\":\"$reason\"}")
    }

    private fun handle(sock: Socket) {
        try {
            sock.soTimeout = upstreamTimeoutMs
            serve(sock)
        } catch (e: IOException) {
            // a client that vanished or stalled
        } catch (e: RuntimeException) {
            reply(sock, 502) // never leak an internal error shape to the tool
        } finally {
            try { sock.close() } catch (e: IOException) { /* best effort */ }
        }
    }

    private class Req(val method: String, val url: String, val headers: List<Pair<String, String>>, val rest: ByteArray, val n: Long)

    private fun parseRequest(input: InputStream): Req {
        val h = readHead(input)
        val parts = h.line.split(" ")
        if (!(parts.size == 3 && parts[2].startsWith("HTTP/1."))) throw Refused(400, "bad_request_line")
        if (h.headers.any { it.first == "transfer-encoding" }) throw Refused(400, "transfer_encoding")
        val cl = unique(h.headers, "content-length")
        if (cl != null && !CL_RE.matches(cl)) throw Refused(400, "bad_content_length")
        val n = if (cl == null) 0L else if (cl.length > 18) Long.MAX_VALUE else cl.toLong()
        return Req(parts[0], parts[1], h.headers, h.rest, n)
    }

    private fun serve(sock: Socket) {
        val input = sock.getInputStream()
        val req = try {
            parseRequest(input)
        } catch (e: Refused) {
            deny(sock, "", "", e.message ?: "refused", e.status)
            return
        }
        val method = req.method
        val url = req.url
        val headers = req.headers
        val rest = req.rest
        val n = req.n
        if (method.uppercase(Locale.ROOT) == "CONNECT") {
            connect(sock, url, rest)
            return
        }
        if (n > maxBodyBytes) {
            deny(sock, method, url, "body_too_large", 413)
            return
        }
        val bodyOut = ByteArrayOutputStream()
        bodyOut.write(rest, 0, minOf(rest.size.toLong(), n).toInt())
        val buf = ByteArray(8192)
        while (bodyOut.size() < n) {
            val r = input.read(buf, 0, minOf(buf.size.toLong(), n - bodyOut.size()).toInt())
            if (r < 0) throw EOFException()
            bodyOut.write(buf, 0, r)
        }
        val body = bodyOut.toByteArray()
        val d = claim(method, url, body)
        if (d["allow"] != true) {
            deny(sock, method, url, d["reason"] as String)
            return
        }
        // the admitted URL was parsed by the same parser the claim used: what was matched is what is connected to
        val u = EgressUrl.parse(url)
        if (u == null) {
            receipt(method, url, d, "error", "upstream:bad_url")
            reply(sock, 502)
            return
        }
        val tls = u.scheme == "https"
        val port = if (u.port >= 0) u.port else if (tls) 443 else 80
        val up = try {
            openUpstream(u.host, port, tls)
        } catch (e: Exception) {
            receipt(method, url, d, "error", ("upstream:" + (if (e is SecurityException) "EACCES" else e.javaClass.simpleName)).take(64))
            reply(sock, 502)
            return
        }
        forward(sock, up, u, method.uppercase(Locale.ROOT), url, headers, body, d)
    }

    private fun forward(sock: Socket, up: Socket, u: EgressUrl.Parsed, method: String, url: String, headers: List<Pair<String, String>>, body: ByteArray, d: Map<String, Any?>) {
        var sent = false
        var status = "502"
        try {
            val path = u.path + (if (u.query.isNotEmpty()) "?" + u.query else "")
            val hostHeader = (if (u.host.indexOf(':') >= 0) "[" + u.host + "]" else u.host) + (if (u.port >= 0) ":" + u.port else "")
            val out = ArrayList<String>()
            out.add("$method $path HTTP/1.1")
            out.add("host: $hostHeader")
            out.add("connection: close")
            for ((k, v) in headers) if (k !in HOP) out.add("$k: $v")
            val upOut = up.getOutputStream()
            upOut.write((out.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1) + body)
            upOut.flush()
            val uh = readHead(up.getInputStream())
            sent = true
            status = uh.line.split(" ").getOrNull(1) ?: "502"
            val keep = uh.headers.filter { it.first !in HOP || it.first == "transfer-encoding" }.map { it.first + ": " + it.second } + "connection: close"
            val cout = sock.getOutputStream()
            cout.write((uh.line + "\r\n" + keep.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1) + uh.rest)
            val buf = ByteArray(65_536)
            val upIn = up.getInputStream()
            while (true) {
                val r = upIn.read(buf)
                if (r < 0) break
                cout.write(buf, 0, r)
            }
            cout.flush()
            receipt(method, url, d, "ok", "status:$status")
        } catch (e: EOFException) {
            if (sent) {
                receipt(method, url, d, "ok", "status:$status")
            } else {
                receipt(method, url, d, "error", "upstream:EOFException")
                reply(sock, 502)
            }
        } catch (e: Exception) {
            receipt(method, url, d, "error", ("upstream:" + e.javaClass.simpleName).take(64))
            if (!sent) reply(sock, 502)
        } finally {
            try { up.close() } catch (e: IOException) { /* best effort */ }
        }
    }

    private fun connect(sock: Socket, target: String, early: ByteArray) {
        val d = claim("CONNECT", target, null)
        if (d["allow"] != true) {
            deny(sock, "CONNECT", target, d["reason"] as String)
            return
        }
        val c = target.lastIndexOf(':')
        val h = target.substring(0, c).removePrefix("[").removeSuffix("]")
        val p = target.substring(c + 1).toInt()
        val up = try {
            openUpstream(h, p, false)
        } catch (e: Exception) {
            receipt("CONNECT", target, d, "error", "upstream:" + (if (e is SecurityException) "EACCES" else "error"))
            reply(sock, 502)
            return
        }
        try {
            receipt("CONNECT", target, d, "ok", "tunnel")
            sock.soTimeout = 0
            up.soTimeout = 0
            val cout = sock.getOutputStream()
            cout.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            cout.flush()
            val upOut = up.getOutputStream()
            if (early.isNotEmpty()) { upOut.write(early); upOut.flush() }
            val back = Thread { pump(up, sock) }
            back.isDaemon = true
            back.start()
            pump(sock, up)
            back.join()
        } finally {
            try { up.close() } catch (e: IOException) { /* best effort */ }
        }
    }

    /** Copy [src] to [dst] until EOF or error, then half-close [dst] so the peer sees the end. */
    private fun pump(src: Socket, dst: Socket) {
        try {
            val i = src.getInputStream()
            val o = dst.getOutputStream()
            val buf = ByteArray(65_536)
            while (true) {
                val r = i.read(buf)
                if (r < 0) break
                o.write(buf, 0, r)
                o.flush()
            }
        } catch (e: SocketTimeoutException) {
            // idle: end the tunnel
        } catch (e: IOException) {
            // a peer went away
        } finally {
            try { dst.shutdownOutput() } catch (e: Exception) { /* best effort */ }
        }
    }

    companion object {
        private const val MAX_HEAD = 65_536
        private val CL_RE = Regex("[0-9]+")
        private val HOP = setOf("connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host")
        private val REASONS = mapOf(200 to "OK", 400 to "Bad Request", 403 to "Forbidden", 413 to "Payload Too Large", 431 to "Request Header Fields Too Large", 502 to "Bad Gateway")
    }
}

/** A forward proxy for non-WASM tools (see [EgressProxy]). Call [EgressProxy.start] to listen. */
@JvmOverloads
fun createEgressProxy(
    policy: Egress.EgressPolicy,
    log: Receipts.ReceiptLog,
    runtimeClass: String = "egress_default_deny",
    allowPrivate: Boolean = false,
    maxBodyBytes: Int = 1 shl 20,
    upstreamTimeoutMs: Int = 10_000,
): EgressProxy = EgressProxy(policy, log, runtimeClass, allowPrivate, maxBodyBytes, upstreamTimeoutMs)
