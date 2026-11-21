package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/** The egress proxy server: loopback only (127.0.0.1, ephemeral ports), no external network. The admission logic itself is replayed by SandboxDiffTest. */
class EgressProxyTest {
    private val op = Authorize.Operation("http.get", "api", linkedMapOf<String, Any?>("x" to 1L))

    private fun result() = Authorize.Result(true, 200, LinkedHashMap(), ArrayList(), null, operation = Authorize.AuthorizedOperation("http.get", "api", Pca.hashCanonical(op.params), "op1"))

    private fun policy(port: Int, extra: Map<String, Any?> = emptyMap(), uses: Long = 1L): Egress.EgressPolicy {
        val p = Egress.EgressPolicy()
        val t = linkedMapOf<String, Any?>("method" to "GET", "scheme" to "http", "host" to "127.0.0.1", "port" to port.toLong(), "path" to "/ok")
        t.putAll(extra)
        p.admit(result(), op, { _ -> t }, uses, null)
        return p
    }

    /** An upstream answering every connection with a fixed 200 and recording each request head. */
    private fun upstream(seen: MutableList<String>): ServerSocket {
        val srv = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val t = Thread {
            try {
                while (true) {
                    val c = srv.accept()
                    val head = StringBuilder()
                    val buf = ByteArray(4096)
                    while (!head.contains("\r\n\r\n")) {
                        val n = c.getInputStream().read(buf)
                        if (n < 0) break
                        head.append(String(buf, 0, n, Charsets.ISO_8859_1))
                    }
                    seen.add(head.toString())
                    c.getOutputStream().write("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-up: 1\r\nconnection: close\r\n\r\nhi".toByteArray())
                    c.close()
                }
            } catch (e: java.io.IOException) {
                // closed
            }
        }
        t.isDaemon = true
        t.start()
        return srv
    }

    private fun sendRaw(port: Int, raw: String): String {
        val s = Socket("127.0.0.1", port)
        s.soTimeout = 5000
        s.getOutputStream().write(raw.toByteArray(Charsets.ISO_8859_1))
        val data = String(s.getInputStream().readBytes(), Charsets.ISO_8859_1)
        s.close()
        return data
    }

    @Test fun proxyFlow() {
        val seen = CopyOnWriteArrayList<String>()
        val up = upstream(seen)
        val log = Receipts.ReceiptLog()
        val proxy = createEgressProxy(policy(up.localPort), log, allowPrivate = true).start()
        try {
            val url = "http://127.0.0.1:${up.localPort}/ok"
            val req = "GET $url HTTP/1.1\r\nhost: x\r\nx-keep: 1\r\nproxy-authorization: secret\r\n\r\n"
            val ok = sendRaw(proxy.port, req)
            assertTrue(ok, ok.startsWith("HTTP/1.1 200") && ok.endsWith("hi") && ok.contains("x-up: 1"))
            assertTrue(seen[0].contains("x-keep: 1") && !seen[0].lowercase().contains("proxy-authorization"))
            // the single use is spent: the same request is refused and never reaches the upstream
            val again = sendRaw(proxy.port, req)
            assertTrue(again, again.startsWith("HTTP/1.1 403") && again.contains("spent") && seen.size == 1)
            // a different path, a body the template does not allow, chunked framing, an origin-form request, a doubled length, a bare LF in a header: all refused
            for (raw in listOf(
                "GET http://127.0.0.1:${up.localPort}/other HTTP/1.1\r\n\r\n", "POST $url HTTP/1.1\r\ncontent-length: 1\r\n\r\nx",
                "GET $url HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "GET /ok HTTP/1.1\r\n\r\n",
                "GET $url HTTP/1.1\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\nxx", "GET $url HTTP/1.1\r\nx-a: b\nx-b: c\r\n\r\n",
            )) {
                val got = sendRaw(proxy.port, raw)
                assertTrue(got, got.startsWith("HTTP/1.1 403") || got.startsWith("HTTP/1.1 400"))
            }
            assertEquals(1, seen.size)
            assertEquals(listOf("ok", "refused"), log.entries().take(2).map { it["outcome"] })
            assertEquals(true, Receipts.verifyReceiptChain(log.entries(), null)["ok"])
        } finally {
            proxy.close()
            up.close()
        }
    }

    @Test fun proxyPrivateGuard() {
        val seen = CopyOnWriteArrayList<String>()
        val up = upstream(seen)
        val log = Receipts.ReceiptLog()
        val proxy = createEgressProxy(policy(up.localPort), log).start() // allowPrivate defaults to false: a loopback upstream is refused
        try {
            val got = sendRaw(proxy.port, "GET http://127.0.0.1:${up.localPort}/ok HTTP/1.1\r\n\r\n")
            assertTrue(got, got.startsWith("HTTP/1.1 502") && seen.isEmpty())
            assertEquals("upstream:EACCES", log.entries().last()["reason"])
        } finally {
            proxy.close()
            up.close()
        }
    }

    @Test fun proxyConnect() {
        val up = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val t = Thread {
            try {
                val c = up.accept()
                val b = ByteArray(4)
                var n = 0
                while (n < 4) { val r = c.getInputStream().read(b, n, 4 - n); if (r < 0) break; n += r }
                c.getOutputStream().write(b, 0, n)
                c.close()
            } catch (e: java.io.IOException) {
                // closed
            }
        }
        t.isDaemon = true
        t.start()
        val uport = up.localPort
        val p = Egress.EgressPolicy()
        val tmpl = linkedMapOf<String, Any?>("method" to "GET", "scheme" to "https", "host" to "127.0.0.1", "port" to uport.toLong(), "path" to "/", "tunnel" to true)
        p.admit(result(), op, { _ -> tmpl }, null, null)
        val proxy = createEgressProxy(p, Receipts.ReceiptLog(), allowPrivate = true).start()
        try {
            val s = Socket("127.0.0.1", proxy.port)
            s.soTimeout = 5000
            s.getOutputStream().write("CONNECT 127.0.0.1:$uport HTTP/1.1\r\n\r\n".toByteArray())
            val buf = ByteArray(4096)
            val n = s.getInputStream().read(buf)
            assertTrue(String(buf, 0, n).startsWith("HTTP/1.1 200"))
            s.getOutputStream().write("ping".toByteArray())
            val echo = ByteArray(4)
            var got = 0
            while (got < 4) { val r = s.getInputStream().read(echo, got, 4 - got); if (r < 0) break; got += r }
            assertEquals("ping", String(echo, 0, got))
            s.close()
            // not admitted any more (one use): refused
            assertTrue(sendRaw(proxy.port, "CONNECT 127.0.0.1:$uport HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 403"))
        } finally {
            proxy.close()
            up.close()
        }
    }
}
