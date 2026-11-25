package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.IntentJs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * The mutual-TLS DKG node over JSSE: a three-party ceremony over loopback with pinned certificates (generated here with the JDK's keytool), and the refusals the
 * identity rule demands before any DKG byte is read: an unpinned certificate, a pinned peer that should have been dialled instead of dialling, a TLS 1.2 client and
 * a plaintext client.
 */
class FrostDkgTlsNodeTest {
    private class Identity(val keyStore: KeyStore, val keyPem: String, val certPem: String)

    private val pw = "changeit".toCharArray()

    private fun pem(label: String, der: ByteArray): String =
        "-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END $label-----\n"

    private fun identity(cn: String): Identity {
        val dir = Files.createTempDirectory("dkg-tls").toFile()
        try {
            val store = File(dir, "id.p12")
            val keytool = File(System.getProperty("java.home"), "bin/keytool").path
            val p = ProcessBuilder(
                keytool, "-genkeypair", "-alias", "n", "-keyalg", "EC", "-keysize", "256", "-sigalg", "SHA256withECDSA", "-dname", "CN=$cn", "-validity", "2",
                "-keystore", store.path, "-storetype", "PKCS12", "-storepass", String(pw), "-keypass", String(pw),
            ).redirectErrorStream(true).start()
            val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
            assertTrue("keytool failed: $out", p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0)
            val ks = KeyStore.getInstance("PKCS12")
            store.inputStream().use { ks.load(it, pw) }
            val key = ks.getKey("n", pw)
            val cert = ks.getCertificate("n") as X509Certificate
            return Identity(ks, pem("PRIVATE KEY", key.encoded), pem("CERTIFICATE", cert.encoded))
        } finally {
            dir.deleteRecursively()
        }
    }

    private val sid = ByteArray(32) { (it + 1).toByte() }

    private fun node(self: Long, me: Identity, peers: Map<Long, Identity>) =
        FrostDkgTlsNode.start(FrostDkgTlsNode.Options(self, sid, me.keyPem, me.certPem, peers.map { FrostDkgTlsNode.PeerCert(it.key, it.value.certPem) }))

    @Test fun threePartyCeremonyOverMutualTls() {
        val ids = listOf(1L, 2L, 3L)
        val idn = ids.associateWith { identity("party$it") }
        val nodes = ids.associateWith { me -> node(me, idn.getValue(me), idn.filterKeys { it != me }) }
        val results = ConcurrentHashMap<Long, FrostDkgChannel.RunDkgResult>()
        val failures = ConcurrentHashMap<Long, Throwable>()
        try {
            val threads = ids.map { me ->
                Thread {
                    try {
                        val addrs = ids.filter { it != me }.map { FrostDkgTlsNode.Address(it, "127.0.0.1", nodes.getValue(it).port) }
                        val ch = nodes.getValue(me).connect(addrs, 20_000.0)
                        results[me] = FrostDkgChannel.runDkgOverChannel(ch, IntentJs.ofLong(2), ids.map { IntentJs.ofLong(it) }, sid, 30_000.0)
                    } catch (t: Throwable) {
                        failures[me] = t
                    }
                }.also { it.start() }
            }
            threads.forEach { it.join(120_000) }
            assertTrue("a party failed: $failures", failures.isEmpty())
            assertEquals(3, results.size)
            val gpk = results.getValue(1L).keyPackage["groupPublicKey"] as ByteArray
            for ((id, r) in results) {
                assertTrue("party $id agrees on the group key", (r.keyPackage["groupPublicKey"] as ByteArray).contentEquals(gpk))
                assertEquals("party $id qualified set", listOf<Any?>(1L, 2L, 3L), r.qualified.map { IntentJs.num(it)!!.toLong() })
            }
        } finally {
            nodes.values.forEach { it.close() }
        }
    }

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** Dial `port` as `who` (or without a certificate) and try to use the link; any outcome other than a live link is fine, the node's own state is asserted. */
    private fun dialAs(who: Identity?, port: Int, protocols: Array<String>?) {
        val ctx = SSLContext.getInstance("TLS")
        val kms = if (who == null) null else KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).also { it.init(who.keyStore, pw) }.keyManagers
        ctx.init(kms, arrayOf(trustAll), null)
        try {
            val s = ctx.socketFactory.createSocket("127.0.0.1", port) as SSLSocket
            if (protocols != null) s.enabledProtocols = protocols
            s.soTimeout = 3_000
            s.startHandshake()
            s.outputStream.write(byteArrayOf(0, 0, 0, 1, 7))
            s.outputStream.flush()
            s.inputStream.read() // a refused link ends (EOF or an alert)
            s.close()
        } catch (e: IOException) {
            // refused during or right after the handshake
        }
    }

    private fun assertNoLink(n: FrostDkgTlsNode.Node, attempt: () -> Unit) {
        attempt()
        try {
            n.connect(emptyList(), 700.0)
            fail("a refused peer must not give a link")
        } catch (e: DkgChannelError) {
            assertEquals("timeout", e.code)
        }
    }

    @Test fun refusesWhatTheIdentityRuleForbids() {
        val me = identity("me")
        val pinnedHigher = identity("higher")
        val pinnedLower = identity("lower")
        val rogue = identity("rogue")

        // an unpinned certificate
        node(2, me, mapOf(3L to pinnedHigher)).let { n -> assertNoLink(n) { dialAs(rogue, n.port, null) } }
        // no certificate at all
        node(2, me, mapOf(3L to pinnedHigher)).let { n -> assertNoLink(n) { dialAs(null, n.port, null) } }
        // a pinned peer, but over TLS 1.2
        node(2, me, mapOf(3L to pinnedHigher)).let { n -> assertNoLink(n) { dialAs(pinnedHigher, n.port, arrayOf("TLSv1.2")) } }
        // a plaintext client
        node(2, me, mapOf(3L to pinnedHigher)).let { n ->
            assertNoLink(n) { try { java.net.Socket("127.0.0.1", n.port).use { it.getOutputStream().write("hello, plaintext".toByteArray()) } } catch (e: IOException) { /* refused */ } }
        }
        // a pinned peer that should have been dialled by this node (a LOWER id) never gets a link by dialling in
        node(2, me, mapOf(1L to pinnedLower)).let { n -> assertNoLink(n) { dialAs(pinnedLower, n.port, null) } }
    }

    @Test fun anAddressForAStrangerIsAnIdentityError() {
        val me = identity("me")
        val peer = identity("peer")
        val n = node(2, me, mapOf(3L to peer))
        try {
            n.connect(listOf(FrostDkgTlsNode.Address(9, "127.0.0.1", 1)), 100.0)
            fail("a stranger's address must be refused")
        } catch (e: DkgChannelError) {
            assertEquals("identity", e.code)
        } finally {
            n.close()
        }
    }
}
