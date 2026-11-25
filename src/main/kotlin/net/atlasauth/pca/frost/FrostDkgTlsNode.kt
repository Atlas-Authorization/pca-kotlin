package net.atlasauth.pca.frost

import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * The mutual-TLS channel of the FROST distributed key generation over the JDK's TLS (JSSE).
 *
 * One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly the other participants' certificates, and
 * the peer's SHA-256 certificate fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the handshake and never from message
 * content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a second connection
 * for an already linked identity and a connection from a party that should have been dialled are all refused before any DKG byte is read. Frames are a 4-byte
 * big-endian length then the message (see [FrostDkgTls]); the length is checked against [FrostDkgChannel.DKG_MAX_MESSAGE_BYTES] before any allocation.
 * Certificate issuance, rotation and revocation are the deployer's: this reads PEM (a PKCS#8 private key, X.509 certificates) and pins what it is given.
 */
object FrostDkgTlsNode {
    /** The pinned certificate of one OTHER participant. */
    class PeerCert(val id: Long, val certPem: String)

    /** `listenPort` 0 is ephemeral (read [Node.port]); the default host is 127.0.0.1. */
    class Options @JvmOverloads constructor(
        val self: Long, val sessionId: ByteArray, val keyPem: String, val certPem: String, val peerCerts: List<PeerCert>,
        val listenPort: Int = 0, val listenHost: String = "127.0.0.1",
    )

    /** Where to dial one lower-numbered peer. */
    class Address(val id: Long, val host: String, val port: Int)

    private const val HANDSHAKE_MS = 10_000
    private const val DIAL_MS = 5_000

    private fun fingerprint(der: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }

    private fun pemBody(pem: String, label: String): ByteArray {
        val m = Regex("-----BEGIN $label-----([A-Za-z0-9+/=\\s]+)-----END $label-----").find(pem) ?: throw IllegalArgumentException("startTlsDkgNode: no PEM $label")
        return Base64.getMimeDecoder().decode(m.groupValues[1])
    }

    private fun certOf(pem: String): X509Certificate {
        val der = try { pemBody(pem, "CERTIFICATE") } catch (e: IllegalArgumentException) { throw IllegalArgumentException("startTlsDkgNode: a peer certificate is not a PEM certificate") }
        return CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }

    private fun keyOf(pem: String): PrivateKey {
        val der = pemBody(pem, "PRIVATE KEY") // PKCS#8
        val spec = PKCS8EncodedKeySpec(der)
        for (alg in listOf("EC", "RSA", "Ed25519", "Ed448", "RSASSA-PSS")) {
            try { return KeyFactory.getInstance(alg).generatePrivate(spec) } catch (e: java.security.GeneralSecurityException) { /* next algorithm */ }
        }
        throw IllegalArgumentException("startTlsDkgNode: the private key is not a supported PKCS#8 key")
    }

    /** One participant's listener and links. */
    class Node internal constructor(private val o: Options) {
        private val pinned = HashMap<String, Long>()
        val peers: List<Long>
        private val lock = Object()
        private val links = HashMap<Long, Link>()
        private val conns = HashSet<Socket>()
        private var closed = false
        private val framed: FrostDkgTls.FramedChannel
        private val ctx: SSLContext
        private val server: SSLServerSocket

        private class Link(val sock: SSLSocket)

        /** The port the node listens on. */
        val port: Int

        init {
            val ps = ArrayList<Long>()
            for (p in o.peerCerts) {
                pinned[fingerprint(certOf(p.certPem).encoded)] = p.id
                ps.add(p.id)
            }
            if (pinned.size != o.peerCerts.size || o.peerCerts.any { it.id == o.self }) throw IllegalArgumentException("startTlsDkgNode: peer certificates must be distinct and none may be this node")
            peers = ps.sorted()
            framed = FrostDkgTls.FramedChannel(o.self, o.sessionId, peers) { to, frame -> write(to, frame) }

            val ks = KeyStore.getInstance("PKCS12")
            ks.load(null, null)
            ks.setKeyEntry("node", keyOf(o.keyPem), "node".toCharArray(), arrayOf(certOf(o.certPem)))
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, "node".toCharArray())
            ctx = SSLContext.getInstance("TLSv1.3")
            ctx.init(kmf.keyManagers, arrayOf(PinnedTrust()), null)

            server = ctx.serverSocketFactory.createServerSocket(o.listenPort, 50, InetAddress.getByName(o.listenHost)) as SSLServerSocket
            server.enabledProtocols = arrayOf("TLSv1.3")
            server.needClientAuth = true
            port = server.localPort
            val t = Thread({ serve() }, "dkg-tls-accept-${o.self}")
            t.isDaemon = true
            t.start()
        }

        /** The certificate verification: a TLS 1.3 handshake whose peer certificate is one of the pinned ones, inside its validity. */
        private inner class PinnedTrust : X509TrustManager {
            private fun check(chain: Array<X509Certificate>?) {
                if (chain == null || chain.isEmpty()) throw CertificateException("no certificate")
                if (!pinned.containsKey(fingerprint(chain[0].encoded))) throw CertificateException("certificate is not pinned")
                chain[0].checkValidity()
            }
            override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = check(chain)
            override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = check(chain)
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray() // pinned by certificate: any issuer name is offered
        }

        private fun track(s: Socket): Boolean = synchronized(lock) { if (closed) false else { conns.add(s); true } }

        private fun peerId(s: SSLSocket): Long? {
            val c = s.session.peerCertificates.firstOrNull() as? X509Certificate ?: return null
            return pinned[fingerprint(c.encoded)]
        }

        private fun serve() {
            while (true) {
                val raw = try { server.accept() as SSLSocket } catch (e: IOException) { return }
                val t = Thread({ inbound(raw) }, "dkg-tls-inbound-${o.self}")
                t.isDaemon = true
                t.start()
            }
        }

        private fun inbound(s: SSLSocket) {
            try {
                if (!track(s)) { s.close(); return }
                s.soTimeout = HANDSHAKE_MS
                s.startHandshake()
                s.soTimeout = 0
                val id = peerId(s)
                // Only a pinned, authorized peer that is supposed to dial us (higher id), once.
                val linked = synchronized(lock) { id != null && links.containsKey(id) }
                if (!FrostDkgTls.acceptInbound(o.self, true, id, linked)) { s.close(); return }
                attach(id!!, s)
            } catch (e: IOException) {
                try { s.close() } catch (x: IOException) { /* gone */ }
            }
        }

        private fun attach(id: Long, s: SSLSocket) {
            val link = Link(s)
            synchronized(lock) {
                if (closed || links.containsKey(id)) { try { s.close() } catch (e: IOException) { /* gone */ }; return }
                links[id] = link
                lock.notifyAll()
            }
            try { s.tcpNoDelay = true } catch (e: IOException) { /* best effort */ }
            val t = Thread({ read(id, link, s.inputStream) }, "dkg-tls-read-${o.self}-$id")
            t.isDaemon = true
            t.start()
        }

        private fun read(id: Long, link: Link, input: InputStream) {
            val buf = ByteArray(32 * 1024)
            try {
                while (true) {
                    val k = input.read(buf)
                    if (k < 0) break
                    if (k > 0 && !framed.onData(id, buf.copyOf(k))) { link.sock.close(); break }
                }
            } catch (e: IOException) { /* the link ended */ }
            synchronized(lock) { if (links[id] === link) links.remove(id) }
            framed.onLinkClosed(id)
        }

        private fun write(to: Long, frame: ByteArray) {
            val link = synchronized(lock) { links[to] } ?: throw DkgChannelError("closed", to, "no authenticated link")
            try {
                synchronized(link) {
                    link.sock.outputStream.write(frame)
                    link.sock.outputStream.flush()
                }
            } catch (e: IOException) {
                throw DkgChannelError("closed", to, "write failed")
            }
        }

        private fun stopped(stop: BooleanArray): Boolean = synchronized(lock) { stop[0] || closed }

        private fun dial(a: Address, stop: BooleanArray) {
            while (!stopped(stop)) {
                var raw: Socket? = null
                try {
                    raw = Socket()
                    raw.connect(InetSocketAddress(a.host, a.port), DIAL_MS)
                    val s = ctx.socketFactory.createSocket(raw, a.host, a.port, true) as SSLSocket
                    s.enabledProtocols = arrayOf("TLSv1.3")
                    if (!track(s)) { s.close(); return }
                    s.soTimeout = HANDSHAKE_MS
                    s.startHandshake()
                    s.soTimeout = 0
                    if (peerId(s) == a.id) { attach(a.id, s); return }
                    s.close()
                } catch (e: IOException) {
                    try { raw?.close() } catch (x: IOException) { /* gone */ }
                }
                try { Thread.sleep(50) } catch (e: InterruptedException) { return }
            }
        }

        /**
         * Dial the lower-numbered peers, wait for the higher-numbered ones, and return the channel once every link is authenticated. A missing link after
         * [connectTimeoutMs] closes the node and throws a `timeout` [DkgChannelError]. An address for a participant that is not a pinned peer is an `identity` error.
         */
        @JvmOverloads
        fun connect(addresses: List<Address>, connectTimeoutMs: Double = 15_000.0): DkgChannel {
            val stop = BooleanArray(1)
            for (a in addresses) {
                if (a.id !in peers) throw DkgChannelError("identity", a.id, "address for a participant that is not a pinned peer")
                if (a.id < o.self) {
                    val t = Thread({ dial(a, stop) }, "dkg-tls-dial-${o.self}-${a.id}")
                    t.isDaemon = true
                    t.start()
                }
            }
            val deadline = System.nanoTime() + (connectTimeoutMs * 1_000_000.0).toLong()
            var missing: List<Long> = emptyList()
            synchronized(lock) {
                while (true) {
                    missing = peers.filter { !links.containsKey(it) }
                    if (missing.isEmpty()) break
                    val left = (deadline - System.nanoTime()) / 1_000_000
                    if (left <= 0) break
                    lock.wait(left)
                }
                stop[0] = true
            }
            if (missing.isNotEmpty()) {
                close()
                throw DkgChannelError("timeout", missing[0], "no authenticated link to ${missing.joinToString(",")}")
            }
            return object : DkgChannel by framed {
                override fun close() = this@Node.close()
            }
        }

        /** End every link and the listener. */
        fun close() {
            val all: List<Socket>
            synchronized(lock) {
                if (closed) return
                closed = true
                all = conns.toList()
                lock.notifyAll()
            }
            framed.close()
            for (s in all) try { s.close() } catch (e: IOException) { /* gone */ }
            try { server.close() } catch (e: IOException) { /* gone */ }
        }
    }

    /** Start a node: it listens at once for the higher-numbered peers. */
    @JvmStatic
    fun start(o: Options): Node = Node(o)
}
