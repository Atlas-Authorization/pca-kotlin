package net.atlasauth.pca.mpc.net

import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.ArrayDeque
import java.util.TreeMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedTrustManager
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.Frame
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.verifier.Json

/**
 * Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3.
 *
 * - MUTUAL TLS with PINNED self-signed certificates ([Certs]). A peer is identified by the SHA-256 fingerprint of its certificate,
 *   never by anything it claims; the id in its hello frame must agree with the pinned fingerprint.
 * - Strict framing and per-link sequence numbers. A malformed frame, a replayed or skipped one, a frame for the wrong round or
 *   session, or an oversize length prefix aborts the whole run with a [NetAbort] naming the sender.
 * - Every receive has a timeout (no hangs); a silent peer is blamed after `recvTimeoutMs`.
 * - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an `abort` frame to every
 *   peer, then closes the sockets. Once failed nothing further is sent as protocol data.
 *
 * A node dials every lower-numbered link target and accepts from the higher-numbered ones.
 *
 * Platform: TLS 1.3 only, with no TLS 1.2 fallback. On Android that needs API 29 (Android 10) or newer; on older devices the
 * handshake is refused and [connect] aborts with a `timeout` naming the missing peer.
 */
class Mesh(private val cfg: Config) {
    /** A node of the session: its address and PUBLIC certificate (the pinned trust anchor and identity). */
    data class NodeAddr(val id: Int, val host: String, val port: Int, val certPem: String)

    /** TEST HOOK input: a frame about to be sent and its honest encoding. */
    class TamperEvent(val to: Int, val frame: Frame, val raw: ByteArray)

    data class LinkStats(val peer: Int, val appBytesOut: Long, val appBytesIn: Long, val framesOut: Long, val framesIn: Long)

    class Config {
        @JvmField var selfId: Int = 0

        /** Every node of the session, including self. */
        @JvmField var nodes: List<NodeAddr>? = null

        /** Node ids this node keeps a link to (default: all others). */
        @JvmField var linkTo: List<Int>? = null
        @JvmField var keyPem: String? = null
        @JvmField var certPem: String? = null
        @JvmField var sessionId: String? = null
        @JvmField var listenHost: String = "0.0.0.0"
        @JvmField var connectTimeoutMs: Long = 30_000
        @JvmField var recvTimeoutMs: Long = 20_000

        /** Time source for deadlines (default: real time). */
        @JvmField var clock: MeshClock? = null

        /** TEST HOOK: a (malicious) sender rewriting its own outgoing frames; refused unless [unsafeTestHooks]. */
        @JvmField var tamper: ((TamperEvent) -> List<ByteArray>)? = null
        /** TEST HOOK: runs on the attaching thread once the link is open and before our hello is sent; refused unless [unsafeTestHooks]. */
        @JvmField var beforeHello: Runnable? = null
        @JvmField var unsafeTestHooks: Boolean = false
        @JvmField var maxInboxFrames: Int = 1024
        @JvmField var maxInboxBytes: Long = 32L * 1024 * 1024
    }

    companion object {
        const val MAX_MESH_EVENTS = 64
        private val TLS13 = arrayOf("TLSv1.3")

        /** Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging). */
        internal fun sanitize(x: String, max: Int): String {
            val sb = StringBuilder()
            for (c in x) sb.append(if (c.code in 0x20..0x7e) c else '?')
            return if (sb.length > max) sb.substring(0, max) else sb.toString()
        }

        /**
         * Bind every mesh (each on the port its config names; 0 = the OS's choice), then tell every mesh the ports the others really got.
         * The meshes are held open throughout: no port is probed, released and bound again later. Call before any [connect].
         */
        @JvmStatic
        fun bindAll(meshes: List<Mesh>) {
            val ports = meshes.map { it.selfId to it.listen() }
            for (m in meshes) for ((id, port) in ports) if (id != m.selfId) m.resolvePort(id, port)
        }

        private fun daemon(name: String, r: Runnable): Thread = Thread(r, name).also { it.isDaemon = true }

        private fun closeQuietly(s: Socket?) {
            if (s == null) return
            try { s.close() } catch (e: IOException) { /* already gone */ }
        }

        private fun asInt(o: Any?): Int? {
            if (o !is Json.Num) return null
            val d = o.toString().toDoubleOrNull() ?: return null
            if (d.isNaN() || d.isInfinite() || d != Math.rint(d) || Math.abs(d) > 1e9 || (d == 0.0 && 1 / d < 0)) return null
            return d.toInt()
        }
    }

    private class Item(val rd: String?, val d: Any?, val size: Int, val abort: NetAbort?)

    private class Link(val id: Int) {
        val splitter = NetWire.FrameSplitter()
        val inbox = ArrayDeque<Item>()
        var socket: SSLSocket? = null
        var out: OutputStream? = null
        var inboxBytes: Long = 0
        var paused = false
        var sendSeq: Long = 0
        var recvSeq: Long = 0
        @Volatile var closed = false
        @Volatile var helloSeen = false
        val bytesIn = AtomicLong()
        val bytesOut = AtomicLong()
        val framesIn = AtomicLong()
        val framesOut = AtomicLong()
    }

    /** Trust exactly the pinned certificates (by SHA-256 fingerprint); no chain building, no hostnames. */
    private class PinTrust(private val pins: Set<String>) : X509ExtendedTrustManager() {
        private fun check(chain: Array<X509Certificate>?) {
            if (chain == null || chain.isEmpty()) throw CertificateException("no peer certificate")
            chain[0].checkValidity()
            if (!pins.contains(Certs.fingerprint(chain[0]))) throw CertificateException("peer certificate is not pinned")
        }

        override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) = check(c)
        override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) = check(c)
        override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?, s: Socket?) = check(c)
        override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?, s: Socket?) = check(c)
        override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?, e: SSLEngine?) = check(c)
        override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?, e: SSLEngine?) = check(c)
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    @JvmField val selfId: Int = cfg.selfId
    private val clock: MeshClock = cfg.clock ?: MeshClock.WALL
    private val sessionId: String
    private val links = TreeMap<Int, Link>()
    private val pinned = HashMap<String, Int>()
    private val nodeById = HashMap<Int, NodeAddr>()
    private val privateKey: PrivateKey
    private val lock = ReentrantLock()
    private val wake = lock.newCondition()
    private val events = ArrayList<String>()
    private val eventsDropped = AtomicLong()
    @Volatile private var failure: NetAbort? = null
    @Volatile private var finished = false
    @Volatile private var closing = false
    @Volatile private var deferAborts = false
    private var ctx: SSLContext? = null
    private var server: SSLServerSocket? = null

    init {
        require((cfg.tamper == null && cfg.beforeHello == null) || cfg.unsafeTestHooks) { "mesh: the test hooks require unsafeTestHooks (test-only)" }
        val nodes = cfg.nodes
        val sid = cfg.sessionId
        val keyPem = cfg.keyPem
        val certPem = cfg.certPem
        require(nodes != null && sid != null && keyPem != null && certPem != null) { "mesh: incomplete config" }
        sessionId = sid
        privateKey = Certs.parseKey(keyPem)
        val selfFp = Certs.fingerprintOf(certPem)
        var selfSeen = false
        for (n in nodes) {
            require(nodeById.put(n.id, n) == null) { "mesh: duplicate node id ${n.id}" }
            val fp = Certs.fingerprintOf(n.certPem)
            if (n.id == selfId) {
                selfSeen = true
                require(fp == selfFp) { "mesh: own certificate differs from the one listed for this node" }
            } else {
                require(pinned.put(fp, n.id) == null && fp != selfFp) { "mesh: two nodes share one certificate" }
            }
        }
        require(selfSeen) { "mesh: self not in nodes" }
        val want = ArrayList<Int>()
        val lt = cfg.linkTo
        if (lt != null) want.addAll(lt) else for (n in nodes) if (n.id != selfId) want.add(n.id)
        for (id in want) {
            require(nodeById.containsKey(id) && id != selfId) { "mesh: unknown link target $id" }
            links[id] = Link(id)
        }
    }

    private fun note(msg: String) {
        synchronized(events) {
            if (events.size < MAX_MESH_EVENTS) events.add(msg) else eventsDropped.incrementAndGet()
        }
    }

    fun events(): List<String> = synchronized(events) { ArrayList(events) }
    fun eventsDropped(): Long = eventsDropped.get()
    fun sessionId(): String = sessionId
    fun failed(): NetAbort? = failure
    fun peers(): List<Int> = ArrayList(links.keys)

    // ------------------------------------------------------------------ connect

    private fun buildContext(): SSLContext {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("node", privateKey, CharArray(0), arrayOf(Certs.parseCert(cfg.certPem!!)))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, CharArray(0))
        val c = SSLContext.getInstance("TLSv1.3")
        c.init(kmf.keyManagers, arrayOf<TrustManager>(PinTrust(HashSet(pinned.keys))), null)
        return c
    }

    /** Port the TLS server is bound to (useful when the configured port was 0). */
    fun boundPort(): Int = server?.localPort ?: -1

    /**
     * Bind the TLS server (the configured port; 0 lets the OS choose) and return the port actually bound. Idempotent. A cluster binds every node
     * first, tells each node the real ports with [resolvePort], and only then calls [connect]: no port is probed and released in between.
     */
    @Synchronized
    fun listen(): Int {
        server?.let { return it.localPort }
        val self = nodeById[selfId]!!
        try {
            val c = buildContext()
            val s = c.serverSocketFactory.createServerSocket(self.port, 128, InetAddress.getByName(cfg.listenHost)) as SSLServerSocket
            s.enabledProtocols = TLS13
            s.needClientAuth = true
            ctx = c
            server = s
            return s.localPort
        } catch (e: Exception) {
            throw IllegalStateException("mesh: cannot listen: " + e.message, e)
        }
    }

    /** Record the port node [id] actually bound (call before [connect]). */
    @Synchronized
    fun resolvePort(id: Int, port: Int) {
        val n = nodeById[id] ?: throw IllegalArgumentException("mesh: unknown node $id")
        nodeById[id] = n.copy(port = port)
    }

    /** Listen (if not yet), dial every lower-numbered link target, and wait until all links are authenticated. */
    fun connect() {
        val deadline = clock.now() + cfg.connectTimeoutMs
        listen()
        daemon("mesh-accept-$selfId") { acceptLoop() }.start()
        for (id in peers()) if (id < selfId) daemon("mesh-dial-$selfId-$id") { dial(id, deadline) }.start()
        var toFail: NetAbort? = null
        lock.lock()
        try {
            while (true) {
                val cur = failure
                if (cur != null) throw cur
                val missing = ArrayList<Int>()
                for (l in links.values) if (!l.helloSeen) missing.add(l.id)
                if (missing.isEmpty()) return
                val left = deadline - clock.now()
                if (left <= 0) {
                    toFail = NetAbort("timeout", missing[0], selfId, "connect: no authenticated link from $missing")
                    break
                }
                try {
                    wake.awaitNanos(20_000_000L) // a poll interval, not a decision: real time
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    toFail = NetAbort("local", null, selfId, "connect interrupted")
                    break
                }
            }
        } finally {
            lock.unlock()
        }
        val tf = toFail!!
        fail(tf, null)
        throw tf
    }

    private fun wakeAll() {
        lock.lock()
        try {
            wake.signalAll()
        } finally {
            lock.unlock()
        }
    }

    private fun acceptLoop() {
        val srv = server!!
        while (!closing && failure == null) {
            val s: Socket
            try {
                s = srv.accept()
            } catch (e: IOException) {
                if (!closing) note("server error: " + e.message)
                return
            }
            val sock = s as SSLSocket
            daemon("mesh-in-$selfId") { onIncoming(sock) }.start()
        }
    }

    private fun dial(id: Int, deadline: Long) {
        val node = nodeById[id]!!
        while (failure == null && !closing && clock.now() < deadline) {
            var s: SSLSocket? = null
            try {
                s = ctx!!.socketFactory.createSocket() as SSLSocket
                s.connect(InetSocketAddress(node.host, node.port), 3000)
                s.enabledProtocols = TLS13
                s.tcpNoDelay = true
                s.soTimeout = maxOf(1L, minOf(Int.MAX_VALUE.toLong(), deadline - clock.now())).toInt()
                s.startHandshake()
                s.soTimeout = 0
                // We pin by certificate (not hostname): the peer must be exactly the pinned identity of node `id`.
                val got = pinned[Certs.fingerprint(s.session.peerCertificates[0] as X509Certificate)]
                if (got == null || got != id) {
                    closeQuietly(s)
                    fail(NetAbort("identity", id, selfId, "dial: peer certificate is not the pinned identity of node $id"), null)
                    return
                }
                attach(id, s)
                return
            } catch (e: IOException) {
                closeQuietly(s)
            }
            try {
                Thread.sleep(150) // retry pacing, not a decision
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }

    private fun onIncoming(sock: SSLSocket) {
        try {
            sock.enabledProtocols = TLS13
            sock.tcpNoDelay = true
            sock.soTimeout = minOf(Int.MAX_VALUE.toLong(), cfg.connectTimeoutMs).toInt()
            sock.startHandshake()
            sock.soTimeout = 0
            val id = pinned[Certs.fingerprint(sock.session.peerCertificates[0] as X509Certificate)]
            if (id == null || !links.containsKey(id) || id < selfId) {
                note("rejected incoming connection (peer $id)")
                closeQuietly(sock)
                return
            }
            attach(id, sock)
        } catch (e: Exception) {
            note("tlsClientError: " + sanitize(e.message.toString(), 120))
            closeQuietly(sock)
        }
    }

    private fun attach(id: Int, sock: SSLSocket) {
        val l = links[id]!!
        // The link monitor is held until our hello is out: a protocol thread whose connect() already returned (the peer's hello arrived first)
        // may send on this link at once, and its frame must not take seq 0 ahead of the hello ("data before hello" at the peer).
        synchronized(l) {
            lock.lock()
            try {
                if (l.socket != null) {
                    note("duplicate connection from node $id")
                    closeQuietly(sock)
                    return
                }
                try {
                    l.out = sock.outputStream
                    l.socket = sock
                } catch (e: IOException) {
                    closeQuietly(sock)
                    return
                }
            } finally {
                lock.unlock()
            }
            daemon("mesh-rd-$selfId-$id") { readLoop(l, sock) }.start()
            cfg.beforeHello?.run()
            // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
            val d = LinkedHashMap<String, Any?>()
            d["id"] = selfId
            sendFrame(l, "hello", "hello", d)
        }
    }

    // ------------------------------------------------------------------ receive path

    private fun readLoop(l: Link, sock: SSLSocket) {
        try {
            val input = sock.inputStream
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) { onClosed(l, "peer ended"); return }
                onData(l, buf.copyOf(n))
                if (failure != null) return
                lock.lock()
                try {
                    while (l.paused && failure == null && !l.closed) wake.awaitUninterruptibly()
                } finally {
                    lock.unlock()
                }
            }
        } catch (e: IOException) {
            onClosed(l, "socket error: " + e.message)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun onData(l: Link, chunk: ByteArray) {
        if (failure != null) return
        l.bytesIn.addAndGet(chunk.size.toLong())
        val bodies: List<ByteArray>
        try {
            bodies = l.splitter.push(chunk)
        } catch (e: IllegalStateException) {
            fail(NetAbort("oversize", l.id, selfId, "length prefix above MAX_FRAME_BYTES"), null)
            return
        }
        for (b in bodies) {
            val f = NetWire.parseFrame(b)
            if (f == null) {
                val pv = NetWire.versionMismatch(b)
                if (pv != null) {
                    fail(NetAbort("version", l.id, selfId, "peer ${l.id} speaks wire version $pv, this node speaks ${NetWire.WIRE_VERSION}; upgrade both peers"), null)
                } else {
                    fail(NetAbort("malformed", l.id, selfId, "undecodable or ill-shaped frame"), null)
                }
                return
            }
            val ty = f["ty"] as String
            val rd = f["rd"] as String?
            if (sessionId != f["sid"]) {
                fail(NetAbort("wrong-session", l.id, selfId, "frame from another session"), null)
                return
            }
            if (ty == "abort") {
                // An abort frame is only a CLAIM by the peer that sent it: we blame that peer, never the party it names.
                val dd = f["d"]
                val d: Map<String, Any?> = if (dd is Map<*, *>) dd as Map<String, Any?> else emptyMap()
                val relayed = d["relayed"] == true
                val ck = d["kind"]
                val claimedKind: String? = if (ck is String && NetWire.ABORT_KINDS.contains(ck)) ck else null
                var maxId = 0
                for (x in cfg.nodes!!) maxId = maxOf(maxId, x.id)
                val cb = asInt(d["blamed"])
                val claimedBlame: Int? = if (cb != null && cb >= 0 && cb <= maxId) cb else null
                val dt = d["detail"]
                val detail = if (dt is String) sanitize(dt, 120) else ""
                val claim = NetAbort(
                    "peer-abort", if (relayed) null else l.id, selfId,
                    "peer ${l.id} ${if (relayed) "relayed" else "reported"} an abort (${claimedKind ?: "unspecified"}, accuses ${claimedBlame?.toString() ?: "no one"}, unverified) $detail",
                    claimedKind, claimedBlame,
                    if (relayed) "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence" else null, null, null,
                )
                if (deferAborts) {
                    // Order-preserving: takes effect when READ, i.e. after every frame this peer sent before it.
                    lock.lock()
                    try { l.inbox.addLast(Item(rd, null, b.size, claim)) } finally { lock.unlock() }
                    continue
                }
                fail(claim, l.id)
                return
            }
            val seq = f["seq"].toString().toDouble().toLong()
            if (seq != l.recvSeq) {
                val kind = if (seq < l.recvSeq) "duplicate" else "out-of-order"
                fail(NetAbort(kind, l.id, selfId, "expected seq ${l.recvSeq}, got $seq (round $rd)"), null)
                return
            }
            l.recvSeq++
            l.framesIn.incrementAndGet()
            if (ty == "hello") {
                val dd = f["d"]
                val hid = if (dd is Map<*, *>) asInt(dd["id"]) else null
                if (l.helloSeen || hid == null || hid != l.id) {
                    fail(NetAbort("identity", l.id, selfId, "hello claims id ${hid?.toString() ?: "?"} on the link pinned to ${l.id}"), null)
                    return
                }
                lock.lock()
                try { l.helloSeen = true; wake.signalAll() } finally { lock.unlock() }
            } else {
                if (!l.helloSeen) {
                    fail(NetAbort("malformed", l.id, selfId, "data before hello"), null)
                    return
                }
                val flood: Boolean
                lock.lock()
                try {
                    l.inbox.addLast(Item(rd, f["d"], b.size, null))
                    l.inboxBytes += b.size
                    flood = l.inbox.size > cfg.maxInboxFrames || l.inboxBytes > cfg.maxInboxBytes
                    if (!flood && !l.paused && (l.inbox.size > cfg.maxInboxFrames / 2 || l.inboxBytes > cfg.maxInboxBytes / 2)) l.paused = true
                } finally {
                    lock.unlock()
                }
                if (flood) {
                    fail(NetAbort("flood", l.id, selfId, "peer ${l.id} queued more than the inbox cap allows"), null)
                    return
                }
            }
        }
        lock.lock()
        try { wake.signalAll() } finally { lock.unlock() }
    }

    private fun onClosed(l: Link, why: String) {
        if (l.closed) return
        l.closed = true
        if (!finished && failure == null && !l.helloSeen) note("link ${l.id} closed before hello: $why")
        lock.lock()
        try { wake.signalAll() } finally { lock.unlock() }
    }

    // ------------------------------------------------------------------ send path

    private fun sendFrame(l: Link, ty: String, rd: String, d: Any?) {
        synchronized(l) {
            val frame = Frame(NetWire.WIRE_VERSION, ty, sessionId, l.sendSeq++, rd, d)
            val raw = NetWire.encodeFrame(frame)
            val t = cfg.tamper
            val outs = if (t != null && ty != "hello") t(TamperEvent(l.id, frame, raw)) else listOf(raw)
            writeAll(l, outs)
            l.framesOut.incrementAndGet()
        }
    }

    private fun writeAll(l: Link, outs: List<ByteArray>) {
        for (b in outs) {
            val s = l.socket
            if (s != null && !s.isClosed) {
                try {
                    l.out!!.write(b)
                    l.out!!.flush()
                    l.bytesOut.addAndGet(b.size.toLong())
                } catch (e: IOException) {
                    // the dead link surfaces as a disconnect on the read side
                }
            }
        }
    }

    /** Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed). */
    fun send(to: Int, round: String, payload: Any?) {
        val f = failure
        if (f != null) throw f
        val l = links[to] ?: throw IllegalArgumentException("mesh: no link to $to")
        sendFrame(l, "msg", round, payload)
    }

    fun broadcast(round: String, payload: Any?) {
        broadcast(round, payload, peers())
    }

    fun broadcast(round: String, payload: Any?, to: List<Int>) {
        for (p in to) send(p, round, payload)
    }

    /** ECDSA-P256/SHA-256 (DER) signature over [data] with this node's TLS identity key. */
    fun sign(data: ByteArray): ByteArray =
        try {
            val s = Signature.getInstance("SHA256withECDSA")
            s.initSign(privateKey)
            s.update(data)
            s.sign()
        } catch (e: Exception) {
            throw IllegalStateException("mesh: sign failed", e)
        }

    /** Verify [sig] over [data] against the PINNED certificate of node [peer]. False on any failure. */
    fun verify(peer: Int, data: ByteArray, sig: ByteArray): Boolean {
        val n = nodeById[peer]
        if (n == null || peer == selfId) return false
        return try {
            val s = Signature.getInstance("SHA256withECDSA")
            s.initVerify(Certs.parseCert(n.certPem).publicKey)
            s.update(data)
            s.verify(sig)
        } catch (e: Exception) {
            false
        }
    }

    /** Receive the next message from [from], which must belong to [round]. Times out; never hangs. */
    fun recv(from: Int, round: String): Any? = recv(from, round, cfg.recvTimeoutMs)

    fun recv(from: Int, round: String, timeoutMs: Long): Any? {
        val l = links[from] ?: throw IllegalArgumentException("mesh: no link to $from")
        val deadline = clock.now() + timeoutMs
        var toFail: NetAbort? = null
        var skip: Int? = null
        lock.lock()
        try {
            while (true) {
                val cur = failure
                if (cur != null) throw cur
                val it = l.inbox.pollFirst()
                if (it != null) {
                    if (it.abort != null) { toFail = it.abort; skip = from; break }
                    l.inboxBytes -= it.size
                    if (l.paused && l.inbox.size <= cfg.maxInboxFrames / 2 && l.inboxBytes <= cfg.maxInboxBytes / 2) {
                        l.paused = false
                        wake.signalAll()
                    }
                    if (it.rd != round) {
                        toFail = NetAbort("wrong-round", from, selfId, "expected round '$round', got '${it.rd}'")
                        break
                    }
                    return it.d
                }
                if (l.closed) {
                    toFail = NetAbort("disconnect", from, selfId, "link to $from closed while awaiting '$round'")
                    break
                }
                val left = deadline - clock.now()
                if (left <= 0) {
                    toFail = NetAbort(
                        "timeout", from, selfId,
                        "no '$round' message from $from within ${timeoutMs}ms (deadline ${timeoutMs}ms; a silent peer is blamed on this local observation only)",
                        null, null, null, null, minOf(Int.MAX_VALUE.toLong(), timeoutMs).toInt(),
                    )
                    break
                }
                var timer: Any? = null
                try {
                    timer = clock.setTimer({ wakeAll() }, left)
                    wake.await()
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    toFail = NetAbort("local", null, selfId, "receive interrupted")
                    break
                } finally {
                    if (timer != null) clock.clearTimer(timer)
                }
            }
        } finally {
            lock.unlock()
        }
        val tf = toFail!!
        fail(tf, skip)
        throw tf
    }

    /**
     * While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and only
     * takes effect when a receive from that peer reaches it (used for the blame round).
     */
    fun setDeferAborts(on: Boolean) { deferAborts = on }

    /** Receive [round] from every peer in [from] concurrently; a failure on any link throws. */
    @JvmOverloads
    fun collect(round: String, from: List<Int> = peers(), timeoutMs: Long? = null): Map<Int, Any?> {
        val t = timeoutMs ?: cfg.recvTimeoutMs
        val out = TreeMap<Int, Any?>()
        val err = arrayOfNulls<RuntimeException>(1)
        val ts = ArrayList<Thread>()
        for (p in from) {
            val th = daemon("mesh-collect-$p") {
                try {
                    val v = recv(p, round, t)
                    synchronized(out) { out[p] = v }
                } catch (e: RuntimeException) {
                    synchronized(out) { if (err[0] == null) err[0] = e }
                }
            }
            ts.add(th)
            th.start()
        }
        for (th in ts) {
            try {
                th.join()
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw NetAbort("local", null, selfId, "collect interrupted")
            }
        }
        err[0]?.let { throw it }
        return out
    }

    // ------------------------------------------------------------------ failure / shutdown

    /**
     * Poison the mesh: record the first failure, tell EVERY peer except [skipPeer] (a forwarded accusation stays a claim, so an
     * innocent bystander is never blamed for merely closing), close all.
     */
    fun fail(err: NetAbort, skipPeer: Int?) {
        lock.lock()
        try {
            if (failure != null) return
            failure = err
            wake.signalAll()
        } finally {
            lock.unlock()
        }
        val fwd = err.kind == "peer-abort"
        val kind = if (fwd) (err.claimedKind ?: "peer-abort") else err.kind
        val blamed = if (fwd) err.claimedBlame else err.blamed
        for (l in links.values) {
            if (skipPeer != null && l.id == skipPeer) continue
            val s = l.socket
            if (s != null && !s.isClosed && !l.closed) {
                val d = LinkedHashMap<String, Any?>()
                d["kind"] = kind
                d["blamed"] = blamed
                d["detail"] = sanitize(err.message ?: "", 200)
                if (fwd) d["relayed"] = true
                try {
                    synchronized(l) {
                        val frame = Frame(NetWire.WIRE_VERSION, "abort", sessionId, l.sendSeq++, "abort", d)
                        writeAll(l, listOf(NetWire.encodeFrame(frame)))
                    }
                } catch (e: RuntimeException) {
                    // best effort
                }
            }
        }
        daemon("mesh-fail-close") {
            try { Thread.sleep(50) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
            closeAll()
        }.start()
    }

    /** Normal completion: flush and close. Peers that are still reading see EOF only after our data. */
    fun finish() {
        finished = true
        try { Thread.sleep(100) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
        closeAll()
    }

    /** Abrupt shutdown with no abort frames (a crashed node; also the way a launcher stops a straggler). */
    fun kill() {
        closeAll()
    }

    private fun closeAll() {
        closing = true
        for (l in links.values) closeQuietly(l.socket)
        val s = server
        if (s != null) {
            try { s.close() } catch (e: IOException) { /* already closed */ }
        }
    }

    fun stats(): List<LinkStats> = links.values.map { LinkStats(it.id, it.bytesOut.get(), it.bytesIn.get(), it.framesOut.get(), it.framesIn.get()) }
}
