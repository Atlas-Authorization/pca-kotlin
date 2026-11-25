package net.atlasauth.pca.mpc.net

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.security.KeyStore
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.net.Certs.Identity
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** A virtual clock: time moves only when the test says so. Timers fire in order of due time during [advance]. */
class ManualClock : MeshClock {
    private var t = 0L
    private var seq = 0L
    private val timers = HashMap<Long, Pair<Long, Runnable>>()

    @Synchronized override fun now(): Long = t

    @Synchronized override fun setTimer(fn: Runnable, ms: Long): Any? {
        val id = ++seq
        timers[id] = Pair(t + ms, fn)
        return id
    }

    @Synchronized override fun clearTimer(handle: Any?) {
        timers.remove(handle as Long)
    }

    @Synchronized fun pending(): Int = timers.size

    fun advance(ms: Long) {
        val target = synchronized(this) { t + ms }
        while (true) {
            val fn: Runnable
            synchronized(this) {
                val best = timers.entries.filter { it.value.first <= target }.minByOrNull { it.value.first }
                if (best == null) { t = target; return }
                timers.remove(best.key)
                t = maxOf(t, best.value.first)
                fn = best.value.second
            }
            fn.run()
        }
    }
}

/** The mutual-TLS mesh over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id, oversize, replay, wrong round, early close). Identities are generated per run. */
class MpcMeshTest {
    companion object {
        const val SID = "mesh-test-session"

        /** Blocking tasks need real threads: the common pool can be as small as one thread on a small CI machine. */
        val EX = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }

        fun cfg(self: Int, nodes: List<NodeAddr>, id: Identity, connectMs: Long, recvMs: Long): Mesh.Config {
            val c = Mesh.Config()
            c.selfId = self
            c.nodes = nodes
            c.keyPem = id.keyPem
            c.certPem = id.certPem
            c.sessionId = SID
            c.listenHost = "127.0.0.1"
            c.connectTimeoutMs = connectMs
            c.recvTimeoutMs = recvMs
            return c
        }

        fun abortOf(t0: Throwable?): NetAbort {
            var t = t0
            while (t != null && t !is NetAbort) t = t.cause
            assertNotNull("expected a NetAbort", t)
            return t as NetAbort
        }

        fun <T> async(f: () -> T): Future<T> = EX.submit(Callable { f() })
    }

    @Test fun honestThreeNodeExchange() {
        val n = 3
        val ids = Array(n) { Certs.generate("node$it") }
        val nodes = (0 until n).map { NodeAddr(it, "127.0.0.1", 0, ids[it].certPem) }
        val meshes = Array(n) { Mesh(cfg(it, nodes, ids[it], 20_000, 10_000)) }
        Mesh.bindAll(meshes.toList())
        val conn = meshes.map { m -> async { m.connect() } }
        for (f in conn) f.get(30, TimeUnit.SECONDS)

        val runs = (0 until n).map { me ->
            async {
                meshes[me].broadcast("r1", linkedMapOf<String, Any?>("x" to me))
                meshes[me].collect("r1")
            }
        }
        for (i in 0 until n) {
            val got = runs[i].get(30, TimeUnit.SECONDS)
            assertEquals(n - 1, got.size)
            for ((k, v) in got) {
                assertNotEquals(i, k)
                assertEquals(k.toString(), (v as Map<*, *>)["x"].toString())
            }
        }
        // signatures are verifiable against the pinned certificate only
        val data = "statement".toByteArray()
        val sig = meshes[0].sign(data)
        assertTrue(meshes[1].verify(0, data, sig))
        assertFalse(meshes[1].verify(2, data, sig))
        assertFalse(meshes[1].verify(0, "other".toByteArray(), sig))
        assertFalse(meshes[0].verify(0, data, sig))
        for (m in meshes) m.finish()
    }

    /**
     * The acceptor's protocol thread sends the moment the link is open, before the attaching thread has sent our hello (the peer's hello
     * already arrived, so connect() returned). The hello must still be the first frame: the peer receives the data, not "data before hello".
     */
    @Test fun aSendRacingTheHelloDoesNotOvertakeIt() {
        val ids = Array(2) { Certs.generate("h$it") }
        val nodes = (0 until 2).map { NodeAddr(it, "127.0.0.1", 0, ids[it].certPem) }
        val c0 = cfg(0, nodes, ids[0], 20_000, 10_000)
        c0.unsafeTestHooks = true
        lateinit var m0: Mesh
        c0.beforeHello = Runnable {
            val sender = Thread { m0.send(1, "r1", "payload") }
            sender.isDaemon = true
            sender.start()
            // wait for a decision point, not a time: the sender either finished (the bug: it overtook the hello) or is parked on the link
            while (sender.isAlive && sender.state != Thread.State.BLOCKED) Thread.yield()
        }
        m0 = Mesh(c0)
        val m1 = Mesh(cfg(1, nodes, ids[1], 20_000, 10_000))
        val meshes = listOf(m0, m1)
        Mesh.bindAll(meshes)
        val conn = meshes.map { m -> async { m.connect() } }
        for (f in conn) f.get(30, TimeUnit.SECONDS)
        assertEquals("payload", m1.recv(0, "r1"))
        assertEquals(null, m1.failed())
        for (m in meshes) m.finish()
    }

    @Test fun seededIdentityKeyIsReproducible() {
        val a = Certs.generate("seeded", "seed-1".toByteArray())
        val b = Certs.generate("seeded", "seed-1".toByteArray())
        val c = Certs.generate("seeded", "seed-2".toByteArray())
        assertEquals(a.keyPem, b.keyPem)
        assertNotEquals(a.keyPem, c.keyPem)
        assertEquals(Certs.parseCert(a.certPem).publicKey, Certs.parseCert(b.certPem).publicKey)
        assertNotEquals(Certs.fingerprintOf(a.certPem), Certs.fingerprintOf(c.certPem))
    }

    @Test fun pinnedCertMismatchRefusesTheLink() {
        val real0 = Certs.generate("real0")
        val imposter = Certs.generate("imposter")
        val id1 = Certs.generate("node1")
        // node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        val view0 = listOf(NodeAddr(0, "127.0.0.1", 0, real0.certPem), NodeAddr(1, "127.0.0.1", 0, id1.certPem))
        val view1 = listOf(NodeAddr(0, "127.0.0.1", 0, imposter.certPem), NodeAddr(1, "127.0.0.1", 0, id1.certPem))
        val m0 = Mesh(cfg(0, view0, real0, 2_500, 2_000))
        val m1 = Mesh(cfg(1, view1, id1, 2_500, 2_000))
        Mesh.bindAll(listOf(m0, m1))
        val c0 = async { m0.connect() }
        val c1 = async { m1.connect() }
        val e1 = assertThrows(ExecutionException::class.java) { c1.get(20, TimeUnit.SECONDS) }
        assertTrue(listOf("timeout", "identity").contains(abortOf(e1).kind))
        assertThrows(ExecutionException::class.java) { c0.get(20, TimeUnit.SECONDS) }
    }

    @Test fun tamperHookNeedsExplicitOptIn() {
        val id0 = Certs.generate("n0")
        val id1 = Certs.generate("n1")
        val nodes = listOf(NodeAddr(0, "127.0.0.1", 1, id0.certPem), NodeAddr(1, "127.0.0.1", 2, id1.certPem))
        val c = cfg(0, nodes, id0, 1000, 1000)
        c.tamper = { ev -> listOf(ev.raw) }
        assertThrows(IllegalArgumentException::class.java) { Mesh(c) }
        // a node whose own certificate differs from the one listed for it is refused
        assertThrows(IllegalArgumentException::class.java) { Mesh(cfg(0, nodes, id1, 1000, 1000)) }
    }

    // ---- refusals from a hand-driven peer (node 1 dials node 0) ----

    /** A raw TLS client speaking the frame format, standing in for node 1. */
    class RawPeer(me: Identity, serverCertPem: String, port: Int) : AutoCloseable {
        val sock: SSLSocket
        val out: OutputStream
        val input: InputStream

        init {
            val ks = KeyStore.getInstance("PKCS12")
            ks.load(null, null)
            ks.setKeyEntry("k", Certs.parseKey(me.keyPem), CharArray(0), arrayOf(Certs.parseCert(me.certPem)))
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, CharArray(0))
            val ts = KeyStore.getInstance("PKCS12")
            ts.load(null, null)
            ts.setCertificateEntry("srv", Certs.parseCert(serverCertPem))
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(ts)
            val ctx = SSLContext.getInstance("TLSv1.3")
            ctx.init(kmf.keyManagers, tmf.trustManagers, null)
            var s: SSLSocket? = null
            val end = System.nanoTime() + 10_000_000_000L
            while (true) {
                try {
                    s = ctx.socketFactory.createSocket() as SSLSocket
                    s.connect(InetSocketAddress("127.0.0.1", port), 2000)
                    s.enabledProtocols = arrayOf("TLSv1.3")
                    s.startHandshake()
                    break
                } catch (e: IOException) {
                    s?.close()
                    if (System.nanoTime() > end) throw e
                    Thread.sleep(100)
                }
            }
            sock = s!!
            out = sock.outputStream
            input = sock.inputStream
        }

        fun frame(ty: String, rd: String, seq: Long, d: Any?) {
            out.write(NetWire.encodeFrame(NetWire.Frame(NetWire.WIRE_VERSION, ty, SID, seq, rd, d)))
            out.flush()
        }

        fun hello(claimedId: Int) = frame("hello", "hello", 0, linkedMapOf<String, Any?>("id" to claimedId))

        override fun close() = sock.close()
    }

    private class Rig(val id0: Identity, val id1: Identity, val m0: Mesh, val connect: Future<Unit>, val port: Int)

    private fun rig(connectMs: Long, recvMs: Long, clock: MeshClock? = null): Rig {
        val id0 = Certs.generate("n0")
        val id1 = Certs.generate("n1")
        val nodes = listOf(NodeAddr(0, "127.0.0.1", 0, id0.certPem), NodeAddr(1, "127.0.0.1", 1, id1.certPem))
        val c = cfg(0, nodes, id0, connectMs, recvMs)
        c.clock = clock
        val m0 = Mesh(c)
        val p0 = m0.listen() // the port the OS gave this node, read from the bound socket
        return Rig(id0, id1, m0, async { m0.connect() }, p0)
    }

    @Test fun helloWithWrongPartyIdIsRefused() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(5)
            val a = abortOf(assertThrows(ExecutionException::class.java) { r.connect.get(15, TimeUnit.SECONDS) })
            assertEquals("identity", a.kind)
            assertEquals(1, a.blamed)
        }
    }

    @Test fun oversizeLengthPrefixIsRefused() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            val bad = NetWire.MAX_FRAME_BYTES + 1
            p.out.write(byteArrayOf((bad ushr 24).toByte(), (bad ushr 16).toByte(), (bad ushr 8).toByte(), bad.toByte()))
            p.out.flush()
            val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 5_000) }
            assertEquals("oversize", a.kind)
            assertEquals(1, a.blamed)
        }
    }

    @Test fun replayedSequenceNumberIsRefused() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            p.frame("msg", "x", 1, "a")
            p.frame("msg", "x", 1, "b")
            val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 5_000); r.m0.recv(1, "x", 5_000) }
            assertEquals("duplicate", a.kind)
        }
    }

    @Test fun skippedSequenceNumberIsRefused() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            p.frame("msg", "x", 5, "a")
            val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 5_000) }
            assertEquals("out-of-order", a.kind)
        }
    }

    @Test fun wrongRoundIsRefused() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            p.frame("msg", "other", 1, "a")
            val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 5_000) }
            assertEquals("wrong-round", a.kind)
            assertEquals(1, a.blamed)
        }
    }

    @Test fun earlyCloseIsADisconnect() {
        val r = rig(10_000, 5_000)
        val p = RawPeer(r.id1, r.id0.certPem, r.port)
        p.hello(1)
        r.connect.get(15, TimeUnit.SECONDS)
        p.close()
        val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 5_000) }
        assertEquals("disconnect", a.kind)
        assertEquals(1, a.blamed)
    }

    @Test fun silentPeerIsBlamedAfterTheDeadline() {
        val r = rig(10_000, 5_000)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            val a = assertThrows(NetAbort::class.java) { r.m0.recv(1, "x", 300) }
            assertEquals("timeout", a.kind)
            assertEquals(1, a.blamed)
            assertEquals(300, a.deadlineMs)
        }
    }

    @Test fun virtualClockDecidesTheReceiveDeadline() {
        val clock = ManualClock()
        val r = rig(10_000, 5_000, clock)
        RawPeer(r.id1, r.id0.certPem, r.port).use { p ->
            p.hello(1)
            r.connect.get(15, TimeUnit.SECONDS)
            val res = async { try { r.m0.recv(1, "x", 60_000); null } catch (e: NetAbort) { e } }
            val end = System.nanoTime() + 10_000_000_000L
            while (clock.pending() == 0 && System.nanoTime() < end) Thread.sleep(10)
            assertEquals(1, clock.pending())
            Thread.sleep(200)
            assertFalse(res.isDone) // real time passing decides nothing
            clock.advance(60_000)
            val a = res.get(10, TimeUnit.SECONDS)
            assertNotNull(a)
            assertEquals("timeout", a!!.kind)
            assertEquals(1, a.blamed)
        }
    }

    @Test fun clientWithAnUnpinnedCertificateNeverLinks() {
        val r = rig(2_000, 1_000)
        val stranger = Certs.generate("stranger")
        try {
            RawPeer(stranger, r.id0.certPem, r.port).use { p -> p.hello(1) }
        } catch (e: IOException) {
            // the server may refuse the unpinned client before or after the handshake completes on our side
        }
        val a = abortOf(assertThrows(ExecutionException::class.java) { r.connect.get(15, TimeUnit.SECONDS) })
        assertEquals("timeout", a.kind)
    }

    // ---- fault injection ----

    private fun twoNodes(view1Port0: (Int) -> Int, tamper1: ((Mesh.TamperEvent) -> List<ByteArray>)?, connectMs: Long): Triple<Mesh, Mesh, Pair<Future<Unit>, Future<Unit>>> {
        val id0 = Certs.generate("a0")
        val id1 = Certs.generate("a1")
        val view0 = listOf(NodeAddr(0, "127.0.0.1", 0, id0.certPem), NodeAddr(1, "127.0.0.1", 0, id1.certPem))
        val view1 = listOf(NodeAddr(0, "127.0.0.1", 0, id0.certPem), NodeAddr(1, "127.0.0.1", 0, id1.certPem))
        val c1 = cfg(1, view1, id1, connectMs, 5_000)
        if (tamper1 != null) { c1.tamper = tamper1; c1.unsafeTestHooks = true }
        val m0 = Mesh(cfg(0, view0, id0, connectMs, 5_000))
        val m1 = Mesh(c1)
        Mesh.bindAll(listOf(m0, m1))
        // what node 1 dials for node 0 may be a proxy in front of the port node 0 really bound
        m1.resolvePort(0, view1Port0(m0.boundPort()))
        return Triple(m0, m1, Pair(async { m0.connect() }, async { m1.connect() }))
    }

    @Test fun duplicatedFrameFromAMaliciousSenderIsRefused() {
        val (m0, m1, conn) = twoNodes({ it }, Faults.tamperFor(FrameFault(FrameFaultKind.DUPLICATE, "r1")), 20_000)
        conn.first.get(30, TimeUnit.SECONDS)
        conn.second.get(30, TimeUnit.SECONDS)
        m1.send(0, "r1", "payload")
        val a = assertThrows(NetAbort::class.java) { m0.recv(1, "r1", 5_000); m0.recv(1, "r1", 5_000) }
        assertEquals("duplicate", a.kind)
        assertEquals(1, a.blamed)
    }

    @Test fun networkBitflipNeverYieldsALink() {
        val proxies = ArrayList<FaultProxy>()
        val (_, _, conn) = twoNodes({ p0 ->
            val px = FaultProxy(0, Pair("127.0.0.1", p0), WireFault(WireFaultKind.BITFLIP, "s2c", 0))
            px.listen()
            proxies.add(px)
            px.port()
        }, null, 3_000)
        assertThrows(ExecutionException::class.java) { conn.second.get(20, TimeUnit.SECONDS) }
        assertThrows(ExecutionException::class.java) { conn.first.get(20, TimeUnit.SECONDS) }
        for (px in proxies) px.close()
    }
}
