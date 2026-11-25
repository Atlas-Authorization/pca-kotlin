package net.atlasauth.pca.mpc.net

import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz.DealerFault
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr
import net.atlasauth.pca.mpc.net.Protocol.Behavior
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyResult

/**
 * Launches n parties (and, for the trusted-dealer mode, a dealer node) in this process on loopback, each with its own fresh
 * per-run identity, its own mutual-TLS mesh and its own thread, and collects what every node ended with. The nodes talk only
 * over TLS sockets, exactly as separate hosts would; a stuck run is cut off after [Options.killAfterMs].
 */
object LaunchLocal {
    class Options {
        @JvmField var n: Int = 0
        @JvmField var Q: Int? = null
        @JvmField var vectors: List<DecisionVector>? = null
        @JvmField var recvTimeoutMs: Long = 30_000
        @JvmField var connectTimeoutMs: Long = 120_000

        /** Hard wall-clock cap for the whole run. */
        @JvmField var killAfterMs: Long = 120_000

        /** TEST ONLY: protocol misbehaviour per node id (parties only). */
        @JvmField var behaviors: Map<Int, Behavior> = emptyMap()

        /** "no-dealer" (default) or "trusted-dealer" (spawns a dealer node; needs insecureTrustedDealer). */
        @JvmField var offline: String = "no-dealer"
        @JvmField var insecureTrustedDealer: Boolean = false
        @JvmField var dealerSeed: BigInteger? = null
        @JvmField var dealerFault: DealerFault? = null
        @JvmField var macFaultAtInput: Int? = null
    }

    /** What a node ended with: a result (parties only), or the throwable that stopped it. */
    class NodeOutput(val id: Int, val role: String, val result: PartyResult?, val error: Throwable?) {
        fun abort(): NetAbort? = error as? NetAbort
    }

    class Launched(val outputs: List<NodeOutput>, val wallMs: Long)

    @JvmStatic
    @Throws(Exception::class)
    fun launch(o: Options): Launched {
        val n = o.n
        val vectors = o.vectors
        require(vectors != null && vectors.size == n) { "launchLocal: one decision vector per party" }
        val dealerMode = o.offline == "trusted-dealer"
        require(!(dealerMode && !o.insecureTrustedDealer)) { "launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer" }
        val nodeCount = if (dealerMode) n + 1 else n
        val sb = ByteArray(8)
        SecureRandom().nextBytes(sb)
        val sessionId = NetHex.enc(sb)
        val nodes = ArrayList<NodeAddr>()
        val idents = ArrayList<Certs.Identity>()
        for (i in 0 until nodeCount) {
            val ident = Certs.generate("mpc-node-$i")
            idents.add(ident)
            nodes.add(NodeAddr(i, "127.0.0.1", 0, ident.certPem)) // port 0: each node binds its own and reports it (Mesh.bindAll)
        }
        val meshes = ArrayList<Mesh>()
        for (i in 0 until nodeCount) {
            val c = Mesh.Config()
            c.selfId = i
            c.nodes = nodes
            c.keyPem = idents[i].keyPem
            c.certPem = idents[i].certPem
            c.sessionId = sessionId
            c.listenHost = "127.0.0.1"
            c.recvTimeoutMs = o.recvTimeoutMs
            c.connectTimeoutMs = o.connectTimeoutMs
            if (dealerMode && i == n) c.linkTo = (0 until n).toList()
            meshes.add(Mesh(c))
        }
        Mesh.bindAll(meshes)
        val ex: ExecutorService = Executors.newCachedThreadPool(ThreadFactory { r ->
            val t = Thread(r, "launch-local")
            t.isDaemon = true
            t
        })
        val t0 = System.nanoTime()
        val active = AtomicInteger(nodeCount)
        val idle = AtomicInteger()
        val fs = ArrayList<Future<NodeOutput>>()
        for (i in 0 until nodeCount) {
            val job = Callable<NodeOutput> {
                try {
                    runNode(o, i, n, dealerMode, meshes[i], sessionId, active, idle)
                } finally {
                    active.decrementAndGet()
                }
            }
            fs.add(ex.submit(job))
        }
        val outs = ArrayList<NodeOutput>()
        val deadline = System.nanoTime() + o.killAfterMs * 1_000_000L
        try {
            for (i in 0 until nodeCount) {
                try {
                    outs.add(fs[i].get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
                } catch (e: TimeoutException) {
                    // a hang is a failure: cut the straggler off and record it
                    for (m in meshes) m.kill()
                    fs[i].cancel(true)
                    outs.add(NodeOutput(i, role(dealerMode, i, n), null, NetAbort("local", null, i, "killed after ${o.killAfterMs}ms")))
                }
            }
        } finally {
            for (m in meshes) m.kill()
            ex.shutdownNow()
        }
        return Launched(outs, (System.nanoTime() - t0) / 1_000_000L)
    }

    private fun role(dealerMode: Boolean, id: Int, n: Int): String = if (dealerMode && id == n) "dealer" else "party"

    private fun runNode(o: Options, id: Int, n: Int, dealerMode: Boolean, mesh: Mesh, sessionId: String, active: AtomicInteger, idle: AtomicInteger): NodeOutput {
        val role = role(dealerMode, id, n)
        try {
            mesh.connect()
            if (role == "dealer") {
                val d = DealerConfig()
                d.insecureTrustedDealer = o.insecureTrustedDealer
                d.n = n
                d.Q = o.Q
                d.mesh = mesh
                d.seed = o.dealerSeed
                d.fault = o.dealerFault
                d.macFaultAtInput = o.macFaultAtInput
                Protocol.runDealer(d)
                return NodeOutput(id, role, null, null)
            }
            val c = PartyConfig()
            c.id = id
            c.n = n
            c.Q = o.Q
            c.input = o.vectors!![id]
            c.mesh = mesh
            c.offline = if (dealerMode) "trusted-dealer" else "no-dealer"
            c.insecureTrustedDealer = o.insecureTrustedDealer
            c.sessionId = sessionId
            val b = o.behaviors[id]
            if (b != null) {
                c.behavior = b
                c.unsafeTestHooks = true
            }
            return NodeOutput(id, role, Protocol.runParty(c), null)
        } catch (e: Protocol.CrashParty) {
            mesh.kill()
            return NodeOutput(id, role, null, e)
        } catch (e: Protocol.SilentParty) {
            // stays connected and stops participating; peers must time out. Idle until every other node has finished.
            idle.incrementAndGet()
            try {
                while (active.get() > idle.get()) Thread.sleep(50)
            } catch (ie: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            return NodeOutput(id, role, null, e)
        } catch (e: Throwable) {
            val f = mesh.failed()
            return NodeOutput(id, role, null, if (e is NetAbort) e else (f ?: e))
        }
    }
}
