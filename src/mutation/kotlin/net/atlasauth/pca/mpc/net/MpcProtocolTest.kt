package net.atlasauth.pca.mpc.net

import java.math.BigInteger
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import net.atlasauth.pca.mpc.Compose
import net.atlasauth.pca.mpc.Compose.ComposedDecision
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz.DealerFault
import net.atlasauth.pca.mpc.SpdzRunner
import net.atlasauth.pca.mpc.net.Protocol.Behavior
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The networked SPDZ-style protocol over loopback mutual TLS, trusted-dealer mode: agreement with the in-process engine, and refusals of a lying dealer and lying parties. */
class MpcProtocolTest {
    private val Q = 4
    private val sid = "protocol-test-session"
    private val ex = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }

    /** n parties (ids 0..n-1) plus a dealer node (id n), every mesh connected. */
    private fun cluster(n: Int, recvMs: Long): Array<Mesh> {
        val total = n + 1
        val ids = Array(total) { Certs.generate("p$it") }
        val nodes = ArrayList<Mesh.NodeAddr>()
        for (i in 0 until total) nodes.add(Mesh.NodeAddr(i, "127.0.0.1", 0, ids[i].certPem))
        val meshes = Array(total) { i ->
            val c = Mesh.Config()
            c.selfId = i
            c.nodes = nodes
            c.keyPem = ids[i].keyPem
            c.certPem = ids[i].certPem
            c.sessionId = sid
            c.listenHost = "127.0.0.1"
            c.connectTimeoutMs = 30_000
            c.recvTimeoutMs = recvMs
            Mesh(c)
        }
        Mesh.bindAll(meshes.toList())
        val conn = meshes.map { m -> ex.submit(Runnable { m.connect() }) }
        for (f in conn) f.get(60, TimeUnit.SECONDS)
        return meshes
    }

    /** What a node ended with: a result, or the throwable that stopped it. */
    private class Outcome(val result: PartyResult?, val error: Throwable?) {
        fun abort(): NetAbort? = error as? NetAbort
    }

    private fun runAll(meshes: Array<Mesh>, input: List<DecisionVector>, dealerCfg: DealerConfig, behaviors: Array<Behavior?>?): List<Outcome> {
        val n = input.size
        val fs = ArrayList<java.util.concurrent.Future<Outcome>>()
        fs.add(ex.submit(Callable {
            try {
                dealerCfg.mesh = meshes[n]
                Protocol.runDealer(dealerCfg)
                Outcome(null, null)
            } catch (t: Throwable) {
                Outcome(null, t)
            }
        }))
        for (me in 0 until n) {
            fs.add(ex.submit(Callable {
                try {
                    val c = PartyConfig()
                    c.id = me
                    c.n = n
                    c.Q = Q
                    c.input = input[me]
                    c.mesh = meshes[me]
                    c.offline = "trusted-dealer"
                    c.insecureTrustedDealer = true
                    c.sessionId = meshes[me].sessionId()
                    if (behaviors != null && behaviors[me] != null) {
                        c.behavior = behaviors[me]
                        c.unsafeTestHooks = true
                    }
                    Outcome(Protocol.runParty(c), null)
                } catch (t: Throwable) {
                    Outcome(null, t)
                }
            }))
        }
        val out = ArrayList<Outcome>()
        for (f in fs) out.add(f.get(120, TimeUnit.SECONDS))
        return out.subList(1, out.size) // the parties; the dealer's own outcome is not asserted
    }

    private fun dealer(n: Int): DealerConfig {
        val d = DealerConfig()
        d.insecureTrustedDealer = true
        d.n = n
        d.Q = Q
        d.seed = BigInteger.valueOf(7)
        return d
    }

    private val inputs = listOf(DecisionVector(1, 1, 1), DecisionVector(1, 2, 3), DecisionVector(1, 1, 2))

    private fun assertSame(a: ComposedDecision, b: ComposedDecision) {
        assertEquals(a.allow, b.allow)
        assertEquals(a.t, b.t)
        assertEquals(a.rQuant, b.rQuant)
    }

    @Test fun dealerModeAgreesWithTheInProcessEngine() {
        val outs = runAll(cluster(3, 60_000), inputs, dealer(3), null)
        val clear = Compose.composeClear(inputs, Q)
        val rc = SpdzRunner.MaliciousMpcConfig()
        rc.q = Q
        rc.seed = BigInteger.ONE
        rc.insecureTrustedDealer = true
        val engine = SpdzRunner.composeSecureMalicious(inputs, rc).composed
        assertSame(clear, engine)
        var digest: String? = null
        for (o in outs) {
            assertNull(o.error.toString(), o.error)
            val r = o.result!!
            assertSame(clear, r.composed)
            assertEquals("trusted-dealer", r.offlineMode)
            assertTrue(r.identifiableAbort)
            if (digest == null) digest = r.transcriptDigest
            assertEquals(digest, r.transcriptDigest)
        }
    }

    @Test fun aWrongProductFromTheDealerIsDetectedAndBlamed() {
        val d = dealer(3)
        d.fault = DealerFault(BigInteger.ONE, null)
        val outs = runAll(cluster(3, 30_000), inputs, d, null)
        var named = false
        for (o in outs) {
            assertNull("no party may produce output", o.result)
            val a = o.abort()
            assertNotNull(o.error.toString(), a)
            if (a!!.kind == "dealer" && a.blamed == 3) named = true
        }
        assertTrue("an honest party names the dealer", named)
    }

    @Test fun aLyingOpenedShareIsNamedByItsPairwiseTag() {
        val b = arrayOfNulls<Behavior>(3)
        b[1] = Behavior("open-lie", "mul0")
        val outs = runAll(cluster(3, 30_000), inputs, dealer(3), b)
        var named = false
        for (o in outs) {
            assertNull("no party may produce output", o.result)
            val a = o.abort()
            if (a != null && a.kind == "mac-check" && a.blamed == 1) named = true
        }
        assertTrue("an honest verifier names party 1", named)
    }

    @Test fun aNonCanonicalFieldElementIsRefused() {
        val b = arrayOfNulls<Behavior>(3)
        b[2] = Behavior("noncanonical", "mul0")
        val outs = runAll(cluster(3, 30_000), inputs, dealer(3), b)
        var named = false
        for (o in outs) {
            assertNull("no party may produce output", o.result)
            val a = o.abort()
            if (a != null && a.kind == "malformed" && a.blamed == 2) named = true
        }
        assertTrue("an honest party names party 2", named)
    }

    /** Party 1 misbehaves; nobody may produce output, and (when expected) an honest party names party 1 with one of [kinds]. */
    private fun liar(kind: String, round: String?, mustBlame: Boolean, vararg kinds: String) {
        val b = arrayOfNulls<Behavior>(3)
        b[1] = Behavior(kind, round)
        val outs = runAll(cluster(3, 30_000), inputs, dealer(3), b)
        var named = false
        for (o in outs) {
            assertNull("$kind: no party may produce output", o.result)
            val a = o.abort()
            assertNotNull("$kind: every party aborts", a)
            if (a != null && a.blamed == 1 && kinds.contains(a.kind)) named = true
        }
        if (mustBlame) assertTrue("$kind: an honest party names party 1", named)
    }

    @Test fun aWrongPairwiseTagIsNamed() = liar("bad-tag", "mul1", true, "mac-check")

    @Test fun aForgedMacShareIsFoundByTheBatchedCheck() = liar("mac-lie", "mul1", true, "mac-check")

    @Test fun aWrongMacResidualIsNamed() = liar("sigma-lie", null, true, "mac-check")

    @Test fun aResidualOpeningThatBreaksItsCommitmentIsNamed() = liar("bad-sigma-open", null, true, "commitment")

    @Test fun aCoinOpeningThatBreaksItsCommitmentIsNamed() = liar("bad-coin-open", null, true, "commitment")

    @Test fun aShortArrayIsMalformed() = liar("short-array", "mul0", true, "malformed")

    @Test fun equivocationNeverYieldsADivergentOutput() = liar("equivocate", "mul0", false)

    @Test fun testHooksAndDealerOptInAreEnforcedBeforeAnyTraffic() {
        val c = PartyConfig()
        c.id = 0
        c.n = 3
        c.Q = Q
        c.input = inputs[0]
        c.sessionId = "s"
        c.offline = "trusted-dealer"
        val a = assertThrows(NetAbort::class.java) { Protocol.runParty(c) }
        assertEquals("local", a.kind)
        c.insecureTrustedDealer = true
        c.behavior = Behavior("open-lie", "out")
        assertEquals("local", assertThrows(NetAbort::class.java) { Protocol.runParty(c) }.kind)
        val d = DealerConfig()
        d.n = 3
        assertThrows(IllegalArgumentException::class.java) { Protocol.runDealer(d) }
    }
}
