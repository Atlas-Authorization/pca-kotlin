package net.atlasauth.pca.mpc.net

import java.io.File
import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import net.atlasauth.pca.mpc.Compose
import net.atlasauth.pca.mpc.Compose.ComposedDecision
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.SpdzRunner
import net.atlasauth.pca.mpc.net.LaunchLocal.NodeOutput
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr
import net.atlasauth.pca.mpc.net.Protocol.Behavior
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** The no-dealer (OT-based) offline phase and the in-process launcher over loopback mutual TLS, with refusals of lying parties. */
class MpcOfflineNetTest {
    private val q = 4
    private val inputs = listOf(DecisionVector(1, 1, 1), DecisionVector(1, 2, 3), DecisionVector(1, 1, 2))

    private fun opts(beh: Map<Int, Behavior>): LaunchLocal.Options {
        val o = LaunchLocal.Options()
        o.n = 3
        o.Q = q
        o.vectors = inputs
        o.recvTimeoutMs = 60_000
        o.killAfterMs = 240_000
        o.behaviors = beh
        return o
    }

    private fun assertSame(want: ComposedDecision, got: ComposedDecision?) {
        assertNotNull(got)
        assertEquals(want.allow, got!!.allow)
        assertEquals(want.t, got.t)
        assertEquals(want.rQuant, got.rQuant)
    }

    @Test fun noDealerAgreesWithTheInProcessEngine() {
        val l = LaunchLocal.launch(opts(emptyMap()))
        val clear = Compose.composeClear(inputs, q)
        val rc = SpdzRunner.MaliciousMpcConfig()
        rc.q = q
        rc.seed = BigInteger.ONE
        assertSame(clear, SpdzRunner.composeSecureMalicious(inputs, rc).composed)
        var digest: String? = null
        assertEquals(3, l.outputs.size)
        for (o in l.outputs) {
            assertNull(o.error.toString(), o.error)
            assertSame(clear, o.result!!.composed)
            assertEquals("no-dealer", o.result.offlineMode)
            assertTrue(o.result.identifiableAbort)
            if (digest == null) digest = o.result.transcriptDigest
            assertEquals(digest, o.result.transcriptDigest)
        }
    }

    @Test fun trustedDealerThroughTheLauncher() {
        val o = opts(emptyMap())
        o.offline = "trusted-dealer"
        o.insecureTrustedDealer = true
        o.dealerSeed = BigInteger.valueOf(11)
        val l = LaunchLocal.launch(o)
        assertEquals(4, l.outputs.size)
        val clear = Compose.composeClear(inputs, q)
        for (out in l.outputs) {
            if (out.role == "party") {
                assertNull(out.error.toString(), out.error)
                assertSame(clear, out.result!!.composed)
            }
        }
    }

    @Test(expected = IllegalArgumentException::class) fun theDealerOptInIsRequired() {
        val o = opts(emptyMap())
        o.offline = "trusted-dealer"
        LaunchLocal.launch(o)
    }

    private fun assertNobodySucceedsAndSomeoneNames(l: LaunchLocal.Launched, kind: String, blamed: Int): NetAbort {
        var named: NetAbort? = null
        for (o in l.outputs) {
            assertNull("no party may produce output", o.result)
            val a = o.abort()
            if (a != null && a.kind == kind && a.blamed == blamed) named = a
        }
        assertNotNull("an honest party names party $blamed with kind $kind", named)
        return named!!
    }

    @Test fun aWrongOtOperandInATripleProductIsCaughtByTheSacrificeAndAttributed() {
        val l = LaunchLocal.launch(opts(mapOf(1 to Behavior("offline-lie", null))))
        assertNobodySucceedsAndSomeoneNames(l, "mac-check", 1)
    }

    @Test fun anInconsistentOtExtensionMatrixIsCaughtByTheKosCheck() {
        val l = LaunchLocal.launch(opts(mapOf(2 to Behavior("ot-u-lie", null))))
        assertNobodySucceedsAndSomeoneNames(l, "ot-check", 2)
    }

    @Test fun aBadBaseOtProofIsRefused() {
        val l = LaunchLocal.launch(opts(mapOf(1 to Behavior("ot-proof-lie", null))))
        assertNobodySucceedsAndSomeoneNames(l, "ot-check", 1)
    }

    @Test fun aSilentPartyIsBlamedByTimeout() {
        val o = opts(mapOf(2 to Behavior("silent", "in-share")))
        o.recvTimeoutMs = 15_000
        o.killAfterMs = 120_000
        val l = LaunchLocal.launch(o)
        var named = false
        for (out in l.outputs) {
            assertNull(out.result)
            val a = out.abort()
            if (a != null && a.kind == "timeout" && a.blamed == 2) named = true
        }
        assertTrue(named)
    }

    @Test fun aNodeRefusesToStartWithTestHooksOutsideATestEnvironment() {
        val f = File.createTempFile("node-cfg", ".json")
        try {
            f.writeText("{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"behavior\":{\"kind\":\"crash\",\"round\":\"out\"}}")
            assumeTrue(System.getenv("PCA_MPC_UNSAFE_TEST_HOOKS") == null)
            assertEquals(3, PartyMain.run(arrayOf(f.path)))
            f.writeText("{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"frameFault\":{}}")
            assertEquals(3, PartyMain.run(arrayOf(f.path)))
        } finally {
            f.delete()
        }
    }

    @Test fun pairwiseBaseOtMatchesOverTheNetwork() {
        val i0 = Certs.generate("ot0")
        val i1 = Certs.generate("ot1")
        val ports = LaunchLocal.reservePorts(2)
        val nodes = listOf(NodeAddr(0, "127.0.0.1", ports[0], i0.certPem), NodeAddr(1, "127.0.0.1", ports[1], i1.certPem))
        fun cfg(id: Int, ident: Certs.Identity): Mesh.Config {
            val c = Mesh.Config()
            c.selfId = id
            c.nodes = nodes
            c.keyPem = ident.keyPem
            c.certPem = ident.certPem
            c.sessionId = "ot-net-session"
            c.listenHost = "127.0.0.1"
            c.connectTimeoutMs = 30_000
            c.recvTimeoutMs = 30_000
            return c
        }
        val m0 = Mesh(cfg(0, i0))
        val m1 = Mesh(cfg(1, i1))
        val ex = Executors.newCachedThreadPool()
        try {
            val s = CompletableFuture.supplyAsync({ m0.connect(); OtNet.runOtSender(m0, 1, 32) }, ex)
            val r = CompletableFuture.supplyAsync({ m1.connect(); OtNet.runOtReceiver(m1, 0, 32) }, ex)
            val sr = s.get(60, TimeUnit.SECONDS)
            val rr = r.get(60, TimeUnit.SECONDS)
            assertTrue(sr.matched)
            assertTrue(rr.matched)
        } finally {
            m0.kill()
            m1.kill()
            ex.shutdownNow()
        }
    }
}
