package net.atlasauth.pca.mpc.net

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/** A cluster binds every node to port 0 itself and learns the real ports from the bound sockets: no port is probed, released and rebound later. */
class MeshBindTest {
    private fun cluster(n: Int): List<Mesh> {
        val ids = Array(n) { Certs.generate("bind$it") }
        val nodes = (0 until n).map { NodeAddr(it, "127.0.0.1", 0, ids[it].certPem) }
        return (0 until n).map {
            val c = Mesh.Config()
            c.selfId = it
            c.nodes = nodes
            c.keyPem = ids[it].keyPem
            c.certPem = ids[it].certPem
            c.sessionId = "bind-test"
            c.listenHost = "127.0.0.1"
            c.connectTimeoutMs = 20_000
            c.recvTimeoutMs = 10_000
            Mesh(c)
        }
    }

    @Test fun everyNodeHoldsItsOwnRealPortAndTheClusterConnects() {
        val meshes = cluster(3)
        Mesh.bindAll(meshes)
        val ports = meshes.map { it.boundPort() }
        assertTrue(ports.toString(), ports.all { it > 0 })
        assertEquals(3, ports.toSet().size)
        for (m in meshes) assertEquals(m.boundPort(), m.listen()) // idempotent: the same socket
        val ex = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }
        try {
            meshes.map { m -> ex.submit { m.connect() } }.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            for (m in meshes) m.kill()
            ex.shutdownNow()
        }
    }

    @Test fun anUnknownNodeCannotBeResolved() {
        val m = cluster(2)[0]
        try {
            assertThrows(IllegalArgumentException::class.java) { m.resolvePort(9, 1234) }
            assertNotEquals(-1, m.listen())
        } finally {
            m.kill()
        }
    }
}
