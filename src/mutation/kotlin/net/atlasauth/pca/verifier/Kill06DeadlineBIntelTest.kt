package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests for AttestIntel loops: quote tail scan, SGX extension read, PCK chain walk, TCB comparison, JSON scanners. */
class Kill06DeadlineBIntelTest {
    private val k = Kill05GcpAmdKit
    private val now = Kill05GcpAmdKit.NOW

    private fun <T> p(name: String, vararg a: Any?): T = KUtil.priv(AttestIntel, name, *a)

    @Test
    fun parseQuoteWithZeroPadding() = Deadline.within {
        val g = Kill05IntelMeshKit.G()
        val q = g.quote()
        val parsed = AttestIntel.parseQuote(q + ByteArray(3))
        assertEquals(g.chain(), parsed.pckChainPem)
        assertEquals(584, parsed.tdReportBody.size)
        assertEquals(384, parsed.qeReportBody.size)
        assertEquals("parseDcapQuote: non-zero bytes after the signature data", try { AttestIntel.parseQuote(q + byteArrayOf(0, 1)); "OK" } catch (e: AttErr) { e.message })
    }

    @Test
    fun sgxExtensionRead() = Deadline.within {
        val g = Kill05IntelMeshKit.G()
        val t = AttestIntel.extractPckFmspcAndTcb(g.pckDer)
        assertArrayEquals(g.fmspc, t.fmspc)
        assertEquals(13, t.pcesvn)
        assertArrayEquals(ByteArray(16) { (it + 1).toByte() }, t.sgx)
        // a two-byte PCESVN walks the integer loop twice
        val wide = AttestIntel.extractPckFmspcAndTcb(Kill05IntelMeshKit.cert(9, "L", "R", g.pck, g.root, Kill05GcpAmdKit.NA, Kill05IntelMeshKit.sgxExt(0x1234, g.fmspc)))
        assertEquals(0x1234, wide.pcesvn)
    }

    @Test
    fun pckChainWalk() = Deadline.within {
        val g = Kill05IntelMeshKit.G()
        val ok = AttestIntel.verifyPckChain(g.chain(), g.pin(), now)
        assertTrue(ok.reason, ok.ok)
        assertEquals(3, ok.depth)
        assertNotNull(ok.leaf)
        assertNotNull(ok.leafKey)
        // the chain in any order and a self-signed single certificate
        val shuffled = k.pem(g.rootDer) + k.pem(g.pckDer) + k.pem(g.caDer)
        assertEquals(3, AttestIntel.verifyPckChain(shuffled, g.pin(), now).depth)
        val s = Kill05IntelMeshKit.G()
        s.single = true
        val one = AttestIntel.verifyPckChain(s.chain(), s.pin(), now)
        assertTrue(one.reason, one.ok)
        assertEquals(1, one.depth)
        // two certificates issuing each other never end in a root
        val a = k.ecKey("secp256r1")
        val b = k.ecKey("secp256r1")
        val x = Kill05IntelMeshKit
        val cyc = k.pem(x.cert(5, "A", "B", a, b, Kill05GcpAmdKit.NA)) + k.pem(x.cert(6, "B", "A", b, a, Kill05GcpAmdKit.NA))
        assertEquals("PCK chain does not terminate in a self-signed root", AttestIntel.verifyPckChain(cyc, g.pin(), now).reason)
    }

    @Test
    fun genuineQuoteAndTcbEvaluation() = Deadline.within {
        val g = Kill05IntelMeshKit.G()
        val r = AttestIntel.verifyGenuineTdxQuote(g.quote(), g.pin(), now, null, false)
        assertTrue(r.reason, r.ok)
        assertEquals("00906ed50000", r.fmspc)
        val c = g.run(null)
        assertTrue(c.reason, c.ok)
        assertEquals("UpToDate", c.status)
        // a platform below the only level: the SGX component loop reaches the mismatch
        val low = Kill05IntelMeshKit.G()
        low.tcbBody = low.tcbBody.replace("\"sgxtcbcomponents\":" + Kill05IntelMeshKit.svns(1), "\"sgxtcbcomponents\":" + Kill05IntelMeshKit.svns(17))
        assertEquals("TCB evaluation: platform TCB is below every level in the TCB info", low.run(null).reason)
        val lowTdx = Kill05IntelMeshKit.G()
        lowTdx.tcbBody = lowTdx.tcbBody.replace("\"tdxtcbcomponents\":" + Kill05IntelMeshKit.svns(0), "\"tdxtcbcomponents\":" + Kill05IntelMeshKit.svns(1))
        assertEquals("TCB evaluation: platform TCB is below every level in the TCB info", lowTdx.run(null).reason)
    }

    @Test
    fun maskedEqAndJsonScanners() = Deadline.within {
        assertTrue(p<Boolean>("maskedEq", byteArrayOf(1, -1), byteArrayOf(-1, 0x0f), byteArrayOf(1, 0x0f)))
        assertFalse(p<Boolean>("maskedEq", byteArrayOf(1, -1), byteArrayOf(-1, 0x0f), byteArrayOf(1, 0x0e)))
        assertEquals(4, p<Int>("skipJsSpace", " \t\n x", 0)) // space, tab, newline, space: x at 4
        val text = """ {"tcbInfo" : {"a":"x\"y}","b":{"c":1}} , "signature":"s"}"""
        assertEquals("""{"a":"x\"y}","b":{"c":1}}""", p<String?>("rawJsonObject", text, "tcbInfo"))
        assertEquals("""{"d":"\\"}""", p<String?>("rawJsonObject", """{"tcbInfo":{"d":"\\"}}""", "tcbInfo"))
    }
}
