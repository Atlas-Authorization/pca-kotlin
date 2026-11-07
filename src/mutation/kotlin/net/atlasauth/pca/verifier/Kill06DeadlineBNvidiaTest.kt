package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** Deadline tests for AttestNvidia / AttestNvidiaCollateral cursors: the SPDM transcript reader, VBIOS rendering, CRL chain walk. */
class Kill06DeadlineBNvidiaTest {
    @Test
    fun spdmTranscriptWithBlocksAndOpaqueTlvs() = Deadline.within {
        nv {
            val opaque = cat(opaqueTlv(3, b(1, 2, 3)), opaqueTlv(6, NONE), opaqueTlv(35, b(9)))
            val t = transcript(ByteArray(32) { 5 }, listOf(block(1, b(1, 2, 3, 4)), block(2, b(7))), opaque)
            val r = AttestNvidia.parseSpdmEvidence(t)
            assertEquals(2, r.measurements.size)
            assertEquals(1, r.measurements[0].index)
            assertArrayEquals(b(1, 2, 3, 4), r.measurements[0].digest)
            assertArrayEquals(b(7), r.measurements[1].digest)
            assertEquals(setOf(3, 6, 35), r.opaque.keys)
            assertArrayEquals(b(1, 2, 3), r.opaque[3])
            assertArrayEquals(NONE, r.opaque[6])
            assertArrayEquals(b(9), r.opaque[35])
            assertEquals(0x11, r.requestVersion)
        }
    }

    @Test
    fun vbiosRendering() = Deadline.within {
        assertEquals("12.34", AttestNvidia.formatVbiosVersion(byteArrayOf(0x12, 0x34)))
        assertEquals("02.01.03", AttestNvidia.formatVbiosVersion(byteArrayOf(1, 2, 3, 4))) // TS attest-nvidia-spdm.ts:179 (node: "02.01.03")
        assertEquals("b", AttestNvidia.formatVbiosVersion(byteArrayOf(0xab.toByte())))
    }

    @Test
    fun chainRevocationWalk() = Deadline.within {
        nv {
            fun rev(vararg crls: ByteArray, need: List<String> = emptyList()) = AttestNvidiaCollateral.checkChainRevocation(CHAIN, crls.toList(), NOW, need)
            val interCrl = crl(dn(INTER_CN), interKey.private)
            val rootCrl = crl(dn(ROOT_CN), rootKey.private)
            assertEquals("", rev(interCrl, rootCrl))
            assertEquals("", rev(rootCrl, interCrl, need = listOf("Identity")))
            assertEquals("chain certificate '${line(LEAF_CN)}' is revoked", rev(crl(dn(INTER_CN), interKey.private, leaf.cert.serial)))
            assertEquals("chain certificate '${line(INTER_CN)}' is revoked", rev(crl(dn(ROOT_CN), rootKey.private, inter.cert.serial), interCrl))
            assertEquals("no CRLs supplied", rev())
        }
    }
}
