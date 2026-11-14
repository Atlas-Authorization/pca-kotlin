package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestNvidia: SPDM transcript parsing, VBIOS rendering, measurement keys, the device chain, and the verifier end to end. */
class Kill05NvSpdmTest {
    /** A transcript with a hand-set block count and record length (unsigned). */
    private fun raw(numBlocks: Int, recLen: Int, rec: ByteArray, opaque: ByteArray): ByteArray = nvBytes {
        val req = ByteArray(37)
        req[1] = 0xe0.toByte()
        cat(req, b(0x11, 0x60, 0, 0, numBlocks, recLen and 0xff, 0, 0), rec, ByteArray(32), le16(opaque.size), opaque, ByteArray(96))
    }

    private fun nvBytes(f: Kill05NvKit.() -> ByteArray): ByteArray = Kill05NvKit.f()

    private fun parseErr(b: ByteArray): String = try {
        AttestNvidia.parseSpdmEvidence(b)
        "OK"
    } catch (e: AttErr) {
        e.message ?: "<null>"
    }

    @Test
    fun transcriptRefusals() = nv {
        val p = "parseNvidiaSpdmEvidence: "
        assertEquals(p + "measurement record length overruns transcript", parseErr(raw(0, 1, NONE, NONE)))
        assertEquals(p + "truncated measurement block header", parseErr(raw(1, 2, b(0, 0), NONE)))
        assertEquals(p + "DMTF value overruns measurement block", parseErr(raw(1, 7, cat(b(1, 1), le16(3), b(1), le16(1)), NONE)))
        assertEquals(p + "opaque TLV overruns opaque data", parseErr(raw(0, 0, NONE, cat(le16(1), le16(5)))))
        assertEquals("OK", parseErr(raw(0, 0, NONE, cat(le16(1), le16(0)))))
    }

    @Test
    fun vbiosRenderingAndMeasurementKeys() = nv {
        assertEquals("", AttestNvidia.formatVbiosVersion(NONE))
        assertEquals("b", AttestNvidia.formatVbiosVersion(b(0xab)))
        assertEquals(0.0, AttestNvidia.jsNumberFromString(""))
        assertEquals(0.0, AttestNvidia.jsNumberFromString(" \t "))
        assertEquals(7.0, AttestNvidia.jsNumberFromString(" 7 "))
        assertEquals(1000.0, AttestNvidia.jsNumberFromString("1e3"))
        assertEquals(0.5, AttestNvidia.jsNumberFromString(".5"))
        assertNull(AttestNvidia.jsNumberFromString("abc"))
        assertNull(AttestNvidia.jsNumberFromString("1 2"))
    }

    @Test
    fun deviceChain() = nv {
        val pems = pem(leaf.der) + pem(inter.der) + pem(root.der)
        val (chain, why) = AttestNvidia.verifyDeviceChain(pems, listOf(ROOT_PIN), NOW)
        assertEquals("", why)
        assertEquals(3, chain!!.size)
        assertEquals("chain root is not a pinned NVIDIA root", AttestNvidia.verifyDeviceChain(pems, emptyList(), NOW).second)
        assertEquals("device chain unparseable: parsePemChain: chain longer than 5", AttestNvidia.verifyDeviceChain(pem(root.der).repeat(6), listOf(ROOT_PIN), NOW).second)
        assertEquals(
            "device chain unparseable: " + AttestCert.OSSL_WRONG_TAG,
            AttestNvidia.verifyDeviceChain("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", listOf(ROOT_PIN), NOW).second,
        )
        // an issuer whose extensions cannot be read (two BasicConstraints) is not a CA
        val dup = issue(dn(INTER_CN), dn(ROOT_CN), rootKey.private, interKey, serial = int(2), exts = listOf(BC_CA, BC_CA, KU_CA))
        assertEquals(
            "device chain cert #1 issues a certificate but is not a CA",
            AttestNvidia.verifyDeviceChain(pem(leaf.der) + pem(dup.der) + pem(root.der), listOf(ROOT_PIN), NOW).second,
        )
    }

    @Test
    fun verifierEndToEnd() = nv {
        val binding = Attest.Binding("holder-pub", "grant-ref", 7.0, "nonce-1")
        val nonce = AttestUtil.sha256(Attest.bindingBytes(binding))
        val d1 = b(1, 2, 3, 4)
        val ev = mapOf<String, Any?>(
            "evidence" to b64(transcript(nonce, listOf(block(1, d1)), NONE)),
            "certChainPem" to pem(leaf.der) + pem(inter.der) + pem(root.der),
        )
        fun verifier(meas: Map<String, Any?>) =
            AttestNvidia.create(mapOf("rootSpkiSha256" to listOf(ROOT_PIN), "policy" to mapOf("measurements" to meas)))
        val one = verifier(linkedMapOf("1" to "01020304"))
        assertEquals("no expected attestation binding supplied", one.verify(ev, null, NOW).reason)
        val ok = one.verify(ev, binding, NOW)
        assertEquals("", ok.reason)
        assertTrue(ok.ok)
        // pinned blocks are checked in numeric index order ("10" sorts before "9" as text)
        assertEquals("measurement block 9 missing from report", verifier(linkedMapOf("10" to "aa", "9" to "aa")).verify(ev, binding, NOW).reason)
        // two keys naming the same index (the sort falls back to the key text)
        assertTrue(verifier(linkedMapOf("1" to "01020304", "01" to "01020304")).verify(ev, binding, NOW).ok)
    }
}
