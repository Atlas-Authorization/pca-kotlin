package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestNvidia, round 2: record length, block size floor, VBIOS rendering, CA role, lone roots, validity bounds, the verifier's inputs and order. */
class Kill05R2NvSpdmTest {
    private fun parse(b: ByteArray): String = try {
        AttestNvidia.parseSpdmEvidence(b)
        "OK"
    } catch (e: AttErr) {
        e.message ?: "<null>"
    }

    private fun thrown(f: () -> Unit): String? = try {
        f()
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun recordLengthReadsItsThirdByte() = nv {
        // a 65,536-byte measurement record: its length is 00 00 01 (little endian)
        val t = transcript(ByteArray(32), listOf(block(1, ByteArray(65000)), block(2, ByteArray(522))), NONE, null)
        val rep = AttestNvidia.parseSpdmEvidence(t)
        assertEquals(listOf(1, 2), rep.measurements.map { it.index })
        assertEquals(listOf(65000, 522), rep.measurements.map { it.digest.size })
    }

    @Test
    fun blockSizeFloorIsThree() = nv {
        val req = ByteArray(37)
        req[1] = 0xe0.toByte()
        fun raw(rec: ByteArray) = cat(req, b(0x11, 0x60, 0, 0, 1, rec.size, 0, 0), rec, ByteArray(32), le16(0), ByteArray(96))
        val p = "parseNvidiaSpdmEvidence: "
        assertEquals(p + "measurement block overruns record", parse(raw(cat(b(1, 1), le16(2), b(1, 0)))))
        assertEquals(p + "DMTF value overruns measurement block", parse(raw(cat(b(1, 1), le16(3), b(1, 1, 0)))))
        assertEquals("OK", parse(raw(cat(b(1, 1), le16(3), b(1, 0, 0)))))
    }

    @Test
    fun vbiosRenderingShortInputs() = nv {
        assertEquals("", AttestNvidia.formatVbiosVersion(NONE))
        assertEquals("b", AttestNvidia.formatVbiosVersion(b(0xab)))
        assertEquals("12.34", AttestNvidia.formatVbiosVersion(b(0x12, 0x34)))
        assertEquals("20.13.0", AttestNvidia.formatVbiosVersion(b(1, 2, 3)))
        assertEquals("96.00.9f.00.04", AttestNvidia.formatVbiosVersion(b(0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa)))
    }

    @Test
    fun measurementKeysReadAsNumberDoes() {
        // Number("1d") is NaN; the JVM double reader would accept the type suffix (full table: JsNumberSweepTest)
        assertNull(AttestNvidia.jsNumberFromString("1d"))
        assertNull(AttestNvidia.jsNumberFromString("2f"))
        assertEquals(12.0, AttestNvidia.jsNumberFromString("12"))
    }

    @Test
    fun caRole() = nv {
        val k = p384()
        fun ca(vararg exts: ByteArray) = AttestNvidia.certIsCa(issue(dn("Role"), dn("Role"), k.private, k, exts = exts.toList()).cert)
        assertTrue(ca(BC_CA, KU_CA))
        assertTrue(ca(BC_CA)) // no keyUsage: BasicConstraints alone decides
        assertFalse(ca())
        assertFalse(ca(KU_CA))
        assertFalse(ca(ext("2.5.29.19", true, seq()))) // cA absent
        assertFalse(ca(BC_CA, ext("2.5.29.15", true, tlv(0x03, b(7, 0x80))))) // keyUsage without keyCertSign
    }

    @Test
    fun chainProfile() = nv {
        fun why(vararg certs: Kill05NvKit.Issued) = AttestNvidia.verifyDeviceChain(certs.joinToString("") { pem(it.der) }, listOf(ROOT_PIN), NOW).second
        fun leafWith(vararg e: ByteArray) = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = int(5), exts = e.toList())
        fun interWith(vararg e: ByteArray) = issue(dn(INTER_CN), dn(ROOT_CN), rootKey.private, interKey, serial = int(6), exts = e.toList())
        val unknown = ext("1.2.3.4", true, NONE)
        val p = "device chain profile: "
        assertEquals("", why(leafWith(ext("2.5.29.37", true, seq(oid(KP_OCSP)))), inter, root))
        assertEquals(p + "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)", why(leafWith(BC_CA), inter, root))
        assertEquals(p + "certificate at depth 0 has an unrecognised critical extension 1.2.3.4", why(leafWith(unknown), inter, root))
        assertEquals(p + "certificate at depth 1 has an unrecognised critical extension 1.2.3.4", why(leaf, interWith(BC_CA, KU_CA, unknown), root))
        val capped = issue(dn(ROOT_CN), dn(ROOT_CN), rootKey.private, rootKey, serial = int(7), exts = listOf(ext("2.5.29.19", true, seq(tlv(0x01, b(0xff)), int(0))), KU_CA))
        assertEquals(p + "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)", why(leaf, inter, capped))
        // a lone certificate has no issuer role, but its extensions must still read
        val dup = issue(dn(ROOT_CN), dn(ROOT_CN), rootKey.private, rootKey, serial = int(8), exts = listOf(BC_CA, BC_CA))
        assertEquals(p + "certificate extension parse failed: duplicate BasicConstraints extension", why(dup))
    }

    @Test
    fun loneRootAndPins() = nv {
        fun lone(c: Kill05NvKit.Issued) = AttestNvidia.verifyDeviceChain(pem(c.der), listOf(AttestCert.keyOfCert(c.cert).spkiSha256()), NOW).second
        assertEquals("", lone(root))
        val k = p384()
        val notRoot = "device chain root is not a self-signed CA"
        assertEquals(notRoot, lone(issue(dn("Plain"), dn("Plain"), k.private, k)))
        assertEquals(notRoot, lone(issue(dn(ROOT_CN), dn(ROOT_CN), k.private, rootKey, exts = listOf(BC_CA, KU_CA))))
        val pems = pem(leaf.der) + pem(inter.der) + pem(root.der)
        // pins compare case-insensitively, wherever the matching one sits in the list
        assertEquals("", AttestNvidia.verifyDeviceChain(pems, listOf("00", ROOT_PIN.uppercase()), NOW).second)
        assertEquals("", AttestNvidia.verifyDeviceChain(pems, listOf(ROOT_PIN, "00"), NOW).second)
        assertEquals("chain root is not a pinned NVIDIA root", AttestNvidia.verifyDeviceChain(pems, listOf("00", "11"), NOW).second)
    }

    @Test
    fun validityBoundsHaveNoSkew() = nv {
        val outside = "device chain cert #0 is outside its validity window"
        val endsNow = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = int(3), notAfter = utc(NOW))
        val startsNow = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = int(4), notBefore = utc(NOW))
        fun at(c: Kill05NvKit.Issued, now: Long) = AttestNvidia.verifyDeviceChain(pem(c.der) + pem(inter.der) + pem(root.der), listOf(ROOT_PIN), now).second
        assertEquals("", at(endsNow, NOW))
        assertEquals(outside, at(endsNow, NOW + 1))
        assertEquals("", at(startsNow, NOW))
        assertEquals(outside, at(startsNow, NOW - 1))
    }

    private val binding = Attest.Binding("holder-pub", "grant-ref", 7.0, "nonce-1")

    private fun verifier(policy: Map<String, Any?>) = AttestNvidia.create(mapOf("rootSpkiSha256" to listOf(Kill05NvKit.ROOT_PIN), "policy" to policy))

    @Test
    fun verifierInputsAndMeasurementOrder() = nv {
        val nonce = AttestUtil.sha256(Attest.bindingBytes(binding))
        val chainPem = pem(leaf.der) + pem(inter.der) + pem(root.der)
        val d1 = b(1, 1, 1, 1)
        val d2 = b(2, 2, 2, 2)
        val d3 = b(3, 3, 3, 3)
        // blocks out of index order (2, 1, 3): the host digest hashes them in index order
        val evidence = b64(transcript(nonce, listOf(block(2, d2), block(1, d1), block(3, d3)), NONE))
        val v = verifier(mapOf("measurements" to mapOf("1" to "01010101")))
        val none = "no NVIDIA GPU evidence for this action"
        assertEquals(none, v.verify(null, binding, NOW).reason)
        assertEquals(none, v.verify(mapOf("certChainPem" to chainPem), binding, NOW).reason)
        assertEquals(none, v.verify(mapOf("evidence" to evidence), binding, NOW).reason)
        assertEquals(none, v.verify(mapOf("evidence" to 5, "certChainPem" to chainPem), binding, NOW).reason)
        val r = v.verify(mapOf("evidence" to evidence, "certChainPem" to chainPem), binding, NOW)
        assertEquals("", r.reason)
        assertTrue(r.ok)
        val host = r.hostAsserted!!
        assertEquals(AttestUtil.hex(md("SHA-384", cat(d1, d2, d3))), host["gpu_measurements_sha384"])
        assertEquals(line(LEAF_CN), host["leaf_subject"])
    }

    @Test
    fun pinnedBlocksAndLeafSubjectPolicy() = nv {
        val nonce = AttestUtil.sha256(Attest.bindingBytes(binding))
        val ev = mapOf<String, Any?>(
            "evidence" to b64(transcript(nonce, listOf(block(1, b(1, 2, 3, 4))), NONE)),
            "certChainPem" to pem(leaf.der) + pem(inter.der) + pem(root.der),
        )
        fun why(policy: Map<String, Any?>) = verifier(policy).verify(ev, binding, NOW).reason
        // checked in numeric index order, whatever the key order
        assertEquals("measurement block 9 missing from report", why(mapOf("measurements" to linkedMapOf("9" to "aa", "10" to "aa"))))
        assertEquals("measurement block 9 missing from report", why(mapOf("measurements" to linkedMapOf("10" to "aa", "9" to "aa"))))
        val range = "createNvidiaSpdmVerifier: measurement index out of range"
        assertEquals(range, thrown { verifier(mapOf("measurements" to linkedMapOf("1" to "aa", "x" to "aa"))) })
        assertEquals(range, thrown { verifier(mapOf("measurements" to linkedMapOf("x" to "aa", "1" to "aa"))) })
        // attest-nvidia-spdm.ts:317 Number(i): a form JS reads as NaN or Infinity is out of range, a radix form is its index
        for (k in listOf("1\u0000", "+0x1", "0x1p3", "1f", "1d", "NaN", "Infinity")) assertEquals(k, range, thrown { verifier(mapOf("measurements" to mapOf(k to "aa"))) })
        assertEquals("", why(mapOf("measurements" to mapOf("0x1" to "01020304"))))
        // leafSubjectIncludes must be a string: a non-string is refused, never stringified or dropped
        val m = mapOf("1" to "01020304")
        assertEquals("", why(mapOf("measurements" to m, "leafSubjectIncludes" to "GH100 A01")))
        assertEquals("device leaf subject does not contain 'Nope'", why(mapOf("measurements" to m, "leafSubjectIncludes" to "Nope")))
        assertEquals("", why(mapOf("measurements" to m, "leafSubjectIncludes" to "")))
        for (bad in listOf<Any?>(5, 100, 0, false, true, listOf("a"))) {
            assertEquals("$bad", "createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string", thrown { verifier(mapOf("measurements" to m, "leafSubjectIncludes" to bad)) })
        }
    }
}
