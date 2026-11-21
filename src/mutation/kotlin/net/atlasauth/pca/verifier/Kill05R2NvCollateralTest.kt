package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AttestNvidiaCollateral, round 2: RIM details, golden conflicts, firmware policy shape and order, bundle inputs, OCSP corners. */
class Kill05R2NvCollateralTest {
    private val rej = "OCSP response rejected: "
    private val noEmbedded = "no embedded responder certificate verifies the response"

    private fun hx(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun thrown(f: () -> Unit): String? = try {
        f()
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun rimCertificateTextAndHashOrder() = nv {
        // JavaScript whitespace (NBSP, EM SPACE) inside the certificate text is dropped before the PEM is formed
        fun spaced(der: ByteArray) = b64(der).chunked(10).joinToString("  ")
        val ki = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + spaced(rimSigner.der) + "</ds:X509Certificate><ds:X509Certificate>" +
            spaced(root.der) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        assertEquals("OK", rimWhy(rim(keyInfo = ki)))
        // Hash<n> attributes are ordered by n, whatever their document order
        val three = "<Resource type=\"Measurement\" index=\"0\" active=\"true\" alternatives=\"3\" size=\"1\" Hash2=\"cc\" Hash0=\"aa\" Hash1=\"bb\"/>"
        val (r, why) = AttestNvidiaCollateral.verifyRim(rim(payload = "<Payload>$three</Payload>"), RIM_PINS, NOW)
        assertEquals("", why)
        assertEquals(listOf("aa", "bb", "cc"), r!!.golden.getValue(0).hashes)
    }

    @Test
    fun goldenConflictNamesItsIndex() = nv {
        fun g(index: Int, hash: String) = AttestNvidiaCollateral.Golden(index, true, 1, hash.length / 2, listOf(hash))
        fun rimOf(vararg gs: AttestNvidiaCollateral.Golden) = AttestNvidiaCollateral.Rim("GH100", "1", gs.associateBy { it.index })
        val rep = report(listOf(AttestNvidia.Measurement(4, hx("aabb"))), emptyMap())
        assertEquals(
            "driver and VBIOS RIMs both have an active measurement at index 3",
            AttestNvidiaCollateral.compareReportToRims(rep, rimOf(g(3, "aabb")), rimOf(g(3, "aabb"))),
        )
    }

    private fun policy(fw: Map<String, Any?>): AttestNvidiaCollateral.FirmwarePolicy = KUtil.priv(AttestNvidiaCollateral, "compileFirmwarePolicy", fw)

    private fun ids(d: String, v: String = "96.00") = AttestNvidiaCollateral.RimIds("GH100", "", "", d, v)

    @Test
    fun firmwareVersionOrder() {
        fun c(fw: Map<String, Any?>, d: String, v: String = "96.00") = policy(fw).check(ids(d, v))
        assertEquals("", c(mapOf("minDriverVersion" to "535"), "536"))
        assertEquals("", c(mapOf("minDriverVersion" to "535.86"), "535.87"))
        assertEquals("", c(mapOf("minDriverVersion" to "535.86"), "535.86.1"))
        assertEquals("", c(mapOf("minVbiosVersion" to "96.00"), "1"))
        assertEquals("", c(mapOf("minVbiosVersion" to "95.ff"), "1"))
        assertEquals("VBIOS 96.00 is below the minimum 96.00.01", c(mapOf("minVbiosVersion" to "96.00.01"), "1"))
        assertEquals("", c(mapOf("denyVbiosVersions" to listOf("96.01")), "1"))
        assertEquals("VBIOS 96.00 is on the deny list", c(mapOf("denyVbiosVersions" to listOf("96.01", "96.0")), "1"))
        assertEquals("driver 536 is on the deny list", c(mapOf("denyDriverVersions" to listOf("535", "536")), "536"))
    }

    @Test
    fun firmwarePolicyShape() {
        // like the reference, a present but malformed setting throws instead of being dropped
        val p = "nvidiaCollateralHook: "
        assertEquals(p + "malformed minDriverVersion '535'", thrown { policy(mapOf("minDriverVersion" to 535)) })
        assertEquals(p + "malformed minVbiosVersion 'true'", thrown { policy(mapOf("minVbiosVersion" to true)) })
        assertEquals(p + "denyDriverVersions must be an array", thrown { policy(mapOf("denyDriverVersions" to "535")) })
        assertEquals(p + "denyVbiosVersions must be an array", thrown { policy(mapOf("denyVbiosVersions" to "")) })
        assertEquals(p + "malformed denyDriverVersions entry '535'", thrown { policy(mapOf("denyDriverVersions" to listOf("1", 535))) })
        assertEquals(p + "malformed denyVbiosVersions entry 'zz'", thrown { policy(mapOf("denyVbiosVersions" to listOf("zz"))) })
        assertEquals(
            p + "malformed denyDriverVersions entry '7'",
            thrown { AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to listOf("aa"), "firmware" to mapOf("denyDriverVersions" to listOf(7)))) },
        )
        // falsy minimums and an absent (null) deny list are no setting at all
        val falsy = policy(mapOf<String, Any?>("minDriverVersion" to "", "minVbiosVersion" to 0, "denyDriverVersions" to null))
        assertNull(falsy.minD)
        assertNull(falsy.minV)
        assertEquals(emptyList<List<Double>>(), falsy.denyD)
        assertEquals(emptyList<List<Double>>(), falsy.denyV)
        assertEquals("", falsy.minDText)
        assertEquals("", falsy.minVText)
        assertEquals("", falsy.check(ids("1")))
        val zero = policy(mapOf("minDriverVersion" to "0", "minVbiosVersion" to "0"))
        assertEquals(listOf(0.0), zero.minD)
        assertEquals("0", zero.minDText)
        assertEquals("0", zero.minVText)
    }

    @Test
    fun bundleInputs() = nv {
        val drvRim = rim(payload = "<Payload>" + res("0", listOf("aabbccdd")) + "</Payload>")
        val vbRim = rim(
            meta = "<Meta product=\"GH100\" colloquialVersion=\"96.00.9F.00.04\"/>",
            payload = "<Payload>" + res("1", listOf("11223344")) + "</Payload>",
        )
        val opaque = linkedMapOf(
            3 to "535.86.10".toByteArray(Charsets.ISO_8859_1),
            6 to b(0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa),
            17 to "2330".toByteArray(Charsets.ISO_8859_1),
            18 to "0200".toByteArray(Charsets.ISO_8859_1),
            15 to "G520".toByteArray(Charsets.ISO_8859_1),
        )
        val rep = report(listOf(AttestNvidia.Measurement(1, hx("aabbccdd")), AttestNvidia.Measurement(2, hx("11223344"))), opaque)
        val noCrl = AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to RIM_PINS, "requireCrls" to false))
        fun run(h: AttestNvidiaCollateral.Hook, b: Map<String, Any?>) = h.withBundle(b).run(rep, CHAIN, NOW)
        val noDriver = "driver RIM: RIM: empty or oversized document"
        val noVbios = "VBIOS RIM: RIM: empty or oversized document"
        assertEquals("", run(noCrl, mapOf("driverRimXml" to drvRim, "vbiosRimXml" to vbRim)))
        assertEquals(noDriver, run(noCrl, mapOf("vbiosRimXml" to vbRim)))
        assertEquals(noDriver, run(noCrl, mapOf("driverRimXml" to 5, "vbiosRimXml" to vbRim)))
        assertEquals(noVbios, run(noCrl, mapOf("driverRimXml" to drvRim)))
        assertEquals(noVbios, run(noCrl, mapOf("driverRimXml" to drvRim, "vbiosRimXml" to listOf(vbRim))))
        // CRLs: non-string entries are skipped, each string is base64
        val crls = AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to RIM_PINS))
        val good = listOf<Any?>(5, b64(crl(dn(INTER_CN), interKey.private)), b64(crl(dn(ROOT_CN), rootKey.private)))
        assertEquals("", run(crls, mapOf("driverRimXml" to drvRim, "vbiosRimXml" to vbRim, "crls" to good)))
        assertEquals("revocation: no CRLs supplied", run(crls, mapOf("driverRimXml" to drvRim, "vbiosRimXml" to vbRim, "crls" to "x")))
    }

    @Test
    fun responseBytesWrapper() = nv {
        val good = basic(rdata(single()))
        assertEquals("OK:good", ocspWhy(seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid(OCSP_BASIC), octets(good))))))
        // [0] must hold exactly one SEQUENCE, even when its first element would verify
        assertEquals(rej + "malformed responseBytes", ocspWhy(seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid(OCSP_BASIC), octets(good)), seq()))))
        assertEquals(rej + "malformed responseBytes", ocspWhy(seq(tlv(0x0a, b(0)), tlv(0xa0, tlv(0x31, oid(OCSP_BASIC), octets(good))))))
    }

    @Test
    fun responderIdByKeyMustBeAnOctetString() = nv {
        val keyHash = AttestUtil.sha1(AttestCert.spkiKeyBits(inter.cert))
        assertEquals("OK:good", ocspWhy(ocsp(single(), rid = tlv(0xa2, octets(keyHash)))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = tlv(0xa2, tlv(0x16, keyHash)))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = tlv(0xa2, tlv(0x80, keyHash)))))
    }

    @Test
    fun delegatedNotAfterUnreadableAtTimeZero() = nv {
        // notBefore 1965 (before the epoch), notAfter unreadable: outside its window even at now = 0
        val ancient = responder(notBefore = utc(-5 * 365 * DAY), notAfter = text(0x18, "20280101000000.5Z"))
        val der = ocsp(single(), rid = byKey(ancient.cert), signer = respKey.private, certs = embed(ancient.der))
        assertEquals("delegated responder certificate is outside its validity window", ocspWhy(der, now = 0))
    }

    @Test
    fun rootOcspResponderIsNotRequired() = nv {
        // a root that advertises an OCSP responder still needs no response (nothing above it can answer for it)
        val rootAia = issue(dn(ROOT_CN), dn(ROOT_CN), rootKey.private, rootKey, serial = int(1), exts = listOf(BC_CA, KU_CA, aia()))
        val chain = listOf(leaf.cert, inter.cert, rootAia.cert)
        val goodLeaf = ocsp(single())
        val goodInter = ocsp(single(inter.cert, rootAia.cert), rid = byName(rootAia.cert), signer = rootKey.private)
        assertEquals("", AttestNvidiaCollateral.checkChainOcsp(chain, listOf(goodLeaf, goodInter), NOW))
    }
}
