package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AttestNvidiaCollateral: RIM ids, golden comparison (merge / NVDEC0), CRL revocation, firmware policy, and the collateral hook. */
class Kill05NvCollateralTest {
    private val vb = Kill05NvKit.b(0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa) // VBIOS 96.00.9f.00.04

    private fun hx(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun opaque(driver: String? = " 535.86.10 \u0000\u0000", chip: String? = null): Map<Int, ByteArray> {
        val m = LinkedHashMap<Int, ByteArray>()
        if (driver != null) m[3] = driver.toByteArray(Charsets.ISO_8859_1)
        m[6] = vb
        m[17] = "2330".toByteArray(Charsets.ISO_8859_1)
        m[18] = "0200".toByteArray(Charsets.ISO_8859_1)
        m[15] = " g520 ".toByteArray(Charsets.ISO_8859_1)
        if (chip != null) m[35] = chip.toByteArray(Charsets.ISO_8859_1)
        return m
    }

    private fun thrown(f: () -> Unit): String? = try {
        f()
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun rimIdsFromTheReport() = nv {
        val ids = AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque()))!!
        assertEquals("GH100", ids.chip)
        assertEquals("NV_GPU_DRIVER_GH100_535.86.10", ids.driver)
        assertEquals("NV_GPU_VBIOS_2330_0200_G520_96009F0004", ids.vbios)
        assertEquals("535.86.10", ids.driverVersion)
        assertEquals("96.00.9f.00.04", ids.vbiosVersion)
        val gb = AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(chip = "GB100\u0000")))!!
        assertEquals("GB100", gb.chip)
        assertEquals("NV_GPU_CC_DRIVER_GB100_535.86.10", gb.driver)
        assertEquals("NV_GPU_DRIVER_GH100_535.86.10", AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(chip = "GH100")))!!.driver)
        assertNull(AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(chip = "gb100"))))
        assertNull(AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(chip = "GB"))))
        assertNull(AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(driver = null))))
        assertNull(AttestNvidiaCollateral.rimIdsForReport(report(emptyList(), opaque(driver = " \u0000"))))
    }

    private fun g(index: Int, vararg hashes: String, active: Boolean = true, size: Int = hashes[0].length / 2) =
        AttestNvidiaCollateral.Golden(index, active, hashes.size, size, hashes.toList())

    private fun rimOf(vararg gs: AttestNvidiaCollateral.Golden) = AttestNvidiaCollateral.Rim("GH100", "1", gs.associateBy { it.index })

    /** A measurement for golden index `index0` (SPDM block index is one more). */
    private fun m(index0: Int, digest: String) = AttestNvidia.Measurement(index0 + 1, hx(digest))

    @Test
    fun goldenComparison() = nv {
        fun cmp(ms: List<AttestNvidia.Measurement>, d: AttestNvidiaCollateral.Rim, v: AttestNvidiaCollateral.Rim, op: Map<Int, ByteArray> = emptyMap()) =
            AttestNvidiaCollateral.compareReportToRims(report(ms, op), d, v)
        val differ1 = "runtime measurements differ from the golden RIM values at 1 index(es)"
        assertEquals("", cmp(listOf(m(0, "ccdd"), m(1, "eeff")), rimOf(g(0, "aabb", "ccdd")), rimOf(g(1, "eeff"))))
        assertEquals("", cmp(listOf(m(0, "aabb")), rimOf(g(0, "aabb")), rimOf()))
        assertEquals("driver and VBIOS RIMs both have an active measurement at index 0", cmp(listOf(m(0, "aabb")), rimOf(g(0, "aabb")), rimOf(g(0, "aabb"))))
        assertEquals("", cmp(listOf(m(0, "aabb")), rimOf(g(0, "0000", active = false)), rimOf(g(0, "aabb"))))
        assertEquals("RIMs carry no active golden measurements", cmp(listOf(m(0, "aabb")), rimOf(g(0, "aabb", active = false)), rimOf(g(1, "aabb", active = false))))
        assertEquals("RIMs list more active measurements than the report carries", cmp(listOf(m(0, "aabb")), rimOf(g(0, "aabb"), g(1, "ccdd")), rimOf()))
        assertEquals(differ1, cmp(listOf(m(5, "aabb")), rimOf(g(0, "aabb")), rimOf()))
        assertEquals(differ1, cmp(listOf(m(0, "aabb")), rimOf(g(0, "aabb", size = 4)), rimOf()))
        assertEquals(
            "runtime measurements differ from the golden RIM values at 2 index(es)",
            cmp(listOf(m(0, "0000"), m(1, "0000")), rimOf(g(0, "aabb"), g(1, "ccdd")), rimOf()),
        )
        // NVDEC0 disabled (opaque 11 starts with 0x55): golden index 34 (block 35) is skipped, and only it
        fun nvdec(index0: Int, op: Map<Int, ByteArray>) = cmp(listOf(m(index0, "0000")), rimOf(g(index0, "aabb")), rimOf(), op)
        assertEquals("", nvdec(34, mapOf(11 to b(0x55))))
        assertEquals("", nvdec(34, mapOf(11 to b(0x55, 0x00))))
        assertEquals(differ1, nvdec(34, mapOf(11 to b(0x54))))
        assertEquals(differ1, nvdec(34, mapOf(11 to b(0xd5))))
        assertEquals(differ1, nvdec(34, mapOf(11 to NONE)))
        assertEquals(differ1, nvdec(34, mapOf(12 to b(0x55))))
        assertEquals(differ1, nvdec(34, emptyMap()))
        assertEquals(differ1, nvdec(33, mapOf(11 to b(0x55))))
        assertEquals(differ1, nvdec(35, mapOf(11 to b(0x55))))
    }

    @Test
    fun crlRevocation() = nv {
        fun rev(vararg crls: ByteArray, need: List<String> = emptyList()) = AttestNvidiaCollateral.checkChainRevocation(CHAIN, crls.toList(), NOW, need, "none")
        val interCrl = crl(dn(INTER_CN), interKey.private)
        assertEquals("", rev(interCrl, crl(dn(ROOT_CN), rootKey.private)))
        assertEquals("chain certificate '${line(LEAF_CN)}' is revoked", rev(crl(dn(INTER_CN), interKey.private, leaf.cert.serial)))
        assertEquals("chain certificate '${line(INTER_CN)}' is revoked", rev(crl(dn(ROOT_CN), rootKey.private, inter.cert.serial)))
        // a CRL lists only the certificates its own issuer issued
        assertEquals("", rev(crl(dn(ROOT_CN), rootKey.private, leaf.cert.serial)))
        // the chain's first certificate may issue a CRL too
        assertEquals("", rev(crl(dn(LEAF_CN), leafKey.private), need = listOf("GH100 A01")))
        assertEquals("no verified CRL issued by a certificate matching 'Device Identity'", rev(crl(dn(LEAF_CN), leafKey.private), need = listOf("Device Identity")))
        assertEquals("CRL #1 rejected: CRL signature does not verify under the issuer", rev(interCrl, crl(dn("Other CA"), p384().private)))
    }

    private fun policy(fw: Map<String, Any?>): AttestNvidiaCollateral.FirmwarePolicy = KUtil.priv(AttestNvidiaCollateral, "compileFirmwarePolicy", fw)

    private fun ids(d: String, v: String = "96.00") = AttestNvidiaCollateral.RimIds("GH100", "", "", d, v)

    @Test
    fun firmwarePolicy() {
        val p = policy(mapOf("minDriverVersion" to "535.86", "minVbiosVersion" to "96.0a", "denyDriverVersions" to listOf("1.2"), "denyVbiosVersions" to listOf("a.b")))
        assertEquals(listOf(535.0, 86.0), p.minD)
        assertEquals(listOf(150.0, 10.0), p.minV)
        assertEquals(listOf(listOf(1.0, 2.0)), p.denyD)
        assertEquals(listOf(listOf(10.0, 11.0)), p.denyV)
        assertEquals("535.86", p.minDText)
        assertEquals("96.0a", p.minVText)
        val none = policy(emptyMap())
        assertNull(none.minD)
        assertNull(none.minV)
        assertEquals("", none.check(ids("12345.1"))) // driver versions are decimal: any number of digits
        assertEquals("driver version 'abc' in the GPU report is not parseable", none.check(ids("abc")))
        assertEquals("VBIOS version '' in the GPU report is not parseable", none.check(ids("535", "")))
        fun c(fw: Map<String, Any?>, d: String, v: String = "96.00") = policy(fw).check(ids(d, v))
        assertEquals("driver 535.86 is below the minimum 535.86.1", c(mapOf("minDriverVersion" to "535.86.1"), "535.86"))
        assertEquals("", c(mapOf("minDriverVersion" to "535.86.0"), "535.86"))
        assertEquals("", c(mapOf("minDriverVersion" to "535.86"), "535.86"))
        assertEquals("driver 535 is below the minimum 535.1", c(mapOf("minDriverVersion" to "535.1"), "535"))
        assertEquals("", c(mapOf("denyDriverVersions" to listOf("535.86")), "535.86.1"))
        assertEquals("", c(mapOf("denyDriverVersions" to listOf("535")), "536"))
        assertEquals("", c(mapOf("denyDriverVersions" to listOf("535")), "535.1"))
        assertEquals("driver 535.86 is on the deny list", c(mapOf("denyDriverVersions" to listOf("535.86.0")), "535.86"))
        assertEquals("VBIOS 96.00 is below the minimum 96.01", c(mapOf("minVbiosVersion" to "96.01"), "535"))
        assertEquals("VBIOS 96.00 is on the deny list", c(mapOf("denyVbiosVersions" to listOf("96.00")), "535"))
        assertEquals(
            "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root",
            thrown { AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to listOf<String>())) },
        )
        assertEquals(
            "nvidiaCollateralHook: requireCrlIssuers must list only strings",
            thrown { AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to listOf("aa"), "requireCrlIssuers" to listOf("NVIDIA", 5))) },
        )
        assertEquals(
            "nvidiaCollateralHook: requireCrlIssuers must list only strings",
            thrown { AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to listOf("aa"), "requireCrlIssuers" to 5)) },
        )
        assertEquals(
            "nvidiaCollateralHook: malformed minDriverVersion '-1'",
            thrown { AttestNvidiaCollateral.newHook(mapOf("rimRootSpkiSha256" to listOf("aa"), "firmware" to mapOf("minDriverVersion" to "-1"))) },
        )
    }

    @Test
    fun collateralHook() = nv {
        val drvRim = rim(payload = "<Payload>" + res("0", listOf("aabbccdd")) + "</Payload>")
        val vbRim = rim(
            meta = "<Meta product=\"GH100\" colloquialVersion=\"96.00.9F.00.04\"/>",
            payload = "<Payload>" + res("1", listOf("11223344")) + "</Payload>",
        )
        val rep = report(listOf(AttestNvidia.Measurement(1, hx("aabbccdd")), AttestNvidia.Measurement(2, hx("11223344"))), opaque())
        fun hook(vararg extra: Pair<String, Any?>) = AttestNvidiaCollateral.newHook(mapOf<String, Any?>("rimRootSpkiSha256" to RIM_PINS) + extra)
        fun bundle(d: String = drvRim, v: String = vbRim, crls: List<ByteArray> = emptyList(), ocsp: List<ByteArray> = emptyList()): Map<String, Any?> =
            mapOf("driverRimXml" to d, "vbiosRimXml" to v, "crls" to crls.map { b64(it) }, "ocsp" to ocsp.map { b64(it) })
        val noCrl = hook("requireCrls" to false)
        assertEquals("GPU report does not carry the opaque fields needed to name its RIMs", noCrl.withBundle(bundle()).run(report(emptyList(), emptyMap()), CHAIN, NOW))
        assertEquals(
            "device leaf subject '${line(ROOT_CN)}' is not a GH100 device certificate (chip family mismatch)",
            noCrl.withBundle(bundle()).run(rep, listOf(root.cert), NOW),
        )
        assertEquals(
            "firmware policy: driver 535.86.10 is below the minimum 999",
            hook("requireCrls" to false, "firmware" to mapOf("minDriverVersion" to "999")).withBundle(bundle()).run(rep, CHAIN, NOW),
        )
        assertEquals("no RIM collateral supplied for this report", noCrl.withBundle(null).run(rep, CHAIN, NOW))
        assertEquals("driver RIM: RIM: empty or oversized document", noCrl.withBundle(bundle(d = "")).run(rep, CHAIN, NOW))
        assertEquals("VBIOS RIM: RIM: empty or oversized document", noCrl.withBundle(bundle(v = "")).run(rep, CHAIN, NOW))
        assertEquals("", noCrl.withBundle(bundle()).run(rep, CHAIN, NOW))
        assertEquals("revocation: no CRLs supplied", hook().withBundle(bundle()).run(rep, CHAIN, NOW))
        assertEquals("revocation (OCSP): no OCSP responses supplied", hook("revocation" to "ocsp").withBundle(bundle()).run(rep, CHAIN, NOW))
        val crls = listOf(crl(dn(INTER_CN), interKey.private), crl(dn(ROOT_CN), rootKey.private))
        val goodInter = ocsp(single(inter.cert, root.cert), rid = byName(root.cert), signer = rootKey.private)
        assertEquals("", hook("revocation" to "both").withBundle(bundle(crls = crls, ocsp = listOf(ocsp(single()), goodInter))).run(rep, CHAIN, NOW))
    }
}
