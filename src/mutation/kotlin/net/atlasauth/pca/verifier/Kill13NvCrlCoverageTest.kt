package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * NVIDIA collateral, CRL coverage (PCA 0.5 hardening): a verified CRL from a certificate's issuer must exist for every non-root chain
 * certificate that names a CRL distribution point (`requireCrlFor` default 'cdp'), for every non-root certificate ('all') or for the
 * listed chain indices. Before this, ANY one fresh CRL (for example the root's alone) satisfied the check and a revoked device
 * certificate passed.
 */
class Kill13NvCrlCoverageTest {
    private val vb = Kill05NvKit.b(0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa)

    private fun hx(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun opaque(): Map<Int, ByteArray> {
        val m = LinkedHashMap<Int, ByteArray>()
        m[3] = " 535.86.10 \u0000\u0000".toByteArray(Charsets.ISO_8859_1)
        m[6] = vb
        m[17] = "2330".toByteArray(Charsets.ISO_8859_1)
        m[18] = "0200".toByteArray(Charsets.ISO_8859_1)
        m[15] = " g520 ".toByteArray(Charsets.ISO_8859_1)
        return m
    }

    private fun thrown(f: () -> Unit): String? = try {
        f()
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    /** The kit's leaf and intermediate re-issued with a CRL distribution point (same names, keys and serials, so OCSP answers still match). */
    private fun Kill05NvKit.cdp(): ByteArray = ext("2.5.29.31", false, seq(seq(tlv(0xa0, tlv(0xa0, text(0x86, "http://crl.example/nv.crl"))))))
    private fun Kill05NvKit.leafCdp() = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = tlv(0x02, b(0x00, 0x9a, 0x01)), exts = listOf(aia(), cdp()))
    private fun Kill05NvKit.interCdp() = issue(dn(INTER_CN), dn(ROOT_CN), rootKey.private, interKey, serial = int(2), exts = listOf(BC_CA, KU_CA, aia(), cdp()))

    private val missingLeaf get() = "no verified CRL from the issuer of chain certificate '${Kill05NvKit.line(Kill05NvKit.LEAF_CN)}'"
    private val missingInter get() = "no verified CRL from the issuer of chain certificate '${Kill05NvKit.line(Kill05NvKit.INTER_CN)}'"

    @Test
    fun aRootCrlAloneNoLongerCoversACdpChain() = nv {
        val chain = listOf(leafCdp().cert, interCdp().cert, root.cert)
        fun rev(vararg crls: ByteArray, how: Any? = "cdp") = AttestNvidiaCollateral.checkChainRevocation(chain, crls.toList(), NOW, emptyList(), how)
        val rootCrl = crl(dn(ROOT_CN), rootKey.private)
        val interCrl = crl(dn(INTER_CN), interKey.private)
        // 1: only the root's CRL (valid, fresh): the device and intermediate certificates are not covered
        assertEquals(missingLeaf, rev(rootCrl))
        // the intermediate's CRL covers the leaf, the root's covers the intermediate
        assertEquals("", rev(interCrl, rootCrl))                       // 2
        assertEquals(missingInter, rev(interCrl))                      // the intermediate's own issuer (the root) has no CRL
        // 3: a revoked leaf on the intermediate's CRL still fails as revoked
        assertEquals("chain certificate '${line(LEAF_CN)}' is revoked", rev(crl(dn(INTER_CN), interKey.private, leaf.cert.serial), rootCrl))
        // coverage is not demanded when nothing names a distribution point (the kit's own chain)
        assertEquals("", AttestNvidiaCollateral.checkChainRevocation(CHAIN, listOf(rootCrl), NOW, emptyList(), "cdp"))
    }

    @Test
    fun anUnparseableDistributionPointStillRequiresACrl() = nv {
        // presence of the extension, not its content, decides: a garbage CDP value fails closed (counts as requiring a CRL)
        val badLeaf = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = tlv(0x02, b(0x00, 0x9a, 0x02)), exts = listOf(aia(), ext("2.5.29.31", false, b(0xff, 0x00, 0x13))))
        val chain = listOf(badLeaf.cert, inter.cert, root.cert)
        val rootCrl = crl(dn(ROOT_CN), rootKey.private)
        assertEquals(missingLeaf, AttestNvidiaCollateral.checkChainRevocation(chain, listOf(rootCrl), NOW, emptyList(), "cdp"))
        assertEquals("", AttestNvidiaCollateral.checkChainRevocation(chain, listOf(crl(dn(INTER_CN), interKey.private), rootCrl), NOW, emptyList(), "cdp"))
    }

    @Test
    fun allAndExplicitIndicesDemandCoverageWithoutADistributionPoint() = nv {
        val chain = listOf(leafCdp().cert, inter.cert, root.cert)   // only the leaf names a CDP
        fun rev(vararg crls: ByteArray, how: Any?) = AttestNvidiaCollateral.checkChainRevocation(chain, crls.toList(), NOW, emptyList(), how)
        val interCrl = crl(dn(INTER_CN), interKey.private)
        val rootCrl = crl(dn(ROOT_CN), rootKey.private)
        // 4: 'cdp' demands the leaf only, 'all' also the intermediate (no CDP, no CRL from the root)
        assertEquals("", rev(interCrl, how = "cdp"))
        assertEquals(missingInter, rev(interCrl, how = "all"))
        assertEquals("", rev(interCrl, rootCrl, how = "all"))
        assertEquals("", rev(interCrl, how = listOf(0L)))
        assertEquals(missingInter, rev(interCrl, how = listOf(1L)))
        assertEquals(missingLeaf, rev(rootCrl, how = listOf(0L, 1L)))
        assertEquals("", rev(rootCrl, how = emptyList<Long>()))
        assertEquals("", rev(interCrl, how = "none"))
        assertEquals("", rev(rootCrl, how = "none"))
    }

    @Test
    fun anIndexThatIsNotANonRootCertificateFailsAndAMalformedOptionThrows() = nv {
        val chain = listOf(leafCdp().cert, interCdp().cert, root.cert)
        val crls = listOf(crl(dn(INTER_CN), interKey.private), crl(dn(ROOT_CN), rootKey.private))
        fun rev(how: Any?) = AttestNvidiaCollateral.checkChainRevocation(chain, crls, NOW, emptyList(), how)
        // 5: the root (index 2), a negative index and a far index are refused with the same wording
        assertEquals("requireCrlFor index 2 is not a non-root chain certificate", rev(listOf(2L)))
        assertEquals("requireCrlFor index -1 is not a non-root chain certificate", rev(listOf(0L, -1L)))
        assertEquals("requireCrlFor index 7 is not a non-root chain certificate", rev(listOf(7L)))
        assertEquals("", rev(listOf(0L, 1L)))
        // the option is validated when the hook is built
        val pins = mapOf<String, Any?>("rimRootSpkiSha256" to RIM_PINS)
        fun msg(bad: Any?) = "nvidiaCollateralHook: malformed requireCrlFor '" + when (bad) {
            is List<*> -> bad.joinToString(",") { it?.toString() ?: "" }
            is Map<*, *> -> "[object Object]"
            else -> bad.toString()
        } + "'"
        for (bad in listOf<Any?>("bogus", "ALL", 5, true, listOf("a"), listOf(1.5), listOf(null), mapOf("a" to 1)))
            assertEquals("$bad", msg(bad), thrown { AttestNvidiaCollateral.newHook(pins + ("requireCrlFor" to bad)) })
        for (good in listOf<Any?>(null, "cdp", "all", listOf<Any?>(), listOf<Any?>(0L, 1L)))
            assertEquals("$good", null, thrown { AttestNvidiaCollateral.newHook(pins + ("requireCrlFor" to good)) })
    }

    @Test
    fun theHookDemandsCoverageOnlyWhereCrlsAreRequired() = nv {
        val chain = listOf(leafCdp().cert, interCdp().cert, root.cert)
        val drvRim = rim(payload = "<Payload>" + res("0", listOf("aabbccdd")) + "</Payload>")
        val vbRim = rim(meta = "<Meta product=\"GH100\" colloquialVersion=\"96.00.9F.00.04\"/>", payload = "<Payload>" + res("1", listOf("11223344")) + "</Payload>")
        val rep = report(listOf(AttestNvidia.Measurement(1, hx("aabbccdd")), AttestNvidia.Measurement(2, hx("11223344"))), opaque())
        fun hook(vararg extra: Pair<String, Any?>) = AttestNvidiaCollateral.newHook(mapOf<String, Any?>("rimRootSpkiSha256" to RIM_PINS) + extra)
        fun bundle(crls: List<ByteArray> = emptyList(), ocsp: List<ByteArray> = emptyList()): Map<String, Any?> =
            mapOf("driverRimXml" to drvRim, "vbiosRimXml" to vbRim, "crls" to crls.map { b64(it) }, "ocsp" to ocsp.map { b64(it) })
        val rootCrl = crl(dn(ROOT_CN), rootKey.private)
        val interCrl = crl(dn(INTER_CN), interKey.private)
        val goodLeaf = ocsp(single())
        val goodInter = ocsp(single(inter.cert, root.cert), rid = byName(root.cert), signer = rootKey.private)
        // the default ('cdp', CRLs required): the root's CRL alone is refused, the intermediate's plus the root's passes
        assertEquals("revocation: $missingLeaf", hook().withBundle(bundle(crls = listOf(rootCrl))).run(rep, chain, NOW))
        assertEquals("", hook().withBundle(bundle(crls = listOf(interCrl, rootCrl))).run(rep, chain, NOW))
        assertEquals("revocation: $missingLeaf", hook("revocation" to "both").withBundle(bundle(crls = listOf(rootCrl), ocsp = listOf(goodLeaf, goodInter))).run(rep, chain, NOW))
        assertEquals("", hook("revocation" to "both").withBundle(bundle(crls = listOf(interCrl, rootCrl), ocsp = listOf(goodLeaf, goodInter))).run(rep, chain, NOW))
        assertEquals("revocation: requireCrlFor index 2 is not a non-root chain certificate", hook("requireCrlFor" to listOf(2L)).withBundle(bundle(crls = listOf(interCrl, rootCrl))).run(rep, chain, NOW))
        // 6: OCSP-only mode, or CRLs not required: the CRLs that are supplied are enforced, but no coverage is demanded
        assertEquals("", hook("revocation" to "ocsp").withBundle(bundle(crls = listOf(rootCrl), ocsp = listOf(goodLeaf, goodInter))).run(rep, chain, NOW))
        assertEquals("", hook("requireCrls" to false).withBundle(bundle(crls = listOf(rootCrl))).run(rep, chain, NOW))
        assertEquals(
            "revocation: chain certificate '${line(LEAF_CN)}' is revoked",
            hook("requireCrls" to false).withBundle(bundle(crls = listOf(crl(dn(INTER_CN), interKey.private, leaf.cert.serial)))).run(rep, chain, NOW),
        )
    }
}
