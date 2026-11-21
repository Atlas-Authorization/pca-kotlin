package net.atlasauth.pca.verifier

import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** A generated Intel TDX DCAP quote, its PCS collateral (CRLs, signed TCB info / QE identity) and DER helpers (keys made at run time). */
internal object Kill05IntelMeshKit {
    val k = Kill05GcpAmdKit
    const val SGX = "1.2.840.113741.1.13.1"
    val ALG: ByteArray = Kill05GcpAmdKit.seq(Kill05GcpAmdKit.oid("1.2.840.10045.4.3.2"))

    fun name(cn: String): ByteArray = k.seq(k.tlv(0x31, k.seq(k.oid("2.5.4.3"), k.tlv(0x0c, cn.toByteArray(Charsets.UTF_8)))))
    fun utc(s: String): ByteArray = k.tlv(0x17, s.toByteArray(Charsets.US_ASCII))
    fun gen(s: String): ByteArray = k.tlv(0x18, s.toByteArray(Charsets.US_ASCII))
    fun hex(b: ByteArray): String = AttestUtil.hex(b)
    fun le(v: Long, n: Int): ByteArray = ByteArray(n) { (v ushr (8 * it)).toByte() }
    fun spkiPin(kp: KeyPair): String = hex(AttestUtil.sha256(kp.public.encoded))

    /** A signature over data (DER for ECDSA). */
    fun ecSign(kp: KeyPair, data: ByteArray, alg: String = "SHA256withECDSA"): ByteArray {
        val s = Signature.getInstance(alg)
        s.initSign(kp.private)
        s.update(data)
        return s.sign()
    }

    /** A v3 certificate with its own serial, valid 2025-01-01 .. notAfter, signed (ECDSA / SHA-256) by signer. */
    fun cert(serial: Long, subjectCn: String, issuerCn: String, subject: KeyPair, signer: KeyPair, notAfter: String, vararg exts: ByteArray): ByteArray {
        val e = if (exts.isEmpty()) ByteArray(0) else k.tlv(0xa3, k.seq(*exts))
        val validity = k.seq(utc(Kill05GcpAmdKit.NB), utc(notAfter))
        val tbs = k.seq(k.tlv(0xa0, k.integer(2)), k.integer(serial), ALG, name(issuerCn), validity, name(subjectCn), subject.public.encoded, e)
        return k.seq(tbs, ALG, k.bits(0, ecSign(signer, tbs)))
    }

    /** The Intel SGX extension: 16 SGX SVNs (1..16), the PCESVN and the FMSPC. */
    fun sgxExt(pcesvn: Long, fmspc: ByteArray): ByteArray {
        val comps = ArrayList<ByteArray>()
        for (i in 1..16) comps.add(k.seq(k.oid("$SGX.2.$i"), k.integer(i.toLong())))
        comps.add(k.seq(k.oid("$SGX.2.17"), k.integer(pcesvn)))
        val tcb = k.seq(k.oid("$SGX.2"), k.seq(*comps.toTypedArray()))
        val fm = k.seq(k.oid("$SGX.4"), k.tlv(0x04, fmspc))
        return k.ext(SGX, false, k.seq(tcb, fm))
    }

    fun revoked(vararg serials: Long): ByteArray = k.seq(*serials.map { k.seq(k.integer(it), utc("250101000000Z")) }.toTypedArray())

    fun crlOf(tbs: ByteArray, signer: KeyPair): ByteArray = k.seq(tbs, ALG, k.bits(0, ecSign(signer, tbs)))

    fun svns(v: Int): String = (0 until 16).joinToString(",", "[", "]") { "{\"svn\":$v}" }

    fun level(sgx: Int, tdx: Int, pce: Int, status: String): String =
        "{\"tcb\":{\"sgxtcbcomponents\":${svns(sgx)},\"pcesvn\":$pce,\"tdxtcbcomponents\":${svns(tdx)}},\"tcbStatus\":\"$status\",\"advisoryIDs\":[]}"

    class G {
        val root: KeyPair = k.ecKey("secp256r1")
        val ca: KeyPair = k.ecKey("secp256r1")
        val pck: KeyPair = k.ecKey("secp256r1")
        val ak: KeyPair = k.ecKey("secp256r1")
        val tcbSigner: KeyPair = k.ecKey("secp256r1")
        val fmspc = byteArrayOf(0x00, 0x90.toByte(), 0x6e, 0xd5.toByte(), 0x00, 0x00)
        val rootDer: ByteArray = cert(1, "Intel SGX Root CA", "Intel SGX Root CA", root, root, Kill05GcpAmdKit.NA, k.basicConstraints(true, 1), k.keyUsageCertSign())
        val caDer: ByteArray = cert(2, "Intel SGX PCK Platform CA", "Intel SGX Root CA", ca, root, Kill05GcpAmdKit.NA, k.basicConstraints(true, 0), k.keyUsageCertSign())
        val pckDer: ByteArray = cert(3, "Intel SGX PCK Certificate", "Intel SGX PCK Platform CA", pck, ca, Kill05GcpAmdKit.NA, sgxExt(13, fmspc))
        val tcbDer: ByteArray = cert(4, "Intel SGX TCB Signing", "Intel SGX Root CA", tcbSigner, root, Kill05GcpAmdKit.NA)

        /** true: the quote carries one self-signed certificate (the PCK key as its own root). */
        var single = false
        var tee0 = 3
        var minor = 0
        val seamAttr = byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0)
        val rtmr0 = ByteArray(48)
        val mrTd = ByteArray(48) { 0x11.toByte() }
        val reportData: ByteArray = Attest.bindingBytes(Kill05GcpAmdKit.BINDING)
        var akRaw: ByteArray? = null
        var qeRd32 = false
        val rootRevoked = ArrayList<Long>()
        val pckRevoked = ArrayList<Long>()

        var tcbBody = "{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2027-01-01T00:00:00Z\",\"nextUpdate\":\"2027-02-01T00:00:00Z\"," +
            "\"fmspc\":\"00906ED50000\",\"tcbEvaluationDataNumber\":0,\"tdxModule\":{\"mrsigner\":\"" + "00".repeat(48) +
            "\",\"attributes\":\"0100000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tcbLevels\":[" + level(1, 0, 13, "UpToDate") + "]}"
        var qeBody = "{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2027-01-01T00:00:00Z\",\"nextUpdate\":\"2027-02-01T00:00:00Z\"," +
            "\"tcbEvaluationDataNumber\":0,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"" + "00".repeat(16) +
            "\",\"attributesMask\":\"" + "FF".repeat(16) + "\",\"mrsigner\":\"" + "00".repeat(32) +
            "\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":0},\"tcbStatus\":\"UpToDate\"}]}"

        fun pin(): String = if (single) spkiPin(pck) else spkiPin(root)

        fun chain(): String =
            if (single) k.pem(cert(7, "PCK", "PCK", pck, pck, Kill05GcpAmdKit.NA, sgxExt(13, fmspc))) else k.pem(pckDer) + k.pem(caDer) + k.pem(rootDer)

        fun signerChain(): String = k.pem(tcbDer) + k.pem(rootDer)

        fun body(): ByteArray {
            val b = ByteArray(584)
            b[0] = tee0.toByte()
            b[1] = minor.toByte()
            System.arraycopy(seamAttr, 0, b, 112, 8)
            System.arraycopy(mrTd, 0, b, 136, 48)
            System.arraycopy(rtmr0, 0, b, 328, 48)
            System.arraycopy(reportData, 0, b, 520, 64)
            return b
        }

        fun ak64(): ByteArray {
            val given = akRaw
            if (given != null) return given
            val w = (ak.public as ECPublicKey).w
            return Kill05JwsKit.unsigned(w.affineX, 32) + Kill05JwsKit.unsigned(w.affineY, 32)
        }

        fun quote(): ByteArray {
            val header = ByteArray(48)
            header[0] = 4
            header[2] = 2
            header[4] = 0x81.toByte()
            val body = body()
            val akR = ak64()
            val auth = "auth".toByteArray(Charsets.US_ASCII)
            val qe = ByteArray(384)
            qe[256] = 2
            System.arraycopy(AttestUtil.sha256(akR + auth), 0, qe, 0x140, 32)
            if (qeRd32) qe[0x140 + 32] = 1
            val qeSig = k.signRaw(pck, "SHA256withECDSA", qe, 32)
            val quoteSig = k.signRaw(ak, "SHA256withECDSA", header + body, 32)
            val chain = chain().toByteArray(Charsets.US_ASCII)
            val inner = qe + qeSig + le(auth.size.toLong(), 2) + auth + le(5L, 2) + le(chain.size.toLong(), 4) + chain
            val sig = quoteSig + akR + le(6L, 2) + le(inner.size.toLong(), 4) + inner
            return header + body + le(sig.size.toLong(), 4) + sig
        }

        fun doc(name: String, body: String): String =
            "{\"" + name + "\":" + body + ",\"signature\":\"" + hex(k.signRaw(tcbSigner, "SHA256withECDSA", body.toByteArray(Charsets.UTF_8), 32)) + "\"}"

        fun crl(signer: KeyPair, serials: List<Long>): ByteArray {
            val rev = if (serials.isEmpty()) ByteArray(0) else revoked(*serials.toLongArray())
            return crlOf(k.seq(k.integer(1), ALG, name("Intel SGX Root CA"), utc(Kill05GcpAmdKit.NB), utc(Kill05GcpAmdKit.NA), rev), signer)
        }

        fun collateral(): AttestIntel.Collateral = AttestIntel.Collateral(
            doc("tcbInfo", tcbBody), signerChain(), doc("enclaveIdentity", qeBody), signerChain(), crl(ca, pckRevoked), crl(root, rootRevoked),
        )

        fun run(pol: AttestIntel.CollateralPolicy?): AttestIntel.CollateralResult =
            AttestIntel.verifyTdxCollateral(quote(), collateral(), Kill05GcpAmdKit.NOW, pol, pin(), false)
    }
}

/** Intel TDX: the PCK chain, the genuine-quote checks, the PCS issuer chains, verifyTdxCollateral end to end and create(). */
class Kill05IntelMeshAttestIntelQuoteTest {
    private val k = Kill05GcpAmdKit
    private val x = Kill05IntelMeshKit
    private val now = Kill05GcpAmdKit.NOW
    private val na = Kill05GcpAmdKit.NA_MS

    private fun <T> p(name: String, vararg a: Any?): T = KUtil.priv(AttestIntel, name, *a)

    @Test fun pckChain() {
        val g = Kill05IntelMeshKit.G()
        val ok = AttestIntel.verifyPckChain(g.chain(), g.pin(), now)
        assertTrue(ok.reason, ok.ok)
        assertEquals(3, ok.depth)
        assertNotNull(ok.leaf)
        assertFalse(ok.validity)
        // the validity boundary is inclusive and read with no skew
        assertTrue(AttestIntel.verifyPckChain(g.chain(), g.pin(), na).ok)
        val exp = AttestIntel.verifyPckChain(g.chain(), g.pin(), na + 1)
        assertFalse(exp.ok)
        assertTrue(exp.validity)
        assertEquals("PCK chain certificate outside its validity period", exp.reason)
        assertEquals(0, exp.depth)
        assertNull(exp.leaf)
        val none = AttestIntel.verifyPckChain("no certificates here", g.pin(), now)
        assertFalse(none.ok)
        assertFalse(none.validity)
        assertNull(none.leafKey)
        assertEquals("no PEM certificates in the PCK chain", none.reason)
        // two certificates issuing each other: the walk stops at the repeat and finds no self-signed root
        val a = k.ecKey("secp256r1")
        val b = k.ecKey("secp256r1")
        val cyc = k.pem(x.cert(5, "A", "B", a, b, Kill05GcpAmdKit.NA)) + k.pem(x.cert(6, "B", "A", b, a, Kill05GcpAmdKit.NA))
        assertEquals("PCK chain does not terminate in a self-signed root", AttestIntel.verifyPckChain(cyc, g.pin(), now).reason)
    }

    @Test fun compactSignatureIsExactly64Bytes() {
        val kp = k.ecKey("secp256r1")
        val msg = k.bytes(1, 2, 3)
        val raw = k.signRaw(kp, "SHA256withECDSA", msg, 32)
        val pub = kp.public as ECPublicKey
        assertTrue(p<Boolean>("verifyP256Compact", msg, raw, pub))
        // r and s each with a leading zero byte: the same signature to the raw verifier, refused by the 64-byte rule
        val padded = k.bytes(0) + raw.copyOfRange(0, 32) + k.bytes(0) + raw.copyOfRange(32, 64)
        assertTrue(AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha256(msg), padded))
        assertFalse(p<Boolean>("verifyP256Compact", msg, padded, pub))
    }

    @Test fun genuineQuote() {
        val g = Kill05IntelMeshKit.G()
        val quote = g.quote()
        val ok = AttestIntel.verifyGenuineTdxQuote(quote, g.pin(), now, null, false)
        assertTrue(ok.reason, ok.ok)
        assertEquals("00906ed50000", ok.fmspc)
        // an empty MRTD allowlist (create() refuses one; only a direct call has it) accepts any MRTD
        assertTrue(AttestIntel.verifyGenuineTdxQuote(quote, g.pin(), now, AttestIntel.QuotePolicy(emptyList(), emptyList(), emptyList(), null, null, false), false).ok)
        assertEquals("MRTD not in policy allowlist",
            AttestIntel.verifyGenuineTdxQuote(quote, g.pin(), now, AttestIntel.QuotePolicy(listOf("ab".repeat(48)), emptyList(), emptyList(), null, null, false), false).reason)
        val bad = AttestIntel.verifyGenuineTdxQuote(ByteArray(10), g.pin(), now, null, false)
        assertFalse(bad.ok)
        assertNull(bad.pck)
        assertEquals("quote parse failed: parseDcapQuote: too short for header + TD report + sig length", bad.reason)
        val rd = Kill05IntelMeshKit.G()
        rd.qeRd32 = true
        val rdr = AttestIntel.verifyGenuineTdxQuote(rd.quote(), rd.pin(), now, null, false)
        assertFalse(rdr.ok)
        assertEquals("QE report_data does not bind the attestation key (AK not endorsed by this QE)", rdr.reason)
        val ak = Kill05IntelMeshKit.G()
        ak.akRaw = ByteArray(64) { 1.toByte() }
        assertEquals("attestation public key is not a valid P-256 point", AttestIntel.verifyGenuineTdxQuote(ak.quote(), ak.pin(), now, null, false).reason)
    }

    @Test fun issuerChains() {
        val g = Kill05IntelMeshKit.G()
        val want = x.spkiPin(g.tcbSigner)
        fun sk(chain: String, at: Long, revoked: Set<String>): String {
            val r = p<Pair<AttestCert.CertKey?, String>>("signerKeyFromChain", chain, g.pin(), at, revoked)
            val key = r.first
            return if (r.second == "" && key != null) "key:" + (AttestUtil.hex(AttestUtil.sha256(key.spki)) == want) else r.second
        }
        assertEquals("key:true", sk(g.signerChain(), now, emptySet()))
        assertEquals("issuer chain certificate outside its validity period", sk(g.signerChain(), na + 1, emptySet()))
        assertEquals("issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor", sk(Kill05IntelMeshKit.G().signerChain(), now, emptySet()))
        assertEquals("issuer chain certificate is revoked by the Intel Root CA CRL", sk(g.signerChain(), now, setOf("4")))
    }

    @Test fun collateralEndToEnd() {
        val g = Kill05IntelMeshKit.G()
        val ok = g.run(null)
        assertTrue(ok.reason, ok.ok)
        assertEquals("UpToDate", ok.status)
        assertEquals(emptyList<String>(), ok.advisoryIds)
        // tcbEvaluationDataNumber 0 is present (not missing) and meets a minimum of 0, not of 1
        assertTrue(g.run(AttestIntel.CollateralPolicy(null, 0.0)).ok)
        assertEquals("tcbEvaluationDataNumber below policy minimum", g.run(AttestIntel.CollateralPolicy(null, 1.0)).reason)
        val q5 = Kill05IntelMeshKit.G()
        q5.tcbBody = q5.tcbBody.replace("\"tcbEvaluationDataNumber\":0", "\"tcbEvaluationDataNumber\":5")
        assertEquals("tcbEvaluationDataNumber below policy minimum", q5.run(AttestIntel.CollateralPolicy(null, 1.0)).reason)
        val fm = Kill05IntelMeshKit.G()
        fm.tcbBody = fm.tcbBody.replace("\"fmspc\":\"00906ED50000\"", "\"fmspc\":5")
        assertEquals("TCB info FMSPC does not match the quote PCK", fm.run(null).reason)

        // each collateral member missing on its own
        val quote = g.quote()
        val c = g.collateral()
        val e = ByteArray(0)
        val parts = listOf(
            AttestIntel.Collateral("", c.tcbInfoChain, c.qeIdentityJson, c.qeIdentityChain, c.pckCrl, c.rootCrl),
            AttestIntel.Collateral(c.tcbInfoJson, "", c.qeIdentityJson, c.qeIdentityChain, c.pckCrl, c.rootCrl),
            AttestIntel.Collateral(c.tcbInfoJson, c.tcbInfoChain, "", c.qeIdentityChain, c.pckCrl, c.rootCrl),
            AttestIntel.Collateral(c.tcbInfoJson, c.tcbInfoChain, c.qeIdentityJson, "", c.pckCrl, c.rootCrl),
            AttestIntel.Collateral(c.tcbInfoJson, c.tcbInfoChain, c.qeIdentityJson, c.qeIdentityChain, e, c.rootCrl),
            AttestIntel.Collateral(c.tcbInfoJson, c.tcbInfoChain, c.qeIdentityJson, c.qeIdentityChain, c.pckCrl, e),
            null,
        )
        for ((i, part) in parts.withIndex()) {
            assertEquals("member $i", "collateral incomplete (fail closed)", AttestIntel.verifyTdxCollateral(quote, part, now, null, g.pin(), false).reason)
        }
        assertTrue(AttestIntel.verifyTdxCollateral(quote, c, now, null, g.pin(), false).ok)

        // a single self-signed PCK certificate verifies as a chain, but no certificate in it is a leaf
        val s = Kill05IntelMeshKit.G()
        s.single = true
        assertTrue(AttestIntel.verifyGenuineTdxQuote(s.quote(), s.pin(), now, null, false).ok)
        assertEquals("PCK leaf not found", s.run(null).reason)
    }

    private fun create(c: Map<String, Any?>): String = try {
        AttestIntel.create(c)
        "OK"
    } catch (e: IllegalArgumentException) {
        e.message ?: ""
    }

    @Test fun constructor() {
        val m96 = "a".repeat(96)
        val pol = KUtil.m("mrtds" to KUtil.l(m96))
        assertEquals("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'", create(KUtil.m("binding" to Json.Num("5"), "policy" to pol)))
        assertEquals("OK", create(KUtil.m("binding" to "azure-runtime-data", "policy" to pol)))
        assertEquals("OK", create(KUtil.m("binding" to "report-data", "policy" to pol, "trustAnchorRootCaSpkiSha256" to Json.Num("5"))))
        assertEquals("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)", create(KUtil.m("binding" to "report-data")))
        for (name in listOf("mrSeams", "mrSignerSeams")) {
            assertEquals("OK", create(KUtil.m("binding" to "report-data", "policy" to KUtil.m("mrtds" to KUtil.l(m96), name to KUtil.l(m96)))))
            for (bad in listOf("g".repeat(96), "a".repeat(94))) {
                assertEquals("createIntelDcapVerifier: every $name entry must be 96 hex chars (48 bytes)",
                    create(KUtil.m("binding" to "report-data", "policy" to KUtil.m("mrtds" to KUtil.l(m96), name to KUtil.l(bad)))))
            }
        }
    }

    @Test fun verifierPolicies() {
        val g = Kill05IntelMeshKit.G()
        g.rtmr0.fill(0xab.toByte())
        val ev = KUtil.m("quote" to k.b64(g.quote()))
        fun run(extra: Map<String, Any?>): Attest.Result {
            val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)))
            pol.putAll(extra)
            val cfg = KUtil.m("binding" to "report-data", "trustAnchorRootCaSpkiSha256" to g.pin().uppercase(), "allowMissingCollateral" to true, "policy" to pol)
            return AttestIntel.create(cfg).verify(ev, Kill05GcpAmdKit.BINDING, now)
        }
        // the RTMR0 allowlist is compared lowercase; the SEAM allowlists match the TD report's (zero) MRSEAM / MRSIGNERSEAM
        val ok = run(KUtil.m("rtmrs" to KUtil.l("AB".repeat(48)), "mrSeams" to KUtil.l("0".repeat(96)), "mrSignerSeams" to KUtil.l("0".repeat(96))))
        assertTrue(ok.reason, ok.ok)
        assertEquals("unevaluated", ok.hostAsserted!!["tcb_status"])
        assertEquals("DCAP quote invalid: RTMR0 not in policy allowlist", run(KUtil.m("rtmrs" to KUtil.l("CD".repeat(48)))).reason)
    }

    @Test fun minimumEvaluationNumberAppliesToTheTcbInfoToo() {
        val g = Kill05IntelMeshKit.G()
        // the TCB info is at 0, the QE identity at 5: a minimum of 1 fails on the TCB info alone
        g.qeBody = g.qeBody.replace("\"tcbEvaluationDataNumber\":0", "\"tcbEvaluationDataNumber\":5")
        assertEquals("tcbEvaluationDataNumber below policy minimum", g.run(AttestIntel.CollateralPolicy(null, 1.0)).reason)
        assertTrue(g.run(AttestIntel.CollateralPolicy(null, 0.0)).ok)
        g.tcbBody = g.tcbBody.replace("\"tcbEvaluationDataNumber\":0", "\"tcbEvaluationDataNumber\":5")
        assertTrue(g.run(AttestIntel.CollateralPolicy(null, 5.0)).ok)
        assertEquals("tcbEvaluationDataNumber below policy minimum", g.run(AttestIntel.CollateralPolicy(null, 6.0)).reason)
    }

    @Test fun seamAllowlistsMustBeNonEmptyStringLists() {
        val m96 = "a".repeat(96)
        for (name in listOf("mrSeams", "mrSignerSeams")) {
            for (bad in listOf<Any?>("x", null, KUtil.l(), KUtil.l(Json.Num("5")))) {
                val pol = KUtil.m("mrtds" to KUtil.l(m96))
                pol[name] = bad
                assertEquals("$name=$bad", "createIntelDcapVerifier: policy.$name, if given, must be a NON-EMPTY list",
                    create(KUtil.m("binding" to "report-data", "policy" to pol)))
            }
        }
        // only the two named members are read: a member with a null key (not JSON, but a caller's map) is ignored
        val odd = HashMap<String?, Any?>()
        odd["mrtds"] = KUtil.l(m96)
        odd[null] = KUtil.l("not hex")
        assertEquals("OK", create(KUtil.m("binding" to "report-data", "policy" to odd)))
    }

    @Test fun fmspcAllowlistIsCaseInsensitive() {
        val g = Kill05IntelMeshKit.G()
        val ev = KUtil.m("quote" to k.b64(g.quote()))
        fun run(fmspcs: List<Any?>): Attest.Result {
            val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)), "fmspcs" to ArrayList<Any?>(fmspcs))
            val cfg = KUtil.m("binding" to "report-data", "trustAnchorRootCaSpkiSha256" to g.pin(), "allowMissingCollateral" to true, "policy" to pol)
            return AttestIntel.create(cfg).verify(ev, Kill05GcpAmdKit.BINDING, now)
        }
        val up = run(listOf("00906ED50000"))
        assertTrue(up.reason, up.ok)
        assertTrue(run(listOf("00906ed50000")).ok)
        assertEquals("DCAP quote invalid: FMSPC not in policy allowlist", run(listOf("00906ED50001")).reason)
        val mixed = assertThrows(IllegalArgumentException::class.java) { run(listOf("00906ED50000", 5)) }
        assertEquals("createIntelDcapVerifier: policy.fmspcs must list only strings", mixed.message)
    }

    @Test fun malformedAllowlistsAndFloorsRefuseTheConfig() {
        val g = Kill05IntelMeshKit.G()
        fun cfg(extra: Map<String, Any?>): Map<String, Any?> {
            val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)))
            pol.putAll(extra)
            return KUtil.m("binding" to "report-data", "policy" to pol)
        }
        val e = assertThrows(IllegalArgumentException::class.java) { AttestIntel.create(cfg(KUtil.m("rtmrs" to KUtil.l("AB".repeat(48), 5)))) }
        assertEquals("createIntelDcapVerifier: policy.rtmrs must list only strings", e.message)
        // through the verifier: a string floor still floors, and a mixed status list never falls back to the default statuses
        val c = g.collateral()
        val ev = KUtil.m("quote" to k.b64(g.quote()), "collateral" to KUtil.m(
            "tcbInfoJson" to c.tcbInfoJson, "tcbInfoIssuerChainPem" to c.tcbInfoChain, "qeIdentityJson" to c.qeIdentityJson,
            "qeIdentityIssuerChainPem" to c.qeIdentityChain, "pckCrlDer" to k.b64(c.pckCrl), "rootCrlDer" to k.b64(c.rootCrl)))
        fun withCollateral(col: Map<String, Any?>): Attest.Result {
            val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)), "collateral" to col)
            return AttestIntel.create(KUtil.m("binding" to "report-data", "trustAnchorRootCaSpkiSha256" to g.pin(), "policy" to pol)).verify(ev, Kill05GcpAmdKit.BINDING, now)
        }
        assertTrue(withCollateral(KUtil.m("minTcbEvaluationDataNumber" to "0")).ok)
        assertEquals("Intel collateral: tcbEvaluationDataNumber below policy minimum", withCollateral(KUtil.m("minTcbEvaluationDataNumber" to "1")).reason)
        assertFalse(withCollateral(KUtil.m("acceptStatuses" to KUtil.l("Revoked", 5))).ok)
        assertTrue(withCollateral(KUtil.m("acceptStatuses" to KUtil.l("UpToDate", 5))).ok)
        val floorMsg = "createIntelDcapVerifier: policy.collateral.minTcbEvaluationDataNumber must be a number"
        for (bad in listOf<Any?>("abc", true, KUtil.m())) {
            val f = assertThrows(IllegalArgumentException::class.java) { AttestIntel.create(cfg(KUtil.m("collateral" to KUtil.m("minTcbEvaluationDataNumber" to bad)))) }
            assertEquals(floorMsg, f.message)
        }
    }

    /** The signature covers the FIRST member: a later duplicate must leave the verdict equal to the honest one, for both documents. */
    @Test fun aLaterDuplicateMemberNeverReplacesTheSignedBody() {
        val forgedTcb = Kill05IntelMeshKit.G().tcbBody
        val g = Kill05IntelMeshKit.G()
        g.tcbBody = g.tcbBody.replace("\"UpToDate\"", "\"Revoked\"")
        val honest = g.run(null)
        assertFalse(honest.ok)
        fun dup(name: String, body: String, later: String) =
            g.doc(name, body).replaceFirst(",\"signature\"", ",\"$name\":$later,\"signature\"")
        fun run(c: AttestIntel.Collateral) = AttestIntel.verifyTdxCollateral(g.quote(), c, Kill05GcpAmdKit.NOW, null, g.pin(), false)
        val base = g.collateral()
        val tcb = run(AttestIntel.Collateral(dup("tcbInfo", g.tcbBody, forgedTcb), base.tcbInfoChain, base.qeIdentityJson, base.qeIdentityChain, base.pckCrl, base.rootCrl))
        assertEquals(honest.reason, tcb.reason)
        assertEquals(honest.ok, tcb.ok)

        val q = Kill05IntelMeshKit.G()
        val forgedQe = q.qeBody
        q.qeBody = q.qeBody.replace("\"tcbStatus\":\"UpToDate\"", "\"tcbStatus\":\"Revoked\"")
        val honestQe = q.run(null)
        assertFalse(honestQe.ok)
        val qb = q.collateral()
        val qe = AttestIntel.verifyTdxCollateral(q.quote(), AttestIntel.Collateral(qb.tcbInfoJson, qb.tcbInfoChain,
            q.doc("enclaveIdentity", q.qeBody).replaceFirst(",\"signature\"", ",\"enclaveIdentity\":$forgedQe,\"signature\""),
            qb.qeIdentityChain, qb.pckCrl, qb.rootCrl), Kill05GcpAmdKit.NOW, null, q.pin(), false)
        assertEquals(honestQe.reason, qe.reason)
        assertEquals(honestQe.ok, qe.ok)
    }
}
