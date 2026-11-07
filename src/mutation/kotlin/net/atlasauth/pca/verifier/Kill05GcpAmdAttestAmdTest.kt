package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** DER / certificate / signature builders shared by the Kill05GcpAmd* tests (every key is generated at run time). */
internal object Kill05GcpAmdKit {
    const val NOW = 1_800_000_000_000L // 2027-01-15
    const val NB = "250101000000Z"
    const val NA = "350101000000Z"
    const val NB_MS = 1_735_689_600_000L // 2025-01-01T00:00:00Z
    const val NA_MS = 2_051_222_400_000L // 2035-01-01T00:00:00Z
    val BINDING = Attest.Binding("holder-key", "passport:abc", 0.0, "nonce-1")

    fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p, 0, p.size)
        return o.toByteArray()
    }

    private fun hdr(tag: Int, n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(tag.toByte(), n.toByte())
        n < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), n.toByte())
        else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }

    fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = cat(*parts)
        return cat(hdr(tag, body.size), body)
    }

    fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, *parts)

    fun oid(dotted: String): ByteArray {
        val a = dotted.split(".")
        val o = ByteArrayOutputStream()
        o.write(a[0].toInt() * 40 + a[1].toInt())
        for (i in 2 until a.size) {
            val v = a[i].toLong()
            var n = 1
            while ((v shr (7 * n)) != 0L) n++
            for (k in n - 1 downTo 0) o.write(((v shr (7 * k)) and 0x7f).toInt() or (if (k > 0) 0x80 else 0))
        }
        return tlv(0x06, o.toByteArray())
    }

    fun integer(v: Long): ByteArray = tlv(0x02, BigInteger.valueOf(v).toByteArray())
    fun bool(v: Boolean): ByteArray = byteArrayOf(0x01, 0x01, if (v) 0xff.toByte() else 0x00)
    fun bits(unused: Int, b: ByteArray): ByteArray = tlv(0x03, byteArrayOf(unused.toByte()), b)
    fun bytes(vararg v: Int): ByteArray = ByteArray(v.size) { v[it].toByte() }
    private fun name(cn: String): ByteArray = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, cn.toByteArray(Charsets.UTF_8)))))

    fun ext(id: String, critical: Boolean, value: ByteArray): ByteArray =
        if (critical) seq(oid(id), bool(true), tlv(0x04, value)) else seq(oid(id), tlv(0x04, value))

    fun basicConstraints(ca: Boolean, pathLen: Int): ByteArray =
        ext("2.5.29.19", true, seq(if (ca) bool(true) else ByteArray(0), if (pathLen >= 0) integer(pathLen.toLong()) else ByteArray(0)))

    /** keyUsage with only keyCertSign (bit 5). */
    fun keyUsageCertSign(): ByteArray = ext("2.5.29.15", true, bits(2, bytes(0x04)))

    private val SIG_ALG = seq(oid("1.2.840.10045.4.3.2")) // ecdsa-with-SHA256

    /** A tbsCertificate-shaped SEQUENCE with a serial and one [3] extensions block (all the extension reader needs). */
    fun roleTbs(vararg exts: ByteArray): ByteArray = seq(integer(1), tlv(0xa3, seq(*exts)))

    fun ecKey(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    fun rsaKey(): KeyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair()

    /** A certificate carrying the SubjectPublicKeyInfo `spki`, signed by `signer` (ECDSA / SHA-256). */
    fun certSpki(subjectCn: String, issuerCn: String, notBefore: String, notAfter: String, spki: ByteArray, signer: KeyPair, vararg exts: ByteArray): ByteArray {
        val e = if (exts.isEmpty()) ByteArray(0) else tlv(0xa3, seq(*exts))
        val validity = seq(tlv(0x17, notBefore.toByteArray(Charsets.US_ASCII)), tlv(0x17, notAfter.toByteArray(Charsets.US_ASCII)))
        val tbs = seq(tlv(0xa0, integer(2)), integer(258), SIG_ALG, name(issuerCn), validity, name(subjectCn), spki, e)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(signer.private)
        s.update(tbs)
        return seq(tbs, SIG_ALG, bits(0, s.sign()))
    }

    fun cert(subjectCn: String, issuerCn: String, subject: KeyPair, signer: KeyPair, vararg exts: ByteArray): ByteArray =
        certSpki(subjectCn, issuerCn, NB, NA, subject.public.encoded, signer, *exts)

    /**
     * The strict chain profile (x509-strict.ts strictChainError) over leaf-first chains under `root`: name, chain, the failure reason
     * ("" when it passes). The chain stops below the root, so a caller can put the root on top or leave it off.
     */
    fun profileTable(leafKey: KeyPair, root: KeyPair): List<Triple<String, List<ByteArray>, String>> {
        val mid = ecKey("secp256r1")
        val up = ecKey("secp256r1")
        val ca = basicConstraints(true, -1)
        val unknown = ext("1.2.3.4", true, ByteArray(0))
        val eku = ext("2.5.29.37", true, seq(oid("1.3.6.1.5.5.7.3.1")))
        val signOnly = ext("2.5.29.15", true, bits(7, bytes(0x80)))
        fun chain(leaf: List<ByteArray>, vararg issuer: ByteArray) =
            listOf(cert("leaf", "mid", leafKey, mid, *leaf.toTypedArray()), cert("mid", "root", mid, root, *issuer))
        fun tall(pathLen: Int) =
            listOf(cert("leaf", "mid", leafKey, mid), cert("mid", "up", mid, up, ca), cert("up", "root", up, root, basicConstraints(true, pathLen)))
        return listOf(
            Triple("plain", chain(emptyList(), ca), ""),
            Triple("critical EKU on the leaf and the issuer", chain(listOf(eku), ca, eku), ""),
            Triple("issuer keyCertSign", chain(emptyList(), ca, keyUsageCertSign()), ""),
            Triple("pathLen exactly enough", tall(1), ""),
            Triple("leaf CA:TRUE", chain(listOf(ca), ca), "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"),
            Triple("issuer without BasicConstraints", chain(emptyList()), "issuer certificate at depth 1 has no BasicConstraints (not a CA)"),
            Triple("issuer CA:FALSE", chain(emptyList(), basicConstraints(false, -1)), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)"),
            Triple("issuer keyUsage without keyCertSign", chain(emptyList(), ca, signOnly), "issuer certificate at depth 1 keyUsage lacks keyCertSign"),
            Triple("pathLen exceeded", tall(0), "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"),
            Triple("unknown critical on the leaf", chain(listOf(unknown), ca), "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"),
            Triple("unknown critical on the issuer", chain(emptyList(), ca, unknown), "certificate at depth 1 has an unrecognised critical extension 1.2.3.4"),
        )
    }

    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    fun pem(der: ByteArray): String = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(der) + "\n-----END CERTIFICATE-----\n"

    /** A DER ECDSA-Sig-Value as raw big-endian r || s, each `n` bytes. */
    fun derToRaw(der: ByteArray, n: Int): ByteArray {
        var p = if ((der[1].toInt() and 0x80) != 0) 3 else 2
        val out = ByteArray(2 * n)
        for (k in 0 until 2) {
            val len = der[p + 1].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(p + 2, p + 2 + len)).toByteArray()
            val b = if (v.size > n) v.copyOfRange(v.size - n, v.size) else v
            System.arraycopy(b, 0, out, k * n + n - b.size, b.size)
            p += 2 + len
        }
        return out
    }

    fun signRaw(kp: KeyPair, alg: String, data: ByteArray, n: Int): ByteArray {
        val s = Signature.getInstance(alg)
        s.initSign(kp.private)
        s.update(data)
        return derToRaw(s.sign(), n)
    }

    fun putLe(b: ByteArray, off: Int, v: Long, n: Int) {
        for (i in 0 until n) b[off + i] = (v ushr (8 * i)).toByte()
    }

    fun assertDenied(name: String, r: Attest.Result, want: String) {
        assertFalse("$name: must be refused", r.ok)
        assertEquals(name, want, r.reason)
    }

    fun assertOk(name: String, r: Attest.Result) {
        assertEquals(name, "", r.reason)
        assertTrue(name, r.ok && r.bound)
    }
}

/** Exact outcomes for the AMD SEV-SNP verifier: SPL decoding, VCEK <-> report binding, the chain edges, policy floors, BigInt. */
@Suppress("UNCHECKED_CAST")
class Kill05GcpAmdAttestAmdTest {
    private val k = Kill05GcpAmdKit
    private val oidHwid = "1.3.6.1.4.1.3704.1.4"
    private val splOids = listOf("1.3.6.1.4.1.3704.1.3.1", "1.3.6.1.4.1.3704.1.3.2", "1.3.6.1.4.1.3704.1.3.3", "1.3.6.1.4.1.3704.1.3.8")
    private val splNames = listOf("bootloader", "tee", "snp", "microcode")
    private val splValues = listOf(1L, 2L, 10L, 11L) // reported_tcb 0x0b0a000000000201
    private val downgrade = " — TCB downgrade?"
    private val invalid = "SEV-SNP report invalid: "
    private val chainInvalid = "SEV-SNP report invalid: cert chain invalid: "

    /** A genuine report under a generated VCEK -> ASK -> ARK chain (the ARK pinned through the conformance override). */
    private inner class Snp {
        val ark = k.ecKey("secp384r1")
        val ask = k.ecKey("secp384r1")
        val vcek = k.ecKey("secp384r1")
        val chipId = ByteArray(64) { 0x5a.toByte() }
        val measurement = ByteArray(48) { 0x3c.toByte() }
        val hostData = ByteArray(32) { 0xab.toByte() }
        val reportedTcb = 0x0b0a000000000201L
        var committedTcb = 0L
        var launchTcb = 0L
        var vmpl = 0L

        fun pin(): String = AttestUtil.hex(AttestUtil.sha384(ark.public.encoded))

        fun vcekDer(notBefore: String = Kill05GcpAmdKit.NB, notAfter: String = Kill05GcpAmdKit.NA, subject: KeyPair = vcek): ByteArray =
            k.certSpki(
                "VCEK", "SEV-Milan", notBefore, notAfter, subject.public.encoded, ask,
                k.ext(oidHwid, false, chipId),
                k.ext(splOids[0], false, k.integer(splValues[0])), k.ext(splOids[1], false, k.integer(splValues[1])),
                k.ext(splOids[2], false, k.integer(splValues[2])), k.ext(splOids[3], false, k.integer(splValues[3])),
            )

        fun askArkPem(): String =
            k.pem(k.cert("SEV-Milan", "ARK-Milan", ask, ark, k.basicConstraints(true, 0), k.keyUsageCertSign())) +
                k.pem(k.cert("ARK-Milan", "ARK-Milan", ark, ark, k.basicConstraints(true, 1), k.keyUsageCertSign()))

        fun report(): ByteArray {
            val r = ByteArray(0x4a0)
            r[0] = 2
            k.putLe(r, 0x030, vmpl, 4)
            k.putLe(r, 0x034, 1, 4)
            Attest.bindingBytes(Kill05GcpAmdKit.BINDING).copyInto(r, 0x050)
            measurement.copyInto(r, 0x090)
            hostData.copyInto(r, 0x0c0)
            k.putLe(r, 0x180, reportedTcb, 8)
            chipId.copyInto(r, 0x1a0)
            k.putLe(r, 0x1e0, committedTcb, 8)
            k.putLe(r, 0x1f0, launchTcb, 8)
            val sig = k.signRaw(vcek, "SHA384withECDSA", r.copyOfRange(0, 0x2a0), 48)
            for (i in 0 until 48) {
                r[0x2a0 + i] = sig[47 - i]
                r[0x2e8 + i] = sig[95 - i]
            }
            return r
        }

        fun evidence(rep: ByteArray = report(), vcekBytes: ByteArray = vcekDer()): Map<String, Any?> =
            linkedMapOf("report" to k.b64(rep), "vcekDer" to k.b64(vcekBytes), "askArkPem" to askArkPem())

        fun config(extraPolicy: String = "", extraTop: String = ""): Map<String, Any?> = ParityVectors.obj(
            "{\"family\":\"milan\",\"binding\":\"report-data\",\"trustAnchorArkSpkiSha384\":\"${pin()}\"$extraTop," +
                "\"policy\":{\"measurements\":[\"${AttestUtil.hex(measurement)}\"]$extraPolicy}}",
        )

        fun run(cfg: Map<String, Any?> = config(), ev: Map<String, Any?>? = evidence(), now: Long = Kill05GcpAmdKit.NOW): Attest.Result =
            ParityVectors.harnessVerifier("amd-sev-snp", cfg).verify(ev, Kill05GcpAmdKit.BINDING, now)
    }

    // ---- decodeSpl ----

    @Test
    fun splWholeResult() {
        val rows = listOf(
            Pair(k.bytes(), Pair(0, "is not a DER INTEGER")),
            Pair(k.bytes(0x02, 0x01), Pair(0, "is not a DER INTEGER")),
            Pair(k.bytes(0x03, 0x01, 0x05), Pair(0, "is not a DER INTEGER")),
            Pair(k.bytes(0x02, 0x01, 0x05), Pair(5, "")),
            Pair(k.bytes(0x02, 0x01, 0x00), Pair(0, "")),
            Pair(k.bytes(0x02, 0x01, 0x7f), Pair(127, "")),
            Pair(k.bytes(0x02, 0x00, 0x00), Pair(0, "has a wrong-length INTEGER")),
            Pair(k.bytes(0x02, 0x03, 0x00, 0x00, 0x01), Pair(0, "has a wrong-length INTEGER")),
            Pair(k.bytes(0x02, 0x01, 0x05, 0x00), Pair(0, "has a wrong-length INTEGER")),
            Pair(k.bytes(0x02, 0x02, 0x05), Pair(0, "has a wrong-length INTEGER")),
            Pair(k.bytes(0x02, 0x01, 0x80), Pair(0, "is negative")),
            Pair(k.bytes(0x02, 0x02, 0xff, 0xff), Pair(0, "is negative")),
            Pair(k.bytes(0x02, 0x02, 0x01, 0x80), Pair(0, "is out of range (> 255)")),
            Pair(k.bytes(0x02, 0x02, 0x00, 0x7f), Pair(0, "is a non-minimal INTEGER")),
            Pair(k.bytes(0x02, 0x02, 0x00, 0x80), Pair(128, "")),
            Pair(k.bytes(0x02, 0x02, 0x00, 0xc8), Pair(200, "")),
            Pair(k.bytes(0x02, 0x02, 0x00, 0xff), Pair(255, "")),
        )
        for ((input, want) in rows) assertEquals(AttestUtil.hex(input), want, AttestAmd.decodeSpl(input))
    }

    // ---- the report layout ----

    private fun le(b: ByteArray, off: Int, n: Int): Long {
        var v = 0L
        for (i in n - 1 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    @Test
    fun reportParsesEveryField() {
        val b = ByteArray(0x4a0) { (it * 37 + 11).toByte() }
        val r = AttestAmd.parseReport(b)
        assertEquals(le(b, 0x004, 4), r.guestSvn)
        assertEquals(le(b, 0x008, 8), r.policy)
        assertEquals(le(b, 0x030, 4), r.vmpl)
        assertEquals(le(b, 0x034, 4), r.sigAlgo)
        assertEquals(le(b, 0x180, 8), r.reportedTcb)
        assertEquals(le(b, 0x1e0, 8), r.committedTcb)
        assertEquals(le(b, 0x1f0, 8), r.launchTcb)
        assertArrayEquals(b.copyOfRange(0x050, 0x090), r.reportData)
        assertArrayEquals(b.copyOfRange(0x090, 0x0c0), r.measurement)
        assertArrayEquals(b.copyOfRange(0x0c0, 0x0e0), r.hostData)
        assertArrayEquals(b.copyOfRange(0x1a0, 0x1e0), r.chipId)
        assertArrayEquals(b.copyOfRange(0, 0x2a0), r.signed)
        assertArrayEquals(b.copyOfRange(0x2a0, 0x2e8), r.sigR)
        assertArrayEquals(b.copyOfRange(0x2e8, 0x330), r.sigS)
        assertEquals(72, AttestAmd.parseReport(ByteArray(816)).sigS.size)
        try {
            AttestAmd.parseReport(ByteArray(815))
            fail("an 815-byte report must be refused")
        } catch (e: AttErr) {
            assertEquals("parseSevSnpReport: report too short (815 < 816)", e.message)
        }
    }

    // ---- VCEK <-> report binding (critical extensions never get past the chain check, so this is called directly) ----

    private fun bindRep(): AttestAmd.Report {
        val b = ByteArray(0x4a0)
        k.putLe(b, 0x180, 0x0b0a000000000201L, 8)
        for (i in 0 until 64) b[0x1a0 + i] = 0x5a
        return AttestAmd.parseReport(b)
    }

    private fun hw(len: Int): ByteArray = k.ext(oidHwid, false, ByteArray(len) { 0x5a.toByte() })

    /** The four good SPL extensions with index `at` replaced by `repl` (null: dropped). */
    private fun spls(at: Int, repl: ByteArray?): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        for (i in 0 until 4) {
            if (i != at) out.add(k.ext(splOids[i], false, k.integer(splValues[i])))
            else if (repl != null) out.add(repl)
        }
        return out
    }

    private fun bind(hwExt: ByteArray?, splExts: List<ByteArray>): String {
        val all = ArrayList<ByteArray>()
        if (hwExt != null) all.add(hwExt)
        all.addAll(splExts)
        return AttestAmd.checkVcekReportBinding(k.roleTbs(*all.toTypedArray()), bindRep())
    }

    @Test
    fun vcekBindingWholeResult() {
        assertEquals("", bind(hw(64), spls(-1, null)))
        assertEquals("VCEK extensions malformed: tbsCertificate is not a SEQUENCE", AttestAmd.checkVcekReportBinding(k.integer(1), bindRep()))
        assertEquals("VCEK certificate has no CHIP_ID (hwID) extension", bind(null, spls(-1, null)))
        val chip = ByteArray(64) { 0x5a.toByte() }
        assertEquals(
            "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)",
            bind(k.ext(oidHwid, true, chip), spls(-1, null)),
        )
        assertEquals("VCEK CHIP_ID (hwID) extension is 63 bytes, expected 64", bind(hw(63), spls(-1, null)))
        assertEquals("VCEK CHIP_ID (hwID) extension is 65 bytes, expected 64", bind(hw(65), spls(-1, null)))
        chip[63] = 0x5b
        assertEquals("VCEK CHIP_ID does not match report chip_id", bind(k.ext(oidHwid, false, chip), spls(-1, null)))
        for (i in 0 until 4) {
            val n = splNames[i]
            assertEquals(n, "VCEK certificate has no $n SPL extension", bind(hw(64), spls(i, null)))
            assertEquals(
                n, "VCEK $n SPL extension is marked critical (the AMD profile is non-critical)",
                bind(hw(64), spls(i, k.ext(splOids[i], true, k.integer(splValues[i])))),
            )
            assertEquals(n, "VCEK $n SPL extension is negative", bind(hw(64), spls(i, k.ext(splOids[i], false, k.integer(-1)))))
            assertEquals(n, "VCEK $n SPL extension is not a DER INTEGER", bind(hw(64), spls(i, k.ext(splOids[i], false, k.bytes(0x04, 0x01, 0x01)))))
            val got = splValues[i] + 1
            assertEquals(
                n, "VCEK $n SPL $got does not match report reported_tcb (${splValues[i]})$downgrade",
                bind(hw(64), spls(i, k.ext(splOids[i], false, k.integer(got)))),
            )
        }
    }

    // ---- the whole verifier over a generated chain ----

    @Test
    fun genuineReportAndIdentity() {
        val g = Snp()
        val r = g.run()
        k.assertOk("genuine", r)
        assertEquals(AttestUtil.hex(g.measurement), r.measured!!["runtime_measurement"])
        assertEquals(AttestUtil.hex(g.chipId), r.measured!!["operator"])
        assertEquals(
            mapOf("attestation_type" to "amd-sev-snp", "family" to "milan", "measurement" to AttestUtil.hex(g.measurement)),
            r.hostAsserted,
        )
        // the allowlists compare lowercase (create lowers them)
        k.assertOk("uppercase host_data / chip_id allowlists", g.run(g.config(",\"hostData\":[\"${"AB".repeat(32)}\"],\"chipIds\":[\"${"5A".repeat(64)}\"]")))
        k.assertDenied("host_data not allowed", g.run(g.config(",\"hostData\":[\"${"cd".repeat(32)}\"]")), invalid + "host_data not in policy allowlist")
        k.assertDenied("chip_id not allowed", g.run(g.config(",\"chipIds\":[\"${"cd".repeat(64)}\"]")), invalid + "chip_id not in policy allowlist")
        // production config never overrides the pin: only `family` sets it, and this generated ARK is not the real Milan ARK
        k.assertDenied("pin override in a production config", Attest.verifierFromConfig("amd-sev-snp", g.config()).verify(g.evidence(), Kill05GcpAmdKit.BINDING, Kill05GcpAmdKit.NOW), chainInvalid + "ARK does not match the pinned AMD trust anchor")
        // a malformed allowlist never means no list
        for (name in listOf("hostData", "chipIds")) {
            val e = assertThrows(IllegalArgumentException::class.java) { g.run(g.config(",\"$name\":[\"${"ab".repeat(32)}\",5]")) }
            assertEquals("createAmdSnpVerifier: policy.$name must list only strings", e.message)
        }
        k.assertOk("an allowlist that is no array is none", g.run(g.config(",\"hostData\":5")))
    }

    @Test
    fun evidenceShapes() {
        val g = Snp()
        val report = k.b64(g.report())
        val vcek = k.b64(g.vcekDer())
        val askArk = g.askArkPem()
        val none = "no AMD SEV-SNP evidence for this action"
        val num = Json.Num("1")
        val rows = listOf(
            Pair("no vcek", linkedMapOf<String, Any?>("report" to report, "askArkPem" to askArk)),
            Pair("vcek not a string", linkedMapOf<String, Any?>("report" to report, "vcekDer" to num, "askArkPem" to askArk)),
            Pair("chain not a string", linkedMapOf<String, Any?>("report" to report, "vcekDer" to vcek, "askArkPem" to num)),
            Pair("no chain", linkedMapOf<String, Any?>("report" to report, "vcekDer" to vcek)),
            Pair("report not a string", linkedMapOf<String, Any?>("report" to num, "vcekDer" to vcek, "askArkPem" to askArk)),
            Pair("no report", linkedMapOf<String, Any?>("vcekDer" to vcek, "askArkPem" to askArk)),
        )
        for ((name, ev) in rows) k.assertDenied(name, g.run(ev = ev), none)
        k.assertDenied("null evidence", g.run(ev = null), none)
        k.assertOk("all three present", g.run(ev = linkedMapOf("report" to report, "vcekDer" to vcek, "askArkPem" to askArk)))
    }

    @Test
    fun reservedSignatureBytes() {
        val g = Snp()
        val raw = g.report()
        for (off in listOf(0x2a0 + 48, 0x2a0 + 71, 0x2e8 + 48, 0x2e8 + 71, 816, 1183)) {
            val t = raw.clone()
            t[off] = 1
            k.assertDenied("offset $off", g.run(ev = g.evidence(rep = t)), invalid + "report signature block has non-zero reserved bytes")
        }
        k.assertOk("untouched", g.run(ev = g.evidence(rep = raw)))
    }

    @Test
    fun chainClockAndValidity() {
        val g = Snp()
        val ev = g.evidence()
        val badSkew = chainInvalid + "clockSkewMs must be a non-negative number"
        k.assertOk("skew 0", g.run(g.config(extraTop = ",\"clockSkewMs\":0"), ev))
        k.assertOk("skew 0.5", g.run(g.config(extraTop = ",\"clockSkewMs\":0.5"), ev))
        k.assertDenied("skew -1", g.run(g.config(extraTop = ",\"clockSkewMs\":-1"), ev), badSkew)
        k.assertDenied("skew -0.5", g.run(g.config(extraTop = ",\"clockSkewMs\":-0.5"), ev), badSkew)
        k.assertDenied("skew not a number", g.run(g.config(extraTop = ",\"clockSkewMs\":\"x\""), ev), badSkew)
        val expired = chainInvalid + "VCEK certificate has expired"
        val early = chainInvalid + "VCEK certificate is not yet valid"
        fun skew(ms: Int) = g.config(extraTop = ",\"clockSkewMs\":$ms")
        k.assertOk("at notAfter", g.run(ev = ev, now = Kill05GcpAmdKit.NA_MS))
        k.assertDenied("past notAfter", g.run(ev = ev, now = Kill05GcpAmdKit.NA_MS + 1000), expired)
        k.assertOk("past notAfter within skew", g.run(skew(2000), ev, Kill05GcpAmdKit.NA_MS + 1000))
        k.assertDenied("past notAfter beyond skew", g.run(skew(500), ev, Kill05GcpAmdKit.NA_MS + 1000), expired)
        k.assertOk("before notAfter, large skew", g.run(skew(5000), ev, Kill05GcpAmdKit.NA_MS - 1000))
        k.assertOk("at notBefore", g.run(ev = ev, now = Kill05GcpAmdKit.NB_MS))
        k.assertDenied("before notBefore", g.run(ev = ev, now = Kill05GcpAmdKit.NB_MS - 1000), early)
        k.assertOk("before notBefore within skew", g.run(skew(5000), ev, Kill05GcpAmdKit.NB_MS - 1000))
        k.assertOk("after notBefore, large skew", g.run(skew(5000), ev, Kill05GcpAmdKit.NB_MS + 1000))
        val unparseable = chainInvalid + "VCEK certificate validity is unparseable"
        k.assertDenied("notBefore month 13", g.run(ev = g.evidence(vcekBytes = g.vcekDer(notBefore = "251301000000Z"))), unparseable)
        k.assertDenied("notAfter month 13", g.run(ev = g.evidence(vcekBytes = g.vcekDer(notAfter = "351301000000Z"))), unparseable)
    }

    @Test
    fun vcekKeyMustBeP384() {
        val g = Snp()
        val pre = chainInvalid + "AMD chain verification error: VCEK is not EC secp384r1 "
        k.assertDenied("RSA VCEK", g.run(ev = g.evidence(vcekBytes = g.vcekDer(subject = k.rsaKey()))), pre + "(got rsa/undefined)")
        k.assertDenied("P-256 VCEK", g.run(ev = g.evidence(vcekBytes = g.vcekDer(subject = k.ecKey("secp256r1")))), pre + "(got ec/prime256v1)")
    }

    @Test
    fun tcbFloorsAndVmpl() {
        val g = Snp()
        g.committedTcb = 5
        g.launchTcb = 7
        val floors = ",\"minCommittedTcb\":\"5\",\"minLaunchTcb\":\"7\",\"minReportedTcb\":\"${0x0b0a000000000201L}\""
        k.assertOk("every TCB at its floor", g.run(g.config(floors)))
        k.assertDenied("launch floor above", g.run(g.config(",\"minLaunchTcb\":\"8\"")), invalid + "launch_tcb below minimum")
        k.assertDenied("committed floor above", g.run(g.config(",\"minCommittedTcb\":\"6\"")), invalid + "committed_tcb below minimum (rollback?)")
        g.committedTcb = 4
        k.assertDenied("committed below", g.run(g.config(floors)), invalid + "committed_tcb below minimum (rollback?)")
        g.committedTcb = -1L // u64 max
        k.assertOk("committed u64 max", g.run(g.config(",\"minCommittedTcb\":\"18446744073709551615\"")))
        // requireVmpl: JSON null means the default 0, like an absent key
        g.committedTcb = 0
        k.assertOk("requireVmpl null, vmpl 0", g.run(g.config(",\"requireVmpl\":null")))
        g.vmpl = 1
        k.assertDenied("requireVmpl null, vmpl 1", g.run(g.config(",\"requireVmpl\":null")), invalid + "vmpl 1 is not the required 0")
        k.assertOk("requireVmpl 1", g.run(g.config(",\"requireVmpl\":1")))
        k.assertOk("requireVmpl any", g.run(g.config(",\"requireVmpl\":\"any\"")))
    }

    @Test
    fun constructionRefusals() {
        val m = "{\"measurements\":[\"aa\"]}"
        val rows = listOf(
            Pair("{\"family\":5,\"binding\":\"report-data\",\"policy\":$m}", "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"),
            Pair("{\"family\":\"milan\",\"binding\":5,\"policy\":$m}", "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"),
            Pair("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"],\"minLaunchTcb\":null}}", "Cannot convert null to a BigInt"),
            Pair("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"],\"minCommittedTcb\":1.5}}", "The number 1.5 cannot be converted to a BigInt because it is not an integer"),
        )
        for ((c, want) in rows) {
            try {
                Attest.verifierFromConfig("amd-sev-snp", ParityVectors.obj(c))
                fail("$c must be refused")
            } catch (e: IllegalArgumentException) {
                assertEquals(c, want, e.message)
            }
        }
        assertNotNull(Attest.verifierFromConfig("amd-sev-snp", ParityVectors.obj("{\"family\":\"turin\",\"binding\":\"azure-runtime-data\",\"policy\":{\"measurements\":[\"aa\"],\"minReportedTcb\":5}}")))
    }

    // ---- BigInt(v) ----

    private fun bigErr(v: Any?): String? = try {
        AttestAmd.parseJsBigInt(v)
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun jsBigIntWholeResult() {
        assertEquals(BigInteger.ZERO, AttestAmd.parseJsBigInt(false))
        assertEquals(BigInteger.ONE, AttestAmd.parseJsBigInt(true))
        val good = listOf(
            "0" to "0", "00" to "0", "9" to "9", "5" to "5", "+5" to "5", "-7" to "-7", "07" to "7", "1234567890" to "1234567890",
            "0x1" to "1", "0x1f" to "31", "0X1F" to "31", "0x1F" to "31", "0xA" to "10", "0xa" to "10", "0xf" to "15", "0xF" to "15",
            "0x09" to "9", "0o10" to "8", "0O10" to "8", "0o7" to "7", "0b10" to "2", "0B10" to "2", "0b1" to "1", " 0x10 " to "16",
            "" to "0", "  " to "0", "18446744073709551615" to "18446744073709551615",
        )
        for ((s, want) in good) assertEquals("'$s'", BigInteger(want), AttestAmd.parseJsBigInt(s))
        val bad = listOf(
            "+", "-", "1a", "1x5", "0x", "0X", "0o", "0b", "0xg", "0xG", "0b2", "0o8", "/", ":", "+-5", "0x+1", "0x-1", "0o+7", "0b-1",
            "-0x5", "1 2", "a", "١٢", "１", "0x１",
        )
        for (s in bad) assertEquals("'$s'", "Cannot convert $s to a BigInt", bigErr(s))
        assertEquals("The number 1e999 cannot be converted to a BigInt because it is not an integer", bigErr(Json.Num("1e999")))
        assertEquals("The number 1.5 cannot be converted to a BigInt because it is not an integer", bigErr(Json.Num("1.5")))
        assertEquals(BigInteger.valueOf(100), AttestAmd.parseJsBigInt(Json.Num("1e2")))
        assertEquals(BigInteger.valueOf(5), AttestAmd.parseJsBigInt(Json.Num("5")))
        // a JSON number is a double: BigInt(9007199254740993) in the reference is 9007199254740992n
        assertEquals(BigInteger("9007199254740992"), AttestAmd.parseJsBigInt(Json.Num("9007199254740993")))
        assertEquals("Cannot convert null to a BigInt", bigErr(null))
        assertEquals("Cannot convert value to a BigInt", bigErr(ArrayList<Any?>()))
        assertEquals("Cannot convert value to a BigInt", bigErr(5.0))
    }
}
