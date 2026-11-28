package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * AMD SEV-SNP helpers that need no AMD hardware and no certificate chain: the 1184-byte ATTESTATION_REPORT parser (little-endian), the ECDSA
 * P-384 / SHA-384 report signature over bytes [0, 0x2a0) (a high-S signature is accepted: AMD does not normalise), the VCEK certificate helpers
 * and the CHIP_ID / TCB binding, the acceptance policy gate, the default identity derivation and the KDS VCEK fetch over an injected transport.
 * The chain verifier and the genuine-report verifier are the vendor verifier of [Attest].
 */
@Suppress("UNCHECKED_CAST")
object SevSnp {
    const val SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384 = 1L

    /** The SPKI SHA-384 (lowercase hex) of the AMD Milan ARK. */
    const val AMD_MILAN_ARK_SPKI_SHA384 = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e"

    /** SEV-SNP guest POLICY bit 19: DEBUG (the host may read and modify guest memory: no confidentiality). */
    val SEV_SNP_POLICY_DEBUG_BIT: BigInteger = BigInteger.ONE.shiftLeft(19)

    private const val OFF_SIGNED_END = 0x2a0
    private const val OFF_SIG_R = 0x2a0
    private const val OFF_SIG_S = 0x2e8

    private fun u64(bb: java.nio.ByteBuffer, off: Int): BigInteger = BigInteger(java.lang.Long.toUnsignedString(bb.getLong(off)))

    /** Lowercase hex of a byte array (the identity string of a measurement, chip id or host data). */
    @JvmStatic fun toHex(bytes: ByteArray): String = AttestUtil.hex(bytes)

    /** A firmware version as AMD defines it: major.minor build N. */
    class FirmwareVersion(val major: Int, val minor: Int, val build: Int)

    /** A fully parsed `ATTESTATION_REPORT`. Byte-array fields are fresh copies. */
    class Report internal constructor(
        val version: Long, val guestSvn: Long, val policy: BigInteger, val familyId: ByteArray, val imageId: ByteArray, val vmpl: Long,
        val signatureAlgo: Long, val currentTcb: BigInteger, val platformInfo: BigInteger, val reportData: ByteArray, val measurement: ByteArray,
        val hostData: ByteArray, val idKeyDigest: ByteArray, val authorKeyDigest: ByteArray, val reportId: ByteArray, val reportIdMa: ByteArray,
        val reportedTcb: BigInteger, val cpuidFamId: Int, val cpuidModId: Int, val cpuidStep: Int, val chipId: ByteArray, val committedTcb: BigInteger,
        val currentVersion: FirmwareVersion, val committedVersion: FirmwareVersion, val launchTcb: BigInteger, val launchMitVector: BigInteger,
        val currentMitVector: BigInteger,
        /** AMD's little-endian r and s, each a 72-byte field exactly as it sits in the report. */
        val signatureR: ByteArray, val signatureS: ByteArray,
        /** The signed region, report bytes [0x000, 0x2A0). The ECDSA signature is over SHA-384 of this. */
        val signed: ByteArray,
        /** The full report bytes (a copy). */
        val raw: ByteArray,
    )

    /** Parse the report layout. Throws on a buffer too short to hold the signed region and the r / s fields. Verifies nothing. */
    @JvmStatic fun parseSevSnpReport(b: ByteArray): Report {
        val minLen = OFF_SIG_S + 72
        if (b.size < minLen) throw IllegalArgumentException("parseSevSnpReport: report too short (${b.size} < $minLen)")
        val bb = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        fun u32(off: Int): Long = bb.getInt(off).toLong() and 0xffffffffL
        fun u8(off: Int): Int = b[off].toInt() and 0xff
        fun slice(off: Int, len: Int): ByteArray = b.copyOfRange(off, off + len)
        return Report(
            u32(0x000), u32(0x004), u64(bb, 0x008), slice(0x010, 16), slice(0x020, 16), u32(0x030), u32(0x034), u64(bb, 0x038), u64(bb, 0x040),
            slice(0x050, 64), slice(0x090, 48), slice(0x0c0, 32), slice(0x0e0, 48), slice(0x110, 48), slice(0x140, 32), slice(0x160, 32),
            u64(bb, 0x180), u8(0x188), u8(0x189), u8(0x18a), slice(0x1a0, 64), u64(bb, 0x1e0),
            FirmwareVersion(u8(0x1ea), u8(0x1e9), u8(0x1e8)), FirmwareVersion(u8(0x1ee), u8(0x1ed), u8(0x1ec)), u64(bb, 0x1f0), u64(bb, 0x1f8), u64(bb, 0x200),
            slice(OFF_SIG_R, 72), slice(OFF_SIG_S, 72), slice(0, OFF_SIGNED_END), b.copyOf(),
        )
    }

    private val P384_ORDER: BigInteger by lazy { AttestUtil.curveParams("secp384r1")!!.order }

    /** A validated P-384 public key, carried as its uncompressed SEC1 point (`0x04 || X(48) || Y(48)`, 97 bytes). */
    class EcdsaP384PublicKey internal constructor(val point: ByteArray, internal val key: ECPublicKey)

    /**
     * Wrap and validate a P-384 public key. Accepts the uncompressed (97-byte, prefix 04) or compressed (49-byte, prefix 02 or 03) SEC1 encoding and
     * normalizes to uncompressed. Throws if the bytes are not a valid curve point.
     */
    @JvmStatic fun ecdsaP384PublicKey(sec1: ByteArray): EcdsaP384PublicKey {
        val okShape = (sec1.size == 97 && sec1[0].toInt() == 4) || (sec1.size == 49 && (sec1[0].toInt() == 2 || sec1[0].toInt() == 3))
        if (!okShape) throw IllegalArgumentException("ecdsaP384PublicKey: not a SEC1 P-384 point")
        val curve = org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-384").curve
        val pt = try {
            curve.decodePoint(sec1)
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("ecdsaP384PublicKey: not a point on the curve")
        }
        if (pt.isInfinity || !pt.isValid) throw IllegalArgumentException("ecdsaP384PublicKey: not a point on the curve")
        val point = pt.getEncoded(false)
        val key = AttestUtil.pointToKey("secp384r1", point) ?: throw IllegalArgumentException("ecdsaP384PublicKey: not a point on the curve")
        return EcdsaP384PublicKey(point, key)
    }

    /**
     * Convert AMD's little-endian r and s (72-byte fields; only the value matters) into the 96-byte big-endian compact form. Throws when r or s is
     * zero or not below the group order.
     */
    @JvmStatic fun sevSnpSignatureToCompact(r: ByteArray, s: ByteArray): ByteArray {
        val rr = AttestUtil.leToBig(r)
        val ss = AttestUtil.leToBig(s)
        if (rr.signum() <= 0 || rr >= P384_ORDER) throw IllegalArgumentException("sev-snp signature: r out of range")
        if (ss.signum() <= 0 || ss >= P384_ORDER) throw IllegalArgumentException("sev-snp signature: s out of range")
        val out = ByteArray(96)
        fun put(v: BigInteger, at: Int) {
            val be = v.toByteArray()
            val start = if (be.size > 48) be.size - 48 else 0
            System.arraycopy(be, start, out, at + 48 - (be.size - start), be.size - start)
        }
        put(rr, 0)
        put(ss, 48)
        return out
    }

    /** Verify the report's ECDSA-P384 / SHA-384 signature over its signed region under the VCEK public key. Never throws: a malformed signature is false. */
    @JvmStatic fun verifySevSnpReportSignature(report: Report, vcek: EcdsaP384PublicKey): Boolean = try {
        val compact = sevSnpSignatureToCompact(report.signatureR, report.signatureS)
        AttestUtil.ecdsaVerify(vcek.key, AttestUtil.sha384(report.signed), BigInteger(1, compact.copyOfRange(0, 48)), BigInteger(1, compact.copyOfRange(48, 96)))
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Bind the VCEK certificate body to the report: its hwID (CHIP_ID) extension must equal the report's chip_id and its four SPL extensions the
     * matching bytes of REPORTED_TCB (bootloader byte 0, TEE byte 1, SNP byte 6, microcode byte 7). Null = bound, else the reason.
     */
    @JvmStatic fun checkVcekReportBinding(vcekTbs: ByteArray, report: Report): String? =
        AttestAmd.checkVcekBinding(vcekTbs, report.chipId, report.reportedTcb.toLong()).ifEmpty { null }

    /** The `tbsCertificate` bytes (header included) of a DER certificate. Throws on a structurally invalid certificate or trailing bytes. */
    @JvmStatic fun extractTbsCertificate(certDer: ByteArray): ByteArray = try {
        AttestDer.tbsOfCertificate(certDer)
    } catch (e: AttErr) {
        throw IllegalArgumentException(e.message)
    }

    /** A VCEK certificate's P-384 key and its `tbsCertificate` bytes. */
    class Vcek internal constructor(val key: EcdsaP384PublicKey, val tbs: ByteArray)

    /** Decode a VCEK certificate (DER): its EC secp384r1 public key and its `tbsCertificate`. Throws unless the certificate parses and the key is secp384r1. */
    @JvmStatic fun extractVcekPublicKey(vcekDer: ByteArray): Vcek {
        val cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(java.io.ByteArrayInputStream(vcekDer))
        val pk = cert.publicKey as? ECPublicKey ?: throw IllegalArgumentException("VCEK is not EC secp384r1 (got ${cert.publicKey.algorithm})")
        if (pk.params.order != P384_ORDER) throw IllegalArgumentException("VCEK is not EC secp384r1")
        fun fixed(v: BigInteger): ByteArray {
            val be = v.toByteArray()
            val out = ByteArray(48)
            val n = Math.min(be.size, 48)
            System.arraycopy(be, be.size - n, out, 48 - n, n)
            return out
        }
        val point = byteArrayOf(4) + fixed(pk.w.affineX) + fixed(pk.w.affineY)
        return Vcek(ecdsaP384PublicKey(point), extractTbsCertificate(vcekDer))
    }

    private val PEM_CERT = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")

    /** Split a PEM bundle into its individual certificate blocks (text unchanged). */
    @JvmStatic fun splitPemCertificates(pem: String): List<String> = PEM_CERT.findAll(pem).map { it.value }.toList()

    /** A transport answer: the HTTP status and the body. */
    class KdsResponse(val status: Int, val body: ByteArray)

    /**
     * Fetch the VCEK certificate (DER) for a report over the injected [fetch] transport:
     * `<baseUrl>/<product>/<chip id hex>?blSPL=&teeSPL=&snpSPL=&ucodeSPL=` from the raw REPORTED_TCB u64 (bootloader byte 0, TEE byte 1, SNP byte 6,
     * microcode byte 7). `product` defaults to Milan, `baseUrl` to the AMD KDS. Throws on a non-2xx status and when no transport is given.
     */
    @JvmStatic @JvmOverloads
    fun fetchVcekFromKds(chipId: ByteArray, reportedTcb: BigInteger, product: String? = null, baseUrl: String? = null, fetch: ((String) -> KdsResponse)? = null): ByteArray {
        val prod = product ?: "Milan"
        val base = baseUrl ?: "https://kdsintf.amd.com/vcek/v1"
        val f = fetch ?: throw IllegalStateException("fetchVcekFromKds: no fetch implementation available")
        fun byteAt(i: Int): Int = reportedTcb.shiftRight(8 * i).and(BigInteger.valueOf(0xff)).toInt()
        val url = "$base/$prod/${toHex(chipId)}?blSPL=${byteAt(0)}&teeSPL=${byteAt(1)}&snpSPL=${byteAt(6)}&ucodeSPL=${byteAt(7)}"
        val res = f(url)
        if (res.status < 200 || res.status > 299) throw IllegalStateException("KDS VCEK fetch failed: HTTP ${res.status} for $url")
        return res.body
    }

    /**
     * The default report to measured-identity mapping: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID), model_id empty, weights_digest
     * empty (or the host-asserted HOST_DATA under the INSECURE `weightsFromHostData`); `weights_measured` is ALWAYS false.
     */
    @JvmStatic fun makeDefaultDeriveIdentity(weightsFromHostData: Boolean): (Report) -> Map<String, Any?> = { r ->
        linkedMapOf(
            "model_id" to "", "weights_digest" to (if (weightsFromHostData) toHex(r.hostData) else ""), "weights_measured" to false,
            "runtime_measurement" to toHex(r.measurement), "operator" to toHex(r.chipId),
        )
    }

    private fun lowered(list: Any?): List<String> = (list as List<*>).map { x -> (x as? String ?: throw IllegalArgumentException("x.toLowerCase is not a function")).lowercase() }

    /**
     * Check the report against the acceptance policy (a decoded JSON object; the minima are [BigInteger]s, as the reference's bigint gates are
     * not JSON numbers). The reason of the first failing gate, else null. Gates in order: signature algorithm (unless `requireEcdsaP384` is false),
     * the DEBUG bit (unless `allowDebug` is true), `minGuestSvn`, `minReportedTcb`, `minCommittedTcb`, `minLaunchTcb`, VMPL (`requireVmpl`, default 0, or
     * "any"), then the measurement, host data and chip id allowlists (lowercase hex; an empty or absent list gates nothing).
     */
    @JvmStatic fun checkSevSnpPolicy(report: Report, policy: Map<String, Any?>?): String? {
        if (policy == null) throw IllegalArgumentException("Cannot read properties of null (reading 'requireEcdsaP384')")
        if (policy["requireEcdsaP384"] != false && report.signatureAlgo != SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384) return "unexpected signature_algo ${report.signatureAlgo}"
        if (policy["allowDebug"] != true && report.policy.and(SEV_SNP_POLICY_DEBUG_BIT).signum() != 0) return "guest policy has the DEBUG bit set (host can inspect the guest)"
        val svn = IntentJs.num(policy["minGuestSvn"])
        if (svn != null && report.guestSvn.toDouble() < svn) return "guest_svn ${report.guestSvn} below minimum ${AttestUtil.jsNumString(svn)}"
        val minR = policy["minReportedTcb"]
        if (minR is BigInteger && report.reportedTcb < minR) return "reported_tcb below minimum (rollback?)"
        val minC = policy["minCommittedTcb"]
        if (minC is BigInteger && report.committedTcb < minC) return "committed_tcb below minimum (rollback?)"
        val minL = policy["minLaunchTcb"]
        if (minL is BigInteger && report.launchTcb < minL) return "launch_tcb below minimum"
        val want: Any? = policy["requireVmpl"] ?: 0L
        if (want != "any") {
            val w = if (want is String || want is Boolean) null else IntentJs.num(want)
            if (w == null || report.vmpl.toDouble() != w) return "vmpl ${report.vmpl} is not the required ${ZkJs.string(want)}"
        }
        val ms = policy["measurements"]
        if (ms is List<*> && ms.isNotEmpty() && toHex(report.measurement) !in lowered(ms)) return "measurement not in policy allowlist"
        val hs = policy["hostData"]
        if (hs is List<*> && hs.isNotEmpty() && toHex(report.hostData) !in lowered(hs)) return "host_data not in policy allowlist"
        val cs = policy["chipIds"]
        if (cs is List<*> && cs.isNotEmpty() && toHex(report.chipId) !in lowered(cs)) return "chip_id not in policy allowlist"
        return null
    }
}
