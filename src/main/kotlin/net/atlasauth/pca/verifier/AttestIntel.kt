package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.LocalDate
import java.time.OffsetDateTime

/**
 * Intel TDX (DCAP v4, ECDSA-P256): the genuine quote end to end (PCK chain to the pinned Intel SGX Root CA, QE report under the
 * PCK leaf, attestation key endorsed by the QE, TD quote signature), the PCA binding in its two modes, and the optional Intel PCS
 * collateral (signed TCB info and QE identity, the PCK and Root CA CRLs, the evaluated TCB status and a status policy). Offline
 * given the collateral bytes; fails closed on missing, stale, malformed, unsigned or revoked collateral. Same checks, order and
 * reason text as the reference verifier. The CRL reader is shared with the NVIDIA CRL checks.
 */
internal object AttestIntel {
    /** Pins Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex). */
    const val SGX_ROOT_CA_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"

    private const val HEADER_LEN = 48
    private const val TD_REPORT_LEN = 584
    private const val SGX_REPORT = 384
    private const val QE_ATTR_OFF = 48
    private const val QE_RDATA_OFF = 0x140

    private fun bkey(b: ByteArray): String = String(b, Charsets.ISO_8859_1)

    class Quote(
        val header: ByteArray, val tdReportBody: ByteArray, val quoteSignature: ByteArray, val akPubRaw: ByteArray,
        val qeReportBody: ByteArray, val qeReportSignature: ByteArray, val qeAuthData: ByteArray, val pckChainPem: String,
    )

    fun parseQuote(q: ByteArray): Quote {
        if (q.size < HEADER_LEN + TD_REPORT_LEN + 4) throw AttErr("parseDcapQuote: too short for header + TD report + sig length")
        val le = ByteBuffer.wrap(q).order(ByteOrder.LITTLE_ENDIAN)
        val version = le.getShort(0).toInt() and 0xffff
        val attKeyType = le.getShort(2).toInt() and 0xffff
        val teeType = le.getInt(4).toLong() and 0xffffffffL
        if (version != 4) throw AttErr("parseDcapQuote: unsupported quote version $version (expected 4)")
        if (attKeyType != 2) throw AttErr("parseDcapQuote: unsupported attestation key type $attKeyType (expected ECDSA-P256 = 2)")
        if (teeType != 0x81L) throw AttErr("parseDcapQuote: unexpected TEE type 0x${java.lang.Long.toHexString(teeType)} (expected TDX = 0x81)")
        val header = q.copyOfRange(0, HEADER_LEN)
        val tdBody = q.copyOfRange(HEADER_LEN, HEADER_LEN + TD_REPORT_LEN)
        var o = HEADER_LEN + TD_REPORT_LEN
        val sigDataLen = le.getInt(o).toLong() and 0xffffffffL
        o += 4
        val sigEndL = o.toLong() + sigDataLen
        if (sigEndL > q.size) throw AttErr("parseDcapQuote: signature data ($sigDataLen) overruns the quote")
        val sigEnd = sigEndL.toInt()
        fun need(n: Int, what: String) {
            if (o + n > sigEnd) throw AttErr("parseDcapQuote: truncated reading $what")
        }
        need(64, "quote signature")
        val quoteSignature = q.copyOfRange(o, o + 64)
        o += 64
        need(64, "attestation public key")
        val akPubRaw = q.copyOfRange(o, o + 64)
        o += 64
        need(6, "outer cert-data header")
        val outerType = le.getShort(o).toInt() and 0xffff
        val outerSize = le.getInt(o + 2).toLong() and 0xffffffffL
        o += 6
        if (outerType != 6) throw AttErr("parseDcapQuote: outer cert-data type $outerType (expected QE-report-cert-data = 6)")
        val outerEndL = o.toLong() + outerSize
        if (outerEndL > sigEnd) throw AttErr("parseDcapQuote: outer cert-data overruns signature data")
        val outerEnd = outerEndL.toInt()
        need(SGX_REPORT, "QE report")
        val qeReportBody = q.copyOfRange(o, o + SGX_REPORT)
        o += SGX_REPORT
        need(64, "QE report signature")
        val qeReportSignature = q.copyOfRange(o, o + 64)
        o += 64
        need(2, "QE auth-data size")
        val authSize = le.getShort(o).toInt() and 0xffff
        o += 2
        need(authSize, "QE auth-data")
        val qeAuthData = q.copyOfRange(o, o + authSize)
        o += authSize
        need(6, "inner cert-data header")
        val innerType = le.getShort(o).toInt() and 0xffff
        val innerSize = le.getInt(o + 2).toLong() and 0xffffffffL
        o += 6
        if (innerType != 5) throw AttErr("parseDcapQuote: inner cert-data type $innerType (expected PCK-cert-chain = 5)")
        if (o.toLong() + innerSize > outerEnd) throw AttErr("parseDcapQuote: inner cert-data overruns outer cert-data")
        val pem = String(q, o, innerSize.toInt(), Charsets.ISO_8859_1)
        for (i in sigEnd until q.size) if (q[i].toInt() != 0) throw AttErr("parseDcapQuote: non-zero bytes after the signature data")
        return Quote(header, tdBody, quoteSignature, akPubRaw, qeReportBody, qeReportSignature, qeAuthData, pem)
    }

    // ---- the Intel SGX extension (byte scan, as the reference does) ----

    private val OID_SGX_FMSPC = byteArrayOf(0x06, 0x0a, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf8.toByte(), 0x4d, 0x01, 0x0d, 0x01, 0x04)
    private val OID_SGX_TCB = byteArrayOf(0x06, 0x0a, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf8.toByte(), 0x4d, 0x01, 0x0d, 0x01, 0x02)

    /** One TLV at `off`; null on any malformed or overrunning length. */
    private fun readTlvLenient(buf: ByteArray, off: Int): AttestDer.Tlv? {
        if (off < 0 || off + 2 > buf.size) return null
        val tag = buf[off].toInt() and 0xff
        var l = buf[off + 1].toInt() and 0xff
        var p = off + 2
        if ((l and 0x80) != 0) {
            val n = l and 0x7f
            if (n == 0 || n > 4 || p + n > buf.size) return null
            l = 0
            for (i in 0 until n) {
                l = l * 256 + (buf[p].toInt() and 0xff)
                p++
            }
        }
        val end = p + l
        if (end > buf.size || end < p) return null
        return AttestDer.Tlv(tag, p, end)
    }

    private fun indexOfBytes(hay: ByteArray, needle: ByteArray): Int {
        var i = 0
        while (i + needle.size <= hay.size) {
            var match = true
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) { match = false; break }
            }
            if (match) return i
            i++
        }
        return -1
    }

    class PckTcb(val fmspc: ByteArray, val sgx: ByteArray, val pcesvn: Int)

    /** The FMSPC and the issued TCB from the PCK leaf's Intel SGX extension. */
    fun extractPckFmspcAndTcb(leaf: ByteArray): PckTcb {
        val fi = indexOfBytes(leaf, OID_SGX_FMSPC)
        if (fi < 0) throw AttErr("extractPckFmspcAndTcb: FMSPC OID not found in certificate")
        val fv = readTlvLenient(leaf, fi + OID_SGX_FMSPC.size)
        if (fv == null || fv.tag != 0x04 || fv.end - fv.start != 6) throw AttErr("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING")
        val fmspc = leaf.copyOfRange(fv.start, fv.end)
        val ti = indexOfBytes(leaf, OID_SGX_TCB)
        if (ti < 0) throw AttErr("extractPckFmspcAndTcb: TCB OID not found in certificate")
        val seq = readTlvLenient(leaf, ti + OID_SGX_TCB.size)
        if (seq == null || seq.tag != 0x30) throw AttErr("extractPckFmspcAndTcb: malformed TCB SEQUENCE")
        val sgx = ByteArray(16)
        var pcesvn = -1
        var p = seq.start
        var idx = 0
        while (p < seq.end) {
            val pair = readTlvLenient(leaf, p)
            if (pair == null || pair.tag != 0x30) throw AttErr("extractPckFmspcAndTcb: malformed TCB component")
            val oid = readTlvLenient(leaf, pair.start)
            if (oid == null || oid.tag != 0x06) throw AttErr("extractPckFmspcAndTcb: TCB component missing OID")
            val v = readTlvLenient(leaf, oid.end) ?: throw AttErr("extractPckFmspcAndTcb: TCB component missing value")
            val last = leaf[oid.end - 1].toInt() and 0xff
            if (v.tag == 0x02) {
                var n = 0L
                for (b in v.start until v.end) n = ((n shl 8) or (leaf[b].toLong() and 0xff)) and 0xffffffffL
                if (last in 1..16) sgx[last - 1] = (n and 0xff).toByte()
                else if (last == 17) pcesvn = (n and 0xffff).toInt()
            }
            p = pair.end
            idx++
            if (idx > 64) break
        }
        if (pcesvn < 0) throw AttErr("extractPckFmspcAndTcb: PCESVN not found in TCB extension")
        return PckTcb(fmspc, sgx, pcesvn)
    }

    // ---- PCK chain ----

    class PckChain(
        val ok: Boolean, val reason: String, val validity: Boolean = false,
        val leaf: AttestCert.Cert? = null, val leafKey: ECPublicKey? = null, val depth: Int = 0,
    )

    /**
     * Verifies a PEM chain to the pinned Intel SGX Root CA (every certificate valid at `nowMs`, every link signed, the root
     * self-signed and pinned, CA roles, no unrecognised critical extension, an EC P-256 leaf).
     */
    fun verifyPckChain(pckChainPem: String, pin: String, nowMs: Long): PckChain {
        fun fail(r: String) = PckChain(false, r)
        return try {
            val blocks = AttestCert.pemCertBlocks(pckChainPem)
            if (blocks.isEmpty()) return fail("no PEM certificates in the PCK chain")
            val certs = blocks.map { AttestCert.certFromPem(it) }
            val issuers = HashSet<String>()
            val bySubject = HashMap<String, AttestCert.Cert>()
            for (c in certs) {
                issuers.add(bkey(c.rawIssuer))
                bySubject[bkey(c.rawSubject)] = c
            }
            var leaf = certs[0]
            for (c in certs) {
                if (!issuers.contains(bkey(c.rawSubject))) { leaf = c; break }
            }
            val ordered = ArrayList<AttestCert.Cert>()
            val seen = HashSet<String>()
            var cur: AttestCert.Cert? = leaf
            while (cur != null && !seen.contains(bkey(cur.rawSubject))) {
                ordered.add(cur)
                seen.add(bkey(cur.rawSubject))
                if (cur.selfIssued()) break
                cur = bySubject[bkey(cur.rawIssuer)]
            }
            val root = ordered[ordered.size - 1]
            if (!root.selfIssued()) return fail("PCK chain does not terminate in a self-signed root")
            if (ordered.size != certs.size) return fail("PCK chain is not a single connected path (orphan/duplicate certificates)")
            for (c in ordered) {
                if (!AttestDer.derValidAt(c.raw, nowMs, 0)) return PckChain(false, "PCK chain certificate outside its validity period", validity = true)
            }
            for (i in 0 until ordered.size - 1) {
                val child = ordered[i]
                val parent = ordered[i + 1]
                if (!child.rawIssuer.contentEquals(parent.rawSubject)) return fail("certificate at depth $i issuer does not match its parent subject")
                if (!AttestCert.certSigOkBy(child, parent)) return fail("certificate at depth $i is not signed by its issuer")
            }
            if (!AttestCert.certSigOkBy(root, root)) return fail("root certificate is not self-signed")
            val rootKey = AttestCert.keyOfCert(root)
            if (rootKey.spkiSha256() != pin.lowercase()) return fail("Intel SGX Root CA does not match the pinned trust anchor")
            val ders = ordered.map { it.raw }
            val roleFail = AttestDer.checkChainRoles(ders)
            if (roleFail != "") return fail(roleFail)
            for ((i, d) in ders.withIndex()) {
                val crit = AttestDer.unrecognisedCriticalExtension(d)
                if (crit != null) return fail("PCK chain certificate at depth $i has an unrecognised critical extension $crit")
            }
            val lk = AttestCert.keyOfCert(leaf)
            if (lk.typ != "ec") return fail("PCK leaf key is not EC (got ${lk.typ})")
            AttestCert.ecPointOfKey(lk, "P-256")
            PckChain(true, "", false, leaf, lk.pub as ECPublicKey, ordered.size)
        } catch (e: AttErr) {
            fail("PCK chain X.509 verification error (fail closed): " + AttestUtil.errMsg(e))
        }
    }

    // ---- genuine quote ----

    class QuotePolicy(
        val mrtds: List<String>, val fmspcs: List<String>, val rtmrs: List<String>,
        val mrSeams: List<String>?, val mrSignerSeams: List<String>?, val allowDebug: Boolean,
    )

    class TdxResult(
        val ok: Boolean, val reason: String, val reportData: ByteArray? = null, val fmspc: String = "",
        val pck: PckTcb? = null, val mrTd: ByteArray? = null,
    )

    private fun verifyP256Compact(msg: ByteArray, sig: ByteArray, pub: ECPublicKey): Boolean {
        if (sig.size != 64) return false
        return AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha256(msg), sig)
    }

    fun verifyGenuineTdxQuote(quote: ByteArray, pin: String, nowMs: Long, pol: QuotePolicy?, allowDebugOnly: Boolean): TdxResult {
        fun bad(r: String) = TdxResult(false, r)
        val q = try {
            parseQuote(quote)
        } catch (e: AttErr) {
            return bad("quote parse failed: " + AttestUtil.errMsg(e))
        }
        val body = q.tdReportBody
        val chain = verifyPckChain(q.pckChainPem, pin, nowMs)
        if (!chain.ok || chain.leafKey == null || chain.leaf == null) return bad("PCK chain invalid: " + chain.reason)
        val tcb = try {
            extractPckFmspcAndTcb(chain.leaf.raw)
        } catch (e: AttErr) {
            return bad("PCK FMSPC/TCB extraction failed: " + AttestUtil.errMsg(e))
        }
        if (!verifyP256Compact(q.qeReportBody, q.qeReportSignature, chain.leafKey)) return bad("QE report signature does not verify under the PCK leaf")
        if ((q.qeReportBody[QE_ATTR_OFF].toInt() and 0x02) != 0) return bad("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)")
        val qeReportData = q.qeReportBody.copyOfRange(QE_RDATA_OFF, QE_RDATA_OFF + 64)
        val akBinding = AttestUtil.sha256(q.akPubRaw + q.qeAuthData)
        var zero = true
        for (i in 32 until 64) if (qeReportData[i].toInt() != 0) zero = false
        if (!AttestUtil.timingSafeEq(qeReportData.copyOfRange(0, 32), akBinding) || !zero) return bad("QE report_data does not bind the attestation key (AK not endorsed by this QE)")
        val akPub = AttestUtil.pointToKey("secp256r1", byteArrayOf(0x04) + q.akPubRaw) ?: return bad("attestation public key is not a valid P-256 point")
        if (!verifyP256Compact(q.header + body, q.quoteSignature, akPub)) return bad("TD quote signature does not verify under the attestation key")
        val allowDebug = allowDebugOnly || (pol != null && pol.allowDebug)
        if (!allowDebug && (body[120].toInt() and 1) != 0) return bad("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)")
        val mrTd = body.copyOfRange(136, 184)
        val fmspcHex = AttestUtil.hex(tcb.fmspc)
        if (pol != null) {
            if (pol.mrtds.isNotEmpty() && AttestUtil.hex(mrTd) !in pol.mrtds) return bad("MRTD not in policy allowlist")
            if (pol.fmspcs.isNotEmpty() && fmspcHex !in pol.fmspcs) return bad("FMSPC not in policy allowlist")
            if (pol.mrSeams != null && AttestUtil.hex(body.copyOfRange(16, 64)) !in pol.mrSeams) return bad("MRSEAM not in policy allowlist")
            if (pol.mrSignerSeams != null && AttestUtil.hex(body.copyOfRange(64, 112)) !in pol.mrSignerSeams) return bad("MRSIGNERSEAM not in policy allowlist")
            if (pol.rtmrs.isNotEmpty() && AttestUtil.hex(body.copyOfRange(328, 376)) !in pol.rtmrs) return bad("RTMR0 not in policy allowlist")
        }
        return TdxResult(true, "", body.copyOfRange(520, 584), fmspcHex, tcb, mrTd)
    }

    // ---- collateral: CRL reading (lenient lengths, as the reference) ----

    private fun tlvLenient(b: ByteArray, off: Int, limit: Int): AttestDer.Tlv {
        if (off + 2 > limit) throw AttErr("DER truncated")
        val tag = b[off].toInt() and 0xff
        var l = b[off + 1].toInt() and 0xff
        var p = off + 2
        if ((l and 0x80) != 0) {
            val n = l and 0x7f
            if (n == 0 || n > 4 || p + n > limit) throw AttErr("DER bad length")
            l = 0
            for (i in 0 until n) l = l * 256 + (b[p + i].toInt() and 0xff)
            p += n
        }
        if (p + l > limit || p + l < p) throw AttErr("DER overrun")
        return AttestDer.Tlv(tag, p, p + l)
    }

    private val UTC_TIME = Regex("([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
    private val GEN_TIME = Regex("([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")

    private fun atoi(s: String): Int = s.toInt()

    /** `Date.UTC` (fields roll over; a year 0..99 means 19YY). */
    fun dateUtc(y0: Int, mo: Int, d: Int, h: Int, mi: Int, s: Int): Long {
        val y = if (y0 in 0..99) y0 + 1900 else y0
        val day = LocalDate.of(y, 1, 1).plusMonths((mo - 1).toLong()).plusDays((d - 1).toLong())
        return day.toEpochDay() * 86_400_000L + h * 3_600_000L + mi * 60_000L + s * 1000L
    }

    private fun crlTime(b: ByteArray, t: AttestDer.Tlv): Long {
        val s = String(b, t.start, t.end - t.start, Charsets.ISO_8859_1)
        when (t.tag) {
            0x17 -> {
                val m = UTC_TIME.matchEntire(s) ?: throw AttErr("bad UTCTime")
                val g = m.groupValues
                val yy = atoi(g[1])
                val y = if (yy >= 50) 1900 + yy else 2000 + yy
                return dateUtc(y, atoi(g[2]), atoi(g[3]), atoi(g[4]), atoi(g[5]), atoi(g[6]))
            }
            0x18 -> {
                val m = GEN_TIME.matchEntire(s) ?: throw AttErr("bad GeneralizedTime")
                val g = m.groupValues
                return dateUtc(atoi(g[1]), atoi(g[2]), atoi(g[3]), atoi(g[4]), atoi(g[5]), atoi(g[6]))
            }
        }
        throw AttErr("not a DER time")
    }

    private fun normSerial(s: String): String = s.lowercase().trimStart('0')

    private class ParsedCrl(val tbs: ByteArray, val thisUpdate: Long, val nextUpdate: Long, val revoked: Set<String>, val sigDer: ByteArray)

    private fun parseCrl(der: ByteArray): ParsedCrl {
        val outer = tlvLenient(der, 0, der.size)
        if (outer.tag != 0x30 || outer.end != der.size) throw AttErr("CRL: bad outer SEQUENCE")
        val tbsT = tlvLenient(der, outer.start, outer.end)
        if (tbsT.tag != 0x30) throw AttErr("CRL: bad TBSCertList")
        val tbs = der.copyOfRange(outer.start, tbsT.end)
        val revoked = HashSet<String>()
        val algT = tlvLenient(der, tbsT.end, outer.end)
        val sigT = tlvLenient(der, algT.end, outer.end)
        if (sigT.tag != 0x03 || sigT.end != outer.end) throw AttErr("CRL: bad signature")
        val sigDer = if (sigT.start + 1 <= sigT.end) der.copyOfRange(sigT.start + 1, sigT.end) else ByteArray(0)
        var p = tbsT.start
        var t = tlvLenient(der, p, tbsT.end)
        if (t.tag == 0x02) {
            p = t.end
            t = tlvLenient(der, p, tbsT.end)
        }
        p = t.end // signature AlgorithmIdentifier
        val iss = tlvLenient(der, p, tbsT.end)
        if (iss.tag != 0x30) throw AttErr("CRL: bad issuer")
        val tu = tlvLenient(der, iss.end, tbsT.end)
        val thisUpdate = crlTime(der, tu)
        var nextUpdate = 0L
        var hasNext = false
        var q = tu.end
        if (q < tbsT.end) {
            var n = tlvLenient(der, q, tbsT.end)
            if (n.tag == 0x17 || n.tag == 0x18) {
                nextUpdate = crlTime(der, n)
                hasNext = true
                q = n.end
            }
            if (q < tbsT.end) {
                n = tlvLenient(der, q, tbsT.end)
                if (n.tag == 0x30) {
                    var e = n.start
                    while (e < n.end) {
                        val ent = tlvLenient(der, e, n.end)
                        val ser = tlvLenient(der, ent.start, ent.end)
                        if (ser.tag != 0x02) throw AttErr("CRL: bad revoked entry")
                        revoked.add(normSerial(AttestUtil.hex(der.copyOfRange(ser.start, ser.end))))
                        e = ent.end
                    }
                }
            }
        }
        if (!hasNext) throw AttErr("CRL: missing nextUpdate")
        return ParsedCrl(tbs, thisUpdate, nextUpdate, revoked, sigDer)
    }

    /** `verify('sha256', tbs, issuerKey, sig)`: ECDSA (DER) or RSA PKCS#1 v1.5 under the issuer key. */
    private fun crlSigOk(tbs: ByteArray, sig: ByteArray, k: AttestCert.CertKey): Boolean {
        val pub = k.pub
        return try {
            when (pub) {
                is ECPublicKey -> AttestUtil.verifyDerEcdsa(pub, AttestUtil.sha256(tbs), sig)
                is RSAPublicKey -> {
                    val s = java.security.Signature.getInstance("SHA256withRSA")
                    s.initVerify(pub)
                    s.update(tbs)
                    s.verify(sig)
                }
                else -> false
            }
        } catch (e: java.security.GeneralSecurityException) {
            false
        }
    }

    /** Verifies a DER CRL under the issuer key at `nowMs`: the revoked serials (lowercase hex, no leading zeros), or the reason. */
    fun verifyCrl(der: ByteArray, issuer: AttestCert.CertKey, nowMs: Long): Pair<Set<String>?, String> {
        val crl = try {
            parseCrl(der)
        } catch (e: AttErr) {
            return Pair(null, "CRL parse failed: " + AttestUtil.errMsg(e))
        }
        if (!crlSigOk(crl.tbs, crl.sigDer, issuer)) return Pair(null, "CRL signature does not verify under the issuer")
        if (nowMs < crl.thisUpdate) return Pair(null, "CRL thisUpdate is in the future")
        if (nowMs > crl.nextUpdate) return Pair(null, "CRL is stale (nextUpdate passed)")
        return Pair(crl.revoked, "")
    }

    // ---- signed JSON documents ----

    private fun skipJsSpace(s: String, i0: Int): Int {
        var i = i0
        while (i < s.length && AttestUtil.isJsSpace(s[i].code)) i++
        return i
    }

    /** The exact source text of the JSON object following `"<name>":` in a top-level object. */
    private fun rawJsonObject(text: String, name: String): String? {
        var i = skipJsSpace(text, 0)
        if (i >= text.length || text[i] != '{') return null
        i = skipJsSpace(text, i + 1)
        val key = "\"$name\""
        if (!text.startsWith(key, i)) return null
        i = skipJsSpace(text, i + key.length)
        if (i >= text.length || text[i] != ':') return null
        i = skipJsSpace(text, i + 1)
        if (i >= text.length || text[i] != '{') return null
        val start = i
        var depth = 0
        var inStr = false
        while (i < text.length) {
            val ch = text[i]
            if (inStr) {
                if (ch == '\\') i++ else if (ch == '"') inStr = false
            } else if (ch == '"') inStr = true
            else if (ch == '{') depth++
            else if (ch == '}') {
                depth--
                if (depth == 0) return text.substring(start, i + 1)
            }
            i++
        }
        return null
    }

    private val SIG128 = Regex("[0-9a-fA-F]{128}")

    /** Verifies a PCS document: the body under `name`, or the failure text. */
    fun verifySignedJson(text: String, name: String, k: AttestCert.CertKey): Pair<Map<String, Any?>?, String> {
        val raw = rawJsonObject(text, name) ?: return Pair(null, "$name not found / malformed")
        val doc = try { Json.parseLenient(text) } catch (e: RuntimeException) { return Pair(null, "$name document is not valid JSON") }
        val top = AttestUtil.rec(doc) ?: emptyMap()
        val sig = top["signature"] as? String ?: ""
        if (!SIG128.matches(sig)) return Pair(null, "$name signature missing or malformed")
        val pk = k.pub as? ECPublicKey
        val sigBytes = AttestUtil.hexDecodeLoose(sig)
        if (pk == null || sigBytes == null || !AttestUtil.verifyRawEcdsa(pk, AttestUtil.sha256(raw.toByteArray(Charsets.UTF_8)), sigBytes)) return Pair(null, "$name signature does not verify under the TCB Signing certificate")
        val body = AttestUtil.rec(top[name]) ?: return Pair(null, "$name is not an object")
        return Pair(body, "")
    }

    /** `Date.parse` for the ISO-8601 forms PCS documents use (epoch ms), null otherwise. */
    private fun jsDateParse(s: String): Long? {
        try {
            return OffsetDateTime.parse(s).toInstant().toEpochMilli()
        } catch (e: java.time.DateTimeException) {
            // fall through to the date-only form
        }
        return try {
            LocalDate.parse(s).toEpochDay() * 86_400_000L
        } catch (e: java.time.DateTimeException) {
            null
        }
    }

    private fun checkFresh(body: Map<String, Any?>, what: String, nowMs: Long): String {
        val issue = (body["issueDate"] as? String)?.let { jsDateParse(it) }
        val next = (body["nextUpdate"] as? String)?.let { jsDateParse(it) }
        if (issue == null || next == null) return "$what: issueDate/nextUpdate missing"
        if (nowMs < issue) return "$what: issueDate is in the future"
        if (nowMs > next) return "$what: stale (nextUpdate passed)"
        return ""
    }

    // ---- status evaluation ----

    private val TCB_STATUS_ORDER = listOf("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked")
    val DEFAULT_ACCEPTED_STATUSES = listOf("UpToDate", "SWHardeningNeeded")

    private fun statusRank(s: String): Int = TCB_STATUS_ORDER.indexOf(s)
    private fun asTcbStatus(v: Any?): String? = (v as? String)?.takeIf { statusRank(it) >= 0 }
    private fun worstStatus(a: String, b: String): String = if (statusRank(a) >= statusRank(b)) a else b

    private fun svnList(v: Any?): List<Double>? {
        val arr = v as? List<*> ?: return null
        if (arr.size != 16) return null
        val out = ArrayList<Double>(16)
        for (c in arr) {
            val r = AttestUtil.rec(c) ?: return null
            out.add(AttestUtil.asFinite(r["svn"]) ?: return null)
        }
        return out
    }

    private fun hexBytesN(v: Any?, n: Int): ByteArray? {
        val s = v as? String ?: return null
        if (s.length != n * 2 || !AttestUtil.isHexText(s)) return null
        return AttestUtil.hexDecodeLoose(s)
    }

    private fun advisoryList(level: Map<String, Any?>): List<String> = (level["advisoryIDs"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()

    private fun maskedEq(value: ByteArray, mask: ByteArray, expected: ByteArray): Boolean {
        for (i in value.indices) if ((((value[i].toInt() and mask[i].toInt()) xor (expected[i].toInt() and mask[i].toInt())) and 0xff) != 0) return false
        return true
    }

    /** `levels.find(l => isRecord(l) && isRecord(l.tcb) && typeof l.tcb.isvsvn === 'number' && l.tcb.isvsvn <= svn)`. */
    private fun findLevel(levels: Any?, svn: Double): Map<String, Any?>? {
        val arr = levels as? List<*> ?: return null
        for (x in arr) {
            val l = AttestUtil.rec(x) ?: continue
            val tcb = AttestUtil.rec(l["tcb"]) ?: continue
            val f = AttestUtil.asFinite(tcb["isvsvn"])
            if (f != null && f <= svn) return l
        }
        return null
    }

    private class TcbEval(val platform: String = "", val module: String = "", val advisories: List<String> = emptyList(), val err: String = "")

    private fun evaluateTcb(info: Map<String, Any?>, pckSgx: ByteArray, pckPcesvn: Int, teeTcbSvn: ByteArray, mrSignerSeam: ByteArray, seamAttributes: ByteArray): TcbEval {
        val levels = info["tcbLevels"] as? List<*> ?: emptyList<Any?>()
        if (levels.isEmpty()) return TcbEval(err = "TCB info has no tcbLevels")
        val minor = teeTcbSvn[1].toInt() and 0xff
        var moduleStatus = "UpToDate"
        val adv = HashSet<String>()
        val modMrSigner: Any?
        val modAttr: Any?
        val modMask: Any?
        if (minor > 0) {
            val id = "TDX_" + String.format("%02X", minor)
            var ident: Map<String, Any?>? = null
            val ids = info["tdxModuleIdentities"] as? List<*>
            if (ids != null) for (x in ids) {
                val r = AttestUtil.rec(x)
                if (r != null && r["id"] == id) { ident = r; break }
            }
            if (ident == null) return TcbEval(err = "TDX module identity $id not present in TCB info")
            modMrSigner = ident["mrsigner"]
            modAttr = ident["attributes"]
            modMask = ident["attributesMask"]
            val svn0 = (teeTcbSvn[0].toInt() and 0xff)
            val hit = findLevel(ident["tcbLevels"], svn0.toDouble()) ?: return TcbEval(err = "TDX module $id SVN $svn0 is below every known level")
            val st = asTcbStatus(hit["tcbStatus"]) ?: return TcbEval(err = "TDX module level has an unknown tcbStatus")
            moduleStatus = st
            adv.addAll(advisoryList(hit))
        } else {
            val m = AttestUtil.rec(info["tdxModule"]) ?: return TcbEval(err = "TCB info missing tdxModule")
            modMrSigner = m["mrsigner"]
            modAttr = m["attributes"]
            modMask = m["attributesMask"]
        }
        val exMr = hexBytesN(modMrSigner, 48)
        val exAttr = hexBytesN(modAttr, 8)
        val mask = hexBytesN(modMask, 8)
        if (exMr == null || exAttr == null || mask == null) return TcbEval(err = "TDX module identity fields malformed")
        if (!exMr.contentEquals(mrSignerSeam)) return TcbEval(err = "TD report MRSIGNERSEAM does not match the TDX module identity")
        if (!maskedEq(seamAttributes, mask, exAttr)) return TcbEval(err = "TD report SEAM attributes do not match the TDX module identity")
        val from = if (minor > 0) 2 else 0
        for (x in levels) {
            val l = AttestUtil.rec(x)
            val tcb = if (l != null) AttestUtil.rec(l["tcb"]) else null
            if (l == null || tcb == null) return TcbEval(err = "malformed TCB level")
            val sgx = svnList(tcb["sgxtcbcomponents"])
            val tdx = svnList(tcb["tdxtcbcomponents"])
            val pce = AttestUtil.asFinite(tcb["pcesvn"])
            if (sgx == null || tdx == null || pce == null) return TcbEval(err = "malformed TCB level components")
            val st = asTcbStatus(l["tcbStatus"]) ?: return TcbEval(err = "TCB level has an unknown tcbStatus")
            var match = pckPcesvn.toDouble() >= pce
            var i = 0
            while (match && i < 16) {
                if ((pckSgx[i].toInt() and 0xff).toDouble() < sgx[i]) match = false
                i++
            }
            i = from
            while (match && i < 16) {
                if ((teeTcbSvn[i].toInt() and 0xff).toDouble() < tdx[i]) match = false
                i++
            }
            if (!match) continue
            adv.addAll(advisoryList(l))
            return TcbEval(platform = st, module = moduleStatus, advisories = adv.sorted())
        }
        return TcbEval(err = "platform TCB is below every level in the TCB info")
    }

    private class QeEval(val status: String = "", val advisories: List<String> = emptyList(), val err: String = "")

    private fun evaluateQe(ident: Map<String, Any?>, qe: ByteArray): QeEval {
        if (ident["id"] != "TD_QE") return QeEval(err = "QE identity id is not TD_QE")
        val ver = AttestUtil.asFinite(ident["version"])
        if (ver == null || ver != 2.0) return QeEval(err = "unsupported QE identity version")
        val miscsel = hexBytesN(ident["miscselect"], 4)
        val miscMask = hexBytesN(ident["miscselectMask"], 4)
        val attr = hexBytesN(ident["attributes"], 16)
        val attrMask = hexBytesN(ident["attributesMask"], 16)
        val mrsigner = hexBytesN(ident["mrsigner"], 32)
        val prodId = AttestUtil.asFinite(ident["isvprodid"])
        if (miscsel == null || miscMask == null || attr == null || attrMask == null || mrsigner == null || prodId == null) return QeEval(err = "QE identity fields malformed")
        if (qe.size != 384) return QeEval(err = "QE report has wrong length")
        if (!maskedEq(qe.copyOfRange(16, 20), miscMask, miscsel)) return QeEval(err = "QE MISCSELECT does not match the QE identity")
        if (!maskedEq(qe.copyOfRange(48, 64), attrMask, attr)) return QeEval(err = "QE ATTRIBUTES do not match the QE identity")
        if (!qe.copyOfRange(128, 160).contentEquals(mrsigner)) return QeEval(err = "QE MRSIGNER does not match the QE identity")
        val prod = (qe[256].toInt() and 0xff) or ((qe[257].toInt() and 0xff) shl 8)
        val isvsvn = (qe[258].toInt() and 0xff) or ((qe[259].toInt() and 0xff) shl 8)
        if (prod.toDouble() != prodId) return QeEval(err = "QE ISVPRODID does not match the QE identity")
        val hit = findLevel(ident["tcbLevels"], isvsvn.toDouble()) ?: return QeEval(err = "QE ISVSVN is below every known level")
        val st = asTcbStatus(hit["tcbStatus"]) ?: return QeEval(err = "QE level has an unknown tcbStatus")
        return QeEval(status = st, advisories = advisoryList(hit))
    }

    /**
     * Verifies a PCS issuer chain (leaf first) to the pinned root, validity at `nowMs` and that no certificate is on the Root CA
     * CRL. The leaf's key, or the failure text.
     */
    private fun signerKeyFromChain(chainPem: String, pin: String, nowMs: Long, rootRevoked: Set<String>): Pair<AttestCert.CertKey?, String> {
        val chain = verifyPckChain(chainPem, pin, nowMs)
        if (chain.validity) return Pair(null, "issuer chain certificate outside its validity period")
        if (!chain.ok || chain.leaf == null) return Pair(null, "issuer chain invalid: " + chain.reason)
        try {
            for (b in AttestCert.pemCertBlocks(chainPem)) {
                val c = AttestCert.certFromPem(b)
                if (!AttestDer.derValidAt(c.raw, nowMs, 0)) return Pair(null, "issuer chain certificate outside its validity period")
                if (rootRevoked.contains(c.serialHex())) return Pair(null, "issuer chain certificate is revoked by the Intel Root CA CRL")
            }
            return Pair(AttestCert.keyOfCert(chain.leaf), "")
        } catch (e: AttErr) {
            return Pair(null, "collateral verification error (fail closed): " + AttestUtil.errMsg(e))
        }
    }

    class CollateralPolicy(val acceptStatuses: List<String>?, val minEval: Double?)

    class Collateral(
        val tcbInfoJson: String, val tcbInfoChain: String, val qeIdentityJson: String, val qeIdentityChain: String,
        val pckCrl: ByteArray, val rootCrl: ByteArray,
    )

    fun collateralFromWire(m: Map<String, Any?>): Collateral {
        fun s(k: String): String = m[k] as? String ?: ""
        return Collateral(s("tcbInfoJson"), s("tcbInfoIssuerChainPem"), s("qeIdentityJson"), s("qeIdentityIssuerChainPem"), AttestUtil.evBytes(m, "pckCrlDer") ?: ByteArray(0), AttestUtil.evBytes(m, "rootCrlDer") ?: ByteArray(0))
    }

    class CollateralResult(val ok: Boolean, val reason: String, val status: String, val advisoryIds: List<String>)

    private fun cfail(r: String) = CollateralResult(false, r, "", emptyList())

    /** Verifies the quote and then its PCS collateral at `nowMs`: the evaluated TCB status and the policy decision. */
    fun verifyTdxCollateral(quote: ByteArray, c: Collateral?, nowMs: Long, pol: CollateralPolicy?, pin: String, allowDebug: Boolean): CollateralResult {
        fun thrown(e: AttErr) = cfail("collateral verification error (fail closed): " + AttestUtil.errMsg(e))
        if (c == null || c.tcbInfoJson.isEmpty() || c.qeIdentityJson.isEmpty() || c.pckCrl.isEmpty() || c.rootCrl.isEmpty() || c.tcbInfoChain.isEmpty() || c.qeIdentityChain.isEmpty()) return cfail("collateral incomplete (fail closed)")
        val base = verifyGenuineTdxQuote(quote, pin, nowMs, null, allowDebug)
        if (!base.ok || base.pck == null || base.fmspc == "") return cfail("quote invalid: " + base.reason)
        try {
            val q = parseQuote(quote)
            val quoteCerts = AttestCert.pemCertBlocks(q.pckChainPem).map { AttestCert.certFromPem(it) }
            for (x in quoteCerts) {
                if (!AttestDer.derValidAt(x.raw, nowMs, 0)) return cfail("PCK chain certificate outside its validity period")
            }
            var leaf: AttestCert.Cert? = null
            var ca: AttestCert.Cert? = null
            var root: AttestCert.Cert? = null
            for (x in quoteCerts) {
                var issues = false
                for (y in quoteCerts) if (y.rawIssuer.contentEquals(x.rawSubject)) issues = true
                if (!issues) { leaf = x; break }
            }
            if (leaf == null) return cfail("PCK leaf not found")
            for (x in quoteCerts) if (x.rawSubject.contentEquals(leaf.rawIssuer)) { ca = x; break }
            if (ca == null) return cfail("PCK CA not found in the quote chain")
            for (x in quoteCerts) if (x.selfIssued()) { root = x; break }
            if (root == null) return cfail("Intel root not found in the quote chain")
            val rootKey = AttestCert.keyOfCert(root)
            val caKey = AttestCert.keyOfCert(ca)
            val (rootRevokedN, why1) = verifyCrl(c.rootCrl, rootKey, nowMs)
            if (why1 != "" || rootRevokedN == null) return cfail("Intel Root CA CRL: $why1")
            val rootRevoked: Set<String> = rootRevokedN
            val (pckRevokedN, why2) = verifyCrl(c.pckCrl, caKey, nowMs)
            if (why2 != "" || pckRevokedN == null) return cfail("PCK CRL: $why2")
            val pckRevoked: Set<String> = pckRevokedN
            if (rootRevoked.contains(ca.serialHex())) return cfail("PCK CA certificate is revoked by the Intel Root CA CRL")
            if (pckRevoked.contains(leaf.serialHex())) return cfail("PCK leaf certificate is revoked by the PCK CRL")

            val (tcbKey, why3) = signerKeyFromChain(c.tcbInfoChain, pin, nowMs, rootRevoked)
            if (why3 != "" || tcbKey == null) return cfail("TCB info: $why3")
            val (info, why4) = verifySignedJson(c.tcbInfoJson, "tcbInfo", tcbKey)
            if (why4 != "" || info == null) return cfail("TCB info: $why4")
            val stale = checkFresh(info, "TCB info", nowMs)
            if (stale != "") return cfail(stale)
            if (info["id"] != "TDX") return cfail("TCB info is not a TDX v3 document")
            val iv = AttestUtil.asFinite(info["version"])
            if (iv == null || iv != 3.0) return cfail("TCB info is not a TDX v3 document")
            val fm = info["fmspc"] as? String
            if (fm == null || fm.lowercase() != base.fmspc) return cfail("TCB info FMSPC does not match the quote PCK")

            val (qeKey, why5) = signerKeyFromChain(c.qeIdentityChain, pin, nowMs, rootRevoked)
            if (why5 != "" || qeKey == null) return cfail("QE identity: $why5")
            val (qeBody, why6) = verifySignedJson(c.qeIdentityJson, "enclaveIdentity", qeKey)
            if (why6 != "" || qeBody == null) return cfail("QE identity: $why6")
            val stale2 = checkFresh(qeBody, "QE identity", nowMs)
            if (stale2 != "") return cfail(stale2)

            val infoNum = AttestUtil.asFinite(info["tcbEvaluationDataNumber"]) ?: -1.0
            val qeNum = AttestUtil.asFinite(qeBody["tcbEvaluationDataNumber"]) ?: -1.0
            if (infoNum < 0 || qeNum < 0) return cfail("tcbEvaluationDataNumber missing")
            if (pol != null && pol.minEval != null && (infoNum < pol.minEval || qeNum < pol.minEval)) return cfail("tcbEvaluationDataNumber below policy minimum")

            val body = q.tdReportBody
            val tcb = evaluateTcb(info, base.pck.sgx, base.pck.pcesvn, body.copyOfRange(0, 16), body.copyOfRange(64, 112), body.copyOfRange(112, 120))
            if (tcb.err != "") return cfail("TCB evaluation: " + tcb.err)
            val qe = evaluateQe(qeBody, q.qeReportBody)
            if (qe.err != "") return cfail("QE identity: " + qe.err)
            val status = worstStatus(worstStatus(tcb.platform, tcb.module), qe.status)
            val ids = (tcb.advisories + qe.advisories).toSortedSet().toList()
            val accepted = if (pol != null && pol.acceptStatuses != null) pol.acceptStatuses else DEFAULT_ACCEPTED_STATUSES
            if (status !in accepted) return CollateralResult(false, "TCB status $status is not accepted by policy", status, ids)
            return CollateralResult(true, "", status, ids)
        } catch (e: AttErr) {
            return thrown(e)
        }
    }

    // ---- the verifier ----

    private class Verifier(
        val binding: String, val pol: QuotePolicy, val pin: String, val allowMissing: Boolean, val collateralPol: CollateralPolicy?,
    ) : Attest.VendorImpl {
        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
            val quote = AttestUtil.evBytes(ev, "quote")
            if (ev == null || quote == null) return Attest.fail("no Intel DCAP quote for this action")
            if (expected == null) return Attest.fail("no expected attestation binding supplied")
            val q = verifyGenuineTdxQuote(quote, pin, nowMs, pol, false)
            if (!q.ok || q.reportData == null || q.mrTd == null) return Attest.fail("DCAP quote invalid: " + q.reason)
            if (binding == "report-data") {
                val want = try {
                    Attest.bindingBytes(expected)
                } catch (e: IllegalArgumentException) {
                    return Attest.fail("binding not constructible: " + e.message)
                }
                if (!AttestUtil.timingSafeEq(q.reportData, want)) return Attest.fail("report_data does not bind holder/grant/epoch/nonce")
            } else {
                val rd = AttestUtil.evBytes(ev, "runtimeData") ?: return Attest.fail("azure-runtime-data binding needs the runtime-data JSON bytes")
                val why = AttestUtil.checkAzureRuntimeDataBinding(q.reportData, rd, expected)
                if (why != "") return Attest.fail(why)
            }
            val host = LinkedHashMap<String, String>()
            host["attestation_type"] = "tdx-dcap"
            host["fmspc"] = q.fmspc
            val col = AttestUtil.rec(ev["collateral"])
            if (col != null) {
                val c = collateralFromWire(col)
                val res = verifyTdxCollateral(quote, c, nowMs, collateralPol, pin, pol.allowDebug)
                if (res.status != "") host["tcb_status"] = res.status
                if (res.advisoryIds.isNotEmpty()) host["advisory_ids"] = res.advisoryIds.joinToString(",")
                if (!res.ok) return Attest.fail("Intel collateral: " + (if (res.reason == "") "rejected" else res.reason))
            } else if (allowMissing) {
                host["tcb_status"] = "unevaluated"
            } else {
                return Attest.fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)")
            }
            return Attest.Result(true, true, "", AttestUtil.newMeasured(AttestUtil.hex(q.mrTd), ""), host)
        }
    }

    private val HEX_PATTERN = Regex("[0-9a-fA-F]+")

    fun create(cfg: Map<String, Any?>): Attest.VendorImpl {
        val binding = cfg["binding"] as? String ?: ""
        if (binding != "report-data" && binding != "azure-runtime-data") throw IllegalArgumentException("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'")
        val pol = AttestUtil.rec(cfg["policy"]) ?: emptyMap()
        val mr = AttestUtil.asStrList(pol["mrtds"])
        if (mr == null || mr.isEmpty()) throw IllegalArgumentException("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")
        val mrtds = AttestUtil.lowerAll(mr)
        for (m in mrtds) if (!HEX_PATTERN.matches(m) || m.length != 96) throw IllegalArgumentException("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)")
        var mrSeams: List<String>? = null
        var mrSigner: List<String>? = null
        for (name in listOf("mrSeams", "mrSignerSeams")) {
            if (!pol.containsKey(name)) continue
            val list = AttestUtil.asStrList(pol[name])
            if (list == null || list.isEmpty()) throw IllegalArgumentException("createIntelDcapVerifier: policy.$name, if given, must be a NON-EMPTY list")
            for (m in list) if (!HEX_PATTERN.matches(m) || m.length != 96) throw IllegalArgumentException("createIntelDcapVerifier: every $name entry must be 96 hex chars (48 bytes)")
            if (name == "mrSeams") mrSeams = AttestUtil.lowerAll(list) else mrSigner = AttestUtil.lowerAll(list)
        }
        val qp = QuotePolicy(
            mrtds = mrtds,
            fmspcs = AttestUtil.lowerAll(AttestUtil.asStrList(pol["fmspcs"]) ?: emptyList()),
            rtmrs = AttestUtil.lowerAll(AttestUtil.asStrList(pol["rtmrs"]) ?: emptyList()),
            mrSeams = mrSeams,
            mrSignerSeams = mrSigner,
            allowDebug = pol["allowDebug"] == true,
        )
        var pin = SGX_ROOT_CA_SPKI_SHA256
        val p = cfg["trustAnchorRootCaSpkiSha256"] as? String
        if (p != null) pin = p.lowercase()
        val allowMissing = cfg["allowMissingCollateral"] == true
        var cpol: CollateralPolicy? = null
        val cp = AttestUtil.rec(pol["collateral"])
        if (cp != null) cpol = CollateralPolicy(AttestUtil.asStrList(cp["acceptStatuses"]), AttestUtil.asFinite(cp["minTcbEvaluationDataNumber"]))
        return Verifier(binding, qp, pin, allowMissing, cpol)
    }
}
