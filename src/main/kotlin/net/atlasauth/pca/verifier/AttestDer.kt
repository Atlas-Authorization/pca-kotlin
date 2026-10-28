package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Strict DER readers shared by the hardware-attestation chain verifiers (the native counterpart of the strict X.509 helpers and
 * the validity reader of `@atlasauth/pca`). The CA-role rules are enforced from a small, strict walk of the certificate's own
 * DER: the raw extension table, the validity instants and the structure checks. Messages are the reference's, byte for byte.
 */
internal object AttestDer {
    /** One element: its tag and the content range `[start, end)`. */
    class Tlv(val tag: Int, val start: Int, val end: Int)

    /** Reads one definite-length element at `off` (inside `limit`). Minimal lengths only, no multi-byte tags. */
    fun readTlvStrict(b: ByteArray, off: Int, limit: Int): Tlv {
        if (off + 2 > limit) throw AttErr("DER: truncated header")
        val tag = b[off].toInt() and 0xff
        if ((tag and 0x1f) == 0x1f) throw AttErr("DER: multi-byte tags are not supported")
        var l = b[off + 1].toInt() and 0xff
        var p = off + 2
        if ((l and 0x80) != 0) {
            val n = l and 0x7f
            if (n == 0 || n > 3) throw AttErr("DER: unsupported length form")
            if (p + n > limit) throw AttErr("DER: truncated length")
            l = 0
            if (n > 1 && b[p].toInt() == 0) throw AttErr("DER: non-minimal length (leading zero)")
            for (i in 0 until n) l = (l shl 8) or (b[p + i].toInt() and 0xff)
            if (l < 0x80) throw AttErr("DER: non-minimal length (long form below 128)")
            p += n
        }
        if (p + l > limit) throw AttErr("DER: element overruns its parent")
        return Tlv(tag, p, p + l)
    }

    /** The CA-role-relevant part of a certificate. */
    class RoleInfo {
        var hasBasicConstraints = false
        var ca = false
        var pathLen = -1
        var hasKeyUsage = false
        var keyCertSign = false
    }

    private val OID_BASIC_CONSTRAINTS = byteArrayOf(0x55, 0x1d, 0x13)
    private val OID_KEY_USAGE = byteArrayOf(0x55, 0x1d, 0x0f)

    private fun oidEquals(b: ByteArray, t: Tlv, want: ByteArray): Boolean {
        if (t.tag != 0x06 || t.end - t.start != want.size) return false
        for (i in want.indices) if (b[t.start + i] != want[i]) return false
        return true
    }

    /** BasicConstraints and keyUsage of a DER certificate; an [AttErr] on a malformed or duplicated extension. */
    fun readCertRoleInfo(cert: ByteArray): RoleInfo {
        val info = RoleInfo()
        val outer = readTlvStrict(cert, 0, cert.size)
        if (outer.tag != 0x30) throw AttErr("certificate is not a DER SEQUENCE")
        if (outer.end != cert.size) throw AttErr("trailing bytes after the certificate")
        val tbs = readTlvStrict(cert, outer.start, outer.end)
        if (tbs.tag != 0x30) throw AttErr("certificate has no tbsCertificate")
        var p = tbs.start
        while (p < tbs.end) {
            val el = readTlvStrict(cert, p, tbs.end)
            p = el.end
            if (el.tag != 0xa3) continue
            val seq = readTlvStrict(cert, el.start, el.end)
            if (seq.tag != 0x30) throw AttErr("extensions is not a SEQUENCE")
            var q = seq.start
            while (q < seq.end) {
                val ext = readTlvStrict(cert, q, seq.end)
                q = ext.end
                if (ext.tag != 0x30) throw AttErr("extension is not a SEQUENCE")
                val id = readTlvStrict(cert, ext.start, ext.end)
                var r = id.end
                var next = readTlvStrict(cert, r, ext.end)
                if (next.tag == 0x01) {
                    r = next.end
                    next = readTlvStrict(cert, r, ext.end)
                }
                if (next.tag != 0x04) throw AttErr("extension value is not an OCTET STRING")
                if (oidEquals(cert, id, OID_BASIC_CONSTRAINTS)) {
                    if (info.hasBasicConstraints) throw AttErr("duplicate BasicConstraints extension")
                    info.hasBasicConstraints = true
                    val bc = readTlvStrict(cert, next.start, next.end)
                    if (bc.tag != 0x30) throw AttErr("BasicConstraints is not a SEQUENCE")
                    var c = bc.start
                    if (c < bc.end) {
                        val first = readTlvStrict(cert, c, bc.end)
                        if (first.tag == 0x01) {
                            if (first.end - first.start != 1) throw AttErr("BasicConstraints cA is not one byte")
                            info.ca = cert[first.start].toInt() != 0
                            c = first.end
                        }
                    }
                    if (c < bc.end) {
                        val pl = readTlvStrict(cert, c, bc.end)
                        if (pl.tag != 0x02 || pl.end - pl.start < 1 || pl.end - pl.start > 2 || (cert[pl.start].toInt() and 0x80) != 0)
                            throw AttErr("BasicConstraints pathLenConstraint malformed")
                        var n = 0
                        for (i in pl.start until pl.end) n = (n shl 8) or (cert[i].toInt() and 0xff)
                        info.pathLen = n
                        c = pl.end
                    }
                    if (c != bc.end) throw AttErr("BasicConstraints has trailing data")
                } else if (oidEquals(cert, id, OID_KEY_USAGE)) {
                    if (info.hasKeyUsage) throw AttErr("duplicate keyUsage extension")
                    info.hasKeyUsage = true
                    val bs = readTlvStrict(cert, next.start, next.end)
                    if (bs.tag != 0x03 || bs.end - bs.start < 2) throw AttErr("keyUsage is not a BIT STRING")
                    if ((cert[bs.start].toInt() and 0xff) > 7) throw AttErr("keyUsage BIT STRING has more than 7 unused bits")
                    info.keyCertSign = (cert[bs.start + 1].toInt() and 0x04) != 0
                }
            }
        }
        return info
    }

    /** One extension: the critical flag and the extnValue OCTET STRING content. */
    class Ext(val critical: Boolean, val value: ByteArray)

    /** Extensions in encounter order (the reference iterates a Map). */
    class ExtTable {
        val oids = ArrayList<String>()
        val m = HashMap<String, Ext>()
        fun get(oid: String): Ext? = m[oid]
    }

    /** `1.2.3` text of the OID content in `t` (strict: no non-minimal arc, not truncated). */
    fun oidToDotted(b: ByteArray, t: Tlv): String {
        if (t.tag != 0x06 || t.end <= t.start) throw AttErr("extension OID is malformed")
        val arcs = ArrayList<BigInteger>()
        var v = BigInteger.ZERO
        var open = false
        for (i in t.start until t.end) {
            val by = b[i].toInt() and 0xff
            if (!open && by == 0x80) throw AttErr("extension OID has a non-minimal arc")
            v = v.shiftLeft(7).or(BigInteger.valueOf((by and 0x7f).toLong()))
            open = (by and 0x80) != 0
            if (!open) {
                arcs.add(v)
                v = BigInteger.ZERO
            }
        }
        if (open) throw AttErr("extension OID is truncated")
        val first = arcs[0]
        val parts = ArrayList<String>()
        val forty = BigInteger.valueOf(40)
        val eighty = BigInteger.valueOf(80)
        when {
            first < forty -> { parts.add("0"); parts.add(first.toString()) }
            first < eighty -> { parts.add("1"); parts.add(first.subtract(forty).toString()) }
            else -> { parts.add("2"); parts.add(first.subtract(eighty).toString()) }
        }
        for (i in 1 until arcs.size) parts.add(arcs[i].toString())
        return parts.joinToString(".")
    }

    /**
     * The strict extension table of a tbsCertificate (the DER SEQUENCE including its header), keyed by dotted OID. It fails
     * closed on a malformed element, a duplicate extension, more than one [3] block, a non-DER critical flag, trailing
     * bytes, or an empty Extensions block.
     */
    fun parseTbsExtensions(tbsDer: ByteArray): ExtTable {
        val tbs = readTlvStrict(tbsDer, 0, tbsDer.size)
        if (tbs.tag != 0x30) throw AttErr("tbsCertificate is not a SEQUENCE")
        if (tbs.end != tbsDer.size) throw AttErr("trailing bytes after tbsCertificate")
        val out = ExtTable()
        var seen = false
        var blockEnd = -1
        var p = tbs.start
        while (p < tbs.end) {
            val el = readTlvStrict(tbsDer, p, tbs.end)
            p = el.end
            if (el.tag != 0xa3) continue
            if (seen) throw AttErr("duplicate [3] extensions block")
            seen = true
            blockEnd = el.end
            val seq = readTlvStrict(tbsDer, el.start, el.end)
            if (seq.tag != 0x30) throw AttErr("extensions is not a SEQUENCE")
            if (seq.end != el.end) throw AttErr("trailing bytes after the Extensions SEQUENCE")
            if (seq.start == seq.end) throw AttErr("empty Extensions SEQUENCE")
            var q = seq.start
            while (q < seq.end) {
                val ext = readTlvStrict(tbsDer, q, seq.end)
                q = ext.end
                if (ext.tag != 0x30) throw AttErr("extension is not a SEQUENCE")
                val id = readTlvStrict(tbsDer, ext.start, ext.end)
                val dotted = oidToDotted(tbsDer, id)
                var r = id.end
                var next = readTlvStrict(tbsDer, r, ext.end)
                var critical = false
                if (next.tag == 0x01) {
                    if (next.end - next.start != 1 || (tbsDer[next.start].toInt() and 0xff) != 0xff) throw AttErr("extension $dotted has a non-DER critical flag")
                    critical = true
                    r = next.end
                    next = readTlvStrict(tbsDer, r, ext.end)
                }
                if (next.tag != 0x04) throw AttErr("extension $dotted value is not an OCTET STRING")
                if (next.end != ext.end) throw AttErr("extension $dotted has trailing bytes")
                if (out.m.containsKey(dotted)) throw AttErr("duplicate extension $dotted")
                out.oids.add(dotted)
                out.m[dotted] = Ext(critical, tbsDer.copyOfRange(next.start, next.end))
            }
        }
        if (seen && blockEnd != tbs.end) throw AttErr("extensions block is not the last TBS element")
        return out
    }

    /** The tbsCertificate bytes (header included) of a DER certificate; trailing bytes are refused. */
    fun tbsOfCertificate(cert: ByteArray): ByteArray {
        val outer = readTlvStrict(cert, 0, cert.size)
        if (outer.tag != 0x30) throw AttErr("certificate is not a DER SEQUENCE")
        if (outer.end != cert.size) throw AttErr("trailing bytes after the certificate")
        val tbs = readTlvStrict(cert, outer.start, outer.end)
        if (tbs.tag != 0x30) throw AttErr("certificate has no tbsCertificate")
        return cert.copyOfRange(outer.start, tbs.end)
    }

    fun parseCertExtensions(cert: ByteArray): ExtTable = parseTbsExtensions(tbsOfCertificate(cert))

    /** The only critical extensions the attestation chain verifiers understand. */
    val RECOGNISED_CRITICAL: Set<String> = setOf("2.5.29.19", "2.5.29.15")

    /** The first critical extension OID the verifier does not recognise (RFC 5280 4.2), or null. */
    fun unrecognisedCriticalExtension(cert: ByteArray, recognised: Set<String> = RECOGNISED_CRITICAL): String? {
        val t = parseCertExtensions(cert)
        for (oid in t.oids) if (t.m.getValue(oid).critical && oid !in recognised) return oid
        return null
    }

    /** CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). The failure reason, or "". */
    fun checkChainRoles(ordered: List<ByteArray>): String {
        val n = ordered.size
        for (i in 0 until n) {
            val info = try {
                readCertRoleInfo(ordered[i])
            } catch (e: AttErr) {
                return "certificate extension parse failed: " + e.message
            }
            if (i == 0 && n > 1) {
                if (info.ca) return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"
                continue
            }
            if (i == 0) continue
            if (!info.hasBasicConstraints) return "issuer certificate at depth $i has no BasicConstraints (not a CA)"
            if (!info.ca) return "issuer certificate at depth $i is not a CA (BasicConstraints CA:FALSE)"
            if (info.hasKeyUsage && !info.keyCertSign) return "issuer certificate at depth $i keyUsage lacks keyCertSign"
            if (info.pathLen >= 0 && info.pathLen < i - 1) return "issuer certificate at depth $i pathLenConstraint ${info.pathLen} is exceeded (${i - 1} intermediate(s) below)"
        }
        return ""
    }

    // ---- validity (read from the certificate's own DER) ----

    /** An epoch-millisecond instant, or not ok (the reference's NaN). */
    class Instant(val ms: Long, val ok: Boolean)

    private val NO_INSTANT = Instant(0, false)

    /** One element at `off` of a whole buffer with the lenient length rules of the reference's `tlvAt`. */
    fun tlvAt(der: ByteArray, off: Int, limit: Int = der.size): Tlv {
        if (off + 2 > limit) throw AttErr("truncated")
        val tag = der[off].toInt() and 0xff
        var l = der[off + 1].toInt() and 0xff
        var start = off + 2
        if ((l and 0x80) != 0) {
            val n = l and 0x7f
            if (n == 0 || n > 4 || start + n > limit) throw AttErr("bad length")
            l = 0
            for (i in 0 until n) l = l * 256 + (der[start + i].toInt() and 0xff)
            start += n
        }
        val end = start + l
        if (end > limit || end < start) throw AttErr("truncated")
        return Tlv(tag, start, end)
    }

    private fun allDigits(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

    /** Strict RFC 5280 Time: UTCTime `YYMMDDHHMMSSZ` (YY >= 50 is 19YY) or GeneralizedTime `YYYYMMDDHHMMSSZ`, every field in range, no roll-over. */
    fun parseDerTime(tag: Int, text: String): Instant {
        val y: Int
        val rest: String
        if (tag == 0x17 && text.length == 13) {
            if (!allDigits(text.substring(0, 12)) || text[12] != 'Z') return NO_INSTANT
            val yy = text.substring(0, 2).toInt()
            y = if (yy >= 50) 1900 + yy else 2000 + yy
            rest = text.substring(2)
        } else if (tag == 0x18 && text.length == 15) {
            if (!allDigits(text.substring(0, 14)) || text[14] != 'Z') return NO_INSTANT
            y = text.substring(0, 4).toInt()
            rest = text.substring(4)
        } else return NO_INSTANT
        val mon = rest.substring(0, 2).toInt()
        val day = rest.substring(2, 4).toInt()
        val h = rest.substring(4, 6).toInt()
        val mi = rest.substring(6, 8).toInt()
        val sec = rest.substring(8, 10).toInt()
        if (mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59) return NO_INSTANT
        return try {
            Instant(LocalDateTime.of(y, mon, day, h, mi, sec).toInstant(ZoneOffset.UTC).toEpochMilli(), true)
        } catch (e: java.time.DateTimeException) {
            NO_INSTANT
        }
    }

    /** The validity window of a DER certificate (Certificate -> tbsCertificate -> validity); both not ok when malformed. */
    fun derValidity(der: ByteArray): Pair<Instant, Instant> {
        val bad = Pair(NO_INSTANT, NO_INSTANT)
        try {
            val cert = tlvAt(der, 0)
            if (cert.tag != 0x30) return bad
            val tbs = tlvAt(der, cert.start)
            if (tbs.tag != 0x30) return bad
            var off = tbs.start
            var el = tlvAt(der, off)
            if (el.tag == 0xa0) {
                off = el.end
                el = tlvAt(der, off)
            }
            if (el.tag != 0x02) return bad
            el = tlvAt(der, el.end)
            if (el.tag != 0x30) return bad
            el = tlvAt(der, el.end)
            if (el.tag != 0x30) return bad
            val validity = tlvAt(der, el.end)
            if (validity.tag != 0x30 || validity.end > tbs.end) return bad
            val nb = tlvAt(der, validity.start)
            val na = tlvAt(der, nb.end)
            if (na.end != validity.end) return bad
            return Pair(
                parseDerTime(nb.tag, String(der, nb.start, nb.end - nb.start, Charsets.ISO_8859_1)),
                parseDerTime(na.tag, String(der, na.start, na.end - na.start, Charsets.ISO_8859_1)),
            )
        } catch (e: AttErr) {
            return bad
        }
    }

    /** True iff both bounds parse and `from - skew <= nowMs <= to + skew` (fail closed on an unparseable bound). */
    fun derValidAt(der: ByteArray, nowMs: Long, skewMs: Long = 0): Boolean {
        val (from, to) = derValidity(der)
        if (!from.ok || !to.ok) return false
        return nowMs + skewMs >= from.ms && nowMs - skewMs <= to.ms
    }

    /** [derValidAt] with a fractional skew (milliseconds). */
    fun derValidAtF(der: ByteArray, nowMs: Long, skewMs: Double): Boolean {
        val (from, to) = derValidity(der)
        if (!from.ok || !to.ok) return false
        return nowMs.toDouble() + skewMs >= from.ms.toDouble() && nowMs.toDouble() - skewMs <= to.ms.toDouble()
    }
}
