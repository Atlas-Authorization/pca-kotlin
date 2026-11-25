package net.atlasauth.pca.spiffe

import net.atlasauth.pca.verifier.Json

/** A SPIFFE validation / parse failure with a stable [code] (the reference's error codes, e.g. `malformed_spiffe_id`). */
class SpiffeError(val code: String, message: String?) : RuntimeException(message)

/**
 * Minimal, bounds-checked DER reader for the X.509 extensions the SPIFFE X.509-SVID rules depend on (basicConstraints, keyUsage,
 * subjectAltName) plus the list of critical extensions. No cryptography: signatures, names and validity are checked elsewhere.
 * Malformed DER throws [IllegalArgumentException].
 */
object SpiffeDer {
    private class Tlv(val tag: Int, val start: Int, val end: Int)

    private fun readTlv(buf: ByteArray, off: Int, limit: Int): Tlv {
        if (off.toLong() + 2 > limit) throw IllegalArgumentException("der: truncated header")
        val tag = buf[off].toInt() and 0xff
        if (tag and 0x1f == 0x1f) throw IllegalArgumentException("der: high-tag-number form is not supported")
        var len = (buf[off + 1].toInt() and 0xff).toLong()
        var p = off.toLong() + 2
        if (len and 0x80 != 0L) {
            val n = (len and 0x7f).toInt()
            if (n == 0 || n > 4) throw IllegalArgumentException("der: unsupported length form")
            if (p + n > limit) throw IllegalArgumentException("der: truncated length")
            len = 0
            for (i in 0 until n) len = len * 256 + (buf[p.toInt() + i].toInt() and 0xff)
            p += n
        }
        if (p + len > limit) throw IllegalArgumentException("der: content exceeds container")
        return Tlv(tag, p.toInt(), (p + len).toInt())
    }

    private fun children(buf: ByteArray, parent: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var off = parent.start
        while (off < parent.end) {
            val t = readTlv(buf, off, parent.end)
            out.add(t)
            off = t.end
        }
        return out
    }

    /** `der[i]` as JavaScript reads it: -1 (undefined) past the end. */
    private fun at(der: ByteArray, i: Int) = if (i >= 0 && i < der.size) der[i].toInt() and 0xff else -1

    private fun hex(buf: ByteArray, t: Tlv): String = (t.start until t.end).joinToString("") { String.format("%02x", buf[it].toInt() and 0xff) }

    private const val OID_KEY_USAGE = "551d0f"
    private const val OID_SAN = "551d11"
    private const val OID_BASIC_CONSTRAINTS = "551d13"
    private val KNOWN_CRITICAL = setOf(OID_KEY_USAGE, OID_SAN, OID_BASIC_CONSTRAINTS, "551d25", "551d0e", "551d23")

    /** The X.509 facts the SVID rules need. */
    class CertFacts {
        var basicConstraintsPresent = false
        var isCa = false
        var keyUsagePresent = false
        var digitalSignature = false
        var keyCertSign = false
        var crlSign = false

        /** pathLenConstraint, or null when absent (a JavaScript number: precision is lost above 2^53, as in the reference). */
        var pathLen: Double? = null
        val uriSans: MutableList<String> = ArrayList()
        val unknownCritical: MutableList<String> = ArrayList()

        /** The facts as a JSON object. */
        fun toJson(): Map<String, Any?> = linkedMapOf(
            "basicConstraintsPresent" to basicConstraintsPresent, "isCa" to isCa,
            "pathLen" to pathLen?.let { Json.Num(if (it == Math.rint(it) && Math.abs(it) < 9e15) it.toLong().toString() else Json.esNumber(it)) },
            "keyUsagePresent" to keyUsagePresent, "digitalSignature" to digitalSignature, "keyCertSign" to keyCertSign, "crlSign" to crlSign,
            "uriSans" to ArrayList<Any?>(uriSans), "unknownCritical" to ArrayList<Any?>(unknownCritical),
        )
    }

    /** Read the X.509 facts the SVID rules need from a DER certificate. Throws IllegalArgumentException on malformed DER. */
    @JvmStatic
    fun readCertFacts(der: ByteArray): CertFacts {
        val cert = readTlv(der, 0, der.size)
        if (cert.tag != 0x30 || cert.end != der.size) throw IllegalArgumentException("der: certificate is not a single SEQUENCE")
        val tbs = children(der, cert).firstOrNull()
        if (tbs == null || tbs.tag != 0x30) throw IllegalArgumentException("der: missing tbsCertificate")
        val extWrap = children(der, tbs).firstOrNull { it.tag == 0xa3 }
        val facts = CertFacts()
        if (extWrap == null) return facts
        val extSeq = children(der, extWrap).firstOrNull()
        if (extSeq == null || extSeq.tag != 0x30) throw IllegalArgumentException("der: malformed extensions")
        val seen = HashSet<String>()
        for (ext in children(der, extSeq)) {
            val parts = children(der, ext)
            val oidT = parts.firstOrNull()
            if (oidT == null || oidT.tag != 0x06) throw IllegalArgumentException("der: malformed extension")
            val oid = hex(der, oidT)
            if (!seen.add(oid)) throw IllegalArgumentException("der: duplicate extension")
            val critical = parts.size == 3 && parts[1].tag == 0x01 && at(der, parts[1].start) == 0xff
            val valueT = parts[parts.size - 1]
            if (valueT.tag != 0x04) throw IllegalArgumentException("der: malformed extension value")
            if (critical && oid !in KNOWN_CRITICAL) facts.unknownCritical.add(oid)
            val inner = readTlv(der, valueT.start, valueT.end)
            when (oid) {
                OID_BASIC_CONSTRAINTS -> {
                    facts.basicConstraintsPresent = true
                    for (c in children(der, inner)) {
                        if (c.tag == 0x01) facts.isCa = at(der, c.start) == 0xff
                        else if (c.tag == 0x02) {
                            var n = 0.0
                            for (i in c.start until c.end) n = n * 256 + (der[i].toInt() and 0xff)
                            facts.pathLen = n
                        }
                    }
                }
                OID_KEY_USAGE -> {
                    if (inner.tag != 0x03 || inner.end - inner.start < 2) throw IllegalArgumentException("der: malformed keyUsage")
                    val b0 = der[inner.start + 1].toInt() and 0xff
                    facts.keyUsagePresent = true
                    facts.digitalSignature = b0 and 0x80 != 0
                    facts.keyCertSign = b0 and 0x04 != 0
                    facts.crlSign = b0 and 0x02 != 0
                }
                OID_SAN -> for (gn in children(der, inner)) {
                    if (gn.tag == 0x86) facts.uriSans.add(String(der, gn.start, gn.end - gn.start, Charsets.ISO_8859_1))
                }
            }
        }
        return facts
    }
}
