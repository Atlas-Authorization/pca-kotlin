package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The strict DER readers: TLV headers, CA-role extensions, the extension table, OIDs, chain roles and the validity window. */
class Kill05XmlAttestDerTest {
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun len(n: Int): ByteArray = when {
        n < 0x80 -> b(n)
        n < 0x100 -> b(0x81, n)
        else -> b(0x82, n shr 8, n and 0xff)
    }

    private fun t(tag: Int, vararg parts: ByteArray): ByteArray {
        var body = ByteArray(0)
        for (p in parts) body += p
        return b(tag) + len(body.size) + body
    }

    private fun msg(f: () -> Any?): String = try {
        f()
        "OK"
    } catch (e: AttErr) {
        e.message ?: ""
    }

    private val bcOid = b(0x55, 0x1d, 0x13)
    private val kuOid = b(0x55, 0x1d, 0x0f)
    private fun ext(oid: ByteArray, value: ByteArray, critical: ByteArray? = null, oidTag: Int = 0x06): ByteArray =
        if (critical == null) t(0x30, t(oidTag, oid), t(0x04, value)) else t(0x30, t(oidTag, oid), critical, t(0x04, value))

    /** A certificate whose tbsCertificate is a serial plus an extensions block (all the role reader walks). */
    private fun cert(vararg exts: ByteArray): ByteArray = t(0x30, t(0x30, t(0x02, b(1)), t(0xa3, t(0x30, *exts))))
    private fun plain(): ByteArray = t(0x30, t(0x30, t(0x02, b(1))))
    private fun bc(vararg inner: ByteArray) = ext(bcOid, t(0x30, *inner))
    private val caTrue = t(0x01, b(0xff))
    private fun ku(vararg v: Int) = ext(kuOid, t(0x03, b(*v)))

    @Test
    fun readTlvStrict() {
        val ok = AttestDer.readTlvStrict(b(0x04, 0x81, 0x80) + ByteArray(0x80), 0, 0x83)
        assertEquals(0x04, ok.tag)
        assertEquals(3, ok.start)
        assertEquals(0x83, ok.end)
        assertEquals("DER: non-minimal length (long form below 128)", msg { AttestDer.readTlvStrict(b(0x30, 0x81, 0x00), 0, 3) })
        assertEquals("DER: non-minimal length (long form below 128)", msg { AttestDer.readTlvStrict(b(0x30, 0x81, 0x7f) + ByteArray(0x7f), 0, 0x82) })
        assertEquals("DER: non-minimal length (leading zero)", msg { AttestDer.readTlvStrict(b(0x30, 0x82, 0x00, 0x80) + ByteArray(0x80), 0, 0x84) })
        val two = AttestDer.readTlvStrict(b(0x30, 0x82, 0x01, 0x00) + ByteArray(0x100), 0, 0x104)
        assertEquals(0x104, two.end)
    }

    @Test
    fun roleInfo() {
        fun info(c: ByteArray) = AttestDer.readCertRoleInfo(c)
        val i1 = info(cert(bc(caTrue, t(0x02, b(0)))))
        assertTrue(i1.hasBasicConstraints)
        assertTrue(i1.ca)
        assertEquals(0, i1.pathLen)
        assertFalse(i1.hasKeyUsage)
        // a pathLen without a cA flag: the INTEGER is not read as the flag
        val i2 = info(cert(bc(t(0x02, b(1)))))
        assertFalse(i2.ca)
        assertEquals(1, i2.pathLen)
        val i3 = info(cert(bc(t(0x01, b(0x00)))))
        assertTrue(i3.hasBasicConstraints)
        assertFalse(i3.ca)
        assertEquals(-1, i3.pathLen)
        assertTrue(info(cert(bc(t(0x01, b(0x01))))).ca)
        val empty = info(cert(bc()))
        assertTrue(empty.hasBasicConstraints)
        assertFalse(empty.ca)
        assertEquals(-1, empty.pathLen)
        assertEquals(256, info(cert(bc(caTrue, t(0x02, b(0x01, 0x00))))).pathLen)
        assertEquals(0x7fff, info(cert(bc(caTrue, t(0x02, b(0x7f, 0xff))))).pathLen)
        // a critical flag before the value is skipped
        assertTrue(info(cert(ext(bcOid, t(0x30, caTrue), caTrue))).ca)
        val none = info(plain())
        assertFalse(none.hasBasicConstraints)
        assertFalse(none.ca)
        assertEquals(-1, none.pathLen)
        // keyUsage: bit 5 (keyCertSign) is 0x04 of the first content byte
        val k1 = info(cert(ku(1, 0x06)))
        assertTrue(k1.hasKeyUsage)
        assertTrue(k1.keyCertSign)
        val k2 = info(cert(ku(0, 0x01)))
        assertTrue(k2.hasKeyUsage)
        assertFalse(k2.keyCertSign)
        assertFalse(info(cert(ku(7, 0x80))).keyCertSign)
        assertTrue(info(cert(ku(0, 0x04))).keyCertSign)
        // only the exact OIDs count
        for (o in listOf(b(0x55, 0x1d, 0x14), b(0x56, 0x1d, 0x13), b(0x55, 0x1e, 0x13), b(0x55, 0x1d, 0x13, 0x00), b(0x55, 0x1d))) {
            val i = info(cert(ext(o, t(0x30, caTrue))))
            assertFalse(i.hasBasicConstraints)
            assertFalse(i.ca)
        }
        assertFalse(info(cert(ext(bcOid, t(0x30, caTrue), oidTag = 0x04))).hasBasicConstraints)
        assertFalse(info(cert(ext(b(0x55, 0x1d, 0x10), t(0x03, b(0, 0x04))))).hasKeyUsage)
    }

    @Test
    fun roleInfoRefusals() {
        fun m(c: ByteArray) = msg { AttestDer.readCertRoleInfo(c) }
        assertEquals("certificate is not a DER SEQUENCE", m(t(0x31, t(0x30))))
        assertEquals("trailing bytes after the certificate", m(plain() + b(0)))
        assertEquals("certificate has no tbsCertificate", m(t(0x30, t(0x31, t(0x02, b(1))))))
        assertEquals("extensions is not a SEQUENCE", m(t(0x30, t(0x30, t(0xa3, t(0x31))))))
        assertEquals("extension is not a SEQUENCE", m(cert(t(0x31, t(0x06, bcOid), t(0x04, t(0x30))))))
        assertEquals("extension value is not an OCTET STRING", m(cert(t(0x30, t(0x06, bcOid), t(0x03, t(0x30))))))
        assertEquals("duplicate BasicConstraints extension", m(cert(bc(), bc())))
        assertEquals("BasicConstraints is not a SEQUENCE", m(cert(ext(bcOid, t(0x31)))))
        assertEquals("BasicConstraints cA is not one byte", m(cert(bc(t(0x01, b(0xff, 0xff))))))
        for (pl in listOf(t(0x02), t(0x02, b(1, 0, 0)), t(0x02, b(0x80)), t(0x02, b(0xff, 0xff)), t(0x04, b(1))))
            assertEquals("BasicConstraints pathLenConstraint malformed", m(cert(bc(caTrue, pl))))
        assertEquals("BasicConstraints has trailing data", m(cert(bc(caTrue, t(0x02, b(1)), t(0x02, b(1))))))
        assertEquals("duplicate keyUsage extension", m(cert(ku(0, 4), ku(0, 4))))
        assertEquals("keyUsage is not a BIT STRING", m(cert(ext(kuOid, t(0x04, b(0, 4))))))
        assertEquals("keyUsage is not a BIT STRING", m(cert(ext(kuOid, t(0x03, b(0))))))
        assertEquals("keyUsage BIT STRING has more than 7 unused bits", m(cert(ku(8, 0x04))))
    }

    @Test
    fun chainRoles() {
        val leaf = plain()
        val leafCa = cert(bc(caTrue))
        val ca = cert(bc(caTrue))
        fun caPl(n: Int) = cert(bc(caTrue, t(0x02, b(n))))
        assertEquals("", AttestDer.checkChainRoles(emptyList()))
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf)))
        assertEquals("", AttestDer.checkChainRoles(listOf(leafCa)))
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf, ca)))
        assertEquals("leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)", AttestDer.checkChainRoles(listOf(leafCa, ca)))
        assertEquals("issuer certificate at depth 1 has no BasicConstraints (not a CA)", AttestDer.checkChainRoles(listOf(leaf, plain())))
        assertEquals("issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)", AttestDer.checkChainRoles(listOf(leaf, cert(bc()))))
        assertEquals("issuer certificate at depth 2 is not a CA (BasicConstraints CA:FALSE)", AttestDer.checkChainRoles(listOf(leaf, ca, cert(bc()))))
        assertEquals("issuer certificate at depth 1 keyUsage lacks keyCertSign", AttestDer.checkChainRoles(listOf(leaf, cert(bc(caTrue), ku(0, 0x02)))))
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf, cert(bc(caTrue), ku(1, 0x06)))))
        // pathLen: the issuer at depth i has i - 1 intermediates below it
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf, caPl(0))))
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf, ca, caPl(1))))
        assertEquals("", AttestDer.checkChainRoles(listOf(leaf, ca, ca, caPl(2))))
        assertEquals(
            "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)",
            AttestDer.checkChainRoles(listOf(leaf, ca, caPl(0))),
        )
        assertEquals(
            "issuer certificate at depth 3 pathLenConstraint 1 is exceeded (2 intermediate(s) below)",
            AttestDer.checkChainRoles(listOf(leaf, ca, ca, caPl(1))),
        )
        assertEquals("certificate extension parse failed: certificate is not a DER SEQUENCE", AttestDer.checkChainRoles(listOf(b(0x31, 0x00), ca)))
        assertEquals("certificate extension parse failed: duplicate BasicConstraints extension", AttestDer.checkChainRoles(listOf(leaf, cert(bc(), bc()))))
    }

    @Test
    fun oidToDotted() {
        fun d(vararg v: Int): String {
            val x = t(0x06, b(*v))
            return try {
                AttestDer.oidToDotted(x, AttestDer.Tlv(0x06, 2, x.size))
            } catch (e: AttErr) {
                "ERR " + e.message
            }
        }
        assertEquals("1.2.840", d(0x2a, 0x86, 0x48))
        assertEquals("2.5.29.19", d(0x55, 0x1d, 0x13))
        assertEquals("0.0", d(0x00))
        assertEquals("0.39", d(0x27))
        assertEquals("1.0", d(0x28))
        assertEquals("1.39", d(0x4f))
        assertEquals("2.0", d(0x50))
        assertEquals("2.48", d(0x81, 0x00))
        assertEquals("2.16305", d(0x81, 0x80, 0x01))
        assertEquals("1.2.0.127", d(0x2a, 0x00, 0x7f))
        assertEquals("ERR extension OID has a non-minimal arc", d(0x80, 0x01))
        assertEquals("ERR extension OID has a non-minimal arc", d(0x2a, 0x80, 0x01))
        assertEquals("ERR extension OID is truncated", d(0x2a, 0x86))
        val e = t(0x06)
        assertEquals("extension OID is malformed", msg { AttestDer.oidToDotted(e, AttestDer.Tlv(0x06, 2, 2)) })
        val w = t(0x04, b(0x2a))
        assertEquals("extension OID is malformed", msg { AttestDer.oidToDotted(w, AttestDer.Tlv(0x04, 2, 3)) })
    }

    @Test
    fun extensionTable() {
        val other = ext(b(0x2b, 0x06, 0x01), b(0xde, 0xad), caTrue)
        val tbs = t(0x30, t(0x02, b(1)), t(0xa3, t(0x30, bc(caTrue), other)))
        val tab = AttestDer.parseTbsExtensions(tbs)
        assertEquals(listOf("2.5.29.19", "1.3.6.1"), tab.oids)
        assertFalse(tab.get("2.5.29.19")!!.critical)
        assertArrayEquals(t(0x30, caTrue), tab.get("2.5.29.19")!!.value)
        assertTrue(tab.get("1.3.6.1")!!.critical)
        assertArrayEquals(b(0xde, 0xad), tab.get("1.3.6.1")!!.value)
        assertNull(tab.get("2.5.29.15"))
        assertEquals(0, AttestDer.parseTbsExtensions(t(0x30, t(0x02, b(1)))).oids.size)
        // the certificate wrapper hands over exactly the tbsCertificate
        val c = t(0x30, tbs, t(0x30), t(0x03, b(0)))
        assertArrayEquals(tbs, AttestDer.tbsOfCertificate(c))
        assertEquals(listOf("2.5.29.19", "1.3.6.1"), AttestDer.parseCertExtensions(c).oids)
        assertEquals("1.3.6.1", AttestDer.unrecognisedCriticalExtension(c))
        assertNull(AttestDer.unrecognisedCriticalExtension(c, setOf("1.3.6.1")))
        assertNull(AttestDer.unrecognisedCriticalExtension(t(0x30, t(0x30, t(0xa3, t(0x30, ext(bcOid, t(0x30), caTrue)))))))

        fun m(x: ByteArray) = msg { AttestDer.parseTbsExtensions(x) }
        fun blk(vararg e: ByteArray) = t(0x30, t(0x02, b(1)), t(0xa3, t(0x30, *e)))
        assertEquals("tbsCertificate is not a SEQUENCE", m(t(0x31, t(0x02, b(1)))))
        assertEquals("trailing bytes after tbsCertificate", m(t(0x30) + b(0)))
        assertEquals("duplicate [3] extensions block", m(t(0x30, t(0xa3, t(0x30, bc())), t(0xa3, t(0x30, ku(0, 4))))))
        assertEquals("extensions is not a SEQUENCE", m(t(0x30, t(0xa3, t(0x31, bc())))))
        assertEquals("trailing bytes after the Extensions SEQUENCE", m(t(0x30, t(0xa3, t(0x30, bc()), b(0x05, 0x00)))))
        assertEquals("empty Extensions SEQUENCE", m(t(0x30, t(0xa3, t(0x30)))))
        assertEquals("extension is not a SEQUENCE", m(blk(t(0x31, t(0x06, bcOid), t(0x04)))))
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", m(blk(ext(bcOid, t(0x30), t(0x01, b(0x01))))))
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", m(blk(ext(bcOid, t(0x30), t(0x01, b(0x00))))))
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", m(blk(ext(bcOid, t(0x30), t(0x01, b(0xff, 0xff))))))
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", m(blk(ext(bcOid, t(0x30), t(0x01)))))
        assertEquals("extension 2.5.29.19 value is not an OCTET STRING", m(blk(t(0x30, t(0x06, bcOid), t(0x03, b(0))))))
        assertEquals("extension 2.5.29.19 has trailing bytes", m(blk(t(0x30, t(0x06, bcOid), t(0x04), b(0x05, 0x00)))))
        assertEquals("duplicate extension 2.5.29.19", m(blk(bc(), bc())))
        assertEquals("extensions block is not the last TBS element", m(t(0x30, t(0xa3, t(0x30, bc())), t(0x02, b(1)))))
        assertEquals("extension OID is malformed", m(blk(t(0x30, t(0x04, bcOid), t(0x04)))))
        assertEquals("certificate is not a DER SEQUENCE", msg { AttestDer.tbsOfCertificate(t(0x31, tbs)) })
        assertEquals("trailing bytes after the certificate", msg { AttestDer.tbsOfCertificate(t(0x30, tbs) + b(0)) })
        assertEquals("certificate has no tbsCertificate", msg { AttestDer.tbsOfCertificate(t(0x30, t(0x31, t(0x02, b(1))))) })
    }

    @Test
    fun tlvAt() {
        fun m(x: ByteArray, limit: Int = x.size) = msg { AttestDer.tlvAt(x, 0, limit) }
        val a = AttestDer.tlvAt(b(0x30, 0x84, 0, 0, 0, 1, 0x05), 0)
        assertEquals(0x30, a.tag)
        assertEquals(6, a.start)
        assertEquals(7, a.end)
        val z = AttestDer.tlvAt(b(0x30, 0x81, 0x00), 0)
        assertEquals(3, z.start)
        assertEquals(3, z.end)
        // lenient: a long form below 128 and a leading zero are accepted
        assertEquals(4, AttestDer.tlvAt(b(0x04, 0x82, 0x00, 0x01, 0x07), 0).start)
        val o = AttestDer.tlvAt(b(0x00, 0x02, 0x30, 0x00), 2)
        assertEquals(0x30, o.tag)
        assertEquals(4, o.start)
        assertEquals(4, o.end)
        assertEquals("bad length", m(b(0x30, 0x80)))
        assertEquals("bad length", m(b(0x30, 0x85, 0, 0, 0, 0, 1, 0x05)))
        assertEquals("bad length", m(b(0x30, 0x82, 0x01)))
        assertEquals("bad length", m(b(0x30, 0x81, 0x00), 2))
        assertEquals("truncated", m(b(0x30)))
        assertEquals("truncated", m(b(0x30, 0x02, 0x01)))
        assertEquals("truncated", m(b(0x30, 0x01, 0x05), 2))
        assertEquals("truncated", m(b(0x30, 0x84, 0xff, 0xff, 0xff, 0xff)))
        assertEquals("truncated", m(b(0x30, 0x84, 0x7f, 0xff, 0xff, 0xff)))
    }

    @Test
    fun derTime() {
        fun ms(tag: Int, s: String): Long? = AttestDer.parseDerTime(tag, s).let { if (it.ok) it.ms else null }
        assertEquals(1735689600000L, ms(0x17, "250101000000Z"))
        assertEquals(-631152000000L, ms(0x17, "500101000000Z"))
        assertEquals(2524607999000L, ms(0x17, "491231235959Z"))
        assertEquals(1262303999000L, ms(0x17, "091231235959Z"))
        assertEquals(1330518645000L, ms(0x17, "120229123045Z"))
        assertEquals(1735689600000L, ms(0x18, "20250101000000Z"))
        assertEquals(2524607999000L, ms(0x18, "20491231235959Z"))
        val bad = listOf(
            0x17 to "20250101000000Z", 0x18 to "250101000000Z", 0x0c to "20250101000000Z", 0x0c to "250101000000Z",
            0x17 to "2501010000:0Z", 0x17 to "25010100/000Z", 0x17 to "x50101000000Z", 0x17 to "2501010000009", 0x17 to "250101000000X",
            0x18 to "2025010100000:Z", 0x18 to "/0250101000000Z", 0x18 to "20250101000000z",
            0x17 to "251301000000Z", 0x17 to "250001000000Z", 0x17 to "250100000000Z", 0x17 to "250132000000Z", 0x17 to "250229000000Z",
            0x17 to "250431000000Z", 0x17 to "250101240000Z", 0x17 to "250101006000Z", 0x17 to "250101000060Z",
            0x17 to "", 0x17 to "25010100000Z", 0x17 to "2501010000000Z",
        )
        for ((tag, s) in bad) assertNull("$tag $s", ms(tag, s))
        assertFalse(AttestDer.parseDerTime(0x17, "x").ok)
    }

    // ---- the validity window read from a certificate ----
    private val nb = "250101000000Z"
    private val na = "491231235959Z"
    private val from = 1735689600000L
    private val to = 2524607999000L
    private fun time(s: String) = t(0x17, s.toByteArray(Charsets.ISO_8859_1))

    private fun vcert(
        version: Boolean = true,
        outer: Int = 0x30,
        tbsTag: Int = 0x30,
        serial: Int = 0x02,
        alg: Int = 0x30,
        issuer: Int = 0x30,
        validity: ByteArray = t(0x30, time(nb), time(na)),
        subject: Boolean = true,
        shortTbs: Boolean = false,
    ): ByteArray {
        var body = ByteArray(0)
        if (version) body += t(0xa0, t(0x02, b(2)))
        body += t(serial, b(5)) + t(alg, t(0x06, b(0x2a))) + t(issuer) + validity
        if (subject) body += t(0x30)
        val tbs = if (shortTbs) b(tbsTag) + len(body.size - 1) + body else b(tbsTag) + len(body.size) + body
        return t(outer, tbs, t(0x30), t(0x03, b(0)))
    }

    @Test
    fun validity() {
        fun win(c: ByteArray): String {
            val (f, u) = AttestDer.derValidity(c)
            return "${f.ok}:${if (f.ok) f.ms else 0}/${u.ok}:${if (u.ok) u.ms else 0}"
        }
        val good = "true:$from/true:$to"
        assertEquals(good, win(vcert()))
        assertEquals(good, win(vcert(version = false)))
        assertEquals(good, win(vcert(subject = false)))
        assertEquals(good, win(vcert(version = false, subject = false)))
        val bad = "false:0/false:0"
        assertEquals(bad, win(vcert(outer = 0x31)))
        assertEquals(bad, win(vcert(tbsTag = 0x31)))
        assertEquals(bad, win(vcert(serial = 0x03)))
        assertEquals(bad, win(vcert(alg = 0x31)))
        assertEquals(bad, win(vcert(issuer = 0x31)))
        assertEquals(bad, win(vcert(validity = t(0x31, time(nb), time(na)))))
        assertEquals(bad, win(vcert(validity = t(0x30, time(nb), time(na), time(na)))))
        assertEquals(bad, win(vcert(validity = t(0x30, time(nb)))))
        assertEquals(bad, win(vcert(subject = false, shortTbs = true)))
        assertEquals(bad, win(b(0x30)))
        assertEquals(bad, win(ByteArray(0)))
        assertEquals("false:0/true:$to", win(vcert(validity = t(0x30, time("x"), time(na)))))
        assertEquals("true:$from/false:0", win(vcert(validity = t(0x30, time(nb), time("251301000000Z")))))
        assertEquals("true:$from/true:$to", win(vcert(validity = t(0x30, time(nb), t(0x18, "20491231235959Z".toByteArray())))))
    }

    @Test
    fun validAt() {
        val c = vcert()
        assertTrue(AttestDer.derValidAt(c, from))
        assertTrue(AttestDer.derValidAt(c, to))
        assertFalse(AttestDer.derValidAt(c, from - 1))
        assertFalse(AttestDer.derValidAt(c, to + 1))
        assertTrue(AttestDer.derValidAt(c, from - 10, 10))
        assertFalse(AttestDer.derValidAt(c, from - 11, 10))
        assertTrue(AttestDer.derValidAt(c, to + 10, 10))
        assertFalse(AttestDer.derValidAt(c, to + 11, 10))
        assertTrue(AttestDer.derValidAt(c, from, 0))
        // an unparseable bound fails closed whatever the clock and skew
        val badFrom = vcert(validity = t(0x30, time("x"), time(na)))
        val badTo = vcert(validity = t(0x30, time(nb), time("x")))
        for (x in listOf(badFrom, badTo, b(0x30))) {
            assertFalse(AttestDer.derValidAt(x, from + 1000, 1L shl 50))
            assertFalse(AttestDer.derValidAtF(x, (from + 1000), 1e15))
        }
        assertTrue(AttestDer.derValidAtF(c, from, 0.0))
        assertTrue(AttestDer.derValidAtF(c, to, 0.0))
        assertFalse(AttestDer.derValidAtF(c, from - 1, 0.0))
        assertFalse(AttestDer.derValidAtF(c, to + 1, 0.0))
        assertTrue(AttestDer.derValidAtF(c, from - 10, 10.0))
        assertFalse(AttestDer.derValidAtF(c, from - 11, 10.0))
        assertTrue(AttestDer.derValidAtF(c, to + 10, 10.0))
        assertFalse(AttestDer.derValidAtF(c, to + 11, 10.0))
        assertFalse(AttestDer.derValidAtF(c, from - 1, 0.5))
        assertFalse(AttestDer.derValidAtF(c, to + 1, 0.5))
        assertTrue(AttestDer.derValidAtF(c, to + 1, 1.0))
    }

    @Test
    fun strictChainErrorParseFailure() {
        // the role reader skips duplicate non-role extensions, so the critical-extension walk is what refuses this one
        val v = t(0x04, b(1))
        val dup = cert(ext(b(0x2a, 3, 4), v), ext(b(0x2a, 3, 4), v))
        assertEquals("certificate extension parse failed: duplicate extension 1.2.3.4", AttestDer.strictChainError(listOf(dup)))
    }
}
