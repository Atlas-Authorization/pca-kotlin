package net.atlasauth.pca.verifier

import java.time.LocalDateTime
import java.time.ZoneOffset
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Intel TDX readers: the DCAP quote layout, the SGX extension scan, the lenient DER / CRL readers, DER times, PCS JSON documents. */
class Kill05IntelMeshAttestIntelParseTest {
    private val k = Kill05GcpAmdKit
    private val x = Kill05IntelMeshKit
    private val sgx = Kill05IntelMeshKit.SGX

    private fun <T> p(name: String, vararg a: Any?): T = KUtil.priv(AttestIntel, name, *a)
    private fun err(f: () -> Any?): String = Kill05CertKit.err(f)
    private fun ms(y: Int, mo: Int, d: Int, h: Int, mi: Int, s: Int): Long = LocalDateTime.of(y, mo, d, h, mi, s).toEpochSecond(ZoneOffset.UTC) * 1000

    // ---- the quote layout ----

    private fun rawQuote(sig: ByteArray): ByteArray {
        val h = ByteArray(48)
        h[0] = 4
        h[2] = 2
        h[4] = 0x81.toByte()
        return h + ByteArray(584) + x.le(sig.size.toLong(), 4) + sig
    }

    /** Signature data of n bytes whose outer cert-data type is 6 (size 0); the quote ends exactly where it does. */
    private fun sig(n: Int): ByteArray = ByteArray(n).also { if (n > 128) it[128] = 6 }

    private fun pq(sigData: ByteArray): String = err { AttestIntel.parseQuote(rawQuote(sigData)) }

    @Test fun quoteLayoutBoundaries() {
        val t = "parseDcapQuote: truncated reading "
        assertEquals(636, rawQuote(ByteArray(0)).size)
        assertEquals(t + "quote signature", pq(ByteArray(0)))
        assertEquals(t + "outer cert-data header", pq(sig(128)))
        assertEquals(t + "QE report", pq(sig(134)))
        assertEquals(t + "QE report", pq(sig(134 + 383)))
        assertEquals(t + "QE report signature", pq(sig(134 + 384)))
        assertEquals(t + "QE report signature", pq(sig(134 + 384 + 63)))
        assertEquals(t + "QE auth-data size", pq(sig(134 + 448)))
        assertEquals(t + "QE auth-data size", pq(sig(134 + 448 + 1)))
        assertEquals(t + "inner cert-data header", pq(sig(134 + 448 + 2 + 5)))
        assertEquals("parseDcapQuote: inner cert-data type 0 (expected PCK-cert-chain = 5)", pq(sig(134 + 448 + 2 + 6)))
    }

    // ---- the SGX extension (byte scan) ----

    private fun tlvText(t: AttestDer.Tlv?): String? = if (t == null) null else "${t.tag}/${t.start}/${t.end}"

    @Test fun lenientTlvReader() {
        fun rt(b: ByteArray, off: Int): String? = tlvText(p<AttestDer.Tlv?>("readTlvLenient", b, off))
        assertEquals("4/2/2", rt(k.bytes(4, 0), 0))
        assertNull(rt(k.bytes(0x30), 0))
        assertNull(rt(k.bytes(4, 0), -1))
        assertEquals("4/6/7", rt(k.bytes(4, 0x84, 0, 0, 0, 1, 0xaa), 0))
        assertNull(rt(k.bytes(4, 0x85, 0, 0, 0, 0, 1, 0xaa), 0))
        assertNull(rt(k.bytes(4, 0x80, 0), 0))
        assertNull(rt(k.bytes(4, 0x81), 0))
        assertEquals("4/3/3", rt(k.bytes(4, 0x81, 0), 0))
        assertNull(rt(k.bytes(4, 2, 0), 0))
    }

    @Test fun byteScan() {
        assertEquals(0, p<Int>("indexOfBytes", k.bytes(1, 2, 3), k.bytes(1, 2, 3)))
        assertEquals(-1, p<Int>("indexOfBytes", k.bytes(9, 2, 3), k.bytes(1, 2, 3)))
        assertEquals(1, p<Int>("indexOfBytes", k.bytes(9, 1, 2), k.bytes(1, 2)))
    }

    private val fm = k.bytes(0, 0x90, 0x6e, 0xd5, 0, 0)

    private fun comp(last: Int, v: ByteArray): ByteArray = k.seq(k.oid("$sgx.2.$last"), v)

    /** FMSPC first (at index 0), then the TCB SEQUENCE, then `after` (a stray TLV past the SEQUENCE by default). */
    private fun leaf(comps: List<ByteArray>, after: ByteArray = k.bytes(5, 0)): ByteArray =
        k.cat(k.oid("$sgx.4"), k.tlv(4, fm), k.oid("$sgx.2"), k.seq(*comps.toTypedArray()), after)

    private fun svn16(): List<ByteArray> = (1..16).map { comp(it, k.integer((10 + it).toLong())) }

    private fun ex(l: ByteArray): String = err { AttestIntel.extractPckFmspcAndTcb(l) }

    @Test fun sgxExtensionScan() {
        val all = svn16() + comp(0, k.integer(99)) + comp(18, k.tlv(4, k.bytes(7))) + comp(17, k.integer(258))
        val t = AttestIntel.extractPckFmspcAndTcb(leaf(all))
        assertArrayEquals(fm, t.fmspc)
        assertEquals(16, t.sgx.size)
        assertArrayEquals(ByteArray(16) { (11 + it).toByte() }, t.sgx)
        assertEquals(258, t.pcesvn)
        assertEquals(0, AttestIntel.extractPckFmspcAndTcb(leaf(svn16() + comp(17, k.integer(0)))).pcesvn)

        val pre = "extractPckFmspcAndTcb: "
        assertEquals(pre + "malformed TCB SEQUENCE", ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm), k.oid("$sgx.2"), k.tlv(0x31, k.integer(1)))))
        assertEquals(pre + "malformed TCB SEQUENCE", ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm), k.oid("$sgx.2"))))
        assertEquals(pre + "malformed TCB component", ex(leaf(listOf(k.integer(1)))))
        // a component header that overruns the buffer reads as no component at all
        assertEquals(pre + "malformed TCB component", ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm), k.oid("$sgx.2"), k.tlv(0x30, k.bytes(0x30, 5)))))
        assertEquals(pre + "TCB component missing OID", ex(leaf(listOf(k.seq(k.integer(1), k.integer(1))))))
        assertEquals(pre + "TCB component missing value", ex(leaf(listOf(k.seq(k.oid("$sgx.2.17"))), ByteArray(0))))
        assertEquals(pre + "PCESVN not found in TCB extension", ex(leaf(svn16() + comp(17, k.tlv(4, k.bytes(13))))))

        // at most 65 components are read
        val dummies = (1..64).map { comp(99, k.integer(1)) }
        assertEquals(258, AttestIntel.extractPckFmspcAndTcb(leaf(dummies + comp(17, k.integer(258)))).pcesvn)
        assertEquals(pre + "PCESVN not found in TCB extension", ex(leaf(dummies + comp(99, k.integer(1)) + comp(17, k.integer(258)))))
    }

    // ---- CRL DER ----

    @Test fun crlTlvReader() {
        fun tl(b: ByteArray, limit: Int): String = try {
            tlvText(p<AttestDer.Tlv>("tlvLenient", b, 0, limit)) ?: ""
        } catch (e: AttErr) {
            e.message ?: ""
        }
        assertEquals("2/2/2", tl(k.bytes(2, 0), 2))
        assertEquals("DER truncated", tl(k.bytes(0x30), 1))
        assertEquals("DER bad length", tl(k.bytes(4, 0x80, 0), 3))
        assertEquals("DER bad length", tl(k.bytes(4, 0x85, 0, 0, 0, 0, 1, 0xaa), 8))
        assertEquals("4/6/7", tl(k.bytes(4, 0x84, 0, 0, 0, 1, 0xaa), 7))
        assertEquals("DER bad length", tl(k.bytes(4, 0x82, 0, 1, 0xaa), 3))
        assertEquals("DER overrun", tl(k.bytes(4, 2, 0, 0), 3))
        assertEquals("4/2/3", tl(k.bytes(4, 1, 0xaa, 0xbb), 3))
    }

    @Test fun dateUtcYears() {
        assertEquals(ms(1900, 1, 1, 0, 0, 0), AttestIntel.dateUtc(0, 1, 1, 0, 0, 0))
        assertEquals(ms(1999, 1, 1, 0, 0, 0), AttestIntel.dateUtc(99, 1, 1, 0, 0, 0))
        assertEquals(ms(100, 1, 1, 0, 0, 0), AttestIntel.dateUtc(100, 1, 1, 0, 0, 0))
        assertEquals(ms(-1, 1, 1, 0, 0, 0), AttestIntel.dateUtc(-1, 1, 1, 0, 0, 0))
        assertEquals(946684800000L + 3_723_000L, AttestIntel.dateUtc(2000, 1, 1, 1, 2, 3))
    }

    @Test fun derTimes() {
        fun ct(der: ByteArray): Any = try {
            p<Long>("crlTime", der, AttestDer.Tlv(der[0].toInt() and 0xff, 2, der.size))
        } catch (e: AttErr) {
            e.message ?: ""
        }
        assertEquals(ms(2049, 12, 31, 23, 59, 58), ct(x.utc("491231235958Z")))
        assertEquals(ms(1950, 1, 2, 3, 4, 5), ct(x.utc("500102030405Z")))
        assertEquals(ms(2035, 6, 15, 12, 34, 56), ct(x.gen("20350615123456Z")))
        assertEquals("bad UTCTime", ct(x.utc("4912312359Z")))
        assertEquals("bad GeneralizedTime", ct(x.gen("2035061512Z")))
        assertEquals("not a DER time", ct(k.tlv(4, "491231235958Z".toByteArray(Charsets.US_ASCII))))
    }

    private val kp = k.ecKey("secp256r1")
    private val key = AttestCert.keyOfSpki(kp.public.encoded)
    private val v1 = k.integer(1)
    private val iss = x.name("Intel SGX Root CA")
    private val tu = x.utc(Kill05GcpAmdKit.NB)
    private val nu = x.utc(Kill05GcpAmdKit.NA)

    private fun crl(vararg tbs: ByteArray): ByteArray = x.crlOf(k.seq(*tbs), kp)

    private fun vc(der: ByteArray, now: Long = Kill05GcpAmdKit.NOW, ck: AttestCert.CertKey = key): String {
        val r = AttestIntel.verifyCrl(der, ck, now)
        val set = r.first
        return if (r.second == "" && set != null) "ok:" + set.sorted().joinToString(",") else r.second
    }

    @Test fun crlReader() {
        val nb = Kill05GcpAmdKit.NB_MS
        val na = Kill05GcpAmdKit.NA_MS
        val full = crl(v1, x.ALG, iss, tu, nu, x.revoked(258, 255))
        assertEquals("ok:102,ff", vc(full))
        assertEquals("ok:102,ff", vc(full, nb))
        assertEquals("ok:102,ff", vc(full, na))
        assertEquals("CRL thisUpdate is in the future", vc(full, nb - 1))
        assertEquals("CRL is stale (nextUpdate passed)", vc(full, na + 1))
        assertEquals("ok:", vc(crl(x.ALG, iss, tu, nu)))
        val g = crl(v1, x.ALG, iss, tu, x.gen("20350101000000Z"))
        assertEquals("ok:", vc(g, na))
        assertEquals("CRL is stale (nextUpdate passed)", vc(g, na + 1))

        val pre = "CRL parse failed: "
        assertEquals(pre + "CRL: missing nextUpdate", vc(crl(v1, x.ALG, iss, tu)))
        assertEquals(pre + "CRL: missing nextUpdate", vc(crl(v1, x.ALG, iss, tu, x.revoked(1))))
        assertEquals(pre + "CRL: bad outer SEQUENCE", vc(k.bytes(0x31, 0)))
        assertEquals(pre + "CRL: bad outer SEQUENCE", vc(full + k.bytes(0)))
        assertEquals(pre + "CRL: bad TBSCertList", vc(k.seq(k.tlv(0x31), x.ALG, k.bits(0, k.bytes(1)))))
        val tbs = k.seq(v1, x.ALG, iss, tu, nu)
        val s = x.ecSign(kp, tbs)
        assertEquals(pre + "CRL: bad signature", vc(k.seq(tbs, x.ALG, k.tlv(4, s))))
        assertEquals(pre + "CRL: bad signature", vc(k.seq(tbs, x.ALG, k.bits(0, s), k.integer(1))))
        assertEquals("ok:", vc(k.seq(tbs, x.ALG, k.bits(0, s))))
        // an empty BIT STRING: no signature bytes at all
        assertEquals("CRL signature does not verify under the issuer", vc(k.seq(tbs, x.ALG, k.tlv(3))))
        assertEquals(pre + "CRL: bad issuer", vc(crl(v1, x.ALG, k.tlv(0x31), tu, nu)))
        assertEquals(pre + "CRL: bad revoked entry", vc(crl(v1, x.ALG, iss, tu, nu, k.seq(k.seq(k.tlv(4, k.bytes(1)), tu)))))
    }

    @Test fun crlSignatureKinds() {
        val rsa = k.rsaKey()
        val rk = AttestCert.keyOfSpki(rsa.public.encoded)
        val tbs = k.seq(v1, x.ALG, iss, tu, nu)
        val good = x.ecSign(rsa, tbs, "SHA256withRSA")
        assertEquals("ok:", vc(k.seq(tbs, x.ALG, k.bits(0, good)), ck = rk))
        val bad = good.copyOf()
        bad[10] = (bad[10].toInt() xor 1).toByte()
        val no = "CRL signature does not verify under the issuer"
        assertEquals(no, vc(k.seq(tbs, x.ALG, k.bits(0, bad)), ck = rk))
        // a wrong-length RSA signature makes the JCA verifier throw: still just "does not verify"
        assertEquals(no, vc(k.seq(tbs, x.ALG, k.bits(0, k.bytes(1, 2, 3, 4, 5))), ck = rk))
        // a key that is neither EC nor RSA never verifies a CRL
        val ed = AttestCert.keyOfSpki(java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded)
        assertEquals(no, vc(crl(v1, x.ALG, iss, tu, nu), ck = ed))
    }

    // ---- PCS JSON documents ----

    @Test fun jsSpaceSkip() {
        assertEquals(2, p<Int>("skipJsSpace", "  x", 0))
        assertEquals(0, p<Int>("skipJsSpace", "", 0))
        assertEquals(2, p<Int>("skipJsSpace", "  ", 0))
        assertEquals(1, p<Int>("skipJsSpace", " x", 0))
        assertEquals(0, p<Int>("skipJsSpace", "x ", 0))
        assertEquals(3, p<Int>("skipJsSpace", "x  ", 1))
    }

    @Test fun rawObjectScan() {
        fun rj(t: String): String? = p<String?>("rawJsonObject", t, "tcbInfo")
        assertEquals("{\"a\":\"}\\\"{\"}", rj(" {\"tcbInfo\" : {\"a\":\"}\\\"{\"},\"signature\":\"x\"}"))
        assertEquals("{}", rj("{ \"tcbInfo\":{}}"))
        assertEquals("{}", rj("{\"tcbInfo\" :{}}"))
        assertEquals("{}", rj("{\"tcbInfo\": {}}"))
        assertEquals("{\"b\":{}}", rj("{\"tcbInfo\":{\"b\":{}}}"))
        val none = listOf(
            "", "   ", "[", "{", "{\"other\":{}}", "{\"tcbInfo\"", "{\"tcbInfo\"x{}}", "{\"tcbInfo\":", "{\"tcbInfo\":[1]}",
            "{\"tcbInfo\":x{}}", "{\"tcbInfo\":{", "{\"tcbInfo\":{\"a\":\"}",
        )
        for (t in none) assertNull(t, rj(t))
    }

    @Test fun signedJson() {
        val tk = AttestCert.keyOfSpki(kp.public.encoded)
        fun sig(body: String): String = x.hex(k.signRaw(kp, "SHA256withECDSA", body.toByteArray(Charsets.UTF_8), 32))
        val body = "{\"id\":\"TDX\"}"
        val ok = AttestIntel.verifySignedJson("{\"tcbInfo\":" + body + ",\"signature\":\"" + sig(body) + "\"}", "tcbInfo", tk)
        assertEquals("", ok.second)
        assertEquals("TDX", ok.first!!["id"])
        val notJson = AttestIntel.verifySignedJson("{\"tcbInfo\":{}", "tcbInfo", tk)
        assertNull(notJson.first)
        assertEquals("tcbInfo document is not valid JSON", notJson.second)
        assertEquals("tcbInfo signature missing or malformed", AttestIntel.verifySignedJson("{\"tcbInfo\":{},\"signature\":5}", "tcbInfo", tk).second)
        val rsa = AttestCert.keyOfSpki(k.rsaKey().public.encoded)
        assertEquals("tcbInfo signature does not verify under the TCB Signing certificate",
            AttestIntel.verifySignedJson("{\"tcbInfo\":{},\"signature\":\"" + "ab".repeat(64) + "\"}", "tcbInfo", rsa).second)
        // the signed text is the first member and the body comes from it; a later duplicate (the parser keeps the last) changes nothing
        for (later in listOf("1", "{\"id\":\"FORGED\"}")) {
            val dup = AttestIntel.verifySignedJson("{\"tcbInfo\":" + body + ",\"tcbInfo\":" + later + ",\"signature\":\"" + sig(body) + "\"}", "tcbInfo", tk)
            assertEquals("", dup.second)
            assertEquals("TDX", dup.first!!["id"])
        }
    }

    @Test fun pcsDates() {
        assertEquals(ms(2027, 1, 15, 8, 0, 0), p<Long?>("jsDateParse", "2027-01-15T08:00:00Z"))
        assertEquals(ms(2027, 1, 15, 0, 0, 0), p<Long?>("jsDateParse", "2027-01-15"))
        assertNull(p<Long?>("jsDateParse", "soon"))
    }

    @Test fun freshness() {
        fun cf(i: Any?, n: Any?, now: Long): String {
            val b = LinkedHashMap<String, Any?>()
            if (i != null) b["issueDate"] = i
            if (n != null) b["nextUpdate"] = n
            return p("checkFresh", b, "TCB info", now)
        }
        val i = "2027-01-01T00:00:00Z"
        val n = "2027-02-01T00:00:00Z"
        val iMs = ms(2027, 1, 1, 0, 0, 0)
        val nMs = ms(2027, 2, 1, 0, 0, 0)
        assertEquals("", cf(i, n, iMs))
        assertEquals("", cf(i, n, nMs))
        assertEquals("TCB info: issueDate is in the future", cf(i, n, iMs - 1))
        assertEquals("TCB info: stale (nextUpdate passed)", cf(i, n, nMs + 1))
        val bad: List<Pair<Any?, Any?>> = listOf(null to n, i to null, Json.Num("5") to n, i to Json.Num("5"), "soon" to n, i to "soon")
        for ((a, b) in bad) assertEquals("$a/$b", "TCB info: issueDate/nextUpdate missing", cf(a, b, iMs))
        assertTrue(cf(i, n, iMs).isEmpty())
    }

    @Test fun quoteEndingRightAfterTheAuthDataSize() {
        // exactly the 2-byte QE auth-data size is left (size 0): the next read is the inner cert-data header
        assertEquals("parseDcapQuote: truncated reading inner cert-data header", pq(sig(134 + 448 + 2)))
        assertEquals("parseDcapQuote: truncated reading inner cert-data header", pq(sig(134 + 448 + 3)))
    }

    @Test fun lengthsThatWrapAroundAreRefused() {
        // a 4-byte length of 0xffffffff (or 0x80000000) overflows a 32-bit int: refused, not read backwards
        fun rt(b: ByteArray): String? = tlvText(p<AttestDer.Tlv?>("readTlvLenient", b, 0))
        assertNull(rt(k.bytes(4, 0x84, 0xff, 0xff, 0xff, 0xff)))
        assertNull(rt(k.bytes(4, 0x84, 0x80, 0, 0, 0)))
        assertNull(rt(k.bytes(4, 0x84, 0xff, 0xff, 0xff, 0xfe, 0xaa)))
        fun tl(b: ByteArray, limit: Int): String = try {
            tlvText(p<AttestDer.Tlv>("tlvLenient", b, 0, limit)) ?: ""
        } catch (e: AttErr) {
            e.message ?: ""
        }
        assertEquals("DER overrun", tl(k.bytes(4, 0x84, 0xff, 0xff, 0xff, 0xff), 6))
        assertEquals("DER overrun", tl(k.bytes(4, 0x84, 0x80, 0, 0, 0), 6))
        assertEquals("DER overrun", tl(k.bytes(4, 0x84, 0xff, 0xff, 0xff, 0xfe, 0xaa), 7))
        // the length bytes may end exactly at the limit
        assertEquals("4/3/3", tl(k.bytes(4, 0x81, 0), 3))
        assertEquals("4/6/6", tl(k.bytes(4, 0x84, 0, 0, 0, 0), 6))
    }

    @Test fun fmspcAndTcbOidPlacement() {
        val pre = "extractPckFmspcAndTcb: "
        val tcb = k.seq(*(svn16() + comp(17, k.integer(7))).toTypedArray())
        // the TCB OID at offset 0, the FMSPC after it
        val first = AttestIntel.extractPckFmspcAndTcb(k.cat(k.oid("$sgx.2"), tcb, k.oid("$sgx.4"), k.tlv(4, fm)))
        assertEquals(7, first.pcesvn)
        assertArrayEquals(fm, first.fmspc)
        assertEquals(pre + "FMSPC OID not found in certificate", ex(k.cat(k.oid("$sgx.2"), tcb)))
        assertEquals(pre + "TCB OID not found in certificate", ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm))))
        val badFmspc = pre + "malformed FMSPC OCTET STRING"
        // nothing after the FMSPC OID
        assertEquals(badFmspc, ex(k.cat(k.oid("$sgx.2"), tcb, k.oid("$sgx.4"))))
        // six bytes, but not an OCTET STRING
        assertEquals(badFmspc, ex(k.cat(k.oid("$sgx.4"), k.tlv(2, fm), k.oid("$sgx.2"), tcb)))
        assertEquals(badFmspc, ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm.copyOfRange(0, 5)), k.oid("$sgx.2"), tcb)))
        assertEquals(badFmspc, ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm + k.bytes(0)), k.oid("$sgx.2"), tcb)))
        // an empty component SEQUENCE as the last bytes: no OID can be read after it
        assertEquals(pre + "TCB component missing OID", ex(k.cat(k.oid("$sgx.4"), k.tlv(4, fm), k.oid("$sgx.2"), k.seq(k.seq()))))
    }

    @Test fun rawObjectNeedsTheOpeningBraceAndTheExactKey() {
        fun rj(t: String): String? = p<String?>("rawJsonObject", t, "tcbInfo")
        assertNull(rj("[\"tcbInfo\":{}}"))
        assertNull(rj("x\"tcbInfo\":{}}"))
        // a key of the same length is not the key
        assertNull(rj("{\"abcdefg\":{}}"))
        assertNull(rj("{\"tcbinfo\":{}}"))
        assertEquals("{}", rj("{\"tcbInfo\":{}}"))
    }
}
