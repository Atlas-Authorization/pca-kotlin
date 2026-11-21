package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.SignatureException
import java.security.SignatureSpi
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verdict of the test-only NONEwithECDSA provider: true / false, or null to refuse the key (a provider that cannot run). */
object K05XmlFake {
    @Volatile var mode: Boolean? = true
    val data = java.io.ByteArrayOutputStream()
    @Volatile var sig: ByteArray? = null
}

/** A NONEwithECDSA that records what it is handed and answers [K05XmlFake.mode]: it isolates ecdsaVerify's own guards. */
class K05XmlFakeEcdsaSpi : SignatureSpi() {
    override fun engineInitVerify(publicKey: PublicKey?) {
        if (K05XmlFake.mode == null) throw InvalidKeyException("k05 fake: refuses every key")
    }

    override fun engineInitSign(privateKey: PrivateKey?) {
        throw InvalidKeyException("k05 fake: verify only")
    }

    override fun engineUpdate(b: Byte) {
        K05XmlFake.data.write(b.toInt())
    }

    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        K05XmlFake.data.write(b!!, off, len)
    }

    override fun engineSign(): ByteArray = throw SignatureException("k05 fake: verify only")
    override fun engineVerify(sigBytes: ByteArray?): Boolean {
        K05XmlFake.sig = sigBytes
        return K05XmlFake.mode!!
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun engineSetParameter(param: String?, value: Any?) {}

    @Suppress("OVERRIDE_DEPRECATION")
    override fun engineGetParameter(param: String?): Any? = null
}

class K05XmlFakeProvider : Provider("K05XmlFake", "1.0", "test-only NONEwithECDSA") {
    init {
        put("Signature.NONEwithECDSA", K05XmlFakeEcdsaSpi::class.java.name)
    }
}

/** Hex / JS text / base64 / JSON access / raw ECDSA (DER parse, range guards, provider fallbacks) / curves / the Azure binding. */
class Kill05XmlAttestUtilTest {
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun big(s: String) = BigInteger(s, 16)

    @Test
    fun hashesAndHex() {
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", AttestUtil.hex(AttestUtil.sha1("abc".toByteArray())))
        assertArrayEquals(b(0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef), AttestUtil.hexDecodeLoose("0123456789abcdefABCDEF"))
        assertArrayEquals(b(0x09, 0x90, 0xaf, 0xfa, 0xAF, 0xFA), AttestUtil.hexDecodeLoose("0990affaAFFA"))
        assertArrayEquals(b(0xab), AttestUtil.hexDecodeLoose("abc"))
        assertArrayEquals(ByteArray(0), AttestUtil.hexDecodeLoose(""))
        assertArrayEquals(ByteArray(0), AttestUtil.hexDecodeLoose("z"))
        for (s in listOf("/0", ":0", "`0", "g0", "@0", "G0", "0/", "0:", "0`", "0g", "0@", "0G", "zz", "00zz", " 0"))
            assertNull(s, AttestUtil.hexDecodeLoose(s))
        assertFalse(AttestUtil.isHexString(""))
        assertFalse(AttestUtil.isHexString("a"))
        assertFalse(AttestUtil.isHexString("abc"))
        assertTrue(AttestUtil.isHexString("aB"))
        assertTrue(AttestUtil.isHexString("09fF"))
        assertFalse(AttestUtil.isHexString("zz"))
        assertFalse(AttestUtil.isHexString("0x"))
        assertFalse(AttestUtil.isHexText(""))
        assertTrue(AttestUtil.isHexText("a"))
        assertTrue(AttestUtil.isHexText("abc"))
        assertFalse(AttestUtil.isHexText("zz"))
        assertFalse(AttestUtil.isHexText("ab "))
    }

    @Test
    fun jsSpace() {
        val yes = listOf(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x2001, 0x2005, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff)
        for (c in yes) assertTrue(Integer.toHexString(c), AttestUtil.isJsSpace(c))
        val no = listOf(0x00, 0x08, 0x0e, 0x1f, 0x21, 0x41, 0x85, 0x9f, 0xa1, 0x167f, 0x1681, 0x180e, 0x1fff, 0x200b, 0x2027, 0x202a, 0x202e, 0x2030, 0x205e, 0x2060, 0x2fff, 0x3001, 0xfefe, 0xff00)
        for (c in no) assertFalse(Integer.toHexString(c), AttestUtil.isJsSpace(c))
        assertEquals("a b", AttestUtil.jsTrim("　 a b\t\n﻿"))
        assertEquals("a", AttestUtil.jsTrim("a"))
        assertEquals("", AttestUtil.jsTrim("   "))
        assertEquals("", AttestUtil.jsTrim(" "))
        assertEquals("", AttestUtil.jsTrim(""))
        assertEquals("x\u0085", AttestUtil.jsTrim(" x\u0085"))
        assertEquals("abc", AttestUtil.stripJsSpace(" a b﻿c "))
        assertEquals("a​b", AttestUtil.stripJsSpace("a​b"))
        assertEquals("", AttestUtil.stripJsSpace(" \t"))
    }

    @Test
    fun base64() {
        fun h(s: String) = AttestUtil.hex(AttestUtil.nodeB64(s))
        assertEquals("414243", h("QUJD"))
        assertEquals("414243", h("QU[JD"))
        assertEquals("414243", h("Q{UJD"))
        assertEquals("414243", h("QU:JD"))
        assertEquals("414243", h("Q`U@JD"))
        assertEquals("414243", h(" Q\nU J\tD "))
        assertEquals("659659", h("ZZZZ"))
        assertEquals("cf3cf3", h("zzzz"))
        assertEquals("f7df7d", h("9999"))
        assertEquals("d34d34", h("0000"))
        assertEquals("000000", h("AAAA"))
        assertEquals("313233", h("MTIz"))
        assertEquals("616263", h("YWJj"))
        assertEquals("fbffbf", h("+/+/"))
        assertEquals("fbffbf", h("-_-_"))
        assertEquals("41", h("QQ==QUJD"))
        assertEquals("4142", h("QUI"))
        assertEquals("", h("Q"))
        assertEquals("", h(""))
        assertArrayEquals("AB".toByteArray(), AttestUtil.base64Std("QUI="))
        assertArrayEquals("ABC".toByteArray(), AttestUtil.base64Std("QUJD"))
        assertArrayEquals(ByteArray(0), AttestUtil.base64Std(""))
        assertNull(AttestUtil.base64Std("QUI"))
        assertNull(AttestUtil.base64Std("QUJDR"))
        assertNull(AttestUtil.base64Std("!!!!"))
        assertNull(AttestUtil.base64Std("-_-_"))
        assertArrayEquals(b(0xab, 0xcd), AttestUtil.decodeClaimBytes(" 0xABcd "))
        assertArrayEquals("ABC".toByteArray(), AttestUtil.decodeClaimBytes("QUJD"))
        assertNull(AttestUtil.decodeClaimBytes(" "))
        assertNull(AttestUtil.evBytes(null, "k"))
        assertNull(AttestUtil.evBytes(mapOf("k" to 1), "k"))
        assertNull(AttestUtil.evBytes(mapOf("j" to "QUJD"), "k"))
        assertArrayEquals("ABC".toByteArray(), AttestUtil.evBytes(mapOf("k" to "QUJD"), "k"))
        assertNull(AttestUtil.evString(null, "k"))
        assertNull(AttestUtil.evString(mapOf("k" to 1), "k"))
        assertEquals("v", AttestUtil.evString(mapOf("k" to "v"), "k"))
    }

    @Test
    fun jsonAccess() {
        assertEquals(listOf("abc", "ä", ""), AttestUtil.lowerAll(listOf("AbC", "Ä", "")))
        assertEquals(emptyList<String>(), AttestUtil.lowerAll(emptyList()))
        assertEquals("x", AttestUtil.asStr("x"))
        assertNull(AttestUtil.asStr(1))
        assertNull(AttestUtil.asStr(null))
        assertEquals(1.5, AttestUtil.asFinite(Json.Num("1.5"))!!, 0.0)
        assertEquals(-2.0, AttestUtil.asFinite(Json.Num("-2"))!!, 0.0)
        assertNull(AttestUtil.asFinite(Json.Num("x")))
        assertNull(AttestUtil.asFinite(Json.Num("1e999")))
        assertNull(AttestUtil.asFinite(Json.Num("NaN")))
        assertEquals(2.5, AttestUtil.asFinite(2.5)!!, 0.0)
        assertEquals(1.5, AttestUtil.asFinite(1.5f)!!, 0.0)
        assertEquals(3.0, AttestUtil.asFinite(3)!!, 0.0)
        assertEquals(4.0, AttestUtil.asFinite(4L)!!, 0.0)
        assertEquals(-7.0, AttestUtil.asFinite(-7)!!, 0.0)
        for (x in listOf<Any?>("5", null, true, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Float.NaN, Float.POSITIVE_INFINITY, listOf(1)))
            assertNull(x.toString(), AttestUtil.asFinite(x))
        assertEquals(listOf("a", "b"), AttestUtil.asStrList(listOf("a", "b")))
        assertEquals(emptyList<String>(), AttestUtil.asStrList(emptyList<Any>()))
        assertNull(AttestUtil.asStrList(listOf("a", 1)))
        assertNull(AttestUtil.asStrList(listOf(null)))
        assertNull(AttestUtil.asStrList("a"))
        assertNull(AttestUtil.asStrList(null))
        assertEquals(listOf("a", "b"), AttestUtil.anyStrings(listOf(1, "a", null, "b", listOf("c"))))
        assertEquals(emptyList<String>(), AttestUtil.anyStrings(listOf(1)))
        assertEquals(emptyList<String>(), AttestUtil.anyStrings("a"))
        assertEquals(emptyList<String>(), AttestUtil.anyStrings(null))
        assertEquals(2, AttestUtil.listLen(listOf(1, 2)))
        assertEquals(3, AttestUtil.listLen("abc"))
        assertEquals(0, AttestUtil.listLen(""))
        assertEquals(0, AttestUtil.listLen(5))
        assertEquals(0, AttestUtil.listLen(null))
        assertEquals("s", AttestUtil.jsAnyString("s"))
        assertEquals("", AttestUtil.jsAnyString(""))
        assertEquals("true", AttestUtil.jsAnyString(true))
        assertEquals("false", AttestUtil.jsAnyString(false))
        assertEquals("3", AttestUtil.jsAnyString(3.0))
        assertEquals("-4", AttestUtil.jsAnyString(-4))
        assertEquals("2", AttestUtil.jsAnyString(Json.Num("2")))
        assertEquals("1.5", AttestUtil.jsAnyString(1.5))
        assertEquals("null", AttestUtil.jsAnyString(null))
        assertEquals("[1]", AttestUtil.jsAnyString(listOf(1)))
        assertEquals("x", AttestUtil.jsAnyString(Json.Num("x")))
        assertEquals(0.0, AttestUtil.skewOf(emptyMap()), 0.0)
        assertEquals(0.0, AttestUtil.skewOf(mapOf("clockSkewMs" to -5.0)), 0.0)
        assertEquals(7.0, AttestUtil.skewOf(mapOf("clockSkewMs" to 7.0)), 0.0)
        assertEquals(0.0, AttestUtil.skewOf(mapOf("clockSkewMs" to "7")), 0.0)
        assertEquals("m", AttestUtil.errMsg(RuntimeException("m")))
        assertEquals("invalid", AttestUtil.errMsg(RuntimeException()))
        assertEquals("invalid", AttestUtil.errMsg(null))
    }

    // ---- raw ECDSA ----
    private fun dlen(n: Int): ByteArray {
        if (n < 0x80) return b(n)
        var k = n
        var out = ByteArray(0)
        while (k > 0) {
            out = b(k and 0xff) + out
            k = k ushr 8
        }
        return b(0x80 or out.size) + out
    }

    private fun intT(c: ByteArray) = b(0x02) + dlen(c.size) + c
    private fun seq(body: ByteArray) = b(0x30) + dlen(body.size) + body
    private fun pos(n: Int) = ByteArray(n).also { it[0] = 1 }

    @Test
    fun derSig() {
        assertArrayEquals(b(0x30, 6, 2, 1, 1, 2, 1, 2), AttestUtil.derSig(BigInteger.ONE, BigInteger.TWO))
        assertArrayEquals(b(0x30, 8, 2, 2, 0, 0x80, 2, 2, 0, 0xff), AttestUtil.derSig(BigInteger.valueOf(128), BigInteger.valueOf(255)))
        val r = BigInteger.ONE.shiftLeft(490)
        val s = BigInteger.ONE.shiftLeft(482)
        assertEquals(62, r.toByteArray().size)
        assertEquals(61, s.toByteArray().size)
        val b127 = b(2, 62) + r.toByteArray() + b(2, 61) + s.toByteArray()
        assertArrayEquals(b(0x30, 127) + b127, AttestUtil.derSig(r, s))
        val b128 = b(2, 62) + r.toByteArray() + b(2, 62) + r.toByteArray()
        assertArrayEquals(b(0x30, 0x81, 128) + b128, AttestUtil.derSig(r, r))
        val big = BigInteger.ONE.shiftLeft(520)
        val b136 = b(2, 66) + big.toByteArray() + b(2, 66) + big.toByteArray()
        assertArrayEquals(b(0x30, 0x81, 136) + b136, AttestUtil.derSig(big, big))
    }

    @Test
    fun parseDerSig() {
        fun p(x: ByteArray): String = AttestUtil.parseDerSig(x)?.let { "${it.first}/${it.second}" } ?: "null"
        assertEquals("1/2", p(b(0x30, 6, 2, 1, 1, 2, 1, 2)))
        assertEquals("0/2", p(b(0x30, 6, 2, 1, 0, 2, 1, 2)))
        assertEquals("128/2", p(b(0x30, 7, 2, 2, 0, 0x80, 2, 1, 2)))
        assertEquals("127/255", p(b(0x30, 7, 2, 1, 0x7f, 2, 2, 0, 0xff)))
        val bad = listOf(
            b(), b(0x31, 6, 2, 1, 1, 2, 1, 2), b(0x30), b(0x30, 0), b(0x30, 3, 2, 1, 1),
            b(0x30, 7, 2, 1, 1, 2, 1, 2), b(0x30, 5, 2, 1, 1, 2, 1), b(0x30, 6, 2, 1, 1, 2, 1, 2, 0), b(0x30, 7, 2, 1, 1, 2, 1, 2, 0),
            b(0x30, 7, 2, 2, 0, 0x7f, 2, 1, 2), b(0x30, 7, 2, 2, 0, 0x01, 2, 1, 2), b(0x30, 7, 2, 1, 1, 2, 2, 0, 5),
            b(0x30, 6, 2, 1, 0x80, 2, 1, 2), b(0x30, 7, 2, 2, 0xff, 0x80, 2, 1, 2), b(0x30, 7, 2, 2, 0xff, 0x7f, 2, 1, 2),
            b(0x30, 6, 2, 1, 0xff, 2, 1, 2), b(0x30, 6, 2, 1, 1, 2, 1, 0x80),
            b(0x30, 5, 2, 0, 2, 1, 2), b(0x30, 6, 3, 1, 1, 2, 1, 2), b(0x30, 6, 2, 1, 1, 3, 1, 2), b(0x30, 6, 2, 5, 1, 2, 1, 2),
            b(0x30, 6, 2, 1, 1, 2, 2, 2),
            b(0x30, 0x80), b(0x30, 0x81), b(0x30, 0x82, 0x01), b(0x30, 0x81, 6, 2, 1, 1, 2, 1, 2), b(0x30, 0x85, 0, 0, 0, 0, 6),
            b(0x30, 0x84, 0, 0, 0, 6, 2, 1, 1, 2, 1, 2), b(0x30, 7, 2, 0x81, 1, 5, 2, 1, 2), b(0x30, 6, 2, 0x80, 2, 1, 2, 0),
        )
        for (x in bad) assertEquals(AttestUtil.hex(x), "null", p(x))
        // long-form lengths: one, two and three length bytes, minimal only
        val c128 = intT(pos(62)) + intT(pos(62))
        assertEquals(128, c128.size)
        assertArrayEquals(b(0x30, 0x81, 0x80), seq(c128).copyOfRange(0, 3))
        val r62 = BigInteger(1, pos(62))
        assertEquals("$r62/$r62", p(seq(c128)))
        assertEquals("null", p(b(0x30, 0x80) + c128))
        val c130 = intT(pos(64)) + intT(pos(62))
        assertEquals(130, c130.size)
        assertEquals("${BigInteger(1, pos(64))}/$r62", p(seq(c130)))
        assertEquals("null", p(b(0x30, 0x82, 0x00, 0x82) + c130))
        val c258 = intT(pos(128)) + intT(pos(125))
        assertEquals(258, c258.size)
        assertArrayEquals(b(0x30, 0x82, 0x01, 0x02, 0x02, 0x81, 0x80), seq(c258).copyOfRange(0, 7))
        assertEquals("${BigInteger(1, pos(128))}/${BigInteger(1, pos(125))}", p(seq(c258)))
        val c3 = intT(pos(65536)) + intT(b(1))
        assertArrayEquals(b(0x30, 0x83, 0x01, 0x00, 0x08, 0x02, 0x83, 0x01, 0x00, 0x00), seq(c3).copyOfRange(0, 10))
        val r3 = AttestUtil.parseDerSig(seq(c3))
        assertEquals(BigInteger(1, pos(65536)), r3!!.first)
        assertEquals(BigInteger.ONE, r3.second)
    }

    @Test
    fun parseDerSigRefusesFourLengthBytes() {
        // the smallest body that needs four length bytes (2^24 + 7): refused like any length over three bytes
        val c4 = intT(pos(0xffffff)) + intT(b(1))
        val s4 = seq(c4)
        assertArrayEquals(b(0x30, 0x84, 0x01, 0x00, 0x00, 0x07), s4.copyOfRange(0, 6))
        // a boolean, not assertNull: a mutant that accepts it would make the failure message print a 128-million-bit BigInteger
        assertTrue("a four-length-byte DER sequence was accepted", AttestUtil.parseDerSig(s4) == null)
    }

    private val p256 by lazy { AttestUtil.curveParams("secp256r1")!! }
    private val g2 = ECPoint(
        big("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"),
        big("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
    )

    /** An EC key that is no provider's own class, over an arbitrary group order. */
    private class FakeKey(private val p: ECParameterSpec) : ECPublicKey {
        override fun getW(): ECPoint = p.generator
        override fun getParams(): ECParameterSpec = p
        override fun getAlgorithm(): String = "EC"
        override fun getFormat(): String = "X.509"
        override fun getEncoded(): ByteArray = byteArrayOf(1)
    }

    private fun fakeKey(order: Long) = FakeKey(ECParameterSpec(p256.curve, p256.generator, BigInteger.valueOf(order), 1))

    private fun <T> withFake(mode: Boolean?, f: () -> T): T {
        K05XmlFake.mode = mode
        K05XmlFake.data.reset()
        K05XmlFake.sig = null
        Security.insertProviderAt(K05XmlFakeProvider(), 1)
        try {
            return f()
        } finally {
            Security.removeProvider("K05XmlFake")
        }
    }

    @Test
    fun ecdsaRangeGuardsComeBeforeAnyProvider() {
        val k = fakeKey(1000)
        val d = b(1, 2, 3)
        fun v(r: Long, s: Long) = AttestUtil.ecdsaVerify(k, d, BigInteger.valueOf(r), BigInteger.valueOf(s))
        withFake(true) {
            assertTrue(v(1, 1))
            assertArrayEquals(b(0x30, 6, 2, 1, 1, 2, 1, 1), K05XmlFake.sig)
            assertArrayEquals(d, K05XmlFake.data.toByteArray())
            assertTrue(v(999, 999))
            assertTrue(v(1, 999))
            for ((r, s) in listOf(0L to 1L, 1L to 0L, 1000L to 1L, 1L to 1000L, -1L to 1L, 1L to -1L, 1001L to 1L, 1L to 1001L, 0L to 0L)) {
                K05XmlFake.sig = null
                assertFalse("$r,$s", v(r, s))
                assertNull("$r,$s", K05XmlFake.sig)
            }
        }
        withFake(false) { assertFalse(v(1, 1)) }
        // the first provider cannot run: no other one can take this key, and a refusal to run is never a pass
        withFake(null) { assertFalse(v(1, 1)) }
    }

    @Test
    fun rawAndDerSignaturesReachTheVerifier() {
        val k = fakeKey(1000)
        val d = b(9)
        withFake(true) {
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, ByteArray(0)))
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, b(1)))
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, b(1, 2, 3)))
            assertNull(K05XmlFake.sig)
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, b(0, 1)))
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, b(1, 0)))
            assertNull(K05XmlFake.sig)
            assertTrue(AttestUtil.verifyRawEcdsa(k, d, b(1, 2)))
            assertArrayEquals(b(0x30, 6, 2, 1, 1, 2, 1, 2), K05XmlFake.sig)
            assertTrue(AttestUtil.verifyRawEcdsa(k, d, b(0, 3, 0, 0x81)))
            assertArrayEquals(b(0x30, 7, 2, 1, 3, 2, 2, 0, 0x81), K05XmlFake.sig)
            assertTrue(AttestUtil.verifyDerEcdsa(k, d, b(0x30, 6, 2, 1, 1, 2, 1, 2)))
            K05XmlFake.sig = null
            assertFalse(AttestUtil.verifyDerEcdsa(k, d, b(0x30, 6, 2, 1, 1, 2, 1, 2, 0)))
            assertFalse(AttestUtil.verifyDerEcdsa(k, d, b(0x30, 6, 2, 1, 0, 2, 1, 2)))
            assertNull(K05XmlFake.sig)
        }
        withFake(false) {
            assertFalse(AttestUtil.verifyRawEcdsa(k, d, b(1, 2)))
            assertFalse(AttestUtil.verifyDerEcdsa(k, d, b(0x30, 6, 2, 1, 1, 2, 1, 2)))
        }
    }

    @Test
    fun curvesAndKeys() {
        // SunEC answers for the curves it names; BouncyCastle only for the others
        assertFalse(p256.javaClass.name.startsWith("org.bouncycastle"))
        assertEquals(256, p256.order.bitLength())
        assertNotNull(AttestUtil.curveParams("sm2p256v1"))
        assertNull(AttestUtil.curveParams("no-such-curve"))
        val g = p256.generator
        fun fixed(x: BigInteger) = x.toByteArray().let { a -> if (a.size > 32) a.copyOfRange(a.size - 32, a.size) else ByteArray(32 - a.size) + a }
        val point = b(4) + fixed(g.affineX) + fixed(g.affineY)
        val key = AttestUtil.pointToKey("secp256r1", point)
        assertNotNull(key)
        assertEquals(g, key!!.w)
        assertNull(AttestUtil.pointToKey("no-such-curve", point))
        assertNull(AttestUtil.pointToKey("secp256r1", point.copyOfRange(0, 64)))
        assertNull(AttestUtil.pointToKey("secp256r1", point + b(0)))
        assertNull(AttestUtil.pointToKey("secp256r1", b(2) + point.copyOfRange(1, 65)))
        assertNull(AttestUtil.pointToKey("secp256r1", b(4) + fixed(g.affineX) + fixed(g.affineY.add(BigInteger.ONE))))
        // a domain SunEC does not know (P-256 with 2G as its generator) is built by BouncyCastle
        val other = ECParameterSpec(p256.curve, g2, p256.order, 1)
        val k2 = AttestUtil.ecKeyOf(ECPublicKeySpec(g, other))
        assertNotNull(k2)
        assertTrue(k2.javaClass.name.startsWith("org.bouncycastle"))
        assertEquals(g, (k2 as ECPublicKey).w)
        assertTrue(AttestUtil.onCurve(p256, g2.affineX, g2.affineY))
    }

    @Test
    fun onCurveBounds() {
        // y^2 = x^3 + x + 1 over F_23: (0, 1) and (4, 0) are on it
        val toy = ECParameterSpec(EllipticCurve(ECFieldFp(BigInteger.valueOf(23)), BigInteger.ONE, BigInteger.ONE), ECPoint(BigInteger.ZERO, BigInteger.ONE), BigInteger.valueOf(28), 1)
        fun on(x: Long, y: Long) = AttestUtil.onCurve(toy, BigInteger.valueOf(x), BigInteger.valueOf(y))
        assertTrue(on(0, 1))
        assertTrue(on(0, 22))
        assertTrue(on(4, 0))
        assertTrue(on(1, 7))
        assertFalse(on(1, 1))
        assertFalse(on(23, 1))
        assertFalse(on(0, 24))
        assertFalse(on(4, 23))
        assertFalse(on(-23, 1))
        assertFalse(on(0, -22))
        assertFalse(on(27, 0))
    }

    @Test
    fun azureRuntimeDataBinding() {
        val bind = Attest.Binding("h", "g", 3.0, "n")
        val good = "{\"user-data\":\"" + AttestUtil.hex(Attest.bindingBytes(bind)) + "\"}"
        fun rd(rt: ByteArray) = AttestUtil.sha256(rt) + ByteArray(32)
        fun chk(rt: String, b: Attest.Binding = bind, r: ByteArray = rd(rt.toByteArray())) =
            AttestUtil.checkAzureRuntimeDataBinding(r, rt.toByteArray(), b)
        assertEquals("", chk(good))
        assertEquals("", chk(good.replace("\"}", "\" }").uppercase().replace("USER-DATA", "user-data")))
        val ok = rd(good.toByteArray())
        assertEquals("report_data is not 64 bytes", chk(good, r = ok.copyOfRange(0, 63)))
        assertEquals("report_data is not 64 bytes", chk(good, r = ok + b(0)))
        for (i in listOf(32, 40, 63)) {
            val z = ok.clone()
            z[i] = 1
            assertEquals("report_data[32:64] is not zero (not an Azure runtime-data hash)", chk(good, r = z))
        }
        val flip = ok.clone()
        flip[0] = (flip[0].toInt() xor 1).toByte()
        assertEquals("sha256(runtime data) does not equal the quote report_data", chk(good, r = flip))
        assertEquals("runtime data is not valid JSON", chk("{"))
        assertEquals("runtime data is not a JSON object", chk("[]"))
        assertEquals("runtime data carries no 64-byte hex user-data", chk("{}"))
        assertEquals("runtime data carries no 64-byte hex user-data", chk("{\"user-data\":1}"))
        assertEquals("runtime data carries no 64-byte hex user-data", chk("{\"user-data\":\"" + "a".repeat(127) + "\"}"))
        assertEquals("runtime data carries no 64-byte hex user-data", chk("{\"user-data\":\"" + "a".repeat(130) + "\"}"))
        assertEquals("runtime data carries no 64-byte hex user-data", chk("{\"user-data\":\"" + "g".repeat(128) + "\"}"))
        assertEquals("binding not constructible: binding: holderPub required", chk(good, Attest.Binding("", "g", 3.0, "n")))
        assertEquals(
            "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)",
            chk(good, Attest.Binding("h", "g", 4.0, "n")),
        )
    }
}
