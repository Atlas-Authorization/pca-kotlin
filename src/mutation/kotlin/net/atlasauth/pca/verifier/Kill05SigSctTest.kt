package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The embedded SCT (RFC 6962 3.2) against a pinned CT log, with the reference's exact reasons. */
class Kill05SigSctTest {
    private val K = Kill05SigKit
    private val ct = K.ec()
    private val ctId = K.sha256(ct.public.encoded)
    private val ts = K.IT * 1000
    private val base = listOf(K.aki(K.CA_KID), K.eku(K.EKU_CS), K.san(K.uri(K.SAN_URI)))

    private fun roots(start: Long = 0, end: Long = Long.MAX_VALUE) =
        Sigstore.PinnedRoots(emptyList(), listOf(Sigstore.PinnedLog(ctId, ct.public, null, start, end, null)), emptyList(), emptyList())

    private fun leafTbs(exts: List<ByteArray>) = K.tbs("Test CA", "leaf", K.leafKey.public, ts - K.DAY, ts + K.DAY, exts)
    private fun leaf(exts: List<ByteArray>): Sigstore.ParsedCert = Sigstore.parseCert(K.seq(leafTbs(exts), K.ALG, K.tlv(0x03, K.b(0, 1))))
    private fun sctExt(list: ByteArray) = K.ext(K.OID_SCT, K.oct(list))

    private fun list(vararg scts: ByteArray): ByteArray {
        val inner = K.cat(*scts.map { K.cat(K.u16(it.size), it) }.toTypedArray())
        return K.cat(K.u16(inner.size), inner)
    }

    private fun sct(id: ByteArray, time: Long, ext: ByteArray, sig: ByteArray, hash: Int = 4, alg: Int = 3): ByteArray =
        K.cat(K.b(0), id, K.u64(time), K.u16(ext.size), ext, K.b(hash, alg), K.u16(sig.size), sig)

    /** A leaf whose SCT list is [raw] (the list bytes, inside the OCTET STRING). */
    private fun check(raw: ByteArray, r: Sigstore.PinnedRoots = roots()): String? = Sigstore.verifySct(leaf(base + sctExt(raw)), K.ca, r)

    /** A leaf built from [exts] carrying one SCT, signed by the pinned log over the precertificate TBS (the leaf TBS without it). */
    private fun signed(exts: List<ByteArray>, ext: ByteArray, time: Long = ts): Sigstore.ParsedCert {
        val pre = leafTbs(exts)
        val n = pre.size
        val head = K.cat(K.b(0, 0), K.u64(time), K.b(0, 1))
        val data = K.cat(head, K.sha256(K.ca.publicKey.encoded), K.b(n shr 16, (n shr 8) and 0xff, n and 0xff), pre, K.u16(ext.size), ext)
        return leaf(exts + sctExt(list(sct(ctId, time, ext, K.sign(ct.private, data)))))
    }

    @Test fun listShape() {
        assertEquals("no embedded SCT", Sigstore.verifySct(leaf(base), K.ca, roots()))
        assertEquals("SCT list is not an OCTET STRING", Sigstore.verifySct(leaf(base + K.ext(K.OID_SCT, K.seq())), K.ca, roots()))
        assertEquals("SCT list length", check(ByteArray(0)))
        assertEquals("SCT list length", check(K.b(0)))
        assertEquals("SCT list length", check(K.b(0, 5)))
        assertEquals("SCT list length", check(K.b(0, 0, 0)))
        assertEquals("no SCT from a pinned CT log", check(K.b(0, 0)))
        assertEquals("SCT truncated", check(K.b(0, 1, 0)))
        assertEquals("SCT truncated", check(list(ByteArray(46))))
        // declares 60 bytes, carries 50
        assertEquals("SCT truncated", check(K.cat(K.u16(52), K.u16(60), ByteArray(50))))
    }

    @Test fun sctFields() {
        val other = ByteArray(32) { 9 }
        // the smallest SCT (47 bytes): from an unknown log, it is skipped
        assertEquals("no SCT from a pinned CT log", check(list(sct(other, 0, ByteArray(0), ByteArray(0)))))
        // two SCTs, both well formed, neither from the pinned log
        assertEquals("no SCT from a pinned CT log", check(list(sct(other, 0, ByteArray(0), ByteArray(0)), sct(other, 1, K.b(1), K.b(2)))))
        // extensions longer than the SCT; then too short for the algorithm and signature length
        assertEquals("SCT truncated", check(list(K.cat(K.b(0), ctId, K.u64(ts), K.u16(100), K.b(4, 3), K.u16(0)))))
        assertEquals("SCT truncated", check(list(K.cat(K.b(0), ctId, K.u64(ts), K.u16(1), K.b(0), K.b(4, 3), K.b(0)))))
        assertEquals("SCT malformed", check(list(K.cat(K.b(0), ctId, K.u64(ts), K.u16(0), K.b(4, 3), K.u16(5), K.b(1, 2, 3)))))
        assertEquals("SCT malformed", check(list(K.cat(K.b(0), ctId, K.u64(ts), K.u16(0), K.b(4, 3), K.u16(1), K.b(1, 2, 3)))))
        // the smallest SCT from the pinned log: parsed to the signature check
        assertEquals("SCT signature invalid", check(list(sct(ctId, ts, ByteArray(0), ByteArray(0)))))
        assertEquals("SCT is not SHA-256 with ECDSA or RSA", check(list(sct(ctId, ts, ByteArray(0), ByteArray(0), hash = 2))))
        assertEquals("SCT is not SHA-256 with ECDSA or RSA", check(list(sct(ctId, ts, ByteArray(0), ByteArray(0), alg = 2))))
    }

    @Test fun timestamps() {
        val range = "SCT timestamp out of range"
        val invalid = "SCT signature invalid"
        fun at(t: Long, r: Sigstore.PinnedRoots = roots()) = check(list(sct(ctId, t, ByteArray(0), K.b(0x30, 0x00))), r)
        assertEquals(invalid, at(0))
        assertEquals(invalid, at(9007199254740991L))
        assertEquals(range, at(9007199254740992L))
        assertEquals(range, at(-1L))
        assertEquals(range, at(Long.MIN_VALUE))
        assertEquals("SCT log key not valid at its timestamp", at(999, roots(1000)))
        assertEquals("SCT log key not valid at its timestamp", at(1001, roots(0, 1000)))
        assertEquals(invalid, at(1000, roots(1000, 1000)))
    }

    @Test fun validSignatures() {
        assertNull(Sigstore.verifySct(signed(base, ByteArray(0)), K.ca, roots()))
        // extensions of 300 bytes: both length bytes of the extension field are used
        assertNull(Sigstore.verifySct(signed(base, ByteArray(300) { it.toByte() }), K.ca, roots()))
        // a precertificate TBS over 64 KiB: all three length bytes are used
        assertNull(Sigstore.verifySct(signed(base + K.ext("1.2.3.4", ByteArray(70000)), ByteArray(0)), K.ca, roots()))
        // the same SCT checked under another issuer key does not verify
        assertEquals("SCT signature invalid", Sigstore.verifySct(signed(base, ByteArray(0)), K.x509(K.leafDer()), roots()))
    }

    @Test fun shortOrOverlongSctIsTruncatedWhateverItsVersion() {
        // the reference refuses a short SCT (n < 47) before it looks at the version byte: a non-v1 one is not skipped
        assertEquals("SCT truncated", check(list(ByteArray(46) { 1 })))
        assertEquals("SCT truncated", check(list(ByteArray(10) { 1 })))
        assertEquals("SCT truncated", check(list(K.b(1))))
        // a v2 SCT of 47 bytes is skipped
        assertEquals("no SCT from a pinned CT log", check(list(ByteArray(47) { 1 })))
        // declares 50 bytes, carries 48: two bytes short
        assertEquals("SCT truncated", check(K.cat(K.u16(50), K.u16(50), ByteArray(48) { 1 })))
        // declares 49, carries 48: one byte short
        assertEquals("SCT truncated", check(K.cat(K.u16(50), K.u16(49), ByteArray(48) { 1 })))
        // a second SCT one byte short after a well-formed (skipped) first one
        val first = K.cat(K.u16(47), ByteArray(47) { 1 })
        assertEquals("SCT truncated", check(K.cat(K.u16(first.size + 50), first, K.u16(49), ByteArray(48) { 1 })))
    }
}
