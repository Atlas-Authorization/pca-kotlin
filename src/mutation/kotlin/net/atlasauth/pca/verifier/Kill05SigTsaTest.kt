package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** RFC 3161 timestamps (TimeStampResp or bare TimeStampToken) under a pinned TSA, with the reference's exact refusals. */
class Kill05SigTsaTest {
    private val K = Kill05SigKit
    private val rootKey = K.ec()
    private val tsaKey = K.ec()
    private val rootDer = K.cert(K.tbs("TSA Root", "TSA Root", rootKey.public, K.CA_NB, K.CA_NA, listOf(K.CA_BC, K.CA_KU)), rootKey.private)
    private val leafDer = K.cert(K.tbs("TSA Root", "TSA", tsaKey.public, K.CA_NB, K.CA_NA, listOf(K.ext("2.5.29.37", K.seq(K.oid(K.EKU_TS)), true))), rootKey.private)
    private val tsas = listOf(Sigstore.PinnedCa(listOf(K.x509(leafDer), K.x509(rootDer)), 0, Long.MAX_VALUE))
    private val data = K.utf8("the envelope signature")
    private val gen = 1735689600000L // 20250101000000Z

    private val signedData = "1.2.840.113549.1.7.2"
    private val tstOid = "1.2.840.113549.1.9.16.1.4"
    private val ctOid = "1.2.840.113549.1.9.3"
    private val mdOid = "1.2.840.113549.1.9.4"

    private fun tst(over: ByteArray = data, time: String = "20250101000000Z") = K.seq(
        K.int(1), K.oid("1.2.3.4"), K.seq(K.seq(K.oid(K.SHA256)), K.oct(K.sha256(over))), K.int(42), K.tlv(0x18, time.toByteArray(Charsets.US_ASCII)),
    )

    private fun attrs(t: ByteArray): List<ByteArray> = listOf(K.seq(K.oid(ctOid), K.set(K.oid(tstOid))), K.seq(K.oid(mdOid), K.set(K.oct(K.sha256(t)))))

    private fun si(attrs: List<ByteArray>, attrTag: Int = 0xa0, sigTag: Int = 0x04): ByteArray {
        val body = K.cat(*attrs.toTypedArray())
        val sig = K.sign(tsaKey.private, K.tlv(0x31, body))
        return K.seq(K.int(1), K.seq(K.name("TSA Root"), K.int(7)), K.seq(K.oid(K.SHA256)), K.tlv(attrTag, body), K.seq(K.oid(K.ECDSA256)), K.tlv(sigTag, sig))
    }

    private fun encap(t: ByteArray): ByteArray = K.seq(K.oid(tstOid), K.tlv(0xa0, K.oct(t)))

    private fun token(t: ByteArray = tst(), infos: ByteArray = K.set(si(attrs(t))), content: ByteArray = encap(t)): ByteArray =
        K.seq(K.oid(signedData), K.tlv(0xa0, K.seq(K.int(3), K.set(K.seq(K.oid(K.SHA256))), content, infos)))

    private fun v(token: ByteArray, over: ByteArray = data, pinned: List<Sigstore.PinnedCa> = tsas): String = try {
        "OK " + Sigstore.verifyRfc3161(token, over, pinned)
    } catch (e: IllegalArgumentException) {
        "IAE:" + e.message
    }

    @Test fun accepted() {
        assertEquals("OK $gen", v(token()))
        assertEquals("OK $gen", v(K.seq(K.seq(K.int(0)), token())))
        // grantedWithMods, with a statusString
        assertEquals("OK $gen", v(K.seq(K.seq(K.int(1), K.seq(K.tlv(0x0c, K.utf8("ok")))), token())))
    }

    @Test fun envelopeRefusals() {
        assertEquals("IAE:timestamp is not one SEQUENCE", v(K.set()))
        assertEquals("IAE:timestamp is not one SEQUENCE", v(K.cat(token(), K.b(0))))
        assertEquals("IAE:not CMS SignedData", v(K.seq()))
        // a first element too short to be a PKIStatusInfo, or not starting with an INTEGER: read as a bare token
        assertEquals("IAE:not an OID", v(K.seq(K.seq(), K.oid(signedData))))
        assertEquals("IAE:not an OID", v(K.seq(K.seq(K.oct(K.b(0))), token())))
        assertEquals("IAE:timestamp status is not granted", v(K.seq(K.seq(K.int(2)), token())))
        assertEquals("IAE:timestamp status is not granted", v(K.seq(K.seq(K.tlv(0x02, K.b(0, 0))), token())))
        assertEquals("IAE:no timeStampToken", v(K.seq(K.seq(K.int(0)))))
        // a bare token whose second element is not [0]
        assertEquals("IAE:not CMS SignedData", v(K.seq(K.oid(signedData), K.seq(K.int(0), K.int(0)))))
        // a response whose "token" is an OID: its content read as DER
        assertEquals("IAE:DER length", v(K.seq(K.seq(K.int(0)), K.oid(signedData))))
    }

    @Test fun contentRefusals() {
        val t = tst()
        val one = K.set(si(attrs(t)))
        assertEquals("IAE:no encapsulated content", v(K.seq(K.oid(signedData), K.tlv(0xa0, K.seq(K.int(3), K.set(), one)))))
        assertEquals("IAE:TSTInfo is not an OCTET STRING", v(token(t, one, K.seq(K.oid(tstOid), K.tlv(0xa0, K.seq())))))
        assertEquals("IAE:messageImprint is not the hash of the signature", v(token(), K.utf8("another signature")))
        assertEquals("IAE:no signerInfos", v(token(t, K.seq())))
        assertEquals("IAE:exactly one SignerInfo is required", v(token(t, K.set())))
        assertEquals("IAE:exactly one SignerInfo is required", v(token(t, K.set(si(attrs(t)), si(attrs(t))))))
    }

    @Test fun signerRefusals() {
        val t = tst()
        val a = attrs(t)
        assertEquals("IAE:signed attributes are required", v(token(t, K.set(si(a, attrTag = 0x31)))))
        val twoValues = listOf(K.seq(K.oid(ctOid), K.set(K.oid(tstOid), K.oid(tstOid))), a[1])
        assertEquals("IAE:an attribute must have one value", v(token(t, K.set(si(twoValues)))))
        val noCommit = "IAE:signed attributes do not commit to the TSTInfo"
        assertEquals(noCommit, v(token(t, K.set(si(listOf(a[1]))))))
        assertEquals(noCommit, v(token(t, K.set(si(listOf(a[0]))))))
        assertEquals(noCommit, v(token(t, K.set(si(listOf(K.seq(K.oid(ctOid), K.set(K.oid(signedData))), a[1]))))))
        assertEquals("IAE:signature is not an OCTET STRING", v(token(t, K.set(si(a, sigTag = 0x03)))))
        val none = "IAE:no pinned timestamp authority signed it (valid at its time)"
        assertEquals(none, v(token(), pinned = emptyList()))
        assertEquals(none, v(token(), pinned = listOf(Sigstore.PinnedCa(tsas[0].chain, gen + 1, Long.MAX_VALUE))))
        assertEquals(none, v(token(), pinned = listOf(Sigstore.PinnedCa(listOf(K.ca), 0, Long.MAX_VALUE))))
    }
}
