package net.atlasauth.pca.verifier

import java.security.KeyPairGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestNvidiaCollateral OCSP (RFC 6960): every structural refusal, CertID matching, responder authentication, freshness, certStatus. */
class Kill05NvOcspTest {
    private val rej = "OCSP response rejected: "
    private val noEmbedded = "no embedded responder certificate verifies the response"
    private val issuerSig = "OCSP response signature does not verify under the issuer key"
    private val delegatedSig = "OCSP response signature does not verify under the delegated responder key"
    private val notSigned = "delegated responder certificate is not signed by the supplied NVIDIA chain"
    private val outside = "delegated responder certificate is outside its validity window"
    private val noMatch = "no SingleResponse matches the certificate (serial / issuer hashes differ)"
    private val badTime = "response carries a malformed (out-of-range) ASN.1 time"

    @Test
    fun responseEnvelope() = nv {
        val cases = listOf(
            b(1, 2, 3) to "response is not valid DER",
            b(0x3f, 0) to "response is not valid DER", // a multi-byte tag
            b(0x30, 0, 0) to "trailing bytes after OCSPResponse",
            b(0x31, 0) to rej + "OCSPResponse is not a SEQUENCE",
            b(0x30, 2, 0x0a, 5) to rej + "malformed OCSPResponse",
            b(0x30, 0) to rej + "malformed OCSPResponse",
            b(0x30, 3, 0x02, 1, 0) to rej + "malformed OCSPResponse",
            b(0x30, 4, 0x0a, 2, 0, 0) to rej + "malformed OCSPResponse",
            b(0x30, 3, 0x0a, 1, 1) to "OCSP responseStatus is 1 (not successful)",
            b(0x30, 3, 0x0a, 1, 0x80) to "OCSP responseStatus is 128 (not successful)",
            b(0x30, 3, 0x0a, 1, 0) to "successful response carries no responseBytes",
            b(0x30, 5, 0x0a, 1, 0, 0xa1, 0) to "successful response carries no responseBytes",
            b(0x30, 7, 0x0a, 1, 0, 0xa0, 2, 0x30, 5) to rej + "malformed responseBytes",
            b(0x30, 5, 0x0a, 1, 0, 0xa0, 0) to rej + "malformed responseBytes",
            b(0x30, 9, 0x0a, 1, 0, 0xa0, 4, 0x30, 0, 0x30, 0) to rej + "malformed responseBytes",
            b(0x30, 7, 0x0a, 1, 0, 0xa0, 2, 0x31, 0) to rej + "malformed responseBytes",
            b(0x30, 9, 0x0a, 1, 0, 0xa0, 4, 0x30, 2, 0x05, 5) to rej + "malformed responseBytes",
            seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid(OCSP_BASIC)))) to rej + "malformed responseBytes",
            seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid(OCSP_BASIC), tlv(0x03, b(0))))) to rej + "malformed responseBytes",
            seq(tlv(0x0a, b(0)), tlv(0xa0, seq(int(1), octets(b(0))))) to rej + "expected an OBJECT IDENTIFIER",
            seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid("1.3.6.1.5.5.7.48.1.2"), octets(b(0))))) to "responseType is not id-pkix-ocsp-basic",
            response(b(0x30, 5)) to "BasicOCSPResponse is not valid DER",
            response(b(0x31, 0)) to rej + "BasicOCSPResponse is not a SEQUENCE",
            response(b(0x30, 2, 0x30, 5)) to rej + "malformed BasicOCSPResponse",
            response(seq(seq(), seq())) to rej + "malformed BasicOCSPResponse",
            response(seq(tlv(0x31), seq(), tlv(0x03))) to rej + "malformed BasicOCSPResponse",
            response(seq(seq(), tlv(0x31), tlv(0x03))) to rej + "malformed BasicOCSPResponse",
            response(seq(seq(), seq(), tlv(0x04))) to rej + "malformed BasicOCSPResponse",
            response(seq(seq(), seq(), tlv(0x03))) to rej + "malformed signatureAlgorithm",
            response(seq(seq(), seq(int(1)), tlv(0x03))) to rej + "expected an OBJECT IDENTIFIER",
            response(seq(seq(), seq(oid("1.2.3")), tlv(0x03))) to "unsupported OCSP signature algorithm 1.2.3",
            response(seq(seq(), seq(oid(EC384)), tlv(0x03))) to rej + "malformed signature",
            response(seq(seq(), seq(oid(EC384)), tlv(0x03, b(0)))) to rej + "malformed ResponseData",
        )
        for ((der, want) in cases) assertEquals(AttestUtil.hex(der), want, ocspWhy(der))
    }

    @Test
    fun responseDataShape() = nv {
        val sig = b(1)
        val cases = listOf(
            seq(tlv(0xa0, int(0)), byName(inter.cert), gen(NOW - HOUR)) to rej + "malformed ResponseData",
            seq(byName(inter.cert), utc(NOW - HOUR), seq(single())) to rej + "malformed ResponseData",
            seq(byName(inter.cert), gen(NOW - HOUR), tlv(0x31, single())) to rej + "malformed ResponseData",
            seq(tlv(0xa3, seq()), gen(NOW - HOUR), seq(single())) to rej + "malformed ResponseData",
            seq(tlv(0xa1), gen(NOW - HOUR), seq(single())) to rej + "malformed responderID",
            seq(tlv(0xa1, inter.cert.rawSubject, inter.cert.rawSubject), gen(NOW - HOUR), seq(single())) to rej + "malformed responderID",
        )
        for ((tbs, want) in cases) assertEquals(AttestUtil.hex(tbs), want, ocspWhy(response(basic(tbs, sig = sig))))
        // with and without the optional [0] version
        assertEquals("OK:good", ocspWhy(response(basic(rdata(single(), version = true)))))
        assertEquals("OK:good", ocspWhy(ocsp(single())))
    }

    @Test
    fun everyAsn1TimeMustBeWellFormed() = nv {
        // the tbs below is not a ResponseData, so a response whose times pass ends at "malformed ResponseData"
        fun t(vararg els: ByteArray): String {
            val r = ocspWhy(response(basic(seq(*els), sig = b(1))))
            return if (r == rej + "malformed ResponseData") "ok" else r
        }
        val gens = listOf(
            "20261231235959Z" to "ok", "20260101000000Z" to "ok", "20260101000000.5Z" to "ok",
            "20261301000000Z" to badTime, "20260001000000Z" to badTime, "20260100000000Z" to badTime, "20260101240000Z" to badTime,
            "20260101006000Z" to badTime, "20260101000060Z" to badTime, "20260230000000Z" to badTime, "2026" to badTime,
            "260101000000Z" to badTime, "20260101000000.50Z" to badTime,
        )
        for ((s, want) in gens) assertEquals("gen $s", want, t(text(0x18, s)))
        val utcs = listOf(
            "260101000000Z" to "ok", "991231235959Z" to "ok", "000229000000Z" to "ok", "960229000000Z" to "ok", "480229000000Z" to "ok",
            "010229000000Z" to badTime, "971301000000Z" to badTime, "20260101000000Z" to badTime, "500229000000Z" to badTime,
        )
        for ((s, want) in utcs) assertEquals("utc $s", want, t(text(0x17, s)))
        assertEquals(badTime, t(seq(text(0x18, "20261301000000Z"))))
        assertEquals(badTime, t(tlv(0xa1, text(0x17, "971301000000Z"))))
        assertEquals(badTime, t(tlv(0x30, b(0x05, 5))))
        assertEquals("ok", t(octets(text(0x18, "20261301000000Z")))) // a primitive is not walked
        assertEquals("ok", t(seq(text(0x18, "20260101000000Z"), text(0x17, "260101000000Z"))))
    }

    @Test
    fun singleResponseAndCertIdShape() = nv {
        val id = certId(leaf.cert, inter.cert)
        val cases = listOf(
            tlv(0x04, b(0x05, 5)) to rej + "malformed SingleResponse",
            seq(id, GOOD) to rej + "malformed SingleResponse",
            seq(octets(NONE), GOOD, gen(NOW - HOUR)) to rej + "malformed SingleResponse",
            seq(id, GOOD, utc(NOW - HOUR)) to rej + "malformed SingleResponse",
            single(id = seq(seq(oid(SHA384)), octets(NONE), octets(NONE))) to rej + "malformed CertID",
            single(id = seq(octets(NONE), octets(NONE), octets(NONE), int(1))) to rej + "malformed CertID",
            single(id = seq(seq(oid(SHA384)), int(1), octets(NONE), int(1))) to rej + "malformed CertID",
            single(id = seq(seq(oid(SHA384)), octets(NONE), int(1), int(1))) to rej + "malformed CertID",
            single(id = seq(seq(oid(SHA384)), octets(NONE), octets(NONE), octets(NONE))) to rej + "malformed CertID",
            // a primitive SingleResponse refuses before anything inside it is read
            tlv(0x04, tlv(0x30, b(0x05, 5)), GOOD, gen(NOW - HOUR)) to rej + "malformed SingleResponse",
            tlv(0x04, seq(tlv(0x30, b(0x05, 5)), octets(NONE), octets(NONE), int(1)), GOOD, gen(NOW - HOUR)) to rej + "malformed SingleResponse",
            single(id = seq(seq(), octets(NONE), octets(NONE), int(1))) to rej + "malformed CertID hash algorithm",
            single(id = seq(seq(int(1)), octets(NONE), octets(NONE), int(1))) to rej + "expected an OBJECT IDENTIFIER",
        )
        for ((s, want) in cases) assertEquals(AttestUtil.hex(s), want, ocspWhy(ocsp(s)))
    }

    @Test
    fun certIdMatching() = nv {
        for (h in listOf(SHA1, SHA256, SHA384, SHA512)) assertEquals(h, "OK:good", ocspWhy(ocsp(single(id = certId(leaf.cert, inter.cert, hashOid = h)))))
        fun withId(id: ByteArray) = ocspWhy(ocsp(single(id = id)))
        assertEquals(noMatch, withId(certId(leaf.cert, inter.cert, hashOid = "1.2.3.4")))
        assertEquals(noMatch, withId(certId(leaf.cert, inter.cert, serial = int(5))))
        assertEquals(noMatch, withId(certId(leaf.cert, inter.cert, nameHash = ByteArray(48))))
        assertEquals(noMatch, withId(certId(leaf.cert, inter.cert, keyHash = ByteArray(48))))
        // serials compare without leading zero bytes (the leaf's DER serial is 00 9a 01)
        assertEquals("OK:good", withId(certId(leaf.cert, inter.cert, serial = tlv(0x02, b(0, 0, 0x9a, 1)))))
        assertEquals("OK:good", withId(certId(leaf.cert, inter.cert, serial = tlv(0x02, b(0x9a, 1)))))
        assertEquals(noMatch, withId(certId(leaf.cert, inter.cert, serial = tlv(0x02, b(1)))))
        // serial 0 keeps its one zero byte; an empty INTEGER is not 0
        val zero = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = tlv(0x02, b(0)), exts = listOf(aia()))
        assertEquals("OK:good", ocspWhy(ocsp(single(zero.cert)), cert = zero.cert))
        assertEquals(noMatch, ocspWhy(ocsp(single(zero.cert, id = certId(zero.cert, inter.cert, serial = tlv(0x02, NONE)))), cert = zero.cert))
        // a non-matching SingleResponse is skipped; two matching ones are ambiguous
        assertEquals("OK:good", ocspWhy(ocsp(single(id = certId(leaf.cert, inter.cert, serial = int(5))), single())))
        assertEquals("ambiguous: multiple SingleResponses match the certificate", ocspWhy(ocsp(single(), single())))
    }

    @Test
    fun nextUpdateAndFreshness() = nv {
        fun s(vararg x: ByteArray) = ocspWhy(ocsp(*x))
        assertEquals("OK:good", s(single(next = null)))
        assertEquals("response is stale (past nextUpdate)", s(single(next = tlv(0xa0, gen(NOW - SEC)))))
        assertEquals("OK:good", s(single(next = tlv(0xa0, gen(NOW)))))
        assertEquals("response nextUpdate is invalid", s(single(next = tlv(0xa0, gen(NOW - 2 * HOUR)))))
        assertEquals("OK:good", s(single(thisUpdate = gen(NOW), next = tlv(0xa0, gen(NOW)))))
        // a [1] is not a nextUpdate; a [0] that is not exactly one GeneralizedTime refuses, it never means no nextUpdate
        assertEquals("OK:good", s(single(next = tlv(0xa1, gen(NOW - 2 * HOUR)))))
        val badNext = rej + "nextUpdate is malformed"
        assertEquals(badNext, s(single(next = tlv(0xa0, gen(NOW + DAY), gen(NOW + DAY)))))
        assertEquals(badNext, s(single(next = tlv(0xa0, utc(NOW + DAY)))))
        assertEquals(badNext, s(single(next = tlv(0xa0))))
        // ... also on a SingleResponse for another certificate
        assertEquals(badNext, s(single(cert = inter.cert, issuer = root.cert, next = tlv(0xa0)), single()))
        assertEquals(rej + "malformed SingleResponse", s(single(tag = 0x04)))
        // after thisUpdate: only an optional [0], then an optional [1]; anything else refuses, on every SingleResponse
        val ms = rej + "malformed SingleResponse"
        val nx = tlv(0xa0, gen(NOW + DAY))
        val ex = tlv(0xa1, seq())
        assertEquals(ms, s(single(next = tlv(0xa2, gen(NOW - SEC)))))
        assertEquals(ms, s(single(cert = inter.cert, issuer = root.cert, next = tlv(0xa2, gen(NOW + DAY))), single()))
        assertEquals("OK:good", s(single(next = nx + ex)))
        assertEquals("OK:good", s(single(next = ex)))
        assertEquals("response is stale (past nextUpdate)", s(single(next = tlv(0xa0, gen(NOW - SEC)) + ex)))
        assertEquals(ms, s(single(next = ex + nx)))
        assertEquals(ms, s(single(next = nx + nx)))
        assertEquals(ms, s(single(next = ex + ex)))
        assertEquals(ms, s(single(next = nx + tlv(0xa2, seq()))))
        assertEquals(ms, s(single(next = nx + ex + tlv(0xa2, seq()))))
        assertEquals(ms, s(single(next = b(0x05, 0))))
        // thisUpdate / producedAt against now, and the 7-day maximum age
        assertEquals("response thisUpdate is in the future", s(single(thisUpdate = gen(NOW + SEC))))
        assertEquals("OK:good", s(single(thisUpdate = gen(NOW))))
        assertEquals("response producedAt is in the future", ocspWhy(response(basic(rdata(single(), produced = gen(NOW + 1))))))
        assertEquals("OK:good", ocspWhy(response(basic(rdata(single(), produced = gen(NOW))))))
        assertEquals("response is older than the maximum accepted age", s(single(thisUpdate = gen(NOW - 7 * DAY - 1), next = null)))
        assertEquals("OK:good", s(single(thisUpdate = gen(NOW - 7 * DAY), next = null)))
    }

    @Test
    fun certStatus() = nv {
        val rt = text(0x18, "20261019120000Z")
        val frac = text(0x18, "20261019120000.5Z")
        val cases = listOf(
            GOOD to "OK:good", b(0xa0, 0) to "malformed certStatus", UNKNOWN to "OK:unknown", b(0xa2, 0) to "malformed certStatus", REVOKED to "OK:revoked",
            b(0x0a, 0) to "malformed certStatus", b(0x40, 0) to "malformed certStatus", b(0xc0, 0) to "malformed certStatus",
            b(0x83, 0) to "unrecognised certStatus", b(0xa3, 0) to "unrecognised certStatus",
            tlv(0xa1) to "malformed revoked certStatus",
            tlv(0x81, b(0x05, 5)) to "malformed certStatus",
            tlv(0xa1, frac) to "malformed revoked certStatus",
            tlv(0xa1, rt, frac) to "OK:revoked",
            tlv(0xa1, frac, rt) to "malformed revoked certStatus",
            tlv(0xa1, rt, tlv(0xa0, tlv(0x0a, b(1)))) to "OK:revoked",
            tlv(0x81, rt) to "malformed certStatus",
        )
        for ((st, want) in cases) assertEquals(AttestUtil.hex(st), want, ocspWhy(ocsp(single(status = st))))
    }

    @Test
    fun issuerAsResponder() = nv {
        assertEquals("OK:good", ocspWhy(ocsp(single(), rid = byKey(inter.cert))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = tlv(0xa2, octets(ByteArray(20))))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = tlv(0xa2, b(0x05, 0)))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = tlv(0xa1, octets(inter.cert.rawSubject)))))
        assertEquals(noEmbedded, ocspWhy(ocsp(single(), rid = byName(root.cert))))
        assertEquals(issuerSig, ocspWhy(ocsp(single(), signer = rootKey.private)))
        for ((jca, o) in listOf("SHA256withECDSA" to EC256, "SHA384withECDSA" to EC384, "SHA512withECDSA" to EC512)) {
            assertEquals(o, "OK:good", ocspWhy(ocsp(single(), jca = jca, sigOid = o)))
        }
        assertEquals(issuerSig, ocspWhy(ocsp(single(), jca = "SHA256withECDSA", sigOid = EC384)))
        for (o in listOf(RSA256, RSA384, RSA512)) assertEquals(o, issuerSig, ocspWhy(ocsp(single(), sigOid = o)))
    }

    @Test
    fun delegatedResponder() = nv {
        fun d(r: Kill05NvKit.Issued, rid: ByteArray = byKey(r.cert), signer: java.security.PrivateKey = respKey.private, certs: ByteArray = embed(r.der), chain: List<AttestCert.Cert> = CHAIN) =
            ocspWhy(ocsp(single(), rid = rid, signer = signer, certs = certs), chain = chain)
        assertEquals("OK:good", d(DELEGATE))
        assertEquals("OK:good", d(DELEGATE, rid = byName(DELEGATE.cert)))
        // an unparseable embedded certificate rejects the response, even beside a good one
        assertTrue(d(DELEGATE, certs = embed(seq(), DELEGATE.der)).startsWith(rej))
        val other = responder(cn = "Other Responder", key = p384())
        assertEquals("OK:good", d(DELEGATE, certs = embed(other.der, DELEGATE.der)))
        assertEquals("embedded certificates do not match the responderID", d(DELEGATE, certs = embed(other.der)))
        val noEku = responder(exts = emptyList())
        assertEquals("delegated responder certificate lacks the id-kp-OCSPSigning EKU", d(noEku))
        assertEquals("delegated responder certificate lacks the id-kp-OCSPSigning EKU", d(responder(exts = listOf(eku(KP_SERVER)))))
        // validity: both bounds inclusive; a bound the strict X.509 time reader refuses is outside
        assertEquals(outside, d(responder(notBefore = utc(NOW + SEC))))
        assertEquals(outside, d(responder(notAfter = utc(NOW - SEC))))
        assertEquals("OK:good", d(responder(notBefore = utc(NOW))))
        assertEquals("OK:good", d(responder(notAfter = utc(NOW))))
        assertEquals(outside, d(responder(notBefore = text(0x18, "20260101000000.5Z"))))
        assertEquals(outside, d(responder(notAfter = text(0x18, "20280101000000.5Z"))))
        // the last refusal reason wins
        val expired = responder(notAfter = utc(NOW - SEC))
        assertEquals(outside, d(DELEGATE, certs = embed(noEku.der, expired.der)))
        // the signer must be the issuer or above it in the supplied chain (or the issuer alone without one)
        val byRoot = responder(issuer = dn(ROOT_CN), signer = rootKey.private)
        assertEquals("OK:good", d(byRoot))
        assertEquals(notSigned, d(byRoot, chain = emptyList()))
        assertEquals("OK:good", d(DELEGATE, chain = emptyList()))
        assertEquals(notSigned, d(responder(issuer = dn(LEAF_CN), signer = leafKey.private)))
        assertEquals(notSigned, d(responder(issuer = dn(INTER_CN), signer = rootKey.private)))
        assertEquals(notSigned, d(responder(issuer = dn(ROOT_CN), signer = interKey.private)))
        // the delegated key itself
        val unreadable = responder(key = null, spki = seq(seq(oid("1.2.3.4")), bits(b(1, 2, 3))))
        assertEquals(delegatedSig, d(unreadable, rid = byName(unreadable.cert)))
        assertEquals(delegatedSig, d(DELEGATE, signer = rootKey.private))
        val ed = responder(cn = "Ed Responder", key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair())
        assertEquals(delegatedSig, d(ed, rid = byName(ed.cert)))
        // certificates are read from every SEQUENCE under the [0]; anything else there is malformed
        assertEquals("OK:good", d(DELEGATE, certs = tlv(0xa0, seq(DELEGATE.der), seq())))
        assertTrue(d(DELEGATE, certs = tlv(0xa0, tlv(0x04, b(0x05, 5)))).startsWith(rej))
        assertEquals(noEmbedded, d(DELEGATE, certs = tlv(0xa1, seq(DELEGATE.der))))
        // OpenSSL checkIssued: AKI keyIdentifier against SKI, keyCertSign when the issuer has a keyUsage
        fun aki(id: ByteArray) = ext("2.5.29.35", false, seq(tlv(0x80, id)))
        val skiId = b(1, 2, 3, 4)
        val iss = issue(dn("Issuing CA"), dn(ROOT_CN), rootKey.private, interKey, serial = int(9), exts = listOf(BC_CA, KU_CA, ext("2.5.29.14", false, octets(skiId))))
        fun di(r: Kill05NvKit.Issued, signerCert: Kill05NvKit.Issued = iss) = ocspWhy(
            ocsp(single(issuer = signerCert.cert), rid = byKey(r.cert), signer = respKey.private, certs = embed(r.der)),
            issuer = signerCert.cert, chain = listOf(leaf.cert, signerCert.cert, root.cert),
        )
        fun rIss(vararg x: ByteArray) = responder(issuer = dn("Issuing CA"), signer = interKey.private, exts = listOf(eku(KP_OCSP), *x))
        assertEquals("OK:good", di(rIss()))
        assertEquals("OK:good", di(rIss(aki(skiId))))
        assertEquals(notSigned, di(rIss(aki(b(9, 9, 9, 9)))))
        assertEquals(notSigned, di(rIss(ext("2.5.29.35", false, seq(tlv(0x82, b(1)))))))
        assertEquals("OK:good", di(rIss(ext("2.5.29.35", false, seq(tlv(0x82, b(9)))))))
        assertEquals(notSigned, di(rIss(ext("2.5.29.35", false, b(0x05, 0)))))
        val noSign = issue(dn("Issuing CA"), dn(ROOT_CN), rootKey.private, interKey, serial = int(9), exts = listOf(BC_CA, ext("2.5.29.15", true, tlv(0x03, b(7, 0x80)))))
        assertEquals(notSigned, di(rIss(), noSign))
        val noKu = issue(dn("Issuing CA"), dn(ROOT_CN), rootKey.private, interKey, serial = int(9), exts = listOf(BC_CA))
        assertEquals("OK:good", di(rIss(), noKu))
        assertEquals("OK:good", di(rIss(aki(skiId)), noKu)) // an issuer without a SKI has nothing to compare
        val badSki = issue(dn("Issuing CA"), dn(ROOT_CN), rootKey.private, interKey, serial = int(9), exts = listOf(BC_CA, ext("2.5.29.14", false, b(0x05, 0))))
        assertEquals(notSigned, di(rIss(aki(skiId)), badSki))
        val badKu = issue(dn("Issuing CA"), dn(ROOT_CN), rootKey.private, interKey, serial = int(9), exts = listOf(BC_CA, ext("2.5.29.15", true, b(0x05, 0))))
        assertEquals(notSigned, di(rIss(), badKu))
        // a responderID naming the issuer whose signature fails: the issuer-key reason, whatever was embedded
        assertEquals(issuerSig, d(DELEGATE, rid = byName(inter.cert)))
    }

    @Test
    fun outerAndTbsSignatureAlgorithmsMustMatch() = nv {
        fun c(inner: String, outer: String): AttestCert.Cert {
            val tbs = seq(tlv(0xa0, int(2)), int(5), seq(oid(inner)), dn(ROOT_CN), seq(utc(NOW - DAY), utc(NOW + DAY)), dn("Algs"), respKey.public.encoded)
            return AttestCert.parseCertDer(seq(tbs, seq(oid(outer)), bits(sign("SHA256withECDSA", rootKey.private, tbs))))
        }
        assertTrue(AttestCert.certSigOkBy(c(EC256, EC256), root.cert))
        assertFalse(AttestCert.certSigOkBy(c(EC384, EC256), root.cert))
    }

    @Test
    fun rsaDelegatedResponder() = nv {
        val rsa = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair()
        val r = responder(cn = "RSA Responder", key = rsa)
        fun d(jca: String, o: String, sig: ByteArray? = null) =
            ocspWhy(response(basic(rdata(single(), rid = byKey(r.cert)), rsa.private, jca, o, embed(r.der), sig)))
        assertEquals("OK:good", d("SHA256withRSA", RSA256))
        assertEquals("OK:good", d("SHA384withRSA", RSA384))
        assertEquals("OK:good", d("SHA512withRSA", RSA512))
        assertEquals(delegatedSig, d("SHA256withRSA", RSA384))
        assertEquals(delegatedSig, d("SHA256withRSA", EC256))
        assertEquals(delegatedSig, d("SHA256withRSA", RSA256, b(1, 2, 3))) // a wrong-length RSA signature throws inside verify
        // PKCS#1 under an rsa-pss key: the same key, only the SPKI algorithm differs
        val pub = rsa.public as java.security.interfaces.RSAPublicKey
        val pkcs1 = seq(tlv(0x02, pub.modulus.toByteArray()), tlv(0x02, pub.publicExponent.toByteArray()))
        val pss = responder(cn = "PSS Responder", key = null, spki = seq(seq(oid("1.2.840.113549.1.1.10")), bits(pkcs1)))
        assertEquals(delegatedSig, ocspWhy(response(basic(rdata(single(), rid = byKey(pss.cert)), rsa.private, "SHA256withRSA", RSA256, embed(pss.der)))))
    }

    @Test
    fun runtimeExceptionsBecomeRefusals() = nv {
        fun throwing(msg: String?) = object : AbstractList<AttestCert.Cert>() {
            override val size: Int get() = throw IllegalStateException(msg)
            override fun get(index: Int): AttestCert.Cert = throw IllegalStateException(msg)
        }
        val der = ocsp(single(), rid = byKey(DELEGATE.cert), signer = respKey.private, certs = embed(DELEGATE.der))
        assertEquals(rej + "boom", ocspWhy(der, chain = throwing("boom")))
        assertEquals(rej + "IllegalStateException", ocspWhy(der, chain = throwing(null)))
    }

    @Test
    fun chainOcsp() = nv {
        val goodLeaf = ocsp(single())
        val goodInter = ocsp(single(inter.cert, root.cert), rid = byName(root.cert), signer = rootKey.private)
        fun c(chain: List<AttestCert.Cert>, vararg rs: ByteArray) = AttestNvidiaCollateral.checkChainOcsp(chain, rs.toList(), NOW)
        assertEquals("chain too short for OCSP", c(listOf(leaf.cert), goodLeaf))
        assertEquals("", c(listOf(leaf.cert, inter.cert), goodLeaf))
        assertEquals("no OCSP responses supplied", c(CHAIN))
        assertEquals("", c(CHAIN, goodLeaf, goodInter))
        assertEquals("no GOOD OCSP response for required certificate '${line(INTER_CN)}' (status: absent)", c(CHAIN, goodLeaf))
        assertEquals("no GOOD OCSP response for required certificate '${line(LEAF_CN)}' (status: absent)", c(CHAIN, goodInter))
        assertEquals("no GOOD OCSP response for required certificate '${line(LEAF_CN)}' (status: unknown)", c(CHAIN, ocsp(single(status = UNKNOWN)), goodInter))
        // a certificate without an OCSP responder URL needs no response
        val interNoAia = issue(dn(INTER_CN), dn(ROOT_CN), rootKey.private, interKey, serial = int(2), exts = listOf(BC_CA, KU_CA))
        assertEquals("", c(listOf(leaf.cert, interNoAia.cert, root.cert), goodLeaf))
        assertEquals("chain certificate '${line(LEAF_CN)}' is revoked (OCSP)", c(CHAIN, ocsp(single(status = REVOKED))))
        assertEquals("OCSP response #0 for '${line(LEAF_CN)}' rejected: response is not valid DER", c(CHAIN, b(1, 2, 3)))
        val unrelated = ocsp(single(id = certId(leaf.cert, inter.cert, serial = int(5))))
        assertEquals("OCSP response #1 rejected: $noMatch", c(CHAIN, goodLeaf, unrelated))
        assertEquals("duplicate OCSP responses for chain certificate #0", c(CHAIN, goodLeaf, goodLeaf))
        // one response answering for two chain certificates (a delegate of the root signs both)
        val rootDelegate = responder(cn = "Root OCSP Responder", issuer = dn(ROOT_CN), signer = rootKey.private)
        val both = ocsp(single(), single(inter.cert, root.cert), rid = byKey(rootDelegate.cert), signer = respKey.private, certs = embed(rootDelegate.der))
        assertEquals("OCSP response #0 matches more than one chain certificate", c(CHAIN, both))
    }
}
