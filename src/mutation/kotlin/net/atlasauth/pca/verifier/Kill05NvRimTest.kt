package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/** AttestNvidiaCollateral.verifyRim: size limit, strict XMLDSig profile, signer chain, signature, digest, Measurement resources. */
class Kill05NvRimTest {
    private val sid = "<SoftwareIdentity xmlns=\"" + Kill05NvKit.SWID + "\" xmlns:ds=\"" + Kill05NvKit.DS + "\">"
    private val end = "</SoftwareIdentity>"
    private val err = "RIM: verification error (fail closed): "

    @Test
    fun documentSizeAndPins() = nv {
        assertEquals("RIM: empty or oversized document", rimWhy(""))
        assertEquals(err + "text outside the document element", rimWhy("x".repeat(4_000_000)))
        assertEquals("RIM: empty or oversized document", rimWhy("x".repeat(4_000_001)))
        // the limit counts code points: 2,000,001 astral characters are 4,000,002 UTF-16 units
        assertEquals(err + "text outside the document element", rimWhy("😀".repeat(2_000_001)))
        assertEquals("RIM: no pinned RIM root configured", rimWhy("<a/>", emptyList()))
        assertEquals(err + "element <a> is not closed", rimWhy("<a>"))
        assertEquals("RIM: XML comments are not permitted", rimWhy("<!-- c --><a/>"))
        assertEquals("RIM: root element is not SoftwareIdentity", rimWhy("<a/>"))
    }

    @Test
    fun signatureStructure() = nv {
        val one = "RIM: expected exactly one Signature element"
        assertEquals(one, rimWhy(sid + META + PAYLOAD + end))
        assertEquals(one, rimWhy(sid + "<ds:Signature/><ds:Signature/>" + end))
        assertEquals("RIM: the Signature must be a direct child of the root", rimWhy(sid + "<Payload><ds:Signature/></Payload>" + end))
        assertEquals("RIM: expected exactly one SignedInfo", rimWhy(sid + "<ds:Signature/>" + end))
        assertEquals("RIM: expected exactly one SignedInfo", rimWhy(sid + "<ds:Signature><ds:SignedInfo/><ds:SignedInfo/></ds:Signature>" + end))
        assertEquals("RIM: CanonicalizationMethod must be C14N 1.1", rimWhy(sid + "<ds:Signature><ds:SignedInfo/></ds:Signature>" + end))
        fun si(inner: String) = rimWhy(sid + "<ds:Signature><ds:SignedInfo>" + C14N_EL + METHOD_EL + inner + "</ds:SignedInfo></ds:Signature>" + end)
        assertEquals("RIM: expected exactly one Reference", si(""))
        assertEquals("RIM: expected exactly one Reference", si("<ds:Reference URI=\"\"/><ds:Reference URI=\"\"/>"))
        val env = "<ds:Transform Algorithm=\"$ENVELOPED\"/><ds:Transform Algorithm=\"$C14N11\"/>"
        val wrongDigest = "<ds:DigestMethod Algorithm=\"$DS" + "sha1\"/>"
        // Transform elements directly under Reference are read when there is no Transforms wrapper
        assertEquals("RIM: DigestMethod must be SHA-384", si("<ds:Reference URI=\"\">$env$wrongDigest</ds:Reference>"))
        assertEquals("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]", si("<ds:Reference URI=\"\"><ds:Transforms/>$env$DIGEST_EL</ds:Reference>"))
    }

    @Test
    fun valuesAndKeyInfo() = nv {
        val missing = "RIM: missing DigestValue / SignatureValue"
        assertEquals(missing, rimWhy(rim(dv = { "" })))
        assertEquals(missing, rimWhy(rim(sv = { "" })))
        assertEquals(missing, rimWhy(rim(dv = { "<ds:DigestValue> \n\t </ds:DigestValue>" })))
        assertEquals(missing, rimWhy(rim(sv = { "<ds:SignatureValue>\t \n</ds:SignatureValue>" })))
        val noCerts = "RIM: no signer certificates in KeyInfo"
        assertEquals(noCerts, rimWhy(rim(keyInfo = "")))
        assertEquals(noCerts, rimWhy(rim(keyInfo = "<ds:KeyInfo/>")))
        assertEquals(noCerts, rimWhy(rim(keyInfo = "<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>")))
        assertEquals("RIM signer chain: chain root is not a pinned NVIDIA root", rimWhy(rim(), listOf("00")))
        assertEquals("RIM: SignatureValue is not a 96-byte P-384 signature", rimWhy(rim(sv = { "<ds:SignatureValue>" + b64(ByteArray(64)) + "</ds:SignatureValue>" })))
        assertEquals("RIM: SignedInfo signature does not verify under the signer certificate", rimWhy(rim(key = leafKey.private)))
        assertEquals("RIM: document digest does not match the signed DigestValue", rimWhy(rim(digestOf = { b64(ByteArray(48)) })))
        // whitespace inside the values and the certificates is not significant
        fun wrap(s: String) = "\n " + s.chunked(16).joinToString("\n ") + "\n"
        val spaced = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + wrap(b64(rimSigner.der)) + "</ds:X509Certificate><ds:X509Certificate>" +
            wrap(b64(root.der)) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        val ws = rim(
            dv = { "<ds:DigestValue>" + wrap(it) + "</ds:DigestValue>" },
            sv = { "<ds:SignatureValue>" + wrap(it) + "</ds:SignatureValue>" },
            keyInfo = spaced,
        )
        assertEquals("OK", rimWhy(ws))
    }

    @Test
    fun manifestContent() = nv {
        val (r0, why) = AttestNvidiaCollateral.verifyRim(rim(), RIM_PINS, NOW)
        assertEquals("", why)
        assertNotNull(r0)
        val r = r0!!
        assertEquals("GH100", r.product)
        assertEquals("535.86.10", r.version)
        assertEquals(listOf(0), r.golden.keys.toList())
        val g = r.golden.getValue(0)
        assertEquals(0, g.index)
        assertEquals(true, g.active)
        assertEquals(1, g.alternatives)
        assertEquals(4, g.size)
        assertEquals(listOf("aabbccdd"), g.hashes)
        // Hash<n> attributes are ordered by n, upper-case hex is lowered, `active` is case-insensitive
        val two = "<Resource type=\"Measurement\" index=\"7\" active=\"TRUE\" alternatives=\"2\" size=\"2\" Hash1=\"CCDD\" Hash0=\"aabb\"/>" +
            res("3", listOf("ab"), active = "false")
        val (r2, why2) = AttestNvidiaCollateral.verifyRim(rim(payload = "<Payload>$two</Payload>"), RIM_PINS, NOW)
        assertEquals("", why2)
        val rr = r2!!
        val g7 = rr.golden.getValue(7)
        assertEquals(listOf("aabb", "ccdd"), g7.hashes)
        assertEquals(2, g7.alternatives)
        assertEquals(true, g7.active)
        val g3 = rr.golden.getValue(3)
        assertEquals(false, g3.active)
        assertEquals(1, g3.size)
        assertEquals(listOf(7, 3), rr.golden.keys.toList())
    }

    @Test
    fun measurementResources() = nv {
        fun p(vararg resources: String) = rimWhy(rim(payload = "<Payload>" + resources.joinToString("") + "</Payload>"))
        val malformed = "RIM: malformed Measurement resource"
        val h = listOf("aabbccdd")
        assertEquals("RIM: missing Meta / Payload", rimWhy(rim(meta = "")))
        assertEquals("RIM: missing Meta / Payload", rimWhy(rim(payload = "")))
        assertEquals("OK", p(res("", h))) // Number("") is 0
        assertEquals("OK", p(res("3", listOf("ab"))))
        for (bad in listOf("-1", "1.5", "abc", "1e19", "+0x1", "0x1p3", "1f", "1d", "NaN", "Infinity")) assertEquals("index $bad", malformed, p(res(bad, h)))
        assertEquals("OK", p(res("0x1", h))) // attest-nvidia-rim.ts:218 Number("0x1") is 1
        assertEquals(malformed, p(res("1", h, alts = "0")))
        assertEquals(malformed, p(res("1", h, size = "0")))
        assertEquals(malformed, p(res("1", h, alts = "x")))
        assertEquals(malformed, p(res("1", h, size = "x")))
        assertEquals("OK", p(res("1", listOf("AABBCCDD"))))
        val inconsistent = "RIM: Measurement 1 hash list is inconsistent with alternatives/size"
        assertEquals(inconsistent, p(res("1", h, alts = "2")))
        assertEquals(inconsistent, p(res("1", listOf("zzzzzzzz"))))
        assertEquals(inconsistent, p(res("1", listOf("aabbcc"), size = "4")))
        assertEquals("RIM: duplicate Measurement index 1", p(res("1", h), res("1", h)))
        assertEquals("RIM: no measurements", p(res("1", h, type = "Other")))
    }
}
