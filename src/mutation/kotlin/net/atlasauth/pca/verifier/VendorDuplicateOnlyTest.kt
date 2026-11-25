package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** The vendor attestation parsers refuse a repeated member and nothing else of the strict profile: 8.0, 1e3 and -0 are read as written, non-JSON reads one reason. */
class VendorDuplicateOnlyTest {
    private val k = Kill05JwsKit
    private val s = k.b64u(byteArrayOf(1))
    private val hdr = k.seg("{\"alg\":\"ES256\"}")

    private fun jwtReason(payload: String): String = try {
        AttestJws.parseJwt("$hdr.${k.seg(payload)}.$s", "P")
        "no error"
    } catch (e: AttErr) {
        e.message ?: "null"
    }

    @Test fun aVendorTokenSegmentReadsNumbersAsWritten() {
        assertEquals("no error", jwtReason("{\"a\":8.0,\"b\":1e3,\"c\":-0,\"d\":1e999}"))
    }

    @Test fun aRepeatedMemberAndNonJsonReadInvalidJson() {
        assertEquals("P: malformed JSON segment: invalid JSON", jwtReason("{\"a\":1,\"a\":2}"))
        assertEquals("P: malformed JSON segment: invalid JSON", jwtReason("not json"))
    }

    private val tk = AttestCert.CertKey(null, "ed25519", "", ByteArray(32), ByteArray(32))

    @Test fun signedCollateralReadsNumbersAsWrittenAndRefusesARepeatedMember() {
        assertEquals("tcbInfo signature missing or malformed", AttestIntel.verifySignedJson("{\"tcbInfo\":{\"a\":8.0,\"b\":1e3,\"c\":-0},\"signature\":5}", "tcbInfo", tk).second)
        assertEquals("tcbInfo document is not valid JSON", AttestIntel.verifySignedJson("{\"tcbInfo\":{\"a\":1,\"a\":2},\"signature\":5}", "tcbInfo", tk).second)
    }

    private fun runtimeReason(runtime: String): String {
        val bytes = runtime.toByteArray(Charsets.UTF_8)
        val report = AttestUtil.sha256(bytes) + ByteArray(32)
        return AttestUtil.checkAzureRuntimeDataBinding(report, bytes, Attest.Binding("h", "g", 0.0, "n"))
    }

    @Test fun runtimeDataReadsNumbersAsWrittenAndRefusesARepeatedMember() {
        assertEquals("runtime data is not valid JSON", runtimeReason("{\"a\":1,\"a\":2}"))
        assertEquals("runtime data carries no 64-byte hex user-data", runtimeReason("{\"x\":1e3,\"y\":8.0}"))
    }

    private fun certsMessage(body: String): String? = try {
        AttestMaaKeys.fetchMaaCerts("https://m.example", AttestMaaKeys.MaaFetch { AttestMaaKeys.MaaHttpResponse(200, body.toByteArray(Charsets.UTF_8), "https://m.example/certs") })
        null
    } catch (e: RuntimeException) {
        e.message
    }

    @Test fun theKeySetReadsNumbersAsWrittenAndRefusesARepeatedMember() {
        assertEquals("MAA certs response is not valid UTF-8 JSON", certsMessage("{\"keys\":[],\"keys\":[]}"))
        assertNotEquals("MAA certs response is not valid UTF-8 JSON", certsMessage("{\"n\":1e3,\"m\":8.0,\"keys\":[]}"))
    }
}
