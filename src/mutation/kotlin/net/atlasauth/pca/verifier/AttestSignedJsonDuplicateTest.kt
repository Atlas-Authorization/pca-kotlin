package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** A signed collateral document is read with the strict profile: a repeated member anywhere is refused before the signature is looked at. */
class AttestSignedJsonDuplicateTest {
    private val tk = AttestCert.CertKey(null, "ed25519", "", ByteArray(32), ByteArray(32))

    private fun check(text: String) {
        val r = AttestIntel.verifySignedJson(text, "tcbInfo", tk)
        assertNull(text, r.first)
        assertEquals(text, "tcbInfo document is not valid JSON", r.second)
    }

    @Test fun aRepeatedMemberInsideTheBodyIsRefused() = check("{\"tcbInfo\":{\"a\":1,\"a\":2},\"signature\":\"00\"}")

    @Test fun aRepeatedMemberOutsideTheBodyIsRefused() = check("{\"tcbInfo\":{\"a\":1},\"signature\":\"00\",\"signature\":\"11\"}")
}
