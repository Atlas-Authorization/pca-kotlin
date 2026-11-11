package net.atlasauth.pca.verifier

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** H6 (at most 8 RFC 3161 timestamps, refused before any is verified) and H7 (a lenient JSON segment over 16 MiB is refused unparsed). */
@Suppress("UNCHECKED_CAST")
class Kill14BTimestampCapAndJsonSizeTest {
    private val K = Kill05SigKit

    private fun withTimestamps(n: Int): Map<String, Any?> {
        val b = K.bundle()
        val ts = MutableList<Any?>(n) { linkedMapOf<String, Any?>("signedTimestamp" to "AAAA") }
        K.vm(b)["timestampVerificationData"] = linkedMapOf<String, Any?>("rfc3161Timestamps" to ts)
        return b
    }

    @Test fun nineTimestampsAreRefusedBeforeVerification() {
        val x = Sigstore.verifySigstoreBundleCore(withTimestamps(9), K.roots())
        assertFalse(x.ok)
        assertEquals("tsa", x.code)
        assertEquals("too many RFC 3161 timestamps (9, at most 8)", x.detail)
    }

    @Test fun eightTimestampsReachVerification() {
        val x = Sigstore.verifySigstoreBundleCore(withTimestamps(8), K.roots())
        assertFalse(x.ok)
        assertEquals("tsa", x.code)
        assertTrue(x.detail, !x.detail!!.startsWith("too many"))
    }

    private fun seg(n: Int): String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(n) { ' '.code.toByte() })

    @Test fun aJwsSegmentOver16MiBIsRefusedUnparsed() {
        val over = AttestUtil.MAX_JSON_BYTES + 1
        val e = org.junit.Assert.assertThrows(AttErr::class.java) { AttestJws.parseJwt("${seg(over)}.${seg(2)}.AAAA", "P") }
        assertEquals("P: malformed JSON segment: input too large", e.message)
        // at the cap the size check passes (blank text is then an ordinary parse failure)
        val at = org.junit.Assert.assertThrows(AttErr::class.java) { AttestJws.parseJwt("${seg(AttestUtil.MAX_JSON_BYTES)}.${seg(2)}.AAAA", "P") }
        assertTrue(at.message, !at.message!!.endsWith("input too large"))
    }
}
