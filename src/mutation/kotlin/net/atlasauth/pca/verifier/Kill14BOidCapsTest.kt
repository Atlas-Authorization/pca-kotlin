package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** OID caps: content over 256 bytes and an arc over 64 base-128 groups are refused before any big-integer work. */
class Kill14BOidCapsTest {
    private fun d(content: ByteArray): String = try {
        AttestDer.oidToDotted(content, AttestDer.Tlv(0x06, 0, content.size))
    } catch (e: AttErr) {
        "ERR " + e.message
    }

    private fun arc(groups: Int): ByteArray = ByteArray(groups) { if (it == 0) 0x81.toByte() else if (it == groups - 1) 0x01 else 0x80.toByte() }.also {
        // groups >= 2: 0x81 0x80.. 0x01 would be non-minimal only for a leading 0x80, so the first byte is 0x81
    }

    @Test fun ordinaryOidsDecode() {
        assertEquals("2.5.29.19", d(byteArrayOf(0x55, 0x1d, 0x13)))
        val uuid = byteArrayOf(0x69) + ByteArray(18) { 0xff.toByte() } + byteArrayOf(0x7f) // 2.25.<19-group arc>
        assertTrue(d(uuid).startsWith("2.25."))
    }

    @Test fun contentOver256BytesIsTooLong() {
        val big = ByteArray(300) { 0x81.toByte() }; big[299] = 0x01
        assertEquals("ERR extension OID is too long", d(big))
        val edge = byteArrayOf(0x2a) + ByteArray(255) { 1 }
        assertTrue(!d(edge).startsWith("ERR"))
        assertEquals("ERR extension OID is too long", d(byteArrayOf(0x2a) + ByteArray(256) { 1 }))
    }

    @Test fun anArcOver64GroupsIsOversized() {
        assertEquals("ERR extension OID has an oversized arc", d(byteArrayOf(0x2a) + arc(65)))
        assertTrue(!d(byteArrayOf(0x2a) + arc(64)).startsWith("ERR extension OID has an oversized"))
    }
}
