package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Test

/** A lone surrogate encodes as U+FFFD (EF BF BD), as the reference's TextEncoder writes it, not as '?'. */
class Utf8LoneSurrogateTest {
    private val fffd = byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte())

    @Test
    fun loneHighAndLowSurrogateEncodeAsFffd() {
        assertArrayEquals(byteArrayOf(0x61) + fffd + byteArrayOf(0x62), Json.utf8("a\uD800b"))
        assertArrayEquals(byteArrayOf(0x61) + fffd + byteArrayOf(0x62), Json.utf8("a\uDC00b"))
        assertArrayEquals(fffd + fffd, Json.utf8("\uDC00\uD800"))
    }

    @Test
    fun aValidPairStaysOneFourByteCodePoint() {
        assertArrayEquals(byteArrayOf(0xF0.toByte(), 0x9F.toByte(), 0x98.toByte(), 0x80.toByte()), Json.utf8("😀"))
    }
}
