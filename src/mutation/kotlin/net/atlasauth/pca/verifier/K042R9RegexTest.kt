package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** r9 mutation kills for SafeRegex.escapeInner: an escaped ASCII letter or digit that is not a supported escape is refused, at every edge of the three ranges. */
class K042R9RegexTest {
    @Test
    fun everyUnsupportedAsciiLetterOrDigitEscapeIsRefused() {
        val supported = "dDwWsStnvfrb0xucDS"
        for (c in ('A'..'Z') + ('a'..'z') + ('0'..'9') + '_') {
            if (c in supported) continue
            val p = "\\" + c
            assertNull(p, SafeRegex.compile(p))
            assertNull("[$p]", SafeRegex.compile("[$p]"))
        }
        // neighbours of each range are ordinary escaped punctuation and match themselves
        for (c in listOf('@', '[', '`', '{', '/', ':', '^', '.', '-', '$', '*', '\\')) {
            assertEquals("\\$c", true, SafeRegex.fullMatch("\\" + c, c.toString()))
        }
    }
}
