package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AttestDer.allDigits is private and parseDerTime only ever hands it 12 or 14 characters, so no public input can reach its
 * empty-string refusal or tell a boundary character from a digit by itself: these call it directly (reflection) with exact
 * answers. Kills the isNotEmpty guard mutants and the digit-range / loop-condition mutants of the one-line body with a test that
 * observes them, instead of relying on whichever certificate test happens to run first.
 */
class Kill10AttestDerAllDigitsTest {
    private val m = AttestDer::class.java.getDeclaredMethod("allDigits", String::class.java).also { it.isAccessible = true }
    private fun ad(s: String) = m.invoke(AttestDer, s) as Boolean

    @Test
    fun theEmptyStringIsNotAllDigits() {
        assertFalse(ad(""))
    }

    @Test
    fun everyAsciiDigitAlone() {
        for (c in '0'..'9') assertTrue(c.toString(), ad(c.toString()))
        assertTrue(ad("0123456789"))
        assertTrue(ad("900000000009"))
    }

    @Test
    fun theCharactersNextToTheDigitRangeAndNonAsciiDigitsAreRefusedAnywhere() {
        for (bad in listOf("/", ":", "a", "Z", " ", "-", "+", "٣", "²", "\u0000")) {
            assertFalse(bad, ad(bad))
            assertFalse(bad, ad("12$bad"))
            assertFalse(bad, ad("${bad}12"))
            assertFalse(bad, ad("1${bad}2"))
        }
    }
}
