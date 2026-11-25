package net.atlasauth.pca.events

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** parseEvent reads its text with the strict canonical JSON profile: a duplicate member, an exponent or trailing-zero number and a lone surrogate are refused at parse time. */
class EventsStrictParseTest {
    private val good = "{\"type\":\"step_up.approved\",\"at\":1700000000000,\"grant_ref\":\"g1\",\"action\":{\"verb\":\"stripe.refund\",\"resource\":\"pi_1\"},\"tier\":2,\"id\":\"_WFEOpHOF2DoDNCiZ82gsd88d9JSKrFI8i5s6c-eZMg\"}"

    private fun refused(text: String) {
        try {
            Events.parseEvent(text)
            fail("accepted: $text")
        } catch (e: IllegalArgumentException) {
            assertTrue(text + " -> " + e.message, e.message!!.startsWith(Events.SYNTAX_PREFIX))
        }
    }

    @Test fun aWellFormedEventParses() = assertEquals("step_up.approved", Events.parseEvent(good)["type"])

    @Test fun aDuplicateMemberIsRefused() {
        refused(good.replace("\"tier\":2,", "\"tier\":2,\"tier\":2,"))
        refused(good.replace("\"verb\":\"stripe.refund\",", "\"verb\":\"stripe.refund\",\"verb\":\"x\","))
    }

    @Test fun anExponentOrTrailingZeroNumberIsRefused() {
        refused(good.replace("1700000000000", "1.7e12"))
        refused(good.replace("1700000000000", "1700000000000.0"))
        refused(good.replace("\"tier\":2", "\"tier\":2.0"))
    }

    @Test fun aLoneSurrogateIsRefusedAtParseTime() {
        refused(good.replace("pi_1", "\\ud800"))
        refused(good.replace("pi_1", "\ud800"))
    }
}
