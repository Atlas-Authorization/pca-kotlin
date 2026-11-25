package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Deciding tests for mutants that otherwise end as a run error: each is small, runs first, and fails (it does not hang) when the
 * cursor of the loop under test does not advance by exactly the right amount.
 */
class Kill15RunErrorDecideTest {
    @Test fun jsTrimEndsAtBothEdgesOfALeadingAndTrailingRun() = Deadline.within {
        assertEquals("x", AttestUtil.jsTrim("  x"))
        assertEquals("x", AttestUtil.jsTrim("x  "))
        assertEquals("a b", AttestUtil.jsTrim("\t\n a b  ﻿"))
        assertEquals("", AttestUtil.jsTrim("   "))
    }

    @Test fun anEndTagAndADoctypeAreConsumedExactly() = Deadline.within {
        val d = AttestXml.parse("<!DOCTYPE d><r><a>t</a>u</r>")
        assertEquals("DTD / DOCTYPE is not permitted", d.violation)
        assertEquals("r", d.root.local)
        assertEquals("a", d.root.elementChildren().single().local)
        assertEquals("tu", d.root.textContent())
        assertEquals("t", d.root.elementChildren().single().textContent())
    }
}
