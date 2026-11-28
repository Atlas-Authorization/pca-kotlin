package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** RIM XML nesting: more than 64 open elements is refused before namespace resolution can walk the ancestors. */
class Kill14BXmlDepthTest {
    private fun nest(n: Int) = "<a>".repeat(n) + "</a>".repeat(n)

    @Test fun sixtyFourDeepParsesSixtyFiveIsRefused() {
        AttestXml.parse(nest(64))
        val e = assertThrows(AttErr::class.java) { AttestXml.parse(nest(65)) }
        assertEquals("XML nesting is too deep", e.message)
        assertEquals("XML nesting is too deep", assertThrows(AttErr::class.java) { AttestXml.parse(nest(100)) }.message)
    }

    @Test fun siblingsDoNotAccumulateDepth() {
        AttestXml.parse("<r>" + "<a></a>".repeat(500) + "<b/>".repeat(500) + "</r>")
    }

    @Test fun aSelfClosingElementAtTheLimitCounts() {
        AttestXml.parse("<a>".repeat(63) + "<b/>" + "</a>".repeat(63))
        assertThrows(AttErr::class.java) { AttestXml.parse("<a>".repeat(64) + "<b/>" + "</a>".repeat(64)) }
    }
}
