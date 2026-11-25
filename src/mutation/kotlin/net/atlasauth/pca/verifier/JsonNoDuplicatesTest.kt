package net.atlasauth.pca.verifier

import net.atlasauth.pca.webbotauth.SignedDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The duplicate-member-only reader (the reference's parseNoDuplicates): a repeated member is refused at any depth; nothing else is added to JSON.parse. */
class JsonNoDuplicatesTest {
    private fun dupMessage(text: String): String? = try { Json.parseNoDuplicates(text); null } catch (e: IllegalArgumentException) { e.message }

    @Test fun aRepeatedMemberIsRefusedAtAnyDepth() {
        assertEquals("duplicate key \"keys\"", dupMessage("{\"keys\":[],\"keys\":[]}"))
        assertEquals("duplicate key \"a\"", dupMessage("{\"x\":[{\"a\":1,\"a\":2}]}"))
    }

    @Test fun otherLeniencyOfJsonParseIsKept() {
        assertEquals(null, dupMessage("{\"a\":1e3,\"b\":1.0,\"c\":\"\\ud800\"}"))
        assertEquals(null, dupMessage("{\"a\":{\"a\":1},\"b\":[{\"a\":1},{\"a\":2}]}")) // the same name in different objects is no duplicate
    }

    @Test fun aDirectoryAndAClientDataWithARepeatedMemberAreRefused() {
        try {
            SignedDirectory.parseKeyDirectory("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg\",\"kid\":\"ka\"}],\"keys\":[]}")
            fail("accepted")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message, e.message == "duplicate key \"keys\"")
        }
    }
}
