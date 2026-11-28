package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** A repeated member in the Sigstore entry body or the in-toto statement is refused; non-canonical numbers (8.0, 1e3) stay accepted. Bundles are minted with throwaway keys. */
class SigstoreDuplicateMemberTest {
    private val K = Kill05SigKit

    private fun why(b: MutableMap<String, Any?>): String {
        val r = Sigstore.verifySigstoreBundleCore(b, K.roots())
        return if (r.ok) "ok" else "${r.code}: ${r.detail}"
    }

    @Test fun aRepeatedMemberInTheEntryBodyIsRefused() {
        for (kind in listOf("dsse", "intoto")) {
            val mk: (String, String, String) -> String = { a, s, c ->
                (if (kind == "dsse") K.dsseBody(a, s, c) else K.intotoBody(a, s, c)).replaceFirst("{", "{\"kind\":\"x\",")
            }
            assertEquals(kind, "tlog_body: fail closed: duplicate key \"kind\"", why(K.bundle(kind, body = mk)))
        }
    }

    @Test fun aRepeatedMemberInTheStatementIsRefused() {
        assertEquals("statement: fail closed: duplicate key \"_type\"", why(K.bundle(payload = K.STATEMENT.replaceFirst("{", "{\"_type\":\"x\","))))
    }

    @Test fun nonCanonicalNumbersStayAccepted() {
        val mk: (String, String, String) -> String = { a, s, c -> K.dsseBody(a, s, c).replaceFirst("{", "{\"n\":8.0,\"e\":1e3,") }
        assertEquals("ok", why(K.bundle("dsse", body = mk)))
        assertEquals("ok", why(K.bundle(payload = K.STATEMENT.replaceFirst("{", "{\"n\":8.0,\"e\":1e3,"))))
    }
}
