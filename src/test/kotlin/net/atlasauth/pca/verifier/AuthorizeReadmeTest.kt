package net.atlasauth.pca.verifier

import java.io.File
import java.sql.DriverManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The README `authorize (0.5)` sample runs as written: [sample] holds its text verbatim between the markers (the test
 * below asserts the two are identical, imports aside) and is executed against a fixture proof. The fixtures are dated,
 * so `System` here is a clock pinned to the fixtures' `now`.
 */
class AuthorizeReadmeTest {
    private object System {
        fun currentTimeMillis(): Long = AuthorizeTestKit.NOW
    }

    @Suppress("UNUSED_VARIABLE")
    private fun sample(
        pcactn: Any?, body: Map<String, Any?>, grants: Map<String, Map<String, Any?>>, revokedGrantIds: Set<String>,
        sendPayment: (Map<String, Any?>) -> Unit,
    ): Authorize.Result {
        // README-BEGIN
        // One row per (grant, agent), safe across processes. Any JDBC connection works: SQLite 3.24+ or PostgreSQL 9.5+.
        val store = PcaJdbcStateStore({ DriverManager.getConnection("jdbc:sqlite:pca-replay.db") })

        val operation = Authorize.Operation("payments.send", "payments/acme", body) // what you will execute
        val result = Authorize.authorize(
            pcactn, // the PCActn as JSON text, UTF-8 bytes or a parsed object
            Authorize.Input(
                operation = operation,
                audience = "payments-rs",
                resolveGrant = { grantRef -> grants[grantRef] }, // from your own store
                stateStore = store,
                isRevoked = { _, grant -> grant["id"] as? String in revokedGrantIds }, // your revocation list
                plan = Authorize.SINGLE_STEP,
                now = System.currentTimeMillis(), // epoch ms; the default is the wall clock
            ),
        )
        if (!result.allow) throw SecurityException(result.reason) // e.g. "policy: caveat(s) not satisfied: max_spend"
        sendPayment(body)
        // README-END
        return result
    }

    @Test
    fun readmeSampleIsVerbatim() {
        val readme = File("README.md").readText(Charsets.UTF_8)
        val at = readme.indexOf("## authorize (0.5)")
        assertTrue("README.md has no '## authorize (0.5)' section (the mirror README asset must carry it)", at >= 0)
        val section = readme.substring(at)
        val block = section.substringAfter("```kotlin\n").substringBefore("```").lines()
        val imports = block.takeWhile { it.startsWith("import ") || it.isEmpty() }
        val code = block.drop(imports.size).dropLastWhile { it.isEmpty() }
        val src = File("src/test/kotlin/net/atlasauth/pca/verifier/AuthorizeReadmeTest.kt").readText(Charsets.UTF_8)
        val region = src.substringAfter("// README-BEGIN\n").substringBefore("        // README-END").lines()
            .dropLastWhile { it.isEmpty() }.map { if (it.startsWith("        ")) it.substring(8) else it }
        assertEquals(code, region)
        for (i in imports.filter { it.isNotEmpty() }) assertTrue(i, src.contains("\n$i\n") || i == "import net.atlasauth.pca.verifier.Authorize" || i == "import net.atlasauth.pca.verifier.PcaJdbcStateStore")
    }

    @Test
    fun readmeSampleRuns() {
        val db = File("pca-replay.db")
        db.delete()
        try {
            val c = AuthorizeTestKit.case("envelope-max-spend-within")
            val g = AuthorizeTestKit.grant(c)
            val grants = mapOf(g["id"] as String to g)
            val text = Json.canonicalizeStrict(AuthorizeTestKit.pcactn(c))
            val body = Json.parse("""{"amount":50,"currency":"usd"}""") as Map<String, Any?>
            val sent = ArrayList<Map<String, Any?>>()
            assertTrue(sample(text, body, grants, emptySet()) { sent.add(it) }.allow)
            assertEquals(listOf(body), sent)
            try { // the same proof again: the SQLite store refuses it
                sample(text, body, grants, emptySet()) { sent.add(it) }
                fail("replay accepted")
            } catch (e: SecurityException) {
                assertEquals("replay: 1 is not greater than last seen 1 (replay)", e.message)
            }
            val c2 = AuthorizeTestKit.case("revoked")
            val g2 = AuthorizeTestKit.grant(c2)
            try {
                sample(AuthorizeTestKit.pcactn(c2), body, mapOf(g2["id"] as String to g2), setOf(g2["id"] as String)) { sent.add(it) }
                fail("revoked accepted")
            } catch (e: SecurityException) {
                assertEquals("revocation: the grant is revoked", e.message)
            }
            assertEquals(1, sent.size)
        } finally {
            db.delete()
        }
    }
}
