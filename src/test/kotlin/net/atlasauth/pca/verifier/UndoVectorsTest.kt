package net.atlasauth.pca.verifier

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Undo windows, the pure layer: `undo-vectors.json` (computed by the TypeScript reference; a missing file FAILS, never skips), every
 * section with full equality. The token and the receipts are re-signed here from the vectors' seed and must match byte for byte.
 */
@Suppress("UNCHECKED_CAST")
class UndoVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("undo-vectors.json") }
    private fun m(x: Any?): Map<String, Any?> = x as Map<String, Any?>
    private fun l(x: Any?): List<Map<String, Any?>> = x as List<Map<String, Any?>>
    private fun canon(v: Any?): String = Json.canonicalize(v)

    private val signer: Map<String, Any?> get() = m(doc["signer"])
    private val seed: ByteArray get() = MessageDigest.getInstance("SHA-256").digest((signer["seed_label"] as String).toByteArray(Charsets.UTF_8))

    @Test
    fun formatAndSigner() {
        assertEquals("pca-undo-vectors", doc["format"])
        assertTrue(OracleFacts.isOne(doc["ver"]))
        assertEquals(signer["public"], Keys.edFromSeed(seed).id())
    }

    @Test
    fun compensation() {
        val cs = l(doc["compensation"])
        assertEquals(3, cs.size)
        for (c in cs) assertEquals(c["name"].toString(), c["digest"], Undo.compensationDigest(m(c["compensation"])))
    }

    @Test
    fun tokenSignEncodeDecodeDigest() {
        val t = m(doc["token"])
        val signed = Undo.signToken(m(t["record"]), seed)
        assertEquals(canon(t["token"]), canon(signed))
        assertEquals(t["encoded"], Undo.encodeToken(signed))
        assertEquals(canon(t["token"]), canon(Undo.decodeToken(t["encoded"])))
        assertEquals(t["digest"], Undo.tokenDigest(m(t["token"])))
        assertNull(Undo.decodeToken("not base64url!"))
        assertNull(Undo.decodeToken(42))
    }

    @Test
    fun tokenChecks() {
        val checks = l(m(doc["token"])["checks"])
        assertTrue(checks.size >= 10)
        for (c in checks) {
            assertEquals(c["name"].toString(), c["expect"], Undo.tokenCheck(c["token"], c["signer"] as String, m(c["record"]), c["now"]))
        }
        // every code is reachable from the vectors
        assertEquals(setOf("ok", "malformed", "signer", "signature", "record", "binding", "expired"), checks.map { it["expect"] }.toSet())
    }

    @Test
    fun receiptsSignVerifyDigest() {
        val list = l(m(doc["receipts"])["list"])
        assertEquals(4, list.size)
        for ((i, e) in list.withIndex()) {
            val r = m(e["receipt"])
            assertEquals("receipt $i", e["digest"], Undo.receiptDigest(r))
            assertTrue("receipt $i", Undo.verifyReceipt(r, signer["public"] as String))
            assertTrue("receipt $i: another signer", !Undo.verifyReceipt(r, signer["other_public"] as String))
            val body = LinkedHashMap<String, Any?>()
            for (k in listOf("record", "event", "state", "at", "compensation_digest", "prev", "note")) body[k] = r[k]
            assertEquals("receipt $i", canon(r), canon(Undo.signReceipt(body, seed)))
        }
    }

    @Test
    fun receiptChains() {
        val chains = l(m(doc["receipts"])["chains"])
        assertTrue(chains.size >= 10)
        for (c in chains) {
            val rec = LinkedHashMap(m(c["record"]))
            rec["receipts"] = c["receipts"]
            val ok = m(c["expect"])["ok"] == true
            val err = Undo.receiptChainError(rec, c["signer"] as String)
            assertEquals("${c["name"]}: $err", ok, err == null)
        }
    }

    @Test
    fun transitions() {
        val ts = l(doc["transitions"])
        assertTrue(ts.size >= 30)
        for (c in ts) {
            val e = m(c["expect"])
            val t = Undo.transition(c["record"], c["event"], c["now"])
            val name = "${c["name"]}: ${t.outcome} ${t.code} ${t.reason}"
            assertEquals(name, e["outcome"], t.outcome)
            if (e.containsKey("code")) assertEquals(name, e["code"], t.code)
            if (e["outcome"] == "applied") {
                val r = t.record!!
                assertEquals(name, e["state"], r["state"])
                assertEquals(name, IntentJs.lng(e["ver"]), IntentJs.lng(r["ver"]))
                if (e.containsKey("attempt")) assertEquals(name, IntentJs.lng(e["attempt"]), IntentJs.lng(r["attempt"]))
            } else {
                assertEquals(name, false, e.containsKey("state"))
            }
        }
    }

    @Test
    fun window() {
        for (c in l(doc["window"])) {
            val p = m(c["policy"])
            val got = Undo.resolveWindow(c["requested"], IntentJs.num(p["minMs"]), IntentJs.num(p["maxMs"]), IntentJs.num(p["defaultMs"]))
            assertEquals(c["name"].toString(), IntentJs.lng(c["expect"]), got)
        }
    }

    @Test
    fun obligation() {
        for (c in l(doc["obligation"])) {
            val ok = m(c["expect"])["ok"] == true
            val err = Obligations.obligationError(c["obligation"])
            assertEquals("${c["name"]}: $err", ok, err == null)
        }
    }
}
