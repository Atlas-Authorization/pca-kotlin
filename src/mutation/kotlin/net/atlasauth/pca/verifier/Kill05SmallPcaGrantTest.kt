package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** Kill tests for PcaGrant (k05 small group); expectations follow the reference isHttpsUrl / validate of the pca_grant type. */
class Kill05SmallPcaGrantTest {
    @Test fun httpsUrlTable() {
        val cases = listOf<Pair<Any?, Boolean>>(
            "https://a" to true,
            "https://a/" + "p".repeat(2048 - 10) to true, // exactly 2048 characters
            "https://a/" + "p".repeat(2049 - 10) to false,
            n5 to false,
            null to false,
            "http://abc/def" to false,
            "https://a b" to false,
            "https://a!" to true, // 0x21 is the lowest allowed
            "https://a~" to true, // 0x7e is the highest allowed
            "https://a\u007f" to false,
            "https://a#x" to false,
            "https://a\\x" to false,
            "https:///x" to false, // empty authority before '/'
            "https://?x" to false, // empty authority before '?'
            "https://host/a@b" to true, // '@' after the authority is path
            "https://host?a@b" to true,
            "https://u@host/" to false,
            "https://" to false,
        )
        for ((u, want) in cases) assertEquals(u.toString(), want, PcaGrant.isHttpsUrl(u))
        assertEquals(2048, ("https://a/" + "p".repeat(2048 - 10)).length)
    }

    private val n5 = Json.Num("5")
    private val d32 = "qK9bTlJxvo3zLOQ4msAVS7_odp-g75Kfsu_Z7L47sqQ"
    private fun entry(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["type"] = "pca_grant"; m["chain_digest"] = d32; m["chain_len"] = Json.Num("1")
        for ((k, v) in over) m[k] = v
        return m
    }

    @Test fun validateCodes() {
        assertEquals(null, PcaGrant.validate(entry()))
        assertEquals("bad_chain_digest", PcaGrant.validate(entry("chain_digest" to n5)))
        assertEquals("bad_chain_digest", PcaGrant.validate(entry("chain_digest" to "abc")))
        assertEquals(null, PcaGrant.validate(entry("locations" to arrayListOf<Any?>("https://a", "https://b"))))
        assertEquals("bad_locations", PcaGrant.validate(entry("locations" to arrayListOf<Any?>("https://a", "http://b"))))
        assertEquals("bad_locations", PcaGrant.validate(entry("locations" to arrayListOf<Any?>("http://b", "https://a"))))
        assertEquals("bad_locations", PcaGrant.validate(entry("locations" to arrayListOf<Any?>())))
        assertEquals("bad_locations", PcaGrant.validate(entry("locations" to "https://a")))
        assertEquals(null, PcaGrant.validate(entry("locations" to ArrayList<Any?>(List(8) { "https://a$it" }))))
        assertEquals("bad_locations", PcaGrant.validate(entry("locations" to ArrayList<Any?>(List(9) { "https://a$it" }))))
    }
}
