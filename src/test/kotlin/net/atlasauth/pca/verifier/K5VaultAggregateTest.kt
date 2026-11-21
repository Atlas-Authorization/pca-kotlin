package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** K5 tokenisation vault and aggregate reads (C-315..C-319): `vault-aggregate-vectors.json`. A missing file FAILS (ParityVectors.load throws). */
@Suppress("UNCHECKED_CAST")
class K5VaultAggregateTest {
    private val va = ParityVectors.load("vault-aggregate-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun canon(o: Any?): String = Json.canonicalize(o)
    private fun num(n: Long) = Json.Num(n.toString())

    @Test
    fun samplerStreams() {
        val s = m(va["sampler"])
        assertTrue(l(s["uniform"]).isNotEmpty() && l(s["laplace"]).size >= 4)
        for (x in l(s["uniform"])) {
            val u = m(x)
            val d = ReadVault.seededDraws(u["seed"] as String)
            assertEquals("uniform ${u["seed"]}", canon(u["draws"]), canon(l(u["bounds"]).map { d.uniform(Json.asLong(it)) }))
        }
        for (x in l(s["laplace"])) {
            val c = m(x)
            val d = ReadVault.seededDraws(c["seed"] as String)
            val got = l(c["values"]).map { ReadVault.discreteLaplace(d, Json.asLong(c["s"]), Json.asLong(c["t"])) }
            assertEquals("laplace ${c["seed"]}", canon(c["values"]), canon(got))
        }
    }

    @Test
    fun samplerBounds() {
        val d = ReadVault.seededDraws("x")
        for (n in listOf(0L, -1L, (1L shl 47) + 1L)) assertTrue("bound $n", runCatching { d.uniform(n) }.isFailure)
    }

    @Test
    fun secureNoiseDiffersPerCall() {
        fun draw() = ReadVault.secureDraws().let { d -> (0 until 8).map { d.uniform(1L shl 47) } }
        assertNotEquals(draw(), draw())
    }

    @Test
    fun vault() {
        val grants = m(m(va["grants"])["vault"])
        assertTrue(l(va["vault"]).size >= 13)
        for (x in l(va["vault"])) {
            val c = m(x)
            val store = ReadVault.memoryVault()
            val r = m(c["redact"])
            val red = ReadVault.redactReadWithVault(
                ReadSide.ReadInput(grants[c["redact_grant"]], r["principal"], r["now"], r["verb"], r["resource"], r["purpose"], r["schema"], r["record"], r["tighten"], r["salt"], r["counts"]),
                store,
            )
            val token = c["token"] ?: red.view[c["field"]]
            val dt = m(c["detok"])
            val got = ReadVault.detokenize(ReadVault.DetokenizeInput(grants[c["detok_grant"]], dt["principal"], dt["now"], dt["sink"], token, store))
            assertEquals("vault ${c["name"]}", canon(c["expect"]), canon(got.toMap()))
        }
    }

    @Test
    fun aggregate() {
        val keys = m(va["keys"])
        val grants = m(m(va["grants"])["aggregate"])
        assertTrue(l(va["aggregate"]).size >= 10)
        for (x in l(va["aggregate"])) {
            val c = m(x)
            var state: Any? = c["initial_state"]
            for (sx in l(c["steps"])) {
                val s = m(sx)
                val i = LinkedHashMap<String, Any?>(
                    mapOf(
                        "principal" to keys["principal"], "now" to num(1_800_000_000_000L), "verb" to "orders.stats", "resource" to "orders/eu", "purpose" to "analytics", "fn" to "sum",
                        "values" to listOf(num(10), num(20), num(500), num(-900)), "salt" to "a-per-read-secret-salt", "noise" to "seeded",
                    ),
                )
                i.putAll(m(s["input"]))
                val got = ReadVault.aggregateRead(
                    ReadVault.AggregateInput(grants[i["grant"]], i["principal"], i["now"], i["verb"], i["resource"], i["purpose"], i["fn"], i["values"], i["salt"], i["noise"], state),
                )
                assertEquals("aggregate ${c["name"]}", canon(s["expect"]), canon(got.toMap()))
                state = got.state
            }
        }
    }

    @Test
    fun hostileInputNeverThrows() {
        val none = ReadVault.aggregateRead(ReadVault.AggregateInput(null, null, null, null, null, null, null, null, null, null, null))
        assertEquals("bad_request", none.code)
        assertEquals(canon(ReadVault.emptyAggregateState()), canon(none.state))
        assertEquals("bad_request", ReadVault.detokenize(ReadVault.DetokenizeInput(null, null, null, null, null, null)).code)
        assertEquals("deny", ReadVault.redactReadWithVault(ReadSide.ReadInput(null, null, null, null, null, null, null, null, null, null, null), ReadVault.memoryVault()).decision)
    }
}
