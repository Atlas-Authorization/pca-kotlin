package net.atlasauth.pca.aggsig

import java.io.File
import net.atlasauth.pca.verifier.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Community-standard BLS12-381 vectors (ethereum/bls12-381-tests v0.1.2) for the PoP ciphersuite
 * BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ (draft-irtf-cfrg-bls-signature has no vectors of its own), vendored in test-data
 * with provenance. The same fixtures the TypeScript package replays.
 */
@Suppress("UNCHECKED_CAST")
class AggsigKatTest {
    private val root = File("test-data/ethereum-bls12-381-tests-v0.1.2")

    private fun h(s: String): ByteArray {
        val x = if (s.startsWith("0x")) s.substring(2) else s
        return ByteArray(x.length / 2) { i -> x.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    private class Case(val name: String, val input: Any?, val output: Any?)

    private fun cases(dir: String): List<Case> {
        val files = File(root, dir).listFiles()!!.sortedBy { it.name }
        assertFalse(dir, files.isEmpty())
        return files.map { p ->
            val j = Json.parse(p.readText(Charsets.UTF_8)) as Map<String, Any?>
            Case(p.name, j["input"], j["output"])
        }
    }

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun hs(list: Any?): List<ByteArray> = (list as List<Any?>).map { h(it as String) }

    private fun assertThrowsRuntime(name: String, f: () -> Unit) {
        try { f() } catch (e: RuntimeException) { return }
        fail(name)
    }

    @Test fun sign() {
        for (c in cases("sign")) {
            val sk = h(map(c.input)["privkey"] as String)
            val msg = h(map(c.input)["message"] as String)
            if (c.output == null) assertThrowsRuntime(c.name) { AggsigCore.sign(sk, msg) }
            else assertArrayEquals(c.name, h(c.output as String), AggsigCore.sign(sk, msg))
        }
    }

    @Test fun verify() {
        for (c in cases("verify")) {
            val i = map(c.input)
            assertEquals(c.name, c.output, AggsigCore.verify(h(i["pubkey"] as String), h(i["message"] as String), h(i["signature"] as String)))
        }
    }

    @Test fun aggregate() {
        for (c in cases("aggregate")) {
            val sigs = hs(c.input)
            if (c.output == null) assertThrowsRuntime(c.name) { AggsigCore.aggregate(sigs) }
            else assertArrayEquals(c.name, h(c.output as String), AggsigCore.aggregate(sigs))
        }
    }

    @Test fun fastAggregateVerify() {
        for (c in cases("fast_aggregate_verify")) {
            val i = map(c.input)
            assertEquals(c.name, c.output, AggsigCore.fastAggregateVerify(hs(i["pubkeys"]), h(i["message"] as String), h(i["signature"] as String)))
        }
    }

    @Test fun aggregateVerify() {
        for (c in cases("aggregate_verify")) {
            val i = map(c.input)
            assertEquals(c.name, c.output, AggsigCore.aggregateVerify(hs(i["pubkeys"]), hs(i["messages"]), h(i["signature"] as String)))
        }
    }

    /** The fixtures test decoding + subgroup; KeyValidate additionally rejects the identity (draft 2.5). */
    @Test fun keyValidate() {
        for (c in cases("deserialization_G1")) {
            val pk = map(c.input)["pubkey"] as String
            val inf = Regex("^c0+$").matches(pk)
            assertEquals(c.name, (c.output as Boolean) && !inf, AggsigCore.keyValidate(h(pk)))
        }
    }

    @Test fun malformedSignaturesNeverVerify() {
        val pk = h("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
        for (c in cases("deserialization_G2")) {
            assertFalse(c.name, AggsigCore.verify(pk, ByteArray(32), h(map(c.input)["signature"] as String)))
        }
    }

    @Test fun popAndRogueKey() {
        val sk1 = h("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
        val sk2 = h("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138")
        val pk1 = AggsigCore.publicKeyOf(sk1)
        val pk2 = AggsigCore.publicKeyOf(sk2)
        val pop1 = AggsigCore.popProve(sk1)
        assertTrue(AggsigCore.popVerify(pk1, pop1))
        assertFalse(AggsigCore.popVerify(pk2, pop1))
        // domain separation both ways
        assertFalse(AggsigCore.popVerify(pk1, AggsigCore.sign(sk1, pk1)))
        assertFalse(AggsigCore.verify(pk1, pk1, pop1))
        // the public API admits only a verified proof of possession
        assertTrue(Aggsig.registerKey(pk1, pop1).ok)
        assertFalse(Aggsig.registerKey(pk2, pop1).ok)
        val reg = KeyRegistry()
        assertTrue(reg.register(pk1, pop1).ok)
        assertTrue(reg.has(pk1))
        assertFalse(reg.has(pk2))
        // one signer cannot be counted twice
        val msg = ByteArray(32)
        val s = Aggsig.sign(sk1, msg)
        val k = reg.get(pk1)
        assertTrue(Aggsig.fastAggregateVerify(listOf(k), msg, s))
        assertFalse(Aggsig.fastAggregateVerify(listOf(k, k, k), msg, Aggsig.aggregate(listOf(s, s, s))))
    }
}
