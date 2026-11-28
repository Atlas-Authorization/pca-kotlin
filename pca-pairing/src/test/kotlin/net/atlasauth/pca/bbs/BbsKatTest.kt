package net.atlasauth.pca.bbs

import java.io.File
import java.math.BigInteger
import net.atlasauth.pca.pairing.Bls12
import net.atlasauth.pca.verifier.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The official fixtures of draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256; byte-identical across draft revisions
 * -06 through -12), vendored in test-data with provenance, plus the RFC 9380 expand_message_xmd vector.
 */
@Suppress("UNCHECKED_CAST")
class BbsKatTest {
    private val suite = File("test-data/draft-irtf-cfrg-bbs-signatures/bls12-381-sha-256")

    private fun load(rel: String): Map<String, Any?> = Json.parse(File(suite, rel).readText(Charsets.UTF_8)) as Map<String, Any?>

    private fun h(s: Any?): ByteArray {
        val x = s as String
        return ByteArray(x.length / 2) { i -> x.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    private fun hx(b: ByteArray): String = b.joinToString("") { String.format("%02x", it) }

    private fun hs(list: Any?): List<ByteArray> = (list as List<Any?>).map { h(it) }

    private fun ints(list: Any?): List<Int> = (list as List<Any?>).map { it.toString().toInt() }

    private fun map(o: Any?) = o as Map<String, Any?>

    @Test fun expandMessageXmdRfc9380() {
        val out = Bls12.expandMessageXmd(ByteArray(0), "QUUX-V01-CS02-with-expander-SHA256-128".toByteArray(Charsets.US_ASCII), 0x20)
        assertEquals("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235", hx(out))
    }

    @Test fun keyGenAndSkToPk() {
        val k = load("keypair.json")
        val sk = Bbs.keyGen(h(k["keyMaterial"]), h(k["keyInfo"]))
        assertEquals(map(k["keyPair"])["secretKey"], hx(Bbs.skToBytes(sk)))
        assertEquals(map(k["keyPair"])["publicKey"], hx(Bbs.skToPk(sk)))
    }

    @Test fun hashToScalar() {
        val f = load("h2s.json")
        assertEquals(f["scalar"], hx(Bls12.i2osp(Bbs.hashToScalar(h(f["message"]), String(h(f["dst"]), Charsets.US_ASCII)), 32)))
    }

    @Test fun mapMessageToScalar() {
        val f = load("MapMessageToScalarAsHash.json")
        for (c in f["cases"] as List<Any?>) {
            assertEquals(map(c)["scalar"], hx(Bls12.i2osp(Bbs.mapMessageToScalarAsHash(h(map(c)["message"])), 32)))
        }
    }

    @Test fun createGenerators() {
        val f = load("generators.json")
        val msg = f["MsgGenerators"] as List<Any?>
        val gens = Bbs.createGenerators(msg.size + 1)
        assertEquals(f["Q1"], hx(gens[0]))
        for (i in msg.indices) assertEquals(msg[i], hx(gens[i + 1]))
    }

    @Test fun signAndVerify() {
        for (i in 1..10) {
            val f = load(String.format("signature/signature%03d.json", i))
            val msgs = hs(f["messages"])
            val pk = h(map(f["signerKeyPair"])["publicKey"])
            val r = Bbs.verifyDetailed(pk, h(f["signature"]), h(f["header"]), msgs)
            val name = f["caseName"] as String
            if (map(f["result"])["valid"] == true) {
                assertTrue(name, r.ok)
                val sk = BigInteger(map(f["signerKeyPair"])["secretKey"] as String, 16)
                assertArrayEquals(name, h(f["signature"]), Bbs.sign(sk, pk, h(f["header"]), msgs))
            } else {
                assertFalse(name, r.ok)
                assertEquals(name, Bbs.PAIRING_MISMATCH, r.reason)
            }
        }
    }

    @Test fun proofGenAndVerify() {
        for (i in 1..15) {
            val f = load(String.format("proof/proof%03d.json", i))
            val name = f["caseName"] as String
            val msgs = hs(f["messages"])
            val idx = ints(f["disclosedIndexes"])
            val disclosed = idx.map { k -> if (k >= 0 && k < msgs.size) msgs[k] else ByteArray(0) }
            val pk = h(f["signerPublicKey"])
            val r = Bbs.proofVerifyDetailed(pk, h(f["proof"]), h(f["header"]), h(f["presentationHeader"]), disclosed, idx)
            if (map(f["result"])["valid"] == true) {
                assertTrue(name, r.ok)
                val rs = map(map(f["trace"])["random_scalars"])
                val scalars = ArrayList<BigInteger>()
                for (key in listOf("r1", "r2", "e_tilde", "r1_tilde", "r3_tilde")) scalars.add(BigInteger(rs[key] as String, 16))
                for (x in rs["m_tilde_scalars"] as List<Any?>) scalars.add(BigInteger(x as String, 16))
                val regen = Bbs.proofGen(pk, h(f["signature"]), h(f["header"]), h(f["presentationHeader"]), msgs, idx, scalars)
                assertEquals(name, f["proof"], hx(regen))
            } else {
                assertFalse(name, r.ok)
            }
        }
    }

    @Test fun randomizedProofVerifiesAndTamperingFails() {
        val f = load("signature/signature004.json")
        val msgs = hs(f["messages"])
        val pk = h(map(f["signerKeyPair"])["publicKey"])
        val hdr = h(f["header"])
        val ph = byteArrayOf(1, 2, 3)
        val idx = listOf(0, 2)
        val proof = Bbs.proofGen(pk, h(f["signature"]), hdr, ph, msgs, idx)
        val dis = listOf(msgs[0], msgs[2])
        assertTrue(Bbs.proofVerify(pk, proof, hdr, ph, dis, idx))
        assertFalse(Bbs.proofVerify(pk, proof, hdr, byteArrayOf(9), dis, idx))
        assertFalse(Bbs.proofVerify(pk, proof, hdr, ph, listOf(msgs[0], msgs[1]), idx))
        val bad = proof.clone()
        bad[proof.size - 1] = (bad[proof.size - 1].toInt() xor 1).toByte()
        assertFalse(Bbs.proofVerify(pk, bad, hdr, ph, dis, idx))
        // two proofs of one signature differ (unlinkability)
        assertFalse(proof.contentEquals(Bbs.proofGen(pk, h(f["signature"]), hdr, ph, msgs, idx)))
    }
}
