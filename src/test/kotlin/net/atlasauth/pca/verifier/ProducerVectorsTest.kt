package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the producer vectors: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519, ML-DSA and SLH-DSA sign deterministically). */
@Suppress("UNCHECKED_CAST")
class ProducerVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private val pqDoc: Map<String, Any?> by lazy { ParityVectors.load("producer-pq-vectors.json") }
    private val ops by lazy { ProducerOps(m(doc["keys"]), null) }
    private val pqOps by lazy { ProducerOps(m(pqDoc["ed_keys"]), m(pqDoc["pq_keys"])) }

    private fun canon(o: Any?) = Json.canonicalize(o)

    private fun refusal(name: String, f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("$name: expected a refusal")
        return ""
    }

    /** Every case: the output byte for byte, or (for a refusal case) the reference's exact refusal text. */
    private fun replay(p: ProducerOps, d: Map<String, Any?>, atLeast: Int) {
        val cases = l(d["cases"])
        assertTrue("the corpus shrank: ${cases.size}", cases.size >= atLeast)
        for (c in cases) {
            val v = m(c)
            val name = v["name"].toString()
            val op = v["op"] as String
            val want = m(v["expect"])
            if (v["exact"] != null && "kotlin" !in l(v["exact"])) {
                // a suite this SDK cannot sign (FN-DSA): refused with unsupported_suite, never signed some other way
                val e = refusal(name) { p.run(op, m(v["args"])) }
                assertTrue("$name: $e", e.startsWith("unsupported_suite: "))
                continue
            }
            if (want.size == 1 && want["error"] != null) {
                val w = want["error"] as String
                val e = refusal(name) { p.run(op, m(v["args"])) }
                // the canonical profile's wording is per-language: a reference canonicalize refusal needs a canonicalize refusal
                if (w.startsWith("canonicalize: ")) assertTrue("$name: $e", e.startsWith("canonicalize: ")) else assertEquals(name, w, e)
            }
            else assertEquals(name, canon(want), canon(p.run(op, m(v["args"]))))
        }
    }

    @Test fun everyCaseIsReproducedByteForByte() = replay(ops, doc, 89)

    @Test fun everyPqSuiteCaseIsReproducedByteForByte() = replay(pqOps, pqDoc, 40)

    @Test fun unknownOpsAndSuitesAreRefusedByName() {
        assertEquals("unsupported_op: sign_nothing", refusal("op") { ops.run("sign_nothing", Issue.obj()) })
        assertEquals("unsupported_suite: fn-dsa-512", refusal("suite") { pqOps.run("pq_keygen", Issue.obj("family" to "fn-dsa-512", "seed" to "AA")) })
        assertEquals("unsupported_op: sign_artifact_suite/nope",
            refusal("kind") { pqOps.run("sign_artifact_suite", Issue.obj("kind" to "nope", "alg" to "ed25519", "signer" to "agent")) })
        assertEquals("unknown key 'nobody'", refusal("key") { ops.run("sign_caution", Issue.obj("signer" to "nobody", "body" to Issue.obj())) })
    }

    private fun case(name: String): Map<String, Any?> = l(doc["cases"]).map { m(it) }.first { it["name"] == name }

    @Test fun offerSetsSignExactlyAndRefuseOutOfProfileBodies() {
        val site = Keys.ed25519(ops.ed("site"))
        for (n in listOf("offer-set-complete", "offer-set-partial-page")) {
            val c = case(n)
            assertEquals(n, canon(c["expect"]), canon(SignersMore.signOfferSet(m(m(c["args"])["body"]), site)))
        }
        for (n in listOf("offer-set-refuses-unsafe-price", "offer-set-refuses-unsafe-issued-at")) {
            val c = case(n)
            assertEquals("canonicalize: integer outside the safe range (|n| > 2^53-1)", m(c["expect"])["error"])
            assertEquals(n, "canonicalize: integer outside the safe range", refusal(n) { SignersMore.signOfferSet(m(m(c["args"])["body"]), site) })
        }
        val body = m(m(case("offer-set-complete")["args"])["body"])
        SignersMore.signOfferSet(body, site)
        assertTrue("the caller's body is not mutated", !body.containsKey("sig"))
    }

    /** Cross-verification: the TS-produced PCActns pass THIS SDK's verifier. */
    @Test fun referenceActionsVerify() {
        var n = 0
        for (c in l(doc["cases"])) {
            val v = m(c)
            val a = m(v["args"])
            if (v["op"] != "act" || a.containsKey("fresh_at")) continue // fresh_at is refused without a fresh_at policy (fail closed)
            val d = Pca.verifyPcactn(m(m(v["expect"])["pcactn"]), m(a["grant"]), Json.asLong(a["iat"]) + 1000, Pca.Audience.Of(a["aud"] as String), insecureSkipPlanRootCheck = true)
            assertTrue("${v["name"]}: ${d.reason}", d.allow)
            n++
        }
        assertTrue(n >= 4)
    }

    @Test fun seededMlDsaKeysAreReproducible() {
        val seed = ByteArray(32) { it.toByte() }
        val a = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed)
        assertEquals(a.pkB64u(), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed).pkB64u())
        seed[0] = (seed[0].toInt() xor 1).toByte()
        assertNotEquals(a.pkB64u(), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed).pkB64u())
    }

    /** FIPS 204 KeyGen_internal step 1: (rho, rho', K) = SHAKE256(xi || k || l, 128 bytes), and pk starts with rho. Proves BouncyCastle used the seed as xi. */
    @Test fun seededMlDsaKeysFollowFips204KeyGenInternal() {
        for ((prim, kl) in listOf(Pq.Prim.ML_DSA_65 to (6 to 5), Pq.Prim.ML_DSA_87 to (8 to 7))) {
            val xi = ByteArray(32) { (it * 7 + 1).toByte() }
            val d = org.bouncycastle.crypto.digests.SHAKEDigest(256)
            d.update(xi, 0, 32)
            d.update(kl.first.toByte())
            d.update(kl.second.toByte())
            val out = ByteArray(128)
            d.doFinal(out, 0, 128)
            val k = Keys.pqFromSeed(prim, xi)
            org.junit.Assert.assertArrayEquals("$prim: rho", out.copyOfRange(0, 32), k.pk.copyOfRange(0, 32))
        }
    }
}
