package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays producer-vectors.json: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519 is deterministic). */
@Suppress("UNCHECKED_CAST")
class ProducerVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun key(name: String) = Keys.edFromSeed(Pca.decodeB64uStrict(m(m(doc["keys"])[name])["seed"], 32)!!)
    private fun suite(name: String) = Keys.ed25519(key(name))
    private fun canon(o: Any?) = Json.canonicalize(o)

    private fun run(op: String, a: Map<String, Any?>): Any? = when (op) {
        "ed25519_sign" -> {
            val k = Keys.edFromSeed(Pca.decodeB64uStrict(a["seed"], 32)!!)
            Issue.obj("public" to k.id(), "sig" to Pca.b64(k.sign((a["message_utf8"] as String).toByteArray(Charsets.UTF_8))))
        }
        "goal_commit" -> Issue.obj("commit" to Issue.goalCommit(a["goal"] as String, a["salt"] as String))
        "params_digest" -> Issue.obj("digest" to Pca.paramsDigest(a["params"]))
        "plan_commit" -> {
            val nodes = l(a["nodes"]).map { m(it) }
            val p = Issue.commitPlan(nodes)
            Issue.obj("root" to p.root, "proofs" to nodes.associate { (it["id"] as String) to p.proofFor(it["id"] as String) })
        }
        "mint_grant" -> {
            val g = Issue.mintGrant(suite(a["principal"] as String), key(a["holder"] as String).id(), null, m(a["envelope"]), a["goal"] as String, a["salt"] as String)
            Issue.obj("grant" to g.grant, "goal_commit" to g.goalCommit, "goal_salt" to g.goalSalt)
        }
        "delegate" -> {
            val parent = m(a["parent"])
            val to = if (a["to_holder"] == null) parent["holder"] as String else key(a["to_holder"] as String).id()
            Issue.delegate(parent, to, l(a["added_caveats"]), suite(a["signer"] as String))
        }
        "act" -> {
            val p = Issue.buildPCActn(
                Issue.ActSpec(
                    grant = m(a["grant"]), chain = l(a["chain"]), plan = Issue.commitPlan(l(a["plan"]).map { m(it) }), nodeId = a["node_id"] as String,
                    counter = Json.asLong(a["counter"]), signer = suite(a["signer"] as String), aud = a["aud"] as String,
                    params = if (a.containsKey("params")) m(a["params"]) else null, iat = Json.asLong(a["iat"]), exp = Json.asLong(a["exp"]),
                    nonce = a["nonce"] as String?, caution = a["caution"], rationaleCommitment = a["rationale_commitment"] as String?,
                    toolBinding = a["tool_binding"] as String?, freshAt = if (a.containsKey("fresh_at")) m(a["fresh_at"]) else null,
                ),
            )
            Issue.obj("pcactn" to p, "threshold_message" to Pca.b64(Pca.thresholdMessage(p)), "header" to Issue.header(p))
        }
        "fresh_at" -> Issue.signFreshAt(key(a["signer"] as String), a["scope"] as String, m(a["state"]), Json.asLong(a["issued_at"]))
        "escalation_digests" -> Issue.obj(
            "policy_digest" to Escalation.policyDigest(a["grant"]), "action_digest" to Escalation.actionDigest(a["pcactn"]),
            "history_head" to Escalation.historyHead(a["last_counter"]?.let { Json.asLong(it) }),
        )
        "sign_escalation_answer" -> Issue.signEscalationAnswer(m(a["body"]), suite(a["signer"] as String))
        "sign_discharge" -> Issue.signDischarge(m(a["body"]), suite(a["signer"] as String))
        "discharge_digest" -> Issue.obj("digest" to CaveatLang.dischargeDigest(a["discharge"]))
        "sign_narrow" -> Issue.signNarrow(m(a["body"]), suite(a["signer"] as String))
        "sign_passport" -> {
            val pp = Issue.issuePassport(m(a["identity"]))
            val signed = Issue.signPassport(pp, suite(a["issuer"] as String), key(a["subject"] as String).id(), Json.asLong(m(a["identity"])["issued_at"]), null, Json.asLong(a["exp"]))
            Issue.obj("passport" to pp, "signed" to signed)
        }
        "sign_workflow" -> Issue.signWorkflow(key(a["signer"] as String), m(a["body"]))
        "sign_step_receipt" -> Issue.signStepReceipt(
            key(a["signer"] as String), m(a["workflow"]), a["step"] as String, a["outcome"] as String, a["params_digest"] as String, m(a["outputs"]),
            Json.asLong(a["issued_at"]), a["prev"]?.let { m(it) },
        )
        "sign_read_grant" -> Issue.signReadGrant(key(a["signer"] as String), m(a["body"]))
        "sign_aggregate_grant" -> Issue.signAggregateGrant(key(a["signer"] as String), m(a["body"]))
        else -> throw IllegalStateException("unknown op $op")
    }

    @Test fun everyCaseIsReproducedByteForByte() {
        val cases = l(doc["cases"])
        assertTrue("the corpus shrank: ${cases.size}", cases.size >= 30)
        for (c in cases) {
            val v = m(c)
            assertEquals(v["name"].toString(), canon(v["expect"]), canon(run(v["op"] as String, m(v["args"]))))
        }
    }

    /** Cross-verification: the TS-produced PCActns pass THIS SDK's verifier. */
    @Test fun referenceActionsVerify() {
        var n = 0
        for (c in l(doc["cases"])) {
            val v = m(c)
            val a = m(v["args"])
            if (v["op"] != "act" || a.containsKey("fresh_at")) continue // fresh_at is refused without a fresh_at policy (fail closed)
            val d = Pca.verifyPcactn(m(m(v["expect"])["pcactn"]), m(a["grant"]), Json.asLong(a["iat"]) + 1000, Pca.Audience.Of(a["aud"] as String))
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
