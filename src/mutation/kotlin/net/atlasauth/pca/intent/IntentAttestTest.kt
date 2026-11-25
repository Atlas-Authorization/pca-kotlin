package net.atlasauth.pca.intent

import net.atlasauth.pca.evidence.EvidenceVerify
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Ledger
import net.atlasauth.pca.verifier.MerkleLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/** Intent map attestations and anchor receipts: sign, verify, and every refusal (tamper, wrong map, wrong signer, wrong log, wrong leaf). */
class IntentAttestTest {
    private val seed = ByteArray(32) { 1 }
    private val signer = Keys.edFromSeed(seed).id()
    private val ok = mapOf<String, Any?>("ok" to true)

    private fun map(fidelity: Long = 5): LinkedHashMap<String, Any?> = linkedMapOf(
        "v" to 1L, "kind" to "pca-intent-map", "intent_ref" to null,
        "metrics" to linkedMapOf<String, Any?>("fidelity_est_ppm" to fidelity, "residual_risk_ppm" to 1L),
    )

    private fun reason(v: Map<String, Any?>): Any? {
        assertEquals(false, v["ok"])
        return v["reason"]
    }

    private fun with(m: Map<String, Any?>, k: String, v: Any?): LinkedHashMap<String, Any?> = LinkedHashMap(m).also { it[k] = v }

    @Test fun mapShape() {
        assertNull(IntentAttest.intentMapShapeError(map()))
        assertEquals("not an intent map v1", IntentAttest.intentMapShapeError(emptyMap<String, Any?>()))
        assertEquals("not an intent map v1", IntentAttest.intentMapShapeError(null))
        assertEquals("intent_ref must be null or canonical base64url (32 bytes)", IntentAttest.intentMapShapeError(with(map(), "intent_ref", "x")))
        assertEquals("intent_ref must be null or canonical base64url (32 bytes)", IntentAttest.intentMapShapeError(LinkedHashMap(map()).also { it.remove("intent_ref") }))
        assertEquals("metrics must be an object", IntentAttest.intentMapShapeError(with(map(), "metrics", 1L)))
        assertEquals("metrics.fidelity_est_ppm must be an integer in [0, 1e6]", IntentAttest.intentMapShapeError(map(1_000_001)))
        assertNull(IntentAttest.intentMapShapeError(map(1_000_000)))
        assertEquals("metrics.fidelity_est_ppm must be an integer in [0, 1e6]", IntentAttest.intentMapShapeError(map(-1)))
        assertEquals(
            "metrics.residual_risk_ppm must be a non-negative integer",
            IntentAttest.intentMapShapeError(with(map(), "metrics", linkedMapOf<String, Any?>("fidelity_est_ppm" to 5L, "residual_risk_ppm" to 1.5))),
        )
    }

    @Test fun attestationRoundTripAndRefusals() {
        val m = map()
        val att = IntentAttest.signIntentMapAttestation(m, seed, 7)
        assertEquals(IntentMapKit.intentMapDigest(m), att["map_digest"])
        assertEquals(signer, att["signer"])
        assertEquals(ok, IntentAttest.verifyIntentMapAttestation(att, m))
        assertEquals(ok, IntentAttest.verifyIntentMapAttestation(att))
        assertEquals(ok, IntentAttest.verifyIntentMapAttestation(att, m, signer))
        assertEquals("signer mismatch", reason(IntentAttest.verifyIntentMapAttestation(att, m, Keys.edFromSeed(ByteArray(32) { 2 }).id())))
        assertEquals("map digest mismatch", reason(IntentAttest.verifyIntentMapAttestation(att, map(6))))
        assertEquals("not an intent map v1", reason(IntentAttest.verifyIntentMapAttestation(att, null)))
        assertEquals("bad signature", reason(IntentAttest.verifyIntentMapAttestation(with(att, "signed_at", 8L))))
        assertEquals("signed_at must be a non-negative safe integer", reason(IntentAttest.verifyIntentMapAttestation(with(att, "signed_at", -1L))))
        assertEquals("map_digest is not canonical base64url (32 bytes)", reason(IntentAttest.verifyIntentMapAttestation(with(att, "map_digest", "x"))))
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", reason(IntentAttest.verifyIntentMapAttestation(with(att, "pq_sig", "AA"))))
        assertEquals("unknown signature suite", reason(IntentAttest.verifyIntentMapAttestation(with(att, "alg", "nope"))))
        assertEquals("not an intent map attestation v1", reason(IntentAttest.verifyIntentMapAttestation("x")))
        // the attested intent_ref is signed: another ref (even with the map's digest untouched) fails
        val ref = Keys.b64u(ByteArray(32) { 9 })
        assertEquals("intent_ref mismatch", reason(IntentAttest.verifyIntentMapAttestation(with(att, "intent_ref", ref), m)))
        assertEquals("bad signature", reason(IntentAttest.verifyIntentMapAttestation(with(att, "intent_ref", ref))))
        try { IntentAttest.signIntentMapAttestation(emptyMap(), seed, 7); fail("a malformed map must not be signed") } catch (e: IllegalArgumentException) { assertNotNull(e.message) }
        try { IntentAttest.signIntentMapAttestation(m, seed, -1); fail("a negative time must not be signed") } catch (e: IllegalArgumentException) { assertNotNull(e.message) }
    }

    @Test fun anchorReceipt() {
        assertEquals(listOf("statement", "map", "observation", "schema", "session", "delta", "receipt", "profile", "evidence"), IntentAttest.INTENT_ANCHOR_KINDS)
        val guardian = Keys.edFromSeed(ByteArray(32) { 3 })
        val digest = Keys.b64u(ByteArray(32) { 7 })
        val log = MerkleLog()
        log.appendCommitment(EvidenceVerify.anchorCommit("statement", Keys.b64u(ByteArray(32) { 8 })))
        log.appendCommitment(EvidenceVerify.anchorCommit("map", digest))
        val head = log.head()
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "principal" to EvidenceVerify.INTENT_ANCHOR_LOG, "size" to head["size"], "root" to head["root"], "prev_root" to "", "timestamp" to 1L,
        )
        val sth = LinkedHashMap(body)
        sth["guardian"] = guardian.id()
        sth["sig"] = Keys.ed25519(guardian).sign(IntentKit.message(Ledger.STH_DOMAIN, body)).first
        val r = linkedMapOf<String, Any?>("kind" to "map", "digest" to digest, "index" to 1L, "proof" to log.inclusionProof(1), "signed_tree_head" to sth)
        assertEquals(ok, IntentAttest.verifyIntentAnchor(r, guardian.id(), "i"))
        assertEquals("artifact is not included under the signed head", reason(IntentAttest.verifyIntentAnchor(with(r, "kind", "statement"), guardian.id(), "i")))
        assertEquals("unknown anchor kind", reason(IntentAttest.verifyIntentAnchor(with(r, "kind", "nope"), guardian.id(), "i")))
        assertEquals("digest is not canonical base64url (32 bytes)", reason(IntentAttest.verifyIntentAnchor(with(r, "digest", "x"), guardian.id(), "i")))
        assertEquals("not a head of this instance intent log", reason(IntentAttest.verifyIntentAnchor(r, guardian.id(), "other")))
        assertEquals("tree head signature invalid", reason(IntentAttest.verifyIntentAnchor(r, signer, "i")))
        assertEquals("tree head signature invalid", reason(IntentAttest.verifyIntentAnchor(with(r, "signed_tree_head", with(sth, "timestamp", 2L)), guardian.id(), "i")))
        assertEquals("proof does not match the head", reason(IntentAttest.verifyIntentAnchor(with(r, "index", 0L), guardian.id(), "i")))
        assertEquals("artifact is not included under the signed head", reason(IntentAttest.verifyIntentAnchor(with(with(r, "index", 0L), "proof", log.inclusionProof(0)), guardian.id(), "i")))
        assertEquals(false, IntentAttest.verifyIntentAnchor(null, guardian.id(), "i")["ok"])
        assertEquals(false, IntentAttest.verifyIntentAnchor(with(r, "proof", null), guardian.id(), "i")["ok"])
    }
}
