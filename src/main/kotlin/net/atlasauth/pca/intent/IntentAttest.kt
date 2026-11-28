package net.atlasauth.pca.intent

import net.atlasauth.pca.evidence.EvidenceVerify
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Ledger
import net.atlasauth.pca.verifier.Pca

/**
 * Intent Map attestations and ledger anchors: a detached signature over an Intent Map's digest (who vouches for the map) and the
 * verifier of an anchoring receipt (the artifact's leaf under a guardian-signed tree head of the instance's intent log). Signatures are
 * suite-agile like every other artifact: Ed25519 by default, a PQ-suite artifact verifies only under a PQ key the verifier pins.
 * Verdicts are {ok: true} or {ok: false, reason}; the verifiers never throw.
 */
@Suppress("UNCHECKED_CAST")
object IntentAttest {
    const val INTENT_MAP_SIG_DOMAIN = "atlas-pca/intent-map-sig/v1\u0000"
    @JvmField val INTENT_ANCHOR_KINDS: List<String> = listOf("statement", "map", "observation", "schema", "session", "delta", "receipt", "profile", "evidence")

    /** Pass as `map` to [verifyIntentMapAttestation] to check the attestation alone (a null map is a malformed map, not "no map"). */
    @JvmField val NO_MAP: Any = Any()

    private const val MAX_SAFE = 9007199254740991L

    private fun verdict(reason: String?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = reason == null
        if (reason != null) r["reason"] = reason
        return r
    }

    private fun isOne(o: Any?): Boolean {
        val d = IntentKit.num(o)
        return d != null && d == 1.0
    }

    /** `intent_ref` is an explicit null or 32 canonical base64url bytes (an absent member is neither). */
    private fun refOk(m: Map<*, *>): Boolean =
        if (m["intent_ref"] == null) m.containsKey("intent_ref") else Pca.decodeB64uStrict(m["intent_ref"], 32) != null

    private fun nonNegInt(o: Any?): Boolean = IntentKit.isInt(o) && IntentKit.num(o)!! >= 0

    /** Structural check of an Intent Map (it does not replay the map): the first problem, or null. */
    @JvmStatic
    fun intentMapShapeError(m: Any?): String? {
        if (m !is Map<*, *> || !isOne(m["v"]) || m["kind"] != "pca-intent-map") return "not an intent map v1"
        if (!refOk(m)) return "intent_ref must be null or canonical base64url (32 bytes)"
        val mt = m["metrics"]
        if (mt !is Map<*, *>) return "metrics must be an object"
        if (!nonNegInt(mt["fidelity_est_ppm"]) || IntentKit.num(mt["fidelity_est_ppm"])!! > 1_000_000) return "metrics.fidelity_est_ppm must be an integer in [0, 1e6]"
        if (!nonNegInt(mt["residual_risk_ppm"])) return "metrics.residual_risk_ppm must be a non-negative integer"
        return null
    }

    private fun mapAttBody(a: Map<*, *>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "map_digest", "intent_ref", "signer", "signed_at")) b[k] = a[k]
        return IntentJs.normalize(b) as Map<String, Any?>
    }

    /** Sign a map attestation as the holder of an Ed25519 seed; `signedAt` is epoch ms. Throws on a malformed map or timestamp. */
    @JvmStatic
    fun signIntentMapAttestation(map: Map<String, Any?>, signerSeed: ByteArray, signedAt: Long): MutableMap<String, Any?> =
        signIntentMapAttestation(map, Keys.ed25519(Keys.edFromSeed(signerSeed)), signedAt)

    /** Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the attestation. */
    @JvmStatic
    fun signIntentMapAttestation(map: Map<String, Any?>, key: Keys.SuiteKey, signedAt: Long): MutableMap<String, Any?> {
        val bad = intentMapShapeError(map)
        if (bad != null) throw IllegalArgumentException("signIntentMapAttestation: $bad")
        if (signedAt < 0 || signedAt > MAX_SAFE) throw IllegalArgumentException("signIntentMapAttestation: signedAt must be a non-negative safe integer")
        val ed = key.ed ?: throw IllegalArgumentException("signIntentMapAttestation: signer needs an Ed25519 identity key")
        val body = mapAttBody(linkedMapOf("v" to 1L, "map_digest" to IntentMapKit.intentMapDigest(map), "intent_ref" to map["intent_ref"], "signer" to ed.id(), "signed_at" to signedAt))
        return IntentKit.signSuite(body, key) { b -> IntentKit.message(INTENT_MAP_SIG_DOMAIN, b) }
    }

    /**
     * Verify a map attestation: well-formed, signature valid, and (unless `map` is [NO_MAP]) the map is well-formed and its digest and
     * intent_ref are the attested ones. Never throws.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyIntentMapAttestation(a: Any?, map: Any? = NO_MAP, expectedSigner: String? = null, pqPins: Map<String, Any?>? = null): MutableMap<String, Any?> {
        try {
            if (a !is Map<*, *> || !isOne(a["v"])) return verdict("not an intent map attestation v1")
            if (Pca.decodeB64uStrict(a["map_digest"], 32) == null) return verdict("map_digest is not canonical base64url (32 bytes)")
            if (!refOk(a)) return verdict("intent_ref must be null or canonical base64url (32 bytes)")
            if (Pca.decodeB64uStrict(a["signer"], 32) == null) return verdict("signer is not canonical base64url (32 bytes)")
            if (!nonNegInt(a["signed_at"])) return verdict("signed_at must be a non-negative safe integer")
            if (expectedSigner != null && expectedSigner != a["signer"]) return verdict("signer mismatch")
            val algPresent = a.containsKey("alg")
            val suite = IntentKit.suiteName(a["alg"], algPresent) ?: return verdict("unknown signature suite")
            if (suite == "ed25519" && (a.containsKey("pq_pk") || a.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig")
            if (map !== NO_MAP) {
                val bad = intentMapShapeError(map)
                if (bad != null) return verdict(bad)
                if (IntentMapKit.intentMapDigest(map) != a["map_digest"]) return verdict("map digest mismatch")
                if ((map as Map<*, *>)["intent_ref"] != a["intent_ref"]) return verdict("intent_ref mismatch")
            }
            val msg = IntentKit.message(INTENT_MAP_SIG_DOMAIN, IntentKit.bindSuiteFields(mapAttBody(a), a["alg"], algPresent, a["pq_pk"], a.containsKey("pq_pk")))
            if (!IntentKit.verifyPinnedSuite(a["alg"], algPresent, a["signer"] as String, a["pq_pk"], msg, a["sig"], a["pq_sig"], pqPins)) return verdict("bad signature")
            return verdict(null)
        } catch (e: RuntimeException) {
            return verdict("malformed intent map attestation: " + e.message)
        }
    }

    /** JavaScript `===` for the receipt's index and size: numbers by value, anything else by identity of the JSON value. */
    private fun sameNumber(a: Any?, b: Any?): Boolean {
        val x = IntentKit.num(a)
        val y = IntentKit.num(b)
        return if (x == null || y == null) x == null && y == null && a == b else x == y
    }

    /**
     * Verify an anchoring receipt {kind, digest, index, proof, signed_tree_head}: the head is signed by `guardianPublic` for the intent
     * log of `instanceId`, and the artifact's leaf is included at `index` under the head's root and size. Never throws.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyIntentAnchor(r: Any?, guardianPublic: String, instanceId: String, pqPins: Map<String, Any?>? = null): MutableMap<String, Any?> {
        try {
            val rec = r as Map<*, *>
            val kind = rec["kind"]
            if (kind !is String || kind !in INTENT_ANCHOR_KINDS) return verdict("unknown anchor kind")
            val digest = rec["digest"]
            if (digest !is String || Pca.decodeB64uStrict(digest, 32) == null) return verdict("digest is not canonical base64url (32 bytes)")
            val h = rec["signed_tree_head"] as Map<*, *>
            if (h["principal"] != EvidenceVerify.INTENT_ANCHOR_LOG || h["instance_id"] != instanceId) return verdict("not a head of this instance intent log")
            if (!Ledger.verifyTreeHead(h, guardianPublic, null, pqPins)) return verdict("tree head signature invalid")
            val proof = rec["proof"] as Map<*, *>
            if (!sameNumber(proof["index"], rec["index"]) || !sameNumber(proof["size"], h["size"])) return verdict("proof does not match the head")
            val root = h["root"]
            if (root !is String || !Ledger.verifyInclusion(root, proof, EvidenceVerify.anchorCommit(kind, digest))) return verdict("artifact is not included under the signed head")
            return verdict(null)
        } catch (e: RuntimeException) {
            return verdict("malformed anchor receipt: " + e.message)
        }
    }
}
