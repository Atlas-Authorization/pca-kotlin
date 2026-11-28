package net.atlasauth.pca.goal

import net.atlasauth.pca.intent.IntentKit
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys

/**
 * The one signer of the goal-to-decision flow: approvals, test sets, policy pins and precedents are artifacts signed with the
 * suite-agile artifact signer under a per-kind domain, over strict canonical bytes.
 */
object GoalSign {
    /** Domain separation: an artifact of one kind never verifies as another kind. */
    @JvmStatic
    fun goalDomain(kind: String): String = "atlas-pca/goal/$kind/v1\u0000"

    /** The pinned public identity (b64u Ed25519) of a signing key. */
    @JvmStatic
    fun signerId(key: Keys.EdKey): String = key.id()

    /** The pinned public identity of a 32-byte Ed25519 seed. */
    @JvmStatic
    fun signerId(seed: ByteArray): String = Keys.edFromSeed(seed).id()

    /** Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body. */
    @JvmStatic
    fun signGoalArtifact(kind: String, body: Map<String, Any?>, signer: Keys.SuiteKey): Map<String, Any?> = Issue.signArtifact(goalDomain(kind), body, signer)

    @JvmStatic
    fun signGoalArtifact(kind: String, body: Map<String, Any?>, seed: ByteArray): Map<String, Any?> =
        signGoalArtifact(kind, body, Keys.ed25519(Keys.edFromSeed(seed)))

    /** Suite capability and shape of an artifact's suite members; null = usable. */
    internal fun artifactSuiteError(a: Map<String, Any?>): String? {
        val suite = IntentKit.suiteName(a["alg"], a.containsKey("alg")) ?: return "unsupported_suite"
        for (k in arrayOf("pq_pk", "pq_sig")) if (a.containsKey(k) && a[k] !is String) return "$k must be a string"
        if (suite == "ed25519" && (a.containsKey("pq_pk") || a.containsKey("pq_sig"))) return "an ed25519 artifact must not carry pq_pk / pq_sig"
        return null
    }

    /**
     * Verify a signed artifact against the caller's PINNED signers (each a b64u key String or a Map {pk, pq_pk}): the pin whose
     * `pk` equals the artifact's own [signerField] member must verify. Total: false on anything malformed.
     */
    @JvmStatic
    fun verifyGoalArtifact(kind: String, artifact: Any?, signerField: String, pins: List<*>): Boolean {
        try {
            val a = G.m(artifact) ?: return false
            if (artifactSuiteError(a) != null) return false
            val who = a[signerField]
            if (who !is String) return false
            var pin: Any? = null
            var found = false
            for (p in pins) {
                val pk = if (p is String) p else G.get(p, "pk")
                if (who == pk) {
                    pin = p
                    found = true
                    break
                }
            }
            if (!found) return false
            return verifyArtifactSig(goalDomain(kind), a, pin)
        } catch (e: RuntimeException) {
            return false
        }
    }

    /**
     * The artifact's signature under a PINNED signer (a b64u key String or a Map {pk, pq_pk?}); the caller has checked the
     * suite members. Ed25519 under `pk`; any other suite only when the artifact's `pq_pk` equals the pin's. Total.
     */
    @JvmStatic
    fun verifyArtifactSig(domain: String, a: Map<String, Any?>, pin: Any?): Boolean {
        try {
            val pk = if (pin is String) pin else G.get(pin, "pk")
            if (a["sig"] !is String || pk !is String) return false
            val pinPq = if (pin is Map<*, *>) pin["pq_pk"] else null
            val body = LinkedHashMap(a)
            body.remove("sig")
            body.remove("pq_sig")
            val pqPins: Map<String, Any?>? = if (pinPq is String) G.map(pk to pinPq) else null
            return IntentKit.verifyPinnedSuite(a["alg"], a.containsKey("alg"), pk, a["pq_pk"], IntentKit.message(domain, body), a["sig"], a["pq_sig"], pqPins)
        } catch (e: RuntimeException) {
            return false
        }
    }

    /** A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents. */
    @JvmStatic
    fun signPayload(kind: String, payload: Any?, key: Keys.EdKey, suite: Keys.SuiteKey): Map<String, Any?> =
        signGoalArtifact(kind, G.map("v" to G.num(1), "kind" to kind, "signer" to key.id(), "payload" to payload), suite)

    @JvmStatic
    fun signPayload(kind: String, payload: Any?, seed: ByteArray): Map<String, Any?> {
        val key = Keys.edFromSeed(seed)
        return signPayload(kind, payload, key, Keys.ed25519(key))
    }

    @JvmStatic
    fun verifyPayload(s: Map<String, Any?>?, kind: String, pins: List<*>): Boolean =
        s != null && G.safeInt(s["v"]) == 1L && kind == s["kind"] && verifyGoalArtifact(kind, s, "signer", pins)
}
