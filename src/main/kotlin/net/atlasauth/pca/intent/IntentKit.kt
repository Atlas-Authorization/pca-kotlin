package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pq

/** Suite and number helpers of the intent artifacts, shared by the intent package (wrappers over the module-internal core). */
internal object IntentKit {
    /** The suite an `alg` resolves to ("ed25519" when absent), or null when this SDK does not implement it. */
    fun suiteName(alg: Any?, algPresent: Boolean): String? = Pq.resolveSigAlg(alg, algPresent)?.alg

    fun verifyPinnedSuite(alg: Any?, algPresent: Boolean, identity: String?, artifactPqPk: Any?, msg: ByteArray, sig: Any?, pqSig: Any?, pqPins: Map<String, Any?>?): Boolean =
        IntentJs.verifyPinnedSuite(alg, algPresent, identity, artifactPqPk, msg, sig, pqSig, pqPins)

    fun bindSuiteFields(base: Map<String, Any?>, alg: Any?, algPresent: Boolean, pqPk: Any?, pqPresent: Boolean): Map<String, Any?> =
        IntentJs.bindSuiteFields(base, alg, algPresent, pqPk, pqPresent)

    /** `Number.isSafeInteger(v) && !Object.is(v, -0)` for a JSON number. */
    fun isInt(v: Any?): Boolean = IntentJs.isInt(v)

    /** The binary64 value of a JSON number, else null. */
    fun num(v: Any?): Double? = IntentJs.num(v)

    /** `utf8(domain) || strictCanonical(body)`. */
    fun message(domain: String, body: Any?): ByteArray = IntentJs.message(domain, body)

    /** Strict Ed25519 under a b64u key; a malformed key or signature is a failed signature. */
    fun verifyEd(pub: Any?, msg: ByteArray, sig: Any?): Boolean = IntentJs.verifyEd(pub, msg, sig)

    /**
     * Sign [body] under [key]'s suite: the message is `msg(bound)` where a non-ed25519 suite binds `alg` and `pq_pk` into the
     * signed body; the result is [body] plus `sig` (and `alg`, `pq_pk`, `pq_sig` when the suite has them). The key must carry
     * an Ed25519 identity (the artifact's principal).
     */
    fun signSuite(body: Map<String, Any?>, key: Keys.SuiteKey, msg: (Map<String, Any?>) -> ByteArray): MutableMap<String, Any?> {
        require(key.ed != null) { "signer needs an Ed25519 identity key" }
        val bound = LinkedHashMap(body)
        if ("ed25519" != key.alg) {
            bound["alg"] = key.alg
            bound["pq_pk"] = key.pqPk()
        }
        val sg = key.sign(msg(bound))
        val out = LinkedHashMap<String, Any?>(bound)
        out["sig"] = sg.first
        if (sg.second != null) out["pq_sig"] = sg.second
        return out
    }
}
