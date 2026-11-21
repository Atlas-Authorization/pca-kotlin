package net.atlasauth.pca.aggsig

import java.security.SecureRandom

/**
 * BLS12-381 signature aggregation for Proof-Carrying Authority (port of the TypeScript aggsig package), on blst.
 *
 * Rogue-key safety by construction: the aggregate verifiers take [RegisteredKey]s only, and a RegisteredKey can only
 * come from [registerKey] / [KeyRegistry.register], which verify KeyValidate and a proof of possession first.
 * The raw verifiers live in the internal `AggsigCore`.
 */
object Aggsig {
    const val SIG_DST = AggsigCore.SIG_DST
    const val POP_DST = AggsigCore.POP_DST
    const val PUBLIC_KEY_LENGTH = AggsigCore.PUBLIC_KEY_LENGTH
    const val SIGNATURE_LENGTH = AggsigCore.SIGNATURE_LENGTH

    /** 32-byte big-endian scalar and its 48-byte compressed G1 public key. */
    class KeyPair internal constructor(val secretKey: ByteArray, val publicKey: ByteArray)

    /** Either a registered key or the reason it was refused. */
    class RegisterResult private constructor(val ok: Boolean, val key: RegisteredKey?, val reason: String?) {
        internal companion object {
            fun ok(k: RegisteredKey) = RegisterResult(true, k, null)
            fun fail(why: String) = RegisterResult(false, null, why)
        }
    }

    internal fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(Character.forDigit((x.toInt() shr 4) and 15, 16)).append(Character.forDigit(x.toInt() and 15, 16))
        return sb.toString()
    }

    fun keyGen(): KeyPair = AggsigCore.keyGen(SecureRandom())

    fun publicKeyOf(secretKey: ByteArray): ByteArray = AggsigCore.publicKeyOf(secretKey)

    fun keyValidate(publicKey: ByteArray?): Boolean = AggsigCore.keyValidate(publicKey)

    fun sign(secretKey: ByteArray, msg: ByteArray): ByteArray = AggsigCore.sign(secretKey, msg)

    /** CoreVerify of one signature. Never throws. */
    fun verify(publicKey: ByteArray?, msg: ByteArray?, sig: ByteArray?): Boolean = AggsigCore.verify(publicKey, msg, sig)

    /** Sum the G2 signature points into one 96-byte aggregate; throws on an empty list or a non-canonical signature. */
    fun aggregate(sigs: List<ByteArray>): ByteArray = AggsigCore.aggregate(sigs)

    /** Sign one's OWN public key under the PoP DST. */
    fun popProve(secretKey: ByteArray): ByteArray = AggsigCore.popProve(secretKey)

    /** Admit a public key: KeyValidate plus a valid proof of possession. The only way to obtain a RegisteredKey. Never throws. */
    fun registerKey(publicKey: ByteArray?, pop: ByteArray?): RegisterResult {
        if (publicKey == null || pop == null) return RegisterResult.fail("public key and proof of possession must be Uint8Arrays")
        if (!AggsigCore.keyValidate(publicKey)) return RegisterResult.fail("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)")
        if (pop.size != AggsigCore.SIGNATURE_LENGTH) return RegisterResult.fail("proof of possession is not a 96-byte compressed G2 signature")
        if (!AggsigCore.popVerify(publicKey, pop)) return RegisterResult.fail("proof of possession does not verify for this key")
        return RegisterResult.ok(RegisteredKey(publicKey))
    }

    /** Why the keys cannot be used for aggregate verification, or null when every element is a genuine RegisteredKey. */
    fun checkRegistered(keys: List<RegisteredKey?>?): String? {
        if (keys == null) return "keys must be an array of RegisteredKey"
        if (keys.isEmpty()) return "no keys"
        for (i in keys.indices) {
            if (keys[i] == null) return "key $i is not a registered key: it was not admitted through registerKey (proof of possession)"
        }
        return null
    }

    private fun rawOf(keys: List<RegisteredKey?>): List<ByteArray> = keys.map { it!!.bytes() }

    /** AggregateVerify over distinct messages, registered keys only. Never throws. */
    fun aggregateVerify(keys: List<RegisteredKey?>?, msgs: List<ByteArray>, aggSig: ByteArray?): Boolean {
        if (checkRegistered(keys) != null) return false
        return AggsigCore.aggregateVerify(rawOf(keys!!), msgs, aggSig)
    }

    /** FastAggregateVerify: one message, registered keys only; one signer may not be counted twice. Never throws. */
    fun fastAggregateVerify(keys: List<RegisteredKey?>?, msg: ByteArray?, aggSig: ByteArray?): Boolean {
        if (checkRegistered(keys) != null) return false
        val seen = HashSet<String>()
        for (k in keys!!) if (!seen.add(hex(k!!.bytes()))) return false
        return AggsigCore.fastAggregateVerify(rawOf(keys), msg, aggSig)
    }
}
