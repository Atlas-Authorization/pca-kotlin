package net.atlasauth.pca.verifier

import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner

/**
 * Agent-side keys: Ed25519 and every post-quantum / hybrid suite this SDK verifies (ML-DSA-65/87, SLH-DSA-SHA2-128f/256s, their
 * hybrids and the SUF-CMA nested hybrid) through BouncyCastle. FN-DSA signs only once a signing backend is registered (pca-fndsa), LESS only with a libatlas_less that carries the signing entry points. Both are refused otherwise.
 * Ed25519 and ML-DSA signing are deterministic; SLH-DSA is signed in its deterministic variant.
 */
object Keys {
    fun b64u(b: ByteArray): String = Pca.b64(b)

    fun unb64u(s: String): ByteArray = Pca.decodeB64uStrict(s, -1) ?: throw IllegalArgumentException("not canonical base64url")

    /** The wire forms of a public key and a signature are canonical base64url of their bytes. */
    fun encodeKey(b: ByteArray): String = b64u(b)

    fun encodeSig(b: ByteArray): String = b64u(b)

    fun decodeKey(s: String): ByteArray = unb64u(s)

    fun decodeSig(s: String): ByteArray = unb64u(s)

    /** An Ed25519 key: the 32-byte seed (RFC 8032 private key) and the 32-byte public key. */
    class EdKey internal constructor(val seed: ByteArray, val pub: ByteArray) {
        /** The b64u public key: the key id used as `issuer` / `holder` on the wire. */
        fun id(): String = b64u(pub)

        @Volatile private var destroyed = false

        /** Overwrites the seed (the private key) with zeros; the key can sign no more. The public key stays. Idempotent. */
        fun destroy() {
            destroyed = true
            seed.fill(0)
        }

        val isDestroyed: Boolean get() = destroyed

        fun sign(msg: ByteArray): ByteArray {
            check(!destroyed) { "the key was destroyed" }
            val s = Ed25519Signer()
            s.init(true, Ed25519PrivateKeyParameters(seed, 0))
            s.update(msg, 0, msg.size)
            return s.generateSignature()
        }
    }

    fun edFromSeed(seed: ByteArray): EdKey {
        require(seed.size == 32) { "an Ed25519 seed is 32 bytes" }
        val s = seed.clone()
        return EdKey(s, Ed25519PrivateKeyParameters(s, 0).generatePublicKey().encoded)
    }

    fun edGenerate(): EdKey {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val key = edFromSeed(seed) // the key keeps its own copy; nothing in edFromSeed throws for a 32-byte seed
        seed.fill(0)
        return key
    }

    /** A post-quantum key pair of one primitive, in the byte encodings the wire uses (FIPS 204 / FIPS 205). */
    class PqKey internal constructor(val prim: Pq.Prim, val pk: ByteArray, val sk: ByteArray, signSeed: ByteArray? = null) {
        /** FN-DSA only: the fixed 32-byte signing seed (conformance replays); null draws fresh CSPRNG bytes per signature. */
        private val signSeed: ByteArray? = signSeed?.clone()

        /** The b64u public key carried as `pq_pk`. */
        fun pkB64u(): String = b64u(pk)

        @Volatile private var destroyed = false

        /** Overwrites the secret key with zeros; the key can sign no more. The public key stays. Idempotent. */
        fun destroy() {
            destroyed = true
            sk.fill(0)
            signSeed?.fill(0)
        }

        val isDestroyed: Boolean get() = destroyed

        internal fun sign(msg: ByteArray): ByteArray = when (prim.also { check(!destroyed) { "the key was destroyed" } }) {
            Pq.Prim.ML_DSA_65, Pq.Prim.ML_DSA_87 -> {
                val s = MLDSASigner() // pure ML-DSA, empty context, deterministic
                s.init(true, MLDSAPrivateKeyParameters(mlParams(prim), sk))
                s.update(msg, 0, msg.size)
                s.generateSignature()
            }
            Pq.Prim.SLH_DSA_SHA2_128F, Pq.Prim.SLH_DSA_SHA2_256S -> {
                val s = SLHDSASigner()
                s.init(true, SLHDSAPrivateKeyParameters(slhParams(prim), sk))
                s.generateSignature(msg)
            }
            Pq.Prim.FN_DSA_512, Pq.Prim.FN_DSA_1024 ->
                Pq.fnDsaSign(if (prim == Pq.Prim.FN_DSA_512) "fn-dsa-512" else "fn-dsa-1024", sk, msg, signSeed ?: ByteArray(32).also { SecureRandom().nextBytes(it) })
            Pq.Prim.LESS_CAT1 -> LessNative.sign(sk, msg, signSeed ?: ByteArray(32).also { SecureRandom().nextBytes(it) })
        }
    }

    private fun mlParams(p: Pq.Prim): MLDSAParameters = if (p == Pq.Prim.ML_DSA_65) MLDSAParameters.ml_dsa_65 else MLDSAParameters.ml_dsa_87
    private fun slhParams(p: Pq.Prim): SLHDSAParameters = if (p == Pq.Prim.SLH_DSA_SHA2_128F) SLHDSAParameters.sha2_128f else SLHDSAParameters.sha2_256s

    /** A SecureRandom that replays a fixed seed, so key generation is reproducible. Never use it for anything else. */
    internal class SeedRandom(private val seed: ByteArray) : SecureRandom() {
        // no defensive copy: pqFromSeed builds one per key generation and nothing writes the array meanwhile
        private var pos = 0

        @Synchronized
        override fun nextBytes(bytes: ByteArray) {
            for (i in bytes.indices) {
                check(pos < seed.size) { "seed exhausted" }
                bytes[i] = seed[pos++]
            }
        }
    }

    private fun pqGen(p: Pq.Prim, rng: SecureRandom): PqKey = when (p) {
        Pq.Prim.ML_DSA_65, Pq.Prim.ML_DSA_87 -> {
            val g = MLDSAKeyPairGenerator()
            g.init(MLDSAKeyGenerationParameters(rng, mlParams(p)))
            val kp = g.generateKeyPair()
            PqKey(p, (kp.public as MLDSAPublicKeyParameters).encoded, (kp.private as MLDSAPrivateKeyParameters).encoded)
        }
        Pq.Prim.SLH_DSA_SHA2_128F, Pq.Prim.SLH_DSA_SHA2_256S -> {
            val g = SLHDSAKeyPairGenerator()
            g.init(SLHDSAKeyGenerationParameters(rng, slhParams(p)))
            val kp = g.generateKeyPair()
            PqKey(p, (kp.public as SLHDSAPublicKeyParameters).encoded, (kp.private as SLHDSAPrivateKeyParameters).encoded)
        }
        else -> throw IllegalArgumentException("cannot generate $p keys in this SDK")
    }

    fun pqGenerate(p: Pq.Prim): PqKey =
        if (isFnDsa(p) || p == Pq.Prim.LESS_CAT1) pqFromSeed(p, ByteArray(32).also { SecureRandom().nextBytes(it) }) else pqGen(p, SecureRandom())

    private fun isFnDsa(p: Pq.Prim) = p == Pq.Prim.FN_DSA_512 || p == Pq.Prim.FN_DSA_1024

    /** Reproducible key from a seed: 32 bytes for ML-DSA (FIPS 204 xi), 3n bytes for SLH-DSA (sk_seed, sk_prf, pk_seed). */
    fun pqFromSeed(p: Pq.Prim, seed: ByteArray, signSeed: ByteArray? = null): PqKey {
        if (isFnDsa(p)) { // FN-DSA: 32-byte keygen seed through the registered backend (refused unsupported_suite without one); [signSeed] fixes the signing randomness
            require(seed.size == 32) { "$p needs a 32-byte seed" }
            require(signSeed == null || signSeed.size == 32) { "$p needs a 32-byte sign seed" }
            val kp = Pq.fnDsaKeygen(if (p == Pq.Prim.FN_DSA_512) "fn-dsa-512" else "fn-dsa-1024", seed)
            return PqKey(p, kp.first, kp.second, signSeed)
        }
        if (p == Pq.Prim.LESS_CAT1) { // LESS: 32-byte seed through libatlas_less (refused unsupported_suite without it); [signSeed] fixes the signing randomness
            require(seed.size == LessNative.SEED_BYTES) { "$p needs a 32-byte seed" }
            require(signSeed == null || signSeed.size >= LessNative.SEED_BYTES) { "$p needs a sign seed of at least 32 bytes" }
            if (!LessNative.canSign) throw IllegalArgumentException("${Pq.UNSUPPORTED_SUITE}: less-cat1")
            val kp = LessNative.keygen(seed)
            return PqKey(p, kp.first, kp.second, signSeed)
        }
        val need = when (p) { Pq.Prim.SLH_DSA_SHA2_128F -> 48; Pq.Prim.SLH_DSA_SHA2_256S -> 96; else -> 32 }
        require(seed.size == need) { "$p needs a $need-byte seed" }
        return pqGen(p, SeedRandom(seed))
    }

    /** Load a key pair from its encoded public and secret key (as produced by another implementation of the same suite). */
    fun pqLoad(p: Pq.Prim, pk: ByteArray, sk: ByteArray, signSeed: ByteArray? = null): PqKey {
        require(pk.size == p.pkBytes) { "wrong public key length for $p" }
        return PqKey(p, pk.clone(), sk.clone(), signSeed)
    }

    /**
     * The key material one signature suite needs: the suite name, the Ed25519 key (every hybrid, and ed25519 itself) and the
     * post-quantum key (every non-ed25519 suite). [suite] fails closed on a missing or mismatched key.
     */
    class SuiteKey internal constructor(val alg: String, val ed: EdKey?, val pq: PqKey?, internal val suite: Pq.Suite) {
        /** The PQ public key bound into the signed body (`pq_pk`); null for ed25519. */
        fun pqPk(): String? = if (suite.needsPqPk) pq!!.pkB64u() else null

        /** The Ed25519 identity (key id) this signer is known by; null for a pure PQ suite. */
        fun id(): String? = ed?.id()

        /** Sign: first is `sig`, second is `pq_sig` (hybrids only, else null). */
        fun sign(msg: ByteArray): Pair<String, String?> {
            if (suite.pq == null) return Pair(b64u(ed!!.sign(msg)), null)
            if (!suite.hasEd25519) return Pair(b64u(pq!!.sign(msg)), null)
            val edSig = ed!!.sign(msg)
            val pqSig = pq!!.sign(if (suite.nested) Pca.concat(msg, edSig) else msg)
            return Pair(b64u(edSig), b64u(pqSig))
        }
    }

    /** Ed25519 only (the default suite). */
    fun ed25519(ed: EdKey): SuiteKey = suite("ed25519", ed, null)

    fun suite(alg: String, ed: EdKey?, pq: PqKey?): SuiteKey {
        val s = Pq.resolveSigAlg(alg, true) ?: throw IllegalArgumentException(Pq.refusal(alg))
        require(!s.hasEd25519 || ed != null) { "'$alg' requires an Ed25519 key" }
        if (s.pq != null) {
            requireNotNull(pq) { "'$alg' requires a ${s.pq} key" }
            require(pq.prim == s.pq) { "'$alg' needs a ${s.pq} key, got ${pq.prim}" }
            require((s.pq != Pq.Prim.LESS_CAT1 || LessNative.canSign) && (!isFnDsa(s.pq!!) || Pq.fnDsaCanSign())) { "${Pq.UNSUPPORTED_SUITE}: $alg" } // LESS and FN-DSA need a signing backend
        }
        return SuiteKey(alg, ed, pq, s)
    }

    /** The verifier-side PQ pin for an identity: `{ ed25519 b64u: pq_pk }` (what `pqPins` holds). */
    fun pqPin(k: SuiteKey): Map<String, Any?> = linkedMapOf<String, Any?>().also { if (k.ed != null && k.pq != null) it[k.ed.id()] = k.pq.pkB64u() }
}
