package net.atlasauth.pca.verifier

import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters

/**
 * Post-quantum key encapsulation that establishes a 32-byte shared secret (no cipher is shipped): the custom HKDF hybrid X25519 +
 * ML-KEM-768 (and its own-domain ML-KEM-1024 variant), the X-Wing hybrid of draft-connolly-cfrg-xwing-kem-09 (SHA3-256 combiner, byte
 * interoperable), and the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM keys. All primitives come from BouncyCastle; every input
 * is length-checked and every refusal throws IllegalArgumentException.
 */
object Kem {
    private const val X_LEN = 32
    private const val SS_LEN = 32

    const val HYBRID_PUBLIC_KEY_LEN = 1216
    const val HYBRID_CIPHERTEXT_LEN = 1120
    const val HYBRID_SHARED_SECRET_LEN = 32
    const val HYBRID_KEM_SUITE = "x25519-ml-kem-768"
    const val XWING_SUITE = "xwing"
    const val XWING_SEED_LEN = 32
    const val XWING_SECRET_KEY_LEN = 32
    const val XWING_PUBLIC_KEY_LEN = 1216
    const val XWING_CIPHERTEXT_LEN = 1120
    const val XWING_SHARED_SECRET_LEN = 32
    const val XWING_ESEED_LEN = 64
    const val HYBRID1024_PUBLIC_KEY_LEN = 1600
    const val HYBRID1024_CIPHERTEXT_LEN = 1600
    const val HYBRID1024_SHARED_SECRET_LEN = 32
    const val HYBRID1024_KEM_SUITE = "x25519-ml-kem-1024"

    private val XWING_LABEL = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

    /** The 6-byte X-Wing domain label, ASCII `\.//^\`. */
    fun xwingLabel(): ByteArray = XWING_LABEL.clone()

    /** A recipient key pair. Hybrid: pub = X25519 pub (32) || ML-KEM ek, secret = X25519 secret (32) || expanded ML-KEM dk. X-Wing: secret = the 32-byte seed. */
    class KeyPair(val publicKey: ByteArray, val secretKey: ByteArray)

    /** The ciphertext to send and the 32-byte shared secret to keep. */
    class Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    private val RNG = SecureRandom()

    private fun random(n: Int): ByteArray = ByteArray(n).also { RNG.nextBytes(it) }

    private fun cat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) { System.arraycopy(p, 0, out, o, p.size); o += p.size }
        return out
    }

    private fun slice(b: ByteArray, from: Int, to: Int): ByteArray = b.copyOfRange(from, to)

    /** A SecureRandom that replays fixed bytes in order (the engines draw d, z / the message in FIPS 203 order). */
    private class Replay(data: ByteArray) : SecureRandom() {
        private val data: ByteArray = data.clone()
        private var at = 0

        @Synchronized override fun nextBytes(bytes: ByteArray) {
            check(at + bytes.size <= data.size) { "Kem: randomness exhausted" }
            System.arraycopy(data, at, bytes, 0, bytes.size)
            at += bytes.size
        }
    }

    /** One ML-KEM parameter set and the hybrid transcript domain built on it. */
    private class Level(val params: MLKEMParameters, val k: Int, val ctLen: Int, suite: String) {
        val ekLen = 384 * k + 32
        val dkLen = 768 * k + 96
        val domain: ByteArray = "atlas-pca/kem/$suite/v1\u0000".toByteArray(Charsets.UTF_8)
    }

    private val L768 = Level(MLKEMParameters.ml_kem_768, 3, 1088, "x25519-ml-kem-768")
    private val L1024 = Level(MLKEMParameters.ml_kem_1024, 4, 1568, "x25519-ml-kem-1024")

    private fun levelOf(level: Int): Level = when (level) {
        768 -> L768
        1024 -> L1024
        else -> throw IllegalArgumentException("ML-KEM level must be 768 or 1024")
    }

    // ---- primitives ----

    private fun xPublic(secret: ByteArray): ByteArray = X25519PrivateKeyParameters(secret, 0).generatePublicKey().encoded

    /** X25519 ECDH; an all-zero result (a low-order peer point) is refused. */
    private fun xAgree(secret: ByteArray, peerPublic: ByteArray): ByteArray {
        val a = X25519Agreement()
        a.init(X25519PrivateKeyParameters(secret, 0))
        val out = ByteArray(X_LEN)
        a.calculateAgreement(X25519PublicKeyParameters(peerPublic, 0), out, 0)
        var acc = 0
        for (b in out) acc = acc or b.toInt()
        require(acc != 0) { "Kem: X25519 produced an all-zero shared secret (low-order point)" }
        return out
    }

    private fun sha3(inp: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(inp, 0, inp.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    /** ML-KEM key generation from the 64-byte seed d || z. */
    private fun mlKeygen(lv: Level, dz: ByteArray): AsymmetricCipherKeyPair {
        val g = MLKEMKeyPairGenerator()
        g.init(MLKEMKeyGenerationParameters(Replay(dz), lv.params))
        return g.generateKeyPair()
    }

    private fun mlEk(kp: AsymmetricCipherKeyPair): ByteArray = (kp.public as MLKEMPublicKeyParameters).encoded

    private fun mlDk(lv: Level, kp: AsymmetricCipherKeyPair): ByteArray {
        val dk = (kp.private as MLKEMPrivateKeyParameters).encoded
        check(dk.size == lv.dkLen) { "Kem: unexpected ML-KEM decapsulation key length ${dk.size}" }
        return dk
    }

    private fun mlEncaps(lv: Level, ek: ByteArray, m: ByteArray): SecretWithEncapsulation =
        MLKEMGenerator(Replay(m)).generateEncapsulated(MLKEMPublicKeyParameters(lv.params, ek))

    /** ML-KEM decapsulation from an EXPANDED dk. BouncyCastle does not validate the encoding length, so it is checked here. */
    private fun mlDecaps(lv: Level, ct: ByteArray, dk: ByteArray): ByteArray {
        require(ct.size == lv.ctLen) { "Kem: ML-KEM ciphertext must be ${lv.ctLen} bytes (got ${ct.size})" }
        require(dk.size == lv.dkLen) { "Kem: ML-KEM decapsulation key must be ${lv.dkLen} bytes (got ${dk.size})" }
        return MLKEMExtractor(MLKEMPrivateKeyParameters(lv.params, dk)).extractSecret(ct)
    }

    /** FIPS 203 section 7.2: every 12-bit coefficient of the 384*k-byte t part is strictly below q = 3329. */
    private fun coefficientsReduced(ek: ByteArray, k: Int): Boolean {
        var i = 0
        while (i < 384 * k) {
            if (((ek[i].toInt() and 0xff) or ((ek[i + 1].toInt() and 0x0f) shl 8)) >= 3329) return false
            if ((((ek[i + 1].toInt() and 0xff) shr 4) or ((ek[i + 2].toInt() and 0xff) shl 4)) >= 3329) return false
            i += 3
        }
        return true
    }

    private fun requireReduced(ek: ByteArray, k: Int, who: String) {
        require(coefficientsReduced(ek, k)) { "$who: ML-KEM encapsulation key fails the FIPS 203 modulus check" }
    }

    private fun combine(lv: Level, ssMl: ByteArray, ssX: ByteArray, ephPub: ByteArray, recipX: ByteArray): ByteArray =
        Entropy.hkdfSha256(cat(ssMl, ssX, ephPub, recipX), null, lv.domain, SS_LEN)

    // ---- the custom HKDF hybrid (768 and 1024 share one body) ----

    private fun hybridKeygen(lv: Level, rng: ByteArray): KeyPair {
        require(rng.size == 96) { "Kem: keygen randomness must be x(32) || d(32) || z(32)" }
        val x = slice(rng, 0, 32)
        val kp = mlKeygen(lv, slice(rng, 32, 96))
        return KeyPair(cat(xPublic(x), mlEk(kp)), cat(x, mlDk(lv, kp)))
    }

    private fun hybridEncaps(lv: Level, pk: ByteArray, rng: ByteArray, who: String): Encapsulation {
        require(pk.size == X_LEN + lv.ekLen) { "$who: public key must be ${X_LEN + lv.ekLen} bytes (got ${pk.size})" }
        require(rng.size == 64) { "Kem: encapsulation randomness must be ephemeral(32) || m(32)" }
        val recipX = slice(pk, 0, X_LEN)
        val recipMl = slice(pk, X_LEN, pk.size)
        val eph = slice(rng, 0, 32)
        val ephPub = xPublic(eph)
        val ssX = xAgree(eph, recipX)
        requireReduced(recipMl, lv.k, who)
        val s = mlEncaps(lv, recipMl, slice(rng, 32, 64))
        return Encapsulation(cat(ephPub, s.encapsulation), combine(lv, s.secret, ssX, ephPub, recipX))
    }

    private fun hybridDecaps(lv: Level, ct: ByteArray, sk: ByteArray, who: String): ByteArray {
        require(ct.size == X_LEN + lv.ctLen) { "$who: ciphertext must be ${X_LEN + lv.ctLen} bytes (got ${ct.size})" }
        require(sk.size > X_LEN) { "$who: malformed secret key" }
        val ephPub = slice(ct, 0, X_LEN)
        val xPriv = slice(sk, 0, X_LEN)
        val ssX = xAgree(xPriv, ephPub)
        val ssMl = mlDecaps(lv, slice(ct, X_LEN, ct.size), slice(sk, X_LEN, sk.size))
        return combine(lv, ssMl, ssX, ephPub, xPublic(xPriv))
    }

    /** Generate a hybrid X25519 + ML-KEM-768 recipient key pair (public 1216 bytes, secret 2432 bytes). */
    fun hybridKemKeygen(): KeyPair = hybridKeygen(L768, random(96))

    /** Test entry point: the randomness is `x(32) || d(32) || z(32)`. */
    internal fun hybridKemKeygenDerand(rng: ByteArray): KeyPair = hybridKeygen(L768, rng)

    /** Encapsulate to a hybrid recipient public key. */
    fun hybridEncapsulate(recipientPublicKey: ByteArray): Encapsulation = hybridEncaps(L768, recipientPublicKey, random(64), "hybridEncapsulate")

    /** Test entry point: the randomness is `ephemeralX25519Secret(32) || m(32)`. */
    internal fun hybridEncapsulateDerand(recipientPublicKey: ByteArray, rng: ByteArray): Encapsulation = hybridEncaps(L768, recipientPublicKey, rng, "hybridEncapsulate")

    /** Decapsulate with the recipient secret key: recovers the same shared secret. */
    fun hybridDecapsulate(ciphertext: ByteArray, secretKey: ByteArray): ByteArray = hybridDecaps(L768, ciphertext, secretKey, "hybridDecapsulate")

    /** Generate a hybrid X25519 + ML-KEM-1024 recipient key pair (public 1600 bytes, secret 3200 bytes). */
    fun hybridKem1024Keygen(): KeyPair = hybridKeygen(L1024, random(96))
    internal fun hybridKem1024KeygenDerand(rng: ByteArray): KeyPair = hybridKeygen(L1024, rng)

    fun hybridEncapsulate1024(recipientPublicKey: ByteArray): Encapsulation = hybridEncaps(L1024, recipientPublicKey, random(64), "hybridEncapsulate1024")
    internal fun hybridEncapsulate1024Derand(recipientPublicKey: ByteArray, rng: ByteArray): Encapsulation = hybridEncaps(L1024, recipientPublicKey, rng, "hybridEncapsulate1024")

    fun hybridDecapsulate1024(ciphertext: ByteArray, secretKey: ByteArray): ByteArray = hybridDecaps(L1024, ciphertext, secretKey, "hybridDecapsulate1024")

    // ---- X-Wing (draft-connolly-cfrg-xwing-kem-09) ----

    private class XWingKey(val ml: AsymmetricCipherKeyPair, val xSecret: ByteArray, val xPublic: ByteArray)

    /** Draft-09 5.2: SHAKE-256(seed, 96) = d(32) || z(32) || skX(32). */
    private fun xwingExpand(seed: ByteArray): XWingKey {
        require(seed.size == XWING_SEED_LEN) { "xwing: seed must be $XWING_SEED_LEN bytes (got ${seed.size})" }
        val sh = SHAKEDigest(256)
        sh.update(seed, 0, seed.size)
        val ex = ByteArray(96)
        sh.doFinal(ex, 0, 96)
        val xs = slice(ex, 64, 96)
        return XWingKey(mlKeygen(L768, slice(ex, 0, 64)), xs, xPublic(xs))
    }

    /** Draft-09 5.3: SHA3-256(ssM || ssX || ctX || pkX || label); ct_M is deliberately not hashed in. */
    private fun xwingCombine(ssM: ByteArray, ssX: ByteArray, ctX: ByteArray, pkX: ByteArray): ByteArray = sha3(cat(ssM, ssX, ctX, pkX, XWING_LABEL))

    /** Generate an X-Wing key pair from a fresh seed; the secret key IS the 32-byte seed. */
    fun xwingKeygen(): KeyPair = xwingKeygen(random(XWING_SEED_LEN))

    /** Deterministic X-Wing key generation from a 32-byte seed (copied into the result). */
    fun xwingKeygen(seed: ByteArray): KeyPair {
        val sk = seed.clone()
        val ex = xwingExpand(sk)
        return KeyPair(cat(mlEk(ex.ml), ex.xPublic), sk)
    }

    /** Derandomized X-Wing encapsulation: `eseed` (64 bytes) = ML-KEM message m (32) || X25519 ephemeral secret (32). */
    fun xwingEncapsulateDerand(recipientPublicKey: ByteArray, eseed: ByteArray): Encapsulation {
        require(recipientPublicKey.size == XWING_PUBLIC_KEY_LEN) { "xwingEncapsulateDerand: public key must be $XWING_PUBLIC_KEY_LEN bytes (got ${recipientPublicKey.size})" }
        require(eseed.size == XWING_ESEED_LEN) { "xwingEncapsulateDerand: eseed must be $XWING_ESEED_LEN bytes (got ${eseed.size})" }
        val pkM = slice(recipientPublicKey, 0, 1184)
        val pkX = slice(recipientPublicKey, 1184, XWING_PUBLIC_KEY_LEN)
        val ekX = slice(eseed, 32, 64)
        requireReduced(pkM, 3, "xwingEncapsulateDerand")
        val s = mlEncaps(L768, pkM, slice(eseed, 0, 32))
        val ctX = xPublic(ekX)
        val ssX = xAgree(ekX, pkX)
        return Encapsulation(cat(s.encapsulation, ctX), xwingCombine(s.secret, ssX, ctX, pkX))
    }

    /** Encapsulate to an X-Wing public key with fresh randomness. */
    fun xwingEncapsulate(recipientPublicKey: ByteArray): Encapsulation = xwingEncapsulateDerand(recipientPublicKey, random(XWING_ESEED_LEN))

    /** Decapsulate an X-Wing ciphertext with the 32-byte seed secret key. */
    fun xwingDecapsulate(ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        require(ciphertext.size == XWING_CIPHERTEXT_LEN) { "xwingDecapsulate: ciphertext must be $XWING_CIPHERTEXT_LEN bytes (got ${ciphertext.size})" }
        val ex = xwingExpand(secretKey)
        val ctM = slice(ciphertext, 0, 1088)
        val ctX = slice(ciphertext, 1088, XWING_CIPHERTEXT_LEN)
        val ssM = MLKEMExtractor(ex.ml.private as MLKEMPrivateKeyParameters).extractSecret(ctM)
        val ssX = xAgree(ex.xSecret, ctX)
        return xwingCombine(ssM, ssX, ctX, ex.xPublic)
    }

    // ---- b64url wire forms (unpadded; decode is strict: canonical alphabet and trailing bits) ----

    fun encodeHybridPublicKey(k: ByteArray): String = Keys.b64u(k)
    fun decodeHybridPublicKey(s: String): ByteArray = Keys.unb64u(s)
    fun encodeHybridCiphertext(c: ByteArray): String = Keys.b64u(c)
    fun decodeHybridCiphertext(s: String): ByteArray = Keys.unb64u(s)
    fun encodeXWingPublicKey(k: ByteArray): String = Keys.b64u(k)
    fun decodeXWingPublicKey(s: String): ByteArray = Keys.unb64u(s)
    fun encodeXWingCiphertext(c: ByteArray): String = Keys.b64u(c)
    fun decodeXWingCiphertext(s: String): ByteArray = Keys.unb64u(s)

    // ---- FIPS 203 7.2 / 7.3 input checks for keys that did not come from this process's own keygen ----

    /** FIPS 203 7.2 type and modulus check of an encapsulation key; false for any wrong length or non-reduced coefficient. An unknown level throws. */
    fun mlKemEncapsulationKeyCheck(level: Int, ek: ByteArray?): Boolean {
        val lv = levelOf(level)
        return ek != null && ek.size == lv.ekLen && coefficientsReduced(ek, lv.k)
    }

    /** FIPS 203 7.3 check of a decapsulation key: length, the embedded H(ek) and the embedded key's modulus check. An unknown level throws. */
    fun mlKemDecapsulationKeyCheck(level: Int, dk: ByteArray?): Boolean {
        val lv = levelOf(level)
        if (dk == null || dk.size != lv.dkLen) return false
        val ek = slice(dk, 384 * lv.k, 768 * lv.k + 32)
        val h = slice(dk, 768 * lv.k + 32, 768 * lv.k + 64)
        return MessageDigest.isEqual(sha3(ek), h) && mlKemEncapsulationKeyCheck(level, ek)
    }
}
