package net.atlasauth.pca.mpc

import java.security.SecureRandom
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters

/**
 * ML-KEM-768 (FIPS 203) on the audited BouncyCastle implementation with caller-supplied randomness: key generation from a 64-byte seed
 * (d || z) and encapsulation from a 32-byte message, so the OT transcripts are reproducible from a seeded stream.
 */
internal object MlKem768 {
    const val MSG_BYTES = 32
    const val KEYGEN_SEED_BYTES = 64

    /** A SecureRandom that replays fixed bytes in order (the engines draw d, z / the message in FIPS 203 order). */
    private class Replay(data: ByteArray) : SecureRandom() {
        private val data: ByteArray = data.clone()
        private var at = 0

        @Synchronized override fun nextBytes(bytes: ByteArray) {
            check(at + bytes.size <= data.size) { "MlKem768: randomness exhausted" }
            System.arraycopy(data, at, bytes, 0, bytes.size)
            at += bytes.size
        }
    }

    /** A key pair; [publicKey] is the 1184-byte encapsulation key. */
    class KeyPair(val publicKey: ByteArray, val secretKey: MLKEMPrivateKeyParameters)

    /** Encapsulation result. */
    class Encapsulation(val cipherText: ByteArray, val sharedSecret: ByteArray)

    fun keygen(seed64: ByteArray): KeyPair {
        require(seed64.size == KEYGEN_SEED_BYTES) { "ml-kem keygen: seed must be exactly 64 bytes" }
        val g = MLKEMKeyPairGenerator()
        g.init(MLKEMKeyGenerationParameters(Replay(seed64), MLKEMParameters.ml_kem_768))
        val kp: AsymmetricCipherKeyPair = g.generateKeyPair()
        return KeyPair((kp.public as MLKEMPublicKeyParameters).encoded, kp.private as MLKEMPrivateKeyParameters)
    }

    fun encapsulate(publicKey: ByteArray, msg32: ByteArray): Encapsulation {
        require(msg32.size == MSG_BYTES) { "ml-kem encapsulate: message must be exactly 32 bytes" }
        val pk = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, publicKey)
        val s = MLKEMGenerator(Replay(msg32)).generateEncapsulated(pk)
        return Encapsulation(s.encapsulation, s.secret)
    }

    fun decapsulate(cipherText: ByteArray, sk: MLKEMPrivateKeyParameters): ByteArray = MLKEMExtractor(sk).extractSecret(cipherText)
}
