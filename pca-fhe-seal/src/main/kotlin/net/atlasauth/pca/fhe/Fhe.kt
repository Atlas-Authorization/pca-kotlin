package net.atlasauth.pca.fhe

import net.atlasauth.pca.fhe.seal.FheSeal

/** The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2). */
class FheRiskPolicy(
    val scale: Long,
    val dim: Long,
    val weightsScaled: LongArray,
    val kappaWeightsScaled: LongArray,
    val budgetScaled: Long,
    val kappa: Double,
) {
    internal fun toJava() = FheSeal.Policy(scale, dim, weightsScaled, kappaWeightsScaled, budgetScaled, kappa)
}

/** Full key material: the key holder keeps [secretKey]; an evaluator only ever gets [evalKeys]. Each is a base64 SEAL stream. */
data class FheKeys(val secretKey: String, val publicKey: String, val relinKeys: String, val galoisKeys: String) {
    val evalKeys: FheEvalKeys get() = FheEvalKeys(publicKey, galoisKeys)
}

class FheEvalKeys(val publicKey: String, val galoisKeys: String)

/** The two encrypted gate outputs, each a base64 SEAL stream. */
data class EncryptedGate(val encRiskRaw: String, val encSlack: String)

/** The opened verdict: [rScaled] is r at scale S^2, [slack] the budget minus the kappa-weighted risk, [admit] is slack >= 0. */
data class FheVerdict(val rScaled: Long, val slack: Long, val admit: Boolean)

/**
 * Homomorphic evaluation of PCA's risk gate (BFV on Microsoft SEAL), a Kotlin face on the Java adapter `net.atlasauth:pca-fhe-seal`, which binds
 * SEAL's own C export API (libsealc, built from the pinned SEAL tag; set the `pca.sealc.lib` system property) and never hand-rolls the scheme.
 * Wire-compatible with the TypeScript reference: SEAL objects cross the API as base64 of the SEAL stream. Malformed input throws
 * IllegalArgumentException; a verdict that cannot be opened (wrong key, spent noise budget) throws IllegalStateException.
 */
object Fhe {
    const val POLY_MODULUS_DEGREE = FheSeal.POLY_MODULUS_DEGREE
    const val PLAIN_MODULUS = FheSeal.PLAIN_MODULUS
    const val SIGNED_BOUND = FheSeal.SIGNED_BOUND
    const val RISK_DIM = FheSeal.RISK_DIM

    /** True when libsealc can be loaded. */
    fun available(): Boolean = FheSeal.available()

    fun keygen(): FheKeys = FheSeal.keygen().let { FheKeys(it.secretKey(), it.publicKey(), it.relinKeys(), it.galoisKeys()) }

    /** Encrypts the integer risk vector (the output of the pure quantizer) under the public key. */
    fun encryptRiskInputs(publicKey: String, inputsScaled: LongArray): String = FheSeal.encryptRiskInputs(publicKey, inputsScaled)

    /** The evaluator's side: weighted risk and admission slack over the encrypted inputs; it never sees a plaintext. */
    fun evalRiskGate(keys: FheEvalKeys, encInputs: String, policy: FheRiskPolicy): EncryptedGate =
        FheSeal.evalRiskGate(keys.publicKey, keys.galoisKeys, encInputs, policy.toJava()).let { EncryptedGate(it.encRiskRaw(), it.encSlack()) }

    fun decryptVerdict(secretKey: String, gate: EncryptedGate, policy: FheRiskPolicy): FheVerdict =
        FheSeal.decryptVerdict(secretKey, gate.encRiskRaw, gate.encSlack, policy.toJava()).let { FheVerdict(it.rScaled(), it.slack(), it.admit()) }

    /** The blob re-saved without compression: byte comparison independent of the zstd build. */
    fun canonicalCipher(blob: String): String = FheSeal.canonicalCipher(blob)

    /** Validates a SEAL stream envelope before SEAL parses it. */
    fun assertSealBlob(blob: String, what: String): ByteArray = FheSeal.assertSealBlob(blob, what)
}
