package net.atlasauth.pca.fndsa

import net.atlasauth.pca.fndsa.FnDsa.FalconBackend
import net.atlasauth.pca.fndsa.FnDsa.FalconKeyPair
import net.atlasauth.pca.verifier.Pq

/**
 * Kotlin face of the real FN-DSA primitive (Pornin's fn-dsa 0.4.0, a draft best guess at FIPS 206; not interoperable with round-3 Falcon from
 * liboqs, BouncyCastle or circl). Every operation is libfndsa reached through the Java adapter ([NativeFnDsa], `ATLAS_PCA_LIBFNDSA` or
 * `-Dpca.fndsa.lib`); the PCA leaf framing and the Ed25519 hybrid rule are the Java [FnDsa] (signPcaWithFndsa, verifyPcaFndsa), reachable as-is
 * once [register] has installed the backend. A missing library fails loudly; nothing falls back to "invalid".
 */
object FnDsaNative {
    /** True when libfndsa can be loaded. */
    fun available(): Boolean = NativeFnDsa.available()

    /**
     * Install the real primitive as the [FnDsa] backend AND as the Kotlin core verifier's FN-DSA hook ([Pq.registerFnDsa]), so fn-dsa-512 / fn-dsa-1024
     * verify AND sign (Keys.pqFromSeed / Keys.suite / Issue.signPCActn, mint, delegate, escalation answers, revocation epochs) through the core suite dispatch (throws when the library cannot be loaded; nothing registers at load).
     */
    fun register(): FalconBackend {
        val b = NativeFnDsa.register()
        Pq.registerFnDsa(CoreBackend)
        return b
    }

    /** The core hook over libfndsa: verifies, and (so the agent-side signers can sign fn-dsa-512/1024) derives keys and signs. */
    private object CoreBackend : Pq.FnDsaBackend {
        override fun verify(variant: String, vk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = NativeFnDsa.verify(variant, vk, msg, sig)
        override fun canSign(): Boolean = true
        override fun keygen(variant: String, seed: ByteArray): Pair<ByteArray, ByteArray> = NativeFnDsa.keygen(variant, seed).let { Pair(it.pk, it.sk) }
        override fun sign(variant: String, sk: ByteArray, msg: ByteArray, seed: ByteArray): ByteArray = NativeFnDsa.sign(variant, sk, msg, seed)
    }

    /** Remove both registrations: the core refuses fn-dsa-* with `unsupported_suite` again. */
    fun unregister() {
        Pq.unregisterFnDsa()
        FnDsa.resetFalconBackend()
    }

    /** Deterministic key generation from a 32-byte seed ("fn-dsa-512" or "fn-dsa-1024"). */
    fun keygen(variant: String, seed: ByteArray): FalconKeyPair = NativeFnDsa.keygen(variant, seed)

    fun keygen(variant: String): FalconKeyPair = NativeFnDsa.keygen(variant)

    /** Signature over a raw message of at most 8192 bytes; [seed] is 32 bytes, fresh CSPRNG bytes when omitted. */
    fun sign(variant: String, sk: ByteArray, msg: ByteArray, seed: ByteArray? = null): ByteArray =
        if (seed == null) NativeFnDsa.sign(variant, sk, msg) else NativeFnDsa.sign(variant, sk, msg, seed)

    /** True only when the library accepts the signature. */
    fun verify(variant: String, vk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = NativeFnDsa.verify(variant, vk, msg, sig)
}
