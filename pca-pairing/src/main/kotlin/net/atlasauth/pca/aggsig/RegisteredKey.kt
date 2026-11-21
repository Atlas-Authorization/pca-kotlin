package net.atlasauth.pca.aggsig

/**
 * A public key whose proof of possession has been verified. The constructor is internal and the class is final, so the
 * only producers are [Aggsig.registerKey] and [KeyRegistry.register], and both run the proof-of-possession check first.
 */
class RegisteredKey internal constructor(bytes: ByteArray) {
    private val raw: ByteArray = bytes.clone()

    /** A copy of the 48-byte compressed G1 public key. */
    fun bytes(): ByteArray = raw.clone()
}
