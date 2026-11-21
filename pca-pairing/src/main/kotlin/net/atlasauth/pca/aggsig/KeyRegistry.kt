package net.atlasauth.pca.aggsig

/** A verifier's pinned set of admitted keys, indexed by key bytes: each was admitted with a verified proof of possession. */
class KeyRegistry {
    private val keys = HashMap<String, RegisteredKey>()

    /** Verify the proof of possession and admit the key. Re-registering the same key is idempotent. */
    @Synchronized
    fun register(publicKey: ByteArray?, pop: ByteArray?): Aggsig.RegisterResult {
        val r = Aggsig.registerKey(publicKey, pop)
        val k = r.key
        if (r.ok && k != null && publicKey != null) keys[Aggsig.hex(publicKey)] = k
        return r
    }

    /** The registered key for these bytes, or null if it was never admitted. */
    @Synchronized
    fun get(publicKey: ByteArray?): RegisteredKey? =
        if (publicKey != null && publicKey.size == AggsigCore.PUBLIC_KEY_LENGTH) keys[Aggsig.hex(publicKey)] else null

    fun has(publicKey: ByteArray?): Boolean = get(publicKey) != null

    @Synchronized
    fun size(): Int = keys.size
}
