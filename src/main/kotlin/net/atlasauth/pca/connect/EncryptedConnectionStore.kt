package net.atlasauth.pca.connect

import net.atlasauth.pca.verifier.Json

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.verifier.Keys

/**
 * Wraps and unwraps the per-secret data keys of [EncryptedConnectionStore]: a local key ring ([LocalKeyWrapper]) or your KMS
 * behind the same two methods. `aad` binds the wrapped key to the exact connection and field, so a ciphertext copied to another
 * connection or field fails to open.
 */
interface KeyWrapper {
    class Wrapped(val keyId: String, val wrapped: ByteArray)

    fun wrap(dek: ByteArray, aad: ByteArray): Wrapped

    fun unwrap(keyId: String, wrapped: ByteArray, aad: ByteArray): ByteArray
}

/**
 * A key ring held in process memory. Rotation: add the new key under a new id and make it active; records written under old ids still open
 * until you remove the old key. For production keys implement [KeyWrapper] over a KMS. [destroy] overwrites the key bytes.
 */
class LocalKeyWrapper(ring: Map<String, ByteArray>, activeId: String) : KeyWrapper {
    private val keys = HashMap<String, ByteArray>()
    private var active: String

    init {
        for ((k, v) in ring) addKey(k, v)
        if (!keys.containsKey(activeId)) throw IllegalArgumentException("LocalKeyWrapper: the active key id is not in the key ring")
        active = activeId
    }

    @Synchronized fun addKey(id: String, key: ByteArray?) {
        if (id.isEmpty()) throw IllegalArgumentException("LocalKeyWrapper: key id must not be empty")
        if (key == null || key.size != 32) throw IllegalArgumentException("LocalKeyWrapper: keys must be 32 bytes")
        keys[id] = key.clone()
    }

    @Synchronized fun setActive(id: String) {
        if (!keys.containsKey(id)) throw IllegalArgumentException("LocalKeyWrapper: the active key id is not in the key ring")
        active = id
    }

    @Synchronized fun removeKey(id: String) {
        if (id == active) throw IllegalArgumentException("LocalKeyWrapper: cannot remove the active key")
        keys.remove(id)?.fill(0)
    }

    @Synchronized fun destroy() {
        for (k in keys.values) k.fill(0)
        keys.clear()
    }

    @Synchronized override fun wrap(dek: ByteArray, aad: ByteArray): KeyWrapper.Wrapped {
        val k = keys[active] ?: throw IllegalStateException("no active key")
        return KeyWrapper.Wrapped(active, seal(k, aad, dek))
    }

    @Synchronized override fun unwrap(keyId: String, wrapped: ByteArray, aad: ByteArray): ByteArray {
        val k = keys[keyId] ?: throw IllegalStateException("unknown key id")
        return open(k, aad, wrapped)
    }

    companion object {
        private val RNG = SecureRandom()

        /** AES-256-GCM: iv(12) || ciphertext || tag(16), the aad authenticated. */
        internal fun seal(key: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
            try {
                val iv = ByteArray(12)
                RNG.nextBytes(iv)
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                c.updateAAD(aad)
                val ct = c.doFinal(plain)
                val out = ByteArray(12 + ct.size)
                System.arraycopy(iv, 0, out, 0, 12)
                System.arraycopy(ct, 0, out, 12, ct.size)
                return out
            } catch (e: GeneralSecurityException) {
                throw IllegalStateException("seal failed", e)
            }
        }

        internal fun open(key: ByteArray, aad: ByteArray, sealed: ByteArray): ByteArray {
            if (sealed.size < 12 + 16) throw IllegalArgumentException("short ciphertext")
            try {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, sealed, 0, 12))
                c.updateAAD(aad)
                return c.doFinal(sealed, 12, sealed.size - 12)
            } catch (e: GeneralSecurityException) {
                throw IllegalStateException("open failed", e)
            }
        }
    }
}

/**
 * Wraps any [ConnectionStore] so `accessToken` and `refreshToken` are encrypted before they reach it (envelope encryption:
 * a random data key per secret, wrapped by a [KeyWrapper], the aad binding it to the exact connection and field). Everything else in
 * a record stays readable so the inner store can index and expire it. Fails closed: a stored token that is not an envelope, fails
 * authentication, or was sealed under an unknown key makes `get` throw a [VaultError.StoreError] that carries no detail.
 */
class EncryptedConnectionStore(private val inner: ConnectionStore, private val wrapper: KeyWrapper) : ConnectionStore {
    override fun encrypted(): Boolean = true

    private fun encryptField(key: ConnectionStore.Key, field: String, plain: String): String {
        val aad = aadFor(key, field)
        val dek = ByteArray(32)
        RNG.nextBytes(dek)
        try {
            val w = wrapper.wrap(dek, aad)
            val sealed = LocalKeyWrapper.seal(dek, aad, Json.utf8(plain))
            return listOf(PREFIX, Keys.b64u(Json.utf8(w.keyId)), Keys.b64u(w.wrapped), Keys.b64u(sealed)).joinToString(".")
        } finally {
            dek.fill(0)
        }
    }

    private fun decryptField(key: ConnectionStore.Key, field: String, value: String): String {
        val parts = value.split('.')
        if (parts.size != 4 || parts[0] != PREFIX) throw IllegalArgumentException("not an envelope")
        val aad = aadFor(key, field)
        val dek = wrapper.unwrap(String(unb64u(parts[1]), Charsets.UTF_8), unb64u(parts[2]), aad)
        try {
            return String(LocalKeyWrapper.open(dek, aad, unb64u(parts[3])), Charsets.UTF_8)
        } finally {
            dek.fill(0)
        }
    }

    override fun get(key: ConnectionStore.Key): StoredConnection? {
        val raw = inner.get(key) ?: return null
        try {
            val out = raw.copy()
            val k = ConnectionStore.Key(raw.agentId, raw.provider, raw.connectionId)
            if (k.agentId != key.agentId || k.provider != key.provider || k.connectionId != key.connectionId) throw IllegalStateException("record key mismatch")
            out.accessToken = decryptField(k, "access", raw.accessToken)
            val rt = raw.refreshToken
            if (rt != null) out.refreshToken = decryptField(k, "refresh", rt)
            return out
        } catch (e: Exception) {
            throw VaultError.StoreError("a stored token could not be decrypted")
        }
    }

    override fun set(connection: StoredConnection) {
        val k = ConnectionStore.Key(connection.agentId, connection.provider, connection.connectionId)
        val sealed = connection.copy()
        try {
            sealed.accessToken = encryptField(k, "access", connection.accessToken)
            val rt = connection.refreshToken
            if (rt != null) sealed.refreshToken = encryptField(k, "refresh", rt)
        } catch (e: Exception) {
            throw VaultError.StoreError("a token could not be encrypted; nothing was stored")
        }
        inner.set(sealed)
    }

    override fun delete(key: ConnectionStore.Key) = inner.delete(key)

    /** Re-encrypt one record under the wrapper's active key (run after rotating the key ring). */
    fun reencrypt(key: ConnectionStore.Key): Boolean {
        val c = get(key) ?: return false
        set(c)
        return true
    }

    companion object {
        private const val PREFIX = "pca1"
        private val RNG = SecureRandom()
        private val B64U = Regex("[A-Za-z0-9_-]*")

        private fun unb64u(s: String): ByteArray {
            if (!B64U.matches(s)) throw IllegalArgumentException("bad encoding")
            return JsText.b64uDecode(s)
        }

        private fun utf8Len(s: String): Int = Json.utf8(s).size

        /** The additional authenticated data: length-prefixed (version, field, agent, provider, connection). */
        internal fun aadFor(key: ConnectionStore.Key, field: String): ByteArray {
            val parts = listOf("pca-connect/v1", field, key.agentId, key.provider, key.connectionId)
            return parts.joinToString("|") { utf8Len(it).toString() + ":" + it }.toByteArray(Charsets.UTF_8)
        }
    }
}
