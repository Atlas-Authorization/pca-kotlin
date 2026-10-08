package net.atlasauth.pca.stepup

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/** Where the 32-byte Ed25519 seed is persisted. */
interface SecretStore {
    fun load(): ByteArray?
    fun save(secret: ByteArray)
    fun delete()
}

/**
 * The principal's Ed25519 device key.
 *
 * HONEST CAVEAT: Android Keystore does not offer Ed25519 on most devices (and never as a
 * portable, exportable key), and the PCA principal key MUST be Ed25519. So this is a SOFTWARE
 * key: the 32-byte seed is stored in [EncryptedSharedPreferences], encrypted at rest with an
 * AES-256 master key that lives in the Android Keystore (hardware-backed where the device has
 * it). The seed itself is not hardware-bound: once decrypted it is in process memory. Gate
 * approvals behind BiometricPrompt in your app to get user-presence on every approval.
 */
class PrincipalDeviceKey(private val store: SecretStore) {

    /** Convenience: back the key with [AndroidKeystoreSecretStore]. */
    constructor(context: Context) : this(AndroidKeystoreSecretStore(context))

    /** True when a key is stored. */
    val exists: Boolean get() = runCatching { store.load() }.getOrNull() != null

    /** Generate a fresh key (replacing any existing one). Returns the public key (base64url) to register as the grant's principal. */
    fun generate(): String {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        store.save(seed)
        return publicOf(seed)
    }

    /**
     * Import an existing principal secret (base64url 32-byte seed, as `@atlasauth/pca` encodes
     * `secretKey`). The key MUST match the grant's principal. Returns the public key.
     */
    fun importSecret(secretB64u: String): String {
        val raw = Base64Url.decode(secretB64u)?.takeIf { it.size == 32 } ?: throw StepUpError.InvalidSecret()
        store.save(raw)
        return publicOf(raw)
    }

    /** Export the secret (base64url seed) for backup/migration. Treat it like a password. */
    fun exportSecret(): String = Base64Url.encode(loadSeed())

    /** The public key (base64url), as registered on the grant. */
    fun publicKey(): String = publicOf(loadSeed())

    /** Ed25519-sign [message]; returns the signature as base64url. */
    fun sign(message: ByteArray): String {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(loadSeed(), 0))
        signer.update(message, 0, message.size)
        return Base64Url.encode(signer.generateSignature())
    }

    /** Remove the key from secure storage. */
    fun delete() = store.delete()

    private fun loadSeed(): ByteArray {
        val seed = store.load() ?: throw StepUpError.NoDeviceKey()
        if (seed.size != 32) throw StepUpError.InvalidSecret()
        return seed
    }

    private fun publicOf(seed: ByteArray): String =
        Base64Url.encode(Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded)
}

/** In-memory store, for tests and previews only. */
class InMemorySecretStore : SecretStore {
    @Volatile private var value: ByteArray? = null
    override fun load() = value?.copyOf()
    override fun save(secret: ByteArray) { value = secret.copyOf() }
    override fun delete() { value = null }
}

/** Production store: Keystore-wrapped [EncryptedSharedPreferences]. */
class AndroidKeystoreSecretStore(
    context: Context,
    fileName: String = "net.atlasauth.pca.stepup",
    private val entry: String = "principal-ed25519",
) : SecretStore {
    private val prefs = context.applicationContext.let { app ->
        EncryptedSharedPreferences.create(
            app,
            fileName,
            MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun load(): ByteArray? = prefs.getString(entry, null)?.let { Base64Url.decode(it) }

    // commit() (synchronous) so the key is durable before generate()/importSecret() returns.
    override fun save(secret: ByteArray) {
        check(prefs.edit().putString(entry, Base64Url.encode(secret)).commit()) { "Could not persist the principal key." }
    }

    override fun delete() { prefs.edit().remove(entry).commit() }
}
