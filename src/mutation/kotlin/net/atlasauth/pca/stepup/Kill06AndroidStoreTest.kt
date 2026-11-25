package net.atlasauth.pca.stepup

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.junit.Assert.*
import org.junit.Test

/** AndroidKeystoreSecretStore's own logic, against the in-memory stand-ins in src/mutation/android-stubs: Android's Keystore itself is not exercised. */
class Kill06AndroidStoreTest {
    private val app = Context()
    private val ctx = object : Context() { override val applicationContext: Context get() = app }

    private fun created() = EncryptedSharedPreferences.last!!

    @Test fun opensTheEncryptedFileWithTheApplicationContextAndAes256() {
        AndroidKeystoreSecretStore(ctx)
        val c = created()
        assertSame(app, c.context)
        assertEquals("net.atlasauth.pca.stepup", c.fileName)
        assertSame(app, c.masterKey.context)
        assertEquals(MasterKey.KeyScheme.AES256_GCM, c.masterKey.scheme)
        assertEquals(EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, c.keyScheme)
        assertEquals(EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM, c.valueScheme)
    }

    @Test fun savesUnderTheEntryAsBase64UrlAndReadsItBack() {
        val s = AndroidKeystoreSecretStore(ctx, "f", "e")
        val c = created()
        assertEquals("f", c.fileName)
        assertNull(s.load())
        val secret = ByteArray(32) { (it * 7).toByte() }
        s.save(secret)
        assertEquals(mapOf("e" to Base64Url.encode(secret)), c.values)
        assertArrayEquals(secret, s.load())
        s.delete()
        assertEquals(emptyMap<String, String?>(), c.values)
        assertEquals(2, c.commits)
        assertNull(s.load())
    }

    @Test fun theDefaultEntryNameIsThePublishedOne() {
        AndroidKeystoreSecretStore(ctx).save(ByteArray(32))
        assertEquals(setOf("principal-ed25519"), created().values.keys)
    }

    @Test fun aFailedCommitRaisesSoTheKeyIsNeverReportedDurable() {
        val s = AndroidKeystoreSecretStore(ctx)
        created().commitResult = false
        val e = assertThrows(IllegalStateException::class.java) { s.save(ByteArray(32)) }
        assertEquals("Could not persist the principal key.", e.message)
    }

    @Test fun theContextConstructorKeepsTheKeyInTheAndroidStore() {
        val k = PrincipalDeviceKey(ctx)
        val pub = k.generate()
        assertEquals(setOf("principal-ed25519"), created().values.keys)
        assertEquals(pub, k.publicKey())
    }
}
