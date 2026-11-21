// Compile-time stand-ins for the Android classes AndroidKeystoreSecretStore calls, so PIT (a plain JVM) can mutate that class.
// They hold values in memory: tests against them cover the store's own logic, never Android's Keystore or EncryptedSharedPreferences.
@file:Suppress("unused")
package android.content

open class Context { open val applicationContext: Context get() = this }

interface SharedPreferences {
    fun getString(key: String, defValue: String?): String?
    fun edit(): Editor
    interface Editor {
        fun putString(key: String, value: String?): Editor
        fun remove(key: String): Editor
        fun commit(): Boolean
    }
}
