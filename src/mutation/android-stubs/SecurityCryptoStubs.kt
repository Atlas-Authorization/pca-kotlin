// See AndroidStubs.kt: in-memory stand-ins, for the store's own logic only.
package androidx.security.crypto

import android.content.Context
import android.content.SharedPreferences

class MasterKey private constructor(val context: Context, val scheme: KeyScheme?) {
    enum class KeyScheme { AES256_GCM }
    class Builder(private val context: Context) {
        private var scheme: KeyScheme? = null
        fun setKeyScheme(s: KeyScheme): Builder { scheme = s; return this }
        fun build() = MasterKey(context, scheme)
    }
}

class EncryptedSharedPreferences private constructor() {
    enum class PrefKeyEncryptionScheme { AES256_SIV }
    enum class PrefValueEncryptionScheme { AES256_GCM }

    /** What the last create() received, and the map it returned, for a test to read. */
    class Created(
        val context: Context, val fileName: String, val masterKey: MasterKey,
        val keyScheme: PrefKeyEncryptionScheme, val valueScheme: PrefValueEncryptionScheme,
    ) : SharedPreferences {
        val values = HashMap<String, String?>()
        var commitResult = true
        var commits = 0
        override fun getString(key: String, defValue: String?) = if (key in values) values[key] else defValue
        override fun edit() = object : SharedPreferences.Editor {
            private val writes = ArrayList<() -> Unit>()
            override fun putString(key: String, value: String?) = apply { writes += { values[key] = value } }
            override fun remove(key: String) = apply { writes += { values.remove(key) } }
            override fun commit(): Boolean { commits++; if (commitResult) writes.forEach { it() }; return commitResult }
        }
    }

    companion object {
        @Volatile var last: Created? = null
        fun create(
            context: Context, fileName: String, masterKey: MasterKey,
            keyScheme: PrefKeyEncryptionScheme, valueScheme: PrefValueEncryptionScheme,
        ): SharedPreferences = Created(context, fileName, masterKey, keyScheme, valueScheme).also { last = it }
    }
}
