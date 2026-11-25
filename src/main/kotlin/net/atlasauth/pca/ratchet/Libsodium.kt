package net.atlasauth.pca.ratchet

import com.goterl.lazysodium.Sodium
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.utils.LibraryLoader
import java.math.BigInteger

/**
 * The one libsodium binding behind every ristretto255 / Ed25519 group operation in this library (vetted, constant-time; no group or field
 * arithmetic is written here). [S] exposes the ristretto255 and scalar natives (lazysodium 5.2.0); lazysodium has no binding for the plain
 * Ed25519 core / scalarmult calls, so [Ed] registers those few over the same libsodium.
 *
 * On Android (a real device or emulator: `Build.VERSION.SDK_INT > 0`) it is `SodiumAndroid` from lazysodium-android, whose AAR carries libsodium for
 * arm64-v8a, armeabi-v7a, x86 and x86_64; on the JVM (including Gradle host unit tests) it is `SodiumJava`, system library preferred, the jar's bundled one as fallback.
 */
internal object Libsodium {
    private val onAndroid: Boolean = try {
        Class.forName("android.os.Build\$VERSION").getField("SDK_INT").getInt(null) > 0
    } catch (_: Throwable) {
        false
    }

    @JvmField val S: Sodium =
        if (onAndroid) Class.forName("com.goterl.lazysodium.SodiumAndroid").getDeclaredConstructor().newInstance() as Sodium else SodiumJava()

    /** crypto_core_ed25519_* and crypto_scalarmult_ed25519_*; 0 means success except is_valid_point (1 = valid). */
    object Ed {
        @JvmStatic external fun crypto_core_ed25519_add(r: ByteArray, p: ByteArray, q: ByteArray): Int
        @JvmStatic external fun crypto_core_ed25519_sub(r: ByteArray, p: ByteArray, q: ByteArray): Int
        @JvmStatic external fun crypto_core_ed25519_is_valid_point(p: ByteArray): Int
        @JvmStatic external fun crypto_scalarmult_ed25519_noclamp(q: ByteArray, n: ByteArray, p: ByteArray): Int
        @JvmStatic external fun crypto_scalarmult_ed25519_base_noclamp(q: ByteArray, n: ByteArray): Int

        // a nested object does not trigger the outer object's initialiser: touch S (loads and sodium_init()s libsodium), then register
        init {
            check(S != null) { "libsodium not loaded" }
            if (onAndroid) com.sun.jna.Native.register(Ed::class.java, "sodium") // the AAR's libsodium.so, as SodiumAndroid does
            else LibraryLoader(listOf<Class<*>>(Ed::class.java)).loadLibrary(LibraryLoader.Mode.PREFER_SYSTEM, "sodium")
        }
    }

    /** Little-endian 32 bytes of a non-negative integer below 2^256. */
    fun le32(n: BigInteger): ByteArray {
        if (n.signum() < 0 || n.bitLength() > 256) throw IllegalArgumentException("scalar out of range")
        val out = ByteArray(32)
        for (i in 0 until 32) out[i] = n.shiftRight(8 * i).toInt().toByte()
        return out
    }

    fun fromLe(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
}
