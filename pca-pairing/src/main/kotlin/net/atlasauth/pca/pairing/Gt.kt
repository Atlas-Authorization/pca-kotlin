package net.atlasauth.pca.pairing

import java.math.BigInteger
import supranational.blst.P1
import supranational.blst.P2

/**
 * The pairing target group GT of BLS12-381, through a small JNI shim over blst (src/main/c/pca_gt.c, the same C sources as the
 * Java binding): canonical 576-byte parsing, multiplication, constant-time exponentiation and multi-pairing with one final
 * exponentiation. jblst's `PT` offers neither parsing nor exponentiation.
 *
 * An element is its 576-byte encoding (12 Fp coordinates in tower order, 48 bytes big-endian each), the same bytes as the
 * TypeScript reference. The native library ships in this module's jar (`natives/<os>-<arch>/`, extracted to a temp file on first use;
 * linux and macOS x64/arm64, windows x64), unless `-Dpca.gt.lib=/path/to/libpcagt.so` names one, else `pcagt` on `java.library.path`; a
 * missing library is a [LinkageError], never a "bad input" result. Not available on Android (JVM-only module).
 */
object Gt {
    /** Byte length of an encoded GT element. */
    const val BYTES = 576

    init {
        val lib = System.getProperty("pca.gt.lib")
        if (!lib.isNullOrEmpty()) System.load(lib) else (Packaged.extract("pcagt")?.let { System.load(it) } ?: System.loadLibrary("pcagt"))
    }

    // static natives on net.atlasauth.pca.pairing.Gt: the JNI symbols are Java_net_atlasauth_pca_pairing_Gt_<name>
    @JvmStatic private external fun mul0(a: ByteArray, b: ByteArray): ByteArray?

    @JvmStatic private external fun pow0(a: ByteArray, k: ByteArray): ByteArray?

    @JvmStatic private external fun isElement0(a: ByteArray): Boolean

    @JvmStatic private external fun pairing0(g1s: ByteArray, g2s: ByteArray, n: Int): ByteArray?

    /** a * b; throws on a non-canonical operand. */
    fun mul(a: ByteArray, b: ByteArray): ByteArray =
        mul0(a, b) ?: throw IllegalArgumentException("not a canonical GT encoding")

    /** a^(k mod r); throws on a non-canonical operand. */
    fun pow(a: ByteArray, k: BigInteger): ByteArray =
        pow0(a, Bls12.i2osp(Bls12.mod(k), 32)) ?: throw IllegalArgumentException("not a canonical GT encoding")

    /** True iff the bytes canonically encode an element of the order-r subgroup other than the identity. */
    fun isElement(a: ByteArray?): Boolean = a != null && a.size == BYTES && isElement0(a)

    /** e(p, q). Throws on an identity point. */
    fun pairing(p: P1, q: P2): ByteArray = pairingProduct(listOf(p), listOf(q))

    /** prod e(g1[i], g2[i]) with one shared final exponentiation. Throws on an identity point. */
    fun pairingProduct(g1: List<P1>, g2: List<P2>): ByteArray {
        val n = g1.size
        if (n == 0 || n != g2.size) throw IllegalArgumentException("pairing product needs equal, non-empty point lists")
        val a = ByteArray(48 * n)
        val b = ByteArray(96 * n)
        for (i in 0 until n) {
            if (g1[i].is_inf() || g2[i].is_inf()) throw IllegalArgumentException("pairing is not defined for the identity")
            System.arraycopy(g1[i].compress(), 0, a, 48 * i, 48)
            System.arraycopy(g2[i].compress(), 0, b, 96 * i, 96)
        }
        return pairing0(a, b, n) ?: throw IllegalArgumentException("invalid pairing input")
    }
}
