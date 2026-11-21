package net.atlasauth.pca.zk

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Zk

/**
 * Kotlin face of the Groth16 primitive for [Zk]: verification and proving of snarkjs artifacts on BN254 and BLS12-381 through the Java
 * adapter ([NativeZk], JNA over libpcazk; `ATLAS_PCA_LIBPCAZK` or `-Dpca.zk.lib`, else the copy packaged in the adapter jar). No pairing or
 * field arithmetic is implemented here. [register] installs it as the engine of the core [Zk]; nothing registers at load. A library that
 * cannot be loaded raises [Zk.ZkBackendMissing]: it is never a verdict about a proof. A fault of the pairing check inside a loaded library is a
 * refusal, as it is in the reference (snarkjs runs inside a try block there).
 */
@Suppress("UNCHECKED_CAST")
object ZkNative {
    /** True when libpcazk can be loaded. */
    fun available(): Boolean = NativeZk.available()

    /** The version string of the loaded library; throws [Zk.ZkBackendMissing] when it cannot be loaded. */
    fun version(): String = try {
        NativeZk.version()
    } catch (e: IllegalStateException) {
        throw Zk.ZkBackendMissing(e.message ?: "zk native library unavailable")
    }

    /** Install the native engine in the core [Zk] (throws [Zk.ZkBackendMissing] when the library cannot be loaded). */
    fun register(): Zk.Groth16Engine {
        version()
        Zk.registerGroth16(Engine)
        return Engine
    }

    /** Remove the registration: the core refuses to answer the pairing question again. */
    fun unregister() = Zk.unregisterGroth16()

    private fun json(v: Any?): ByteArray = Json.canonicalize(v).toByteArray(Charsets.UTF_8)

    /** pca_zk.h PCA_ZK_CURVE_FROM_KEY: the library reads the key's own curve name as snarkjs does (valid with the snarkjs-compat flag only). */
    private const val CURVE_FROM_KEY = 2

    /** The explicit curve of a protocol name (`bn128` / `bls12381`): the strict mode and proving; the compat verify leaves the name to the library. */
    private fun curveOf(name: Any?): Int = when (name) {
        "bn128" -> NativeZk.CURVE_BN254
        "bls12381" -> NativeZk.CURVE_BLS12_381
        else -> -1
    }

    /**
     * The Groth16 pairing check of a snarkjs proof under a snarkjs verification key (the curve is the key's `curve` member). By default
     * with the acceptance rules of snarkjs; `strict` also checks the key's protocol tag and nPublic and wants exactly one IC entry per
     * signal plus one. False for an invalid or malformed input.
     */
    @JvmOverloads
    fun verify(vkey: Any?, publicSignals: List<Any?>, proof: Any?, strict: Boolean = false): Boolean {
        version() // a missing library is never a verdict
        // snarkjs picks the curve from the key's name itself (aliases such as "BN254" or "alt_bn128" included): the library does the same
        val curve = if (strict) curveOf((vkey as? Map<*, *>)?.get("curve")) else CURVE_FROM_KEY
        if (curve < 0) return false
        val bytes = try {
            Triple(json(vkey), json(proof), json(publicSignals))
        } catch (e: RuntimeException) {
            return false // not JSON values: no key or proof
        }
        return try {
            NativeZk.verify(curve, !strict, bytes.first, bytes.second, bytes.third)
        } catch (e: IllegalStateException) {
            false // the library loaded (checked above) but refused to decide on this input: a refusal, as snarkjs inside the reference's try block
        }
    }

    private object Engine : Zk.Groth16Engine {
        override fun verify(vkey: Any?, publicSignals: List<Any?>, proof: Any?): Boolean = ZkNative.verify(vkey, publicSignals, proof, false)

        override fun prove(curve: String, wasm: ByteArray, zkey: ByteArray, input: Map<String, String>): Map<String, Any?> {
            val c = curveOf(curve)
            require(c >= 0) { "zk: unknown curve '$curve'" }
            val text = try {
                NativeZk.prove(c, wasm, zkey, json(input), null)
            } catch (e: net.atlasauth.pca.Zk.BackendMissing) {
                throw Zk.ZkBackendMissing(e.message ?: "zk native library unavailable")
            }
            return Json.parseLenient(text) as Map<String, Any?>
        }
    }
}
