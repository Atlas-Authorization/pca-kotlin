package net.atlasauth.pca.verifier

/**
 * The provenance harness every authorize test presents (mirrors the reference harness): a recorder under the pinned key
 * (Ed25519 seed = 32 bytes of 0x01, mediator `conformance-harness`, kid `k1`) records the operation principal-direct, and the
 * verifier pins that key. The gate stays on; it passes because the bundle is genuine, never because it is switched off.
 */
object ProvHarness {
    const val MEDIATOR = "conformance-harness"
    const val KID = "k1"
    private val SEED = ByteArray(32) { 1 }

    /** A fresh recorder under the harness key (fixed session and clock, so a bundle is reproducible). */
    fun recorder(): ArgProvenance.Recorder = ArgProvenance.Recorder(MEDIATOR, KID, Keys.ed25519(Keys.edFromSeed(SEED)), Pca.b64(ByteArray(32) { 2 }), { 1_700_000_000_000L })

    val pin: Map<String, Any?> by lazy { recorder().pin }

    val options: Authorize.ProvenanceOptions by lazy { Authorize.ProvenanceOptions(listOf(pin)) }

    /** The principal-direct bundle for `op`; null for no operation or one outside the JSON model (the test then exercises that refusal). */
    fun bundle(op: Authorize.Operation?): Map<String, Any?>? =
        if (op == null) null else try { ArgProvenance.principalDirect(recorder(), op) } catch (e: RuntimeException) { null }

    /** The `PCA-Provenance` header for `op`. */
    fun header(op: Authorize.Operation): String = ArgProvenance.headerOf(bundle(op)!!)
}
