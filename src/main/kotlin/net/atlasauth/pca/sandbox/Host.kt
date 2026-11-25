package net.atlasauth.pca.sandbox

/**
 * The WebAssembly host contract. The only import module a sandboxed tool may name, and the only functions in it; anything else is
 * ambient authority. Running a module (a WebAssembly engine, a worker, a wasmtime child process) is not part of this port: the JVM
 * carries no WebAssembly runtime, so the host, the component runner and the HTTP proxy server stay with the other SDKs.
 */
object Host {
    const val IMPORT_MODULE = "pca:act"

    @JvmField
    val ALLOWED_IMPORTS: List<String> = listOf("invoke", "handle_count", "handle_verb")
}
