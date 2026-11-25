package net.atlasauth.pca.natives

import java.io.File
import java.io.IOException

/**
 * The native tools this jar carries under `natives/<os>-<arch>/`: the LESS library (`libatlas_less`, found by `LessNative` on its own) and the
 * reference WebAssembly host `pca-wasmtime-host` for `WasmSubprocess`. JVM only (not for Android): linux and macOS x64/arm64 and windows x64.
 */
object PackagedNatives {
    /** The extracted host binary and the SHA-256 (hex) it was built with, ready for `WasmSubprocess(host.binary, host.sha256)`. */
    class WasmtimeHost(@JvmField val binary: File, @JvmField val sha256: String)

    private fun platform(): String {
        val os = System.getProperty("os.name", "").lowercase()
        val arch = System.getProperty("os.arch", "").lowercase()
        val o = if (os.contains("win")) "windows" else if (os.contains("mac") || os.contains("darwin")) "macos" else "linux"
        val a = if (arch == "aarch64" || arch == "arm64") "arm64" else if (arch == "amd64" || arch == "x86_64") "x64" else arch
        return "$o-$a"
    }

    /** The packaged host for this platform, or null when this jar does not carry one. The pin is the jar's own, so the trust root is the jar you installed. */
    fun wasmtimeHost(): WasmtimeHost? {
        val exe = if (platform().startsWith("windows")) ".exe" else ""
        val base = "/natives/${platform()}/pca-wasmtime-host"
        return try {
            val bin = PackagedNatives::class.java.getResourceAsStream("$base$exe")?.use { it.readBytes() } ?: return null
            val sha = PackagedNatives::class.java.getResourceAsStream("$base.sha256")?.use { it.readBytes() }?.toString(Charsets.US_ASCII)?.trim() ?: return null
            val f = File.createTempFile("pca-wasmtime-host", exe)
            f.deleteOnExit()
            f.writeBytes(bin)
            if (!f.setExecutable(true, true)) return null
            WasmtimeHost(f, sha)
        } catch (e: IOException) {
            null
        }
    }
}
