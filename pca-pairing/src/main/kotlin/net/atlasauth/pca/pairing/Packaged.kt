package net.atlasauth.pca.pairing

import java.io.File
import java.io.IOException

/** Finds a native library packaged in this jar at `natives/<os>-<arch>/<System.mapLibraryName(name)>` and extracts it to a temp file. */
internal object Packaged {
    private fun platform(): String {
        val os = System.getProperty("os.name", "").lowercase()
        val arch = System.getProperty("os.arch", "").lowercase()
        val o = if (os.contains("mac") || os.contains("darwin")) "macos" else if (os.contains("win")) "windows" else "linux" // "darwin" contains "win"
        val a = if (arch == "aarch64" || arch == "arm64") "arm64" else if (arch == "amd64" || arch == "x86_64") "x64" else arch
        return "$o-$a"
    }

    /** Absolute path of the extracted library, or null when this jar does not carry it for this platform. */
    fun extract(name: String): String? {
        val file = System.mapLibraryName(name)
        return try {
            Packaged::class.java.getResourceAsStream("/natives/${platform()}/$file")?.use { ins ->
                val f = File.createTempFile("pca-native", "-$file")
                f.deleteOnExit()
                f.outputStream().use { ins.copyTo(it) }
                f.path
            }
        } catch (e: IOException) {
            null // fall back to the configured or system library
        }
    }
}
