package net.atlasauth.pca.natives

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PackagedNativesTest {
    private fun host(platform: String, files: Map<String, ByteArray>) = PackagedNatives.wasmtimeHost(platform) { files[it]?.let { b -> ByteArrayInputStream(b) } }

    private fun withProps(os: String, arch: String, body: () -> Unit) {
        val o = System.getProperty("os.name")
        val a = System.getProperty("os.arch")
        try {
            System.setProperty("os.name", os)
            System.setProperty("os.arch", arch)
            body()
        } finally {
            System.setProperty("os.name", o)
            System.setProperty("os.arch", a)
        }
    }

    @Test fun platformNamesTheOsAndArchitectureTheWayTheJarDoes() {
        withProps("Linux", "amd64") { assertEquals("linux-x64", PackagedNatives.platform()) }
        withProps("Linux", "x86_64") { assertEquals("linux-x64", PackagedNatives.platform()) }
        withProps("Linux", "aarch64") { assertEquals("linux-arm64", PackagedNatives.platform()) }
        withProps("Mac OS X", "arm64") { assertEquals("macos-arm64", PackagedNatives.platform()) }
        withProps("Mac OS X", "x86_64") { assertEquals("macos-x64", PackagedNatives.platform()) }
        withProps("Darwin", "amd64") { assertEquals("macos-x64", PackagedNatives.platform()) }
        withProps("Windows 11", "AMD64") { assertEquals("windows-x64", PackagedNatives.platform()) }
        withProps("FreeBSD", "riscv64") { assertEquals("linux-riscv64", PackagedNatives.platform()) }
    }

    @Test fun aPackagedHostIsExtractedExecutableWithItsOwnPin() {
        val bin = byteArrayOf(1, 2, 3, 4)
        val h = host("linux-x64", mapOf("/natives/linux-x64/pca-wasmtime-host" to bin, "/natives/linux-x64/pca-wasmtime-host.sha256" to "  abc123\n".toByteArray()))
        assertNotNull(h)
        assertEquals("abc123", h!!.sha256)
        assertArrayEquals(bin, h.binary.readBytes())
        assertTrue(h.binary.canExecute())
        assertTrue(h.binary.name.startsWith("pca-wasmtime-host"))
        assertTrue(!h.binary.name.endsWith(".exe"))
    }

    @Test fun windowsLooksForAnExeAndNamesTheFileSo() {
        val files = mapOf("/natives/windows-x64/pca-wasmtime-host.exe" to byteArrayOf(9), "/natives/windows-x64/pca-wasmtime-host.sha256" to "ff".toByteArray())
        val h = host("windows-x64", files)
        assertNotNull(h)
        assertTrue(h!!.binary.name.endsWith(".exe"))
        assertNull(host("windows-x64", mapOf("/natives/windows-x64/pca-wasmtime-host" to byteArrayOf(9), "/natives/windows-x64/pca-wasmtime-host.sha256" to "ff".toByteArray())))
        assertNull(host("linux-x64", files))
    }

    @Test fun aMissingBinaryOrPinIsNullNeverAHalfHost() {
        val bin = byteArrayOf(1)
        val sha = "aa".toByteArray()
        assertNull(host("linux-x64", emptyMap()))
        assertNull(host("linux-x64", mapOf("/natives/linux-x64/pca-wasmtime-host" to bin)))
        assertNull(host("linux-x64", mapOf("/natives/linux-x64/pca-wasmtime-host.sha256" to sha)))
        assertNull(host("macos-arm64", mapOf("/natives/linux-x64/pca-wasmtime-host" to bin, "/natives/linux-x64/pca-wasmtime-host.sha256" to sha)))
    }

    @Test fun anIoFailureReadingTheJarIsNull() {
        val broken = object : InputStream() { override fun read(): Int = throw IOException("jar entry unreadable") }
        assertNull(PackagedNatives.wasmtimeHost("linux-x64") { broken })
    }

    @Test fun aSourceBuildCarriesNoHost() {
        assertNull(PackagedNatives.wasmtimeHost())
    }
}
