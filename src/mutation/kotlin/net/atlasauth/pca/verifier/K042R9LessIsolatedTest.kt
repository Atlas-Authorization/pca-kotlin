package net.atlasauth.pca.verifier

import java.io.File
import java.lang.reflect.Field
import java.net.URL
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * r9 mutation kills for LessNative.kt that need a LessNative the process environment cannot reach: a fresh copy of the object
 * (its own static initialiser) is loaded by a child-first loader while ATLAS_PCA_LIBLESS, atlas.pca.libless and user.dir are
 * set to the case under test. The mutation agent rewrites every loader's copy of the class, so these assertions bind the
 * mutants; the in-process env override is the JDK's own String-keyed environment map, reached with Unsafe (no --add-opens).
 */
class K042R9LessIsolatedTest {
    companion object {
        init { LessNative.available } // initialise the real object under the real environment before any case changes it

        @JvmField var closed = 0
        @JvmStatic fun countClose() { closed++ }

        @Suppress("UNCHECKED_CAST")
        fun envMap(): MutableMap<String, String>? = try {
            val uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe")
            uf.isAccessible = true
            val u = uf.get(null)
            val uc = u.javaClass
            val f = Class.forName("java.lang.ProcessEnvironment").getDeclaredField("theUnmodifiableEnvironment")
            val base = uc.getMethod("staticFieldBase", Field::class.java).invoke(u, f)
            val off = uc.getMethod("staticFieldOffset", Field::class.java).invoke(u, f) as Long
            val unm = uc.getMethod("getObject", Any::class.java, Long::class.javaPrimitiveType).invoke(u, base, off)
            val mf = Class.forName("java.util.Collections\$UnmodifiableMap").getDeclaredField("m")
            val moff = uc.getMethod("objectFieldOffset", Field::class.java).invoke(u, mf) as Long
            uc.getMethod("getObject", Any::class.java, Long::class.javaPrimitiveType).invoke(u, unm, moff) as MutableMap<String, String>
        } catch (t: Throwable) {
            null
        }

        /** Windows only: System.getenv(name) reads ProcessEnvironment.theCaseInsensitiveEnvironment, a separate table. */
        @Suppress("UNCHECKED_CAST")
        fun caseInsensitiveEnv(): MutableMap<String, String>? = try {
            val uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe")
            uf.isAccessible = true
            val u = uf.get(null)
            val uc = u.javaClass
            val f = Class.forName("java.lang.ProcessEnvironment").getDeclaredField("theCaseInsensitiveEnvironment")
            val base = uc.getMethod("staticFieldBase", Field::class.java).invoke(u, f)
            val off = uc.getMethod("staticFieldOffset", Field::class.java).invoke(u, f) as Long
            uc.getMethod("getObject", Any::class.java, Long::class.javaPrimitiveType).invoke(u, base, off) as MutableMap<String, String>
        } catch (t: Throwable) {
            null // not Windows: the field does not exist
        }

        fun setEnv(m: MutableMap<String, String>, ci: MutableMap<String, String>?, v: String?) {
            for (t in listOfNotNull(m, ci)) if (v == null) t.remove("ATLAS_PCA_LIBLESS") else t["ATLAS_PCA_LIBLESS"] = v
        }

        fun rmTree(p: Path) {
            Files.walk(p).use { w -> w.sorted(Comparator.reverseOrder()).forEach { it.toFile().delete() } }
        }

        /** Runs [body] with the three inputs of LessNative.candidates() under control; restores them afterwards. */
        fun withInputs(env: String?, prop: String?, cwd: Path?, body: (Path) -> Unit) {
            val m = envMap()
            assumeTrue("the process environment is not reachable on this runtime", m != null)
            m!!
            val ci = caseInsensitiveEnv()
            val oldEnv = System.getenv("ATLAS_PCA_LIBLESS")
            val oldProp = System.getProperty("atlas.pca.libless")
            val oldDir = System.getProperty("user.dir")
            val tmp = Files.createTempDirectory("k042r9").toAbsolutePath()
            try {
                setEnv(m, ci, env)
                if (prop == null) System.clearProperty("atlas.pca.libless") else System.setProperty("atlas.pca.libless", prop)
                System.setProperty("user.dir", (cwd ?: tmp).toString())
                body(tmp)
            } finally {
                setEnv(m, ci, oldEnv)
                if (oldProp == null) System.clearProperty("atlas.pca.libless") else System.setProperty("atlas.pca.libless", oldProp)
                if (oldDir == null) System.clearProperty("user.dir") else System.setProperty("user.dir", oldDir)
                rmTree(tmp)
            }
        }
    }

    // ---- a private copy of LessNative ----
    private class Iso(root: URL) : URLClassLoader(arrayOf(root), K042R9LessIsolatedTest::class.java.classLoader) {
        private val own = "net.atlasauth.pca.verifier.LessNative"
        override fun loadClass(name: String, resolve: Boolean): Class<*> {
            if (name != own && !name.startsWith("$own\$")) return super.loadClass(name, resolve)
            synchronized(getClassLoadingLock(name)) {
                val c = findLoadedClass(name) ?: findClass(name)
                if (resolve) resolveClass(c)
                return c
            }
        }
    }

    /** A fresh LessNative object. */
    private class Fresh(val cls: Class<*>) {
        val inst: Any = cls.getField("INSTANCE").get(null)
        fun available(): Boolean = cls.getMethod("getAvailable").invoke(inst) as Boolean
        fun verify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean =
            cls.getMethod("verify", ByteArray::class.java, ByteArray::class.java, ByteArray::class.java).invoke(inst, pk, msg, sig) as Boolean
        fun ffm(): Any? = cls.getDeclaredField("ffm").also { it.isAccessible = true }.get(null)
    }

    private fun fresh(): Fresh {
        val root = LessNative::class.java.protectionDomain.codeSource.location
        return Fresh(Iso(root).loadClass("net.atlasauth.pca.verifier.LessNative"))
    }

    private fun library(): Path? = LessNative.candidates().firstOrNull { Files.isRegularFile(it) }

    private fun feature(): Int = System.getProperty("java.specification.version")?.toIntOrNull() ?: 0

    // ---- candidates(): environment, property fallback, upward search ----
    @Test
    fun environmentThenPropertyThenBuildDirectory() {
        val a = File("one.so").absolutePath
        val b = File("two.so").absolutePath
        val sep = File.pathSeparator
        withInputs(null, a + sep + sep + b, null) { assertEquals("unset: the property", listOf(Paths.get(a), Paths.get(b)), LessNative.candidates()) }
        withInputs("", a, null) { assertEquals("empty: the property", listOf(Paths.get(a)), LessNative.candidates()) }
        withInputs(b, a, null) { assertEquals("set: the variable wins", listOf(Paths.get(b)), LessNative.candidates()) }
        withInputs(null, null, null) { assertEquals("nothing configured, no build directory above", emptyList<Path>(), LessNative.candidates()) }
        withInputs("", "", null) { assertEquals("both empty", emptyList<Path>(), LessNative.candidates()) }
        withInputs(sep, null, null) { assertEquals("separators only", emptyList<Path>(), LessNative.candidates()) }
    }

    @Test
    fun aRelativeUserDirIsMadeAbsoluteBeforeTheUpwardSearch() {
        val here = Paths.get("").toAbsolutePath()
        val root = Files.createTempDirectory(here, "k042r9rel")
        try {
            val build = Files.createDirectories(root.resolve("sdks").resolve("pca-less-c").resolve("build"))
            Files.createDirectories(root.resolve("a").resolve("b"))
            val rel = here.relativize(root.resolve("a").resolve("b"))
            withInputs(null, null, rel) {
                val got = LessNative.candidates()
                assertEquals(listOf(build.resolve("libatlas_less.so"), build.resolve("libatlas_less.dylib"), build.resolve("atlas_less.dll")), got)
                assertTrue(got[0].isAbsolute)
            }
        } finally {
            rmTree(root)
        }
    }

    // ---- the load ----
    @Test
    fun availableOnlyWithAReadableLibrary() {
        val lib = library()
        withInputs(null, null, null) {
            val f = fresh()
            assertEquals("no candidate: LESS is unavailable", false, f.available())
            assertEquals("unavailable: refuse", false, f.verify(ByteArray(LessNative.PUBLIC_KEY_BYTES), ByteArray(4), ByteArray(LessNative.SIGNATURE_MIN_BYTES)))
        }
        assumeTrue("no library / no FFM here", lib != null && feature() >= 22)
        lib!!
        withInputs(lib.toString(), null, null) { assertEquals(true, fresh().available()) }
        withInputs(null, lib.toString(), null) { assertEquals(true, fresh().available()) }
        withInputs(lib.resolveSibling("no-such-library.so").toString(), null, null) { assertEquals("a path that is not a library", false, fresh().available()) }
    }

    // ---- verify(): failures inside the native call refuse, and the arena is always closed ----
    @Test
    fun anInternalFailureRefusesAndTheArenaIsClosed() {
        val lib = library()
        assumeTrue("no library / no FFM here", lib != null && feature() >= 22)
        withInputs(lib!!.toString(), null, null) {
            val f = fresh()
            val ffm = f.ffm()
            assertNotNull(ffm)
            ffm!!
            val pk = ByteArray(LessNative.PUBLIC_KEY_BYTES)
            val sig = ByteArray(LessNative.SIGNATURE_MIN_BYTES)
            val msg = byteArrayOf(1, 2, 3)
            assertEquals("a zero key does not verify", false, f.verify(pk, msg, sig))
            val close = ffm.javaClass.getDeclaredField("arenaClose").also { it.isAccessible = true }
            val alloc = ffm.javaClass.getDeclaredField("arenaAllocate").also { it.isAccessible = true }
            val realClose = close.get(ffm)
            val realAlloc = alloc.get(ffm)
            // the arena allocation throws: the call refuses (it must not answer true) and still closes the arena
            close.set(ffm, K042R9LessIsolatedTest::class.java.getMethod("countClose"))
            alloc.set(ffm, String::class.java.getMethod("length"))
            closed = 0
            assertEquals("an internal failure is a refusal", false, f.verify(pk, msg, sig))
            assertEquals("the arena is closed on the failure path", 1, closed)
            alloc.set(ffm, realAlloc)
            closed = 0
            assertEquals(false, f.verify(pk, msg, sig))
            assertEquals("the arena is closed on the normal path", 1, closed)
            close.set(ffm, realClose)
        }
    }

    // ---- a real signature through the fresh copy's FFM path: every Ffm member is on the path ----
    @Suppress("UNCHECKED_CAST")
    private fun vectors(): Map<String, Any?> {
        var d: Path? = Paths.get("").toAbsolutePath()
        while (d != null) {
            val c = d.resolve("packages/pca/conformance/less-vectors.json")
            if (Files.isRegularFile(c)) return Json.parseLenient(String(Files.readAllBytes(c), Charsets.UTF_8)) as Map<String, Any?>
            d = d.parent
        }
        error("less-vectors.json not found")
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun aValidSignatureVerifiesThroughTheFreshCopyAndAForgedOneDoesNot() {
        val lib = library()
        assumeTrue("no library / no FFM here", lib != null && feature() >= 22)
        val doc = vectors()
        fun vec(n: String) = (doc["vectors"] as List<Any?>).map { it as Map<String, Any?> }.first { it["name"] == n }
        fun b(v: Map<String, Any?>, m: String) = Pca.decodeB64uStrict(v[m], -1)!!
        val pk = Pca.decodeB64uStrict((((doc["keys"] as Map<String, Any?>)["main"]) as Map<String, Any?>)["pq_pk"], -1)!!
        val valid = vec("less-cat1-valid")
        val forged = vec("less-cat1-flip-digest")
        withInputs(lib!!.toString(), null, null) {
            val f = fresh()
            assertEquals(true, f.available())
            assertEquals("a valid LESS signature verifies; a null Ffm member would fail it", true, f.verify(pk, b(valid, "message"), b(valid, "sig")))
            assertEquals(true, f.verify(pk, b(valid, "message"), b(valid, "sig")))
            assertEquals(false, f.verify(pk, b(forged, "message"), b(forged, "sig")))
        }
    }
}
