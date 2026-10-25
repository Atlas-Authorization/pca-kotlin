package net.atlasauth.pca.verifier

import java.io.File
import java.lang.invoke.MethodHandle
import java.lang.reflect.Method
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Optional

/**
 * LESS (less-252-45, the `less-cat1` / `hybrid-ed25519-less-cat1` suites; a NIST additional-signature round-2 candidate, not a
 * standard) through the Foreign Function and Memory API to `libatlas_less`: the patched LESS reference C of the repository's
 * `sdks/pca-less-c`, built as a shared library (`sdks/pca-less-c/build.sh`).
 *
 * The API is final in Java 22 and absent on Android; it is reached reflectively, only on a Java 22+ runtime with 64-bit
 * addresses. The library is found at `ATLAS_PCA_LIBLESS` (or the system property `atlas.pca.libless`; one path, or several
 * separated by the path separator), else in `sdks/pca-less-c/build/` of the repository containing the working directory. It
 * counts only if it reports the less-252-45 sizes. Without a runtime, a library or native access, the LESS suites are not
 * registered and fail closed with `unsupported_suite`. Run with `--enable-native-access=ALL-UNNAMED` to keep the JDK's
 * restricted-method warning quiet. Never throws.
 */
object LessNative {
    const val PUBLIC_KEY_BYTES = 97484
    const val SIGNATURE_MIN_BYTES = 1153
    const val SIGNATURE_MAX_BYTES = 1329
    private const val SIGNATURE_STEP_BYTES = 16

    private class Ffm(
        val verify: MethodHandle,
        val arenaOfConfined: Method,
        val arenaAllocate: Method,
        val arenaClose: Method,
        val segOfArray: Method,
        val segCopyFrom: Method,
    )

    private val ffm: Ffm? = load()

    /** True iff a usable libatlas_less is loaded. */
    val available: Boolean get() = ffm != null

    /** `n` is a signature length the parameter set produces. */
    fun sigLenOk(n: Int): Boolean =
        n in SIGNATURE_MIN_BYTES..SIGNATURE_MAX_BYTES && (SIGNATURE_MAX_BYTES - n) % SIGNATURE_STEP_BYTES == 0

    /** Candidate library paths, in order. */
    internal fun candidates(): List<Path> {
        val out = ArrayList<Path>()
        val env = System.getenv("ATLAS_PCA_LIBLESS")?.takeIf { it.isNotEmpty() } ?: System.getProperty("atlas.pca.libless", "")
        env.split(File.pathSeparator).filter { it.isNotEmpty() }.forEach { out.add(Paths.get(it)) }
        var d: Path? = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath()
        while (d != null) {
            val build = d.resolve("sdks").resolve("pca-less-c").resolve("build")
            if (Files.isDirectory(build)) {
                listOf("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll").forEach { out.add(build.resolve(it)) }
                break
            }
            d = d.parent
        }
        return out
    }

    /**
     * The Java feature version from `java.specification.version` ("22"; "1.8" and Android's "0.9" give null), NOT
     * `Runtime.version()`, which the Android SDK does not have (the library variant would not compile).
     */
    private fun javaFeature(): Int? = System.getProperty("java.specification.version")?.toIntOrNull()

    private fun load(): Ffm? = try {
        if ((javaFeature() ?: 0) < 22) null else loadFfm()
    } catch (t: Throwable) {
        null // no FFM runtime: LESS is unsupported
    }

    private fun loadFfm(): Ffm? {
        val linkerC = Class.forName("java.lang.foreign.Linker")
        val arenaC = Class.forName("java.lang.foreign.Arena")
        val lookupC = Class.forName("java.lang.foreign.SymbolLookup")
        val layoutC = Class.forName("java.lang.foreign.MemoryLayout")
        val valueC = Class.forName("java.lang.foreign.ValueLayout")
        val descC = Class.forName("java.lang.foreign.FunctionDescriptor")
        val segC = Class.forName("java.lang.foreign.MemorySegment")
        val optC = Class.forName("java.lang.foreign.Linker\$Option")
        val address = valueC.getField("ADDRESS").get(null)
        if (layoutC.getMethod("byteSize").invoke(address) as Long != 8L) return null // size_t is bound as a 64-bit long
        val jLong = valueC.getField("JAVA_LONG").get(null)
        val jInt = valueC.getField("JAVA_INT").get(null)
        val linker = linkerC.getMethod("nativeLinker").invoke(null)
        val global = arenaC.getMethod("global").invoke(null)
        val descOf = descC.getMethod("of", layoutC, layoutC.arrayType())
        val sizeDesc = descOf.invoke(null, jLong, java.lang.reflect.Array.newInstance(layoutC, 0))
        val args = java.lang.reflect.Array.newInstance(layoutC, 6)
        for (i in 0 until 6) java.lang.reflect.Array.set(args, i, if (i % 2 == 0) address else jLong)
        val verifyDesc = descOf.invoke(null, jInt, args)
        val noOpts = java.lang.reflect.Array.newInstance(optC, 0)
        val downcall = linkerC.getMethod("downcallHandle", segC, descC, optC.arrayType())
        val find = lookupC.getMethod("find", String::class.java)
        val want = listOf(
            "atlas_less_cat1_public_key_bytes" to PUBLIC_KEY_BYTES.toLong(),
            "atlas_less_cat1_signature_min_bytes" to SIGNATURE_MIN_BYTES.toLong(),
            "atlas_less_cat1_signature_max_bytes" to SIGNATURE_MAX_BYTES.toLong(),
        )
        for (path in candidates()) {
            if (!Files.isRegularFile(path)) continue
            try {
                val lookup = lookupC.getMethod("libraryLookup", Path::class.java, arenaC).invoke(null, path, global)
                val sizesOk = want.all { (name, n) ->
                    val sym = find.invoke(lookup, name) as Optional<*>
                    sym.isPresent && (downcall.invoke(linker, sym.get(), sizeDesc, noOpts) as MethodHandle).invokeWithArguments() as Long == n
                }
                val v = find.invoke(lookup, "atlas_less_cat1_verify") as Optional<*>
                if (!sizesOk || !v.isPresent) continue
                return Ffm(
                    downcall.invoke(linker, v.get(), verifyDesc, noOpts) as MethodHandle,
                    arenaC.getMethod("ofConfined"),
                    arenaC.getMethod("allocate", Long::class.javaPrimitiveType),
                    arenaC.getMethod("close"),
                    segC.getMethod("ofArray", ByteArray::class.java),
                    segC.getMethod("copyFrom", segC),
                )
            } catch (e: ReflectiveOperationException) {
                // not this library: try the next one
            } catch (e: RuntimeException) {
                // no native access, or not this library: try the next one
            }
        }
        return null
    }

    /** The detached signature opens under `pk` and yields exactly `msg`. Never throws. */
    fun verify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val f = ffm ?: return false
        if (pk.size != PUBLIC_KEY_BYTES || !sigLenOk(sig.size)) return false
        return try {
            val arena = f.arenaOfConfined.invoke(null)
            try {
                val segs = listOf(pk, if (msg.isEmpty()) ByteArray(1) else msg, sig).map { b ->
                    f.arenaAllocate.invoke(arena, b.size.toLong()).also { f.segCopyFrom.invoke(it, f.segOfArray.invoke(null, b)) }
                }
                f.verify.invokeWithArguments(segs[0], pk.size.toLong(), segs[1], msg.size.toLong(), segs[2], sig.size.toLong()) as Int == 1
            } finally {
                f.arenaClose.invoke(arena)
            }
        } catch (t: Throwable) {
            false
        }
    }
}
