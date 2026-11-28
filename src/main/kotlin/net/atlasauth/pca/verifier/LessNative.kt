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
 * separated by the path separator), else the copy shipped in the `pca-natives` jar when that is on the class path, else in `sdks/pca-less-c/build/` of the repository containing the working directory. It
 * counts only if it reports the less-252-45 sizes. Without a runtime, a library or native access, the LESS suites are not
 * registered and fail closed with `unsupported_suite`. Run with `--enable-native-access=ALL-UNNAMED` to keep the JDK's
 * restricted-method warning quiet. Never throws.
 */
object LessNative {
    const val PUBLIC_KEY_BYTES = 97484
    const val SIGNATURE_MIN_BYTES = 1153
    const val SIGNATURE_MAX_BYTES = 1329
    const val SIGNATURE_STEP_BYTES = 16

    /** The secret key is the 32-byte seed the public key is expanded from; keygen and sign take at least this many seed bytes. */
    const val SECRET_KEY_BYTES = 32
    const val SEED_BYTES = 32

    private class Ffm(
        val verify: MethodHandle,
        /** Null when the library predates the signing entry points. */
        val keygen: MethodHandle?,
        val sign: MethodHandle?,
        val byteLayout: Any,
        val segToArray: Method,
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
        packaged()?.let { out.add(it) } // after an explicit override, before the repository build
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

    /** The libatlas_less shipped in the `pca-natives` jar (`natives/<os>-<arch>/`), extracted to a temp file; null when no jar on the class path carries it. */
    private fun packaged(): Path? = try {
        val os = System.getProperty("os.name", "").lowercase()
        val arch = System.getProperty("os.arch", "").lowercase()
        val o = if (os.contains("mac") || os.contains("darwin")) "macos" else if (os.contains("win")) "windows" else "linux" // "darwin" contains "win"
        val a = if (arch == "aarch64" || arch == "arm64") "arm64" else if (arch == "amd64" || arch == "x86_64") "x64" else arch
        val file = System.mapLibraryName("atlas_less")
        LessNative::class.java.getResourceAsStream("/natives/$o-$a/$file")?.use { ins ->
            val f = File.createTempFile("pca-less", "-$file")
            f.deleteOnExit()
            f.outputStream().use { ins.copyTo(it) }
            f.toPath()
        }
    } catch (e: Exception) {
        null // no packaged copy: the configured paths and the repository build are tried next
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
        val verifyDesc = descOf.invoke(null, jInt, args) // (ptr, len, ptr, len, ptr, len) -> int: verify and keygen share the shape
        val signArgs = java.lang.reflect.Array.newInstance(layoutC, 9)
        for (i in 0 until 9) java.lang.reflect.Array.set(signArgs, i, if (i % 2 == 0) address else jLong)
        val signDesc = descOf.invoke(null, jInt, signArgs)
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
                val kg = find.invoke(lookup, "atlas_less_cat1_keygen") as Optional<*>
                val sg = find.invoke(lookup, "atlas_less_cat1_sign") as Optional<*>
                val canSign = kg.isPresent && sg.isPresent
                return Ffm(
                    downcall.invoke(linker, v.get(), verifyDesc, noOpts) as MethodHandle,
                    if (canSign) downcall.invoke(linker, kg.get(), verifyDesc, noOpts) as MethodHandle else null,
                    if (canSign) downcall.invoke(linker, sg.get(), signDesc, noOpts) as MethodHandle else null,
                    valueC.getField("JAVA_BYTE").get(null),
                    segC.getMethod("toArray", Class.forName("java.lang.foreign.ValueLayout\$OfByte")),
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

    /** True iff the loaded library carries the keygen and sign entry points. */
    val canSign: Boolean get() = ffm?.keygen != null && ffm.sign != null

    private fun segOf(f: Ffm, arena: Any?, b: ByteArray): Any? {
        val seg = f.arenaAllocate.invoke(arena, b.size.toLong())
        f.segCopyFrom.invoke(seg, f.segOfArray.invoke(null, b))
        return seg
    }

    private fun bytesOf(f: Ffm, seg: Any?, n: Int): ByteArray = (f.segToArray.invoke(seg, f.byteLayout) as ByteArray).copyOf(n)

    /**
     * Deterministic key pair from a seed of at least [SEED_BYTES]: (public key, secret key). Throws IllegalStateException when the
     * library (or its signing entry points) is unavailable or the call fails.
     */
    fun keygen(seed: ByteArray): Pair<ByteArray, ByteArray> {
        val f = ffm
        val kg = f?.keygen
        check(f != null && kg != null && f.sign != null) { "LESS signing is unavailable: libatlas_less with the keygen entry point is not loaded" }
        require(seed.size >= SEED_BYTES) { "a LESS seed is at least $SEED_BYTES bytes" }
        try {
            val arena = f.arenaOfConfined.invoke(null)
            try {
                val pk = f.arenaAllocate.invoke(arena, PUBLIC_KEY_BYTES.toLong())
                val sk = f.arenaAllocate.invoke(arena, SECRET_KEY_BYTES.toLong())
                val sd = segOf(f, arena, seed)
                val rc = kg.invokeWithArguments(pk, PUBLIC_KEY_BYTES.toLong(), sk, SECRET_KEY_BYTES.toLong(), sd, seed.size.toLong()) as Int
                check(rc == 1) { "LESS keygen failed" }
                return Pair(bytesOf(f, pk, PUBLIC_KEY_BYTES), bytesOf(f, sk, SECRET_KEY_BYTES))
            } finally {
                f.arenaClose.invoke(arena)
            }
        } catch (e: IllegalStateException) {
            throw e
        } catch (t: Throwable) {
            throw IllegalStateException("LESS keygen failed", t)
        }
    }

    /** Detached signature (1153..1329 bytes) of [msg] under [sk], the signing RNG seeded from [seed] (at least [SEED_BYTES] bytes). */
    fun sign(sk: ByteArray, msg: ByteArray, seed: ByteArray): ByteArray {
        val f = ffm
        val sg = f?.sign
        check(f != null && sg != null && f.keygen != null) { "LESS signing is unavailable: libatlas_less with the sign entry point is not loaded" }
        require(sk.size == SECRET_KEY_BYTES) { "a LESS secret key is $SECRET_KEY_BYTES bytes" }
        require(seed.size >= SEED_BYTES) { "a LESS seed is at least $SEED_BYTES bytes" }
        try {
            val arena = f.arenaOfConfined.invoke(null)
            try {
                val skS = segOf(f, arena, sk)
                val msS = segOf(f, arena, if (msg.isEmpty()) ByteArray(1) else msg)
                val sdS = segOf(f, arena, seed)
                val sigS = f.arenaAllocate.invoke(arena, SIGNATURE_MAX_BYTES.toLong())
                val lenS = f.arenaAllocate.invoke(arena, 8L)
                val rc = sg.invokeWithArguments(skS, sk.size.toLong(), msS, msg.size.toLong(), sdS, seed.size.toLong(), sigS, SIGNATURE_MAX_BYTES.toLong(), lenS) as Int
                check(rc == 1) { "LESS sign failed" }
                val n = java.nio.ByteBuffer.wrap(bytesOf(f, lenS, 8)).order(java.nio.ByteOrder.nativeOrder()).getLong()
                check(n in SIGNATURE_MIN_BYTES.toLong()..SIGNATURE_MAX_BYTES.toLong() && sigLenOk(n.toInt())) { "LESS sign returned a wrong-length signature" }
                return bytesOf(f, sigS, n.toInt())
            } finally {
                f.arenaClose.invoke(arena)
            }
        } catch (e: IllegalStateException) {
            throw e
        } catch (t: Throwable) {
            throw IllegalStateException("LESS sign failed", t)
        }
    }
}
