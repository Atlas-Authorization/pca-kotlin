package net.atlasauth.pca.verifier

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.4.2 mutation kills for LessNative.kt (port of the Java K042WbPcaMiscLessTest): the signature-length rule on both sides
 * of every bound, the library search path, the load itself (a Java 22+ runtime with a readable candidate library MUST load
 * it) and the FFM verify on the known answers of packages/pca/conformance/less-vectors.json. The native assertions run when
 * LessNative is available (the mutation job builds libatlas_less and exports ATLAS_PCA_LIBLESS); otherwise they skip, as
 * on a runtime without FFM.
 */
class K042LessNativeKillTest {
    private fun b64(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private val doc: Map<String, Any?> by lazy {
        var d: Path? = Paths.get("").toAbsolutePath()
        var p: Path? = null
        while (d != null && p == null) {
            val c = d.resolve("packages/pca/conformance/less-vectors.json")
            if (Files.isRegularFile(c)) p = c
            d = d.parent
        }
        @Suppress("UNCHECKED_CAST")
        Json.parseLenient(String(Files.readAllBytes(p ?: error("less-vectors.json not found")), Charsets.UTF_8)) as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private fun vector(name: String): Map<String, Any?> =
        (doc["vectors"] as List<Any?>).map { it as Map<String, Any?> }.first { it["name"] == name }

    @Suppress("UNCHECKED_CAST")
    private fun key(k: String, member: String): ByteArray =
        Pca.decodeB64uStrict(((doc["keys"] as Map<String, Any?>)[k] as Map<String, Any?>)[member], -1)!!

    private fun bytes(v: Map<String, Any?>, m: String): ByteArray = Pca.decodeB64uStrict(v[m], -1)!!

    @Test
    fun sigLenOkEveryBound() {
        assertEquals(97484, LessNative.PUBLIC_KEY_BYTES)
        assertEquals(1153, LessNative.SIGNATURE_MIN_BYTES)
        assertEquals(1329, LessNative.SIGNATURE_MAX_BYTES)
        val ok = (-20..1400).filter { LessNative.sigLenOk(it) }
        assertEquals((1153..1329 step 16).toList(), ok)
        assertEquals(12, ok.size)
        for (n in listOf(1152, 1330, 1345, 1137, 1328, 1154, 0, Int.MIN_VALUE, Int.MAX_VALUE)) assertFalse("$n", LessNative.sigLenOk(n))
        for (n in listOf(1153, 1313, 1329, 1281)) assertTrue("$n", LessNative.sigLenOk(n))
        assertTrue(Pq.Prim.LESS_CAT1.sigLenOk(1153))
        assertTrue(Pq.Prim.LESS_CAT1.sigLenOk(1281))
        assertFalse(Pq.Prim.LESS_CAT1.sigLenOk(1154))
        assertFalse(Pq.Prim.LESS_CAT1.sigLenOk(1330))
        assertTrue(Pq.Prim.ML_DSA_65.sigLenOk(3309))
        assertFalse(Pq.Prim.ML_DSA_65.sigLenOk(3310))
        assertFalse(Pq.Prim.ML_DSA_65.sigLenOk(1313))
    }

    private fun envEntries(): List<Path> {
        var env = System.getenv("ATLAS_PCA_LIBLESS")
        if (env.isNullOrEmpty()) env = System.getProperty("atlas.pca.libless", "")
        return env.split(File.pathSeparator).filter { it.isNotEmpty() }.map { Paths.get(it) }
    }

    private fun assertBuildTail(build: Path, got: List<Path>) {
        assertTrue(got.size >= 3)
        assertEquals(build.resolve("libatlas_less.so"), got[got.size - 3])
        assertEquals(build.resolve("libatlas_less.dylib"), got[got.size - 2])
        assertEquals(build.resolve("atlas_less.dll"), got[got.size - 1])
        assertTrue(got[got.size - 1].isAbsolute)
    }

    @Test
    fun candidatesAreEnvThenRepositoryBuild() {
        val want = ArrayList<Path>(envEntries())
        var build: Path? = null
        var d: Path? = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath()
        while (d != null && build == null) {
            val b = d.resolve("sdks").resolve("pca-less-c").resolve("build")
            if (Files.isDirectory(b)) build = b
            d = d.parent
        }
        if (build != null) for (n in listOf("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll")) want.add(build.resolve(n))
        val got = LessNative.candidates()
        assertEquals(want, got)
        if (build != null) assertBuildTail(build, got)
        val env = System.getenv("ATLAS_PCA_LIBLESS")
        if (!env.isNullOrEmpty() && !env.contains(File.pathSeparator)) assertEquals(Paths.get(env), got[0])
        assertNotSame(got, LessNative.candidates())
    }

    @Test
    fun candidatesSearchUpwardForTheNearestBuildDirectory() {
        val root = Files.createTempDirectory("k042-less").toAbsolutePath()
        val dir = System.getProperty("user.dir")
        try {
            val outer = Files.createDirectories(root.resolve("sdks").resolve("pca-less-c").resolve("build"))
            val mid = root.resolve("a")
            val inner = Files.createDirectories(mid.resolve("sdks").resolve("pca-less-c").resolve("build"))
            val cwd = Files.createDirectories(mid.resolve("b").resolve("c"))
            // a FILE sdks/pca-less-c/build nearer than both directories is not a build directory
            Files.createDirectories(cwd.resolve("sdks").resolve("pca-less-c"))
            Files.write(cwd.resolve("sdks").resolve("pca-less-c").resolve("build"), ByteArray(0))
            val envs = envEntries()
            System.setProperty("user.dir", cwd.toString())
            var got = LessNative.candidates()
            assertEquals(got.toString(), envs.size + 3, got.size)
            assertEquals(envs, got.subList(0, envs.size))
            assertBuildTail(inner, got)
            Files.delete(inner)
            got = LessNative.candidates()
            assertEquals(got.toString(), envs.size + 3, got.size)
            assertBuildTail(outer, got)
            Files.delete(outer)
            assertEquals(envs, LessNative.candidates())
        } finally {
            if (dir == null) System.clearProperty("user.dir") else System.setProperty("user.dir", dir)
            Files.walk(root).use { w -> w.sorted(Comparator.reverseOrder()).forEach { it.toFile().delete() } }
        }
    }

    @Test
    fun availableIffARuntimeAndALibrary() {
        val feature = System.getProperty("java.specification.version")?.toIntOrNull() ?: 0
        val lib = LessNative.candidates().any { Files.isRegularFile(it) }
        if (feature >= 22 && lib) assertTrue("a Java 22+ runtime with a candidate library must load LESS", LessNative.available)
        if (feature < 22) assertFalse(LessNative.available)
        assertEquals(LessNative.available, "less-cat1" in Pq.supportedSuites())
        assertEquals(LessNative.available, "hybrid-ed25519-less-cat1" in Pq.supportedSuites())
        assertEquals(LessNative.available, Pq.resolveSigAlg("less-cat1", true) != null)
        assertEquals(LessNative.available, Pq.resolveSigAlg("hybrid-ed25519-less-cat1", true) != null)
        assertEquals(if (LessNative.available) 12 else 10, Pq.supportedSuites().size)
        if (!LessNative.available) for (alg in listOf("less-cat1", "hybrid-ed25519-less-cat1")) {
            assertNull(alg, Pq.resolveSigAlg(alg, true))
            assertEquals("unsupported_suite: $alg", Pq.refusal(alg))
        }
    }

    @Test
    fun lessVerifyOneValidOneForged() {
        if (!LessNative.available) return
        val pk = key("main", "pq_pk")
        val valid = vector("less-cat1-valid")
        assertTrue(LessNative.verify(pk, bytes(valid, "message"), bytes(valid, "sig")))
        val forged = vector("less-cat1-flip-digest")
        assertFalse(LessNative.verify(pk, bytes(forged, "message"), bytes(forged, "sig")))
    }

    @Test
    fun lessVerifyKnownAnswers() {
        if (!LessNative.available) return
        val pk = key("main", "pq_pk")
        val other = key("other", "pq_pk")
        assertEquals(97484, pk.size)
        val valid = vector("less-cat1-valid")
        val msg = bytes(valid, "message")
        val sig = bytes(valid, "sig")
        assertEquals(1313, sig.size)
        assertTrue(LessNative.verify(pk, msg, sig))
        assertTrue("repeatable", LessNative.verify(pk, msg, sig))
        val v2 = vector("less-cat1-valid-other-key")
        assertTrue(LessNative.verify(other, bytes(v2, "message"), bytes(v2, "sig")))
        assertFalse(LessNative.verify(pk, bytes(v2, "message"), bytes(v2, "sig")))
        assertFalse(LessNative.verify(other, msg, sig))
        for (n in listOf("less-cat1-flip-digest", "less-cat1-flip-salt", "less-cat1-flip-seed", "less-cat1-padding-bit",
            "less-cat1-seed-count-up", "less-cat1-seed-count-max", "less-cat1-wrong-message", "less-cat1-drop-last-seed",
            "less-cat1-seed-padded-zero", "less-cat1-seed-padded-junk", "less-cat1-zero-min", "less-cat1-empty-message-forged",
            "less-cat1-truncated-one", "less-cat1-oversize")) {
            val v = vector(n)
            assertFalse(n, LessNative.verify(pk, bytes(v, "message"), bytes(v, "sig")))
        }
        val m2 = msg.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(LessNative.verify(pk, m2, sig))
        assertFalse(LessNative.verify(pk, msg.copyOf(msg.size - 1), sig))
        assertFalse(LessNative.verify(pk, msg.copyOf(msg.size + 1), sig))
        assertFalse(LessNative.verify(pk, ByteArray(0), sig))
        val s2 = sig.clone().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFalse(LessNative.verify(pk, msg, s2))
        val pk2 = pk.clone().also { it[100] = (it[100].toInt() xor 1).toByte() }
        assertFalse(LessNative.verify(pk2, msg, sig))
    }

    @Test
    fun lessVerifyRefusesEachBadArgumentWithoutThrowing() {
        val pk = if (LessNative.available) key("main", "pq_pk") else ByteArray(97484)
        val valid = vector("less-cat1-valid")
        val msg = bytes(valid, "message")
        val sig = bytes(valid, "sig")
        assertFalse(LessNative.verify(pk.copyOf(pk.size - 1), msg, sig))
        assertFalse(LessNative.verify(pk.copyOf(pk.size + 1), msg, sig))
        assertFalse(LessNative.verify(ByteArray(0), msg, sig))
        assertFalse(LessNative.verify(pk, msg, sig.copyOf(sig.size + 1)))
        assertFalse(LessNative.verify(pk, msg, sig.copyOf(sig.size + 16)))
        assertFalse(LessNative.verify(pk, msg, ByteArray(0)))
        if (!LessNative.available) assertFalse(LessNative.verify(pk, msg, sig))
    }

    @Test
    fun pqVerifyLessAndHybridThroughEveryEntryPoint() {
        if (!LessNative.available) return
        val pk = key("main", "pq_pk")
        val valid = vector("less-cat1-valid")
        val msg = bytes(valid, "message")
        val sig = bytes(valid, "sig")
        assertTrue(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg, sig))
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg.copyOf(3), sig))
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, key("other", "pq_pk"), msg, sig))
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg, sig.copyOf(sig.size - 1)))
        assertTrue(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig)))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig.copyOf(sig.size - 1))))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig.copyOf(sig.size + 1))))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk.copyOf(10)), msg, b64(sig)))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, null, msg, b64(sig)))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, null))
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig) + "="))
        @Suppress("UNCHECKED_CAST")
        val ed = ((doc["keys"] as Map<String, Any?>)["main"] as Map<String, Any?>)["ed_pub"] as String
        assertTrue(Pq.verifyArtifactSignature("less-cat1", ed, b64(pk), msg, b64(sig), null))
        val h = vector("hybrid-less-valid")
        assertTrue(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h["sig"], h["pq_sig"]))
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h["sig"], null))
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h["sig"], 7L))
        for (n in listOf("hybrid-less-bad-ed25519", "hybrid-less-bad-less")) {
            val b = vector(n)
            assertFalse(n, Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(b, "message"), b["sig"], b["pq_sig"]))
        }
    }
}
