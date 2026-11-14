package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Kill tests for Keys (k05 small group): every refusal message, the defensive copies and every primitive's key / sign path. */
class Kill05SmallKeysTest {
    private fun iae(f: () -> Any?): String? = assertThrows(IllegalArgumentException::class.java) { f() }.message

    @Test fun unb64u() {
        assertArrayEquals(byteArrayOf(0, 0, 0), Keys.unb64u("AAAA"))
        assertEquals("not canonical base64url", iae { Keys.unb64u("A") })
    }

    @Test fun edKeysCopyTheirSeed() {
        assertEquals("an Ed25519 seed is 32 bytes", iae { Keys.edFromSeed(ByteArray(31)) })
        val seed = ByteArray(32) { 7 }
        val k = Keys.edFromSeed(seed)
        val pub = k.pub.clone()
        seed.fill(0)
        assertArrayEquals(ByteArray(32) { 7 }, k.seed)
        assertArrayEquals(pub, Keys.edFromSeed(ByteArray(32) { 7 }).pub)
        assertEquals(32, Keys.edGenerate().pub.size)
    }

    @Test fun seedRandomReplaysThenRefuses() {
        val r = Keys.SeedRandom(byteArrayOf(1, 2, 3))
        val a = ByteArray(2)
        r.nextBytes(a)
        assertArrayEquals(byteArrayOf(1, 2), a)
        val b = ByteArray(1)
        r.nextBytes(b)
        assertArrayEquals(byteArrayOf(3), b)
        val e = assertThrows(IllegalStateException::class.java) { r.nextBytes(ByteArray(1)) }
        assertEquals("seed exhausted", e.message)
    }

    @Test fun pqSeedLengths() {
        assertEquals(Pq.Prim.SLH_DSA_SHA2_128F.pkBytes, Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, ByteArray(48)).pk.size)
        assertEquals("${Pq.Prim.SLH_DSA_SHA2_128F} needs a 48-byte seed", iae { Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, ByteArray(49)) })
        assertEquals("${Pq.Prim.SLH_DSA_SHA2_256S} needs a 96-byte seed", iae { Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, ByteArray(97)) })
        assertEquals("${Pq.Prim.ML_DSA_65} needs a 32-byte seed", iae { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(48)) })
        assertEquals(Pq.Prim.ML_DSA_65.pkBytes, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32)).pk.size)
    }

    @Test fun slhDsa256sKeyAndSignature() {
        val k = Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, ByteArray(96) { it.toByte() })
        assertEquals(Pq.Prim.SLH_DSA_SHA2_256S.pkBytes, k.pk.size)
        assertEquals(Pq.Prim.SLH_DSA_SHA2_256S.sigBytes, k.sign(byteArrayOf(1)).size)
    }

    @Test fun unsupportedPrimitives() {
        val less = Keys.pqLoad(Pq.Prim.LESS_CAT1, ByteArray(Pq.Prim.LESS_CAT1.pkBytes), ByteArray(0))
        assertEquals("cannot sign with ${Pq.Prim.LESS_CAT1} in this SDK", iae { less.sign(byteArrayOf(1)) })
        assertEquals("cannot generate ${Pq.Prim.LESS_CAT1} keys in this SDK", iae { Keys.pqGenerate(Pq.Prim.LESS_CAT1) })
        assertEquals(Pq.Prim.ML_DSA_65.pkBytes, Keys.pqGenerate(Pq.Prim.ML_DSA_65).pk.size)
    }

    @Test fun pqLoadChecksAndCopies() {
        assertEquals("wrong public key length for ${Pq.Prim.SLH_DSA_SHA2_128F}", iae { Keys.pqLoad(Pq.Prim.SLH_DSA_SHA2_128F, ByteArray(31), ByteArray(64)) })
        assertEquals("wrong public key length for ${Pq.Prim.SLH_DSA_SHA2_128F}", iae { Keys.pqLoad(Pq.Prim.SLH_DSA_SHA2_128F, ByteArray(33), ByteArray(64)) })
        val pk = ByteArray(32) { 1 }
        val sk = ByteArray(64) { 2 }
        val k = Keys.pqLoad(Pq.Prim.SLH_DSA_SHA2_128F, pk, sk)
        pk.fill(0)
        sk.fill(0)
        assertSame(Pq.Prim.SLH_DSA_SHA2_128F, k.prim)
        assertArrayEquals(ByteArray(32) { 1 }, k.pk)
        assertArrayEquals(ByteArray(64) { 2 }, k.sk)
    }

    @Test fun suiteRefusalsAndAccessors() {
        val ed = Keys.edFromSeed(ByteArray(32) { 3 })
        val ml65 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 4 })
        val ml87 = Keys.pqFromSeed(Pq.Prim.ML_DSA_87, ByteArray(32) { 5 })
        assertEquals(Pq.refusal("bogus"), iae { Keys.suite("bogus", ed, null) })
        assertEquals("'ed25519' requires an Ed25519 key", iae { Keys.suite("ed25519", null, null) })
        assertEquals("'hybrid-ed25519-ml-dsa-65' requires a ${Pq.Prim.ML_DSA_65} key", iae { Keys.suite("hybrid-ed25519-ml-dsa-65", ed, null) })
        assertEquals("'ml-dsa-65' needs a ${Pq.Prim.ML_DSA_65} key, got ${Pq.Prim.ML_DSA_87}", iae { Keys.suite("ml-dsa-65", null, ml87) })

        val pure = Keys.suite("ml-dsa-65", null, ml65)
        assertNull(pure.id())
        assertSame(ml65, pure.pq)
        assertEquals(LinkedHashMap<String, Any?>(), Keys.pqPin(pure))
        val hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", ed, ml65)
        assertEquals(ed.id(), hybrid.id())
        assertEquals(linkedMapOf<String, Any?>(ed.id() to ml65.pkB64u()), Keys.pqPin(hybrid))
        assertEquals(LinkedHashMap<String, Any?>(), Keys.pqPin(Keys.ed25519(ed)))
    }

    @Test fun lessCannotBeSigned() {
        assumeTrue("LESS suites resolve only with the native library", LessNative.available)
        val less = Keys.pqLoad(Pq.Prim.LESS_CAT1, ByteArray(Pq.Prim.LESS_CAT1.pkBytes), ByteArray(0))
        assertEquals("unsupported_suite: less-cat1", iae { Keys.suite("less-cat1", null, less) })
        assertNotNull(Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32))))
    }
}
