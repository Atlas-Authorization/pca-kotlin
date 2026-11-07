package net.atlasauth.pca.stepup

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.*
import org.junit.Test

/** Base64Url, PrincipalDeviceKey, InMemorySecretStore, the value types and the error messages. */
class Kill06StepUpKeyTest {
    private class FixedStore(var value: ByteArray?) : SecretStore {
        var saved: ByteArray? = null
        var deletes = 0
        override fun load(): ByteArray? = value
        override fun save(secret: ByteArray) { saved = secret.copyOf(); value = secret.copyOf() }
        override fun delete() { deletes++; value = null }
    }

    private class ThrowingStore : SecretStore {
        override fun load(): ByteArray? = throw IllegalStateException("boom")
        override fun save(secret: ByteArray) {}
        override fun delete() {}
    }

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // ---- Base64Url ----

    @Test fun encodeMatchesRfc4648Vectors() {
        assertEquals("", Base64Url.encode(ByteArray(0)))
        assertEquals("Zg", Base64Url.encode("f".toByteArray()))
        assertEquals("Zm8", Base64Url.encode("fo".toByteArray()))
        assertEquals("Zm9v", Base64Url.encode("foo".toByteArray()))
        assertEquals("Zm9vYg", Base64Url.encode("foob".toByteArray()))
        assertEquals("Zm9vYmE", Base64Url.encode("fooba".toByteArray()))
        assertEquals("Zm9vYmFy", Base64Url.encode("foobar".toByteArray()))
        assertEquals("-_8", Base64Url.encode(b(0xfb, 0xff)))
        assertEquals("__79", Base64Url.encode(b(0xff, 0xfe, 0xfd)))
        assertEquals("AQ", Base64Url.encode(b(1)))
        assertEquals("AQI", Base64Url.encode(b(1, 2)))
    }

    @Test fun decodeInvertsEncodeAndToleratesPadding() {
        for (n in 0 until 24) {
            val d = ByteArray(n) { ((it * 53 + 200) and 0xff).toByte() }
            assertArrayEquals(d, Base64Url.decode(Base64Url.encode(d)))
        }
        assertArrayEquals("f".toByteArray(), Base64Url.decode("Zg=="))
        assertArrayEquals("fo".toByteArray(), Base64Url.decode("Zm8="))
        assertArrayEquals("fo".toByteArray(), Base64Url.decode("Zm8"))
        assertArrayEquals("foob".toByteArray(), Base64Url.decode("Zm9vYg==="))
        assertArrayEquals(b(0xfb, 0xff), Base64Url.decode("-_8"))
        assertArrayEquals(ByteArray(3), Base64Url.decode("AAAA"))
        assertArrayEquals(ByteArray(1), Base64Url.decode("AA"))
        assertArrayEquals(ByteArray(0), Base64Url.decode(""))
    }

    @Test fun decodeRejectsMalformedInput() {
        assertNull(Base64Url.decode("A"))
        assertNull(Base64Url.decode("AAAAA"))
        assertNull(Base64Url.decode("AAAAAAAAA"))
        assertNull(Base64Url.decode("Zm9!"))
        assertNull(Base64Url.decode("Zm+v"))
        assertNull(Base64Url.decode("Zg=A"))
        assertNull(Base64Url.decode("\u0080AAA"))
        assertNull(Base64Url.decode("AAAé"))
        assertNull(Base64Url.decode("A\u007fAA"))
        assertNull(Base64Url.decode("AAAĀ"))
    }

    // ---- PrincipalDeviceKey ----

    @Test fun existsIsTrueOnlyForAStoredKeyAndFalseWhenTheStoreThrows() {
        assertFalse(PrincipalDeviceKey(ThrowingStore()).exists)
        assertFalse(PrincipalDeviceKey(FixedStore(null)).exists)
        assertTrue(PrincipalDeviceKey(FixedStore(ByteArray(32))).exists)
    }

    @Test fun generateSavesARandom32ByteSeedAndReturnsItsPublicKey() {
        val s = FixedStore(null)
        val k = PrincipalDeviceKey(s)
        val pub = k.generate()
        assertEquals(32, s.saved!!.size)
        assertFalse(s.saved!!.all { it == 0.toByte() })
        assertEquals(pub, k.publicKey())
        assertEquals(Base64Url.encode(s.saved!!), k.exportSecret())
        assertEquals(32, Base64Url.decode(pub)!!.size)
        val k2 = PrincipalDeviceKey(InMemorySecretStore())
        assertNotEquals(pub, k2.generate())
        assertNotEquals(Base64Url.encode(ByteArray(32)), k2.exportSecret())
    }

    @Test fun importSecretAcceptsOnlyA32ByteSeed() {
        val s = FixedStore(null)
        val k = PrincipalDeviceKey(s)
        for (bad in listOf(Base64Url.encode(ByteArray(31)), Base64Url.encode(ByteArray(33)), Base64Url.encode(ByteArray(0)), "!!!!", "A")) {
            val e = assertThrows(StepUpError.InvalidSecret::class.java) { k.importSecret(bad) }
            assertEquals("The principal secret must be a base64url-encoded 32-byte Ed25519 seed.", e.message)
        }
        assertNull(s.saved)
        val seed = ByteArray(32) { (it + 1).toByte() }
        val pub = k.importSecret(Base64Url.encode(seed))
        assertArrayEquals(seed, s.saved)
        assertEquals(pub, k.publicKey())
        assertEquals(Base64Url.encode(seed), k.exportSecret())
    }

    @Test fun aMissingOrWrongSizedStoredSeedIsRejectedEverywhere() {
        val none = PrincipalDeviceKey(FixedStore(null))
        val msg = ByteArray(2)
        for (f in listOf<() -> Any>({ none.publicKey() }, { none.exportSecret() }, { none.sign(msg) })) {
            val e = assertThrows(StepUpError.NoDeviceKey::class.java) { f() }
            assertEquals("No principal device key is stored on this device.", e.message)
        }
        for (size in listOf(31, 33)) {
            val k = PrincipalDeviceKey(FixedStore(ByteArray(size)))
            for (f in listOf<() -> Any>({ k.publicKey() }, { k.exportSecret() }, { k.sign(msg) })) {
                val e = assertThrows(StepUpError.InvalidSecret::class.java) { f() }
                assertEquals("The principal secret must be a base64url-encoded 32-byte Ed25519 seed.", e.message)
            }
        }
    }

    @Test fun signProducesAnEd25519SignatureOverTheMessage() {
        val k = PrincipalDeviceKey(InMemorySecretStore())
        val pub = k.generate()
        val msg = "hello".toByteArray()
        val sig = Base64Url.decode(k.sign(msg))!!
        assertEquals(64, sig.size)
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(Base64Url.decode(pub)!!, 0))
        v.update(msg, 0, msg.size)
        assertTrue(v.verifySignature(sig))
        val v2 = Ed25519Signer()
        v2.init(false, Ed25519PublicKeyParameters(Base64Url.decode(pub)!!, 0))
        v2.update("hellp".toByteArray(), 0, 5)
        assertFalse(v2.verifySignature(sig))
    }

    @Test fun deleteRemovesTheKeyFromTheStore() {
        val s = FixedStore(ByteArray(32))
        val k = PrincipalDeviceKey(s)
        k.delete()
        assertEquals(1, s.deletes)
        assertFalse(k.exists)
        val mem = InMemorySecretStore()
        val k2 = PrincipalDeviceKey(mem)
        k2.generate()
        assertNotNull(mem.load())
        k2.delete()
        assertNull(mem.load())
        assertFalse(k2.exists)
    }

    @Test fun inMemoryStoreCopiesOnSaveAndLoad() {
        val m = InMemorySecretStore()
        assertNull(m.load())
        val a = byteArrayOf(1, 2, 3)
        m.save(a)
        a[0] = 9
        val l = m.load()!!
        assertArrayEquals(byteArrayOf(1, 2, 3), l)
        l[1] = 9
        assertArrayEquals(byteArrayOf(1, 2, 3), m.load())
        m.delete()
        assertNull(m.load())
    }

    // ---- value types and errors ----

    @Test fun pendingStepUpExposesEveryField() {
        val p = PendingStepUp("i", "g", "payments.refund", "order/1234", 4, "tm", 99L)
        assertEquals("i", p.id)
        assertEquals("g", p.grantRef)
        assertEquals("payments.refund", p.actionVerb)
        assertEquals("order/1234", p.actionResource)
        assertEquals(4, p.requiredT)
        assertEquals("tm", p.thresholdMessageB64u)
        assertEquals(99L, p.expiresAt)
        assertEquals("payments.refund on order/1234", p.summary)
    }

    @Test fun approveResultExposesEveryField() {
        val r = ApproveResult("approved", true, 202)
        assertEquals("approved", r.status)
        assertTrue(r.anchored)
        assertEquals(202, r.httpStatus)
        assertFalse(ApproveResult("x", false, 200).anchored)
    }

    @Test fun errorsCarryTheirMessagesAndFields() {
        val cause = RuntimeException("c")
        val a = StepUpError.Api(404, "nope")
        assertEquals(404, a.status)
        assertEquals("HTTP 404: nope", a.message)
        assertEquals("m", StepUpError.PrincipalMismatch("m").message)
        val t = StepUpError.Transport("t", cause)
        assertEquals("t", t.message)
        assertSame(cause, t.cause)
        assertNull(StepUpError.Transport("t").cause)
        assertNull(StepUpError.NoDeviceKey().cause)
        assertNull(StepUpError.InvalidSecret().cause)
        assertNull(StepUpError.InvalidThresholdMessage().cause)
        assertNull(a.cause)
    }
}
