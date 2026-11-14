package net.atlasauth.pca.verifier

import java.security.SecureRandom
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** ed25519Strict takes exactly 32-byte keys and 64-byte signatures: a longer array whose prefix verifies is refused (TS reads both through the strict base64url decoder with exact lengths, hash.ts:72-81). */
class Kill06Ed25519LengthTest {
    @Test fun aKeyOrSignatureWithATrailingByteIsRefused() {
        val sk = ByteArray(32).also { SecureRandom().nextBytes(it) } // generated at test load
        val pk = ByteArray(32).also { Ed25519.generatePublicKey(sk, 0, it, 0) }
        val msg = "pca".toByteArray()
        val sig = ByteArray(64).also { Ed25519.sign(sk, 0, msg, 0, msg.size, it, 0) }
        assertTrue(Pca.ed25519Strict(pk, msg, sig))
        assertFalse(Pca.ed25519Strict(pk + 0.toByte(), msg, sig))
        assertFalse(Pca.ed25519Strict(pk, msg, sig + 0.toByte()))
    }
}
