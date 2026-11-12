package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

/** A KeyFactory that refuses every spec: the provider-refusal catch of rsaPublicKey (parsePkcs1 and jwkRsaKey both go through it). */
class Kill08K1RefusingRsaSpi : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec?): PublicKey { throw InvalidKeySpecException("refused") }
    override fun engineGeneratePrivate(keySpec: KeySpec?): PrivateKey { throw InvalidKeySpecException("refused") }
    override fun <T : KeySpec?> engineGetKeySpec(key: Key?, keySpec: Class<T>?): T { throw InvalidKeySpecException("refused") }
    override fun engineTranslateKey(key: Key?): Key { throw java.security.InvalidKeyException("refused") }
}

class Kill08K1RefusingRsaProvider : Provider("Kill08K1BadRsa", "1.0", "refusing RSA KeyFactory for a test") {
    init { put("KeyFactory.RSA", Kill08K1RefusingRsaSpi::class.java.name) }
}

class Kill08K1RsaSeamTest {
    @Test fun aProviderRefusalIsTheUnsupportedKeyRefusal() {
        val bad = KeyFactory.getInstance("RSA", Kill08K1RefusingRsaProvider())
        val n = BigInteger.ONE.shiftLeft(511).add(BigInteger.ONE)
        val e = assertThrows(AttErr::class.java) { AttestCert.rsaPublicKey(n, BigInteger.valueOf(65537), bad) }
        assertEquals(AttestCert.OSSL_UNSUPPORTED, e.message)
    }
}
