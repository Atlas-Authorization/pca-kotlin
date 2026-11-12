package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** Round-2 kills from full run 41911466407 shard 13 (vendor verifiers). */
class Kill05R2VendorTest {
    private fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun fixed(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray().let { if (it.size > len) it.copyOfRange(it.size - len, it.size) else it }
        val out = ByteArray(len)
        System.arraycopy(b, 0, out, len - b.size, b.size)
        return out
    }

    private fun reason(f: () -> Any?): String = try {
        f()
        "no error"
    } catch (e: AttErr) {
        e.message ?: "null"
    }

    /**
     * AttestJws.jwkEcKey: `crv` is matched by the whole string, not by its hash. Each name below has the same String.hashCode
     * as P-256 / P-384 / P-521 (the last two characters (c1, c2) replaced by (c1 + 1, c2 - 31)), so only the equality check
     * after the hash switch refuses it.
     */
    @Test fun ecJwkCurveNamesCollidingByHashAreRefused() {
        for ((crv, twin, gen) in listOf(
            Triple("P-256", "P-26\u0017", "secp256r1"),
            Triple("P-384", "P-39\u0015", "secp384r1"),
            Triple("P-521", "P-53\u0012", "secp521r1"),
        )) {
            assertEquals(crv.hashCode(), twin.hashCode())
            val pub = Kill05JwsKit.ecKey(gen).public as ECPublicKey
            val len = (pub.params.order.bitLength() + 7) / 8
            val x = b64u(fixed(pub.w.affineX, len))
            val y = b64u(fixed(pub.w.affineY, len))
            assertEquals(crv, "no error", reason { AttestJws.jwkEcKey(crv, x, y) })
            assertEquals(twin, AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkEcKey(twin, x, y) })
        }
    }

    /** Attest.DefaultHardware exposes the evidence picker it was built with. */
    @Test fun defaultHardwareKeepsItsEvidencePicker() {
        val impl = object : Attest.VendorImpl {
            override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = Attest.fail("x")
        }
        val ver = Attest.VendorVerifier("x", impl, null)
        val pick: (Map<String, Any?>) -> Map<String, Any?>? = { null }
        assertSame(pick, Attest.DefaultHardware(ver, pick).evidence)
        assertNull(Attest.DefaultHardware(ver).evidence)
    }
}
