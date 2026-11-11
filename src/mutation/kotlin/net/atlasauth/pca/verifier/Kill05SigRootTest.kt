package net.atlasauth.pca.verifier

import java.security.SecureRandom
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Sigstore trusted-root parsing: pinned logs (ECDSA, RSA PKCS#1, Ed25519 signed-note), CA chains, the root itself. */
class Kill05SigRootTest {
    private val K = Kill05SigKit
    private val start = linkedMapOf<String, Any?>("start" to "2020-01-01T00:00:00Z")

    private fun log(der: ByteArray, keyId: ByteArray, details: String, baseUrl: Any? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "publicKey" to linkedMapOf<String, Any?>("rawBytes" to K.std(der), "keyDetails" to details, "validFor" to start),
            "logId" to linkedMapOf<String, Any?>("keyId" to K.std(keyId)),
        )
        if (baseUrl != null) m["baseUrl"] = baseUrl
        return m
    }

    @Test fun malformedLogEntries() {
        val spki = K.logSpki
        assertEquals("IAE:log entry malformed", K.err { Sigstore.pinnedLog(mapOf("logId" to mapOf("keyId" to K.std(K.logId))), true) })
        assertEquals("IAE:log entry malformed", K.err { Sigstore.pinnedLog(mapOf("publicKey" to mapOf("rawBytes" to K.std(spki))), true) })
        assertEquals("IAE:log entry malformed", K.err { Sigstore.pinnedLog(null, true) })
    }

    @Test fun ecdsaLog() {
        val spki = K.logSpki
        val ok = Sigstore.pinnedLog(log(spki, K.sha256(spki), "PKIX_ECDSA_P256_SHA_256"), true)!!
        assertArrayEquals(K.logId, ok.keyId)
        assertEquals("EC", ok.key!!.algorithm)
        assertNull(ok.v2Name)
        assertEquals(1577836800000L, ok.start)
        assertEquals(Long.MAX_VALUE, ok.end)
        assertEquals("IAE:log id is not the SHA-256 of its key", K.err { Sigstore.pinnedLog(log(spki, ByteArray(32), "PKIX_ECDSA_P256_SHA_256"), true) })
        assertNull(Sigstore.pinnedLog(log(spki, K.sha256(spki), "PKIX_ECDSA_P384_SHA_384"), true))
    }

    @Test fun rsaCtLog() {
        val spki = K.rsa().public.encoded
        val top = Sigstore.tlv(spki, 0)
        val bits = Sigstore.kids(spki, top)[1]
        val pkcs1 = spki.copyOfRange(bits.body + 1, bits.end)
        val ok = Sigstore.pinnedLog(log(pkcs1, K.sha256(spki), "PKCS1_RSA_PKCS1V5"), false)!!
        assertNotNull(ok.key)
        assertEquals("RSA", ok.key!!.algorithm)
        assertArrayEquals(spki, ok.key!!.encoded)
        assertEquals("IAE:log id is not the SHA-256 of its key", K.err { Sigstore.pinnedLog(log(pkcs1, K.sha256(pkcs1), "PKCS1_RSA_PKCS1V5"), false) })
        // an RSA transparency log is not supported (skipped)
        assertNull(Sigstore.pinnedLog(log(pkcs1, K.sha256(spki), "PKCS1_RSA_PKCS1V5"), true))
    }

    @Test fun ed25519Log() {
        val sk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val pk = ByteArray(32)
        Ed25519.generatePublicKey(sk, 0, pk, 0)
        val der = K.cat(K.b(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00), pk)
        val id = K.sha256(K.utf8("rekor.example\n"), K.b(1), pk)
        val ok = Sigstore.pinnedLog(log(der, id, "PKIX_ED25519", "https://Rekor.Example/api"), true)!!
        assertEquals("rekor.example", ok.v2Name)
        assertArrayEquals(pk, ok.ed25519)
        assertNull(ok.key)
        val notEd = "IAE:not an Ed25519 key"
        assertEquals(notEd, K.err { Sigstore.pinnedLog(log(der.copyOfRange(0, 43), id, "PKIX_ED25519", "https://rekor.example"), true) })
        val badPrefix = der.copyOf().also { it[8] = 0x71 }
        assertEquals(notEd, K.err { Sigstore.pinnedLog(log(badPrefix, id, "PKIX_ED25519", "https://rekor.example"), true) })
        val noName = "IAE:log id is not the signed-note key hash of its key"
        assertEquals(noName, K.err { Sigstore.pinnedLog(log(der, id, "PKIX_ED25519"), true) })
        assertEquals(noName, K.err { Sigstore.pinnedLog(log(der, id, "PKIX_ED25519", 5L), true) })
        assertEquals(noName, K.err { Sigstore.pinnedLog(log(der, id, "PKIX_ED25519", "https://other.example"), true) })
        // a CT log is never Ed25519 here (skipped)
        assertNull(Sigstore.pinnedLog(log(der, id, "PKIX_ED25519", "https://rekor.example"), false))
    }

    @Test fun hostnames() {
        assertEquals("rekor.example", Sigstore.urlHostname("https://Rekor.Example:443/x"))
        assertEquals("a.b", Sigstore.urlHostname(" https://a.b/\n"))
        assertEquals("IAE:Invalid URL", K.err { Sigstore.urlHostname("mailto:a@b.c") })
        assertEquals("IAE:Invalid URL", K.err { Sigstore.urlHostname("https:///x") })
    }

    @Test fun caChains() {
        assertEquals("IAE:certificate authority entry malformed", K.err { Sigstore.pinnedChain(mapOf("certChain" to mapOf("certificates" to emptyList<Any?>()), "validFor" to start)) })
        assertEquals("IAE:certificate authority entry malformed", K.err { Sigstore.pinnedChain(null) })
        val ca = Sigstore.pinnedChain(mapOf("certChain" to mapOf("certificates" to listOf(mapOf("rawBytes" to K.std(K.caDer)))), "validFor" to mapOf("start" to K.IT_RFC, "end" to "2025-01-01T01:00:01Z")))
        assertEquals(1, ca.chain.size)
        assertEquals(K.IT * 1000, ca.start)
        assertEquals(K.IT * 1000 + 1000, ca.end)
    }

    @Test fun trustedRoot() {
        val need = "IAE:a trusted root needs a transparency log and a CA"
        assertEquals(need, K.err { Sigstore.parseTrustedRoot(K.rootJson().also { it.remove("tlogs") }) })
        assertEquals(need, K.err { Sigstore.parseTrustedRoot(K.rootJson().also { it.remove("certificateAuthorities") }) })
        assertEquals("IAE:not a trusted root v0.1", K.err { Sigstore.parseTrustedRoot(K.rootJson().also { it["mediaType"] = "x" }) })
        assertEquals("IAE:not base64", K.err { Sigstore.parseTrustedRoot(K.rootJson().also { it["tlogs"] = listOf(log(K.logSpki, K.logId, "PKIX_ECDSA_P256_SHA_256").plus("logId" to mapOf("keyId" to "!"))) }) })
        val r = Sigstore.parseTrustedRoot(K.rootJson())
        assertEquals(1, r.tlogs.size)
        assertEquals(1, r.cas.size)
        assertTrue(r.ctlogs.isEmpty() && r.tsas.isEmpty())
        // a key the JDK refuses (not an IllegalArgumentException) is wrapped with its message
        val notKey = K.seq(K.int(0))
        try {
            Sigstore.parseTrustedRoot(K.rootJson().also { it["tlogs"] = listOf(log(notKey, K.sha256(notKey), "PKIX_ECDSA_P256_SHA_256")) })
            fail("accepted a malformed log key")
        } catch (e: IllegalArgumentException) {
            val cause = e.cause
            assertNotNull("no cause", cause)
            assertNotNull("cause without message", cause!!.message)
            assertEquals("trusted root malformed: ${cause.message}", e.message)
        }
    }
}
