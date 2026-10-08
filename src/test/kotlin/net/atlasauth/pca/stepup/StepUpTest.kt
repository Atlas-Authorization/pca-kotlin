package net.atlasauth.pca.stepup

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.*
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

class StepUpTest {
    private fun verify(pubB64: String, msg: ByteArray, sigB64: String): Boolean {
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(Base64Url.decode(pubB64)!!, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(Base64Url.decode(sigB64)!!)
    }

    @Test fun base64urlRoundTrip() {
        for (n in 0 until 40) {
            val d = ByteArray(n) { ((it * 37 + 250) and 0xff).toByte() }
            assertArrayEquals(d, Base64Url.decode(Base64Url.encode(d)))
        }
        assertNull(Base64Url.decode("a"))
    }

    @Test fun keyGenerateExportImportSign() {
        val k = PrincipalDeviceKey(InMemorySecretStore())
        assertFalse(k.exists)
        val pub = k.generate()
        val k2 = PrincipalDeviceKey(InMemorySecretStore())
        assertEquals(pub, k2.importSecret(k.exportSecret()))
        val msg = "hello".toByteArray()
        assertTrue(verify(pub, msg, k2.sign(msg)))
        assertThrows(StepUpError.InvalidSecret::class.java) { k2.importSecret("AAAA") }
        assertThrows(StepUpError.NoDeviceKey::class.java) { PrincipalDeviceKey(InMemorySecretStore()).sign(msg) }
    }

    // RFC 8032 test vector 1 (empty message): proves BouncyCastle matches the noble/Ed25519 the server uses.
    @Test fun rfc8032Vector1() {
        fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val k = PrincipalDeviceKey(InMemorySecretStore())
        val seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pub = k.importSecret(Base64Url.encode(seed))
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            Base64Url.decode(pub)!!.joinToString("") { "%02x".format(it) })
        assertEquals("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            Base64Url.decode(k.sign(ByteArray(0)))!!.joinToString("") { "%02x".format(it) })
    }

    private fun iso(ms: Long) = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(ms))

    @Test fun listApproveDeny() = runBlocking {
        MockWebServer().use { dash -> MockWebServer().use { inst ->
            val key = PrincipalDeviceKey(InMemorySecretStore()); val pub = key.generate()
            val msg = byteArrayOf(1, 2, 3, -6, -5)
            val exp = iso(System.currentTimeMillis() + 600_000)
            dash.enqueue(MockResponse().setBody("""{"stepups":[{"id":"su_1","grant_ref":"g1","action":{"verb":"pay","resource":"order/1"},"required_t":3,"threshold_message":"${Base64Url.encode(msg)}","created_at":"x","expires_at":"$exp","status":"pending"},{"id":"old","grant_ref":"g","action":{"verb":"v","resource":"r"},"required_t":3,"threshold_message":"AA","created_at":"x","expires_at":"2001-01-01T00:00:00.000Z","status":"pending"}]}"""))
            dash.enqueue(MockResponse().setBody("{}"))
            inst.enqueue(MockResponse().setBody("""{"status":"approved","allow":true}"""))
            val c = StepUpClient(dash.url("/").toString(), inst.url("/").toString(), "acc", "ins", key, { "dsk_x" })
            val items = c.pending()
            assertEquals(listOf("su_1"), items.map { it.id })
            assertEquals("pay", items[0].actionVerb)
            val listReq = dash.takeRequest()
            assertEquals("Bearer dsk_x", listReq.getHeader("Authorization"))
            assertTrue(listReq.path!!.contains("status=pending"))

            assertTrue(c.approve(items[0]).anchored)
            val cos = inst.takeRequest()
            assertEquals("/v1/pca/stepups/su_1/cosign", cos.path)
            val body = Json.parseToJsonElement(cos.body.readUtf8()).jsonObject
            assertEquals("principal", body["role"]!!.jsonPrimitive.content)
            assertEquals(pub, body["publicKey"]!!.jsonPrimitive.content)
            assertTrue(verify(pub, msg, body["sig"]!!.jsonPrimitive.content))

            c.deny(items[0], "no")
            assertTrue(dash.takeRequest().path!!.endsWith("/su_1/deny"))
        } }
    }

    @Test fun principalMismatchSurfacesGuidance() = runBlocking {
        MockWebServer().use { inst ->
            inst.enqueue(MockResponse().setResponseCode(403).setBody("""{"errors":[{"code":"forbidden","message":"The share is not from this grant's principal key."}]}"""))
            val key = PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() }
            val c = StepUpClient(inst.url("/").toString(), inst.url("/").toString(), "a", "i", key, { "t" })
            val su = PendingStepUp("s", "g", "v", "r", 3, "AAEC", 0)
            val e = runCatching { c.approve(su) }.exceptionOrNull()
            assertTrue(e is StepUpError.PrincipalMismatch)
            assertTrue(e!!.message!!.contains("principal key"))
        }
    }
}
