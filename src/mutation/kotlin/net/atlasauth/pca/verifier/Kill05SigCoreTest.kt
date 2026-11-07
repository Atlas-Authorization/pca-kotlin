package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * verifySigstoreBundleCore / verifySigstoreBundle on bundles from a self-made Sigstore world (Kill05SigKit): every refusal's code
 * AND detail, as the reference words them, and the signed-note checkpoint.
 */
@Suppress("UNCHECKED_CAST")
class Kill05SigCoreTest {
    private val K = Kill05SigKit
    private val roots = K.roots()

    private fun r(b: Any?, rt: Sigstore.PinnedRoots? = roots): String {
        val x = Sigstore.verifySigstoreBundleCore(b, rt)
        return if (x.ok) "ok" else "${x.code}|${x.detail}"
    }

    @Test fun acceptsTheForgedWorld() {
        for (kind in listOf("dsse", "intoto")) {
            val x = Sigstore.verifySigstoreBundleCore(K.bundle(kind), roots)
            assertTrue("$kind: ${x.code} ${x.detail}", x.ok)
            assertTrue("$kind: ${x.core}", IntentJs.jsonEquals(K.expectedCore(), x.core))
            assertNull(x.detail)
        }
        val f = Sigstore.verifySigstoreBundle(K.bundle(), roots)
        assertTrue("${f.code} ${f.detail}", f.ok)
        assertNull(f.detail)
        assertEquals("b", f.facts!!["builder_id"])
    }

    @Test fun notABundle() {
        val nb = "malformed|not a bundle"
        assertEquals(nb, r(null))
        assertEquals(nb, r("x"))
        assertEquals(nb, r(mapOf("mediaType" to K.V03)))
        assertEquals(nb, r(K.bundle(), null))
        val f = Sigstore.verifySigstoreBundle(null, roots)
        assertEquals("malformed", f.code)
        assertEquals("not a bundle", f.detail)
    }

    @Test fun mediaTypeDetail() {
        assertEquals("media_type|unsupported media type undefined", r(K.bundle().also { it.remove("mediaType") }))
        assertEquals("media_type|unsupported media type null", r(K.bundle().also { it["mediaType"] = null }))
        assertEquals("media_type|unsupported media type 5", r(K.bundle().also { it["mediaType"] = 5L }))
        assertEquals("media_type|unsupported media type x", r(K.bundle().also { it["mediaType"] = "x" }))
        val f = Sigstore.verifySigstoreBundle(K.bundle().also { it["mediaType"] = "x" }, roots)
        assertEquals("unsupported media type x", f.detail)
    }

    @Test fun earlyStages() {
        assertEquals("malformed|fail closed: not base64", r(K.bundle().also { K.m(it["dsseEnvelope"])["payload"] = "!!!!" }))
        assertEquals("tlog_count|exactly one transparency log entry is required", r(K.bundle().also { K.vm(it)["tlogEntries"] = listOf("x") }))
        val kind = "tlog_kind|unsupported entry "
        assertEquals(kind, r(K.bundle().also { K.entry(it).remove("kindVersion") }))
        assertEquals(kind, r(K.bundle().also { K.m(K.entry(it)["kindVersion"])["kind"] = 5L }))
        assertEquals(kind, r(K.bundle().also { K.m(K.entry(it)["kindVersion"])["version"] = 5L }))
        assertEquals("tlog_kind|unsupported entry dsse/0.0.2", r(K.bundle().also { K.m(K.entry(it)["kindVersion"])["version"] = "0.0.2" }))
        assertEquals("tlog_key|the entry names a log the verifier did not pin", r(K.bundle().also { K.m(K.entry(it)["logId"])["keyId"] = K.std(ByteArray(32)) }))
    }

    @Test fun inclusionAndCheckpoint() {
        val none = "tlog_inclusion|no inclusion proof"
        assertEquals(none, r(K.bundle().also { K.entry(it).remove("inclusionProof") }))
        assertEquals(none, r(K.bundle().also { K.m(K.entry(it)["inclusionProof"]).remove("hashes") }))
        assertEquals(none, r(K.bundle().also { K.m(K.entry(it)["inclusionProof"])["hashes"] = "x" }))
        assertEquals(none, r(K.bundle().also { K.m(K.entry(it)["inclusionProof"]).remove("checkpoint") }))
        val env = "tlog_checkpoint|the checkpoint envelope is not a string"
        assertEquals(env, r(K.bundle().also { K.m(K.entry(it)["inclusionProof"])["checkpoint"] = mapOf("envelope" to 5L) }))
        assertEquals(env, r(K.bundle().also { K.m(K.entry(it)["inclusionProof"])["checkpoint"] = emptyMap<String, Any?>() }))
    }

    @Test fun caValidityEdges() {
        // the CA's validFor may start or end exactly at the signing time
        assertEquals("ok", r(K.bundle(), K.roots(caStart = K.IT_RFC)))
        assertEquals("ok", r(K.bundle(), K.roots(caEnd = K.IT_RFC)))
        val chain = "cert_chain|no pinned CA issued the certificate, valid at every signing time"
        assertEquals(chain, r(K.bundle(), K.roots(caStart = "2025-01-01T01:00:01Z")))
        assertEquals(chain, r(K.bundle(), K.roots(caEnd = "2025-01-01T00:59:59Z")))
    }

    @Test fun entryBodySignatures() {
        val one = "tlog_body|the entry must name exactly one signature"
        assertEquals(one, r(K.bundle("dsse", body = { ps, _, _ ->
            "{\"apiVersion\":\"0.0.1\",\"kind\":\"dsse\",\"spec\":{\"payloadHash\":{\"algorithm\":\"sha256\",\"value\":\"$ps\"},\"signatures\":[\"x\"]}}"
        })))
        assertEquals(one, r(K.bundle("intoto", body = { ps, _, _ ->
            "{\"apiVersion\":\"0.0.2\",\"kind\":\"intoto\",\"spec\":{\"content\":{\"envelope\":{\"signatures\":[\"x\"]},\"payloadHash\":{\"algorithm\":\"sha256\",\"value\":\"$ps\"}}}}"
        })))
    }

    @Test fun leafKeyAndIdentity() {
        // an RSA leaf: everything up to the DSSE signature holds, then its key type is refused
        assertEquals("signature|unsupported leaf key type", r(K.bundle(leaf = K.leafDer(pub = K.rsa().public))))
        val noIssuer = "identity|no OIDC issuer extension"
        assertEquals(noIssuer, r(K.bundle(leaf = K.leafDer(K.leafExts(issuerExt = null)))))
        assertEquals(noIssuer, r(K.bundle(leaf = K.leafDer(K.leafExts(issuerExt = K.fulcio(1, ByteArray(0)))))))
    }

    @Test fun statementSubjects() {
        val noSubject = "statement|no subject"
        fun st(subject: String?) = K.bundle(
            payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"," + (if (subject == null) "" else "\"subject\":$subject,") + "\"predicateType\":\"p\"}",
        )
        assertEquals(noSubject, r(st("[]")))
        assertEquals(noSubject, r(st(null)))
        assertEquals(noSubject, r(st("\"x\"")))
        assertEquals("statement|no sha256/sha512 subject digest (or more than 64)", r(st("[{\"digest\":{\"md5\":\"aa\"}}]")))
    }

    @Test fun stackOverflowIsRefused() {
        val deep = object : AbstractMap<String, Any?>() {
            override val entries: Set<Map.Entry<String, Any?>> get() = throw StackOverflowError()
        }
        val x = Sigstore.verifySigstoreBundleCore(deep, roots)
        assertEquals("malformed|fail closed: too deep", "${x.code}|${x.detail}")
    }

    @Test fun checkpointText() {
        val log = roots.tlogs[0]
        val root = ByteArray(32) { 1 }
        val body = "o\n7\n${K.std(root)}\n"
        fun line(b: String) = "— o " + K.std(K.cat(log.keyId.copyOfRange(0, 4), K.sign(K.logKey.private, K.utf8(b)))) + "\n"
        assertNull(Sigstore.verifyCheckpoint(body + "\n" + line(body), log, 7, root))
        assertEquals("checkpoint has no signature block", Sigstore.verifyCheckpoint(body, log, 7, root))
        val short = "checkpoint body too short or without an origin"
        assertEquals(short, Sigstore.verifyCheckpoint("\n\n" + line(body), log, 7, root))
        assertEquals(short, Sigstore.verifyCheckpoint("o\n7\n\n" + line(body), log, 7, root))
        assertEquals(short, Sigstore.verifyCheckpoint("\n7\n${K.std(root)}\n\n" + line(body), log, 7, root))
        assertEquals("checkpoint size differs from the proof", Sigstore.verifyCheckpoint(body + "\n" + line(body), log, 8, root))
        assertEquals("checkpoint root differs from the proof", Sigstore.verifyCheckpoint(body + "\n" + line(body), log, 7, ByteArray(32)))
        val noSig = "no checkpoint signature by the pinned log key"
        assertEquals(noSig, Sigstore.verifyCheckpoint(body + "\n", log, 7, root))
        assertEquals(noSig, Sigstore.verifyCheckpoint(body + "\n" + line("other\n"), log, 7, root))
    }

    @Test fun checkpointSignatureLinesShorterThanTheKeyHintAreSkipped() {
        val log = roots.tlogs[0]
        val root = ByteArray(32) { 1 }
        val body = "o\n7\n${K.std(root)}\n"
        val good = "— o " + K.std(K.cat(log.keyId.copyOfRange(0, 4), K.sign(K.logKey.private, K.utf8(body)))) + "\n"
        // 1..4 raw bytes: no room for a 4-byte key hint and a signature; such a line is skipped, the next one still verifies
        for (n in 1..4) {
            val short = "— o " + K.std(ByteArray(n) { log.keyId[it] }) + "\n"
            assertNull("$n", Sigstore.verifyCheckpoint(body + "\n" + short + good, log, 7, root))
            assertEquals("$n", "no checkpoint signature by the pinned log key", Sigstore.verifyCheckpoint(body + "\n" + short, log, 7, root))
        }
    }
}
