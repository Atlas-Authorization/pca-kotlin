package net.atlasauth.pca.guard

import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull

/** Shared helpers of the Kill06 guard tests. */
@Suppress("UNCHECKED_CAST")
internal object Kill06GuardKit {
    const val REF = "$PCA_DOCS/reference/refusals.md"
    const val QUICK = "$PCA_DOCS/guides/resource-server-quickstart.md"
    const val MAX = 524288
    val EMPTY = ByteArray(0)

    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    /** Strict unpadded base64url of the UTF-8 text. */
    fun hdr(s: String): String = Pca.b64(utf8(s))

    fun cfg(
        sc: GuardFixtures.Scenario, az: Authorize.AuthorizeOptions?, ip: Pca.IntentPolicy? = null, sigOnly: Boolean = false,
        executor: PcaExecutorConfig? = null, clock: () -> Long = { sc.now },
    ): PcaGuardConfig = PcaGuardConfig(sc.audience, { ref -> if (ref == sc.grant["id"]) sc.grant else null }, az, ip, sigOnly, clock, executor)

    fun decide(
        sc: GuardFixtures.Scenario, config: PcaGuardConfig, header: String? = sc.header, esc: String? = null, body: ByteArray = EMPTY,
        op: Authorize.Operation? = sc.operation, wf: Authorize.WorkflowStep? = null, prov: String? = sc.provenanceHeader,
    ): GuardOutcome = PcaGuard.decide(config, header, esc, body, op, wf, prov)

    /** A JSON body of exactly `size` bytes carrying the principal-direct provenance bundle of `sc` as `pca_provenance`. */
    fun padded(sc: GuardFixtures.Scenario, size: Int): ByteArray {
        fun mk(n: Int) = Json.canonicalize(linkedMapOf<String, Any?>("pad" to "a".repeat(n), ArgProvenance.BODY_MEMBER to GuardFixtures.provenance(sc.operation)))
        val base = utf8(mk(0)).size
        val out = utf8(mk(size - base))
        assertEquals(size, out.size)
        return out
    }

    /** A refusal before any verdict: 401/403, the body keys, the challenge, and nothing else set. */
    fun pre(o: GuardOutcome, status: Int, code: String?, desc: String, doc: String = explainRefusal(desc).docs) {
        assertFalse(o.allowed)
        assertEquals(status, o.status)
        assertEquals("deny", o.decision)
        assertEquals(if (code == null) "PCA realm=\"pca\"" else "PCA realm=\"pca\", error=\"$code\"", o.wwwAuthenticate)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("doc", "decision", "error", "error_description"), b.keys)
        assertEquals(code ?: "pca_required", b["error"])
        assertEquals(desc, b["error_description"])
        assertEquals("deny", b["decision"])
        assertEquals(doc, b["doc"])
        assertNull(o.authorization)
        assertNull(o.verdict)
        assertNull(o.pcactn)
        assertNull(o.boundOperation)
        assertNull(o.idempotencyKey)
        assertNull(o.operation)
    }

    /** A refusal of the executor path (status, error code, description; the challenge only on 401 / 403). */
    fun plain(o: GuardOutcome, status: Int, code: String, desc: String? = null) {
        assertFalse(o.allowed)
        assertEquals(status, o.status)
        assertEquals("deny", o.decision)
        assertEquals(if (status == 401 || status == 403) "PCA realm=\"pca\", error=\"$code\"" else null, o.wwwAuthenticate)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("doc", "decision", "error", "error_description"), b.keys)
        assertEquals(code, b["error"])
        if (desc != null) assertEquals(desc, b["error_description"])
        assertEquals("deny", b["decision"])
        assertEquals(explainRefusal(b["error_description"]).docs, b["doc"])
        assertNull(o.authorization)
        assertNull(o.verdict)
        assertNull(o.pcactn)
        assertNull(o.boundOperation)
        assertNull(o.idempotencyKey)
    }
}
