package net.atlasauth.pca.evidence

import net.atlasauth.pca.scitt.Scitt
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the dispute evidence bundle: shape, normal forms, digest, registration reference and the replay helpers. */
class EvidenceDiffTest {
    private val m = "ref-evidence"

    @Suppress("UNCHECKED_CAST")
    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    @Test fun bundleShapeError() = OracleCases.each(m, "bundleShapeError") { a -> EvidenceBundle.bundleShapeError(a[0]) }

    @Test fun normalizeBundle() = OracleCases.each(m, "normalizeBundle") { a -> EvidenceBundle.normalizeBundle(a[0]) }

    @Test fun buildEvidenceBundle() = OracleCases.each(m, "buildEvidenceBundle") { a -> EvidenceBundle.buildEvidenceBundle(map(a[0])) }

    @Test fun commitmentForm() = OracleCases.each(m, "commitmentForm") { a -> EvidenceBundle.commitmentForm(a[0]) }

    @Test fun evidenceSignedStatement() = OracleCases.each("ref-evidence-java-extra", "evidenceSignedStatement") { a ->
        val spec = map(a[1])
        val opts = Scitt.SignStatementOpts(Scitt.CoseAlg.EdDSA, Scitt.ed25519PrivateKey(Keys.unb64u(spec["seed"] as String)), spec["issuer"] as String?)
        if (spec.containsKey("subject")) opts.subject(spec["subject"] as String?)
        EvidenceScitt.evidenceSignedStatement(a[0], opts)
    }

    @Test fun evidenceDigest() = OracleCases.each(m, "evidenceDigest") { a -> EvidenceBundle.evidenceDigest(a[0]) }

    @Test fun evidenceRef() = OracleCases.each(m, "evidenceRef") { a -> EvidenceScitt.evidenceRef(a[0]) }

    @Test fun evidenceAnchorCommit() = OracleCases.each(m, "evidenceAnchorCommit") { a -> EvidenceScitt.evidenceAnchorCommit(a[0] as String) }

    @Test fun anchorCommit() = OracleCases.each(m, "anchorCommit") { a -> EvidenceVerify.anchorCommit(a[0] as String, a[1] as String) }

    @Test fun capOf() = OracleCases.each(m, "capOf") { a -> EvidenceVerify.capOf(a[0], a[1] as String, a[2] as String) }

    // no argument = undefined = valid
    @Test fun principalsTrustError() = OracleCases.each(m, "principalsTrustError") { a -> if (a.isEmpty()) null else EvidenceVerify.principalsTrustError(a[0]) }

    @Test fun accTrustError() = OracleCases.each(m, "accTrustError") { a -> if (a.isEmpty()) null else EvidenceVerify.accTrustError(a[0]) }

    @Test fun consts() = OracleCases.each(m, "consts") { _ ->
        linkedMapOf<String, Any?>(
            "EVIDENCE_DOMAIN" to EvidenceBundle.EVIDENCE_DOMAIN,
            "EVIDENCE_REPORT_DOMAIN" to EvidenceVerify.EVIDENCE_REPORT_DOMAIN,
            "EVIDENCE_CONTENT_TYPE" to EvidenceScitt.EVIDENCE_CONTENT_TYPE,
        )
    }
}
