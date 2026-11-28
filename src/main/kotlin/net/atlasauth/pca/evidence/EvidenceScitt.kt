package net.atlasauth.pca.evidence

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.scitt.Scitt

/**
 * Registration reference of an evidence bundle: its digest anchors in the intent anchor log (kind `evidence`) and a SCITT signed
 * statement names the bundle by that digest. [evidenceRef] is the payload; [evidenceSignedStatement] signs it as a COSE Signed
 * Statement through the SCITT port.
 */
object EvidenceScitt {
    const val EVIDENCE_CONTENT_TYPE = "application/pca-intent-evidence+json"

    fun evidenceRef(bundle: Any?): Map<String, Any?> {
        val subj = Js.member(bundle, "subject")
        // {...bundle.subject}: a spread of a non-object is empty
        val subject = if (subj is Map<*, *>) LinkedHashMap<String, Any?>().also { m -> for ((k, v) in subj) m[k as String] = v } else LinkedHashMap<String, Any?>()
        return linkedMapOf("kind" to "pca-intent-evidence-ref", "digest" to EvidenceBundle.evidenceDigest(bundle), "subject" to subject)
    }

    /**
     * A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. The subject defaults to the bundle's
     * `subject.pcactn_digest`; the content type is always [EVIDENCE_CONTENT_TYPE] (any `opts.contentType` is replaced). A non-string
     * subject digest is refused (the statement's subject claim is text).
     */
    fun evidenceSignedStatement(bundle: Any?, opts: Scitt.SignStatementOpts): ByteArray {
        val ref = evidenceRef(bundle)
        var subject = opts.subject
        if (subject == null) {
            val d = (ref["subject"] as Map<*, *>)["pcactn_digest"]
            if (d != null && d !is String) throw IllegalArgumentException("evidenceSignedStatement: subject.pcactn_digest must be a string")
            subject = d as String?
        }
        val o = Scitt.SignStatementOpts(opts.alg, opts.key, opts.issuer).contentType(EVIDENCE_CONTENT_TYPE)
        if (subject != null) o.subject(subject)
        return Scitt.signStatement(ref, o)
    }

    /** The intent-anchor-log leaf for a bundle digest (`intentAnchorCommit` construction, kind `evidence`). */
    fun evidenceAnchorCommit(digest: String): String = EvidenceVerify.anchorCommit("evidence", digest)
}
