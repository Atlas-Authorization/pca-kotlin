package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * Threshold-share verification, mirroring `packages/pca/src/threshold.ts` (and the Java / Rust / Go / Python /
 * Ruby / PHP / .NET / Swift SDKs). Covers the v2.1 AGENT-LEAF BINDING (conformance `agent_leaf_binding: "2.1"`):
 * every role's EXPLICIT share — `guardian`, `principal` AND (new in v2.1) `agent` — signs the SAME
 * role/signer-set/threshold-bound bytes
 *
 *     "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte) || suiteTag
 *
 * so a share cannot be replayed under another role, in a different signer set, or at a different threshold. The
 * OLD bare-threshold-message agent share MUST be rejected because it does not verify over these bound bytes
 * (GAP 2 `agent-bare-rejected`), and a share bound to signer set A MUST be rejected against signer set B — the
 * `signerSetHash` binding defeats cross-signer-set replay (`agent-bound-wrong-set`). The PCActn LEAF signature
 * `p.sig` is the only thing that stays bare (it signs `thresholdMessage` directly) and is handled by the
 * `leaf_signature` verifier check, not here.
 *
 * Fail-closed throughout: an unknown suite, a malformed signer set, a bad base64url field, or a signature that
 * does not verify all return `false`; nothing in the verify path swallows an exception into a pass.
 */
object Threshold {
    private const val SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\u0000"

    /** Domain-separated suite tag appended for a NON-default suite; ed25519 / absent / unknown => empty. */
    private const val SHARE_SUITE_TAG = "\u0000atlas-pca/share-suite/v1\u0000"

    /** Version marker for the v2.1 agent-leaf share binding (matches `vectors.json.agent_leaf_binding`). */
    const val AGENT_LEAF_SHARE_BINDING_VERSION = "2.1"

    private fun utf8(s: String): ByteArray = s.toByteArray(StandardCharsets.UTF_8)

    /**
     * `sha256(DOMAIN || canonical(sorted [{publicKey, role[, pq_pk]}]))`, the rows sorted bytewise by
     * `(role, publicKey)` so signer and verifier agree however the set is listed. ADDITIVE: a registered
     * `pq_pk` is carried into the bound set; an ed25519-only set hashes byte-identically to pre-agility.
     */
    fun signerSetHash(signerSet: List<Any?>): ByteArray {
        val rows = signerSet.map { o ->
            val s = Pca.asMap(o)
            val row = LinkedHashMap<String, Any?>()
            row["publicKey"] = s["publicKey"].toString()
            row["role"] = s["role"].toString()
            if (s["pq_pk"] is String) row["pq_pk"] = s["pq_pk"]
            row
        }.sortedWith(Comparator { a, b ->
            val c = Json.compareUtf8(a["role"] as String, b["role"] as String)
            if (c != 0) c else Json.compareUtf8(a["publicKey"] as String, b["publicKey"] as String)
        })
        return Pca.sha(utf8(SIGNER_SET_DOMAIN), Pca.canonBytes(rows))
    }

    /** Empty for ed25519 / absent / unknown, else `SHARE_SUITE_TAG || suite.alg`. */
    private fun shareSuiteTag(alg: Any?, algPresent: Boolean): ByteArray {
        val suite = Pq.resolveSigAlg(alg, algPresent)
        if (suite == null || suite.alg == "ed25519") return ByteArray(0)
        return utf8(SHARE_SUITE_TAG + suite.alg)
    }

    /** The bytes a share of `role` signs. `t` MUST be 1, 2 or 3. */
    fun shareMessage(role: String, thresholdMessage: ByteArray, signerSet: List<Any?>, t: Int, alg: Any?, algPresent: Boolean): ByteArray {
        require(t in 1..3) { "shareMessage: t must be 1, 2 or 3" }
        return Pca.concat(
            utf8("atlas-pca/share/$role\u0000"),
            Pca.sha(thresholdMessage),
            signerSetHash(signerSet),
            byteArrayOf(t.toByte()),
            shareSuiteTag(alg, algPresent),
        )
    }

    /**
     * Verify a single EXPLICIT threshold share by RECOMPUTING the role/set/t-bound [shareMessage] from the entry
     * (never trusting a precomputed `share_message`) and checking `share.sig` over it under `share.publicKey`
     * (ed25519) / `share.pq_pk` (PQ) per `share.alg`. Fail-closed; never throws.
     *
     * @param role             the binding role (the threshold_share entry's `role`)
     * @param thresholdMessage the RAW threshold message bytes (base64url-decoded `threshold_message`)
     * @param signerSet        the signer set the share is bound into
     * @param t                the threshold (1..3)
     * @param share            `{role, publicKey, sig[, alg, pq_pk, pq_sig]}`
     */
    fun verifyShare(role: String, thresholdMessage: ByteArray, signerSet: List<Any?>, t: Int, share: Map<String, Any?>): Boolean {
        return try {
            val msg = shareMessage(role, thresholdMessage, signerSet, t, share["alg"], share.containsKey("alg"))
            val publicKey = Pca.asStr(share["publicKey"])
            Pq.verifyLeafSuite(share["alg"], share.containsKey("alg"), publicKey, share["pq_pk"], msg, share["sig"], share["pq_sig"])
        } catch (e: RuntimeException) {
            false // fail-closed: a malformed share never counts as a valid one
        }
    }
}
