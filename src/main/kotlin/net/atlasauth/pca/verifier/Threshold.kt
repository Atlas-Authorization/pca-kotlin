package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * Risk-adaptive threshold signatures (spec §6 L2/L3), a sound t-of-n MULTI-SIGNATURE: a bag of `t`
 * INDEPENDENT Ed25519 signatures, each produced by a distinct allowed role over the SAME canonical message
 * (`Pca.thresholdMessage(pcactn)`). Verification counts the number of DISTINCT keys (== distinct roles,
 * since the signer set maps one key to one role) whose share both (a) is signed by that role's registered
 * key and (b) verifies over that role's message; the signature is accepted iff that count is >= t.
 *
 * Faithful Kotlin port of `packages/pca/src/threshold.ts` (`signerSetHash`, `shareMessage`, `verifyThreshold`).
 * Role-, signer-set- and t-bound so a share cannot be replayed under another role, in a different signer set,
 * or at a different threshold. Deterministic and TOTAL — never throws.
 */
object Threshold {
    val ROLES = listOf("agent", "guardian", "principal")
    val VALID_THRESHOLDS = listOf(1, 2, 3)
    private const val SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\u0000"

    private fun isValidT(t: Int): Boolean = t == 1 || t == 2 || t == 3

    data class Signer(val role: String, val publicKey: String)

    data class ThresholdShare(val role: String, val publicKey: String, val sig: String)

    data class ThresholdVerdict(
        val ok: Boolean,
        val count: Int,
        val roles: List<String>,
        val reason: String? = null,
    )

    /**
     * Hash of a signer set: sha256(DOMAIN || canonical(sorted [{publicKey, role}])), sorted bytewise by
     * (role, publicKey). Order-insensitive, so signer and verifier agree however the set is listed.
     */
    fun signerSetHash(signerSet: List<Signer>): ByteArray {
        val rows = signerSet
            .map { linkedMapOf<String, Any?>("publicKey" to it.publicKey, "role" to it.role) }
            .sortedWith(Comparator { a, b ->
                val c = Json.compareUtf8(a["role"] as String, b["role"] as String)
                if (c != 0) c else Json.compareUtf8(a["publicKey"] as String, b["publicKey"] as String)
            })
        return Pca.sha(Pca.concat(SIGNER_SET_DOMAIN.toByteArray(StandardCharsets.UTF_8), Pca.canonBytes(rows)))
    }

    /**
     * The bytes a guardian / principal SHARE signs:
     *   "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t   (t = ONE byte, 1..3)
     * The AGENT role's share is the PCActn leaf signature `sig`, which signs `thresholdMessage` directly.
     */
    fun shareMessage(role: String, message: ByteArray, signerSet: List<Signer>, t: Int): ByteArray {
        if (!isValidT(t)) throw IllegalArgumentException("shareMessage: t must be 1, 2 or 3")
        return Pca.concat(
            "atlas-pca/share/$role\u0000".toByteArray(StandardCharsets.UTF_8),
            Pca.sha(message),
            signerSetHash(signerSet),
            byteArrayOf(t.toByte()),
        )
    }

    /**
     * Verify a t-of-n multi-signature over `message` (= `Pca.thresholdMessage(pcactn)`). The signer set is
     * validated FIRST and the whole verification fails closed if it is malformed: every role is a known role,
     * each role has EXACTLY ONE registered key, and no public key is registered under two roles. A share counts
     * iff its role+key are registered and its signature verifies over that role's message. The count is of
     * DISTINCT KEYS.
     */
    fun verifyThreshold(shares: List<ThresholdShare>, message: ByteArray, signerSet: List<Signer>, t: Int): ThresholdVerdict {
        fun fail(reason: String) = ThresholdVerdict(false, 0, emptyList(), reason)
        if (!isValidT(t)) return fail("invalid threshold t=$t (must be 1, 2 or 3)")

        val keyOfRole = HashMap<String, String>()
        val roleOfKey = HashMap<String, String>()
        for (s in signerSet) {
            if (!ROLES.contains(s.role) || Pca.decodeB64uStrict(s.publicKey, 32) == null) return fail("malformed signer set")
            val prevKey = keyOfRole[s.role]
            if (prevKey != null && prevKey != s.publicKey) return fail("signer set registers more than one key for role ${s.role}")
            val prevRole = roleOfKey[s.publicKey]
            if (prevRole != null && prevRole != s.role) return fail("signer set registers one key under two roles")
            keyOfRole[s.role] = s.publicKey
            roleOfKey[s.publicKey] = s.role
        }

        val validKeys = LinkedHashSet<String>()
        val validRoles = ArrayList<String>()
        var reason: String? = null

        for (share in shares) {
            if (validKeys.contains(share.publicKey)) continue // a key counts once
            val registeredKey = keyOfRole[share.role]
            if (registeredKey == null) {
                if (reason == null) reason = "role ${share.role} is not in the signer set"
                continue
            }
            if (share.publicKey != registeredKey) {
                if (reason == null) reason = "share for role ${share.role} uses a key not registered for that role"
                continue
            }
            val signed = if (share.role == "agent") message else shareMessage(share.role, message, signerSet, t)
            if (!Pca.verifyB64u(share.publicKey, signed, share.sig)) {
                if (reason == null) reason = "invalid signature for role ${share.role}"
                continue
            }
            validKeys.add(share.publicKey)
            validRoles.add(share.role)
        }

        val count = validKeys.size
        val ok = count >= t
        return if (ok) ThresholdVerdict(true, count, validRoles)
        else ThresholdVerdict(false, count, validRoles, reason ?: "only $count distinct valid key(s), need $t")
    }
}
