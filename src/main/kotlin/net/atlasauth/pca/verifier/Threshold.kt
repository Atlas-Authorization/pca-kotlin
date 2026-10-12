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

    /** Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1). */
    private val PQ_PK_LENGTHS = setOf(1952, 2592, 32, 64, 897, 1793, 97484)
    private val ROLES = setOf("agent", "guardian", "principal")

    /**
     * R6-03: the reference's signer-set validation (decideThreshold BuildReg). Every entry is an object with a known role
     * (case-sensitive) and a canonical 32-byte publicKey; a PRESENT pq_pk (JSON null is present) is canonical base64url of a
     * registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the same pq_pk.
     * Returns role -> (publicKey, pq_pk or null), or null when the set is malformed.
     */
    internal fun validatedRegistry(signerSet: List<Any?>): Map<String, Pair<String, String?>>? {
        val reg = LinkedHashMap<String, Pair<String, String?>>()
        for (o in signerSet) {
            if (o !is Map<*, *>) return null
            val role = o["role"] as? String ?: return null
            if (role !in ROLES) return null
            val pk = o["publicKey"] as? String ?: return null
            if (Pca.decodeB64uStrict(pk, 32) == null) return null
            var pq: String? = null
            if (o.containsKey("pq_pk")) {
                val ps = o["pq_pk"] as? String ?: return null
                val pb = Pca.decodeB64uStrict(ps, -1) ?: return null
                if (pb.size !in PQ_PK_LENGTHS) return null
                pq = ps
            }
            val prev = reg[role]
            if (prev != null) {
                if (prev.first != pk) return null   // two keys for one role
                if (prev.second != pq) return null  // duplicate (role, key) with a conflicting pq_pk
                continue
            }
            if (reg.values.any { it.first == pk }) return null // one key under two roles
            reg[role] = Pair(pk, pq)
        }
        return reg
    }

    /** The signer-set hash (base64url) of a raw signer set; null when it is not a list of objects with string role / publicKey. */
    fun signerSetHashB64u(signerSet: Any?): String? = try {
        if (signerSet !is List<*> || signerSet.any { it !is Map<*, *> || it["role"] !is String || it["publicKey"] !is String }) null
        else Pca.b64(signerSetHash(signerSet))
    } catch (e: RuntimeException) {
        null
    }

    /**
     * Verify a `primitives.threshold_share[]`-shaped ENTRY `{role, t, signer_set, threshold_message, share}` of ANY JSON shape.
     * TOTAL (R6-05): anything malformed is `false`, never an exception. `t` must be exactly 1, 2 or 3.
     */
    @Suppress("UNCHECKED_CAST")
    fun verifyShareEntry(entry: Any?): Boolean = try {
        val e = entry as? Map<String, Any?>
        val role = e?.get("role") as? String
        val t = exactT(e?.get("t"))
        val set = e?.get("signer_set") as? List<Any?>
        val tm = if (e == null) null else Pca.decodeB64uStrict(e["threshold_message"], -1)
        val share = e?.get("share") as? Map<String, Any?>
        if (role == null || t == null || set == null || tm == null || share == null) false
        else verifyShare(role, tm, set, t, share)
    } catch (ex: RuntimeException) {
        false
    }

    /** 1, 2 or 3 when [o] is a JSON number of exactly that value, else null. */
    internal fun exactT(o: Any?): Int? {
        val d = try {
            when (o) {
                is Json.Num -> java.math.BigDecimal(o.raw)
                is Boolean -> return null
                is Number -> java.math.BigDecimal(o.toString())
                else -> return null
            }
        } catch (e: RuntimeException) {
            return null
        }
        return (1..3).firstOrNull { d.compareTo(java.math.BigDecimal.valueOf(it.toLong())) == 0 }
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
            if (t !in 1..3) return false // R6-04: exactly 1, 2 or 3
            // R6-03: validate the WHOLE signer set like the reference before looking at the share.
            val reg = validatedRegistry(signerSet) ?: return false
            // share.role is required and must name the verified role (reference: a share without a string role is malformed).
            if (share["role"] !is String || share["role"] != role) return false
            // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the
            // share's own publicKey / pq_pk never vouch for themselves.
            val publicKey = Pca.asStr(share["publicKey"])
            val r = reg[role] ?: return false
            if (r.first != publicKey) return false
            val regPq: String? = r.second
            val roleHasPq = regPq != null
            val algPresent = share.containsKey("alg")
            val suite = Pq.resolveSigAlg(share["alg"], algPresent)
            // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering
            // none has nothing it could equal). The key used is always the registered one.
            if (share.containsKey("pq_pk") && (regPq == null || share["pq_pk"] != regPq)) return false
            // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share
            // for it is refused (otherwise an Ed25519 break would still forge the role).
            if (roleHasPq && suite != null && suite.alg == "ed25519") return false
            var pqPk: Any? = share["pq_pk"]
            if (suite == null || suite.alg != "ed25519") {
                // PQ key = the signer set's registered pq_pk, never the share's own.
                if (regPq == null) return false
                pqPk = regPq
            }
            val msg = shareMessage(role, thresholdMessage, signerSet, t, share["alg"], algPresent)
            Pq.verifyLeafSuite(share["alg"], algPresent, publicKey, pqPk, msg, share["sig"], share["pq_sig"])
        } catch (e: RuntimeException) {
            false // fail-closed: a malformed share never counts as a valid one
        }
    }
}
