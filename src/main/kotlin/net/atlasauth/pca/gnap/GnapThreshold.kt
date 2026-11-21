package net.atlasauth.pca.gnap

import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.Threshold

/**
 * The t-of-n distinct-role count of the reference's `verifyThreshold` (the continuation passes no agent-leaf baseline, as the
 * reference does), over the explicit shares folded into a PCActn. The signer set is validated first and the whole verification fails
 * closed if it is malformed; a share counts iff its role and key are registered and its signature (Ed25519, pure PQ or hybrid, against
 * the role's registered pq_pk) verifies over the role/signer-set/t-bound share message. A suite this verifier does not implement is refused
 * as an unknown algorithm.
 */
internal object GnapThreshold {
    private val ROLES = setOf("agent", "guardian", "principal")
    private val PQ_PK_LENGTHS = setOf(1952, 2592, 32, 64, 897, 1793, 97484)

    /** Reason text for a possibly hostile value: primitives as String(v), containers by kind only. */
    private fun show(v: Any?): String = when (v) {
        is Map<*, *> -> "<object>"
        is List<*> -> "<array>"
        else -> GnapJs.str(v)
    }

    private fun member(o: Any?, k: String) = GnapJs.member(o, k)

    private fun pqPkOk(v: Any?): Boolean {
        if (v !is String) return false
        val b = Pca.decodeB64uStrict(v, -1)
        return b != null && b.size in PQ_PK_LENGTHS
    }

    private fun verdict(ok: Boolean, count: Int, roles: List<String>, reason: String?): Map<String, Any?> {
        val m = Issue.obj("ok" to ok, "count" to count.toLong(), "roles" to ArrayList<Any?>(roles))
        if (reason != null) m["reason"] = reason
        return m
    }

    @Suppress("UNCHECKED_CAST")
    fun verify(threshold: Map<String, Any?>?, message: ByteArray, signerSet: List<Any?>, t: Int): Map<String, Any?> {
        if (t < 1 || t > 3) return verdict(false, 0, emptyList(), "invalid threshold t=$t (must be 1, 2 or 3)")
        // the signer set: role -> key, role -> registered pq_pk
        val keyOfRole = HashMap<String, String>()
        val roleOfKey = HashMap<String, String>()
        val pqOfRole = HashMap<String, String>()
        val seenEntry = HashMap<String, String?>()
        for (s in signerSet) {
            val ro = member(s, "role")
            val ko = member(s, "publicKey")
            val role = if (ro is String && ro in ROLES) ro else null
            val keyOk = s != null && Pca.decodeB64uStrict(ko, 32) != null
            val hasPq = GnapJs.has(s, "pq_pk") // a present pq_pk (JSON null is present)
            var pqOk = !hasPq || pqPkOk(member(s, "pq_pk"))
            if (role != null && keyOk && pqOk) {
                val id = role + "\u0000" + ko
                val pq = member(s, "pq_pk") as? String
                // a duplicate (role, key) entry is harmless only if it registers the SAME pq_pk (or none on both)
                if (seenEntry.containsKey(id) && seenEntry[id] != pq) pqOk = false else seenEntry[id] = pq
                if (pqOk && !pqOfRole.containsKey(role) && !keyOfRole.containsKey(role)) { if (pq != null) pqOfRole[role] = pq }
            }
            if (!(role != null && keyOk)) return verdict(false, 0, emptyList(), "malformed signer set")
            if (!pqOk) return verdict(false, 0, emptyList(), "malformed signer set (pq_pk)")
            val k = ko as String
            val prevKey = keyOfRole[role]
            if (prevKey != null && prevKey != k) return verdict(false, 0, emptyList(), "signer set registers more than one key for role ${show(ro)}")
            val prevRole = roleOfKey[k]
            if (prevRole != null && prevRole != role) return verdict(false, 0, emptyList(), "signer set registers one key under two roles")
            if (prevKey == null) { keyOfRole[role] = k; roleOfKey[k] = role }
        }
        // the shares, in order
        val shares = threshold?.get("shares") as? List<Any?> ?: emptyList()
        val keys = ArrayList<String>()
        val roles = ArrayList<String>()
        var reason: String? = null
        for (share in shares) {
            val wellFormed = share is Map<*, *> && member(share, "role") is String && member(share, "publicKey") is String
            if (!wellFormed) { if (reason == null) reason = "malformed share"; continue }
            val pub = member(share, "publicKey") as String
            if (pub in keys) continue
            val roleName = member(share, "role") as String
            val regKey = if (roleName in ROLES) keyOfRole[roleName] else null
            val pqPk = member(share, "pq_pk")
            val fail = when {
                regKey == null -> "role ${show(roleName)} is not in the signer set"
                regKey != pub -> "share for role ${show(roleName)} uses a key not registered for that role"
                Pq.resolveSigAlg(member(share, "alg"), GnapJs.has(share, "alg")) == null -> "share for role ${show(roleName)} declares an unknown signature alg"
                GnapJs.has(share, "pq_pk") && !(pqPk is String && pqPk == pqOfRole[roleName]) ->
                    "share for role ${show(roleName)} names a pq_pk that is not the key its role registers"
                // PQ / hybrid shares verify against the role's registered pq_pk; a role that registers one refuses an Ed25519-only share
                !Threshold.verifyShare(roleName, message, signerSet, t, share as Map<String, Any?>) -> "invalid signature for role ${show(roleName)}"
                else -> null
            }
            if (fail != null) { if (reason == null) reason = fail; continue }
            keys.add(pub)
            roles.add(roleName)
        }
        val count = keys.size
        if (count >= t) return verdict(true, count, roles, null)
        return verdict(false, count, roles, reason ?: "only $count distinct valid key(s), need $t")
    }
}
