package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.BreakGlass
import net.atlasauth.pca.verifier.Blueprint
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Lease
import net.atlasauth.pca.verifier.Pca

/**
 * Signing side of the operational-plane artifacts (lease, lease revocation, agent blueprint, break-glass, review) and the
 * domain-separated body signature they share. A record is signed only when the matching verifier would take it: the record is signed
 * and then run through that verifier (shape plus signature), so no shape rule is duplicated here.
 */
object GrantSigning {
    private val LEASE_KEYS = listOf("v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority")
    private val REVOKE_KEYS = listOf("v", "target", "value", "revoked_at", "authority")
    private val BLUEPRINT_KEYS = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator")
    private val BG_KEYS = listOf("v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority")
    private val REVIEW_KEYS = listOf("v", "id", "outcome", "notes_digest", "at", "reviewer")

    @JvmStatic
    fun signerOf(secret: Keys.EdKey): String = secret.id()

    /** b64u Ed25519 signature over `domain || strictCanonicalJSON(body)`. */
    @JvmStatic
    fun signBody(domain: String, body: Any?, secret: Keys.EdKey): String = Issue.signBody(secret, domain, body)

    /** True iff `sig` is a canonical 64-byte b64u signature by `signer` over exactly `body`. Never throws. */
    @JvmStatic
    fun verifyBody(domain: String, body: Any?, signer: String, sig: Any?): Boolean = K3Sig.verifyBody(domain, body, signer, sig)

    private fun base(rec: Map<String, Any?>, authorityKey: String, secret: Keys.EdKey): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["v"] = 1L
        b.putAll(rec)
        b[authorityKey] = secret.id()
        return b
    }

    private fun pick(o: Map<String, Any?>, keys: List<String>, onlyPresent: Boolean): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in keys) if (!onlyPresent || o.containsKey(k)) b[k] = o[k]
        return b
    }

    private fun signed(base: LinkedHashMap<String, Any?>, domain: String, keys: List<String>, onlyPresent: Boolean, secret: Keys.EdKey): LinkedHashMap<String, Any?> {
        base["sig"] = signBody(domain, pick(base, keys, onlyPresent), secret)
        return base
    }

    @JvmStatic
    fun signLease(secret: Keys.EdKey, l: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(l, "authority", secret), Lease.DOMAIN, LEASE_KEYS, false, secret)
        require(Lease.verifyLease(b) && Json.asLong(b["expires_at"]) <= Json.asLong(b["issued_at"]) + Json.asLong(b["max_ttl"])) {
            "signLease: a malformed lease, or one past issued_at + max_ttl"
        }
        return b
    }

    /** Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it. */
    @JvmStatic
    fun signLeaseUnsafeOverCap(secret: Keys.EdKey, l: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(l, "authority", secret), Lease.DOMAIN, LEASE_KEYS, false, secret)
        require(Lease.verifyLease(b)) { "signLeaseUnsafeOverCap: malformed" }
        return b
    }

    @JvmStatic
    fun signLeaseRevocation(secret: Keys.EdKey, r: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(r, "authority", secret), Lease.REVOKE_DOMAIN, REVOKE_KEYS, false, secret)
        require(Lease.verifyLeaseRevocation(b)) { "signLeaseRevocation: malformed" }
        return b
    }

    @JvmStatic
    fun signBlueprint(secret: Keys.EdKey, bp: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(bp, "operator", secret), Blueprint.DOMAIN, BLUEPRINT_KEYS, true, secret)
        require(Blueprint.verify(b)) { "signBlueprint: a malformed blueprint" }
        return b
    }

    @JvmStatic
    fun signBreakGlass(secret: Keys.EdKey, bg: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(bg, "authority", secret), BreakGlass.DOMAIN, BG_KEYS, false, secret)
        require(BreakGlass.verifyBreakGlass(b)) { "signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16" }
        return b
    }

    @JvmStatic
    fun signBreakGlassReview(secret: Keys.EdKey, r: Map<String, Any?>): Map<String, Any?> {
        val b = signed(base(r, "reviewer", secret), BreakGlass.REVIEW_DOMAIN, REVIEW_KEYS, false, secret)
        require(BreakGlass.verifyBreakGlassReview(b)) { "signBreakGlassReview: malformed" }
        return b
    }

    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }

    private fun root(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        val k = split(hs.size)
        return Pca.nodeHash(root(hs.subList(0, k)), root(hs.subList(k, hs.size)))
    }

    /** RFC 6962 inclusion proof `{index, size, path:[{side, hash}]}` (leaf to root) for leaf [index]; throws when out of range. */
    @JvmStatic
    fun merkleProof(leaves: List<Any?>, index: Int): Map<String, Any?> {
        require(index >= 0 && index < leaves.size) { "merkleProof: index out of range" }
        val hs = ArrayList<ByteArray>()
        for (l in leaves) hs.add(Pca.leafHash(l))
        val path = ArrayList<Any?>()
        prove(hs, index, path)
        val p = LinkedHashMap<String, Any?>()
        p["index"] = index.toLong()
        p["size"] = leaves.size.toLong()
        p["path"] = path
        return p
    }

    private fun prove(hs: List<ByteArray>, idx: Int, out: MutableList<Any?>) {
        if (hs.size == 1) return
        val k = split(hs.size)
        val step = LinkedHashMap<String, Any?>()
        if (idx < k) {
            prove(hs.subList(0, k), idx, out)
            step["side"] = "R"
            step["hash"] = Pca.b64(root(hs.subList(k, hs.size)))
        } else {
            prove(hs.subList(k, hs.size), idx - k, out)
            step["side"] = "L"
            step["hash"] = Pca.b64(root(hs.subList(0, k)))
        }
        out.add(step)
    }

    /** The newest record held for a blueprint key, or null. */
    @JvmStatic
    fun blueprintGet(registry: Blueprint.Registry, key: String): Map<String, Any?>? = registry.get(key)

    /** The shard a lease id lives in. */
    @JvmStatic
    fun shardOf(id: String, shards: Int): Int = Lease.shardOf(id, shards)
}
