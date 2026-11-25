package net.atlasauth.pca.verifier

/**
 * An append-only RFC 9162 Merkle log over opaque commitment strings: head, root at an earlier size, inclusion and consistency
 * proofs, in the wire shapes the verifiers in [Ledger] and [Mesh] read. It holds only commitments (no openings).
 */
class MerkleLog {
    private val commits = ArrayList<String>()
    private val hashes = ArrayList<ByteArray>()

    fun size(): Int = commits.size

    fun commits(): List<String> = ArrayList(commits)

    /** Append an opaque commitment leaf; refuses an empty one. Returns its index. */
    fun appendCommitment(commit: String): Int {
        if (commit.isEmpty()) throw IllegalArgumentException("appendCommitment: commit must be a non-empty string")
        commits.add(commit)
        hashes.add(Pca.leafHash(commit))
        return commits.size - 1
    }

    /** {size, root}. */
    fun head(): Map<String, Any?> = linkedMapOf("size" to StoreJs.num(size().toLong()), "root" to root())

    fun root(): String = Pca.b64(mth(hashes))

    /** The root the log had when it held only the first `size` entries. */
    fun rootAt(size: Long): String {
        if (size < 0 || size > size()) throw IllegalArgumentException("rootAt: size out of range")
        return Pca.b64(mth(hashes.subList(0, size.toInt())))
    }

    /** {index, size, path: [{side, hash}]}. */
    fun inclusionProof(index: Long): Map<String, Any?> {
        if (index < 0 || index >= size()) throw IllegalArgumentException("merkleProof: index out of range")
        val path = ArrayList<Any?>()
        prove(hashes, index.toInt(), path)
        return linkedMapOf("index" to StoreJs.num(index), "size" to StoreJs.num(size().toLong()), "path" to path)
    }

    /** RFC 9162 SUBPROOF: {oldSize, newSize, path: [b64u]}. */
    @JvmOverloads
    fun consistencyProof(oldSize: Long, newSize: Long = size().toLong()): Map<String, Any?> {
        if (oldSize < 0 || oldSize > newSize || newSize > size()) throw IllegalArgumentException("consistencyProof: invalid sizes")
        val out = ArrayList<Any?>()
        if (oldSize > 0 && oldSize < newSize) sub(oldSize.toInt(), hashes.subList(0, newSize.toInt()), true, out)
        return linkedMapOf("oldSize" to StoreJs.num(oldSize), "newSize" to StoreJs.num(newSize), "path" to out)
    }

    companion object {
        fun of(commits: List<String>): MerkleLog = MerkleLog().also { l -> for (c in commits) l.appendCommitment(c) }

        internal fun split(n: Int): Int {
            var k = 1
            while (k * 2 < n) k *= 2
            return k
        }

        internal fun build(hs: List<ByteArray>): ByteArray {
            if (hs.size == 1) return hs[0]
            val k = split(hs.size)
            return Pca.nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size)))
        }

        private fun mth(hs: List<ByteArray>): ByteArray = if (hs.isEmpty()) Pca.sha(ByteArray(0)) else build(hs)

        internal fun prove(hs: List<ByteArray>, idx: Int, out: MutableList<Any?>) {
            if (hs.size == 1) return
            val k = split(hs.size)
            if (idx < k) {
                prove(hs.subList(0, k), idx, out)
                out.add(linkedMapOf("side" to "R", "hash" to Pca.b64(build(hs.subList(k, hs.size)))))
            } else {
                prove(hs.subList(k, hs.size), idx - k, out)
                out.add(linkedMapOf("side" to "L", "hash" to Pca.b64(build(hs.subList(0, k)))))
            }
        }

        /** RFC 9162 SUBPROOF(m, D[n], b). */
        private fun sub(m: Int, hs: List<ByteArray>, b: Boolean, out: MutableList<Any?>) {
            val n = hs.size
            if (m == n) {
                if (!b) out.add(Pca.b64(mth(hs)))
                return
            }
            val k = split(n)
            if (m <= k) {
                sub(m, hs.subList(0, k), b, out)
                out.add(Pca.b64(mth(hs.subList(k, n))))
            } else {
                sub(m - k, hs.subList(k, n), false, out)
                out.add(Pca.b64(mth(hs.subList(0, k))))
            }
        }
    }
}

/** A sorted set of revoked ids with the size-bound root and non-membership proofs the mesh verifier reads. */
class RevocationSet @JvmOverloads constructor(initial: Iterable<String> = emptyList()) {
    private val ids = ArrayList<String>()

    init { for (id in initial) revoke(id) }

    fun size(): Int = ids.size

    private fun lowerBound(id: String): Int {
        var lo = 0
        var hi = ids.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (Json.compareUtf8(ids[mid], id) < 0) lo = mid + 1 else hi = mid
        }
        return lo
    }

    /** Idempotent. Returns true when newly revoked. */
    fun revoke(id: String): Boolean {
        val lo = lowerBound(id)
        if (lo < ids.size && ids[lo] == id) return false
        ids.add(lo, id)
        return true
    }

    fun has(id: String): Boolean {
        val lo = lowerBound(id)
        return lo < ids.size && ids[lo] == id
    }

    /** Sorted revoked ids (copy). */
    fun list(): List<String> = ArrayList(ids)

    /**
     * Proof that `id` is NOT in the set: `{size, lo?, hi?}`, the bracketing leaves `{id, proof}` (lo = the greatest id below, hi = the
     * least id above). Throws when the id IS revoked (no such proof can exist).
     */
    fun nonMembershipProof(id: String): Map<String, Any?> {
        if (has(id)) throw IllegalStateException("nonMembershipProof: id is revoked")
        val n = ids.size
        val lo = lowerBound(id) // first index whose leaf is > id
        val hs = ids.map { Pca.leafHash(it) }
        val p = linkedMapOf<String, Any?>("size" to StoreJs.num(n.toLong()))
        if (lo > 0) p["lo"] = leaf(hs, lo - 1)
        if (lo < n) p["hi"] = leaf(hs, lo)
        return p
    }

    private fun leaf(hs: List<ByteArray>, i: Int): Map<String, Any?> {
        val path = ArrayList<Any?>()
        MerkleLog.prove(hs, i, path)
        val proof = linkedMapOf<String, Any?>("index" to StoreJs.num(i.toLong()), "size" to StoreJs.num(hs.size.toLong()), "path" to path)
        return linkedMapOf("id" to ids[i], "proof" to proof)
    }

    /** The size-bound root. */
    fun root(): String = IntentRevocation.revsetRoot(ids)
}
