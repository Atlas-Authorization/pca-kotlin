package net.atlasauth.pca.scitt

import java.security.MessageDigest

/**
 * RFC 9162 section 2.1 Merkle tree (SHA-256): tree hash, inclusion paths and consistency proofs, with the verification algorithms of
 * sections 2.1.3.2 and 2.1.4.2. Leaf inputs are the raw entry bytes (`SHA-256(0x00 || entry)`), so any independent RFC 9162 /
 * RFC 6962 verifier can check a proof given the same entry bytes.
 */
object Rfc9162 {
    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    /** Root hash of the empty tree: SHA-256 of the empty string. */
    @JvmStatic fun emptyRoot(): ByteArray = sha256()

    /** `SHA-256(0x00 || entry)`. */
    @JvmStatic fun leafHash(entry: ByteArray): ByteArray = sha256(byteArrayOf(0x00), entry)

    /** `SHA-256(0x01 || left || right)`. */
    @JvmStatic fun nodeHash(left: ByteArray, right: ByteArray): ByteArray = sha256(byteArrayOf(0x01), left, right)

    /** Largest power of two strictly less than n (n >= 2). */
    private fun splitPoint(n: Int): Int {
        var k = 1
        while (k * 2L < n) k *= 2
        return k
    }

    /** MTH over already-hashed leaves (RFC 9162 section 2.1.1). */
    @JvmStatic
    fun treeHash(leafHashes: List<ByteArray>): ByteArray {
        val n = leafHashes.size
        if (n == 0) return emptyRoot()
        if (n == 1) return leafHashes[0]
        val k = splitPoint(n)
        return nodeHash(treeHash(leafHashes.subList(0, k)), treeHash(leafHashes.subList(k, n)))
    }

    /** Inclusion path for leaf [index] (RFC 9162 section 2.1.3.1), bottom-up. */
    @JvmStatic
    fun inclusionPath(leafHashes: List<ByteArray>, index: Long): MutableList<ByteArray> {
        val n = leafHashes.size
        if (index < 0 || index >= n) throw IndexOutOfBoundsException("rfc9162: leaf index out of range")
        if (n == 1) return ArrayList()
        val k = splitPoint(n)
        return if (index < k) inclusionPath(leafHashes.subList(0, k), index).also { it.add(treeHash(leafHashes.subList(k, n))) }
        else inclusionPath(leafHashes.subList(k, n), index - k).also { it.add(treeHash(leafHashes.subList(0, k))) }
    }

    private fun equal(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    private fun allHashes(path: List<ByteArray?>): Boolean = path.all { it != null && it.size == 32 }

    /**
     * Recompute the tree root from a leaf hash and its inclusion path (RFC 9162 section 2.1.3.2). Returns null when the
     * (index, size, path length) combination is invalid.
     */
    @JvmStatic
    fun rootFromInclusionPath(leaf: ByteArray?, index: Long, size: Long, path: List<ByteArray>): ByteArray? {
        if (index < 0 || size < 1 || index >= size) return null
        if (leaf == null || leaf.size != 32 || !allHashes(path)) return null
        var fn = index
        var sn = size - 1
        var r: ByteArray = leaf
        for (p in path) {
            if (sn == 0L) return null
            if (fn and 1L == 1L || fn == sn) {
                r = nodeHash(p, r)
                while (fn and 1L == 0L && fn != 0L) { fn = fn ushr 1; sn = sn ushr 1 }
            } else {
                r = nodeHash(r, p)
            }
            fn = fn ushr 1
            sn = sn ushr 1
        }
        return if (sn == 0L) r else null
    }

    /** Verify an inclusion proof: the recomputed root must equal [root]. */
    @JvmStatic
    fun verifyInclusionPath(leaf: ByteArray?, index: Long, size: Long, path: List<ByteArray>, root: ByteArray?): Boolean {
        val computed = rootFromInclusionPath(leaf, index, size, path)
        return computed != null && root != null && equal(computed, root)
    }

    private fun subproof(m: Int, d: List<ByteArray>, complete: Boolean): MutableList<ByteArray> {
        val n = d.size
        if (m == n) return if (!complete) arrayListOf(treeHash(d)) else ArrayList()
        val k = splitPoint(n)
        return if (m <= k) subproof(m, d.subList(0, k), complete).also { it.add(treeHash(d.subList(k, n))) }
        else subproof(m - k, d.subList(k, n), false).also { it.add(treeHash(d.subList(0, k))) }
    }

    /** Consistency proof between the first [m] leaves and all of [leafHashes] (RFC 9162 section 2.1.4.1). */
    @JvmStatic
    fun consistencyPath(leafHashes: List<ByteArray>, m: Long): MutableList<ByteArray> {
        if (m < 1 || m > leafHashes.size) throw IndexOutOfBoundsException("rfc9162: consistency size out of range")
        return subproof(m.toInt(), leafHashes, true)
    }

    /**
     * Verify a consistency proof between a tree of [first] leaves (root [firstRoot]) and one of [second] leaves ([secondRoot]) per
     * RFC 9162 section 2.1.4.2. A proof from an empty tree is rejected.
     */
    @JvmStatic
    fun verifyConsistencyPath(first: Long, second: Long, firstRoot: ByteArray?, secondRoot: ByteArray?, path: List<ByteArray>): Boolean {
        if (first < 1 || second < first) return false
        if (firstRoot == null || secondRoot == null || firstRoot.size != 32 || secondRoot.size != 32 || !allHashes(path)) return false
        if (first == second) return path.isEmpty() && equal(firstRoot, secondRoot)
        if (path.isEmpty()) return false
        val nodes = ArrayList(path)
        if (first and (first - 1) == 0L) nodes.add(0, firstRoot) // first is an exact power of two
        var fn = first - 1
        var sn = second - 1
        while (fn and 1L == 1L) { fn = fn ushr 1; sn = sn ushr 1 }
        var fr = nodes[0]
        var sr = nodes[0]
        for (c in nodes.subList(1, nodes.size)) {
            if (sn == 0L) return false
            if (fn and 1L == 1L || fn == sn) {
                fr = nodeHash(c, fr)
                sr = nodeHash(c, sr)
                while (fn and 1L == 0L && fn != 0L) { fn = fn ushr 1; sn = sn ushr 1 }
            } else {
                sr = nodeHash(sr, c)
            }
            fn = fn ushr 1
            sn = sn ushr 1
        }
        return sn == 0L && equal(fr, firstRoot) && equal(sr, secondRoot)
    }
}
