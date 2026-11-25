package net.atlasauth.pca.scitt

/**
 * Durable, append-only storage for a transparency log. [append] is atomic: it succeeds only when the log still has exactly
 * `expectedSize` entries (a compare-and-set, so two writers cannot both take the same index) and stores the entry and the new
 * subtree hashes together, or none of them. Entries and nodes are immutable once written.
 */
interface ScittLogStore {
    /** The hash of the complete subtree at [level] covering leaves [index * 2^level, (index + 1) * 2^level). */
    class StoredNode(@JvmField val level: Long, @JvmField val index: Long, @JvmField val hash: ByteArray)

    fun size(): Long

    /** The entry at [index], or null when absent. Returns a copy. */
    fun getEntry(index: Long): ByteArray?

    /** The subtree hash, or null when absent. Returns a copy. */
    fun getNode(level: Long, index: Long): ByteArray?

    fun append(expectedSize: Long, entry: ByteArray, nodes: List<StoredNode>): Boolean
}
