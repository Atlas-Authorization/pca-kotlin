package net.atlasauth.pca.scitt

/** In-memory [ScittLogStore]: forgets everything on restart. For tests only. */
class MemoryScittLogStore : ScittLogStore {
    private val entries = ArrayList<ByteArray>()
    private val nodes = HashMap<String, ByteArray>()

    @Synchronized override fun size(): Long = entries.size.toLong()

    @Synchronized override fun getEntry(index: Long): ByteArray? {
        if (index < 0 || index >= entries.size) return null
        return entries[index.toInt()].clone()
    }

    @Synchronized override fun getNode(level: Long, index: Long): ByteArray? = nodes["$level:$index"]?.clone()

    @Synchronized override fun append(expectedSize: Long, entry: ByteArray, nodes: List<ScittLogStore.StoredNode>): Boolean {
        if (entries.size.toLong() != expectedSize) return false
        entries.add(entry.clone())
        for (n in nodes) this.nodes["${n.level}:${n.index}"] = n.hash.clone()
        return true
    }
}
