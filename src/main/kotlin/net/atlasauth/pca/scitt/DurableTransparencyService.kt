package net.atlasauth.pca.scitt

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import net.atlasauth.pca.scitt.ScittLogStore.StoredNode
import net.atlasauth.pca.verifier.Keys

/**
 * A durable SCITT Transparency Service. The log keeps the hash of every complete aligned subtree in a [ScittLogStore], so an
 * append is O(log n) store reads and writes, the root is O(log n) and a proof O(log^2 n) reads. State lives entirely in the store you
 * supply (a database, an object store, a file): a restart loses nothing and the service holds no log state of its own.
 */
class DurableTransparencyService(private val store: ScittLogStore?, private val signer: Scitt.ReceiptSignerOpts) {
    /** The result of registering or re-issuing: index, receipt, root (b64u) and, for appendAndReceipt, the statement. */
    class Registration(
        @JvmField val index: Long,
        @JvmField val receipt: ByteArray,
        @JvmField val root: String,
        /** The signed statement (appendAndReceipt only), else null. */
        @JvmField val statement: ByteArray?,
    ) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            if (statement != null) m["statement"] = statement
            m["index"] = index
            m["receipt"] = receipt
            m["root"] = root
            return m
        }
    }

    private val st: ScittLogStore = store
        ?: throw ScittLogError("store_required", "a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default")
    private val reader = Reader(st)

    /** Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs). */
    private class Reader(private val store: ScittLogStore) {
        fun node(level: Long, index: Long): ByteArray {
            val h = store.getNode(level, index)
            if (h == null || h.size != 32) throw ScittLogError("store_corrupt", "missing or malformed subtree hash ($level, $index)")
            return h
        }

        fun range(lo: Long, n: Long): ByteArray {
            if (n == 1L) return node(0, lo)
            if (isPow2(n) && lo % n == 0L) return node(java.lang.Long.numberOfTrailingZeros(n).toLong(), lo / n)
            val k = largestPow2Below(n)
            return Rfc9162.nodeHash(range(lo, k), range(lo + k, n - k))
        }

        fun root(size: Long): ByteArray = if (size == 0L) Rfc9162.emptyRoot() else range(0, size)

        fun inclusion(index: Long, size: Long): List<ByteArray> = walk(0, size, index)

        private fun walk(lo: Long, n: Long, idx: Long): MutableList<ByteArray> {
            if (n == 1L) return ArrayList()
            val k = largestPow2Below(n)
            val out: MutableList<ByteArray>
            if (idx < k) {
                out = walk(lo, k, idx)
                out.add(range(lo + k, n - k))
            } else {
                out = walk(lo + k, n - k, idx - k)
                out.add(range(lo, k))
            }
            return out
        }

        fun consistency(m: Long, size: Long): List<ByteArray> = sub(0, size, m, true)

        private fun sub(lo: Long, n: Long, mm: Long, complete: Boolean): MutableList<ByteArray> {
            if (mm == n) {
                val out = ArrayList<ByteArray>()
                if (!complete) out.add(range(lo, n))
                return out
            }
            val k = largestPow2Below(n)
            val out: MutableList<ByteArray>
            if (mm <= k) {
                out = sub(lo, k, mm, complete)
                out.add(range(lo + k, n - k))
            } else {
                out = sub(lo + k, n - k, mm - k, false)
                out.add(range(lo, k))
            }
            return out
        }
    }

    fun size(): Long {
        val n = st.size()
        if (n < 0) throw ScittLogError("store_corrupt", "the store reported an invalid size")
        return n
    }

    /** The current tree root (b64u). */
    fun root(): String = Keys.b64u(reader.root(size()))

    private fun receiptFor(index: Long, size: Long, statement: ByteArray?): Registration {
        val root = reader.root(size)
        val proof = Scitt.inclusionProofMap(index, size, reader.inclusion(index, size))
        val r = Keys.b64u(root)
        return Registration(index, Scitt.buildReceipt(r, proof, signer), r, statement)
    }

    /** Append a Signed Statement (validated structurally first) and return its receipt against the new root. */
    fun register(statement: ByteArray): Registration {
        try {
            val cose = Scitt.decodeCoseSign1(statement)
            if (cose.payload == null) throw IllegalArgumentException("detached payload")
        } catch (e: RuntimeException) {
            throw ScittLogError("bad_statement", "cannot register: " + e.message)
        }
        for (attempt in 0 until MAX_APPEND_ATTEMPTS) {
            val n = size()
            val nodes = ArrayList<StoredNode>()
            var hash = Rfc9162.leafHash(statement)
            nodes.add(StoredNode(0, n, hash))
            // Completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored.
            var level = 1
            while (level < 62 && (n + 1) % (1L shl level) == 0L) {
                val idx = (n + 1) / (1L shl level) - 1
                val left = st.getNode((level - 1).toLong(), 2 * idx)
                if (left == null || left.size != 32) throw ScittLogError("store_corrupt", "missing subtree hash (${level - 1}, ${2 * idx})")
                hash = Rfc9162.nodeHash(left, hash)
                nodes.add(StoredNode(level.toLong(), idx, hash))
                level++
            }
            if (st.append(n, statement, nodes)) return receiptFor(n, n + 1, null)
        }
        throw ScittLogError("append_contention", "could not append: the log kept changing")
    }

    /** Sign [payload] as a Signed Statement, register it, and return the statement plus its receipt. */
    fun appendAndReceipt(payload: Any?, stmt: Scitt.SignStatementOpts): Registration {
        val statement = Scitt.signStatement(payload, stmt)
        val r = register(statement)
        return Registration(r.index, r.receipt, r.root, statement)
    }

    /** A receipt for an entry, against the CURRENT root. */
    fun getReceipt(index: Long): Registration {
        val size = size()
        if (index < 0 || index >= size) throw ScittLogError("out_of_range", "getReceipt: index out of range")
        return receiptFor(index, size, null)
    }

    fun getEntry(index: Long): ByteArray {
        val size = size()
        if (index < 0 || index >= size) throw ScittLogError("out_of_range", "getEntry: index out of range")
        return st.getEntry(index) ?: throw ScittLogError("store_corrupt", "entry $index is missing")
    }

    /** An RFC 9162 consistency proof that the first [oldSize] entries are a prefix of the current log. */
    fun consistencyProof(oldSize: Long): Scitt.ConsistencyProofResult {
        val size = size()
        if (oldSize < 1 || oldSize > size) throw ScittLogError("out_of_range", "consistencyProof: size out of range")
        val path = reader.consistency(oldSize, size)
        return Scitt.ConsistencyProofResult(
            oldSize, size, Keys.b64u(reader.root(oldSize)), Keys.b64u(reader.root(size)),
            Cbor.encode(listOf(oldSize, size, ArrayList<Any?>(path))),
        )
    }

    companion object {
        private const val MAX_APPEND_ATTEMPTS = 16

        internal fun isPow2(n: Long): Boolean = n > 0 && (n and (n - 1)) == 0L

        internal fun largestPow2Below(n: Long): Long {
            var k = 1L
            while (k * 2 < n) k *= 2
            return k
        }

        private fun filled(b: Int): ByteArray = ByteArray(32).also { it.fill(b.toByte()) }

        /**
         * Check a store implementation against the contract the service relies on. Returns the failures (empty = conforms): compare-and-set,
         * atomic entry-plus-nodes, immutability and a single winner among concurrent appends.
         */
        @JvmStatic
        fun checkScittLogStore(makeStore: () -> ScittLogStore): List<String> {
            val failures = ArrayList<String>()
            try {
                val s = makeStore()
                if (s.size() != 0L) failures.add("a new store is not empty")
                if (!s.append(0, byteArrayOf(1), listOf(StoredNode(0, 0, filled(1))))) failures.add("append at the right size was refused")
                if (s.append(0, byteArrayOf(2), listOf(StoredNode(0, 1, filled(2))))) failures.add("append at a stale size was accepted (no compare-and-set)")
                if (s.size() != 1L) failures.add("a refused append changed the size")
                if (s.getNode(0, 1) != null) failures.add("a refused append left a node behind (not atomic)")
                if (s.getEntry(1) != null) failures.add("a refused append left an entry behind")
                val e0 = s.getEntry(0)
                if (e0 == null || e0.size != 1 || e0[0] != 1.toByte()) failures.add("the stored entry does not read back")
                if (e0 != null && e0.isNotEmpty()) e0[0] = 9
                val again = s.getEntry(0)
                if (again == null || again.isEmpty() || again[0] != 1.toByte()) failures.add("a returned entry aliases the stored one (mutable)")
                val pool = Executors.newFixedThreadPool(4)
                try {
                    val racers = (1..4).map { k ->
                        pool.submit(Callable { s.append(1, byteArrayOf((10 + k).toByte()), listOf(StoredNode(0, 1, filled(10 + k)))) })
                    }
                    var wins = 0
                    for (f in racers) if (f.get()) wins++
                    if (wins != 1) failures.add("concurrent appends at the same size did not produce exactly one winner")
                } finally {
                    pool.shutdown()
                }
                if (s.size() != 2L) failures.add("the size after a race is not 2")
            } catch (e: Exception) {
                failures.add("the store threw: " + e.message)
            }
            return failures
        }
    }
}
