package net.atlasauth.pca.verifier

/**
 * Chain compaction: a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus the leaf hop. A
 * verifier that has verified the full chain once remembers it under that root ([Memo]); later presentations carry only
 * `{depth, hops_root, leaf}`.
 *
 * The root commits to the order and the number of hops. Nothing is trusted from the presentation: a compact chain is accepted only when
 * the verifier's OWN memo holds an entry for `hops_root` that its own chain verification produced ([Memo.rememberVerified] runs the
 * verification itself), the depth equals the memoized depth and the presented leaf hashes to the memoized last hop.
 */
object ChainCompact {
    const val CHAIN_HOP_DOMAIN = "atlas-pca/chain-hop/v1"

    /** A memo entry lives at most this long. */
    const val CHAIN_MEMO_MAX_TTL_MS = 3_600_000.0
    const val CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000
    const val MAX_CHAIN_DEPTH = Pca.MAX_CHAIN_HOPS

    /** The Merkle leaf of one hop: its content hash under a domain tag, `{d, hop}`. */
    fun hopLeaf(hop: Map<String, Any?>): Map<String, Any?> = linkedMapOf("d" to CHAIN_HOP_DOMAIN, "hop" to Pca.capHash(hop))

    /** The handle of a chain: Merkle root over the ordered hop leaves. */
    fun hopsRoot(chain: List<Any?>): String = Pca.merkleRoot(chain.map { hopLeaf(Pca.asMap(it)) })

    /** Fold a chain into `{v:1, kind, depth, hops_root, leaf}`. Throws on an empty or over-deep chain. Does not verify it (the memo does). */
    fun compactChain(chain: List<Any?>): Map<String, Any?> {
        require(chain.isNotEmpty() && chain.size <= MAX_CHAIN_DEPTH) { "compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops" }
        return linkedMapOf(
            "v" to 1L, "kind" to "pca-chain-compact", "depth" to chain.size.toLong(),
            "hops_root" to hopsRoot(chain), "leaf" to chain[chain.size - 1],
        )
    }

    /** Why a presented compact chain is malformed, or null. */
    fun compactChainShapeError(c: Any?): String? {
        if (c !is Map<*, *>) return "not an object"
        val required = listOf("v", "kind", "depth", "hops_root", "leaf")
        for (k in c.keys) if (k !in required) return "unknown member 'compact chain.$k'"
        for (k in required) if (!c.containsKey(k)) return "missing member 'compact chain.$k'"
        if (num(c["v"]) != 1.0 || c["kind"] != "pca-chain-compact") return "not a pca-chain-compact v1"
        val d = c["depth"]
        val dn = num(d)
        if (!(Json.isSafeInt(d) && dn != null && dn >= 1 && dn <= MAX_CHAIN_DEPTH)) return "depth must be 1..$MAX_CHAIN_DEPTH"
        val r = c["hops_root"]
        if (r !is String || r.length != 43) return "hops_root must be a 43 character digest"
        if (c["leaf"] !is Map<*, *>) return "leaf must be a capability"
        return null
    }

    private fun num(v: Any?): Double? = when (v) {
        is Json.Num -> v.raw.toDoubleOrNull()
        is Number -> v.toDouble()
        else -> null
    }

    private fun safeClock(now: Double): Boolean = !(now.isNaN() || now.isInfinite() || now != Math.rint(now) || Math.abs(now) > 9007199254740991.0)

    /** What the caveat language needs of a chain: hop count, per-hop hash and caveat-list length, and the leaf. */
    interface ChainView {
        fun n(): Int
        fun leaf(): Map<String, Any?>
        fun hash(i: Int): String
        fun count(i: Int): Int
    }

    private fun caveatCount(h: Map<String, Any?>): Int = (h["caveats"] as? List<*>)?.size ?: 0

    /** The view of a full chain (root first), else of the grant alone. */
    fun viewOfChain(grant: Map<String, Any?>, chain: List<Any?>?): ChainView {
        val hops: List<Any?> = if (chain != null && chain.isNotEmpty()) chain else listOf<Any?>(grant)
        val cache = arrayOfNulls<String>(hops.size)
        return object : ChainView {
            override fun n(): Int = hops.size
            override fun leaf(): Map<String, Any?> = Pca.asMap(hops[hops.size - 1])
            override fun hash(i: Int): String = cache[i] ?: Pca.capHash(Pca.asMap(hops[i])).also { cache[i] = it }
            override fun count(i: Int): Int = caveatCount(Pca.asMap(hops[i]))
        }
    }

    private class Entry(val depth: Int, val hashes: List<String>, val counts: List<Int>, val expiresAt: Double)

    /** The outcome of [Memo.resolve]: [view] when ok, else [reason]. */
    class Resolved internal constructor(val ok: Boolean, val view: ChainView?, val reason: String?)

    /** The verifier's memory of chains it verified itself. Thread-safe. */
    class Memo @JvmOverloads constructor(private val maxEntries: Int? = null, private val ttlMs: Double? = null) {
        private val entries = LinkedHashMap<String, Entry>()

        @Synchronized fun size(): Int = entries.size

        /**
         * Verify [chain] (rooted at [expectedRootIssuer]) with the full verifier and remember it; returns the compact form a holder
         * presents. Throws when the chain does not verify or the memo is full of live entries (a full memo never evicts a live entry, so
         * one tenant cannot push another out).
         */
        @Synchronized
        fun rememberVerified(chain: List<Any?>, expectedRootIssuer: String, now: Double): Map<String, Any?> {
            check(safeClock(now)) { "rememberVerified: the clock is not a safe integer" }
            val why = Pca.verifyChain(chain, expectedRootIssuer, true, null)
            check(why.isEmpty()) { "rememberVerified: the chain does not verify: $why" }
            val compact = compactChain(chain)
            val ttl = Math.min(ttlMs ?: CHAIN_MEMO_MAX_TTL_MS, CHAIN_MEMO_MAX_TTL_MS)
            prune(now)
            val root = compact["hops_root"] as String
            check(entries.containsKey(root) || entries.size < (maxEntries ?: CHAIN_MEMO_DEFAULT_MAX_ENTRIES)) { "rememberVerified: the memo is full of live entries" }
            val hashes = ArrayList<String>()
            val counts = ArrayList<Int>()
            for (h in chain) {
                hashes.add(Pca.capHash(Pca.asMap(h)))
                counts.add(caveatCount(Pca.asMap(h)))
            }
            entries[root] = Entry(chain.size, hashes, counts, now + ttl)
            return compact
        }

        /** Drop entries whose time is up. */
        @Synchronized fun prune(now: Double) { entries.values.removeIf { !(now.isFinite() && it.expiresAt >= now) } }

        /** Forget a chain (for example when it is revoked). */
        @Synchronized fun forget(hopsRoot: String): Boolean = entries.remove(hopsRoot) != null

        private fun no(r: String) = Resolved(false, null, r)

        /** Resolve a presented compact chain against the memo. Total. */
        @Synchronized
        fun resolve(compact: Any?, now: Double): Resolved {
            try {
                if (!safeClock(now)) return no("the verifier clock is not a safe integer (fail closed)")
                val e = compactChainShapeError(compact)
                if (e != null) return no("malformed compact chain: $e")
                val c = Pca.asMap(compact)
                val root = c["hops_root"] as String
                val m = entries[root] ?: return no("the chain is not in this verifier memo (present the full chain)")
                if (!(m.expiresAt >= now)) {
                    entries.remove(root)
                    return no("the memoized chain has expired (present the full chain)")
                }
                if (m.depth != num(c["depth"])!!.toInt()) return no("the depth differs from the memoized chain")
                val leaf = Pca.asMap(c["leaf"])
                if (Pca.capHash(leaf) != m.hashes[m.depth - 1]) return no("the leaf is not the memoized last hop")
                if (leaf["caveats"] !is List<*> || caveatCount(leaf) != m.counts[m.depth - 1]) return no("the leaf caveats differ from the memoized chain")
                return Resolved(
                    true,
                    object : ChainView {
                        override fun n(): Int = m.depth
                        override fun leaf(): Map<String, Any?> = leaf
                        override fun hash(i: Int): String = m.hashes[i]
                        override fun count(i: Int): Int = m.counts[i]
                    },
                    null,
                )
            } catch (err: RuntimeException) {
                return no("compact chain error (fail closed): " + (err.message ?: "unknown"))
            }
        }
    }
}
