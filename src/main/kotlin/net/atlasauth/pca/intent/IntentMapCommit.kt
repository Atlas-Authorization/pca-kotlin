package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.IntentMap
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The builder side of the committed Intent Map (Merkle form, per-leaf salts derived from one session secret): the leaf layout,
 * salts, tree and Z0 disclosure that the verifier side checks. Inputs and outputs are plain JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentMapCommit {
    /** Informative per-leaf salt derivation tag (wallet side). */
    const val MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\u0000"

    /** One committed leaf: its kind, its (normalised) JSON and its salt. */
    class Leaf internal constructor(@JvmField val kind: String, @JvmField val leaf: Any?, @JvmField val salt: ByteArray)

    class CommittedMap internal constructor(
        @JvmField val mapCommit: String,
        @JvmField val size: Int,
        @JvmField val leaves: List<Leaf>,
        private val hashes: List<ByteArray>,
        private val full: List<Map<String, Any?>>,
    ) {
        /** The leaves as JSON: [{kind, leaf, salt}]. */
        fun leavesJson(): List<Any?> = leaves.map { l -> linkedMapOf("kind" to l.kind, "leaf" to l.leaf, "salt" to Pca.b64(l.salt)) }

        private fun entry(i: Int): Map<String, Any?> {
            val out = ArrayList<ByteArray>()
            auditPath(hashes, i, out)
            return linkedMapOf("index" to i.toLong(), "salt" to Pca.b64(leaves[i].salt), "leaf" to leaves[i].leaf, "path" to out.map { Pca.b64(it) })
        }

        /** Z0 disclosure for an action; throws when the action lies outside the map. */
        fun disclose(verb: String, resource: Any?, params: Any?): Map<String, Any?> {
            val hi = full.indexOfFirst { it["verb"] == verb }
            require(hi >= 0) { "commitMap.disclose: verb $verb is not in the map" }
            val w = IntentMap.cellOf(full[hi], resource, params)
            requireNotNull(w) { "commitMap.disclose: the action lies outside the committed map's dimension" }
            return linkedMapOf(
                "size" to size.toLong(),
                "header" to entry(hi),
                "cell" to entry((IntentJs.lng(full[hi]["first"]) + w.second).toInt()),
                "metrics" to entry(size - 2),
            )
        }
    }

    private fun split(n: Long): Long {
        var k = 1L
        while (k * 2 < n) k *= 2
        return k
    }

    private fun treeRoot(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        val k = split(hs.size.toLong()).toInt()
        return IntentMap.nodeHash(treeRoot(hs.subList(0, k)), treeRoot(hs.subList(k, hs.size)))
    }

    private fun auditPath(hs: List<ByteArray>, idx: Int, out: MutableList<ByteArray>) {
        if (hs.size == 1) return
        val k = split(hs.size.toLong()).toInt()
        if (idx < k) {
            auditPath(hs.subList(0, k), idx, out)
            out.add(treeRoot(hs.subList(k, hs.size)))
        } else {
            auditPath(hs.subList(k, hs.size), idx - k, out)
            out.add(treeRoot(hs.subList(0, k)))
        }
    }

    /** Per-leaf salt: SHA-256(TAG_SALT || secret || u64be(index)). */
    fun mapLeafSalt(secret: ByteArray, index: Long): ByteArray = Pca.sha(IntentJs.utf8(MAP_TAG_SALT), secret, IntentMap.u64be(index))

    private fun dimCells(d: Map<String, Any?>): Long = if ("num" == d["kind"]) IntentMap.numCells(d).size.toLong() else (d["values"] as List<*>).size.toLong()

    /**
     * Build the committed form. headers: [{verb, dims}], cells: verb -> [{cell, p_ppm, in_grant}] in flat order,
     * metrics: the metrics leaf, learnerDigest: the learner settings' content address. Throws on a malformed input.
     */
    fun commitMap(headers: List<Map<String, Any?>>, cells: Map<String, List<Map<String, Any?>>>, metrics: Map<String, Any?>, learnerDigest: String, secret: ByteArray?): CommittedMap {
        require(secret != null && secret.size == 32) { "commitMap: the secret is 32 bytes" }
        val heads = ArrayList(headers)
        heads.sortWith { a, b -> Json.compareUtf8(a["verb"] as String, b["verb"] as String) }
        for (i in 1 until heads.size) require(heads[i]["verb"] != heads[i - 1]["verb"]) { "commitMap: duplicate verb" }
        val counts = LongArray(heads.size)
        for (i in counts.indices) {
            var n = 1L
            for (d in heads[i]["dims"] as List<Any?>) n *= dimCells(d as Map<String, Any?>)
            counts[i] = n
        }
        var next = heads.size.toLong()
        val full = ArrayList<Map<String, Any?>>()
        for (i in heads.indices) {
            full.add(linkedMapOf("verb" to heads[i]["verb"], "first" to next, "cells" to counts[i], "dims" to heads[i]["dims"]))
            next += counts[i]
        }
        val kinds = ArrayList<String>()
        val leaves = ArrayList<Any?>()
        for (h in full) { kinds.add("header"); leaves.add(h) }
        for (h in full) {
            val cs = cells[h["verb"] as String]
            require(cs != null && cs.size.toLong() == h["cells"] as Long) { "commitMap: verb ${h["verb"]} needs ${h["cells"]} cell leaves" }
            for (c in cs) {
                kinds.add("cell")
                leaves.add(linkedMapOf("verb" to h["verb"], "cell" to c["cell"], "p_ppm" to c["p_ppm"], "in_grant" to c["in_grant"]))
            }
        }
        kinds.add("metrics")
        leaves.add(metrics)
        kinds.add("learner")
        leaves.add(linkedMapOf("learner_digest" to learnerDigest))
        for (i in leaves.indices) {
            val leaf = leaves[i]
            val e = when (kinds[i]) {
                "header" -> IntentMap.headerError(leaf)
                "cell" -> IntentMap.cellError(leaf)
                "metrics" -> IntentMap.metricsError(leaf)
                else -> IntentMap.learnerError(leaf)
            }
            require(e == null) { "commitMap: $e" }
        }
        require(!(leaves.size < 4 || leaves.size > IntentMap.MAX_MAP_LEAVES)) { "commitMap: the map has too few or too many leaves" }
        val out = ArrayList<Leaf>()
        val hashes = ArrayList<ByteArray>()
        for (i in leaves.indices) {
            val salt = mapLeafSalt(secret, i.toLong())
            val norm = IntentJs.normalize(leaves[i])
            out.add(Leaf(kinds[i], norm, salt))
            hashes.add(IntentMap.leafHash(kinds[i], salt, norm))
        }
        return CommittedMap(IntentMap.commitOf(hashes.size.toLong(), treeRoot(hashes)), hashes.size, out, hashes, IntentJs.normalize(full) as List<Map<String, Any?>>)
    }
}
