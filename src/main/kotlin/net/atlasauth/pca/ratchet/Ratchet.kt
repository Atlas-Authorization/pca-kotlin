package net.atlasauth.pca.ratchet

import java.math.BigDecimal
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The Capability Ratchet: puncturable forward-secure capability keys (cryptographic one-time-use). A holder commits, up front, to a Merkle
 * root over 2^depth one-time Ed25519 leaf keys derived from a GGM puncturable-PRF tree; signing at a leaf produces an offline-verifiable
 * signature AND returns a state in which that leaf is PUNCTURED: its key material is dropped and can never be re-derived, so the same leaf
 * can never sign twice ("already spent" becomes "key no longer exists").
 *
 * The PRG is HMAC-SHA256 (a PRF), `PRG(seed) = (HMAC(seed, D||0x00), HMAC(seed, D||0x01))`. The secret state is a co-path of disjoint covering
 * node seeds whose subtrees are exactly the leaves that can still sign; puncturing expands the covering node down to the leaf, keeps every
 * off-path sibling and drops every on-path seed.
 */
object Ratchet {
    /** Longest tree accepted: setup derives all 2^depth leaf public keys, so this bounds that cost. */
    const val MAX_RATCHET_DEPTH = 20

    private val PRG_DOMAIN = "atlas-pca-ratchet/ggm-prg/v1".toByteArray(Charsets.UTF_8)
    private val LEAFKEY_DOMAIN = "atlas-pca-ratchet/ggm-leafkey/v1".toByteArray(Charsets.UTF_8)
    private val ROOT_DOMAIN = "atlas-pca-ratchet/ggm-root/v1".toByteArray(Charsets.UTF_8)
    private val NULLIFIER_DOMAIN = "atlas-pca-ratchet/nullifier/v1\u0000".toByteArray(Charsets.UTF_8)
    private val SIG_DOMAIN = "atlas-pca-ratchet/leaf-sig/v1\u0000".toByteArray(Charsets.UTF_8)

    /** A covering node of the secret co-path: [level] 0 is the root, `depth` a leaf. */
    class CoverNode internal constructor(val level: Int, val nodeIndex: Long, internal val seed: ByteArray)

    /**
     * The live ratchet. [leafPubKeys] are public. `covering` is the SECRET co-path: punctured leaves are absent from every covering subtree.
     * Immutable: signing returns a new state.
     */
    class RatchetState internal constructor(
        val depth: Int,
        val leafCount: Long,
        val rootCommitment: String,
        val leafPubKeys: List<String>,
        internal val covering: Map<String, CoverNode>,
    )

    /** The result of [deriveRatchetRoot]. */
    class Derived internal constructor(val rootCommitment: String, val state: RatchetState)

    /** The result of [signAtLeaf]: the signature (a JSON-shaped map: edSig, leafPubKey, merklePath, nullifier) and the punctured state. */
    class Signed internal constructor(val signature: Map<String, Any?>, val newState: RatchetState)

    // ---- GGM ----

    private fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    private fun prg(seed: ByteArray, bit: Int): ByteArray {
        val m = PRG_DOMAIN.copyOf(PRG_DOMAIN.size + 1)
        m[PRG_DOMAIN.size] = bit.toByte()
        return hmac(seed, m)
    }

    private fun leafSigningSeed(leafSeed: ByteArray): ByteArray = hmac(leafSeed, LEAFKEY_DOMAIN)

    private fun leafPublicKey(leafSeed: ByteArray): String = Keys.b64u(Keys.edFromSeed(leafSigningSeed(leafSeed)).pub)

    private fun covers(level: Int, nodeIndex: Long, leafIndex: Long, depth: Int): Boolean = (leafIndex ushr (depth - level)) == nodeIndex

    /** The bit chosen when descending from [level] towards [leafIndex] (0 = left, 1 = right). */
    private fun descendBit(level: Int, leafIndex: Long, depth: Int): Int = ((leafIndex ushr (depth - level - 1)) and 1L).toInt()

    private fun deriveLeafSeed(node: CoverNode, leafIndex: Long, depth: Int): ByteArray {
        var seed = node.seed
        for (level in node.level until depth) seed = prg(seed, descendBit(level, leafIndex, depth))
        return seed
    }

    /** The off-path siblings that together cover every leaf under [node] except [leafIndex]; the on-path seeds are never returned. */
    private fun punctureSiblings(node: CoverNode, leafIndex: Long, depth: Int): List<CoverNode> {
        val out = ArrayList<CoverNode>()
        var seed = node.seed
        var nodeIndex = node.nodeIndex
        for (level in node.level until depth) {
            val bit = descendBit(level, leafIndex, depth)
            val left = prg(seed, 0)
            val right = prg(seed, 1)
            val childBase = nodeIndex * 2
            out.add(CoverNode(level + 1, childBase + (1 - bit), if (bit == 0) right else left))
            seed = if (bit == 0) left else right
            nodeIndex = childBase + bit
        }
        return out
    }

    private fun allLeaves(seed: ByteArray, level: Int, depth: Int, base: Int, out: Array<String?>) {
        if (level == depth) {
            out[base] = leafPublicKey(seed)
            return
        }
        val half = 1 shl (depth - level - 1)
        allLeaves(prg(seed, 0), level + 1, depth, base, out)
        allLeaves(prg(seed, 1), level + 1, depth, base + half, out)
    }

    private fun coverKey(level: Int, nodeIndex: Long): String = "$level:$nodeIndex"

    // ---- Merkle (RFC 6962 shape, over the base64url leaf public keys) ----

    private fun merkleRoot(leaves: List<String>): String = Pca.merkleRoot(ArrayList<Any?>(leaves))

    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }

    private fun prove(leaves: List<String>, idx: Int, out: MutableList<Any?>) {
        if (leaves.size == 1) return
        val k = split(leaves.size)
        val step = LinkedHashMap<String, Any?>()
        if (idx < k) {
            prove(leaves.subList(0, k), idx, out)
            step["side"] = "R"
            step["hash"] = merkleRoot(leaves.subList(k, leaves.size))
        } else {
            prove(leaves.subList(k, leaves.size), idx - k, out)
            step["side"] = "L"
            step["hash"] = merkleRoot(leaves.subList(0, k))
        }
        out.add(step)
    }

    private fun merkleProof(leaves: List<String>, index: Int, indexOut: Any?): Map<String, Any?> {
        val path = ArrayList<Any?>()
        prove(leaves, index, path)
        val proof = LinkedHashMap<String, Any?>()
        proof["index"] = indexOut
        proof["size"] = leaves.size.toLong()
        proof["path"] = path
        return proof
    }

    // ---- public API ----

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    internal fun jsNum(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    internal fun isNegZero(d: Double): Boolean = d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L

    private fun isInt(d: Double): Boolean = !d.isNaN() && !d.isInfinite() && d == Math.rint(d)

    /** A leaf index as the reference's BigInt(x) takes it: an integer-valued number; anything else throws (a TypeError / RangeError there). */
    private fun leafLong(leafIndex: Any?): Long {
        if (leafIndex is Boolean) return if (leafIndex) 1L else 0L
        if (leafIndex is String) {
            val t = leafIndex.trim()
            return if (t.isEmpty()) 0L else t.toLongOrNull() ?: throw IllegalArgumentException("leafIndex is not an integer")
        }
        val d = jsNum(leafIndex)
        if (d == null || !isInt(d)) throw IllegalArgumentException("leafIndex is not an integer")
        return BigDecimal(d).toBigInteger().toLong()
    }

    /** The per-leaf nullifier a verifier records to detect leaf reuse: `b64u(sha256(domain || len(root) || root || index))`. */
    @JvmStatic
    fun leafNullifier(rootCommitment: String, leafIndex: Any?): String {
        val root = Json.utf8(rootCommitment)
        val out = ByteBuffer.allocate(NULLIFIER_DOMAIN.size + 4 + root.size + 8)
        out.put(NULLIFIER_DOMAIN)
        out.putInt(root.size)
        out.put(root)
        out.putLong(leafLong(leafIndex))
        return Keys.b64u(sha256(out.array()))
    }

    /** The signed message: domain, the 8-byte big-endian leaf index (so a signature cannot be lifted elsewhere), then the message. */
    private fun leafSigMessage(leafIndex: Any?, message: ByteArray): ByteArray {
        val out = ByteBuffer.allocate(SIG_DOMAIN.size + 8 + message.size)
        out.put(SIG_DOMAIN)
        out.putLong(leafLong(leafIndex))
        out.put(message)
        return out.array()
    }

    /**
     * Build a ratchet from a root seed (at least 32 bytes of entropy) and a tree depth in [1, MAX_RATCHET_DEPTH]. [depth] is any value (a
     * non-integer is refused as invalid_depth, as in the reference).
     */
    @JvmStatic
    fun deriveRatchetRoot(seed: ByteArray?, depth: Any?): Derived {
        val d = jsNum(depth)
        if (d == null || !isInt(d) || d < 1 || d > MAX_RATCHET_DEPTH) {
            throw RatchetError("invalid_depth", "depth must be an integer in [1, $MAX_RATCHET_DEPTH]")
        }
        if (seed == null || seed.size < 32) throw RatchetError("invalid_seed", "seed must be a Uint8Array of at least 32 bytes")
        val dep = d.toInt()
        val root = hmac(seed, ROOT_DOMAIN)
        val pubs = arrayOfNulls<String>(1 shl dep)
        allLeaves(root, 0, dep, 0, pubs)
        val leafPubKeys: List<String> = java.util.Collections.unmodifiableList(pubs.map { it!! })
        val rootCommitment = merkleRoot(leafPubKeys)
        val covering = LinkedHashMap<String, CoverNode>()
        covering[coverKey(0, 0)] = CoverNode(0, 0, root)
        return Derived(rootCommitment, RatchetState(dep, 1L shl dep, rootCommitment, leafPubKeys, covering))
    }

    private fun findCovering(state: RatchetState, leafIndex: Long): CoverNode? =
        state.covering.values.firstOrNull { covers(it.level, it.nodeIndex, leafIndex, state.depth) }

    private fun checkedLeaf(state: RatchetState, leafIndex: Any?): Long {
        val d = jsNum(leafIndex)
        if (d == null || !isInt(d) || d < 0 || d >= state.leafCount) {
            throw RatchetError("leaf_out_of_range", "leaf $leafIndex is out of range [0, ${state.leafCount})")
        }
        return d.toLong()
    }

    /**
     * Sign [message] at leaf [leafIndex], then puncture that leaf. Throws [RatchetError] if the leaf is out of range or already punctured (a
     * spent leaf can never sign again).
     */
    @JvmStatic
    fun signAtLeaf(state: RatchetState, leafIndex: Any?, message: ByteArray): Signed {
        val idx = checkedLeaf(state, leafIndex)
        val node = findCovering(state, idx) ?: throw RatchetError("leaf_punctured", "leaf $idx is already punctured (spent) and cannot sign")
        val leafSeed = deriveLeafSeed(node, idx, state.depth)
        val key = Keys.edFromSeed(leafSigningSeed(leafSeed))
        val edSig = Keys.b64u(key.sign(leafSigMessage(idx, message)))
        val leafPub = Keys.b64u(key.pub)
        // the reference copies the caller's index into the proof, so a negative zero stays one (and such a proof never verifies, as there)
        val given = jsNum(leafIndex)
        val indexOut: Any = if (given != null && isNegZero(given)) Json.Num("-0") else idx
        val merklePath = merkleProof(state.leafPubKeys, idx.toInt(), indexOut)
        val covering = LinkedHashMap(state.covering)
        covering.remove(coverKey(node.level, node.nodeIndex))
        for (sib in punctureSiblings(node, idx, state.depth)) covering[coverKey(sib.level, sib.nodeIndex)] = sib
        val sig = LinkedHashMap<String, Any?>()
        sig["edSig"] = edSig
        sig["leafPubKey"] = leafPub
        sig["merklePath"] = merklePath
        sig["nullifier"] = leafNullifier(state.rootCommitment, idx)
        return Signed(sig, RatchetState(state.depth, state.leafCount, state.rootCommitment, state.leafPubKeys, covering))
    }

    /**
     * Verify a ratchet signature offline against the root commitment, with no shared state: the Ed25519 signature must be valid under
     * `leafPubKey` and `merklePath` must prove it is the leaf at [leafIndex] under [rootCommitment]. Never throws.
     */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun verifyLeafSignature(rootCommitment: String, leafIndex: Any?, message: ByteArray, signature: Any?): Boolean {
        try {
            if (signature !is Map<*, *> && signature !is List<*>) return false
            val s: Map<*, *> = signature as? Map<*, *> ?: LinkedHashMap<Any?, Any?>()
            val edSig = s["edSig"]
            val leafPubKey = s["leafPubKey"]
            val merklePath = s["merklePath"]
            val nullifier = s["nullifier"]
            if (nullifier !is String || nullifier != leafNullifier(rootCommitment, leafIndex)) return false
            if (edSig !is String || leafPubKey !is String || merklePath == null || !(merklePath is Map<*, *> || merklePath is List<*>)) return false
            val mi = if (merklePath is Map<*, *>) jsNum(merklePath["index"]) else null
            val li = jsNum(leafIndex)
            if (mi == null || li == null) return false
            val miv: Double = mi
            val liv: Double = li
            if (miv != liv) return false // IEEE comparison: -0 equals 0 here, refused just below
            // the inclusion verifier refuses a negative-zero index and any hash suite but sha256
            if (isNegZero(miv)) return false
            val mp = merklePath as Map<*, *>
            if (mp.containsKey("hash_suite") && "sha256" != mp["hash_suite"]) return false
            val pk = Pca.decodeB64uStrict(leafPubKey, 32)
            val sg = Pca.decodeB64uStrict(edSig, 64)
            if (pk == null || sg == null || !Pca.ed25519Strict(pk, leafSigMessage(leafIndex, message), sg)) return false
            return Pca.verifyInclusion(rootCommitment, mp as Map<String, Any?>, leafPubKey)
        } catch (e: RuntimeException) {
            return false
        }
    }

    /** Indices of leaves that can still sign (not yet punctured), ascending. */
    @JvmStatic
    fun availableLeaves(state: RatchetState): List<Long> {
        val out = ArrayList<Long>()
        for (n in state.covering.values) {
            val span = 1L shl (state.depth - n.level)
            val base = n.nodeIndex * span
            for (i in 0 until span) out.add(base + i)
        }
        out.sort()
        return out
    }

    /**
     * Whether leaf [leafIndex] can still sign. As in the reference, the test is `floor(leafIndex / 2^(depth-level)) === nodeIndex` on JavaScript
     * numbers, so a fractional index inside a covered subtree reads as available; NaN, infinities and other types are not.
     */
    @JvmStatic
    fun isLeafAvailable(state: RatchetState, leafIndex: Any?): Boolean {
        val d = jsNum(leafIndex)
        if (d == null || d.isNaN()) return false
        for (n in state.covering.values) {
            if (Math.floor(d / Math.pow(2.0, (state.depth - n.level).toDouble())) == n.nodeIndex.toDouble()) return true
        }
        return false
    }
}
