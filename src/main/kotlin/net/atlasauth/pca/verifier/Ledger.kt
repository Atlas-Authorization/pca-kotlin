package net.atlasauth.pca.verifier

import java.security.MessageDigest

/**
 * Transparency-ledger verification (extension layer; packages/pca/src/ledger.ts): RFC 6962 inclusion of ledger commits, RFC 9162
 * consistency, guardian-signed tree heads, witness cosignatures, head-to-head consistency, checkpoint chains and legacy witnessed
 * heads. Inputs are parsed JSON values ([Json.parseLenient]) so a hostile wire object cannot throw out of any function here: every
 * verifier returns false on malformed input. Every suite the SDK verifies (ed25519, ML-DSA, hybrids) is accepted via [IntentJs.verifyPinnedSuite]; a PQ
 * key verifies only under a verifier pin (`pins`: identity b64u to ML-DSA public key), an unknown suite is refused (false).
 */
object Ledger {
    const val STH_DOMAIN = "atlas-pca/sth/v1\u0000"
    const val STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\u0000"
    const val LEDGER_HEAD_DOMAIN = "atlas-pca/ledger-head/v1\u0000"

    /** The longest consistency path any tree of fewer than 2^53 leaves can need (2*53+1), plus one of slack as the reference. */
    private const val MAX_CONSISTENCY_PATH = 2 * 53 + 2

    private fun sha(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /** The root of the empty tree (RFC 9162 2.1.1: SHA-256 of the empty string), base64url. */
    val EMPTY_TREE_ROOT: String = Pca.b64(sha(ByteArray(0)))

    private fun node(l: ByteArray, r: ByteArray): ByteArray = sha(byteArrayOf(1) + l + r)

    @Suppress("UNCHECKED_CAST")
    private fun map(v: Any?): Map<String, Any?>? = v as? Map<String, Any?>

    private fun str(m: Map<String, Any?>, k: String): String? = m[k] as? String

    /** A JavaScript safe integer (JSON number, integral, |n| <= 2^53-1). */
    internal fun safeInt(v: Any?): Double? = if (IntentJs.isSafeInteger(v)) IntentJs.num(v) else null

    /** The pins a policy carries (`policy.pqPins`), the default pin for witness cosignatures. */
    @Suppress("UNCHECKED_CAST")
    private fun policyPins(policy: Map<String, Any?>?): Map<String, Any?>? = policy?.get("pqPins") as? Map<String, Any?>

    /**
     * The artifact's suite signature over `domain || strictCanonical(body + suite fields)` under identity `pub` (b64u): ed25519
     * as before, ML-DSA / hybrid only under a pin. An unknown or non-string `alg` is false.
     */
    internal fun signed(m: Map<String, Any?>, pub: String, domain: String, body: Map<String, Any?>, pins: Map<String, Any?>?): Boolean {
        val algPresent = m.containsKey("alg")
        if (Pq.resolveSigAlg(m["alg"], algPresent) == null) return false
        val msg = try {
            IntentJs.message(domain, IntentJs.bindSuiteFields(body, m["alg"], algPresent, m["pq_pk"], m.containsKey("pq_pk")))
        } catch (e: IllegalArgumentException) { return false }
        return IntentJs.verifyPinnedSuite(m["alg"], algPresent, pub, m["pq_pk"], msg, m["sig"], m["pq_sig"], pins)
    }

    /** The named members; null when one is absent (the reference throws on undefined). */
    private fun pick(m: Map<String, Any?>, vararg keys: String): LinkedHashMap<String, Any?>? {
        val out = LinkedHashMap<String, Any?>()
        for (k in keys) {
            if (!m.containsKey(k)) return null
            out[k] = m[k]
        }
        return out
    }

    /** JavaScript `===` on JSON values (compared through their strict canonical form; both must be canonicalizable). */
    internal fun same(a: Any?, b: Any?): Boolean = try {
        Json.canonicalizeStrict(a) == Json.canonicalizeStrict(b)
    } catch (e: IllegalArgumentException) {
        false
    }

    /** Checks a ledger commit (string leaf) against a root with an RFC 6962 inclusion proof. */
    @JvmStatic
    fun verifyInclusion(root: String, proof: Any?, commit: Any?): Boolean {
        val p = map(proof) ?: return false
        return Pca.verifyInclusion(root, p, commit)
    }

    /**
     * RFC 9162 2.1.4.2 consistency verification. Sizes are JSON safe integers; the index arithmetic is done in 64-bit so sizes 3 and
     * 3+2^32 never collide. Size 0 pins `oldRoot` to the empty-tree root and requires an empty path. Never throws.
     */
    @JvmStatic
    fun verifyConsistency(oldRoot: Any?, newRoot: Any?, proof: Any?): Boolean = try {
        consistency(oldRoot, newRoot, proof)
    } catch (e: RuntimeException) {
        false
    }

    private fun consistency(oldRoot: Any?, newRoot: Any?, proof: Any?): Boolean {
        val oldR = oldRoot as? String ?: return false
        val newR = newRoot as? String ?: return false
        val p = map(proof) ?: return false
        val ff = safeInt(p["oldSize"]) ?: return false
        val sf = safeInt(p["newSize"]) ?: return false
        val rawPath = p["path"] as? List<*> ?: return false
        if (ff < 0 || ff > sf || rawPath.size > MAX_CONSISTENCY_PATH) return false
        val first = ff.toLong()
        val second = sf.toLong()
        if (first == 0L) {
            if (rawPath.isNotEmpty() || oldR != EMPTY_TREE_ROOT) return false
            if (second == 0L) return newR == EMPTY_TREE_ROOT
            return true // vacuous for a non-empty new tree
        }
        if (first == second) return rawPath.isEmpty() && oldR == newR
        val path = ArrayList<ByteArray>(rawPath.size + 1)
        if ((first and (first - 1)) == 0L) path.add(Pca.decodeB64uStrict(oldR, -1) ?: return false)
        for (e in rawPath) {
            val s = e as? String ?: return false
            path.add(Pca.decodeB64uStrict(s, -1) ?: return false)
        }
        if (path.isEmpty()) return false
        var fn = first - 1
        var sn = second - 1
        while ((fn and 1L) == 1L) {
            fn = fn ushr 1
            sn = sn ushr 1
        }
        var fr = path[0]
        var sr = path[0]
        for (i in 1 until path.size) {
            val c = path[i]
            if (sn == 0L) return false
            if ((fn and 1L) == 1L || fn == sn) {
                fr = node(c, fr)
                sr = node(c, sr)
                while ((fn and 1L) == 0L && fn != 0L) {
                    fn = fn ushr 1
                    sn = sn ushr 1
                }
            } else {
                sr = node(sr, c)
            }
            fn = fn ushr 1
            sn = sn ushr 1
        }
        return sn == 0L && Pca.b64(fr) == oldR && Pca.b64(sr) == newR
    }

    /** Verifies a legacy witnessed head `{principal, size, root, witness, sig}` against the witness key. */
    @JvmStatic
    fun verifyWitnessedHead(wh: Any?, witnessPublic: String, pins: Map<String, Any?>? = null): Boolean {
        val m = map(wh) ?: return false
        if (str(m, "witness") != witnessPublic) return false
        val body = pick(m, "principal", "size", "root") ?: return false
        return signed(m, witnessPublic, LEDGER_HEAD_DOMAIN, body, pins)
    }

    /** True when `a` and `b` are both validly witnessed by the witness for the same principal and size but carry different roots (a split view). */
    @JvmStatic
    fun detectEquivocation(a: Any?, b: Any?, witnessPublic: String, pins: Map<String, Any?>? = null): Boolean {
        val am = map(a) ?: return false
        val bm = map(b) ?: return false
        if (!verifyWitnessedHead(a, witnessPublic, pins) || !verifyWitnessedHead(b, witnessPublic, pins)) return false
        val asz = IntentJs.num(am["size"])
        val bsz = IntentJs.num(bm["size"])
        return same(am["principal"], bm["principal"]) && asz == bsz && am["root"] as? String != bm["root"] as? String
    }

    /** Verifies one cosignature of a tree head under a trusted witness key, bound to the head's `{instance_id, principal, size, root, prev_root, guardian_epoch (absent or null = 0)}`. */
    @JvmStatic
    fun verifyWitnessCosignature(sth: Any?, cosig: Any?, witnessPublic: String, pins: Map<String, Any?>? = null): Boolean {
        val sm = map(sth) ?: return false
        val cm = map(cosig) ?: return false
        if (str(cm, "key") != witnessPublic || cm["sig"] !is String) return false
        val body = pick(sm, "instance_id", "principal", "size", "root", "prev_root") ?: return false
        val e = sm["guardian_epoch"]
        body["guardian_epoch"] = if (sm.containsKey("guardian_epoch") && e != null) e else IntentJs.ofLong(0)
        return signed(cm, witnessPublic, STH_WITNESS_DOMAIN, body, pins)
    }

    /**
     * The k-of-n check: at least `policy.threshold` DISTINCT trusted witnesses (`policy.witnessKeys`) carry a valid cosignature over
     * this exact head. Unknown, duplicate and mis-bound cosignatures do not count; threshold 0 is vacuously met; a non-integer or
     * negative threshold fails.
     */
    @JvmStatic
    fun verifyWitnessCosignatures(sth: Any?, policy: Map<String, Any?>?, pins: Map<String, Any?>? = policyPins(policy)): Boolean {
        val sm = map(sth)
        if (sm == null || policy == null) return false
        val tf = IntentJs.num(policy["threshold"])
        if (tf == null || tf != Math.floor(tf) || tf < 0) return false
        if (tf == 0.0) return true
        val trusted = HashSet<String>()
        val ks = policy["witnessKeys"] as? List<*>
        if (ks != null) for (k in ks) if (k is String) trusted.add(k)
        if (trusted.isEmpty()) return false
        val ws = sm["witnesses"] as? List<*> ?: return false
        val counted = HashSet<String>()
        for (w in ws) {
            val wm = map(w) ?: continue
            val key = str(wm, "key")
            val sig = str(wm, "sig")
            if (key == null || sig == null || !trusted.contains(key) || counted.contains(key)) continue
            if (!verifyWitnessCosignature(sth, w, key, pins)) continue
            counted.add(key)
            if (counted.size.toDouble() >= tf) return true
        }
        return counted.size.toDouble() >= tf
    }

    /**
     * Verifies a guardian-signed tree head against the pinned guardian key: the head names that guardian, its size is a non-negative
     * safe integer, the signature covers `{instance_id, principal, size, root, prev_root, timestamp}`, and, when `policy` is given,
     * enough trusted witnesses cosigned it.
     */
    @JvmStatic
    fun verifyTreeHead(sth: Any?, guardianPublic: String, policy: Map<String, Any?>? = null, pins: Map<String, Any?>? = null): Boolean {
        val m = map(sth) ?: return false
        if (str(m, "guardian") != guardianPublic) return false
        val sz = safeInt(m["size"])
        if (sz == null || sz < 0) return false
        val body = pick(m, "instance_id", "principal", "size", "root", "prev_root", "timestamp") ?: return false
        if (!signed(m, guardianPublic, STH_DOMAIN, body, pins)) return false
        return policy == null || verifyWitnessCosignatures(sth, policy, pins ?: policyPins(policy))
    }

    /**
     * Both heads are genuine for the pinned guardian, belong to the same instance and log, the proof connects exactly their sizes,
     * the signed `prev_root` equals `older.root` when the heads are adjacent (`newer.size == older.size + 1`), and the RFC 9162 path
     * verifies.
     */
    @JvmStatic
    fun verifyHeadConsistency(older: Any?, newer: Any?, proof: Any?, guardianPublic: String, policy: Map<String, Any?>? = null, pins: Map<String, Any?>? = null): Boolean {
        if (!verifyTreeHead(older, guardianPublic, policy, pins) || !verifyTreeHead(newer, guardianPublic, policy, pins)) return false
        val om = map(older)!!
        val nm = map(newer)!!
        val pm = map(proof) ?: return false
        if (!same(om["instance_id"], nm["instance_id"]) || !same(om["principal"], nm["principal"])) return false
        val os = IntentJs.num(om["size"])
        val ns = IntentJs.num(nm["size"])
        val ps = IntentJs.num(pm["oldSize"])
        val pn = IntentJs.num(pm["newSize"])
        if (os == null || ns == null || ps == null || pn == null || ps != os || pn != ns) return false
        if (ns == os + 1 && !same(nm["prev_root"], om["root"])) return false
        return verifyConsistency(om["root"], nm["root"], proof)
    }

    /** The result of [verifyCheckpointChain]: `ok`, or `at` = index of the first checkpoint that fails. */
    class CheckpointVerdict(val ok: Boolean, val at: Int) {
        override fun toString(): String = "CheckpointVerdict(ok=$ok, at=$at)"
    }

    /**
     * Verifies pinned checkpoints end to end: every head is genuine (and witnessed when `policy` is given), the first needs no proof,
     * every later one carries a consistency proof from the checkpoint before. An empty or non-array chain fails at 0.
     */
    @JvmStatic
    fun verifyCheckpointChain(chain: Any?, guardianPublic: String, policy: Map<String, Any?>? = null, pins: Map<String, Any?>? = null): CheckpointVerdict {
        val cs = chain as? List<*>
        if (cs == null || cs.isEmpty()) return CheckpointVerdict(false, 0)
        var prev: Any? = null
        for ((i, c) in cs.withIndex()) {
            val cm = map(c)
            if (cm == null || !verifyTreeHead(cm["sth"], guardianPublic, policy, pins)) return CheckpointVerdict(false, i)
            if (i > 0) {
                val pr = cm["proof"]
                if (pr == null || pr == false) return CheckpointVerdict(false, i)
                if (!verifyHeadConsistency(prev, cm["sth"], pr, guardianPublic, policy, pins)) return CheckpointVerdict(false, i)
            }
            prev = cm["sth"]
        }
        return CheckpointVerdict(true, 0)
    }
}
