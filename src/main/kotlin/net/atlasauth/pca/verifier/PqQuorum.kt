package net.atlasauth.pca.verifier

/**
 * Post-quantum t-of-n authorization by composition (a quorum certificate): a quorum set is n registered post-quantum signers with a
 * threshold `t` and a floor `minHashBased` of hash-based (SLH-DSA) signers; a proof is t independent per-signer signatures over one
 * domain-separated message bound to the set id, an epoch and an action digest. Sets rotate through certificates signed by the
 * outgoing set. Nothing here is a threshold signature scheme: every share is an ordinary suite signature, verified under the key the
 * set registers. The verifiers never throw and answer with typed verdicts (`{ok: false, reason}`).
 */
@Suppress("UNCHECKED_CAST")
object PqQuorum {
    private const val SET_DOMAIN = "atlas-pca/pq-quorum-set/v1"
    private const val MSG_DOMAIN = "atlas-pca/pq-quorum-msg/v1\u0000"
    private const val ROTATION_KIND = "pq-quorum-rotation"
    const val PQ_QUORUM_MAX_SIGNERS = 256
    const val PQ_QUORUM_MAX_CHAIN = 1024

    private fun sha384(b: ByteArray): ByteArray = Pca.hashWithSuite(b, "sha384")

    private fun bad(reason: String): LinkedHashMap<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)
    private val BAD_SET: Map<String, Any?> get() = bad("bad-set")

    private fun isEpoch(v: Any?): Boolean = IntentJs.isSafeInteger(v) && IntentJs.num(v)!! >= 0 && !IntentJs.isNegZero(IntentJs.num(v)!!)

    private fun isHashBased(s: Pq.Suite): Boolean = s.pq == Pq.Prim.SLH_DSA_SHA2_128F || s.pq == Pq.Prim.SLH_DSA_SHA2_256S

    private fun isPq(s: Pq.Suite): Boolean = s.pq != null && s.pq != Pq.Prim.LESS_CAT1

    private fun suiteOf(entry: Map<*, *>): Pq.Suite = Pq.resolveSigAlg(entry["alg"], true) ?: throw IllegalArgumentException("unknown suite")

    private fun pqKeyOf(s: Pq.Suite, keys: Any?): Any? = ZkJs.get(
        keys,
        when (s.pq) {
            Pq.Prim.ML_DSA_65 -> "mlDsaPub"
            Pq.Prim.ML_DSA_87 -> "mlDsa87Pub"
            Pq.Prim.SLH_DSA_SHA2_128F -> "slhDsaPub"
            Pq.Prim.FN_DSA_512 -> "fnDsa512Pub"
            Pq.Prim.FN_DSA_1024 -> "fnDsa1024Pub"
            else -> "slhDsa256sPub"
        },
    )

    /** `{alg, ed?, pq}` for a registered PQ suite with well-formed keys, else null. `ed` is required on a hybrid and forbidden otherwise (a null counts as present). */
    private fun normalizeEntry(alg: Any?, ed: Any?, pq: Any?): Map<String, Any?>? {
        val suite = Pq.resolveSigAlg(if (alg === ZkJs.UNDEF) null else alg, alg !== ZkJs.UNDEF) ?: return null
        if (!isPq(suite)) return null
        if (Pca.decodeB64uStrict(pq, suite.pq!!.pkBytes) == null) return null
        if (suite.hasEd25519) {
            if (Pca.decodeB64uStrict(ed, 32) == null) return null
            return linkedMapOf("alg" to suite.alg, "ed" to ed, "pq" to pq)
        }
        if (ed !== ZkJs.UNDEF) return null
        return linkedMapOf("alg" to suite.alg, "pq" to pq)
    }

    private fun entryKey(e: Map<String, Any?>): String = "${e["alg"]}|${e["ed"] ?: ""}|${e["pq"]}"

    private fun computeId(t: Any?, k: Any?, signers: List<Map<String, Any?>>): String {
        val s = signers.map { linkedMapOf("a" to it["alg"], "e" to it["ed"], "p" to it["pq"]) }
        return Pca.b64(sha384(Pca.canonBytes(linkedMapOf("d" to SET_DOMAIN, "t" to t, "k" to k, "s" to s))))
    }

    private fun finalize(entries: List<Map<String, Any?>>, t: Any?, k: Any?): Map<String, Any?> {
        val n = entries.size
        if (n < 1 || n > PQ_QUORUM_MAX_SIGNERS) return BAD_SET
        if (!IntentJs.isSafeInteger(t) || IntentJs.num(t)!! < 1 || IntentJs.num(t)!! > n) return BAD_SET
        if (!IntentJs.isSafeInteger(k) || IntentJs.num(k)!! < 0 || IntentJs.num(k)!! > IntentJs.num(t)!!) return BAD_SET
        val sorted = entries.sortedWith(compareBy { entryKey(it) }) // UTF-16 order, stable: the reference's string `<`
        val seen = HashSet<Any?>()
        for (e in sorted) {
            if (e.containsKey("ed") && !seen.add(e["ed"])) return BAD_SET
            if (!seen.add(e["pq"])) return BAD_SET
        }
        if (sorted.count { isHashBased(suiteOf(it)) } < IntentJs.num(k)!!) return BAD_SET
        val set = linkedMapOf<String, Any?>("t" to t, "minHashBased" to k, "signers" to sorted, "id" to computeId(t, k, sorted)) // a -0 floor is refused by the canonical form
        return linkedMapOf("ok" to true, "set" to set)
    }

    /**
     * Build a quorum set from `[{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?, fnDsa1024Pub?}}]`
     * (base64url public keys), a threshold and the hash-based floor: `{ok: true, set: {t, minHashBased, signers, id}}` with the
     * signers in canonical order, or `{ok: false, reason: "bad-set"}`.
     */
    @JvmStatic
    @JvmOverloads
    fun buildQuorumSet(signers: Any?, t: Any?, minHashBased: Any? = IntentJs.ofLong(0)): Map<String, Any?> {
        try {
            if (signers !is List<*>) return BAD_SET
            val entries = ArrayList<Map<String, Any?>>()
            for (s in signers) {
                if (s !is Map<*, *> || s["keys"] !is Map<*, *>) return BAD_SET
                val alg = ZkJs.get(s, "alg")
                val suite = Pq.resolveSigAlg(if (alg === ZkJs.UNDEF) null else alg, alg !== ZkJs.UNDEF) ?: return BAD_SET
                entries.add(normalizeEntry(alg, ZkJs.get(s["keys"], "edPub"), pqKeyOf(suite, s["keys"])) ?: return BAD_SET)
            }
            return finalize(entries, t, minHashBased)
        } catch (e: RuntimeException) {
            return BAD_SET
        }
    }

    /** Load a quorum set from the wire: its id is re-derived and must match, and its signers must already be in canonical order. */
    @JvmStatic
    fun loadQuorumSet(x: Any?): Map<String, Any?> {
        try {
            if (x !is Map<*, *> || x["signers"] !is List<*> || x["id"] !is String) return BAD_SET
            val entries = ArrayList<Map<String, Any?>>()
            for (s in x["signers"] as List<*>) {
                if (s !is Map<*, *>) return BAD_SET
                entries.add(normalizeEntry(ZkJs.get(s, "alg"), ZkJs.get(s, "ed"), ZkJs.get(s, "pq")) ?: return BAD_SET)
            }
            val r = finalize(entries, x["t"], x["minHashBased"])
            if (r["ok"] != true) return r
            val set = r["set"] as Map<String, Any?>
            val sorted = set["signers"] as List<Map<String, Any?>>
            for (i in sorted.indices) if (entryKey(sorted[i]) != entryKey(entries[i])) return BAD_SET
            return if (set["id"] == x["id"]) r else BAD_SET
        } catch (e: RuntimeException) {
            return BAD_SET
        }
    }

    /** The message every share signs: the domain, then SHA-384 of the strict canonical `{set_id, epoch, action}`. Throws on a value the canonical form refuses. */
    @JvmStatic
    fun quorumMessage(setId: Any?, epoch: Any?, actionDigest: Any?): ByteArray =
        Pca.concat(Json.utf8(MSG_DOMAIN), sha384(Pca.canonBytes(linkedMapOf("set_id" to setId, "epoch" to epoch, "action" to actionDigest))))

    /** The action digest of an approved message: base64url SHA-384. */
    @JvmStatic
    fun quorumActionDigest(message: ByteArray): String = Pca.b64(sha384(message))

    /**
     * One signer's share `{i, sig, pq_sig?}`: the signature of slot `index` of the set over [quorumMessage], under that slot's suite
     * with the given keys (`ed` for a hybrid slot, `pq` the slot's post-quantum key). Throws on an unknown slot or keys that do not
     * fit the slot's suite.
     */
    @JvmStatic
    fun signQuorumShare(set: Map<String, Any?>, index: Int, epoch: Any?, actionDigest: Any?, ed: Keys.EdKey?, pq: Keys.PqKey?): Map<String, Any?> {
        val e = (set["signers"] as? List<*>)?.getOrNull(index) as? Map<*, *> ?: throw IndexOutOfBoundsException("signQuorumShare: no such signer index")
        val suite = suiteOf(e)
        val p = Keys.suite(suite.alg, if (suite.hasEd25519) ed else null, pq).sign(quorumMessage(set["id"], epoch, actionDigest))
        val out = linkedMapOf<String, Any?>("i" to index, "sig" to p.first)
        if (p.second != null) out["pq_sig"] = p.second
        return out
    }

    /** `{set_id, sigs}` from the collected shares (copied as given). */
    @JvmStatic
    fun assembleQuorumProof(set: Map<String, Any?>, shares: List<Any?>): Map<String, Any?> = linkedMapOf("set_id" to set["id"], "sigs" to ArrayList(shares))

    // `Math.max` reads its arguments as numbers
    private fun toNumber(v: Any?): Double {
        if (v is Boolean) return if (v) 1.0 else 0.0
        if (v is String) return if (v.isBlank()) 0.0 else (v.trim().toDoubleOrNull() ?: Double.NaN)
        return IntentJs.num(v) ?: Double.NaN
    }

    /**
     * Verify a quorum proof: `{set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}` gives
     * `{ok: true, signers, count, hashBased}` or `{ok: false, reason, detail?}`. The set must load, match the pinned id, and the proof
     * must carry at least `t` valid shares of distinct registered signers, of which the larger of the set's and the verifier's
     * hash-based floor are hash-based. Every share present must verify. Never throws.
     */
    @JvmStatic
    fun verifyQuorum(input: Any?): Map<String, Any?> {
        try {
            if (input !is Map<*, *>) return bad("malformed")
            val loaded = loadQuorumSet(input["set"])
            if (loaded["ok"] != true) return bad("bad-set")
            val set = loaded["set"] as Map<String, Any?>
            val signers = set["signers"] as List<Map<String, Any?>>
            val expected = ZkJs.get(input, "expectedSetId")
            if (expected !== ZkJs.UNDEF && expected != set["id"]) return bad("set-mismatch")
            if (!isEpoch(input["epoch"]) || input["actionDigest"] !is String) return bad("malformed")
            val p = input["proof"]
            if (p !is Map<*, *> || p["set_id"] !is String || p["sigs"] !is List<*>) return bad("malformed")
            if (p["set_id"] != set["id"]) return bad("set-mismatch")
            val sigs = p["sigs"] as List<*>
            if (sigs.size > signers.size) return bad("too-many-signatures")
            val msg = quorumMessage(set["id"], input["epoch"], input["actionDigest"])
            val seen = java.util.TreeSet<Int>()
            var hashBased = 0
            for (raw in sigs) {
                if (raw !is Map<*, *> || raw["sig"] !is String) return bad("malformed")
                val iv = raw["i"]
                if (!isEpoch(iv) || IntentJs.num(iv)!! >= signers.size) return bad("unknown-signer")
                val i = IntentJs.num(iv)!!.toInt()
                if (!seen.add(i)) return bad("duplicate-signer").also { it["detail"] = i }
                val e = signers[i]
                val suite = suiteOf(e)
                if (suite.needsPqSig != raw.containsKey("pq_sig")) return bad("bad-signature").also { it["detail"] = i }
                // the PQ half verifies under the key the SET registers for this signer, never under anything the proof carries
                if (!Pq.verifyLeafSuite(suite.alg, true, e["ed"] as String?, e["pq"], msg, raw["sig"], raw["pq_sig"])) return bad("bad-signature").also { it["detail"] = i }
                if (isHashBased(suite)) hashBased++
            }
            if (seen.size < IntentJs.num(set["t"])!!) return bad("below-threshold")
            val floor = ZkJs.get(input, "requireHashBased")
            val k = Math.max(IntentJs.num(set["minHashBased"])!!, if (floor == null || floor === ZkJs.UNDEF) 0.0 else toNumber(floor))
            if (k.isNaN() || k.isInfinite() || k != Math.rint(k) || Math.abs(k) > IntentJs.MAX_SAFE || k < 0) return bad("malformed")
            if (hashBased < k) return bad("diversity-unmet")
            return linkedMapOf("ok" to true, "signers" to ArrayList(seen), "count" to seen.size, "hashBased" to hashBased)
        } catch (e: RuntimeException) {
            return bad("malformed")
        }
    }

    /** True only when the proof approves exactly `message` at `epoch`; `opts` may pin `expectedSetId` and `requireHashBased`. */
    @JvmStatic
    @JvmOverloads
    fun verifyQuorumApproval(set: Any?, proof: Any?, message: ByteArray?, epoch: Any?, opts: Map<String, Any?>? = null): Boolean {
        try {
            if (message == null) return false
            val input = linkedMapOf<String, Any?>("set" to set, "proof" to proof, "epoch" to epoch, "actionDigest" to quorumActionDigest(message))
            if (opts != null) input.putAll(opts)
            return verifyQuorum(input)["ok"] == true
        } catch (e: RuntimeException) {
            return false
        }
    }

    // ---- rotation ----

    /** The action digest a rotation to `toSetId` at `toEpoch` is approved under. */
    @JvmStatic
    fun rotationActionDigest(toSetId: Any?, toEpoch: Any?): String =
        Pca.b64(sha384(Pca.canonBytes(linkedMapOf("kind" to ROTATION_KIND, "to_set_id" to toSetId, "to_epoch" to toEpoch))))

    private fun nextEpoch(fromEpoch: Any?): Any? {
        val d = IntentJs.num(fromEpoch) ?: throw IllegalArgumentException("the epoch must be a number")
        return IntentJs.normalize(d + 1)
    }

    /** `{from_set_id, from_epoch, to_set, to_epoch: from_epoch + 1, proof}` from the outgoing set's shares. */
    @JvmStatic
    fun buildRotationCert(from: Map<String, Any?>, fromEpoch: Any?, to: Any?, shares: List<Any?>): Map<String, Any?> =
        linkedMapOf("from_set_id" to from["id"], "from_epoch" to fromEpoch, "to_set" to to, "to_epoch" to nextEpoch(fromEpoch), "proof" to assembleQuorumProof(from, shares))

    /** A signer of the outgoing set approves the rotation to `to` (its share over [rotationActionDigest] of `to.id` at `fromEpoch + 1`). */
    @JvmStatic
    fun signRotationShare(from: Map<String, Any?>, index: Int, fromEpoch: Any?, to: Map<String, Any?>, ed: Keys.EdKey?, pq: Keys.PqKey?): Map<String, Any?> =
        signQuorumShare(from, index, fromEpoch, rotationActionDigest(to["id"], nextEpoch(fromEpoch)), ed, pq)

    private fun broken(reason: Any?, at: Int): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason, "at" to at)

    /**
     * Walk a chain of rotation certificates from the genesis set and epoch: `{ok: true, set, epoch, length}` (the current set), or
     * `{ok: false, reason, at}` with the index of the first bad link (-1 for the genesis or the chain itself). Each link must name the
     * current set and epoch, advance the epoch by exactly one, load a different set, and be approved by a quorum of the CURRENT set.
     */
    @JvmStatic
    fun verifyRotationChain(genesisSet: Any?, genesisEpoch: Any?, chain: Any?): Map<String, Any?> {
        try {
            val g = loadQuorumSet(genesisSet)
            if (g["ok"] != true || !isEpoch(genesisEpoch)) return broken("bad-set", -1)
            if (chain !is List<*>) return broken("malformed", -1)
            if (chain.size > PQ_QUORUM_MAX_CHAIN) return broken("chain-too-long", -1)
            var cur = g["set"] as Map<String, Any?>
            var epoch: Any? = genesisEpoch
            for ((n, c) in chain.withIndex()) {
                if (c !is Map<*, *> || c["from_set_id"] !is String || !isEpoch(c["from_epoch"]) || !isEpoch(c["to_epoch"])) return broken("malformed", n)
                if (c["from_set_id"] != cur["id"]) return broken("chain-broken", n)
                val e = IntentJs.num(epoch)!!
                if (IntentJs.num(c["from_epoch"])!! != e || IntentJs.num(c["to_epoch"])!! != e + 1) return broken("non-monotone-epoch", n)
                val next = loadQuorumSet(c["to_set"])
                if (next["ok"] != true) return broken("bad-rotation", n)
                val nextSet = next["set"] as Map<String, Any?>
                if (nextSet["id"] == cur["id"]) return broken("bad-rotation", n)
                val input = linkedMapOf<String, Any?>("set" to cur, "epoch" to epoch, "actionDigest" to rotationActionDigest(nextSet["id"], c["to_epoch"]), "expectedSetId" to cur["id"])
                if (c.containsKey("proof")) input["proof"] = c["proof"]
                val v = verifyQuorum(input)
                if (v["ok"] != true) return broken(v["reason"], n)
                cur = nextSet
                epoch = c["to_epoch"]
            }
            return linkedMapOf("ok" to true, "set" to cur, "epoch" to epoch, "length" to chain.size)
        } catch (e: RuntimeException) {
            return broken("malformed", -1)
        }
    }

    /** Two certificates rotate the same set at the same epoch to different sets: evidence of a fork. */
    @JvmStatic
    fun isRotationFork(a: Any?, b: Any?): Boolean {
        if (a !is Map<*, *> || b !is Map<*, *>) return false
        val ta = a["to_set"]
        val tb = b["to_set"]
        if (ta !is Map<*, *> || tb !is Map<*, *>) return false
        return ZkJs.strictEq(ZkJs.get(a, "from_set_id"), ZkJs.get(b, "from_set_id")) && ZkJs.strictEq(ZkJs.get(a, "from_epoch"), ZkJs.get(b, "from_epoch")) &&
            ta["id"] is String && tb["id"] is String && ta["id"] != tb["id"]
    }

    private fun shareBytes(e: Any?): Int {
        val s = suiteOf(e as Map<*, *>)
        return s.sigBytes + (if (s.needsPqSig) s.pq!!.sigBytes else 0)
    }

    /**
     * The size of a proof of this set in signature bytes: `{minBytes, maxBytes, t, compact: false}` over the `t` smallest and largest
     * shares, plus `chosenBytes` for the given signer indices (an unknown index counts 0). Throws on a malformed set.
     */
    @JvmStatic
    @JvmOverloads
    fun quorumProofSize(set: Map<String, Any?>, indices: List<Any?>? = null): Map<String, Any?> {
        val signers = set["signers"] as List<Any?>
        val sizes = signers.map { shareBytes(it) }.sorted()
        val t = Math.max(0, Math.min(sizes.size, (IntentJs.num(set["t"]) ?: 0.0).toInt()))
        val r = linkedMapOf<String, Any?>("minBytes" to sizes.take(t).sum(), "maxBytes" to sizes.takeLast(t).sum(), "t" to set["t"], "compact" to false)
        if (indices != null) {
            var chosen = 0
            for (iv in indices) {
                val d = IntentJs.num(iv)
                if (d != null && d == Math.rint(d) && d >= 0 && d < signers.size) chosen += shareBytes(signers[d.toInt()])
            }
            r["chosenBytes"] = chosen
        }
        return r
    }
}
