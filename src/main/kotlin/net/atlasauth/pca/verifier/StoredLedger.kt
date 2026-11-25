package net.atlasauth.pca.verifier

/**
 * A transparency log over a [LedgerStore] (guardian-signed checkpoints). Open it with [open]; the constructor is private so that no
 * instance exists whose state was not verified against the stored checkpoints.
 *
 * On `open` the Merkle tree is rebuilt from the stored commits and checked against EVERY stored checkpoint: the guardian signature, the
 * signed `prev_root` chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each checkpoint root. A store
 * that lost entries after a checkpoint (rollback), edited an entry (tamper) or holds a forged checkpoint FAILS CLOSED with a
 * [LedgerStoreError]. [checkpoint] refuses to sign a head that is not consistent with the previous one.
 *
 * Checkpoints are Ed25519 by default. A post-quantum or hybrid suite ([Options.suite]) needs the verifier's PQ pin for the guardian
 * ([Options.pin]); every stored checkpoint is then verified under that pin, so a checkpoint signed by another PQ key is refused.
 */
class StoredLedger private constructor(
    private val opts: Options,
    private val guardianPublic: String,
    private val log: MerkleLog,
    private val cps: MutableList<Map<String, Any?>>,
) {
    /** Open options. [store] and [guardianKey] are required (there is no in-memory default). */
    class Options {
        var store: LedgerStore? = null
        var guardianKey: Keys.EdKey? = null

        /** Checkpoint signature suite (null: ed25519). A PQ or hybrid suite needs [pin]; its Ed25519 key, when it has one, is the guardian key. */
        var suite: Keys.SuiteKey? = null

        /** PQ pins for the guardian identity, `{ed25519 b64u: pq_pk}`; required with a non-ed25519 suite. */
        var pin: Map<String, Any?>? = null
        var instanceId: String? = null
        var principal: String? = null

        /** Epoch-ms clock for checkpoint timestamps (default the system clock). */
        var clock: (() -> Double)? = null
    }

    private val store: LedgerStore get() = opts.store!!

    private class Failure(val at: Int, val reason: String)

    /** verifyCheckpointChain with the failing reason (head / proof_missing / inconsistent); null when the chain verifies. */
    private fun chainFailure(chain: List<Map<String, Any?>>): Failure? {
        var prev: Map<String, Any?>? = null
        for (i in chain.indices) {
            val sth = sthOf(chain[i])
            if (!Ledger.verifyTreeHead(sth, guardianPublic, null, opts.pin)) return Failure(i, "head")
            if (i > 0) {
                val proof = chain[i]["proof"]
                if (proof == null || proof == false) return Failure(i, "proof_missing")
                if (!Ledger.verifyHeadConsistency(prev, sth, proof, guardianPublic, null, opts.pin)) return Failure(i, "inconsistent")
            }
            prev = sth
        }
        return null
    }

    /** The checkpoint chain, the log and the stored commits must tell one story. */
    private fun verifyAgainstCheckpoints() {
        var attested = 0L
        for (cp in cps) {
            val sz = sthOf(cp)["size"]
            if (Json.isSafeInt(sz)) attested = maxOf(attested, Json.asLong(sz))
        }
        if (log.size() < attested) throw LedgerStoreError("rollback", "the log has ${log.size()} entries but a checkpoint attests $attested")
        for (i in cps.indices) {
            val sth = sthOf(cps[i])
            if (sth["instance_id"] != opts.instanceId || sth["principal"] != opts.principal) {
                throw LedgerStoreError("forged_checkpoint", "checkpoint $i belongs to another log")
            }
            val sz = sth["size"]
            if (!Json.isSafeInt(sz)) throw IllegalArgumentException("rootAt: size out of range")
            if (log.rootAt(Json.asLong(sz)) != sth["root"]) {
                throw LedgerStoreError("tamper", "the stored entries do not reproduce the root of checkpoint $i (size ${Json.canonicalize(sz)})")
            }
        }
        if (cps.isEmpty()) return
        val v = chainFailure(cps) ?: return
        throw LedgerStoreError(if (v.reason == "inconsistent") "inconsistent" else "forged_checkpoint", "checkpoint ${v.at}: ${v.reason}")
    }

    @Synchronized fun size(): Int = log.size()

    /** The guardian public key (b64u) every checkpoint verifies under. */
    fun guardian(): String = guardianPublic

    /** The latest signed tree head, or null. */
    @Synchronized fun latestCheckpoint(): Map<String, Any?>? = if (cps.isEmpty()) null else sthOf(cps[cps.size - 1])

    @Synchronized fun checkpointChain(): List<Map<String, Any?>> = cps.map { StoreJs.deepCopy(it) as Map<String, Any?> }

    /** `{size, root}`. */
    @Synchronized fun head(): Map<String, Any?> = log.head()

    @Synchronized fun inclusionProof(index: Long): Map<String, Any?> = log.inclusionProof(index)

    /** RFC 9162 proof from a size the caller already pinned (a checkpoint, or a witness's) to the current log. */
    @Synchronized fun consistencyProofFrom(oldSize: Long): Map<String, Any?> = log.consistencyProof(oldSize, log.size().toLong())

    @Synchronized fun commits(): List<String> = log.commits()

    /** Append an opaque commitment leaf; returns its index. If another writer took the position, reloads and appends at the new tail. */
    @Synchronized fun append(commit: String?): Long {
        if (commit.isNullOrEmpty()) throw LedgerStoreError("invalid_commit", "a commit must be a non-empty string")
        for (attempt in 0 until 16) {
            val index = log.size().toLong()
            val out = try {
                store.append(index, listOf(commit))
            } catch (e: RuntimeException) {
                throw unavailable(e)
            }
            if (out.outcome == "appended" || out.outcome == "replayed") {
                log.appendCommitment(commit)
                return index
            }
            catchUpLocked() // another writer advanced the log: pick up its entries, then try the new tail
        }
        throw LedgerStoreError("conflict", "the log kept moving; could not append")
    }

    /** Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints). */
    @Synchronized fun catchUp() = catchUpLocked()

    private fun catchUpLocked() {
        try {
            val size = store.size()
            if (size < log.size()) throw LedgerStoreError("rollback", "the store shrank from ${log.size()} to $size entries")
            for (c in store.read(log.size().toLong(), size)) log.appendCommitment(c)
            cps.addAll(store.checkpoints(cps.size.toLong()))
            verifyAgainstCheckpoints()
        } catch (e: RuntimeException) {
            throw unavailable(e)
        }
    }

    /** A checkpoint signs what THIS handle holds, so first prove the store still holds exactly that. */
    private fun assertStoreMatchesMemory() {
        val stored = try {
            store.read(0, log.size().toLong())
        } catch (e: RuntimeException) {
            throw unavailable(e)
        }
        if (stored != log.commits()) throw LedgerStoreError("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them")
    }

    /**
     * Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the
     * previous checkpoint, so a log that was rewritten under this handle is refused (`inconsistent`). An unchanged head returns the
     * existing tree head.
     */
    @Synchronized fun checkpoint(): Map<String, Any?> {
        catchUpLocked()
        assertStoreMatchesMemory()
        val prev = if (cps.isEmpty()) null else cps[cps.size - 1]
        val size = log.size().toLong()
        val root = log.root()
        if (prev != null && Json.isSafeInt(sthOf(prev)["size"]) && Json.asLong(sthOf(prev)["size"]) == size) return sthOf(prev)
        val t = (opts.clock ?: { System.currentTimeMillis().toDouble() })()
        if (t.isNaN() || t.isInfinite()) throw LedgerStoreError("clock_invalid", "the clock returned a non-finite time")
        val body = LinkedHashMap<String, Any?>()
        body["instance_id"] = opts.instanceId
        body["principal"] = opts.principal
        body["size"] = StoreJs.num(size)
        body["root"] = root
        body["prev_root"] = if (prev == null) "" else sthOf(prev)["root"]
        body["timestamp"] = if (t == Math.rint(t) && Math.abs(t) < 9e15) StoreJs.num(t.toLong()) else StoreJs.num(t)
        val suite = opts.suite ?: Keys.ed25519(opts.guardianKey!!)
        val bound = IntentJs.bindSuiteFields(body, suite.alg, true, suite.pqPk(), true)
        val msg = Pca.concat(Json.utf8(Ledger.STH_DOMAIN), Pca.canonBytes(bound))
        val sigs = suite.sign(msg)
        val sth = LinkedHashMap<String, Any?>(bound) // the bound body carries alg and pq_pk for a non-ed25519 suite
        sth["guardian"] = guardianPublic
        sth["sig"] = sigs.first
        if (sigs.second != null) sth["pq_sig"] = sigs.second
        val cp = LinkedHashMap<String, Any?>()
        cp["sth"] = sth
        if (prev != null) cp["proof"] = log.consistencyProof(Json.asLong(sthOf(prev)["size"]), size)
        val chain = ArrayList<Map<String, Any?>>(cps)
        chain.add(cp)
        val v = chainFailure(chain)
        if (v != null) {
            if (v.reason == "head") throw LedgerStoreError("forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)")
            throw LedgerStoreError("inconsistent", "the new head is not consistent with checkpoint ${v.at - 1}")
        }
        val out = try {
            store.appendCheckpoint(cps.size.toLong(), cp)
        } catch (e: RuntimeException) {
            throw unavailable(e)
        }
        if (out.outcome == "conflict") throw LedgerStoreError("conflict", out.reason ?: "conflict")
        cps.add(cp)
        return sth
    }

    companion object {
        private fun unavailable(e: RuntimeException): LedgerStoreError = e as? LedgerStoreError ?: LedgerStoreError("store_unavailable", e.message ?: "store failed", e)

        @Suppress("UNCHECKED_CAST")
        private fun sthOf(cp: Map<String, Any?>): Map<String, Any?> = StoreJs.map(cp["sth"]) ?: LinkedHashMap()

        /** Load the log and verify it against every stored checkpoint. Throws [LedgerStoreError] with the reference's codes. */
        @JvmStatic
        fun open(opts: Options?): StoredLedger {
            if (opts?.store == null) throw LedgerStoreError("store_missing", "a LedgerStore is required (there is no in-memory default)")
            val key = opts.guardianKey
            if (key == null || key.isDestroyed) throw LedgerStoreError("guardian_key_missing", "a guardian secret key is required")
            val gp = key.id()
            val suite = opts.suite
            if (suite != null && suite.alg != "ed25519" && opts.pin == null) {
                throw LedgerStoreError("pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)")
            }
            if (suite?.ed != null && suite.ed.id() != gp) throw IllegalArgumentException("the suite's Ed25519 key is not the guardian key")
            try {
                val size = opts.store!!.size()
                val commits = opts.store!!.read(0, size)
                val cps = ArrayList(opts.store!!.checkpoints(0))
                val self = StoredLedger(opts, gp, MerkleLog.of(commits), cps)
                self.verifyAgainstCheckpoints()
                return self
            } catch (e: RuntimeException) {
                throw unavailable(e)
            }
        }
    }
}
