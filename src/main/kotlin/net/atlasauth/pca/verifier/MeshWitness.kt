package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/** In-process [MeshWitnessStore]: a test double, and the default when no store is given. It does not survive a restart. */
class MemoryMeshWitnessStore : MeshWitnessStore {
    private var state: String? = null

    @Synchronized
    override fun load(): Map<String, Any?>? = state?.let { StoreJs.map(Json.parseLenient(it)) }

    @Synchronized
    override fun save(state: Map<String, Any?>) { this.state = Json.canonicalize(state) }
}

/**
 * An independent mesh log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified
 * append-only extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces `rev_root` and is
 * a superset of the previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when
 * configured). State is committed only after every check passes, and (with a store) persisted BEFORE the cosignature is returned.
 * First sight of a domain is trust-on-first-use. Every refusal throws IllegalStateException with the reference's message.
 */
class MeshWitness @JvmOverloads constructor(private val key: Keys.EdKey, options: Options? = null) {
    /** Optional witness configuration. */
    class Options {
        var store: MeshWitnessStore? = null

        /** Witness's own clock; when set, heads timestamped beyond `now + maxClockSkewMs` are refused. */
        var clock: (() -> Double)? = null
        var maxClockSkewMs: Double? = null
    }

    private class Seen(val head: Map<String, Any?>, val rev: List<String>)

    private val opts = options ?: Options()
    val id: String = key.id()
    private val seen = LinkedHashMap<String, Seen>()

    init {
        val loaded = opts.store?.load()
        if (loaded != null) importState(loaded)
    }

    /** The newest head this witness cosigned for `domain` (a copy), or null. */
    @Synchronized
    fun lastSeen(domain: String): Map<String, Any?>? = seen[domain]?.let { StoreJs.map(StoreJs.deepCopy(it.head)) }

    /** Cosign a head request `{head: {head, sig, cosigs}, consistency?, rev_ids}`; returns `{witness, sig}`. Throws (and changes nothing) if any rule is violated. */
    @Synchronized
    fun cosign(req: Map<String, Any?>?): Map<String, Any?> {
        val ch = if (req == null) null else StoreJs.map(req["head"])
        if (ch == null || validHead(ch["head"]) == null || ch["sig"] !is String) throw refuse("malformed head")
        val h = validHead(ch["head"])!!
        if (!Pca.verifyB64u(h["domain"] as String, msg(Mesh.HEAD_DOMAIN, h), ch["sig"] as String)) throw refuse("head not signed by its domain")
        val ts = StoreJs.dbl(h["timestamp"])!!
        val clock = opts.clock
        if (clock != null) {
            val skew = opts.maxClockSkewMs ?: DEFAULT_MAX_CLOCK_SKEW_MS
            val clk = clock()
            if (!(clk.isFinite() && skew.isFinite() && ts <= clk + skew)) throw refuse("head timestamp is in the future")
        }
        val idsO = req!!["rev_ids"]
        if (idsO !is List<*> || idsO.size > MAX_REV_IDS) throw refuse("malformed revocation list")
        val ids = idsO.map { it as? String ?: throw refuse("malformed revocation list") }
        val set = RevocationSet(ids)
        if (set.size().toLong() != Json.asLong(h["rev_size"]) || set.root() != h["rev_root"]) throw refuse("revocation list does not match head")
        val prev = seen[h["domain"] as String]
        if (prev != null) {
            val why = Mesh.checkHeadAdvance(prev.head, h, req["consistency"])
            if (why.isNotEmpty()) throw refuse(why)
            if (!(ts >= StoreJs.dbl(prev.head["timestamp"])!!)) throw refuse("timestamp regresses")
            if (!set.list().toHashSet().containsAll(prev.rev)) throw refuse("revocation set drops a previously cosigned revocation")
        }
        val next = Seen(StoreJs.map(StoreJs.deepCopy(h))!!, set.list())
        opts.store?.let { store ->
            // Persist first, commit to memory second: if the disk write fails nothing was cosigned and nothing changed.
            val copy = LinkedHashMap(seen)
            copy[h["domain"] as String] = next
            try {
                store.save(stateOf(copy))
            } catch (e: RuntimeException) {
                throw refuse("could not persist state; refusing to cosign")
            }
        }
        seen[h["domain"] as String] = next
        return linkedMapOf("witness" to id, "sig" to Keys.b64u(key.sign(msg(Mesh.COSIG_DOMAIN, h))))
    }

    /** Export memory for persistence. Deterministic order. */
    @Synchronized
    fun exportState(): Map<String, Any?> = stateOf(seen)

    /** Restore memory; each record must be internally consistent (its revocation list reproduces its root). */
    @Synchronized
    fun importState(state: Map<String, Any?>?) {
        val next = LinkedHashMap<String, Seen>()
        val list = state?.get("seen")
        if (list != null && list !is List<*>) throw refuse("malformed state")
        if (list != null) {
            for (so in list as List<*>) {
                val s = StoreJs.map(so)
                val head = if (s == null) null else validHead(s["head"])
                val revIds = s?.get("rev_ids")
                if (head == null || revIds !is List<*>) throw refuse("malformed state")
                val ids = revIds.map { it as? String ?: throw refuse("malformed state") }
                val set = RevocationSet(ids)
                if (set.size().toLong() != Json.asLong(head["rev_size"]) || set.root() != head["rev_root"]) throw refuse("malformed state")
                next[head["domain"] as String] = Seen(StoreJs.map(StoreJs.deepCopy(head))!!, set.list())
            }
        }
        seen.clear()
        seen.putAll(next)
    }

    companion object {
        const val DEFAULT_MAX_CLOCK_SKEW_MS = 60_000.0
        private const val MAX_REV_IDS = 1_000_000

        private fun nat(x: Any?): Boolean = Json.isSafeInt(x) && Json.asLong(x) >= 0

        /** The head shape the reference's validHead accepts, or null. */
        internal fun validHead(h: Any?): Map<String, Any?>? {
            val m = StoreJs.map(h)
            if (m == null || m["domain"] !is String || m["root"] !is String || m["rev_root"] !is String) return null
            if (!nat(m["size"]) || !nat(m["rev_size"]) || !IntentJs.isFinite(m["timestamp"])) return null
            return if ((Json.asLong(m["size"]) == 0L) == (m["root"] as String).isEmpty()) m else null
        }

        private fun msg(domain: String, body: Any?): ByteArray = Pca.concat(Json.utf8(domain), Pca.canonBytes(body))

        private fun stateOf(seen: Map<String, Seen>): Map<String, Any?> {
            // the reference sorts by UTF-16 code units; the domains are unique, so any total order on them is the same order
            val all = seen.values.sortedBy { it.head["domain"] as String }
            return linkedMapOf("seen" to all.map { linkedMapOf("head" to StoreJs.deepCopy(it.head), "rev_ids" to ArrayList<Any?>(it.rev)) })
        }

        private fun refuse(why: String) = IllegalStateException("witness: $why")
    }
}

/**
 * The issuing side of a mesh domain (an organisation): an append-only delegation log, a revocation set, and head publication against
 * [MeshWitness]es. In production this is the deployed signed-tree-head + revocation-epoch machinery; here it is in memory so the
 * witness protocol can be exercised end to end.
 */
class MeshDomain(val name: String, private val key: Keys.EdKey) {
    val id: String = key.id()
    private val log = MerkleLog()
    private val rev = RevocationSet()

    /** What each published head saw, keyed by the head's signature (what [evidence] and [pinProof] prove against). */
    private class Snapshot(val log: List<String>, val rev: RevocationSet)

    private val snaps = LinkedHashMap<String, Snapshot>()

    /** Vouch that an agent key belongs to this domain: `{agent, domain, role, sig}` (for domain policy, not authority). */
    fun enroll(agent: String, role: String): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>("agent" to agent, "domain" to id, "role" to role)
        val m = Pca.concat(Json.utf8(Mesh.BINDING_DOMAIN), Pca.canonBytes(body))
        return LinkedHashMap(body).also { it["sig"] = Keys.b64u(key.sign(m)) }
    }

    /**
     * The proof a verifier holding `pin` (a head of this domain) needs to accept `head` (a cosigned head this domain published, larger
     * than the pin): `{domain, proof}`. Throws if the head is unknown or the pin is not a prefix of that head's log.
     */
    @Synchronized
    fun pinProof(pin: Map<String, Any?>, head: Map<String, Any?>): Map<String, Any?> {
        val snap = snaps[head["sig"].toString()] ?: throw IllegalStateException("pinProof: unknown head")
        val inner = StoreJs.map(head["head"])!!
        return linkedMapOf("domain" to id, "proof" to MerkleLog.of(snap.log).consistencyProof(Json.asLong(pin["size"]), Json.asLong(inner["size"])))
    }

    /**
     * Per-hop evidence against a previously published head: `{domain, head, inclusion, binding?, revocation: {cap, issuer_key}}`. Throws if the
     * head is unknown, the capability is not in that head's log, or the capability or its issuer key is revoked as of that head. `binding` may be null.
     */
    @Synchronized
    fun evidence(cap: Map<String, Any?>, head: Map<String, Any?>, binding: Map<String, Any?>?): Map<String, Any?> {
        val snap = snaps[head["sig"].toString()] ?: throw IllegalStateException("evidence: unknown head")
        val idx = snap.log.indexOf(Pca.capHash(cap))
        if (idx < 0) throw IllegalStateException("evidence: capability not in this head")
        val rv = linkedMapOf<String, Any?>(
            "cap" to snap.rev.nonMembershipProof(cap["id"] as String),
            "issuer_key" to snap.rev.nonMembershipProof("key:" + cap["issuer"]),
        )
        val ev = linkedMapOf<String, Any?>("domain" to id, "head" to head, "inclusion" to MerkleLog.of(snap.log).inclusionProof(idx.toLong()), "revocation" to rv)
        if (binding != null) ev["binding"] = binding
        return ev
    }

    /** Log a delegation hop issued in this domain (identified by its capability hash). Idempotent. Returns its index. */
    @Synchronized
    fun record(cap: Map<String, Any?>): Int {
        val h = Pca.capHash(cap)
        val i = log.commits().indexOf(h)
        return if (i >= 0) i else log.appendCommitment(h)
    }

    /** A copy of the current revocation set (for proofs about it). */
    @Synchronized
    fun revocationSetCopy(): RevocationSet = RevocationSet(rev.list())

    /** Revoke a capability id or an agent key. */
    @Synchronized
    fun revoke(revokedId: String) { rev.revoke(revokedId) }

    /** RFC 9162 consistency proof between two sizes of this domain's current log. */
    @Synchronized
    fun consistencyProof(oldSize: Long, newSize: Long): Map<String, Any?> = log.consistencyProof(oldSize, newSize)

    /** RFC 9162 consistency proof from `oldSize` to the whole of this domain's current log. */
    @Synchronized
    fun consistencyProof(oldSize: Long): Map<String, Any?> = log.consistencyProof(oldSize, log.size().toLong())

    /**
     * Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof from ITS last-seen head plus the
     * revocation list. Throws if a witness refuses (unless `threshold` tolerates it). Returns `{head, sig, cosigs}`.
     */
    @Synchronized
    @JvmOverloads
    fun publishHead(witnesses: List<MeshWitness>, timestamp: Double, threshold: Int? = null): Map<String, Any?> {
        val size = log.size().toLong()
        val head = linkedMapOf<String, Any?>(
            "domain" to id, "size" to StoreJs.num(size), "root" to (if (size == 0L) "" else log.root()),
            "rev_root" to rev.root(), "rev_size" to StoreJs.num(rev.size().toLong()),
            "timestamp" to (if (timestamp == Math.rint(timestamp) && Math.abs(timestamp) < 9e15) StoreJs.num(timestamp.toLong()) else StoreJs.num(timestamp)),
        )
        val m = Pca.concat(Json.utf8(Mesh.HEAD_DOMAIN), Pca.canonBytes(head))
        val cosigs = ArrayList<Any?>()
        val ch = linkedMapOf<String, Any?>("head" to head, "sig" to Keys.b64u(key.sign(m)), "cosigs" to cosigs)
        val revIds = rev.list()
        val errors = ArrayList<RuntimeException>()
        for (w in witnesses) {
            val prev = w.lastSeen(id)
            var consistency: Map<String, Any?>? = null
            if (prev != null) {
                val ps = Json.asLong(prev["size"])
                if (ps < size) consistency = log.consistencyProof(ps, size)
                else if (ps > size) // will be refused as rollback
                    consistency = linkedMapOf("oldSize" to StoreJs.num(ps), "newSize" to StoreJs.num(size), "path" to ArrayList<Any?>())
            }
            val req = linkedMapOf<String, Any?>("head" to ch)
            if (consistency != null) req["consistency"] = consistency
            req["rev_ids"] = ArrayList<Any?>(revIds)
            try {
                cosigs.add(w.cosign(req))
            } catch (e: RuntimeException) {
                errors.add(e)
            }
        }
        val need = threshold ?: witnesses.size
        if (cosigs.size < need) throw (if (errors.isEmpty()) IllegalStateException("publishHead: not enough witnesses") else errors[0])
        snaps[ch["sig"] as String] = Snapshot(log.commits(), RevocationSet(rev.list()))
        return ch
    }
}
