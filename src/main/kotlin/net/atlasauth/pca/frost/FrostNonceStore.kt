package net.atlasauth.pca.frost

/**
 * Durable round-1 nonce persistence for a FROST signer, built so a restart can neither lose a session nor reuse a nonce.
 *
 * Reusing one nonce pair across two messages reveals the signing share. The rule that prevents it across restarts is ORDER: the nonce is durably marked spent
 * BEFORE the signature share is computed. A crash after the mark loses that session (liveness cost: the coordinator opens a new one); a crash before it leaves an
 * unspent nonce that can still be used exactly once. The store never has to be trusted to forget a nonce: [spend] removes the secret bytes and keeps only the marker.
 *
 * The contract every implementation must meet (checked by [FrostNonceStore.assertNonceStoreContract]): `create` is durable before it returns and throws if the
 * session id exists in ANY state (live or spent); `load` returns the live record or null (spent, dropped and unknown ids all give null); `spend` is atomic and
 * durable, throws unless the session is live, deletes the secret nonces and records the id as spent forever (a second `spend` throws); `isSpent` is true for every
 * spent id, including after a restart; every method throws on failure. The signer treats any throw as a refusal (fail closed): no commitment is released when
 * `create` fails and no share is released when `spend` fails. The records hold SECRET nonces: a durable store must encrypt them at rest.
 */
class NonceRecord(val hiding: ByteArray, val binding: ByteArray, val hidingCommitment: ByteArray, val bindingCommitment: ByteArray, val createdAt: Double) {
    fun copy(): NonceRecord = NonceRecord(hiding.clone(), binding.clone(), hidingCommitment.clone(), bindingCommitment.clone(), createdAt)
}

interface NonceStore {
    fun create(sessionId: String, record: NonceRecord)
    fun load(sessionId: String): NonceRecord?
    fun spend(sessionId: String)
    fun drop(sessionId: String)
    fun isSpent(sessionId: String): Boolean
}

/** Reference implementation: correct, not durable (a process restart loses it, which fails closed). Use it as the model. */
class MemoryNonceStore : NonceStore {
    private val live = HashMap<String, NonceRecord>()
    private val spent = HashSet<String>()

    @Synchronized override fun create(sessionId: String, record: NonceRecord) {
        if (sessionId.isEmpty()) throw IllegalArgumentException("nonce-store: session id must be a non-empty string")
        if (live.containsKey(sessionId) || spent.contains(sessionId)) throw IllegalStateException("nonce-store: session already exists")
        live[sessionId] = record.copy()
    }

    @Synchronized override fun load(sessionId: String): NonceRecord? = live[sessionId]?.copy()

    @Synchronized override fun spend(sessionId: String) {
        val r = live[sessionId] ?: throw IllegalStateException("nonce-store: cannot spend a session that is not live")
        r.hiding.fill(0)
        r.binding.fill(0)
        live.remove(sessionId)
        spent.add(sessionId)
    }

    @Synchronized override fun drop(sessionId: String) {
        val r = live[sessionId]
        if (r != null) {
            r.hiding.fill(0)
            r.binding.fill(0)
            live.remove(sessionId)
        }
    }

    @Synchronized override fun isSpent(sessionId: String): Boolean = spent.contains(sessionId)
}

object FrostNonceStore {
    /**
     * Conformance check for a [NonceStore]. `reopen` must return a store over the SAME durable state (a simulated restart); for the in-memory reference it returns
     * the same instance. Throws `nonce-store contract: <what>` on the first violation.
     */
    @JvmStatic @JvmOverloads
    fun assertNonceStoreContract(make: () -> NonceStore, reopen: (NonceStore) -> NonceStore = { it }) {
        fun rec(n: Int) = NonceRecord(ByteArray(32) { n.toByte() }, ByteArray(32) { (n + 1).toByte() }, ByteArray(32) { (n + 2).toByte() }, ByteArray(32) { (n + 3).toByte() }, n.toDouble())
        fun must(ok: Boolean, what: String) {
            if (!ok) throw IllegalStateException("nonce-store contract: $what")
        }
        fun throws(f: () -> Unit): Boolean = try {
            f()
            false
        } catch (e: RuntimeException) {
            true
        }
        var s = make()
        must(s.load("a") == null && !s.isSpent("a"), "an unknown id is neither live nor spent")
        s.create("a", rec(1))
        must(throws { s.create("a", rec(9)) }, "create must refuse an existing live id")
        s.create("b", rec(5))
        s = reopen(s)
        val got = s.load("a")
        must(got != null && got.hiding[0].toInt() == 1 && got.createdAt == 1.0, "a live record survives a restart")
        got!!.hiding.fill(0xee.toByte())
        must(s.load("a")!!.hiding[0].toInt() == 1, "load returns a copy")
        s.spend("a")
        must(s.load("a") == null && s.isSpent("a"), "spend removes the secret and records the marker")
        must(throws { s.spend("a") }, "a second spend must throw")
        must(throws { s.create("a", rec(2)) }, "create must refuse a spent id")
        must(throws { s.spend("zzz") }, "spend of an unknown id must throw")
        s = reopen(s)
        must(s.isSpent("a") && s.load("a") == null, "a spent marker survives a restart")
        must(s.load("b") != null, "the other live record survives")
        s.drop("b")
        must(s.load("b") == null && !s.isSpent("b"), "drop removes a live record without marking it spent")
        s.drop("never-existed")
    }
}
