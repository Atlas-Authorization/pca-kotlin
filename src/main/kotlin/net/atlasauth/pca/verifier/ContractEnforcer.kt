package net.atlasauth.pca.verifier

/**
 * Durable enforcement of a signed behavioural contract (packages/pca/src/contract-enforcer.ts). The monitor state is ONE document in an
 * [AtomicKv]; the whole read-check-advance runs inside `update`, so racing callers serialise and a counter-style state never forks. Only a
 * contract signed by the PINNED principal is loaded, the state document is bound to the contract id, every corrupt or unreadable state and
 * every store error DENIES, and a real violation LATCHES the enforcer until the principal signs a reset.
 */
@Suppress("UNCHECKED_CAST")
class ContractEnforcer private constructor(
    private val kv: AtomicKv,
    private val contract: Map<String, Any?>,
    private val key: String,
    private val now: () -> Double,
    private val latch: Boolean,
) {
    /** The outcome of one check: [reason] is ok, latched, violated, permission, state-error or store-error. */
    class Result internal constructor(val allow: Boolean, val reason: String, val violated: List<Any?>, val reasons: List<Any?>, val seq: Long)

    private fun res(allow: Boolean, reason: String, violated: List<Any?>, reasons: List<Any?>, seq: Long) = Result(allow, reason, violated, reasons, seq)

    /** A clock value as a JSON number; a non-finite one (NaN, +/-Infinity) stays a number the monitor refuses as a clock regression, as the reference does (never a thrown store error). */
    private fun clockNum(d: Double): Json.Num = if (d.isNaN() || d.isInfinite()) Json.Num(d.toString()) else Prohibitions.jn(d)

    private fun latchedResult(doc: Map<String, Any?>): Result {
        val l = Prohibitions.obj(doc["latched"])
        return res(false, "latched", ArrayList(Prohibitions.arr(l["violated"])), listOf("<latched>: contract violated at seq " + AttestUtil.jsNumString(Prohibitions.dv(l["seq"]))), seqOf(doc))
    }

    /** Checks one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws. */
    fun check(action: Any?, permitted: Boolean): Result {
        val id = contract["id"] as String
        var out = res(false, "store-error", emptyList(), listOf("store unavailable"), 0)
        try {
            val wall = now()
            kv.update(key) { prev ->
                if (prev != null && !isDoc(prev, id)) {
                    out = res(false, "state-error", emptyList(), listOf(CORRUPT), 0)
                    return@update null
                }
                val pd = if (prev == null) null else Prohibitions.obj(prev)
                if (pd != null && (wall.isNaN() || wall.isInfinite())) {
                    out = res(false, "state-error", emptyList(), listOf("<state>: clock is not finite"), seqOf(pd))
                    return@update null
                }
                val doc: Map<String, Any?> = pd ?: Prohibitions.map(
                    "v", Prohibitions.jn(DOC_VERSION.toDouble()), "contract_id", id,
                    "state", Prohibitions.emptyState(Prohibitions.jn(if (wall.isNaN() || wall.isInfinite()) 0.0 else wall)),
                )
                if (doc.containsKey("latched")) {
                    out = latchedResult(doc)
                    return@update null
                }
                val state = Prohibitions.obj(doc["state"])
                val stateNow = Prohibitions.dv(state["now"])
                val r = Contracts.checkAndAdvanceContract(permitted, state, action, contract, clockNum(Math.max(wall, stateNow)), state["seq"], null)
                if (r["allow"] == true) {
                    out = res(true, "ok", emptyList(), emptyList(), Prohibitions.dv(Prohibitions.obj(r["next"])["seq"]).toLong())
                    val next = LinkedHashMap(doc)
                    next["state"] = r["next"]
                    return@update next
                }
                val structural = r["decidedBy"] == "state"
                val violated = Prohibitions.arr(r["violated"])
                val real = !structural && violated.isNotEmpty()
                out = res(false, if (structural) "state-error" else if (real) "violated" else "permission", if (real) ArrayList(violated) else emptyList(), ArrayList(Prohibitions.arr(r["reasons"])), seqOf(doc))
                if (real && latch) {
                    val next = LinkedHashMap(doc)
                    next["latched"] = Prohibitions.map("seq", state["seq"], "violated", ArrayList(violated))
                    return@update next
                }
                null
            }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            out = res(false, "store-error", emptyList(), listOf("store error (fail closed)"), 0)
        }
        return out
    }

    /** Read-only evaluation against the stored state: nothing is advanced or latched. Never throws. */
    fun peek(action: Any?): Result = try {
        val prev = kv.get(key)
        if (prev != null && !isDoc(prev, contract["id"] as String)) res(false, "state-error", emptyList(), listOf(CORRUPT), 0)
        else if (prev != null && Prohibitions.obj(prev).containsKey("latched")) latchedResult(Prohibitions.obj(prev))
        else {
            val wall = now()
            val state = if (prev != null) Prohibitions.obj(prev)["state"] else Prohibitions.emptyState(Prohibitions.jn(if (wall.isNaN() || wall.isInfinite()) 0.0 else wall))
            val r = Contracts.checkContract(action, contract, state)
            val seq = if (prev != null) seqOf(Prohibitions.obj(prev)) else 0L
            if (r["ok"] == true) res(true, "ok", emptyList(), emptyList(), seq)
            else res(false, "violated", ArrayList(Prohibitions.arr(r["violated"])), ArrayList(Prohibitions.arr(r["reasons"])), seq)
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        res(false, "store-error", emptyList(), listOf("store error (fail closed)"), 0)
    }

    /** The stored state (and whether it is latched), or null when nothing was admitted yet. Throws [IllegalStateException] on a corrupt document. */
    fun state(): Map<String, Any?>? {
        val d = kv.get(key) ?: return null
        if (!isDoc(d, contract["id"] as String)) throw IllegalStateException("ContractEnforcer: stored state is corrupt or belongs to another contract")
        return Prohibitions.map("state", Prohibitions.obj(d)["state"], "latched", Prohibitions.obj(d).containsKey("latched"))
    }

    /** Un-latches with the principal's signature at the latched sequence (see [signReset]); returns whether it cleared. */
    fun reset(sig: String?): Boolean {
        var cleared = false
        val id = contract["id"] as String
        try {
            kv.update(key) { prev ->
                if (!isDoc(prev, id) || !Prohibitions.obj(prev).containsKey("latched")) return@update null
                val seq = Prohibitions.dv(Prohibitions.obj(Prohibitions.obj(prev)["latched"])["seq"]).toLong()
                if (sig == null || !IntentJs.verifyEd(contract["principal"], resetMessage(id, seq), sig)) return@update null
                cleared = true
                val next = LinkedHashMap(Prohibitions.obj(prev))
                next.remove("latched")
                next
            }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return false
        }
        return cleared
    }

    companion object {
        const val RESET_DOMAIN = "atlas-pca/contract-reset/v1\u0000"
        private const val DOC_VERSION = 1
        private const val CORRUPT = "<state>: stored state is corrupt or belongs to another contract"

        /**
         * Opens an enforcer; throws [IllegalArgumentException] unless the contract verifies under the pinned principal.
         * [key] and [now] (epoch milliseconds) default to `contract/<id>` and the wall clock.
         */
        @JvmStatic
        @JvmOverloads
        fun open(kv: AtomicKv?, contract: Any?, principal: String?, key: String? = null, now: (() -> Double)? = null, latchOnViolation: Boolean = true): ContractEnforcer {
            if (kv == null) throw IllegalArgumentException("ContractEnforcer: a durable key-value store is required")
            if (principal.isNullOrEmpty()) throw IllegalArgumentException("ContractEnforcer: a pinned principal is required")
            val v = Contracts.verifyContract(contract, principal)
            if (v != null) throw IllegalArgumentException("ContractEnforcer: contract refused: $v")
            val c = Prohibitions.obj(contract)
            return ContractEnforcer(kv, c, key ?: ("contract/" + Contracts.contractId(c)), now ?: { System.currentTimeMillis().toDouble() }, latchOnViolation)
        }

        private fun resetMessage(id: String, seq: Long): ByteArray =
            Pca.concat(RESET_DOMAIN.toByteArray(Charsets.UTF_8), AttestUtil.sha256("$id:$seq".toByteArray(Charsets.UTF_8)))

        /** The principal's authorisation to un-latch a contract at sequence [seq] (binds both, so it cannot be replayed later). */
        @JvmStatic
        fun signReset(principalSeed: ByteArray, contractId: String, seq: Long): String =
            Pca.b64(Keys.edFromSeed(principalSeed).sign(resetMessage(contractId, seq)))

        private fun isDoc(dO: Any?, id: String): Boolean {
            if (!Prohibitions.isObj(dO)) return false
            val d = Prohibitions.obj(dO)
            if (!Prohibitions.isInteger(d["v"]) || Prohibitions.dv(d["v"]) != DOC_VERSION.toDouble() || id != d["contract_id"] || Prohibitions.stateProblem(d["state"]) != null) return false
            if (!d.containsKey("latched")) return true
            val l = d["latched"]
            if (!Prohibitions.isObj(l)) return false
            val lm = Prohibitions.obj(l)
            if (!Prohibitions.isInteger(lm["seq"]) || Prohibitions.negZero(lm["seq"]) || lm["violated"] !is List<*>) return false
            for (v in Prohibitions.arr(lm["violated"])) if (v !is String) return false
            return true
        }

        private fun seqOf(doc: Map<String, Any?>): Long = Prohibitions.dv(Prohibitions.obj(doc["state"])["seq"]).toLong()
    }
}
