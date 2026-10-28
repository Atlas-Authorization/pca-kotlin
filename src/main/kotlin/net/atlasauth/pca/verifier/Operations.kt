package net.atlasauth.pca.verifier

/**
 * Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
 *
 * [Authorize.authorize] decides and consumes the PCActn's replay counter. Between that decision and the end of the side
 * effect the process can crash, the client can time out and retry, or two workers can pick up the same authorization. This
 * object closes that gap with a record per operation id ([Authorize.AuthorizedOperation.id], the digest of the presented PCActn):
 *
 *  1. [executeAuthorized] creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N
 *     concurrent executions of one authorization exactly one gets to run `fn`);
 *  2. for an irreversible operation it re-checks revocation, expiry and approval immediately before `fn` (`recheck`; required,
 *     fail closed); a failed re-check records `aborted` and `fn` never runs;
 *  3. it moves the record to `executing` and only then calls `fn` with the operation id as the idempotency key for the
 *     downstream call;
 *  4. the record becomes `committed` (with `fn`'s result) or `failed` (with its error) afterwards.
 *
 * A second execution of the same id never runs `fn` again: it is answered from the record. Nothing is re-run after a crash
 * either. Once `pendingTimeoutMs` has passed, a record still `pending` is settled as `aborted` (the side effect never
 * started: the agent may sign a fresh PCActn), and one still `executing` as `uncertain` (the side effect may or may not have
 * happened: an operator or a reconciliation job settles it with [resolveOperation], asking the downstream system by the
 * idempotency key). [Executor] combines `authorize` and [executeAuthorized] so that a retry of the same PCActn (which `authorize`
 * refuses as a replay) is answered from the record instead of a bare replay denial.
 *
 * Records are JSON objects (`Map<String, Any?>`) with the reference's keys (`startedAt`, `executingAt`, `finishedAt`, ...), so a
 * store shared with other implementations holds one format. `fn`'s result must be JSON-serialisable for a durable store.
 */
object Operations {
    const val PENDING_TIMEOUT_MS = 5 * 60_000L

    val STATES = listOf("pending", "executing", "committed", "failed", "aborted", "uncertain")

    // ---- stores ----

    /**
     * The operation-record store contract. [create] and [transition] MUST be atomic across every process and node that shares the
     * store (a unique-key insert and a conditional `UPDATE ... WHERE state = ?`, a Redis Lua script, a row lock). A call that cannot
     * decide MUST throw; the executor then refuses or reports the outcome as unknown.
     */
    interface Store {
        /** Atomically insert `record` if no record with its id exists (returns null); otherwise return the existing record unchanged. */
        fun create(record: Map<String, Any?>): Map<String, Any?>?

        fun get(id: String): Map<String, Any?>?

        /** Atomically replace the record with `next` only if its current state is `from`. Returns whether it did. */
        fun transition(id: String, from: String, next: Map<String, Any?>): Boolean

        /** Records still open (`pending` or `executing`) for [recoverOperations]; null when the store cannot list (recover by id). */
        fun listOpen(): List<Map<String, Any?>>? = null

        /** `"process"` (the records die with the process: tests and single-process tools) or `"shared"`. */
        val scope: String get() = "shared"
    }

    /** In-memory [Store] for ONE process (tests, a single worker). Its records die with the process. */
    class MemoryStore : Store {
        private val m = HashMap<String, Map<String, Any?>>()
        override val scope: String get() = "process"

        override fun create(record: Map<String, Any?>): Map<String, Any?>? = synchronized(m) {
            val id = record["id"] as String
            val cur = m[id]
            if (cur != null) return@synchronized LinkedHashMap(cur)
            m[id] = LinkedHashMap(record)
            null
        }

        override fun get(id: String): Map<String, Any?>? = synchronized(m) { m[id]?.let { LinkedHashMap(it) } }

        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean = synchronized(m) {
            if (m[id]?.get("state") != from) return@synchronized false
            val n = LinkedHashMap(next)
            n["id"] = id
            m[id] = n
            true
        }

        override fun listOpen(): List<Map<String, Any?>> = synchronized(m) {
            m.values.filter { it["state"] == "pending" || it["state"] == "executing" }.map { LinkedHashMap(it) }
        }
    }

    private fun asRecord(v: Any?): Map<String, Any?>? {
        if (v !is Map<*, *> || v["id"] !is String || v["state"] !is String) return null
        @Suppress("UNCHECKED_CAST")
        return v as Map<String, Any?>
    }

    /**
     * [Store] over any [AtomicKv] ([JdbcAtomicKv]: crash-safe and multi-process-safe). `prefix` namespaces the keys. It has no
     * `listOpen`; recover a known id with [recoverOperation].
     */
    class KvStore @JvmOverloads constructor(
        private val kv: AtomicKv,
        private val prefix: String = "pca-op:",
        override val scope: String = "shared",
    ) : Store {
        override fun create(record: Map<String, Any?>): Map<String, Any?>? {
            var existing: Map<String, Any?>? = null
            kv.update(prefix + (record["id"] as String)) { prev ->
                existing = asRecord(prev)
                if (existing != null) null else LinkedHashMap(record)
            }
            return existing
        }

        override fun get(id: String): Map<String, Any?>? = asRecord(kv.get(prefix + id))

        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            var done = false
            kv.update(prefix + id) { prev ->
                done = asRecord(prev)?.get("state") == from
                if (done) LinkedHashMap(next).also { it["id"] = id } else null
            }
            return done
        }
    }

    /** A durable [Store] on a JDBC database (SQLite and PostgreSQL both work); the table is created when missing. */
    @JvmOverloads
    fun jdbcStore(connections: PcaJdbcStateStore.ConnectionSource, table: String = "pca_kv"): KvStore = KvStore(JdbcAtomicKv(connections, table))

    // ---- executing ----

    /** What a pre-execution re-check answered. */
    class Recheck private constructor(val ok: Boolean, val reason: String?) {
        companion object {
            val OK = Recheck(true, null)
            fun refuse(reason: String): Recheck = Recheck(false, reason)
        }
    }

    /** What the executed function receives. [idempotencyKey] is the operation id: pass it as the idempotency key of the downstream call. */
    class ExecutionHandle(val idempotencyKey: String, val operation: Authorize.AuthorizedOperation, val pcactn: Map<String, Any?>)

    /**
     * The outcome of an execution attempt; `replayed` means it was answered from an existing record. `status`:
     * `committed` ([result]; `recorded` false = `fn` ran but the record could not be written: it stays executing and becomes
     * uncertain), `failed` ([error]), `aborted` ([reason]), `pending` (another execution of this id is in flight), `uncertain`
     * ([reason]: an earlier outcome is unknown, reconcile it), `refused` (nothing recorded: the authorization does not allow this
     * operation, or the configuration is incomplete) or `denied` (the [Executor]: [authorization] is the denying result, nothing ran).
     */
    class ExecuteOutcome internal constructor(
        val status: String,
        val operationId: String? = null,
        val result: Any? = null,
        val replayed: Boolean = false,
        val recorded: Boolean = true,
        val error: String? = null,
        val reason: String? = null,
        val authorization: Authorize.Result? = null,
    ) {
        /** The reference's JSON shape of the outcome. */
        fun toMap(): Map<String, Any?> = when (status) {
            "committed" -> linkedMapOf("status" to status, "operationId" to operationId, "result" to result, "replayed" to replayed, "recorded" to recorded)
            "failed" -> linkedMapOf("status" to status, "operationId" to operationId, "error" to error, "replayed" to replayed)
            "aborted", "uncertain" -> linkedMapOf("status" to status, "operationId" to operationId, "reason" to reason, "replayed" to replayed)
            "pending" -> linkedMapOf("status" to status, "operationId" to operationId, "replayed" to true)
            else -> linkedMapOf("status" to status, "reason" to reason)
        }

        override fun toString(): String = "Operations.ExecuteOutcome(${toMap()})"
    }

    private fun storeOk(store: Store?): Boolean = store != null

    private fun num(v: Any?): Double? = IntentJs.num(v)

    private fun settleStale(store: Store, rec: Map<String, Any?>, now: Long, timeoutMs: Double): Map<String, Any?> {
        val st = rec["state"]
        if (st != "pending" && st != "executing") return rec
        // `executing` is aged from the moment `fn` was started (a slow re-check does not count against it)
        val start = (if (st == "executing") num(rec["executingAt"]) ?: num(rec["startedAt"]) else num(rec["startedAt"])) ?: return rec
        if (!(now - start > timeoutMs)) return rec
        val next = LinkedHashMap(rec)
        if (st == "pending") {
            next["state"] = "aborted"
            next["error"] = "not started within ${Revocation.fmt(timeoutMs)} ms of the claim: the side effect never ran"
        } else {
            next["state"] = "uncertain"
            next["error"] = "no outcome recorded within ${Revocation.fmt(timeoutMs)} ms of the start: the side effect may or may not have happened"
        }
        next["finishedAt"] = now
        val id = rec["id"] as String
        store.transition(id, st as String, next)
        // whatever is stored now (the original execution may have finished in between)
        return store.get(id) ?: next
    }

    private fun fromRecord(store: Store, rec0: Map<String, Any?>, now: Long, timeoutMs: Double): ExecuteOutcome {
        val rec = settleStale(store, rec0, now, timeoutMs)
        val id = rec["id"] as String
        return when (val st = rec["state"]) {
            "committed" -> ExecuteOutcome("committed", id, result = rec["result"], replayed = true, recorded = true)
            "failed" -> ExecuteOutcome("failed", id, error = (rec["error"] as? String)?.takeIf { it.isNotEmpty() } ?: "failed", replayed = true)
            "aborted" -> ExecuteOutcome("aborted", id, reason = (rec["error"] as? String)?.takeIf { it.isNotEmpty() } ?: "aborted", replayed = true)
            "uncertain" -> ExecuteOutcome("uncertain", id, reason = (rec["error"] as? String)?.takeIf { it.isNotEmpty() } ?: "outcome unknown", replayed = true)
            "pending", "executing" -> ExecuteOutcome("pending", id, replayed = true)
            else -> ExecuteOutcome("uncertain", id, reason = "unknown record state '${IntentRevocation.jsText(st, true)}'", replayed = true)
        }
    }

    /** Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state. */
    private fun finish(store: Store, rec: Map<String, Any?>, patch: Map<String, Any?>): Boolean {
        val out = LinkedHashMap(rec)
        out.putAll(patch)
        val id = rec["id"] as String
        if (store.transition(id, rec["state"] as String, out)) return true
        return rec["state"] == "executing" && store.transition(id, "uncertain", out)
    }

    private fun answerCurrent(store: Store, id: String, now: Long, timeoutMs: Double): ExecuteOutcome {
        val cur = store.get(id)
        return if (cur != null) fromRecord(store, cur, now, timeoutMs)
        else ExecuteOutcome("uncertain", id, reason = "the operation record disappeared", replayed = true)
    }

    /**
     * Execute an allowed [Authorize.authorize] result at most once, with a durable record (see the object doc). `fn` runs only if this
     * call created the `pending` record and the re-check (when required) passed; every other outcome is answered from the record. A
     * throw from `fn` is recorded as `failed` and returned, not re-thrown.
     *
     *  - `operation`  what the handler is about to execute: the authorization must be for exactly it ([Authorize.isAuthorizedFor]).
     *  - `recheck`    re-checks, immediately before `fn`, that the authorization still stands (the grant is not revoked, the
     *                 approval has not expired or been withdrawn). REQUIRED for an irreversible operation (fail closed); with
     *                 `recheckFor = "always"` for every class. The PCActn's own `exp` is always checked with it. A throw counts as a refusal.
     *  - `reversibilityClass`  the server's authoritative class; the stricter of it and the signed class applies (missing = irreversible).
     *  - `pendingTimeoutMs`    an open record older than this is settled (pending -> aborted, executing -> uncertain). Default 5 min.
     *  - `now`        the clock (epoch ms).
     */
    fun executeAuthorized(
        authorization: Authorize.Result?,
        store: Store?,
        operation: Authorize.Operation? = null,
        recheck: ((ExecutionHandle) -> Recheck)? = null,
        recheckFor: String = "irreversible",
        reversibilityClass: String? = null,
        pendingTimeoutMs: Double = PENDING_TIMEOUT_MS.toDouble(),
        now: () -> Long = { System.currentTimeMillis() },
        fn: (ExecutionHandle) -> Any?,
    ): ExecuteOutcome {
        if (!storeOk(store)) return ExecuteOutcome("refused", reason = "executeAuthorized: missing required component: store (fail closed)")
        val pcactn = authorization?.pcactn
        val op = authorization?.operation
        if (authorization == null || !authorization.allow || pcactn == null || op == null || op.id.isEmpty())
            return ExecuteOutcome("refused", reason = "executeAuthorized: the authorization did not allow an operation")
        if (operation != null && !Authorize.isAuthorizedFor(authorization, operation))
            return ExecuteOutcome("refused", reason = "executeAuthorized: the authorization is not for this operation (verb, resource or params differ)")
        val st = store!!
        val action = pcactn["action"] as? Map<*, *>
        val cls = Revocation.effectiveReversibility(reversibilityClass, action?.get("reversibility_class"))
        val mustRecheck = cls == "irreversible" || recheckFor == "always"
        if (mustRecheck && recheck == null)
            return ExecuteOutcome("refused", reason = "executeAuthorized: a $cls operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)")

        val handle = ExecutionHandle(op.id, op, pcactn)
        val rec = linkedMapOf<String, Any?>(
            "id" to op.id, "state" to "pending", "verb" to op.verb, "resource" to op.resource, "params_digest" to op.paramsDigest,
            "reversibility" to cls, "startedAt" to now(),
        )
        val existing = st.create(rec)
        if (existing != null) return fromRecord(st, existing, now(), pendingTimeoutMs)

        if (mustRecheck) {
            var rc: Recheck
            try {
                val t = now()
                val exp = pcactn["exp"]
                val expNum = if (exp is Boolean) null else num(exp)
                rc = if (expNum != null && t > expNum) Recheck.refuse("the PCActn expired at ${Revocation.fmt(expNum)}") else recheck!!(handle)
            } catch (e: Exception) {
                rc = Recheck.refuse("recheck error (fail closed): ${e.message ?: e.javaClass.simpleName}")
            }
            if (!rc.ok) {
                val reason = "recheck: ${rc.reason?.takeIf { it.isNotEmpty() } ?: "refused"}"
                val patch = linkedMapOf<String, Any?>("state" to "aborted", "error" to reason, "finishedAt" to now())
                if (finish(st, rec, patch)) return ExecuteOutcome("aborted", op.id, reason = reason, replayed = false)
                return answerCurrent(st, op.id, now(), pendingTimeoutMs)
            }
        }

        // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
        val running = LinkedHashMap(rec)
        running["state"] = "executing"
        running["executingAt"] = now()
        if (!st.transition(op.id, "pending", running)) return answerCurrent(st, op.id, now(), pendingTimeoutMs)

        val result: Any? = try {
            fn(handle)
        } catch (e: Exception) {
            val error = e.message ?: e.javaClass.simpleName
            try { finish(st, running, linkedMapOf("state" to "failed", "error" to error, "finishedAt" to now())) } catch (ignored: Exception) {}
            return ExecuteOutcome("failed", op.id, error = error, replayed = false)
        }
        val recorded: Boolean = try {
            finish(st, running, linkedMapOf("state" to "committed", "result" to result, "finishedAt" to now()))
        } catch (e: Exception) {
            false
        }
        return ExecuteOutcome("committed", op.id, result = result, replayed = false, recorded = recorded)
    }

    /** [recoverOperations] for one id. Returns the record as it now stands (null: no record, the operation never started). */
    @JvmOverloads
    fun recoverOperation(store: Store, id: String, olderThanMs: Double = PENDING_TIMEOUT_MS.toDouble(), now: () -> Long = { System.currentTimeMillis() }): Map<String, Any?>? {
        val r = store.get(id) ?: return null
        return settleStale(store, r, now(), olderThanMs)
    }

    /**
     * Settle every open record older than `olderThanMs` (run it at startup and periodically): `pending` -> `aborted` (the side effect
     * never started), `executing` -> `uncertain`. Returns the records it settled. Needs a store that lists ([Store.listOpen]), else
     * throws [UnsupportedOperationException]. Nothing is re-run: reconcile each `uncertain` one with [resolveOperation].
     */
    @JvmOverloads
    fun recoverOperations(store: Store, olderThanMs: Double = PENDING_TIMEOUT_MS.toDouble(), now: () -> Long = { System.currentTimeMillis() }): List<Map<String, Any?>> {
        val open = store.listOpen() ?: throw UnsupportedOperationException("recoverOperations: the store has no listOpen (recover by id with recoverOperation)")
        val out = ArrayList<Map<String, Any?>>()
        for (r in open) {
            val u = recoverOperation(store, r["id"] as String, olderThanMs, now)
            if (u != null && u["state"] != r["state"]) out.add(u)
        }
        return out
    }

    /**
     * Settle an `uncertain` record after reconciling with the downstream system (look the idempotency key up there):
     * `committed` (with the result it reports) or `failed` (it never applied). False if the record is not `uncertain`.
     */
    @JvmOverloads
    fun resolveOperation(store: Store, id: String, committed: Boolean, resultOrError: Any? = null, now: () -> Long = { System.currentTimeMillis() }): Boolean {
        val r = store.get(id)
        if (r == null || r["state"] != "uncertain") return false
        val next = LinkedHashMap(r)
        next["finishedAt"] = now()
        if (committed) {
            next["state"] = "committed"
            if (resultOrError != null) next["result"] = resultOrError
        } else {
            next["state"] = "failed"
            next["error"] = resultOrError
        }
        return store.transition(id, "uncertain", next)
    }

    // ---- the executor ----

    /**
     * `authorize` + [executeAuthorized] in one call, with retries answered from the record. A second presentation of the same PCActn is
     * refused by `authorize` as a replay; if that replay is the ONLY failing check (the proof, binding, policy and revocation all still
     * pass now) and a record exists for its operation id and this operation, the record's outcome is returned (`replayed`) instead of
     * the denial. No record means the first attempt never reached execution: the denial stands (the authorization was consumed; the
     * agent signs a fresh PCActn).
     *
     * The executor always re-runs `options.isRevoked` against the grant from `resolveGrant`, checks the PCActn's expiry and, with
     * `options.plans`, that a registered plan is still executable; `recheck` adds to them (e.g. a step-up approval still stands).
     * `reversibilityClassOf(operation)` is the server's catalog class for an operation.
     */
    class Executor @JvmOverloads constructor(
        private val operations: Store?,
        private val options: Authorize.AuthorizeOptions,
        private val audience: String?,
        private val resolveGrant: ((String) -> Map<String, Any?>?)?,
        private val recheck: ((ExecutionHandle) -> Recheck)? = null,
        private val recheckFor: String = "irreversible",
        private val reversibilityClassOf: ((Authorize.Operation) -> String?)? = null,
        private val pendingTimeoutMs: Double = PENDING_TIMEOUT_MS.toDouble(),
        private val now: () -> Long = { System.currentTimeMillis() },
    ) {
        private fun recheckAll(h: ExecutionHandle): Recheck {
            val p = h.pcactn
            val grantRef = p["grant_ref"] as? String
            val grant = if (grantRef == null) null else resolveGrant?.invoke(grantRef)
            if (grant == null) return Recheck.refuse("the grant is no longer known")
            val revoked: Any? = try { options.isRevoked?.invoke(p, grant) } catch (e: Exception) { null }
            if (revoked != false) return Recheck.refuse(if (revoked == true) "the grant has been revoked" else "revocation could not be checked")
            // a registered plan must still be executable: not revoked, the principal's approval not expired
            val plans = options.plans
            val pl = p["plan"] as? Map<*, *>
            val root = pl?.get("root")
            if (plans != null && root is String && plans.get(grantRef!!, root) != null) {
                val ps = plans.check(grantRef, root, nodeId = pl["node_id"] as? String, now = now())
                if (!ps.executable) return Recheck.refuse(ps.reason ?: "plan is ${ps.state}")
            }
            return recheck?.invoke(h) ?: Recheck.OK
        }

        /** Authorize `pcactn` for `operation` and, when allowed, run `fn` at most once (see the class doc). */
        fun execute(
            pcactn: Any?, operation: Authorize.Operation?, intentPolicy: Pca.IntentPolicy? = null,
            intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null, escalationAnswer: Any? = null,
            workflowCall: Authorize.WorkflowStep? = null, fn: (ExecutionHandle) -> Any?,
        ): ExecuteOutcome {
            if (!storeOk(operations)) return ExecuteOutcome("refused", reason = "createExecutor: missing required component: operations (fail closed)")
            val ops = operations!!
            val r = options.run(pcactn, operation, audience, resolveGrant, now(), intentPolicy, intentV2, escalationAnswer, workflowCall = workflowCall)
            if (r.allow) {
                val cls = if (operation != null) reversibilityClassOf?.invoke(operation) else null
                return executeAuthorized(r, ops, operation, { h -> recheckAll(h) }, recheckFor, cls, pendingTimeoutMs, now, fn)
            }
            val failed = r.checks.filterValues { it == "fail" }.keys
            if (r.status != 403 || failed.toList() != listOf("replay")) return ExecuteOutcome("denied", reason = r.reason, authorization = r)
            // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
            val p = Authorize.coerceProof(pcactn).first ?: return ExecuteOutcome("denied", reason = r.reason, authorization = r)
            val rec = ops.get(Pca.hashCanonical(p))
            if (rec == null || operation == null || rec["verb"] != operation.verb || rec["resource"] != operation.resource ||
                rec["params_digest"] != Pca.paramsDigest(operation.params)
            ) return ExecuteOutcome("denied", reason = r.reason, authorization = r)
            return fromRecord(ops, rec, now(), pendingTimeoutMs)
        }
    }
}
