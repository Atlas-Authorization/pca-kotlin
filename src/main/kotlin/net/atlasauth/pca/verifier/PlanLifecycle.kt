package net.atlasauth.pca.verifier

import java.net.URLEncoder

/**
 * Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the
 * principal's plan authorization.
 *
 * ```
 * draft --validate--> validated --commit--> committed --authorize--> authorized
 *   |_____________________|_______________________|__________revoke______|--> revoked
 * ```
 *  - `draft`: the nodes are recorded; the root is computed from them (never taken from the caller).
 *  - `validated`: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the server's
 *    own validator.
 *  - `committed`: the root is fixed. A committed plan is NOT executable: it still needs the principal.
 *  - `authorized`: the principal approved this root for this grant, optionally until `expiresAt`.
 *  - `revoked`: terminal; every later action against the root is denied.
 *
 * "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is `authorized`, the approval has
 * not expired and its stored nodes still hash to the root. [PlanRegistry.check] adds the per-action rules a server applies
 * immediately before execution: the node exists and the operation's verb, resource and params still match what the principal approved.
 *
 * Records are JSON objects with the reference's keys (`grantRef`, `createdAt`, ...), so a registry on a shared store is
 * interchangeable with the other implementations'. `Authorize.Input.plans` feeds the stored plan and its executability into the
 * verification context.
 */
object PlanLifecycle {
    val STATES = listOf("draft", "validated", "committed", "authorized", "revoked")

    /** The Merkle root of a plan's nodes (plan-node leaves; equals the TypeScript root). Throws on an unhashable plan. */
    fun planRoot(nodes: List<Map<String, Any?>>): String =
        Pca.merkleRoot(nodes.map { Pca.planLeaf(it["id"], it, Pca.conditionsDigest(it["pre"], it["post"])) })

    /** The structural problem of a plan's nodes, or null when valid. */
    fun structuralProblem(nodes: Any?): String? {
        if (nodes !is List<*> || nodes.isEmpty()) return "a plan needs at least one node"
        val ids = HashSet<String>()
        for (n in nodes) {
            val id = (n as? Map<*, *>)?.get("id")
            if (n !is Map<*, *> || id !is String || id == "") return "every node needs an id"
            if (!ids.add(id)) return "duplicate node id '$id'"
            val verb = n["verb"]
            val resource = n["resource"]
            if (verb !is String || verb == "" || resource !is String || resource == "") return "node '$id' needs a verb and a resource"
            if (n.containsKey("reversibility_class")) {
                val rc = n["reversibility_class"]
                if (!(rc is String && Revocation.isKnownClass(rc))) return "node '$id' has an unknown reversibility class '${IntentRevocation.jsText(rc, true)}'"
            }
        }
        return null
    }

    /** The result of a lifecycle transition: `ok` with the new `record`, or not ok with the plan's current `state` (`unknown` for none) and the `reason`. */
    class Transition internal constructor(val ok: Boolean, val record: Map<String, Any?>? = null, val state: String? = null, val reason: String? = null) {
        /** The reference's JSON shape. */
        fun toMap(): Map<String, Any?> =
            if (ok) linkedMapOf("ok" to true, "record" to record) else linkedMapOf("ok" to false, "state" to state, "reason" to reason)

        override fun toString(): String = "PlanLifecycle.Transition(${toMap()})"
    }

    /** A plan's state at the moment of use. [state] is `unknown` for a root the registry does not hold. */
    class Status internal constructor(val state: String, val executable: Boolean, val reason: String? = null, val record: Map<String, Any?>? = null) {
        fun toMap(): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("state" to state, "executable" to executable)
            if (reason != null) m["reason"] = reason
            if (record != null) m["record"] = record
            return m
        }

        override fun toString(): String = "PlanLifecycle.Status(${toMap()})"
    }

    /** The verifier context for an action against a root: the stored `plan` nodes, `planAuthorized` (= executable now) and the [status]. */
    class PlanContext internal constructor(val plan: List<Map<String, Any?>>, val planAuthorized: Boolean, val status: Status) {
        fun toMap(): Map<String, Any?> = linkedMapOf("plan" to plan, "planAuthorized" to planAuthorized, "status" to status.toMap())
    }

    /** What a server validator answered. */
    class Validation private constructor(val ok: Boolean, val reason: String?) {
        companion object {
            val OK = Validation(true, null)
            fun refuse(reason: String): Validation = Validation(false, reason)
        }
    }

    private fun isRecord(v: Any?): Boolean = v is Map<*, *> && v["root"] is String && v["nodes"] is List<*>

    @Suppress("UNCHECKED_CAST")
    private fun rec(v: Any?): Map<String, Any?>? = if (isRecord(v)) v as Map<String, Any?> else null

    /** JavaScript `encodeURIComponent`. */
    private fun encodeUriComponent(s: String): String =
        URLEncoder.encode(s, "UTF-8").replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(").replace("%29", ")").replace("%7E", "~")

    /**
     * The plan registry. `kv` is an atomic key/value store ([MemoryAtomicKv] by default; [JdbcAtomicKv] for durable, multi-process
     * state). `now` is the clock (epoch ms). `validator` is the server's validation, run by [validate] after the structural checks;
     * a throw refuses.
     */
    class PlanRegistry @JvmOverloads constructor(
        private val kv: AtomicKv = MemoryAtomicKv(),
        private val prefix: String = "pca-plan:",
        private val now: () -> Long = { System.currentTimeMillis() },
        private val validator: ((Map<String, Any?>) -> Validation)? = null,
    ) {
        private fun key(grantRef: String, root: String) = "$prefix${encodeUriComponent(grantRef)}:$root"

        fun get(grantRef: String, root: String): Map<String, Any?>? = rec(kv.get(key(grantRef, root)))

        private fun move(grantRef: String, root: String, from: List<String>, to: String, next: (Map<String, Any?>) -> Map<String, Any?>): Transition {
            var out = Transition(false, state = "unknown", reason = "plan $root is unknown for this grant")
            kv.update(key(grantRef, root)) { prev ->
                val cur = rec(prev)
                if (cur == null) {
                    out = Transition(false, state = "unknown", reason = "plan $root is unknown for this grant")
                    null
                } else if (cur["state"] !in from) {
                    out = Transition(false, state = cur["state"] as String, reason = "plan $root is ${cur["state"]}: cannot $to")
                    null
                } else {
                    val n = next(cur)
                    out = Transition(true, record = n)
                    n
                }
            }
            return out
        }

        /** Record a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused. */
        fun draft(grantRef: String?, nodes: List<Map<String, Any?>>): Transition {
            if (grantRef == null || grantRef == "") return Transition(false, state = "unknown", reason = "a plan needs a grant")
            // structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
            val root = try {
                planRoot(nodes)
            } catch (e: RuntimeException) {
                val m = e.message ?: "unknown"
                return Transition(false, state = "unknown", reason = "the plan cannot be committed: ${if (m == "empty leaf set") "merkleRoot: $m" else m}")
            }
            val record = linkedMapOf<String, Any?>(
                "grantRef" to grantRef, "root" to root, "nodes" to MemoryAtomicKv.copyTree(nodes), "state" to "draft", "createdAt" to now(),
            )
            var out = Transition(true, record = record)
            kv.update(key(grantRef, root)) { prev ->
                val cur = rec(prev)
                if (cur != null) {
                    out = Transition(false, state = cur["state"] as String, reason = "plan $root already exists (${cur["state"]})")
                    null
                } else record
            }
            return out
        }

        /** draft -> validated (structural checks, then the server's validator). */
        fun validate(grantRef: String, root: String): Transition {
            val cur = get(grantRef, root) ?: return Transition(false, state = "unknown", reason = "plan $root is unknown for this grant")
            val st = cur["state"] as String
            if (st != "draft") return Transition(false, state = st, reason = "plan $root is $st: cannot validate")
            @Suppress("UNCHECKED_CAST")
            val nodes = cur["nodes"] as List<Map<String, Any?>>
            var problem = structuralProblem(nodes)
            if (problem == null) {
                problem = try {
                    if (planRoot(nodes) == root) null else "the stored nodes no longer hash to the root"
                } catch (e: RuntimeException) {
                    "the stored nodes no longer hash to the root"
                }
            }
            if (problem != null) return Transition(false, state = st, reason = "plan $root is invalid: $problem")
            val v = validator
            if (v != null) {
                @Suppress("UNCHECKED_CAST")
                val copy = MemoryAtomicKv.copyTree(cur) as Map<String, Any?>
                val res: Validation = try {
                    v(copy)
                } catch (e: Exception) {
                    Validation.refuse("validator error (fail closed): ${e.message ?: e.javaClass.simpleName}")
                }
                if (!res.ok) return Transition(false, state = st, reason = "plan $root is invalid: ${res.reason?.takeIf { it.isNotEmpty() } ?: "refused by the validator"}")
            }
            return move(grantRef, root, listOf("draft"), "validate") { r -> LinkedHashMap(r).also { it["state"] = "validated"; it["validatedAt"] = now() } }
        }

        /** validated -> committed: the root is fixed; it still needs the principal's authorization to execute. */
        fun commit(grantRef: String, root: String): Transition =
            move(grantRef, root, listOf("validated"), "commit") { r -> LinkedHashMap(r).also { it["state"] = "committed"; it["committedAt"] = now() } }

        /**
         * committed -> authorized: the principal's approval (call it only after verifying the principal's consent). `approval` is
         * `{by: <who>, expiresAt?: <epoch ms>}`.
         */
        fun authorize(grantRef: String, root: String, approval: Map<String, Any?>?): Transition {
            fun stateNow() = get(grantRef, root)?.get("state") as? String ?: "unknown"
            val by = approval?.get("by")
            if (approval == null || by !is String || by == "") return Transition(false, state = stateNow(), reason = "an approval names who approved (`by`)")
            if (approval.containsKey("expiresAt") && IntentJs.num(approval["expiresAt"])?.isFinite() != true)
                return Transition(false, state = stateNow(), reason = "approval.expiresAt must be a time (epoch ms)")
            return move(grantRef, root, listOf("committed"), "authorize") { r ->
                LinkedHashMap(r).also { it["state"] = "authorized"; it["authorizedAt"] = now(); it["approval"] = LinkedHashMap(approval) }
            }
        }

        /** Any state except revoked -> revoked (terminal). */
        fun revoke(grantRef: String, root: String, reason: String?): Transition =
            move(grantRef, root, listOf("draft", "validated", "committed", "authorized"), "revoke") { r ->
                LinkedHashMap(r).also { it["state"] = "revoked"; it["revokedAt"] = now(); it["revokedReason"] = reason ?: "" }
            }

        /** The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). */
        @JvmOverloads
        fun status(grantRef: String, root: String, at: Long = now()): Status {
            val record = get(grantRef, root) ?: return Status("unknown", false, "plan $root is unknown for this grant")
            val st = record["state"] as String
            if (st != "authorized") {
                val why = when (st) {
                    "committed" -> "committed but not authorized by the principal"
                    "revoked" -> "revoked (${record["revokedReason"] ?: "no reason given"})"
                    else -> "$st, not authorized"
                }
                return Status(st, false, "plan $root is $why", record)
            }
            val exp = (record["approval"] as? Map<*, *>)?.get("expiresAt")
            if (exp != null) {
                val e = IntentJs.num(exp)
                if (e == null || !(at.toDouble() < e)) return Status(st, false, "plan $root: the principal's approval expired at ${IntentRevocation.jsText(IntentJs.normalize(exp), true)}", record)
            }
            @Suppress("UNCHECKED_CAST")
            val same = try { planRoot(record["nodes"] as List<Map<String, Any?>>) == root } catch (e: RuntimeException) { false }
            if (!same) return Status(st, false, "plan $root: the stored nodes no longer hash to the root", record)
            return Status(st, true, null, record)
        }

        /**
         * [status] plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately before
         * execution. `operation` is the one about to execute.
         */
        @JvmOverloads
        fun check(grantRef: String, root: String, nodeId: String? = null, operation: Authorize.Operation? = null, now: Long = this.now()): Status {
            val s = status(grantRef, root, now)
            val record = s.record
            if (!s.executable || record == null) return s
            if (nodeId == null && operation == null) return s
            @Suppress("UNCHECKED_CAST")
            val nodes = record["nodes"] as List<Map<String, Any?>>
            val node = if (nodeId != null) nodes.firstOrNull { it["id"] == nodeId } else null
            if (nodeId != null && node == null) return Status(s.state, false, "plan $root has no node '$nodeId'", record)
            if (operation != null) {
                val candidates = if (node != null) listOf(node) else nodes
                val digest = try {
                    Pca.paramsDigest(operation.params)
                } catch (e: RuntimeException) {
                    return Status(s.state, false, "plan $root: the operation's params cannot be hashed", record)
                }
                val empty = Pca.paramsDigest(null)
                val same = candidates.any { n ->
                    n["verb"] == operation.verb && n["resource"] == operation.resource && (n["params_digest"] ?: empty) == digest
                }
                if (!same) return Status(s.state, false, "plan $root: the operation (${operation.verb} on ${operation.resource} with these params) is not what the principal approved", record)
            }
            return s
        }

        /** True only when the plan is executable now (for hooks that take a yes / no). */
        fun isPlanAuthorized(grantRef: String, planRoot: String): Boolean = try {
            status(grantRef, planRoot).executable
        } catch (e: Exception) {
            false
        }

        /** The verifier context for an action against `root`; null for an unknown root. */
        @JvmOverloads
        fun context(grantRef: String, root: String, at: Long = now()): PlanContext? {
            val s = status(grantRef, root, at)
            val record = s.record ?: return null
            @Suppress("UNCHECKED_CAST")
            return PlanContext(MemoryAtomicKv.copyTree(record["nodes"]) as List<Map<String, Any?>>, s.executable, s)
        }
    }
}
