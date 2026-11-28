package net.atlasauth.pca.sandbox

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca

/**
 * A per-sandbox capability table (a CSpace): indices are small integers meaningful only inside one table, like file descriptors.
 * A slot exists only because a verified authorization allowed exactly that operation, so the authority a tool holds is the set of
 * operations someone with the right to approve them approved. Derivation is monotone; revoking a slot revokes everything derived
 * from it. Handle indices are 1-based.
 */
@Suppress("UNCHECKED_CAST")
object Handles {
    /** Negative return codes of a handle use (the WASM ABI returns them as i32). */
    @JvmField
    val USE_ERR: Map<String, Long> = linkedMapOf(
        "unknown_handle" to -1L, "spent" to -2L, "out_too_small" to -3L, "bad_memory" to -4L, "executor_error" to -5L, "no_executor" to -6L,
    )

    /** What a tool may do with a handle: run the one authorized operation. A null result or a throw is an executor error. */
    fun interface Executor {
        fun run(verb: String, resource: String, params: Map<String, Any?>): ByteArray?
    }

    /** Outcome of a handle use. */
    class UseResult internal constructor(@JvmField val ok: Boolean, @JvmField val result: ByteArray?, @JvmField val reason: String?) {
        /** `{ok:true, result}` or `{ok:false, reason}`. */
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) m["result"] = result else m["reason"] = reason
            return m
        }
    }

    private fun fail(reason: String) = UseResult(false, null, reason)

    /** Options of [HandleTable.mint]: JSON numbers (or null for the default) and an optional minimum runtime class. */
    class MintOptions {
        /** How many times the handle may be used. Default 1. */
        @JvmField var uses: Any? = null

        /** Epoch ms after which the handle is spent. Default never. */
        @JvmField var expiresAt: Any? = null

        /** Refuse to mint into a table below this class. */
        @JvmField var requires: String? = null
    }

    private class Slot(val verb: String, val resource: String, val params: Map<String, Any?>, val paramsDigest: String, val opId: String, var uses: Long, val expiresAt: Double) {
        var revoked = false
        val children = ArrayList<Int>()
    }

    private fun deepCopy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = deepCopy(x) }
        is List<*> -> ArrayList<Any?>().also { out -> for (x in v) out.add(deepCopy(x)) }
        else -> v
    }

    /** The capability table of one sandbox. [now] is the clock in epoch ms (default the system clock). */
    class HandleTable @JvmOverloads constructor(
        private val runtimeClass: String, private val log: Receipts.ReceiptLog, private val executors: Map<String, Executor>, now: (() -> Double)? = null,
    ) {
        private val slots = ArrayList<Slot>()
        private val now: () -> Double = now ?: { System.currentTimeMillis().toDouble() }

        fun runtimeClass(): String = runtimeClass

        fun size(): Int = slots.size

        private fun slot(index: Long): Slot? = if (index >= 1 && index <= slots.size) slots[(index - 1).toInt()] else null

        private fun push(s: Slot): Int {
            slots.add(s)
            return slots.size
        }

        /** Mint a handle for the operation [result] allowed. Throws (fail closed) if [result] does not allow exactly [operation]. */
        fun mint(result: Authorize.Result, operation: Authorize.Operation, opts: MintOptions): Int {
            if (opts.requires != null && !Receipts.satisfiesRuntimeClass(runtimeClass, opts.requires))
                throw IllegalArgumentException("runtime_class_too_weak: table is $runtimeClass, grant requires ${opts.requires}")
            if (!Authorize.isAuthorizedFor(result, operation)) throw IllegalArgumentException("not_authorized: result does not allow exactly this operation")
            val u = Js.num(opts.uses ?: 1L)
            if (u == null || u.isNaN() || u.isInfinite() || u != Math.rint(u) || u < 1 || u > 1_000_000) throw IllegalArgumentException("bad_uses")
            val params = deepCopy(operation.params) as Map<String, Any?>
            val ex = if (opts.expiresAt == null) null else Js.num(opts.expiresAt)
            return push(Slot(operation.verb, operation.resource, params, Pca.hashCanonical(params), result.operation?.id ?: "", u.toLong(), ex ?: Double.POSITIVE_INFINITY))
        }

        /** Derive a narrower handle: takes [uses] from the parent (never more than it has) and an expiry no later than the parent's. */
        fun attenuate(index: Long, uses: Any?, expiresAt: Any?): Int {
            val p = live(index) ?: throw IllegalArgumentException("unknown_handle")
            val u = Js.num(uses ?: p.uses)
            if (u == null || u.isNaN() || u.isInfinite() || u != Math.rint(u) || u < 1 || u > p.uses) throw IllegalArgumentException("attenuate_widens")
            val ex = if (expiresAt == null) p.expiresAt else Js.num(expiresAt)
            if (ex == null || !(ex <= p.expiresAt)) throw IllegalArgumentException("attenuate_widens")
            p.uses -= u.toLong()
            val c = Slot(p.verb, p.resource, deepCopy(p.params) as Map<String, Any?>, p.paramsDigest, p.opId, u.toLong(), ex)
            val child = push(c)
            p.children.add(child)
            return child
        }

        /** Revoke a handle and, transitively, every handle derived from it. */
        fun revoke(index: Long) {
            val s = slot(index)
            if (s == null || s.revoked) return
            s.revoked = true
            for (c in s.children) revoke(c.toLong())
        }

        /** The verb a handle carries, or null. */
        fun verbOf(index: Long): String? = slot(index)?.verb

        /**
         * Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs
         * and stays consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).
         */
        fun use(index: Long): UseResult {
            val s = slot(index)
            if (s == null) {
                log.append(runtimeClass, body("", "", "", "", "refused", "unknown_handle"))
                return fail("unknown_handle")
            }
            val live = live(index) ?: return finish(s, fail("spent"))
            val exec = executors[s.verb] ?: return finish(s, fail("no_executor"))
            live.uses -= 1
            return try {
                val result = exec.run(s.verb, s.resource, deepCopy(s.params) as Map<String, Any?>)
                if (result == null) finish(s, fail("executor_error")) else finish(s, UseResult(true, result, null))
            } catch (e: Exception) {
                finish(s, fail("executor_error"))
            }
        }

        private fun finish(s: Slot, r: UseResult): UseResult {
            val outcome = if (r.ok) "ok" else if (r.reason == "executor_error") "error" else "refused"
            log.append(runtimeClass, body(s.opId, s.verb, s.resource, s.paramsDigest, outcome, if (r.ok) "used" else r.reason))
            return r
        }

        private fun live(index: Long): Slot? {
            val s = slot(index)
            if (s == null || s.revoked || s.uses <= 0) return null
            val t = now()
            return if (t.isFinite() && t < s.expiresAt) s else null // a -Infinity clock is "before" every expiry
        }
    }

    private fun body(opId: String, verb: String, resource: String, paramsDigest: String, outcome: String, reason: String?): Map<String, Any?> = linkedMapOf(
        "kind" to "handle_use",
        "subject" to linkedMapOf<String, Any?>("op_id" to opId, "verb" to verb, "resource" to resource, "params_digest" to paramsDigest),
        "outcome" to outcome, "reason" to reason,
    )
}
