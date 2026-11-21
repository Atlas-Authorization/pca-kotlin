package net.atlasauth.pca.doctor

import net.atlasauth.pca.doctor.Doctor.CheckResult
import net.atlasauth.pca.storeconformance.Kit
import net.atlasauth.pca.storeconformance.Op
import net.atlasauth.pca.storeconformance.Reference
import net.atlasauth.pca.storeconformance.Runner
import net.atlasauth.pca.storeconformance.StoreAdapter
import net.atlasauth.pca.storeconformance.Workloads

/**
 * Replay / counter store checks through the conformance kit's adapter interface: a REAL concurrent conflicting write (many clients
 * consume one fresh key at once: exactly one may win; counters race on one stream) and durability (write, close, restart when the
 * adapter can, read back). Short by design; the full kit goes further.
 */
internal object DoctorStore {
    private fun opName(kind: String): String = if (kind == "consume") "consumeOnce" else "advance"

    private fun firstCounterexample(h: Kit.HistoryCheck): String {
        if (h.violations.isEmpty()) return ""
        val v = h.violations[0]
        val ce: List<Op> = v.counterexample ?: ArrayList()
        return " First violating key " + v.key + ": " + Kit.formatOps(ce).joinToString(" | ")
    }

    /** Without a store adapter the replay store cannot be exercised remotely: both checks are skipped. */
    fun checkStore(cfg: Map<String, Any?>): List<CheckResult> {
        val store = Js.g(cfg, "store")
        val spec = Js.g(store, "adapter")
        val out = ArrayList<CheckResult>()
        if (!Js.truthy(spec)) {
            val detail = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely"
            out.add(CheckResult.of("store.atomicity", "skip", detail))
            out.add(CheckResult.of("store.durability", "skip", detail))
            return out
        }
        val options = LinkedHashMap<String, String>()
        val opts = Js.g(store, "options")
        if (opts is Map<*, *>) for ((k, v) in opts) options[k as String] = Js.str(v)
        val adapter: StoreAdapter = try {
            Reference.loadAdapter(Js.str(spec), options)
        } catch (e: Exception) {
            return listOf(
                CheckResult.of("store.atomicity", "fail", "cannot load the store adapter " + Js.str(spec) + ": " + e.message)
                    .fix("Point --store at a store adapter class (see the store conformance kit guide)."),
            )
        }
        try {
            val kinds = Runner.detectKinds(adapter)
            val res = ArrayList<CheckResult>()
            res.add(atomicity(adapter, kinds, store))
            res.add(durability(adapter, kinds))
            return res
        } catch (e: Exception) {
            return listOf(CheckResult.of("store.atomicity", "fail", "the store adapter failed: " + e.message).fix(Doctor.ATOMICITY_REMEDIATION))
        } finally {
            try { adapter.teardown() } catch (ignored: Exception) { /* the check's result stands */ }
        }
    }

    private fun atomicity(adapter: StoreAdapter, kinds: List<String>, store: Any?): CheckResult {
        val clients = Js.toNumber(Js.or(Js.g(store, "concurrency"), 32.0)).toInt()
        val rounds = Js.toNumber(Js.or(Js.g(store, "rounds"), 10.0)).toInt()
        val parts = ArrayList<String>()
        val observed = LinkedHashMap<String, Any?>()
        var status = "pass"
        var cx = ""
        for (kind in kinds) {
            val wo = Workloads.WorkloadOptions()
            wo.clients = clients
            wo.rounds = rounds
            wo.values = 8
            val w = Workloads.runBurst(adapter, kind, wo)
            val h = Kit.checkHistory(w.ops, null)
            val winners = HashSet<String>()
            for (o in w.ops) if (o.res == "true") winners.add(o.key)
            val oc = LinkedHashMap<String, Any?>()
            oc["true"] = h.outcomes[0]
            oc["false"] = h.outcomes[1]
            oc["unknown"] = h.outcomes[2]
            val ob = LinkedHashMap<String, Any?>()
            ob["ops"] = h.ops
            ob["keys"] = h.keys
            ob["outcomes"] = oc
            ob["violations"] = h.violations.size
            ob["unresolved"] = h.unresolved.size
            observed[kind] = ob
            val definite = h.outcomes[0] + h.outcomes[1]
            if (h.violations.isNotEmpty()) {
                status = "fail"
                if (cx.isEmpty()) cx = firstCounterexample(h)
                parts.add(opName(kind) + ": " + h.violations.size + " of " + rounds + " same-key rounds NOT linearizable (" + clients + " concurrent clients)")
            } else if (definite == 0 || h.unresolved.isNotEmpty()) {
                if (status == "pass") status = "warn"
                parts.add(
                    opName(kind) + ": inconclusive (" + w.errors + " of " + h.ops + " calls failed or timed out" +
                        (if (h.unresolved.isEmpty()) "" else ", " + h.unresolved.size + " key(s) undecided") + ")",
                )
            } else {
                parts.add(
                    opName(kind) + ": " + rounds + " rounds of " + clients + " concurrent conflicting calls linearizable" +
                        (if (kind == "consume") " (" + winners.size + " of " + rounds + " rounds had exactly one TRUE)" else "") +
                        (if (w.errors > 0) ", " + w.errors + " calls failed closed" else ""),
                )
            }
        }
        val r = CheckResult.of("store.atomicity", status, adapter.name() + ": " + parts.joinToString("; ") + "." + cx)
        if (status != "pass") r.fix(Doctor.ATOMICITY_REMEDIATION)
        return r.observed(observed)
    }

    private fun durability(adapter: StoreAdapter, kinds: List<String>): CheckResult {
        if (adapter.capabilities()?.durable == false) {
            return CheckResult.of("store.durability", "warn", adapter.name() + " declares itself non-durable: a restart forgets consumed nonces").fix(Doctor.DURABILITY_REMEDIATION)
        }
        val parts = ArrayList<String>()
        var status = "pass"
        var cx = ""
        for (kind in kinds) {
            val w = Workloads.runDurability(adapter, kind, Workloads.WorkloadOptions())
            val h = Kit.checkHistory(w.ops, null)
            if (h.violations.isNotEmpty()) {
                status = "fail"
                if (cx.isEmpty()) cx = firstCounterexample(h)
                parts.add(opName(kind) + ": state LOST across close/restart")
            } else if (h.outcomes[0] + h.outcomes[1] < w.ops.size) {
                if (status == "pass") status = "warn"
                parts.add(opName(kind) + ": inconclusive (" + w.errors + " calls failed)")
            } else {
                parts.add(opName(kind) + ": survived")
            }
        }
        val how = if (adapter.hasRestart()) "write, close, restart() the backend, read back" else "write, close, re-open (no restart() hook: the backend itself was not restarted)"
        val r = CheckResult.of("store.durability", status, adapter.name() + " (" + how + "): " + parts.joinToString("; ") + "." + cx)
        if (status != "pass") r.fix(Doctor.DURABILITY_REMEDIATION)
        return r
    }
}
