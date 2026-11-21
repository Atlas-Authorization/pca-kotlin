package net.atlasauth.pca.verifier

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. A record with `runtime_pins` is accepted; at the check it denies `admission_required` without an `admitted` hook and `not_admitted` when the hook says no. [Registry] keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch with
 * different content is a fork). A non-empty ceiling is never evaluated here: it denies (`ceiling_unevaluable`). Everything is total.
 */
object Blueprint {
    const val DOMAIN = "atlas-pca/agent-blueprint/v1\u0000"
    private val BODY_KEYS = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator")

    private val PIN_KEYS = listOf("runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id")

    private fun pinOk(x: Any?): Boolean {
        val m = K3Sig.map(x) ?: return false
        if (m.isEmpty()) return false
        for ((k, s) in m) if (k !in PIN_KEYS || !K3Sig.isStr(s, 256)) return false
        return true
    }

    private fun wellFormed(v: Any?): Boolean {
        val b = K3Sig.map(v) ?: return false
        if (!IntentJs.isSafeInteger(b["v"]) || IntentJs.lng(b["v"]) != 1L) return false
        if (!K3Sig.isStr(b["id"], 128) || !K3Sig.isStr(b["key"], 128) || !K3Sig.isStr(b["operator"], 128)) return false
        if (!K3Sig.isSafeInt(b["epoch"]) || !K3Sig.isSafeInt(b["issued_at"])) return false
        if (b["status"] != "active" && b["status"] != "disabled") return false
        if (b.containsKey("max_depth") && !(K3Sig.isSafeInt(b["max_depth"]) && IntentJs.lng(b["max_depth"]) >= 1)) return false
        if (b.containsKey("expires_at") && !K3Sig.isSafeInt(b["expires_at"])) return false
        if (b.containsKey("runtime_pins")) {
            val p = K3Sig.list(b["runtime_pins"])
            if (p == null || p.isEmpty() || p.size > 16) return false
            for (x in p) if (!pinOk(x)) return false
        }
        val c = K3Sig.list(b["ceiling"]) ?: return false
        if (c.size > 32) return false
        for (x in c) if (K3Sig.map(x)?.get("type") !is String) return false
        return true
    }

    @JvmStatic
    fun verify(v: Any?): Boolean {
        if (!wellFormed(v)) return false
        val b = IntentJs.obj(v)
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) if (b.containsKey(k)) body[k] = b[k]
        return K3Sig.verifyBody(DOMAIN, body, b["operator"], b["sig"])
    }

    /** [code] is null when the record was taken. */
    class Accept(val code: String?, val replaced: Boolean)

    private const val MAX_EPOCH_KEY = "blueprint/max_epoch"
    private fun recordKey(key: String) = "blueprint/record/$key"

    /**
     * Records live in [kv] (`blueprint/record/<key>`, plus the highest accepted epoch under `blueprint/max_epoch`), so a disabled blueprint
     * stays disabled across a restart and across instances. The compare-and-store of [accept] is one atomic `update`. A store that
     * throws is `store_unreachable` ([accept] and [check]). `MemoryAtomicKv` is the explicit single-process store.
     */
    class Registry(private val operators: List<String>, private val kv: AtomicKv) {
        @Suppress("UNCHECKED_CAST")
        internal fun get(key: String): Map<String, Any?>? = kv.get(recordKey(key)) as? Map<String, Any?>

        fun accept(v: Any?): Accept {
            if (!verify(v)) return Accept("bad_record", false)
            val b = IntentJs.obj(v)
            if (b["operator"] !in operators) return Accept("unknown_operator", false)
            val key = b["key"] as String
            var out = Accept("store_unreachable", false)
            try {
                kv.update(recordKey(key)) { prev ->
                    @Suppress("UNCHECKED_CAST") val cur = prev as? Map<String, Any?>
                    if (cur != null) {
                        if (cur["operator"] != b["operator"]) { out = Accept("operator_changed", false); return@update null }
                        val ce = IntentJs.lng(cur["epoch"])
                        val be = IntentJs.lng(b["epoch"])
                        if (be < ce) { out = Accept("stale_epoch", false); return@update null }
                        if (be == ce) { out = if (cur["sig"] == b["sig"]) Accept(null, false) else Accept("epoch_fork", false); return@update null }
                    }
                    out = Accept(null, true)
                    b
                }
                if (out.replaced) {
                    val e = b["epoch"]
                    kv.update(MAX_EPOCH_KEY) { prev -> if (prev == null || IntentJs.lng(e) > IntentJs.lng(prev)) e else null }
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Accept("store_unreachable", false)
            }
            return out
        }

        /** The highest blueprint epoch this registry has accepted (0 when empty). */
        fun epoch(): Long = kv.get(MAX_EPOCH_KEY)?.let { IntentJs.lng(it) } ?: 0L
    }

    /** [decision] is allow, deny or escalate. */
    class Decision(val decision: String, val code: String? = null, val blueprint: String? = null, val governed: List<String> = emptyList(), val have: Long = 0, val need: Long = 0)

    private fun deny(code: String, bp: String? = null) = Decision("deny", code, bp)

    /** Gate a chain (hops with issuer and holder, root first). [mode] is require or any; [minEpoch] may be null. */
    @JvmStatic
    fun check(chain: Any?, reg: Registry, now: Any?, mode: String, minEpoch: Long? = null, admitted: ((String, Map<String, Any?>) -> Boolean)? = null): Decision {
        val hops = K3Sig.list(chain)
        if (hops == null || hops.isEmpty() || !K3Sig.isSafeInt(now)) return deny("bad_input")
        val hs = ArrayList<Pair<String, String>>()
        for (h in hops) {
            val m = K3Sig.map(h)
            if (m == null || !K3Sig.isStr(m["issuer"], 128) || !K3Sig.isStr(m["holder"], 128)) return deny("bad_input")
            hs.add((m["issuer"] as String) to (m["holder"] as String))
        }
        val nowMs = IntentJs.lng(now)
        try {
            return gate(hs, reg, nowMs, mode, minEpoch, admitted)
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return deny("store_unreachable")
        }
    }

    private fun gate(hs: List<Pair<String, String>>, reg: Registry, nowMs: Long, mode: String, minEpoch: Long?, admitted: ((String, Map<String, Any?>) -> Boolean)?): Decision {
        if (minEpoch != null) {
            val have = reg.epoch()
            if (have < minEpoch) return Decision("escalate", "stale_blueprint_state", have = have, need = minEpoch)
        }
        val governed = ArrayList<String>()
        for ((i, hop) in hs.withIndex()) {
            val bp = reg.get(hop.first) ?: continue
            val id = bp["id"] as String
            if (i == 0 || hs[i - 1].second != bp["key"]) return deny("broken_link", id)
            if (bp["status"] != "active") return deny("blueprint_disabled", id)
            if (bp.containsKey("expires_at") && nowMs >= IntentJs.lng(bp["expires_at"])) return deny("blueprint_expired", id)
            if (bp.containsKey("max_depth") && hs.size - i > IntentJs.lng(bp["max_depth"])) return deny("too_deep", id)
            // a pinned blueprint needs the host's admission hook: none is admission_required, anything but true is not_admitted (a throw is store_unreachable)
            if (bp.containsKey("runtime_pins")) {
                if (admitted == null) return deny("admission_required", id)
                if (!admitted(hop.second, bp)) return deny("not_admitted", id)
            }
            if (K3Sig.list(bp["ceiling"])!!.isNotEmpty()) return deny("ceiling_unevaluable", id)
            governed.add(id)
        }
        if (governed.isEmpty() && mode == "require") return deny("no_blueprint")
        return Decision("allow", governed = governed)
    }
}
