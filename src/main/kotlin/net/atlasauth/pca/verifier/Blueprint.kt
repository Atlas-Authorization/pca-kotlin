package net.atlasauth.pca.verifier

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. A record with `runtime_pins` is accepted and denies at the check (`admission_required`). [Registry] keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch with
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

    class Registry(private val operators: List<String>) {
        internal val store = HashMap<String, Map<String, Any?>>()

        @Synchronized
        internal fun get(key: String): Map<String, Any?>? = store[key]

        @Synchronized
        fun accept(v: Any?): Accept {
            if (!verify(v)) return Accept("bad_record", false)
            val b = IntentJs.obj(v)
            if (b["operator"] !in operators) return Accept("unknown_operator", false)
            val key = b["key"] as String
            val cur = store[key]
            if (cur != null) {
                if (cur["operator"] != b["operator"]) return Accept("operator_changed", false)
                val ce = IntentJs.lng(cur["epoch"])
                val be = IntentJs.lng(b["epoch"])
                if (be < ce) return Accept("stale_epoch", false)
                if (be == ce) return if (cur["sig"] == b["sig"]) Accept(null, false) else Accept("epoch_fork", false)
            }
            store[key] = b
            return Accept(null, true)
        }

        @Synchronized
        fun epoch(): Long {
            var e = 0L
            for (b in store.values) e = Math.max(e, IntentJs.lng(b["epoch"]))
            return e
        }
    }

    /** [decision] is allow, deny or escalate. */
    class Decision(val decision: String, val code: String? = null, val blueprint: String? = null, val governed: List<String> = emptyList(), val have: Long = 0, val need: Long = 0)

    private fun deny(code: String, bp: String? = null) = Decision("deny", code, bp)

    /** Gate a chain (hops with issuer and holder, root first). [mode] is require or any; [minEpoch] may be null. */
    @JvmStatic
    fun check(chain: Any?, reg: Registry, now: Any?, mode: String, minEpoch: Long? = null): Decision {
        val hops = K3Sig.list(chain)
        if (hops == null || hops.isEmpty() || !K3Sig.isSafeInt(now)) return deny("bad_input")
        val hs = ArrayList<Pair<String, String>>()
        for (h in hops) {
            val m = K3Sig.map(h)
            if (m == null || !K3Sig.isStr(m["issuer"], 128) || !K3Sig.isStr(m["holder"], 128)) return deny("bad_input")
            hs.add((m["issuer"] as String) to (m["holder"] as String))
        }
        val nowMs = IntentJs.lng(now)
        if (minEpoch != null && reg.epoch() < minEpoch) return Decision("escalate", "stale_blueprint_state", have = reg.epoch(), need = minEpoch)
        val governed = ArrayList<String>()
        for ((i, hop) in hs.withIndex()) {
            val bp = reg.get(hop.first) ?: continue
            val id = bp["id"] as String
            if (i == 0 || hs[i - 1].second != bp["key"]) return deny("broken_link", id)
            if (bp["status"] != "active") return deny("blueprint_disabled", id)
            if (bp.containsKey("expires_at") && nowMs >= IntentJs.lng(bp["expires_at"])) return deny("blueprint_expired", id)
            if (bp.containsKey("max_depth") && hs.size - i > IntentJs.lng(bp["max_depth"])) return deny("too_deep", id)
            // runtime admission is not implemented here: a pinned blueprint must deny, never fall through (blueprint.ts:202-205)
            if (bp.containsKey("runtime_pins")) return deny("admission_required", id)
            if (K3Sig.list(bp["ceiling"])!!.isNotEmpty()) return deny("ceiling_unevaluable", id)
            governed.add(id)
        }
        if (governed.isEmpty() && mode == "require") return deny("no_blueprint")
        return Decision("allow", governed = governed)
    }
}
