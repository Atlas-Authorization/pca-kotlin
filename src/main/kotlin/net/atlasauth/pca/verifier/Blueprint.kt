package net.atlasauth.pca.verifier

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. [Registry] keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch with
 * different content is a fork). A non-empty ceiling is never evaluated here: it denies (`ceiling_unevaluable`). Everything is total.
 */
object Blueprint {
    const val DOMAIN = "atlas-pca/agent-blueprint/v1\u0000"
    private val BODY_KEYS = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator")

    private fun wellFormed(v: Any?): Map<String, Any?>? {
        val b = K3Sig.map(v) ?: return null
        if (!IntentJs.isSafeInteger(b["v"]) || IntentJs.lng(b["v"]) != 1L) return null
        if (!K3Sig.isStr(b["id"], 128) || !K3Sig.isStr(b["key"], 128) || !K3Sig.isStr(b["operator"], 128)) return null
        if (!K3Sig.isSafeInt(b["epoch"]) || !K3Sig.isSafeInt(b["issued_at"])) return null
        if (b["status"] != "active" && b["status"] != "disabled") return null
        if (b.containsKey("max_depth") && !(K3Sig.isSafeInt(b["max_depth"]) && IntentJs.lng(b["max_depth"]) >= 1)) return null
        if (b.containsKey("expires_at") && !K3Sig.isSafeInt(b["expires_at"])) return null
        val c = K3Sig.list(b["ceiling"]) ?: return null
        if (c.size > 32 || !c.all { K3Sig.map(it)?.get("type") is String }) return null
        return b
    }

    @JvmStatic
    fun verify(v: Any?): Boolean {
        val b = wellFormed(v) ?: return false
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) if (b.containsKey(k)) body[k] = b[k]
        return K3Sig.verifyBody(DOMAIN, body, b["operator"], b["sig"])
    }

    /** [code] is null when the record was taken. */
    class Accept(val code: String?, val replaced: Boolean)

    class Registry(private val operators: List<String>) {
        internal val store = HashMap<String, Map<String, Any?>>()

        fun accept(v: Any?): Accept {
            val b = wellFormed(v)
            if (b == null || !verify(v)) return Accept("bad_record", false)
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

        fun epoch(): Long = store.values.maxOfOrNull { IntentJs.lng(it["epoch"]) } ?: 0L
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
            val bp = reg.store[hop.first] ?: continue
            val id = bp["id"] as String
            if (i == 0 || hs[i - 1].second != bp["key"]) return deny("broken_link", id)
            if (bp["status"] != "active") return deny("blueprint_disabled", id)
            if (bp.containsKey("expires_at") && nowMs >= IntentJs.lng(bp["expires_at"])) return deny("blueprint_expired", id)
            if (bp.containsKey("max_depth") && hs.size - i > IntentJs.lng(bp["max_depth"])) return deny("too_deep", id)
            if (K3Sig.list(bp["ceiling"])!!.isNotEmpty()) return deny("ceiling_unevaluable", id)
            governed.add(id)
        }
        if (governed.isEmpty() && mode == "require") return deny("no_blueprint")
        return Decision("allow", governed = governed)
    }
}
