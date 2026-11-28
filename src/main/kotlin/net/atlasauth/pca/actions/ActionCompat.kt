package net.atlasauth.pca.actions

/**
 * Migration shims between the old, disagreeing action vocabularies and the one action-def vocabulary. Old names stay accepted on INPUT
 * for one release; every conversion is total and fails closed.
 */
@Suppress("UNCHECKED_CAST")
object ActionCompat {
    private val BLAST_RADII = listOf("one", "bounded", "tenant", "global")
    private val BLAST_PPM = mapOf("one" to 50_000L, "bounded" to 300_000L, "tenant" to 700_000L, "global" to 1_000_000L)
    private const val PPM_MAX = 1_000_000L
    private val READ_RE = Regex("\\A(?:read|get|list|view|search|fetch|head)(?:_|\\z)")
    private val DELETE_RE = Regex("(?:\\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\\z)")
    private val SEND_RE = Regex("(?:\\A|_)(?:send|post|publish|notify|email|sms)(?:_|\\z)")
    private val REV_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "irreversible" to 2)

    /** Any old reversibility word to the canonical class (anything unknown is irreversible: fail closed). */
    fun normalizeReversibility(x: Any?): String {
        if ("reversible" == x || "read" == x) return "reversible"
        if ("rate_limited" == x || "costly" == x) return "rate_limited"
        return "irreversible"
    }

    /** The operations-side word for the revocation staleness table (`rate_limited` becomes `costly`). */
    fun legacyOperationsClass(r: String): String = if ("rate_limited" == r) "costly" else r

    fun maxRevOf(a: String, b: String): String = if (REV_RANK[a]!! >= REV_RANK[b]!!) a else b

    /** The schema `units` entry and the envelope unit tag from a def's unit (null for a money unit whose currency is a reference). */
    fun unitTagOf(u: Map<String, Any?>): MutableMap<String, Any?>? {
        if ("money" != u["kind"]) return J.obj("kind", u["kind"])
        if (u["ccy"] !is String) return null
        val m = J.obj("kind", "money", "currency", u["ccy"])
        if (u.containsKey("exp")) m["exponent"] = u["exp"]
        return m
    }

    private fun ppmOf(x: Double): Long {
        val v = (if (x.isNaN() || x.isInfinite()) 1.0 else x) * 1_000_000
        val r = Math.floor(v)
        val rounded = (if (v - r >= 0.5) r + 1 else r).toLong()
        return Math.min(PPM_MAX, Math.max(0L, rounded))
    }

    /** The smallest radius whose default covers the float, and the integer ppm. */
    fun blastOfFloat(x: Double): MutableMap<String, Any?> {
        val ppm = ppmOf(x)
        var radius = "global"
        for (r in BLAST_RADII) if (BLAST_PPM[r]!! >= ppm) { radius = r; break }
        return J.obj("radius", radius, "ppm", J.n(ppm))
    }

    /** A legacy float kept EXACTLY: the largest radius whose default does not exceed it, with the ppm override carrying the exact value. */
    fun blastExactOfFloat(x: Double): MutableMap<String, Any?> {
        val ppm = ppmOf(x)
        var radius = "one"
        for (i in BLAST_RADII.size - 1 downTo 0) if (BLAST_PPM[BLAST_RADII[i]]!! <= ppm) { radius = BLAST_RADII[i]; break }
        return J.obj("radius", radius, "ppm", J.n(ppm))
    }

    /**
     * Convert an old catalog entry (`connector, action, verb, reversibility, blastRadius, amountField?, resource?, description`).
     * Effects are inferred conservatively from the action name (an unknown write is `update`, never `read`); `o`:
     * `{ccy?, exp?, maxAmount?}`. The result is `authored`.
     */
    fun fromCatalogSpec(s: Map<String, Any?>, o: Map<String, Any?>?): MutableMap<String, Any?> {
        val effects = ArrayList<Any?>()
        val amountField = s["amountField"]
        val action = s["action"] as String
        if (amountField != null) effects.add("pay")
        if (READ_RE.containsMatchIn(action)) effects.add("read")
        if (DELETE_RE.containsMatchIn(action)) effects.add("delete")
        if (SEND_RE.containsMatchIn(action)) effects.add("send")
        if (effects.isEmpty()) effects.add("update")
        val params = LinkedHashMap<String, Any?>()
        if (amountField != null) {
            val max = if (o != null && o["maxAmount"] != null) o["maxAmount"] else J.n(100_000_000_000L)
            val ccy = if (o != null && o["ccy"] != null) o["ccy"] else "USD"
            val exp = if (o != null && o["exp"] != null) o["exp"] else J.n(2)
            params[amountField as String] = J.obj("type", "integer", "role", "money.amount", "min", J.n(0), "max", max, "unit", J.obj("kind", "money", "ccy", ccy, "exp", exp))
            params["idempotency_key"] = J.obj("type", "string", "max_len", J.n(128))
        }
        val b = blastOfFloat(J.num(s["blastRadius"])!!)
        val resource = s["resource"]
        val wildcard = resource == null || "*" == resource
        val desc = s["description"] as String
        val d = J.obj(
            "v", J.n(1), "kind", "pca-action-def", "verb", s["verb"], "title", if (desc.length > 120) desc.substring(0, 117) + "..." else desc, "description", desc,
            "effects", effects,
            "resource", J.obj("type", s["connector"], "id", if (wildcard) "*" else J.obj("prefix", "", "class", "any_safe", "len", J.list(J.n(1), J.n(128))), "scope", if (wildcard) "set" else "one"),
            "params", params, "reversibility", normalizeReversibility(s["reversibility"]), "blast", J.obj("radius", b["radius"], "ppm", b["ppm"]),
        )
        if (amountField != null) d["idempotency"] = J.obj("mode", "key_param", "param", "idempotency_key")
        d["review"] = J.obj("state", "authored")
        return d
    }

    fun fromCatalog(specs: List<*>, o: Map<String, Any?>?): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (s in specs) out.add(fromCatalogSpec(J.m(s), o))
        return out
    }
}
