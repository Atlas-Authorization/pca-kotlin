package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Facade

/**
 * liftLegacy: the total, conservative lift of the facade's `{permissions, limits}` input to a Goal plus IR ontology. The corrected
 * semantics of the facade's old limit bugs live here: `$200/day` is a SLIDING 86 400 000 ms sum bound (not a per-call ceiling plus a
 * one-day lifetime); a `$` limit on a verb with no amount field is an error; every limit is its own bound, so adding a limit only
 * narrows. Money parameters are integers in MINOR units of USD (cents).
 */
object GoalLegacy {
    private val PATTERN_RESOURCE = Regex("[*?]|^re:")

    private fun usd(): Map<String, Any?> = G.map("k" to "money", "ccy" to "USD")

    private fun cmp(op: String, l: Map<String, Any?>, r: Map<String, Any?>): Map<String, Any?> = G.map("k" to "cmp", "op" to op, "l" to l, "r" to r)

    private fun usdLit(n: Long): Map<String, Any?> = G.map("k" to "lit", "v" to G.map("k" to "q", "q" to G.map("u" to usd(), "n" to G.num(n))))

    /** JavaScript Math.round: nearest integer, ties toward +infinity. */
    private fun jsRound(v: Double): Double {
        val f = Math.floor(v)
        return if (v - f >= 0.5) f + 1 else f
    }

    /**
     * Lift a legacy permission map (`{connector: [action, ...]}`) and limits (`{verb or action: "$500/day"}`) to
     * {goal, ontology}. [limits], [catalog], [notAfter], [notBefore] and [nlDigest] may be null.
     */
    @JvmStatic
    fun liftLegacy(
        permissions: Map<String, Any?>,
        limits: Map<String, Any?>?,
        catalog: Catalog?,
        principal: String,
        notAfter: Long?,
        notBefore: Long?,
        nlDigest: String?,
    ): Map<String, Any?> {
        val raw: Map<String, Any?> = limits ?: LinkedHashMap()
        // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
        val specs = Facade.compilePolicy(permissions, null, catalog, null, null, 0L).actions
        val grants = ArrayList<Any?>()
        val bounds = ArrayList<Any?>()
        val verbs = ArrayList<Any?>()
        for (s in specs) {
            val gid = "g:" + s.verb
            val amountPath = if (s.amountField != null && s.amountField.isNotEmpty()) s.amountField else null
            val params = ArrayList<Any?>()
            if (amountPath != null) params.add(G.map("path" to amountPath, "ty" to G.map("k" to "q", "u" to usd())))
            verbs.add(G.map("verb" to s.verb, "cls" to s.reversibility, "params" to params))
            val resource = s.resource ?: "*"
            if (PATTERN_RESOURCE.containsMatchIn(resource) && resource != "*") {
                throw IllegalArgumentException("liftLegacy: resource pattern '$resource' of ${s.verb} is not expressible; name exact resources or acknowledge a wildcard")
            }
            // own(verb) ?? own(action): a null verb limit falls through to the action; a present null action limit is malformed (parseLimit refuses it)
            var rawLimit = raw[s.verb]
            var has = rawLimit != null
            if (!has) {
                has = raw.containsKey(s.action)
                rawLimit = raw[s.action]
            }
            var cond: Map<String, Any?> = G.map("k" to "true")
            if (has) {
                val lim = Facade.parseLimit(rawLimit)
                if (lim.unit == "usd") {
                    if (amountPath == null) {
                        throw IllegalArgumentException("liftLegacy: '$' limit on '${s.verb}' but the catalog gives that verb no amount field, so the limit could not be enforced")
                    }
                    val mm = jsRound(lim.amount * 100)
                    if (mm.isNaN() || mm.isInfinite() || Math.abs(mm) > G.MAX_SAFE) throw IllegalArgumentException("liftLegacy: limit for ${s.verb} is out of range")
                    val minor = mm.toLong()
                    val amt = G.map("k" to "param", "path" to amountPath, "ty" to G.map("k" to "q", "u" to usd()))
                    cond = G.map("k" to "and", "a" to cmp("gte", amt, usdLit(0)), "b" to cmp("lte", amt, usdLit(minor)))
                    if (lim.periodMs != null) {
                        bounds.add(
                            G.map(
                                "bid" to "b:" + s.verb, "sel" to G.map("k" to "gids", "gids" to G.list(gid)), "agg" to "sum", "value" to amt, "key" to "",
                                "window" to G.map("k" to "sliding", "ms" to G.num(lim.periodMs)), "scope" to G.map("k" to "session"),
                                "cap" to G.map("u" to usd(), "n" to G.num(minor)), "onExceed" to "deny",
                            ),
                        )
                    }
                } else {
                    if (lim.amount != Math.rint(lim.amount) || Math.abs(lim.amount) > G.MAX_SAFE) {
                        throw IllegalArgumentException("liftLegacy: count limit for ${s.verb} must be a whole number")
                    }
                    val count = G.map("k" to "count")
                    bounds.add(
                        G.map(
                            "bid" to "b:" + s.verb, "sel" to G.map("k" to "gids", "gids" to G.list(gid)), "agg" to "count",
                            "value" to G.map("k" to "lit", "v" to G.map("k" to "q", "q" to G.map("u" to count, "n" to G.num(1)))), "key" to "",
                            "window" to (if (lim.periodMs != null) G.map("k" to "sliding", "ms" to G.num(lim.periodMs)) else G.map("k" to "lifetime")),
                            "scope" to G.map("k" to "session"), "cap" to G.map("u" to count, "n" to G.num(lim.amount.toLong())), "onExceed" to "deny",
                        ),
                    )
                }
            }
            grants.add(
                G.map(
                    "gid" to gid, "verb" to s.verb,
                    "res" to (if (resource == "*") G.map("k" to "any", "reason" to "legacy default: no resource scope given") else G.map("k" to "exact", "id" to resource)),
                    "cond" to cond,
                ),
            )
        }
        grants.sortWith(Comparator { a, b -> G.cmp(G.get(a, "gid") as String, G.get(b, "gid") as String) })
        bounds.sortWith(Comparator { a, b -> G.cmp(G.get(a, "bid") as String, G.get(b, "bid") as String) })
        for (i in 1 until grants.size) {
            if (G.get(grants[i], "gid") == G.get(grants[i - 1], "gid")) throw IllegalArgumentException("liftLegacy: duplicate grant " + G.get(grants[i], "gid"))
        }
        val mayTouch = ArrayList<Any?>()
        val wildcardAck = ArrayList<Any?>()
        for (g in grants) {
            mayTouch.add(G.get(g, "gid"))
            if ("any" == G.kind(G.get(g, "res"))) wildcardAck.add(G.get(g, "gid"))
        }
        val goal = G.map(
            "v" to G.num(1), "principal" to principal, "ontDigest" to "legacy-catalog", "nlDigest" to (nlDigest ?: ""), "sources" to ArrayList<Any?>(),
            "grants" to grants, "prohibits" to ArrayList<Any?>(), "bounds" to bounds,
            "validity" to G.map("notBefore" to G.num(notBefore ?: 0L), "notAfter" to G.num(notAfter ?: G.MAX_SAFE), "maxIdle" to G.num(0)),
            "deleg" to G.map("maxDepth" to G.num(16), "narrowOnly" to true, "mayTouch" to mayTouch),
            "escalateOn" to ArrayList<Any?>(), "wildcardAck" to wildcardAck, "holes" to ArrayList<Any?>(),
        )
        verbs.sortWith(Comparator { a, b -> G.cmp(G.get(a, "verb") as String, G.get(b, "verb") as String) })
        val uniq = ArrayList<Any?>()
        for (i in verbs.indices) if (i == 0 || G.get(verbs[i - 1], "verb") != G.get(verbs[i], "verb")) uniq.add(verbs[i])
        return G.map("goal" to goal, "ontology" to G.map("verbs" to uniq, "rels" to ArrayList<Any?>()))
    }
}
