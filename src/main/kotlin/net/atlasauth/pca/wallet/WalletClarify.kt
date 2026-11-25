package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js

/**
 * Agent-initiated clarification. The agent may ask BEFORE acting with `{candidates: [at most 8 structured actions], reason}`:
 * there is no free-text field and unknown members are refused. The wallet maps each candidate to its own cell: certain cells are
 * answered at once as a dry run (admitted / denied / outside), and among the uncertain ones it picks the cell of maximal expected
 * information gain under the current asymmetric noise (ties broken by risk weight, then cell index, then candidate position).
 */
object WalletClarify {
    const val MAX_CANDIDATES = 8
    private const val MAX_VALUES = 64
    private const val MAX_STRING = 256
    private val PATH_RE = Regex("[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*", RegexOption.IGNORE_CASE)

    private fun bad(error: String): Map<String, Any?> = Wallet.obj("ok", false, "error", error)

    /** Strict parse of a clarification body: {ok:true, request:{candidates, reason}} or {ok:false, error}. Never throws. */
    fun parseClarifyRequest(body: Any?): Map<String, Any?> {
        if (!Wallet.isObj(body)) return bad("body must be an object")
        val b = body as Map<*, *>
        for (k in b.keys) if ("candidates" != k && "reason" != k) return bad("unknown member \"$k\" (clarifications carry no text)")
        val reason = b["reason"]
        if (reason !is String || !WalletCard.CLARIFY_REASONS.contains(reason)) return bad("reason must be one of " + WalletCard.CLARIFY_REASONS.joinToString(", "))
        val cands = b["candidates"]
        if (cands !is List<*> || cands.isEmpty() || cands.size > MAX_CANDIDATES) return bad("candidates must be 1..8 structured actions")
        val out = ArrayList<Any?>()
        var i = 0
        for (cO in cands) {
            if (!Wallet.isObj(cO)) return bad("candidates[$i] must be an object")
            val c = cO as Map<*, *>
            for (k in c.keys) if ("verb" != k && "values" != k) return bad("candidates[$i] has an unknown member \"$k\"")
            val verb = c["verb"]
            if (verb !is String || verb.isEmpty() || verb.length > 128) return bad("candidates[$i].verb must be a non-empty string")
            if (!Wallet.isObj(c["values"])) return bad("candidates[$i].values must be an object")
            val vals = c["values"] as Map<*, *>
            if (vals.size > MAX_VALUES) return bad("candidates[$i] has too many values")
            val values = LinkedHashMap<String, Any?>()
            for ((pO, v) in vals) {
                val p = pO as String
                if (!PATH_RE.matches(p)) return bad("candidates[$i] has a malformed path")
                if (!(p == "action.resource" || p.startsWith("action.params."))) return bad("candidates[$i].values may only name action.params.* or action.resource")
                if (Js.isNumber(v)) {
                    if (!Wallet.isSafeInteger(v) || Js.isNegZero(v)) return bad("candidates[$i].values.$p must be a safe integer")
                } else if (v !is String || v.length > MAX_STRING) return bad("candidates[$i].values.$p must be a string (≤ $MAX_STRING) or an integer")
                values[p] = v
            }
            out.add(Wallet.obj("verb", verb, "values", values))
            i++
        }
        return Wallet.obj("ok", true, "request", Wallet.obj("candidates", out, "reason", reason))
    }

    /** Expected information gain (bits) of asking a cell with acceptance p under asymmetric noise. */
    fun informationGain(p: Double, etaPos: Double, etaNeg: Double): Double {
        val py = p * (1 - etaNeg) + (1 - p) * etaPos
        return WalletStats.binEnt(py) - (p * WalletStats.binEnt(etaNeg) + (1 - p) * WalletStats.binEnt(etaPos))
    }

    /** The plan for a clarification: a dry-run verdict per candidate and the one cell to ask (or null). */
    class Plan {
        @JvmField val verdicts: MutableList<Map<String, Any?>> = ArrayList()
        /** {index, verb, idx[], p, ig} or null. */
        @JvmField var ask: Map<String, Any?>? = null
        @JvmField var askIdx: IntArray? = null

        fun toMap(): Map<String, Any?> = Wallet.obj("verdicts", ArrayList<Any?>(verdicts), "ask", ask)
    }

    private class Best(val index: Int, val verb: String, val idx: IntArray, val p: Double, val ig: Double, val weight: Double, val flat: Double)

    private fun verdict(index: Int, v: String): Map<String, Any?> = Wallet.obj("index", index.toLong(), "verdict", v)

    /**
     * Plan a clarification over the parsed candidates (maps {verb, values}). [lift] (nullable) lifts a candidate into the
     * lifted outcome space; [asked] holds the cells already asked ("verb|i,j,..." keys).
     */
    fun planClarification(
        omega: Map<String, Any?>, view: WalletView, candidates: List<Map<String, Any?>>, lift: ((Map<String, Any?>) -> Map<String, Any?>)?,
        asked: Set<String>, etaPos: Double, etaNeg: Double, harm: WalletOmega.HarmModel,
    ): Plan {
        val plan = Plan()
        var best: Best? = null
        val seen = HashSet<String>()
        for (index in candidates.indices) {
            val cand = candidates[index]
            val at = WalletBox.cellOfAction(omega, if (lift != null) lift(cand) else cand)
            if (at == null) { plan.verdicts.add(verdict(index, "outside")); continue }
            val verb = at.vs["verb"] as String
            val idx = at.idx
            if (view.outsideCeiling(verb, idx) || view.vetoed(verb, idx)) { plan.verdicts.add(verdict(index, "denied")); continue }
            val p = view.p(verb, idx)
            if (p <= 0) { plan.verdicts.add(verdict(index, "denied")); continue }
            if (p >= 1) { plan.verdicts.add(verdict(index, "admitted")); continue }
            val key = WalletNoise.cellKey(verb, idx)
            if (asked.contains(key)) { plan.verdicts.add(verdict(index, "asked")); continue }
            plan.verdicts.add(verdict(index, "uncertain"))
            if (seen.contains(key)) continue
            seen.add(key)
            val ig = informationGain(p, etaPos, etaNeg)
            val s = WalletOmega.cellStats(at.vs, idx, harm)
            val c2 = Best(index, verb, idx, p, ig, s[0] * s[1], WalletBox.flatIndex(at.vs, idx))
            val b = best
            if (b == null || c2.ig > b.ig + 1e-12 ||
                (Math.abs(c2.ig - b.ig) <= 1e-12 && (c2.weight > b.weight || (c2.weight == b.weight && c2.flat < b.flat)))) best = c2
        }
        val b = best
        if (b != null) {
            plan.ask = Wallet.obj("index", b.index.toLong(), "verb", b.verb, "idx", WalletNoise.idxList(b.idx), "p", b.p, "ig", b.ig)
            plan.askIdx = b.idx
        }
        return plan
    }
}
