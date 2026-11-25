package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Principal review and signing for a Goal IR. The PolicyCard is a deterministic, template-only (no model) rendering of the WHOLE goal:
 * every grant, prohibition, bound, validity window, delegation limit, escalation trigger, hole, wildcard and confirmed boundary example,
 * with exact numbers. Lossless-or-refuse: a card is never truncated; reviewer-fatigue limits REFUSE a goal or diff that is too large to
 * read. The semantic diff counts anything not PROVEN narrower as a widening. A GoalApproval is a pinned reviewer's signature over
 * {goal, policy, card, ontology, tests, instruction, model-set digests}; [loadApprovedGoal] trusts nothing the submission claims
 * about itself: it recomputes every digest, recompiles, re-renders, re-runs the confirmed examples, then checks the signature.
 *
 * The compiler is injected ([ReviewKernel]): the proved extracted compiler is not carried natively. A submission is
 * {goal, ontology, instruction, model_set, tests?}.
 */
@Suppress("UNCHECKED_CAST")
object GoalReview {
    /** The compiler and decision entry points the review flow needs. */
    interface ReviewKernel {
        /** Goal, IR ontology -> {ok: true, policy} | {ok: false, reasons}. Pure and total. */
        fun compile(goal: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?>

        /** Content digest of the compiled policy. */
        fun policyDigest(policy: Map<String, Any?>): String

        /** Error-level analyzer findings over the compiled policy; any finding refuses. The default has no analyzer. */
        fun analyze(policy: Map<String, Any?>): List<String> = ArrayList()

        /** Whether [decide] is available (needed to re-run the confirmed examples). */
        fun canDecide(): Boolean = false

        /** The decision ("allow" | "deny" | "escalate") for an action. */
        fun decide(goal: Map<String, Any?>, ont: Map<String, Any?>, act: Map<String, Any?>, hist: Map<String, Any?>): String = throw UnsupportedOperationException("no decide")

        /** Whether [newlyAllowed] is available. */
        fun canListNewlyAllowed(): Boolean = false

        /** Actions allowed by `next` and not by `prev`: {witnesses, complete}. */
        fun newlyAllowed(prev: Map<String, Any?>, next: Map<String, Any?>, ont: Map<String, Any?>, limit: Long): Map<String, Any?> = throw UnsupportedOperationException("no newlyAllowed")
    }

    // ---- limits (reviewer fatigue) ----

    private fun reviewLimits(): MutableMap<String, Long> {
        val m = LinkedHashMap<String, Long>()
        m["max_grants"] = 32L
        m["max_prohibits"] = 64L
        m["max_bounds"] = 32L
        m["max_escalate_on"] = 32L
        m["max_examples"] = 40L
        m["max_card_lines"] = 200L
        m["max_card_bytes"] = 24576L
        m["max_diff_changes"] = 60L
        m["max_diff_widenings"] = 12L
        m["max_witnesses"] = 20L
        return m
    }

    /** The hard caps on what a human is asked to read, as a fresh map. */
    @JvmStatic
    fun REVIEW_LIMITS(): Map<String, Long> = reviewLimits()

    /** Caller overrides may only TIGHTEN a limit (a larger number is ignored). [o] may be null. */
    @JvmStatic
    fun effectiveLimits(o: Map<String, Any?>?): Map<String, Long> {
        val out = reviewLimits()
        if (o != null) for (k in ArrayList(out.keys)) {
            val v = o[k]
            val x = if (v == null) null else G.safeInt(v)
            if (x != null && x >= 0 && x < out[k]!!) out[k] = x
        }
        return out
    }

    /** A review refusal with a stable code: card_too_large, unrenderable, holes, wildcard_unacknowledged, diff_too_large, too_many_widenings. */
    class ReviewError(val code: String, detail: String) : RuntimeException("goal review: $code: $detail")

    private const val D_CARD = "atlas-pca/policy-card/v1"
    private const val D_CLAUSE = "atlas-pca/goal-clause/v1"
    const val GOAL_APPROVAL_KIND = "goal-approval"

    /** An approval may not be valid for longer than this. */
    const val MAX_GOAL_APPROVAL_TTL_MS = 24L * 3_600_000L
    private const val DEFAULT_TTL_MS = 3_600_000L

    /** The fields covered by the signature. */
    @JvmField
    val GOAL_APPROVAL_SIGNED_FIELDS: List<String> = listOf("v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest", "model_set_digest", "reviewer", "approved_at", "expires_at")

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    private fun list(o: Any?): List<Any?> = G.arr(o, "")

    private fun isObj(o: Any?): Boolean = o is Map<*, *>

    private fun jsonOf(v: Any?): String =
        try {
            Json.canonicalizeStrict(v)
        } catch (e: RuntimeException) {
            throw ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)")
        }

    private fun line(id: String, kind: String, text: String, clause: Any?, severity: String): Map<String, Any?> =
        G.map("id" to id, "kind" to kind, "severity" to severity, "text" to text, "clause_digest" to Pca.hashCanonical(G.map("d" to D_CLAUSE, "kind" to kind, "clause" to clause)))

    /** Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped. */
    private fun safeText(f: () -> String, clause: Any?): String =
        try {
            val t = f()
            if (t.contains("undefined")) throw IllegalStateException("unknown clause shape")
            t
        } catch (e: RuntimeException) {
            if (e is ReviewError) throw e
            jsonOf(clause)
        }

    private fun big(what: String, n: Long, max: Long) {
        if (n > max) throw ReviewError("card_too_large", "$n $what exceed the cap of $max: split the goal into smaller goals")
    }

    private fun goalDigestOf(goal: Map<String, Any?>): String =
        try {
            GoalDigests.goalDigest(goal)
        } catch (e: RuntimeException) {
            throw ReviewError("unrenderable", "the Goal has no canonical form (float, undefined or cycle)")
        }

    private fun sev(red: Boolean): String = if (red) "red" else "info"

    /**
     * Render the card: {v, goal_digest, ontology_digest, nl_digest, principal, lines}. Deterministic, no model, no locale. Throws
     * ReviewError `holes` (unless [allowHoles]), `wildcard_unacknowledged`, `card_too_large`, `unrenderable`.
     * [tests] and [limits] may be null.
     */
    @JvmStatic
    fun renderPolicyCard(goal: Map<String, Any?>?, tests: List<Any?>?, limits: Map<String, Any?>?, allowHoles: Boolean): Map<String, Any?> {
        val lim = effectiveLimits(limits)
        val ts: List<Any?> = tests ?: ArrayList()
        if (goal == null || goal["grants"] !is List<*> || goal["prohibits"] !is List<*> || goal["bounds"] !is List<*> || goal["escalateOn"] !is List<*> ||
            goal["holes"] !is List<*> || !isObj(goal["validity"]) || !isObj(goal["deleg"])
        ) throw ReviewError("unrenderable", "not a Goal IR")
        val grants = list(goal["grants"])
        val prohibits = list(goal["prohibits"])
        val bounds = list(goal["bounds"])
        val escalateOn = list(goal["escalateOn"])
        val holes = list(goal["holes"])
        big("grants", grants.size.toLong(), lim["max_grants"]!!)
        big("prohibitions", prohibits.size.toLong(), lim["max_prohibits"]!!)
        big("bounds", bounds.size.toLong(), lim["max_bounds"]!!)
        big("escalation triggers", escalateOn.size.toLong(), lim["max_escalate_on"]!!)
        big("boundary examples", ts.size.toLong(), lim["max_examples"]!!)
        big("card lines", 3L + grants.size + prohibits.size + bounds.size + escalateOn.size + holes.size + ts.size, lim["max_card_lines"]!!)
        if (holes.isNotEmpty() && !allowHoles) throw ReviewError("holes", "${holes.size} unresolved question(s): a goal with holes is a draft and cannot be signed")
        val ack = LinkedHashSet<Any?>()
        if (goal["wildcardAck"] is List<*>) ack.addAll(list(goal["wildcardAck"]))
        val lines = ArrayList<Any?>()
        lines.add(line("principal", "meta", "Acting for principal " + jsonOf(goal["principal"]) + ". Nothing outside this card is allowed (default deny).", goal["principal"], "info"))
        for (go in grants) {
            val g = mm(go)!!
            val wild = "any" == G.kind(G.get(g, "res"))
            if (wild && !ack.contains(g["gid"])) throw ReviewError("wildcard_unacknowledged", "grant " + jsonOf(g["gid"]) + " allows ANY resource without a wildcard acknowledgement")
            lines.add(line(G.jsStr(g["gid"]), "grant", safeText({ GoalCard.grantLine(g) + "." + (if (wild) " WILDCARD acknowledged by the principal." else "") }, g), g, sev(wild)))
        }
        for (po in prohibits) {
            val p = mm(po)!!
            lines.add(line(G.jsStr(p["pid"]), "prohibit", safeText({ GoalCard.prohibitLine(p) + "." }, p), p, sev("any" == G.kind(G.get(p, "res")))))
        }
        for (bo in bounds) {
            val b = mm(bo)!!
            lines.add(line(G.jsStr(b["bid"]), "bound", safeText({ GoalCard.boundLine(b) + "." }, b), b, "info"))
        }
        val validity = mm(goal["validity"])!!
        val deleg = mm(goal["deleg"])!!
        lines.add(line("validity", "validity", safeText({ GoalCard.validityLine(validity) + "." }, validity), validity, "info"))
        lines.add(line("delegation", "delegation", safeText({ GoalCard.delegationLine(deleg) + "." }, deleg), deleg, sev(!G.truthy(deleg["narrowOnly"]))))
        for (i in escalateOn.indices) {
            val c = mm(escalateOn[i])!!
            lines.add(line("escalate_on[$i]", "escalate", safeText({ GoalCard.escalateLine(c) + "." }, c), c, "info"))
        }
        for (i in holes.indices) {
            val h = mm(holes[i])!!
            lines.add(line("hole[$i]", "hole", safeText({ GoalCard.holeLine(h) + ". Everything depending on it is dropped." }, h), h, "red"))
        }
        for (to in ts) {
            val t = mm(to)!!
            val act = mm(t["act"])!!
            val adms = list(mm(t["hist"])!!["adms"]).size
            val ans = if ("ask" == t["answer"]) "ASKED about" else if ("allow" == t["answer"]) "ALLOWED" else "DENIED"
            lines.add(
                line(
                    "example:" + G.jsStr(t["id"]), "example",
                    "EXAMPLE you confirmed: " + jsonOf(act["verb"]) + " on " + jsonOf(act["res"]) + " with " + jsonOf(act["params"]) +
                        (if (adms > 0) " after $adms earlier admitted action(s)" else "") + " must be " + ans + ".",
                    t, "info",
                ),
            )
        }
        big("card lines", lines.size.toLong(), lim["max_card_lines"]!!)
        val card = G.map("v" to G.num(1), "goal_digest" to goalDigestOf(goal), "ontology_digest" to goal["ontDigest"], "nl_digest" to goal["nlDigest"], "principal" to goal["principal"], "lines" to lines)
        big("bytes of card", Json.canonicalizeStrict(card).toByteArray(Charsets.UTF_8).size.toLong(), lim["max_card_bytes"]!!)
        return card
    }

    @JvmStatic
    fun cardDigest(card: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to D_CARD, "card" to card))

    /** Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`. */
    @JvmStatic
    fun cardToText(card: Map<String, Any?>): String {
        val out = ArrayList<String>()
        for (lo in list(card["lines"])) out.add((if ("red" == G.get(lo, "severity")) "!! " else "   ") + G.jsStr(G.get(lo, "text")))
        return out.joinToString("\n")
    }

    // ---- semantic diff ----

    private fun same(a: Any?, b: Any?): Boolean = jsonOf(a) == jsonOf(b)

    private fun conjuncts(c: Map<String, Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        val k = G.kind(c)
        if (k == "and") {
            out.addAll(conjuncts(mm(c!!["a"])))
            out.addAll(conjuncts(mm(c["b"])))
        } else if (k != "true") out.add(c)
        return out
    }

    /** new.cond is old.cond AND more (or equal): provably no wider. */
    private fun whereNoWider(oldW: Map<String, Any?>?, newW: Map<String, Any?>?): Boolean {
        val have = LinkedHashSet<String>()
        for (c in conjuncts(newW)) have.add(jsonOf(c))
        for (c in conjuncts(oldW)) if (!have.contains(jsonOf(c))) return false
        return true
    }

    private fun grantDir(o: Map<String, Any?>?, n: Map<String, Any?>?): String {
        if (same(o, n)) return "neutral"
        return if (o!!["verb"] == n!!["verb"] && same(o["res"], n["res"]) && whereNoWider(mm(o["cond"]), mm(n["cond"]))) "narrow" else "unknown"
    }

    private fun prohibitDir(o: Map<String, Any?>?, n: Map<String, Any?>?): String {
        if (same(o, n)) return "neutral"
        return if (same(o!!["target"], n!!["target"]) && same(o["res"], n["res"]) && whereNoWider(mm(n["cond"]), mm(o["cond"]))) "narrow" else "unknown"
    }

    private fun boundDir(o: Map<String, Any?>?, n: Map<String, Any?>?): String {
        if (same(o, n)) return "neutral"
        val ro = LinkedHashMap(o!!)
        val rn = LinkedHashMap(n!!)
        ro["cap"] = null
        rn["cap"] = null
        if (!same(ro, rn) || !same(G.get(o["cap"], "u"), G.get(n["cap"], "u"))) return "unknown"
        val a = G.toNum(G.get(n["cap"], "n"))
        val b = G.toNum(G.get(o["cap"], "n"))
        return if (a < b) "narrow" else if (a > b) "widen" else "neutral"
    }

    private fun idle(x: Any?): Double {
        val d = G.toNum(x)
        return if (d == 0.0) Double.POSITIVE_INFINITY else d
    }

    private fun validityDir(o: Map<String, Any?>?, n: Map<String, Any?>?): String {
        if (same(o, n)) return "neutral"
        val nb = G.toNum(n!!["notBefore"])
        val ob = G.toNum(o!!["notBefore"])
        val na = G.toNum(n["notAfter"])
        val oa = G.toNum(o["notAfter"])
        val nar = nb >= ob && na <= oa && idle(n["maxIdle"]) <= idle(o["maxIdle"])
        val wid = nb <= ob && na >= oa && idle(n["maxIdle"]) >= idle(o["maxIdle"])
        return if (nar) "narrow" else if (wid) "widen" else "unknown"
    }

    private fun delegationDir(o: Map<String, Any?>?, n: Map<String, Any?>?): String {
        if (same(o, n)) return "neutral"
        val touchO = list(o!!["mayTouch"])
        val touchN = list(n!!["mayTouch"])
        val sub = touchO.containsAll(touchN)
        val sup = touchN.containsAll(touchO)
        val nd = G.toNum(n["maxDepth"])
        val od = G.toNum(o["maxDepth"])
        val nar = nd <= od && sub && (G.truthy(n["narrowOnly"]) || !G.truthy(o["narrowOnly"]))
        val wid = nd >= od && sup && (G.truthy(o["narrowOnly"]) || !G.truthy(n["narrowOnly"]))
        return if (nar) "narrow" else if (wid) "widen" else "unknown"
    }

    private fun keyed(xs: List<Any?>, field: String): List<Pair<String, Any?>> {
        val r = ArrayList<Pair<String, Any?>>()
        for (x in xs) r.add(Pair(G.jsStr(G.get(x, field)), x))
        return r
    }

    private fun pairs(
        out: MutableList<Any?>, prev: List<Pair<String, Any?>>, next: List<Pair<String, Any?>>, kind: String, added: String, removed: String,
        changed: (Map<String, Any?>?, Map<String, Any?>?) -> String, text: (String, Map<String, Any?>) -> String,
    ) {
        val pm = LinkedHashMap<String, Any?>()
        val nm = LinkedHashMap<String, Any?>()
        for (e in prev) pm[e.first] = e.second
        for (e in next) nm[e.first] = e.second
        for (e in next) {
            val id = e.first
            val v = mm(e.second)!!
            val o = pm[id]
            if (!pm.containsKey(id)) out.add(G.map("change" to "added", "kind" to kind, "id" to id, "direction" to added, "text" to ("ADDED " + text(id, v))))
            else if (!same(o, v)) out.add(G.map("change" to "changed", "kind" to kind, "id" to id, "direction" to changed(mm(o), v), "text" to ("CHANGED " + text(id, v) + " (was: " + text(id, mm(o)!!) + ")")))
        }
        for (e in prev) if (!nm.containsKey(e.first)) out.add(G.map("change" to "removed", "kind" to kind, "id" to e.first, "direction" to removed, "text" to ("REMOVED " + text(e.first, mm(e.second)!!))))
    }

    private fun isWide(c: Any?): Boolean {
        val d = G.get(c, "direction")
        return "widen" == d || "unknown" == d
    }

    /**
     * Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Throws ReviewError
     * `diff_too_large` / `too_many_widenings` past the fatigue caps. [kernel] (newlyAllowed), [limits] and [ontology] may be null.
     */
    @JvmStatic
    fun diffGoals(prev: Map<String, Any?>, next: Map<String, Any?>, kernel: ReviewKernel?, limits: Map<String, Any?>?, ontology: Map<String, Any?>?): Map<String, Any?> {
        val lim = effectiveLimits(limits)
        val gl: (String, Map<String, Any?>) -> String = { id, g -> "grant " + jsonOf(id) + ": " + jsonOf(g["verb"]) + " on " + GoalCard.res(mm(g["res"])!!) + " when " + GoalCard.cond(mm(g["cond"])!!) }
        val pl: (String, Map<String, Any?>) -> String = { id, p ->
            val t = mm(p["target"])
            "prohibition " + jsonOf(id) + ": " + (if ("verb" == G.kind(t)) jsonOf(t!!["verb"]) else "effect class " + jsonOf(t!!["cls"])) + " on " + GoalCard.res(mm(p["res"])!!) + " when " + GoalCard.cond(mm(p["cond"])!!)
        }
        val bl: (String, Map<String, Any?>) -> String = { id, b -> "bound " + jsonOf(id) + ": " + GoalCard.boundLine(b) + " (" + GoalCard.quantity(mm(b["cap"])!!) + ")" }
        val changes = ArrayList<Any?>()
        pairs(changes, keyed(list(prev["grants"]), "gid"), keyed(list(next["grants"]), "gid"), "grant", "widen", "narrow", { o, n -> grantDir(o, n) }, gl)
        pairs(changes, keyed(list(prev["prohibits"]), "pid"), keyed(list(next["prohibits"]), "pid"), "prohibit", "narrow", "widen", { o, n -> prohibitDir(o, n) }, pl)
        pairs(changes, keyed(list(prev["bounds"]), "bid"), keyed(list(next["bounds"]), "bid"), "bound", "narrow", "widen", { o, n -> boundDir(o, n) }, bl)
        val ep = ArrayList<Pair<String, Any?>>()
        val en = ArrayList<Pair<String, Any?>>()
        for (c in list(prev["escalateOn"])) ep.add(Pair(jsonOf(c), c))
        for (c in list(next["escalateOn"])) en.add(Pair(jsonOf(c), c))
        pairs(changes, ep, en, "escalate", "narrow", "widen", { _, _ -> "unknown" }, { _, c -> "escalation when " + GoalCard.cond(c) })
        if (!same(prev["validity"], next["validity"])) changes.add(
            G.map(
                "change" to "changed", "kind" to "validity", "id" to "validity", "direction" to validityDir(mm(prev["validity"]), mm(next["validity"])),
                "text" to ("CHANGED validity: " + jsonOf(next["validity"]) + " (was: " + jsonOf(prev["validity"]) + ")"),
            ),
        )
        if (!same(prev["deleg"], next["deleg"])) changes.add(
            G.map(
                "change" to "changed", "kind" to "delegation", "id" to "delegation", "direction" to delegationDir(mm(prev["deleg"]), mm(next["deleg"])),
                "text" to ("CHANGED delegation: " + jsonOf(next["deleg"]) + " (was: " + jsonOf(prev["deleg"]) + ")"),
            ),
        )
        // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
        if (prev["principal"] != next["principal"]) changes.add(
            G.map(
                "change" to "changed", "kind" to "meta", "id" to "principal", "direction" to "unknown",
                "text" to ("CHANGED principal: " + jsonOf(next["principal"]) + " (was: " + jsonOf(prev["principal"]) + ")"),
            ),
        )
        if (prev["ontDigest"] != next["ontDigest"]) changes.add(
            G.map(
                "change" to "changed", "kind" to "meta", "id" to "ontology", "direction" to "unknown",
                "text" to ("CHANGED ontology: every term now means what the new vocabulary says (was " + jsonOf(prev["ontDigest"]) + ", now " + jsonOf(next["ontDigest"]) + ")"),
            ),
        )
        if (!same(prev["wildcardAck"], next["wildcardAck"])) changes.add(
            G.map(
                "change" to "changed", "kind" to "meta", "id" to "wildcard_ack", "direction" to "unknown",
                "text" to ("CHANGED wildcard acknowledgements: " + jsonOf(next["wildcardAck"]) + " (was: " + jsonOf(prev["wildcardAck"]) + ")"),
            ),
        )
        if (prev["nlDigest"] != next["nlDigest"]) changes.add(
            G.map("change" to "changed", "kind" to "meta", "id" to "instruction", "direction" to "neutral", "text" to "CHANGED the instruction text the goal was interpreted from"),
        )
        var widenings = 0
        for (c in changes) if (isWide(c)) widenings++
        val maxChanges = lim["max_diff_changes"]!!
        val maxWid = lim["max_diff_widenings"]!!
        val maxWit = lim["max_witnesses"]!!
        if (changes.size > maxChanges) throw ReviewError("diff_too_large", "${changes.size} changes exceed the cap of $maxChanges: review the new goal as a whole instead")
        if (widenings > maxWid) throw ReviewError("too_many_widenings", "$widenings widenings exceed the cap of $maxWid per review")
        val na = if (ontology != null && kernel != null && kernel.canListNewlyAllowed()) kernel.newlyAllowed(prev, next, ontology, maxWit) else null
        val witnesses = ArrayList<Any?>()
        var complete = false
        if (na != null) {
            val w = list(na["witnesses"])
            var i = 0
            while (i < w.size && i < maxWit) {
                witnesses.add(w[i])
                i++
            }
            complete = na["complete"] == true && w.size <= maxWit
        }
        val ordered = ArrayList<Any?>()
        for (c in changes) if (isWide(c)) ordered.add(c)
        for (c in changes) if (!isWide(c)) ordered.add(c)
        return G.map(
            "v" to G.num(1), "from_goal_digest" to goalDigestOf(prev), "to_goal_digest" to goalDigestOf(next), "newly_allowed" to witnesses,
            "newly_allowed_complete" to complete, "changes" to ordered, "widenings" to G.num(widenings),
        )
    }

    @JvmStatic
    fun diffToText(d: Map<String, Any?>): String {
        val out = ArrayList<String>()
        for (w in list(d["newly_allowed"])) out.add("!! NEWLY ALLOWED: " + jsonOf(G.get(w, "verb")) + " on " + jsonOf(G.get(w, "res")) + " with " + jsonOf(G.get(w, "params")))
        if (d["newly_allowed_complete"] != true) out.add("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.")
        for (c in list(d["changes"])) out.add((if (isWide(c)) "!! " else "   ") + G.jsStr(G.get(c, "text")))
        return out.joinToString("\n")
    }

    // ---- GoalApproval ----

    /** Options of [approveGoal]; every field may be null. */
    class ApproveOptions {
        @JvmField var kernel: ReviewKernel? = null
        @JvmField var now: Long? = null
        @JvmField var ttlMs: Long? = null
        @JvmField var limits: Map<String, Any?>? = null

        /** The previously approved goal: when given, the diff must be reviewable (fatigue caps) or signing is refused. */
        @JvmField var base: Map<String, Any?>? = null
    }

    /** Options of [loadApprovedGoal]. `reviewers`: pinned b64u keys or {pk, ...} maps. */
    class LoadOptions {
        @JvmField var kernel: ReviewKernel? = null
        @JvmField var reviewers: List<*>? = null
        @JvmField var ontologyDigest: String? = null
        @JvmField var now: Long? = null
        @JvmField var limits: Map<String, Any?>? = null
    }

    private fun bad(reason: String): Map<String, Any?> = G.map("ok" to false, "reason" to reason)

    private val FIELD_REASON: List<Pair<String, String>> = listOf(
        Pair("goal_digest", "goal_digest_mismatch"), Pair("policy_digest", "policy_digest_mismatch"), Pair("ontology_digest", "ontology_mismatch"),
        Pair("tests_digest", "tests_digest_mismatch"), Pair("nl_digest", "nl_digest_mismatch"), Pair("model_set_digest", "model_set_digest_mismatch"),
        Pair("card_digest", "card_digest_mismatch"),
    )

    /** {ok: true, digests, policy} | {ok: false, reason}. */
    private fun derive(subO: Any?, kernel: ReviewKernel, limits: Map<String, Any?>?): Map<String, Any?> {
        if (!isObj(subO)) return bad("malformed_submission")
        val sub = mm(subO)!!
        if (!isObj(sub["goal"]) || !isObj(sub["ontology"]) || sub["instruction"] !is String || sub["model_set"] !is List<*> || (sub.containsKey("tests") && sub["tests"] !is List<*>)) return bad("malformed_submission")
        for (m in list(sub["model_set"])) if (m !is String) return bad("malformed_submission")
        val goal = mm(sub["goal"])!!
        val ontology = mm(sub["ontology"])!!
        val tests: List<Any?> = if (sub.containsKey("tests")) list(sub["tests"]) else ArrayList()
        val card: Map<String, Any?>
        try {
            card = renderPolicyCard(goal, tests, limits, false)
        } catch (e: ReviewError) {
            return bad(e.code)
        } catch (e: RuntimeException) {
            return bad("malformed_goal")
        }
        val gd: String
        val nl: String
        val ts: String
        val ms: String
        try {
            gd = GoalDigests.goalDigest(goal)
            nl = GoalDigests.nlDigest(sub["instruction"] as String)
            ts = GoalExamples.testsDigest(tests)
            val models = ArrayList<String>()
            for (m in list(sub["model_set"])) models.add(m as String)
            ms = GoalDigests.modelSetDigest(models)
        } catch (e: RuntimeException) {
            return bad("malformed_goal")
        }
        if (goal["nlDigest"] !is String || nl != goal["nlDigest"]) return bad("instruction_mismatch")
        val compiled: Map<String, Any?>
        try {
            compiled = kernel.compile(goal, ontology)
        } catch (e: RuntimeException) {
            return bad("compile_error")
        }
        if (compiled["ok"] != true) return bad("compile_error")
        val policy = mm(compiled["policy"])!!
        val pd: String
        try {
            val findings = kernel.analyze(policy)
            if (findings.isNotEmpty()) return bad("analyzer_error")
            pd = kernel.policyDigest(policy)
        } catch (e: RuntimeException) {
            return bad("analyzer_error")
        }
        if (tests.isNotEmpty()) {
            if (!kernel.canDecide()) return bad("tests_unverifiable")
            // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
            for (to in tests) {
                val t = mm(to)!!
                val got: String
                try {
                    var ont: Map<String, Any?> = ontology
                    if (G.truthy(t["rels"])) {
                        val oo = LinkedHashMap(ontology)
                        oo["rels"] = t["rels"]
                        ont = oo
                    }
                    got = kernel.decide(goal, ont, mm(t["act"])!!, mm(t["hist"])!!)
                } catch (e: RuntimeException) {
                    return bad("tests_unverifiable")
                }
                if (got != GoalExamples.expectedDecision(t["answer"] as String?)) return bad("tests_contradicted")
            }
        }
        val digests = G.map("goal_digest" to gd, "policy_digest" to pd, "card_digest" to cardDigest(card), "ontology_digest" to goal["ontDigest"], "tests_digest" to ts, "nl_digest" to nl, "model_set_digest" to ms)
        return G.map("ok" to true, "digests" to digests, "policy" to policy)
    }

    private fun approveWith(sub: Map<String, Any?>, reviewerId: String, signer: (Map<String, Any?>) -> Map<String, Any?>, opts: ApproveOptions?): Map<String, Any?> {
        val o = opts ?: ApproveOptions()
        val now = o.now ?: System.currentTimeMillis()
        val ttl = o.ttlMs ?: DEFAULT_TTL_MS
        if (ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS || Math.abs(now) > G.MAX_SAFE) throw IllegalArgumentException("approveGoal: invalid time or ttl")
        val kernel = o.kernel ?: throw IllegalArgumentException("approveGoal: a compiler kernel is required")
        val d = derive(sub, kernel, o.limits)
        if (d["ok"] != true) throw IllegalArgumentException("approveGoal: " + d["reason"])
        val base = o.base
        if (base != null) diffGoals(base, mm(sub["goal"])!!, null, o.limits, null)
        val body = LinkedHashMap(mm(d["digests"])!!)
        body["v"] = G.num(1)
        body["reviewer"] = reviewerId
        body["approved_at"] = G.num(now)
        body["expires_at"] = G.num(now + ttl)
        return signer(body)
    }

    /**
     * The human step: sign the exact goal with an Ed25519 seed. Re-derives everything the loader will; throws when the goal is not signable
     * (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a contradicted test, an instruction that
     * does not match `nlDigest`). A kernel is required.
     */
    @JvmStatic
    fun approveGoal(sub: Map<String, Any?>, reviewerSeed: ByteArray, opts: ApproveOptions?): Map<String, Any?> =
        approveWith(sub, GoalSign.signerId(reviewerSeed), { body -> GoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewerSeed) }, opts)

    /** [approveGoal] with a suite-agile (hybrid or post-quantum) signer. */
    @JvmStatic
    fun approveGoal(sub: Map<String, Any?>, reviewer: Keys.SuiteKey, opts: ApproveOptions?): Map<String, Any?> =
        approveWith(sub, reviewer.id() ?: throw IllegalArgumentException("approveGoal: the reviewer has no pinned identity"), { body -> GoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewer) }, opts)

    /**
     * The only door from a submitted goal to an enforceable one: recomputes every digest, recompiles, re-renders the card, re-runs the
     * confirmed examples, then checks the signature. Never throws: {ok: true, approved} | {ok: false, reason}.
     */
    @JvmStatic
    fun loadApprovedGoal(sub: Any?, approval: Map<String, Any?>?, opts: LoadOptions): Map<String, Any?> {
        try {
            val now = opts.now ?: System.currentTimeMillis()
            val reviewers = opts.reviewers
            if (reviewers == null || reviewers.isEmpty()) return bad("no_reviewers_pinned")
            val a = approval
            if (a == null || G.safeInt(a["v"]) != 1L || a["sig"] !is String || a["reviewer"] !is String || G.safeInt(a["approved_at"]) == null || G.safeInt(a["expires_at"]) == null) return bad("malformed_approval")
            for (f in FIELD_REASON) if (a[f.first] !is String) return bad("malformed_approval")
            val kernel = opts.kernel ?: throw IllegalArgumentException("a compiler kernel is required")
            val d = derive(sub, kernel, opts.limits)
            if (d["ok"] != true) return d
            val goal = mm((sub as Map<*, *>)["goal"])!!
            if (opts.ontologyDigest != null && opts.ontologyDigest != goal["ontDigest"]) return bad("ontology_mismatch")
            val digests = mm(d["digests"])!!
            for (f in FIELD_REASON) if (a[f.first] != digests[f.first]) return bad(f.second)
            var pinned = false
            for (p in reviewers) if ((if (p is String) p else G.get(p, "pk")) == a["reviewer"]) pinned = true
            if (!pinned) return bad("reviewer_not_pinned")
            val approvedAt = G.safeInt(a["approved_at"])!!
            val expiresAt = G.safeInt(a["expires_at"])!!
            if (expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_GOAL_APPROVAL_TTL_MS) return bad("ttl_too_long")
            if (approvedAt > now) return bad("not_yet_valid")
            if (now >= expiresAt) return bad("expired")
            if (!GoalSign.verifyGoalArtifact(GOAL_APPROVAL_KIND, a, "reviewer", reviewers)) return bad("bad_signature")
            val ref = G.map("goal_digest" to digests["goal_digest"], "policy_digest" to digests["policy_digest"])
            val approved = G.map(
                "goal" to goal, "ontology" to sub["ontology"], "policy" to d["policy"], "ref" to ref, "goal_string" to Pca.intentGoalV3(Pca.ApprovedGoal.fromJson(ref)),
                "intent_policy" to G.map("approved_goal" to ref), "instruction" to sub["instruction"], "reviewer" to a["reviewer"], "expires_at" to a["expires_at"],
            )
            return G.map("ok" to true, "approved" to approved)
        } catch (e: RuntimeException) {
            return bad("malformed_approval")
        }
    }
}
