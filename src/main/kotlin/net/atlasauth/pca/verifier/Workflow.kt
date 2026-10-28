package net.atlasauth.pca.verifier

/**
 * Workflow (DAG) admission (K5, C-300..C-309): a principal signs ONE commitment to a whole workflow (steps, dataflow edges with
 * per-edge constraints, label restrictions, freshness, budgets); each step is admitted only as part of that DAG and its inputs are
 * proven from the signed receipts of earlier steps. [Workflow.admitStep] and [Workflow.bindPromises] are total and pure: everything
 * unknown, malformed, unsigned, out of order or unplanned DENIES. Integers only (a JSON number must be an exact safe integer).
 * Replays packages/pca/conformance/workflow-vectors.json; mirrors packages/pca/src/workflow.ts check for check.
 */
object Workflow {
    const val WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\u0000"
    const val WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\u0000"
    private const val WF_REF = "atlas-pca/workflow-ref/v1"
    private const val WR_REF = "atlas-pca/wf-receipt-ref/v1"
    private const val VAL = "atlas-pca/wf-value/v1"

    private const val MAX_STEPS = 64
    private const val MAX_EDGES = 256
    private const val MAX_DEPS = 16
    private const val MAX_LABELS = 16
    internal const val MAX_FIELDS = 32
    private const val MAX_COST = 8

    // ---- shared strict helpers (also used by ReadSide) ----
    internal val ID_RE = Regex("(?!__proto__\\z)[A-Za-z0-9_.:-]{1,64}")
    internal val LABEL_RE = Regex("(?!__proto__\\z)[a-z0-9_.:-]{1,64}")
    internal val NAME_RE = Regex("(?!__proto__\\z)[A-Za-z0-9_.-]{1,64}")
    internal val UNIT_RE = Regex("[A-Za-z0-9_.:-]{1,16}")

    internal fun obj(o: Any?): Map<String, Any?>? = K3Sig.map(o)
    internal fun isUint(o: Any?): Boolean = Json.isSafeInt(o) && Json.asLong(o) >= 0L
    internal fun isStr(o: Any?, max: Int): Boolean = K3Sig.isStr(o, max)
    internal fun isB32(o: Any?): Boolean = Pca.decodeB64uStrict(o, 32) != null
    internal fun isId(o: Any?): Boolean = o is String && ID_RE.matches(o)
    private fun isName(o: Any?): Boolean = o is String && NAME_RE.matches(o)
    private fun isUnit(o: Any?): Boolean = o is String && UNIT_RE.matches(o)
    private fun nullOr(o: Any?, ok: (Any?) -> Boolean): Boolean = o == null || ok(o)

    /** Strictly ascending (bytewise; every member is ASCII) with every member matching [re]. */
    internal fun sortedUnique(x: Any?, re: Regex, max: Int): Boolean {
        val l = x as? List<*> ?: return false
        if (l.size > max) return false
        for (i in l.indices) {
            val s = l[i] as? String ?: return false
            if (!re.matches(s)) return false
            if (i > 0 && !((l[i - 1] as String) < s)) return false
        }
        return true
    }

    internal fun onlyKeys(o: Map<String, Any?>, keys: List<String>): Boolean = o.size == keys.size && keys.all { o.containsKey(it) }

    internal fun verifyBody(domain: String, body: Any?, signer: Any?, sig: Any?): Boolean = K3Sig.verifyBody(domain, body, signer, sig)

    private fun isScalar(v: Any?): Boolean = v is String || v is Boolean || Json.isSafeInt(v)

    internal fun isScalarMap(x: Any?): Boolean {
        val m = obj(x) ?: return false
        return m.size <= MAX_FIELDS && m.all { (k, v) -> NAME_RE.matches(k) && isScalar(v) }
    }

    /** The digest of a scalar value as it appears in step receipts (domain separated). */
    @JvmStatic
    fun valueDigest(v: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to VAL, "v" to v))

    private fun uintMap(x: Any?, max: Int): Boolean {
        val m = obj(x) ?: return false
        return m.size <= max && m.all { (k, v) -> NAME_RE.matches(k) && isUint(v) }
    }

    // ---- validation ----
    private val STEP_KEYS = listOf("id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost")
    private val EDGE_KEYS = listOf("from", "to", "op", "unit", "deny_labels", "promise")
    private val BODY_KEYS = listOf("v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget")
    private val OPS = setOf("eq", "le", "ge", "lt", "gt")

    private fun validStep(x: Any?): Boolean {
        val s = obj(x) ?: return false
        if (!onlyKeys(s, STEP_KEYS)) return false
        return isId(s["id"]) && isStr(s["verb"], 128) && isStr(s["resource"], 512) && nullOr(s["params_digest"], { isB32(it) }) &&
            sortedUnique(s["deps"], ID_RE, MAX_DEPS) && nullOr(s["sink"], { isId(it) }) && sortedUnique(s["deny_labels"], LABEL_RE, MAX_LABELS) &&
            sortedUnique(s["escalate_labels"], LABEL_RE, MAX_LABELS) && nullOr(s["fresh_ms"], { isUint(it) }) && uintMap(s["cost"], MAX_COST)
    }

    private fun validEdge(x: Any?): Boolean {
        val e = obj(x) ?: return false
        if (!onlyKeys(e, EDGE_KEYS)) return false
        val f = obj(e["from"])
        val t = obj(e["to"])
        return f != null && onlyKeys(f, listOf("step", "field")) && isId(f["step"]) && isName(f["field"]) &&
            t != null && onlyKeys(t, listOf("step", "param")) && isId(t["step"]) && isName(t["param"]) &&
            e["op"].let { it is String && it in OPS } && nullOr(e["unit"], { isUnit(it) }) && sortedUnique(e["deny_labels"], LABEL_RE, MAX_LABELS) && nullOr(e["promise"], { isId(it) })
    }

    private fun isOne(o: Any?): Boolean = Json.isSafeInt(o) && Json.asLong(o) == 1L

    /** Shape of the body only (no signature, no DAG semantics). */
    @JvmStatic
    fun validWorkflowBody(x: Any?): Boolean {
        val b = obj(x) ?: return false
        if (!onlyKeys(b, BODY_KEYS) || !isOne(b["v"])) return false
        if (!isId(b["id"]) || !isB32(b["principal"]) || !nullOr(b["goal_digest"], { isB32(it) }) || !nullOr(b["plan_root"], { isB32(it) }) || !isUint(b["issued_at"]) || !isUint(b["expires_at"])) return false
        val steps = b["steps"] as? List<*> ?: return false
        if (steps.isEmpty() || steps.size > MAX_STEPS || !steps.all({ validStep(it) })) return false
        val edges = b["edges"] as? List<*> ?: return false
        if (edges.size > MAX_EDGES || !edges.all({ validEdge(it) })) return false
        val bg = obj(b["budget"]) ?: return false
        if (!onlyKeys(bg, listOf("max_steps", "caps")) || !isUint(bg["max_steps"]) || !uintMap(bg["caps"], MAX_COST)) return false
        val caps = obj(bg["caps"])!!
        // every cost name must be capped: an uncapped cost is a budget that silently does not exist
        return steps.all { s -> obj(obj(s)!!["cost"])!!.keys.all { caps.containsKey(it) } }
    }

    private fun stepsOf(b: Map<String, Any?>): List<Map<String, Any?>> = (b["steps"] as List<*>).map { obj(it)!! }
    private fun edgesOf(b: Map<String, Any?>): List<Map<String, Any?>> = (b["edges"] as List<*>).map { obj(it)!! }
    private fun strs(o: Any?): List<String> = (o as List<*>).map { it as String }
    private fun ref(e: Map<String, Any?>, which: String, k: String): String = obj(e[which])!![k] as String

    /** DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. Null when fine. */
    @JvmStatic
    fun dagError(b: Map<String, Any?>): String? {
        val ids = HashSet<String>()
        val steps = stepsOf(b)
        for (s in steps) if (!ids.add(s["id"] as String)) return "duplicate step id"
        for (s in steps) for (d in strs(s["deps"])) if (d == s["id"] || d !in ids) return "bad dependency"
        val anc = ancestors(b) ?: return "cycle"
        for (e in edgesOf(b)) {
            val from = ref(e, "from", "step")
            val to = ref(e, "to", "step")
            if (from !in ids || to !in ids || from !in anc[to]!!) return "edge does not follow a dependency"
        }
        return null
    }

    /** step id -> the set of its transitive dependencies; null on a cycle. */
    @JvmStatic
    fun ancestors(b: Map<String, Any?>): Map<String, Set<String>>? {
        val byId = HashMap<String, Map<String, Any?>>()
        for (s in stepsOf(b)) byId[s["id"] as String] = s
        val out = HashMap<String, Set<String>>()
        val state = HashMap<String, Int>()
        fun visit(id: String): Boolean {
            if (state[id] == 2) return true
            if (state[id] == 1) return false
            state[id] = 1
            val set = HashSet<String>()
            for (d in strs(byId[id]!!["deps"])) {
                if (!visit(d)) return false
                set.add(d)
                set.addAll(out[d]!!)
            }
            out[id] = set
            state[id] = 2
            return true
        }
        for (s in stepsOf(b)) if (!visit(s["id"] as String)) return null
        return out
    }

    @JvmStatic
    fun workflowDigest(b: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to WF_REF, "w" to b))

    @JvmStatic
    fun receiptRef(r: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to WR_REF, "r" to r))

    private val RECEIPT_KEYS = listOf("v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig")

    /** The signed body of a step receipt: the receipt without `sig`. */
    private fun recBody(r: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in RECEIPT_KEYS) if (k != "sig") m[k] = r[k]
        return m
    }

    private fun validReceiptShape(x: Any?): Boolean {
        val r = obj(x) ?: return false
        if (!onlyKeys(r, RECEIPT_KEYS) || !isOne(r["v"])) return false
        if (!isB32(r["wf"]) || !isId(r["step"]) || !isUint(r["seq"]) || !nullOr(r["prev"], { isB32(it) }) || (Json.asLong(r["seq"]) == 0L) != (r["prev"] == null) ||
            (r["outcome"] != "ok" && r["outcome"] != "failed")) return false
        if (!isB32(r["params_digest"]) || !isUint(r["issued_at"]) || !isB32(r["signer"]) || r["sig"] !is String) return false
        val o = obj(r["outputs"]) ?: return false
        if (o.size > MAX_FIELDS) return false
        return o.all { (k, v) ->
            val m = obj(v)
            NAME_RE.matches(k) && m != null && onlyKeys(m, listOf("digest", "num", "unit", "labels")) && isB32(m["digest"]) && nullOr(m["num"], { isUint(it) }) &&
                nullOr(m["unit"], { isUnit(it) }) && sortedUnique(m["labels"], LABEL_RE, MAX_LABELS)
        }
    }

    // ---- admission ----
    class WfResult(
        val decision: String,
        val code: String?,
        val step: String?,
        /** index of the offending receipt (receipt-chain failures) */
        val at: Int?,
        /** edge indexes whose source receipt does not exist yet (promise pipelining) */
        val pending: List<Int>,
    ) {
        fun toMap(): Map<String, Any?> = linkedMapOf("decision" to decision, "code" to code, "step" to step, "at" to at?.toLong(), "pending" to pending.map { it.toLong() })
    }

    /** All members are parsed JSON values (or null); `principal` and `rsSigner` are the keys the verifier pinned. */
    class AdmitInput(val workflow: Any?, val principal: Any?, val rsSigner: Any?, val receipts: Any?, val now: Any?, val request: Any?)

    private fun res(decision: String, code: String?, step: String?, at: Int? = null, pending: List<Int> = emptyList()) = WfResult(decision, code, step, at, pending)
    private fun deny(code: String, step: String? = null, at: Int? = null) = res("deny", code, step, at)

    /** Is [root] the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? Never throws. */
    @JvmStatic
    fun planRootAuthorized(workflow: Any?, principal: Any?, now: Any?, root: Any?): Boolean = try {
        val w = obj(workflow)
        val body = w?.get("body")
        val b = obj(body)
        w != null && b != null && validWorkflowBody(body) && dagError(b) == null && b["principal"] == principal && Json.isSafeInt(now) &&
            verifyBody(WORKFLOW_DOMAIN, body, principal, w["sig"]) && Json.asLong(now) >= Json.asLong(b["issued_at"]) &&
            Json.asLong(now) < Json.asLong(b["expires_at"]) && b["plan_root"] == root
    } catch (e: Exception) {
        false
    }

    private fun validRequest(x: Any?): Boolean {
        val r = obj(x) ?: return false
        if (!onlyKeys(r, listOf("step", "verb", "resource", "params", "units", "goal_digest", "plan_root"))) return false
        val units = obj(r["units"]) ?: return false
        return isId(r["step"]) && isStr(r["verb"], 128) && isStr(r["resource"], 512) && isScalarMap(r["params"]) &&
            units.all { (k, v) -> NAME_RE.matches(k) && isUnit(v) } && nullOr(r["goal_digest"], { isB32(it) }) && nullOr(r["plan_root"], { isB32(it) })
    }

    /** Check the receipt chain against the workflow. Returns the offending index, or null. */
    private fun receiptError(w: Map<String, Any?>, rsSigner: String, receipts: List<*>, now: Long): Int? {
        val wd = workflowDigest(w)
        val byId = HashMap<String, Map<String, Any?>>()
        for (s in stepsOf(w)) byId[s["id"] as String] = s
        val edges = edgesOf(w)
        val index = HashSet<String>()
        var prev: Map<String, Any?>? = null
        for (i in receipts.indices) {
            val r = obj(receipts[i])
            if (r == null || !validReceiptShape(r) || r["signer"] != rsSigner || r["wf"] != wd || Json.asLong(r["seq"]) != i.toLong() || Json.asLong(r["issued_at"]) > now) return i
            val step = r["step"] as String
            if (step !in byId || step in index) return i
            val p = prev
            if ((if (p == null) r["prev"] != null else r["prev"] != receiptRef(p)) || !verifyBody(WF_RECEIPT_DOMAIN, recBody(r), rsSigner, r["sig"])) return i
            // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
            for (d in strs(byId[step]!!["deps"])) {
                if (d in index) continue
                val es = edges.filter { ref(it, "from", "step") == d && ref(it, "to", "step") == step }
                if (es.isEmpty() || es.any { it["promise"] == null }) return i
            }
            index.add(step)
            prev = r
        }
        return null
    }

    private fun cost(s: Map<String, Any?>, name: String): Long {
        val c = obj(s["cost"])!!
        return if (c.containsKey(name)) Json.asLong(c[name]) else 0L
    }

    private fun evaluate(inp: AdmitInput, bind: Boolean): WfResult {
        val sw = obj(inp.workflow)
        val q = obj(inp.request)
        val receiptsAny = inp.receipts
        if (sw == null || !onlyKeys(sw, listOf("body", "sig")) || !validWorkflowBody(sw["body"]) || !validRequest(q) || receiptsAny !is List<*> || !isB32(inp.principal) || !isB32(inp.rsSigner) || !isUint(inp.now)) return deny("bad_workflow")
        q!!
        val w = obj(sw["body"])!!
        val principal = inp.principal as String
        val rsSigner = inp.rsSigner as String
        val now = Json.asLong(inp.now)
        val qStep = q["step"] as String
        if (dagError(w) != null) return deny("bad_dag", qStep)
        if (w["principal"] != principal || !verifyBody(WORKFLOW_DOMAIN, w, principal, sw["sig"])) return deny("bad_signature", qStep)
        if (now < Json.asLong(w["issued_at"])) return deny("not_yet", qStep)
        if (now >= Json.asLong(w["expires_at"])) return deny("expired", qStep)
        if (q["goal_digest"] != w["goal_digest"]) return deny("goal_mismatch", qStep)
        if (q["plan_root"] != w["plan_root"]) return deny("plan_root_mismatch", qStep)
        val bad = receiptError(w, rsSigner, receiptsAny, now)
        if (bad != null) return deny("bad_receipt", qStep, bad)
        val done = receiptsAny.map { obj(it)!! }
        val rec = HashMap<String, Map<String, Any?>>()
        for (r in done) rec[r["step"] as String] = r
        val steps = stepsOf(w)
        val step = steps.find { it["id"] == qStep } ?: return deny("unplanned_step", qStep)
        if (step["verb"] != q["verb"] || step["resource"] != q["resource"]) return deny("step_mismatch", qStep)
        val params = obj(q["params"])!!
        val pd = Pca.hashCanonical(params)
        if (step["params_digest"] != null && step["params_digest"] != pd) return deny("params_mismatch", qStep)
        val mine = rec[step["id"] as String]
        val budget = obj(w["budget"])!!
        if (bind) {
            if (mine == null || mine["params_digest"] != pd) return deny("params_mismatch", qStep)
        } else {
            if (mine != null) return deny("already_done", qStep)
            if (done.size + 1 > Json.asLong(budget["max_steps"])) return deny("budget_exceeded", qStep)
            for ((name, cap) in obj(budget["caps"])!!) {
                val spent = done.sumOf { r -> cost(steps.find { it["id"] == r["step"] }!!, name) } + cost(step, name)
                if (spent > Json.asLong(cap)) return deny("budget_exceeded", qStep)
            }
        }
        // dependencies
        val edges = edgesOf(w)
        val pending = ArrayList<Int>()
        var unconstrained = false
        val sid = step["id"] as String
        for (d in strs(step["deps"])) {
            val dr = rec[d]
            if (dr == null) {
                val es = edges.filter { ref(it, "from", "step") == d && ref(it, "to", "step") == sid }
                if (bind || es.isEmpty()) return deny("deps_unmet", qStep)
                if (es.any { it["promise"] == null }) unconstrained = true
                continue
            }
            if (dr["outcome"] != "ok") return deny("dep_failed", qStep)
            val fresh = step["fresh_ms"]
            if (fresh != null && now - Json.asLong(dr["issued_at"]) > Json.asLong(fresh)) return deny("stale_dep", qStep)
        }
        // edge constraints
        val units = obj(q["units"])!!
        for (i in edges.indices) {
            val e = edges[i]
            if (ref(e, "to", "step") != sid) continue
            val src = rec[ref(e, "from", "step")]
            if (src == null) {
                pending.add(i)
                continue
            }
            val outs = obj(src["outputs"])!!
            val field = ref(e, "from", "field")
            val param = ref(e, "to", "param")
            if (!outs.containsKey(field) || !params.containsKey(param)) return deny("edge_missing", qStep, i)
            val out = obj(outs[field])!!
            val v = params[param]
            val ou = out["unit"]
            if (ou != units[param] || ou != e["unit"]) return deny("edge_unit", qStep, i)
            if (e["op"] == "eq") {
                if (valueDigest(v) != out["digest"]) return deny("edge_digest", qStep, i)
            } else {
                if (!Json.isSafeInt(v) || out["num"] == null) return deny("edge_value", qStep, i)
                val a = Json.asLong(v)
                val n = Json.asLong(out["num"])
                val ok = when (e["op"]) { "le" -> a <= n; "ge" -> a >= n; "lt" -> a < n; else -> a > n }
                if (!ok) return deny("edge_relation", qStep, i)
            }
            val denied = strs(e["deny_labels"])
            if (strs(out["labels"]).any { it in denied }) return deny("taint_flow", qStep, i)
        }
        if (bind && pending.isNotEmpty()) return deny("deps_unmet", qStep)
        // taint across the DAG: every label any executed ancestor produced
        val anc = ancestors(w)!!
        val inherited = HashSet<String>()
        for (a in anc[sid]!!) for (o in obj(rec[a]?.get("outputs"))?.values ?: emptyList<Any?>()) inherited.addAll(strs(obj(o)!!["labels"]))
        if (strs(step["deny_labels"]).any { it in inherited }) return deny("taint_flow", qStep)
        if (unconstrained) return res("escalate", "pipeline_unconstrained", qStep)
        if (strs(step["escalate_labels"]).any { it in inherited }) return res("escalate", "taint_escalate", qStep)
        return res("allow", null, qStep, null, pending)
    }

    /** Admit ONE step of the committed workflow, or deny / escalate. */
    @JvmStatic
    fun admitStep(inp: AdmitInput): WfResult = try {
        evaluate(inp, false)
    } catch (e: Exception) {
        deny("bad_workflow")
    }

    /** Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge. */
    @JvmStatic
    fun bindPromises(inp: AdmitInput): WfResult = try {
        evaluate(inp, true)
    } catch (e: Exception) {
        deny("bad_workflow")
    }
}
