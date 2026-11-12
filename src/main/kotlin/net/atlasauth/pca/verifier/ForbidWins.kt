package net.atlasauth.pca.verifier

/**
 * Forbid-wins decision witness and certificate (security contract C-240, C-241; packages/pca/src/forbid-certificate.ts) and the
 * veto-polarity trigger of the prohibition engine (`whenMatches`). A policy is a flat list of clauses: `permit` grants (anything
 * undecidable is "not matched"); `forbid` vetoes and `escalate` caps the decision at escalate, both with the prohibition polarity
 * (anything undecidable is "matched"). The decision is order-independent: any forbid matched denies; else no permit matched denies;
 * else any escalate matched escalates; else allow. [certify] turns a decision into a canonical certificate and [check] re-derives
 * it, so a verifier never trusts a certificate it did not recompute. Pure and total: nothing here throws.
 */
@Suppress("UNCHECKED_CAST")
object ForbidWins {
    const val CERT_VERSION = 1
    const val CERT_KIND = "forbid-wins"
    const val MAX_CLAUSES = 512
    private val KINDS = listOf("permit", "forbid", "escalate")
    private val OPS = setOf("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of")
    private const val MAX_CONDITION_DEPTH = 32

    /** The forbid-wins gate of `authorize` (`Input.forbid`): the clause source plus the decision options. */
    class Options @JvmOverloads constructor(
        /** `(operation, grant) -> clause list` from your own store (a throwing source refuses). */
        val clauses: (Authorize.Operation, Map<String, Any?>?) -> List<Any?>,
        /** `{subject?, env?}` for the clause predicates (the operation supplies the action); optional. */
        val context: ((Authorize.Operation) -> Map<String, Any?>?)? = null,
        /** Signers, most authoritative first. */
        val precedence: List<String>? = null,
        /** When non-null a permit from a signer outside this list is ignored. */
        val permitSigners: List<String>? = null,
        /** The call must carry a certificate recomputed from the clauses and the operation. */
        val requireCertificate: Boolean = false,
    )

    // ---- the veto-polarity trigger (prohibitions.ts whenMatches)

    internal fun validateCondition(c: Any?, depth: Int): String? {
        if (c !is Map<*, *>) return "condition not an object"
        if (depth > MAX_CONDITION_DEPTH) return "condition nesting too deep"
        if (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not")) {
            if (c.containsKey("not")) return validateCondition(c["not"], depth + 1)
            val key = if (c.containsKey("all_of")) "all_of" else "any_of"
            val arr = c[key]
            if (arr !is List<*> || arr.isEmpty()) return "condition.$key must be a non-empty array"
            for (child in arr) validateCondition(child, depth + 1)?.let { return it }
            return null
        }
        val field = c["field"]
        if (field !is String || field.isEmpty()) return "condition.field missing"
        val op = c["op"]
        if (op !is String || op !in OPS) return "unknown condition op " + IntentRevocation.jsText(op, c.containsKey("op"))
        if (c.containsKey("ref") && (c["ref"] !is String || (c["ref"] as String).isEmpty())) return "bad condition.ref"
        if (op == "member_of" && c.containsKey("collection") && (c["collection"] !is String || (c["collection"] as String).isEmpty())) return "bad condition.collection"
        return null
    }

    /** Null when a trigger (`{verb, resource?, where?}`) is well formed. */
    internal fun validateWhen(w: Any?, label: String, safeSource: (String) -> Boolean = SafeRegex::isSafeSource): String? {
        if (w !is Map<*, *>) return "$label: not an object"
        val v = w["verb"]
        val verbOk = (v is String && v.isNotEmpty()) || (v is List<*> && v.isNotEmpty() && v.all { it is String && it.isNotEmpty() })
        if (!verbOk) return "$label: bad verb"
        if (w.containsKey("resource")) {
            val r = w["resource"]
            if (r !is String) return "$label: bad resource"
            if (r.startsWith("re:")) {
                val src = r.substring(3)
                if (src.length > 200 || !safeSource(src)) return "$label: unsafe regex resource"
                if (SafeRegex.compile(src) == null) return "$label: invalid regex resource"
            }
        }
        if (w.containsKey("where")) {
            val wh = w["where"]
            if (wh !is List<*>) return "$label: where not an array"
            for (c in wh) validateCondition(c, 0)?.let { return "$label: $it" }
        }
        return null
    }

    /**
     * Does a prohibition trigger match? verb and resource exactly as the permission DSL; where-conditions conservatively. FULLY
     * fail-closed: a malformed trigger, an unsafe regex, an oversized regex subject, an unknown op, a missing field or operand all
     * count as MATCHED (the veto applies). Never throws.
     */
    fun whenMatches(w: Any?, ctx: Map<String, Any?>?): Boolean = try {
        whenMatchesInner(w, ctx)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        true // cannot evaluate: the veto applies
    }

    private fun whenMatchesInner(w: Any?, ctx: Map<String, Any?>?): Boolean {
        if (validateWhen(w, "when") != null) return true
        val a = ctx?.get("action") as? Map<String, Any?>
        if (a == null || a["verb"] !is String || a["resource"] !is String) return true
        val wm = w as Map<String, Any?>
        val res = wm["resource"]
        val oversized = res is String && res.startsWith("re:") && (a["resource"] as String).length > Predicates.MAX_RE_RESOURCE_LEN
        val refused0 = SafeRegex.refusals()
        val probe = LinkedHashMap<String, Any?>()
        probe["verb"] = wm["verb"]
        if (!oversized && res != null) probe["resource"] = res
        if (!Predicates.predicateMatches(probe, ctx)) {
            if (SafeRegex.refusals() == refused0) return false
        }
        val wh = wm["where"]
        if (wh is List<*>) {
            for (c in wh) if (Predicates.evaluateConditionTri(c, ctx) == Predicates.Tri.FALSE) return false
        }
        return true
    }

    // ---- clauses

    /** Null when the clause list is well formed (distinct ids, known kinds, a predicate for each). */
    fun clausesError(clauses: Any?): String? {
        if (clauses !is List<*>) return "clauses must be an array"
        if (clauses.size > MAX_CLAUSES) return "more than $MAX_CLAUSES clauses"
        val seen = HashSet<String>()
        for (i in clauses.indices) {
            val c = clauses[i]
            if (c !is Map<*, *>) return "clauses[$i] must be an object"
            val id = c["id"]
            if (id !is String || id.isEmpty() || id.length > 128) return "clauses[$i].id must be a string of 1..128 characters"
            if (!seen.add(id)) return "clauses[$i].id '$id' is a duplicate"
            val kind = c["kind"]
            if (kind !is String || kind !in KINDS) return "clauses[$i].kind must be permit, forbid or escalate"
            if (c.containsKey("signer") && (c["signer"] !is String || (c["signer"] as String).length > 256)) return "clauses[$i].signer must be a string of at most 256 characters"
            if (c["when"] !is Map<*, *>) return "clauses[$i].when must be a predicate object"
        }
        return null
    }

    private fun valueOf(c: Map<String, Any?>, ctx: Map<String, Any?>?): String {
        val w = c["when"]
        if (c["kind"] == "permit") return if (Predicates.predicateMatches(w, ctx)) "true" else "false"
        if (!whenMatches(w, ctx)) return "false"
        return if (Predicates.predicateMatches(w, ctx)) "true" else "unknown"
    }

    private fun rank(signer: Any?, precedence: List<String>): Int {
        val i = if (signer is String) precedence.indexOf(signer) else -1
        return if (i < 0) precedence.size else i
    }

    /** A decision: `decision` allow, escalate or deny; the winner (kind, id), the shadowed ids and the per-clause values. */
    class Decision internal constructor(
        val decision: String,
        val winnerKind: String,
        val winnerId: String?,
        val shadowed: List<String>,
        val values: List<Map<String, Any?>>,
    )

    private fun malformed() = Decision("deny", "malformed", null, emptyList(), emptyList())

    /**
     * Decide a clause list against an action context `{action: {verb, resource, params}}`. `precedence` lists signers most
     * authoritative first; `permitSigners` (nullable) drops other signers' permits.
     */
    @JvmOverloads
    fun decide(clauses: Any?, ctx: Map<String, Any?>?, precedence: List<String>? = null, permitSigners: List<String>? = null): Decision = try {
        decideInner(clauses, ctx, precedence, permitSigners)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        malformed()
    }

    private fun decideInner(clauses: Any?, ctx: Map<String, Any?>?, precedence: List<String>?, permitSigners: List<String>?): Decision {
        if (clausesError(clauses) != null) return malformed()
        val a = ctx?.get("action")
        if (a !is Map<*, *> || a["verb"] !is String || a["resource"] !is String) return malformed()
        val prec = precedence ?: emptyList()
        val cs = (clauses as List<*>).map { it as Map<String, Any?> }
        val values = cs.map { c ->
            val active = c["kind"] != "permit" || permitSigners == null || (c["signer"] is String && permitSigners.contains(c["signer"] as String))
            linkedMapOf<String, Any?>("id" to c["id"], "kind" to c["kind"], "value" to (if (active) valueOf(c, ctx) else "false"))
        }
        fun hit(kind: String) = cs.filterIndexed { i, c -> c["kind"] == kind && values[i]["value"] != "false" }
        val forbids = hit("forbid").sortedWith(Comparator<Map<String, Any?>> { x, y ->
            val r = rank(x["signer"], prec).compareTo(rank(y["signer"], prec))
            if (r != 0) r else (x["id"] as String).compareTo(y["id"] as String)
        })
        val permits = hit("permit")
        val escalates = hit("escalate")
        fun others(win: Map<String, Any?>?): List<String> = (forbids + permits + escalates).filter { it !== win }.map { it["id"] as String }
        if (forbids.isNotEmpty()) return Decision("deny", "forbid", forbids[0]["id"] as String, others(forbids[0]), values)
        if (permits.isEmpty()) return Decision("deny", "none", null, others(null), values)
        if (escalates.isNotEmpty()) return Decision("escalate", "escalate", escalates[0]["id"] as String, others(escalates[0]), values)
        return Decision("allow", "permit", permits[0]["id"] as String, others(permits[0]), values)
    }

    /** The canonical certificate of a decision. */
    @JvmOverloads
    fun certify(clauses: Any?, ctx: Map<String, Any?>?, precedence: List<String>? = null, permitSigners: List<String>? = null): Map<String, Any?> {
        val d = decide(clauses, ctx, precedence, permitSigners)
        val byId = HashMap<String, Map<String, Any?>>()
        if (clauses is List<*>) for (c in clauses) if (c is Map<*, *> && c["id"] is String) byId[c["id"] as String] = c as Map<String, Any?>
        val rows = d.values.map { v ->
            val row = linkedMapOf<String, Any?>("id" to v["id"], "kind" to v["kind"])
            val s = byId[v["id"] as String]?.get("signer")
            if (s != null) row["signer"] = s
            row["value"] = v["value"]
            row
        }
        return linkedMapOf(
            "v" to IntentJs.ofLong(CERT_VERSION.toLong()),
            "kind" to CERT_KIND,
            "policy" to Pca.hashCanonical(clauses),
            "action" to Pca.hashCanonical(ctx),
            "decision" to d.decision,
            "winner" to linkedMapOf<String, Any?>("kind" to d.winnerKind, "id" to d.winnerId),
            "shadowed" to ArrayList<Any?>(d.shadowed),
            "clauses" to ArrayList<Any?>(rows),
        )
    }

    /** The rule over the certificate's own table: the decision, winner and shadowed list the per-clause values force (no evaluator needed). */
    @JvmOverloads
    fun consistent(cert: Any?, precedence: List<String>? = null): Boolean = PolicyAuthoring.forbidCertificateConsistent(cert, precedence ?: emptyList())

    /** Recompute the certificate from the clauses and the action; it must match byte for byte. Null when it does, else the refusal reason. */
    @JvmOverloads
    fun check(cert: Any?, clauses: Any?, ctx: Map<String, Any?>?, precedence: List<String>? = null, permitSigners: List<String>? = null): String? = try {
        if (clausesError(clauses) != null) "malformed clauses"
        else if (!consistent(cert, precedence)) "certificate table does not entail its decision"
        else if (Pca.hashCanonical(certify(clauses, ctx, precedence, permitSigners)) != Pca.hashCanonical(cert)) "certificate does not match the recomputed decision"
        else null
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "certificate check error (fail closed)"
    }
}
