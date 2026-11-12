package net.atlasauth.pca.verifier

/**
 * Bounded safety-LTL behavioural contracts (packages/pca/src/contracts.ts): an optional embedded prohibition constitution (`invariants`)
 * plus temporal `clauses` (always, never, precedes, requires_prior, responds_within, and) over ONE shared, hash-chained [Prohibitions]
 * state. A contract without clauses behaves exactly like the prohibition monitor. Everything malformed, unknown or unresolvable fails
 * closed; nothing here throws.
 */
@Suppress("UNCHECKED_CAST")
object Contracts {
    const val CONTRACT_VERSION = 1
    const val CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\u0000"
    const val MAX_CLAUSES = 256
    const val MAX_CLAUSE_DEPTH = 16

    private fun one(s: String): List<String> = arrayListOf(s)

    /** Structural problems with a clause (empty = well formed); collects ids into [seen] for global uniqueness. */
    internal fun validateClause(clO: Any?, seen: MutableSet<String>, depth: Int): List<String> {
        if (depth > MAX_CLAUSE_DEPTH) return one("clause nesting too deep")
        if (!Prohibitions.isObj(clO)) return one("clause not an object")
        val cl = Prohibitions.obj(clO)
        val rawId = cl["id"]
        if (rawId !is String || rawId.isEmpty()) return one("<no id>: missing clause id")
        val id: String = rawId
        if (id.length > Prohibitions.MAX_ID_LEN) return one("$id: id too long")
        if (id in Prohibitions.FORBIDDEN_IDS) return one("$id: forbidden id")
        if (id in seen) return one("$id: duplicate id")
        seen.add(id)
        val kind = Prohibitions.get(cl, "kind")
        var e: String?
        if (kind == "always" || kind == "never") {
            e = ForbidWins.validateWhen(cl["p"], "p")
            return if (e != null) one("$id: $e") else ArrayList()
        }
        if (kind == "precedes" || kind == "requires_prior" || kind == "responds_within") {
            e = ForbidWins.validateWhen(cl["p"], "p")
            if (e == null) e = ForbidWins.validateWhen(cl["q"], "q")
            if (e != null) return one("$id: $e")
            if (kind == "responds_within") {
                val within = cl["within"]
                if (!Prohibitions.isInteger(within) || Prohibitions.dv(within) < 1 || Prohibitions.dv(within) > Prohibitions.MAX_DEADLINE) {
                    return one("$id: within must be an integer in [1, MAX_DEADLINE]")
                }
            }
            return ArrayList()
        }
        if (kind == "and") {
            val subs = cl["clauses"]
            if (subs !is List<*> || subs.isEmpty()) return one("$id: and.clauses must be a non-empty array")
            val out = ArrayList<String>()
            for (sub in subs) out.addAll(validateClause(sub, seen, depth + 1))
            return out
        }
        return one("$id: unknown clause kind ${Prohibitions.text(kind)}")
    }

    private fun countClauses(cls: List<Any?>, depth: Int): Int {
        // bounded recursion: an absurdly deep nest is "too many" at once (validateClause then reports the depth)
        if (depth > MAX_CLAUSE_DEPTH + 1) return MAX_CLAUSES + 1
        var n = 0
        for (cl in cls) {
            n++
            if (Prohibitions.isObj(cl) && Prohibitions.obj(cl)["kind"] == "and" && Prohibitions.obj(cl)["clauses"] is List<*>) {
                n += countClauses(Prohibitions.arr(Prohibitions.obj(cl)["clauses"]), depth + 1)
            }
        }
        return n
    }

    /** Structural problems with a contract (empty = well formed). Total. */
    fun validateContract(cO: Any?): List<String> {
        if (!Prohibitions.isObj(cO)) return one("contract not an object")
        val c = Prohibitions.obj(cO)
        val out = ArrayList<String>()
        val version = c["version"]
        if (!(Prohibitions.fin(version) && Prohibitions.dv(version) == CONTRACT_VERSION.toDouble())) out.add("unsupported version " + Prohibitions.text(Prohibitions.get(c, "version")))
        if (c["principal"] !is String || (c["principal"] as String).isEmpty()) out.add("principal missing")
        val ids = HashSet<String>()
        if (c.containsKey("invariants")) {
            val invariants = c["invariants"]
            if (invariants !is List<*>) {
                out.add("invariants not an array")
                return out
            }
            if (invariants.size > Prohibitions.MAX_INVARIANTS) out.add("too many invariants")
            for (inv in invariants) {
                out.addAll(Prohibitions.validateInvariant(inv))
                val id = if (Prohibitions.isObj(inv)) Prohibitions.obj(inv)["id"] else null
                if (id is String) {
                    if (id in ids) out.add("$id: duplicate id")
                    ids.add(id)
                }
            }
        }
        if (c.containsKey("clauses")) {
            val clauses = c["clauses"]
            if (clauses !is List<*>) {
                out.add("clauses not an array")
                return out
            }
            if (countClauses(clauses, 1) > MAX_CLAUSES) out.add("too many clauses")
            // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
            for (cl in clauses) out.addAll(validateClause(cl, ids, 1))
        }
        return out
    }

    // ---- commitment

    fun contractId(c: Map<String, Any?>): String = Pca.hashCanonical(Prohibitions.body(c))

    /** Signs a contract with the principal's Ed25519 seed. Throws [IllegalArgumentException] on an invalid contract. */
    fun signContract(c: Map<String, Any?>, principalSeed: ByteArray): Map<String, Any?> {
        val problems = validateContract(c)
        if (problems.isNotEmpty()) throw IllegalArgumentException("signContract: " + problems.joinToString("; "))
        val id = contractId(c)
        val out = Prohibitions.body(c)
        out["id"] = id
        out["sig"] = Pca.b64(Keys.edFromSeed(principalSeed).sign(Prohibitions.domainMessage(CONTRACT_SIG_DOMAIN, id)))
        return out
    }

    /** Well formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Null when it verifies, else the reason. Never throws. */
    fun verifyContract(sc: Any?, expectedPrincipal: String?): String? = try {
        verifyInner(sc, expectedPrincipal)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "verification error (fail closed)"
    }

    private fun verifyInner(sc: Any?, expectedPrincipal: String?): String? {
        val problems = validateContract(sc)
        if (problems.isNotEmpty()) return problems[0]
        val c = Prohibitions.obj(sc)
        if (expectedPrincipal != null && expectedPrincipal != c["principal"]) return "principal mismatch"
        val cid = c["id"]
        if (cid !is String || cid != contractId(c)) return "id does not match content"
        val sig = c["sig"]
        if (sig !is String || !IntentJs.verifyEd(c["principal"], Prohibitions.domainMessage(CONTRACT_SIG_DOMAIN, cid), sig)) return "bad signature"
        return null
    }

    internal fun embeddedConstitution(c: Map<String, Any?>): Map<String, Any?> =
        Prohibitions.map("version", Prohibitions.jn(1.0), "principal", c["principal"], "invariants", if (c["invariants"] is List<*>) c["invariants"] else ArrayList<Any?>())

    // ---- clause evaluation

    private fun row(cl: Map<String, Any?>, ok: Boolean, reason: Any?): LinkedHashMap<String, Any?> {
        val r = Prohibitions.map("id", cl["id"], "kind", cl["kind"], "result", if (ok) "pass" else "violated")
        if (Prohibitions.truthy(reason)) r["reason"] = reason
        return r
    }

    private fun base(cl: Map<String, Any?>, ok: Boolean, reason: Any?): LinkedHashMap<String, Any?> {
        val t = Prohibitions.map(
            "ok", ok, "rows", arrayListOf<Any?>(row(cl, ok, reason)),
            "latchSet", LinkedHashMap<String, Any?>(), "deadlineSet", LinkedHashMap<String, Any?>(),
        )
        if (Prohibitions.truthy(reason)) t["reason"] = reason
        return t
    }

    private fun desc(cl: Map<String, Any?>, dflt: String): Any? = cl["description"] ?: dflt

    /** The per-clause transition: the verdict plus the intended latch / deadline updates (applied only if the whole contract is ok). */
    internal fun evalClause(cl: Map<String, Any?>, ctx: Map<String, Any?>, state: Map<String, Any?>, now: Any?): Map<String, Any?> {
        val latched = Prohibitions.obj(state["latched"])
        val deadlines: Map<String, Any?> = if (state["deadlines"] is Map<*, *>) Prohibitions.obj(state["deadlines"]) else LinkedHashMap()
        try {
            when (cl["kind"] as String) {
                "always" -> return if (Prohibitions.whenAffirmative(cl["p"], ctx)) base(cl, true, null) else base(cl, false, desc(cl, "always-invariant violated (action does not satisfy p)"))
                "never" -> return if (ForbidWins.whenMatches(cl["p"], ctx)) base(cl, false, desc(cl, "never-invariant violated (forbidden action)")) else base(cl, true, null)
                "precedes", "requires_prior" -> {
                    val isQ = ForbidWins.whenMatches(cl["q"], ctx) // the guarded action, conservative
                    val held = latched.containsKey(cl["id"] as String)
                    val ok = !isQ || held
                    val t = base(cl, ok, if (ok) null else desc(cl, "precedence violated (prerequisite p not yet admitted before q)"))
                    // latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
                    if (!held && Prohibitions.whenAffirmative(cl["p"], ctx)) (t["latchSet"] as MutableMap<String, Any?>)[cl["id"] as String] = now
                    return t
                }
                "responds_within" -> {
                    var violated = false
                    var carried: Any? = null
                    if (deadlines.containsKey(cl["id"] as String)) {
                        val cur = Prohibitions.dv(deadlines[cl["id"] as String])
                        if (Prohibitions.whenAffirmative(cl["q"], ctx)) {
                            carried = null // any response discharges all open obligations
                        } else {
                            val r = cur - 1
                            if (r <= 0) violated = true // the window is exhausted with no response: a violation at this action
                            else carried = Prohibitions.jn(r)
                        }
                    }
                    if (violated) {
                        val reason = desc(cl, "bounded-liveness deadline missed (no q within " + Prohibitions.text(cl["within"]) + " actions of p)")
                        val rw = row(cl, false, reason)
                        return Prohibitions.map(
                            "ok", false, "reason", rw["reason"], "rows", arrayListOf<Any?>(rw),
                            "latchSet", LinkedHashMap<String, Any?>(), "deadlineSet", LinkedHashMap<String, Any?>(),
                        )
                    }
                    var nxt = carried
                    if (ForbidWins.whenMatches(cl["p"], ctx)) {
                        nxt = if (nxt == null) cl["within"] else (if (Prohibitions.dv(nxt) <= Prohibitions.dv(cl["within"])) nxt else cl["within"])
                    }
                    val ds = LinkedHashMap<String, Any?>()
                    ds[cl["id"] as String] = nxt
                    return Prohibitions.map("ok", true, "rows", arrayListOf<Any?>(row(cl, true, null)), "latchSet", LinkedHashMap<String, Any?>(), "deadlineSet", ds)
                }
                "and" -> {
                    val rows = ArrayList<Any?>()
                    val latchSet = LinkedHashMap<String, Any?>()
                    val deadlineSet = LinkedHashMap<String, Any?>()
                    var ok = true
                    var reason: Any? = null
                    for (sub in Prohibitions.arr(cl["clauses"])) {
                        val r = evalClause(Prohibitions.obj(sub), ctx, state, now)
                        rows.addAll(Prohibitions.arr(r["rows"]))
                        latchSet.putAll(Prohibitions.obj(r["latchSet"]))
                        deadlineSet.putAll(Prohibitions.obj(r["deadlineSet"]))
                        if (r["ok"] != true && ok) {
                            ok = false
                            reason = r["reason"]
                        }
                    }
                    val out = Prohibitions.map("ok", ok, "rows", rows, "latchSet", latchSet, "deadlineSet", deadlineSet)
                    if (Prohibitions.truthy(reason)) out["reason"] = reason
                    return out
                }
                else -> return base(cl, false, "unknown clause kind (fail closed)")
            }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return base(cl, false, "clause evaluation error (fail closed)")
        }
    }

    // ---- the contract monitor

    /** Evaluates a whole contract (embedded constitution + temporal clauses) against one action, WITHOUT advancing: `{ok, violated, reasons, evaluated}`. Total, fail closed. */
    fun checkContract(action: Any?, contract: Any?, state: Any?): Map<String, Any?> =
        SafeRegex.withBudget { checkInner(action, contract, state) }

    private fun checkInner(action: Any?, contract: Any?, state: Any?): Map<String, Any?> {
        try {
            val cp = validateContract(contract)
            if (cp.isNotEmpty()) return structural("<contract>", cp[0])
            if (!Prohibitions.actionOk(action)) return structural("<action>", "malformed action")
            val sp = Prohibitions.stateProblem(state)
            if (sp != null) return structural("<state>", sp)
            val evaluated = ArrayList<Any?>()
            val c = Prohibitions.obj(contract)
            val constitution = embeddedConstitution(c)
            if (Prohibitions.arr(constitution["invariants"]).isNotEmpty()) evaluated.addAll(Prohibitions.arr(Prohibitions.checkProhibitions(action, constitution, state)["evaluated"]))
            val now = Prohibitions.obj(state)["now"]
            if (c["clauses"] is List<*>) {
                for (clO in Prohibitions.arr(c["clauses"])) {
                    val cl = Prohibitions.obj(clO)
                    try {
                        evaluated.addAll(Prohibitions.arr(evalClause(cl, Prohibitions.obj(action), Prohibitions.obj(state), now)["rows"]))
                    } catch (e: Throwable) {
                        if (!Contain.ok(e)) throw e
                        evaluated.add(Prohibitions.map("id", cl["id"], "kind", cl["kind"] ?: "clause", "result", "violated", "reason", "clause evaluation error (fail closed)"))
                    }
                }
            }
            return Prohibitions.summarize(evaluated)
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return structural("<monitor>", "monitor error (fail closed)")
        }
    }

    /** A structural failure: the reason is reported under the id (`<id>: reason`). */
    private fun structural(id: String, reason: String): Map<String, Any?> {
        val r = Prohibitions.structural(id, reason)
        r["reasons"] = arrayListOf<Any?>("$id: $reason")
        return r
    }

    private fun refuse(state: Any?, action: Any?, contract: Any?, decidedBy: String, r: Map<String, Any?>?, reason: String?): Map<String, Any?> {
        val base = r ?: checkContract(action, contract, state)
        val violated = ArrayList(Prohibitions.arr(base["violated"]))
        val reasons = ArrayList(Prohibitions.arr(base["reasons"]))
        if (reason != null) {
            violated.removeAll { it == "<state>" }
            violated.add("<state>")
            reasons.add("<state>: $reason")
        }
        return Prohibitions.map("ok", false, "violated", violated, "reasons", reasons, "evaluated", base["evaluated"], "next", state, "decidedBy", decidedBy)
    }

    /**
     * Checks the whole contract against one action and, iff it holds, advances the hash-chained monitor state. `now` (nullable: the
     * state's own), `expectedSeq` and `expectedStateDigest` (nullable) are the options. Fail closed; `next` is the input state unless `ok`.
     */
    @JvmOverloads
    fun advanceContract(state: Any?, action: Any?, contract: Any?, nowOpt: Any? = null, expectedSeq: Any? = null, expectedStateDigest: String? = null): Map<String, Any?> {
        try {
            val now = nowOpt ?: (if (state is Map<*, *>) state["now"] else null)
            // CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
            if (expectedSeq != null && (!Prohibitions.isObj(state) || !Prohibitions.fin(Prohibitions.obj(state)["seq"]) || Prohibitions.dv(Prohibitions.obj(state)["seq"]) != Prohibitions.dv(expectedSeq))) {
                return refuse(state, action, contract, "state", null, "stale state head (seq)")
            }
            if (expectedStateDigest != null && expectedStateDigest != Prohibitions.safe { Prohibitions.stateDigest(state) }) {
                return refuse(state, action, contract, "state", null, "stale state head (digest)")
            }
            val verdict = checkContract(action, contract, state)
            if (verdict["ok"] != true) {
                var structural = false
                for (v in Prohibitions.arr(verdict["violated"])) {
                    val s = Prohibitions.text(v)
                    if (s.startsWith("<") && s.endsWith(">")) structural = true
                }
                val out = LinkedHashMap(verdict)
                out["next"] = state
                out["decidedBy"] = if (structural) "state" else "contract"
                return out
            }
            val c = Prohibitions.obj(contract)
            val constitution = embeddedConstitution(c)
            val adv = Prohibitions.advanceStateStrict(action, constitution, state, now)
            if (adv["ok"] != true) return refuse(state, action, contract, "state", verdict, "advance failed: " + adv["reason"])
            val advState = Prohibitions.obj(adv["state"])
            val latched = LinkedHashMap(Prohibitions.obj(advState["latched"]))
            val deadlines = LinkedHashMap(if (Prohibitions.obj(state)["deadlines"] is Map<*, *>) Prohibitions.obj(Prohibitions.obj(state)["deadlines"]) else LinkedHashMap<String, Any?>())
            SafeRegex.withBudget {
                if (c["clauses"] is List<*>) {
                    for (clO in Prohibitions.arr(c["clauses"])) {
                        val t = evalClause(Prohibitions.obj(clO), Prohibitions.obj(action), Prohibitions.obj(state), now)
                        for ((k, v) in Prohibitions.obj(t["latchSet"])) if (!latched.containsKey(k)) latched[k] = v
                        for ((k, v) in Prohibitions.obj(t["deadlineSet"])) {
                            if (v == null) deadlines.remove(k) else deadlines[k] = v
                        }
                    }
                }
            }
            val next = LinkedHashMap(advState)
            next["latched"] = latched
            if (deadlines.isNotEmpty()) next["deadlines"] = deadlines
            val sp = Prohibitions.stateProblem(next)
            if (sp != null) return refuse(state, action, contract, "state", verdict, "resulting state invalid: $sp")
            val out = LinkedHashMap(verdict)
            out["next"] = next
            out["decidedBy"] = "none"
            return out
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return refuse(state, action, contract, "state", null, "advance error (fail closed)")
        }
    }

    /** `allow = permitted AND contract.ok`; on allow the state advances. The contract monitor runs unconditionally. */
    @JvmOverloads
    fun checkAndAdvanceContract(permitted: Boolean, state: Any?, action: Any?, contract: Any?, nowOpt: Any? = null, expectedSeq: Any? = null, expectedStateDigest: String? = null): Map<String, Any?> {
        val adv = advanceContract(state, action, contract, nowOpt, expectedSeq, expectedStateDigest)
        if (adv["ok"] != true) {
            val out = LinkedHashMap(adv)
            out["allow"] = false
            out["permitted"] = permitted
            return out
        }
        if (!permitted) {
            val reasons = ArrayList(Prohibitions.arr(adv["reasons"]))
            reasons.add("<permission>: not permitted")
            return Prohibitions.map(
                "ok", false, "violated", adv["violated"], "reasons", reasons, "evaluated", adv["evaluated"], "next", state,
                "decidedBy", "contract", "allow", false, "permitted", false,
            )
        }
        val out = LinkedHashMap(adv)
        out["allow"] = true
        out["permitted"] = true
        return out
    }
}
