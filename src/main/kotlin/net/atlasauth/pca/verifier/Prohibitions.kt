package net.atlasauth.pca.verifier

/**
 * The prohibition engine (packages/pca/src/prohibitions.ts): a signed constitution of invariants (never, never_unless, cap, rate,
 * never_after, require_prior, require_approval_over) checked against every action, over a canonical, hash-chained monitor state,
 * with per-action safety evidence. The veto trigger (`whenMatches`) is [ForbidWins.whenMatches]. Everything is pure and total:
 * anything malformed, unknown or unresolvable fails closed and nothing here throws. Values are JSON trees ([Json.Num] numbers);
 * the JavaScript semantics the reference relies on are kept (a missing property reads as undefined, `String(null)` is `"null"`,
 * lengths count UTF-16 units).
 */
@Suppress("UNCHECKED_CAST")
object Prohibitions {
    const val CONSTITUTION_VERSION = 1
    const val CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\u0000"
    const val EVIDENCE_VERSION = 1
    const val STATE_DIGEST_DOMAIN = "atlas-pca/monitor-state/v1"
    const val STATE_CHAIN_DOMAIN = "atlas-pca/monitor-state-link/v1"
    const val MAX_LEDGER = 10_000
    const val MAX_INVARIANTS = 256
    const val MAX_DEADLINE = 1_000_000
    internal const val MAX_STATE_ENTRIES = 100_000
    internal const val MAX_STATE_KEYS = 1024
    internal const val MAX_ID_LEN = 128
    internal val FORBIDDEN_IDS = setOf("__proto__", "constructor", "prototype")
    const val UNHASHABLE = "<unhashable>"
    const val SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\u0000"

    /** An absent property (JavaScript `undefined`), distinct from a JSON null. */
    internal val UNDEF = Any()

    // ---- JavaScript-flavoured helpers

    internal fun isObj(o: Any?): Boolean = o is Map<*, *>
    internal fun obj(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    internal fun arr(o: Any?): List<Any?> = o as List<Any?>
    internal fun fin(o: Any?): Boolean = Risk.fin(o) != null
    internal fun dv(o: Any?): Double = Risk.fin(o)!!

    /** `Number.isInteger`. */
    internal fun isInteger(o: Any?): Boolean = Risk.fin(o)?.let { it == Math.floor(it) } ?: false

    internal fun negZero(o: Any?): Boolean = Risk.fin(o)?.let { it == 0.0 && 1 / it < 0 } ?: false

    internal fun jn(d: Double): Json.Num = Json.Num(AttestUtil.jsNumString(d))

    /** `o.k`: undefined on a non-object. */
    internal fun prop(o: Any?, k: String): Any? = if (o is Map<*, *> && o.containsKey(k)) o[k] else UNDEF

    internal fun get(m: Map<String, Any?>, k: String): Any? = if (m.containsKey(k)) m[k] else UNDEF

    /** JavaScript `String(x)`; [UNDEF] reads `"undefined"`. */
    internal fun text(v: Any?): String = if (v === UNDEF) "undefined" else IntentRevocation.jsText(v, true)

    internal fun truthy(v: Any?): Boolean = v !== UNDEF && IntentRevocation.truthy(v)

    internal fun map(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    internal fun domainMessage(domain: String, id: String): ByteArray =
        Pca.concat(domain.toByteArray(Charsets.UTF_8), AttestUtil.sha256(id.toByteArray(Charsets.UTF_8)))

    internal fun safe(f: () -> String): String = try {
        f()
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        UNHASHABLE
    }

    // ---- constitution

    /** Genesis monitor state at time `now`: empty ledger, no latches, seq 0, no parent. */
    fun emptyState(now: Any?): Map<String, Any?> =
        map("now", now, "seq", jn(0.0), "parent", null, "ledger", LinkedHashMap<String, Any?>(), "latched", LinkedHashMap<String, Any?>())

    internal fun body(c: Map<String, Any?>): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for ((k, v) in c) if (k != "id" && k != "sig") b[k] = v
        return b
    }

    fun constitutionId(c: Map<String, Any?>): String = Pca.hashCanonical(body(c))

    private fun actionPath(v: Any?): Boolean = v is String && v.startsWith("action.")

    private fun validateConditions(cs: Any?, label: String): String? {
        if (cs !is List<*> || cs.isEmpty()) return "$label must be a non-empty array"
        for (c in cs) ForbidWins.validateCondition(c, 0)?.let { return it }
        return null
    }

    private fun one(s: String): List<String> = arrayListOf(s)

    /** Structural problems with an invariant (empty = well formed). */
    fun validateInvariant(invO: Any?): List<String> {
        if (!isObj(invO)) return one("invariant not an object")
        val inv = obj(invO)
        val rawId = inv["id"]
        if (rawId !is String || rawId.isEmpty()) return one("<no id>: missing id")
        val id: String = rawId
        if (id.length > MAX_ID_LEN) return one("$id: id too long")
        if (id in FORBIDDEN_IDS) return one("$id: forbidden id")
        val kind = get(inv, "kind")
        var e: String?
        when (kind) {
            "never" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                return if (e != null) one("$id: $e") else ArrayList()
            }
            "never_unless" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                if (e == null) e = validateConditions(inv["unless"], "unless")
                return if (e != null) one("$id: $e") else ArrayList()
            }
            "cap" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                if (e != null) return one("$id: $e")
                if (!actionPath(inv["amount"])) return one("$id: amount must be an action.* path")
                if (!fin(inv["max"]) || dv(inv["max"]) < 0) return one("$id: max must be a finite number >= 0")
                if (inv.containsKey("window_secs") && (!fin(inv["window_secs"]) || dv(inv["window_secs"]) <= 0)) return one("$id: bad window_secs")
                return ArrayList()
            }
            "rate" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                if (e != null) return one("$id: $e")
                val m = inv["max"]
                if (!isInteger(m) || dv(m) < 0 || negZero(m) || dv(m) > MAX_LEDGER) return one("$id: max must be an integer in [0,10000]")
                if (!fin(inv["window_secs"]) || dv(inv["window_secs"]) <= 0) return one("$id: window_secs must be > 0")
                return ArrayList()
            }
            "never_after" -> {
                e = ForbidWins.validateWhen(inv["after"], "after")
                if (e == null) e = ForbidWins.validateWhen(inv["forbid"], "forbid")
                return if (e != null) one("$id: $e") else ArrayList()
            }
            "require_prior" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                if (e == null) e = ForbidWins.validateWhen(inv["prior"], "prior")
                return if (e != null) one("$id: $e") else ArrayList()
            }
            "require_approval_over" -> {
                e = ForbidWins.validateWhen(inv["when"], "when")
                if (e != null) return one("$id: $e")
                if (!actionPath(inv["amount"])) return one("$id: amount must be an action.* path")
                if (!fin(inv["threshold"]) || dv(inv["threshold"]) < 0) return one("$id: threshold must be a finite number >= 0")
                e = validateConditions(inv["approved"], "approved")
                return if (e != null) one("$id: $e") else ArrayList()
            }
        }
        return one("$id: unknown invariant kind ${text(kind)}")
    }

    /** Structural problems with a constitution (empty = well formed). */
    fun validateConstitution(cO: Any?): List<String> {
        if (!isObj(cO)) return one("constitution not an object")
        val c = obj(cO)
        val out = ArrayList<String>()
        val version = c["version"]
        if (!(fin(version) && dv(version) == CONSTITUTION_VERSION.toDouble())) out.add("unsupported version " + text(get(c, "version")))
        if (c["principal"] !is String || (c["principal"] as String).isEmpty()) out.add("principal missing")
        val invs = c["invariants"]
        if (invs !is List<*>) {
            out.add("invariants not an array")
            return out
        }
        if (invs.size > MAX_INVARIANTS) out.add("too many invariants")
        val seen = HashSet<String>()
        for (inv in invs) {
            out.addAll(validateInvariant(inv))
            val id = if (isObj(inv)) obj(inv)["id"] else null
            if (id is String) {
                if (!seen.add(id)) out.add("$id: duplicate id")
            }
        }
        return out
    }

    /** Well formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Null when it verifies, else the reason. Never throws. */
    fun verifyConstitution(sc: Any?, expectedPrincipal: String?): String? = try {
        verifyConstitutionInner(sc, expectedPrincipal)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "verification error (fail closed)"
    }

    private fun verifyConstitutionInner(sc: Any?, expectedPrincipal: String?): String? {
        val problems = validateConstitution(sc)
        if (problems.isNotEmpty()) return problems[0]
        val c = obj(sc)
        if (expectedPrincipal != null && expectedPrincipal != c["principal"]) return "principal mismatch"
        val cid = c["id"]
        if (cid !is String || cid != constitutionId(c)) return "id does not match content"
        val sig = c["sig"]
        if (sig !is String || !IntentJs.verifyEd(c["principal"], domainMessage(CONSTITUTION_SIG_DOMAIN, cid), sig)) return "bad signature"
        return null
    }

    // ---- canonical monitor state

    /** The structural problem of a monitor state (null = well formed). Total. */
    fun stateProblem(stateO: Any?): String? = try {
        stateProblemInner(stateO)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "malformed monitor state"
    }

    private fun stateProblemInner(stateO: Any?): String? {
        if (!isObj(stateO)) return "malformed monitor state"
        val state = obj(stateO)
        if (!fin(state["now"]) || !isObj(state["ledger"]) || !isObj(state["latched"])) return "malformed monitor state"
        val seq = state["seq"]
        if (!isInteger(seq) || dv(seq) < 0 || negZero(seq)) return "malformed monitor state: seq"
        val parent = get(state, "parent")
        if (parent != null && parent !is String) return "malformed monitor state: parent"
        if (dv(seq) == 0.0 && parent != null) return "malformed monitor state: genesis has a parent"
        if (dv(seq) > 0 && parent == null) return "malformed monitor state: missing chain link"
        val now = dv(state["now"])
        val ledger = obj(state["ledger"])
        val latched = obj(state["latched"])
        if (ledger.size > MAX_STATE_KEYS || latched.size > MAX_STATE_KEYS) return "malformed monitor state: too many keys"
        var total = 0L
        for ((k, v) in ledger) {
            if (k in FORBIDDEN_IDS || k.length > MAX_ID_LEN) return "malformed monitor state: bad ledger key"
            if (v !is List<*> || v.size > MAX_LEDGER) return "malformed monitor state: bad ledger"
            total += v.size
            for (e in v) {
                if (!isObj(e) || !fin(obj(e)["t"]) || !fin(obj(e)["amount"]) || dv(obj(e)["amount"]) < 0) return "malformed monitor state: bad ledger entry"
                // an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
                if (dv(obj(e)["t"]) > now) return "malformed monitor state: ledger entry after now (clock regression)"
            }
        }
        if (total > MAX_STATE_ENTRIES) return "malformed monitor state: too many entries"
        for ((k, v) in latched) {
            if (k in FORBIDDEN_IDS || k.length > MAX_ID_LEN) return "malformed monitor state: bad latch key"
            if (!fin(v) || dv(v) > now) return "malformed monitor state: bad latch"
        }
        if (state.containsKey("deadlines")) {
            val dl = state["deadlines"]
            if (!isObj(dl)) return "malformed monitor state: deadlines"
            if (obj(dl).size > MAX_STATE_KEYS) return "malformed monitor state: too many deadline keys"
            for ((k, d) in obj(dl)) {
                if (k in FORBIDDEN_IDS || k.length > MAX_ID_LEN) return "malformed monitor state: bad deadline key"
                if (!isInteger(d) || dv(d) < 1 || dv(d) > MAX_DEADLINE) return "malformed monitor state: bad deadline"
            }
        }
        return null
    }

    private fun cmpEntry(a: Map<String, Any?>, b: Map<String, Any?>): Int {
        val c = java.lang.Double.compare(dv(a["t"]), dv(b["t"]))
        return if (c != 0) c else java.lang.Double.compare(dv(a["amount"]), dv(b["amount"]))
    }

    /** Canonical form of a state: unknown fields dropped, ledger entries reduced to {t, amount} and sorted, empty ledger arrays omitted. Throws on a malformed state. */
    fun canonicalState(stateO: Any?): Map<String, Any?> {
        stateProblem(stateO)?.let { throw IllegalArgumentException(it) }
        val state = obj(stateO)
        val ledger = LinkedHashMap<String, Any?>()
        for ((k, v) in obj(state["ledger"])) {
            val l = arr(v).map { map("t", obj(it)["t"], "amount", obj(it)["amount"]) as Map<String, Any?> }.sortedWith { a, b -> cmpEntry(a, b) }
            if (l.isNotEmpty()) ledger[k] = ArrayList<Any?>(l)
        }
        val base = map(
            "d", STATE_DIGEST_DOMAIN, "now", state["now"], "seq", state["seq"], "parent", state["parent"],
            "ledger", ledger, "latched", LinkedHashMap(obj(state["latched"])),
        )
        if (state.containsKey("deadlines")) {
            val dl = LinkedHashMap(obj(state["deadlines"]))
            if (dl.isNotEmpty()) base["deadlines"] = dl
        }
        return base
    }

    fun stateDigest(state: Any?): String = Pca.hashCanonical(canonicalState(state))

    /** The same state at a later `now`; refuses regression. `{ok, state}` or `{ok: false, reason}`. */
    fun tickState(state: Any?, now: Any?): Map<String, Any?> {
        if (stateProblem(state) != null) return map("ok", false, "reason", "malformed monitor state")
        if (!fin(now) || dv(now) < dv(obj(state)["now"])) return map("ok", false, "reason", "clock regression")
        val next = LinkedHashMap(obj(state))
        next["now"] = now
        return map("ok", true, "state", next)
    }

    // ---- the monitor

    private fun allHold(cs: Any?, ctx: Map<String, Any?>): Boolean {
        for (c in arr(cs)) if (!Predicates.evaluateCondition(c, ctx)) return false
        return true
    }

    private fun windowEntries(state: Map<String, Any?>, id: String, windowSecs: Any?): List<Map<String, Any?>> {
        val l = obj(state["ledger"])[id]
        if (l !is List<*>) return emptyList()
        val now = dv(state["now"])
        val lo = if (windowSecs == null) Double.NEGATIVE_INFINITY else now - dv(windowSecs) * 1000
        val out = ArrayList<Map<String, Any?>>()
        for (e in l) {
            val t = dv(obj(e)["t"])
            if (t > lo && t <= now) out.add(obj(e))
        }
        out.sortWith { a, b -> cmpEntry(a, b) }
        return out
    }

    private fun reasonOf(inv: Map<String, Any?>, dflt: String): String {
        val d = inv["description"]
        return if (d == null) dflt else text(d)
    }

    private fun okRes(): Map<String, Any?> = map("ok", true)

    private fun bad(reason: String): Map<String, Any?> = map("ok", false, "reason", reason)

    private fun evalOne(inv: Map<String, Any?>, ctx: Map<String, Any?>, state: Map<String, Any?>): Map<String, Any?> {
        val kind = inv["kind"] as String
        val latched = obj(state["latched"])
        when (kind) {
            "never" -> return if (ForbidWins.whenMatches(inv["when"], ctx)) bad(reasonOf(inv, "forbidden action")) else okRes()
            "never_unless" -> {
                if (!ForbidWins.whenMatches(inv["when"], ctx)) return okRes()
                return if (allHold(inv["unless"], ctx)) okRes() else bad(reasonOf(inv, "forbidden without required condition"))
            }
            "cap" -> {
                if (!ForbidWins.whenMatches(inv["when"], ctx)) return okRes()
                val a = Predicates.resolvePath(ctx, inv["amount"])
                if (!a.found || !fin(a.value) || dv(a.value) < 0) return bad("amount unresolvable (fail closed)")
                var spent = 0.0
                for (e in windowEntries(state, inv["id"] as String, inv["window_secs"])) spent += dv(e["amount"])
                val total = spent + dv(a.value)
                if (total <= dv(inv["max"])) return okRes()
                return bad("cap exceeded: " + AttestUtil.jsNumString(spent) + " + " + AttestUtil.jsNumString(dv(a.value)) + " > " + AttestUtil.jsNumString(dv(inv["max"])))
            }
            "rate" -> {
                if (!ForbidWins.whenMatches(inv["when"], ctx)) return okRes()
                val n = windowEntries(state, inv["id"] as String, inv["window_secs"]).size
                if (n + 1 <= dv(inv["max"])) return okRes()
                return bad("rate exceeded: " + (n + 1) + " > " + AttestUtil.jsNumString(dv(inv["max"])) + " per " + AttestUtil.jsNumString(dv(inv["window_secs"])) + "s")
            }
            "never_after" -> {
                if (!latched.containsKey(inv["id"] as String) || !ForbidWins.whenMatches(inv["forbid"], ctx)) return okRes()
                return bad(reasonOf(inv, "forbidden after trigger"))
            }
            "require_prior" -> {
                if (!ForbidWins.whenMatches(inv["when"], ctx)) return okRes()
                return if (latched.containsKey(inv["id"] as String)) okRes() else bad(reasonOf(inv, "required prior action not admitted"))
            }
            "require_approval_over" -> {
                if (!ForbidWins.whenMatches(inv["when"], ctx)) return okRes()
                val a = Predicates.resolvePath(ctx, inv["amount"])
                val over = !a.found || !fin(a.value) || dv(a.value) < 0 || dv(a.value) > dv(inv["threshold"])
                if (!over) return okRes()
                return if (allHold(inv["approved"], ctx)) okRes() else bad(reasonOf(inv, "approval required over " + AttestUtil.jsNumString(dv(inv["threshold"]))))
            }
            else -> throw IllegalStateException("unknown invariant kind") // unreachable after validation; the caller turns it into a fail-closed row
        }
    }

    internal fun actionOk(action: Any?): Boolean {
        val a = if (action is Map<*, *>) action["action"] else null
        return a is Map<*, *> && a["verb"] is String && a["resource"] is String
    }

    internal fun structural(id: String, reason: String): LinkedHashMap<String, Any?> {
        val row = map("id", id, "kind", "structural", "result", "violated", "reason", reason)
        return map("ok", false, "violated", arrayListOf<Any?>(id), "reasons", arrayListOf<Any?>(reason), "evaluated", arrayListOf<Any?>(row))
    }

    /** Evaluates EVERY invariant (no short-circuit) against the action and the running state. Pure, total, fail closed: `{ok, violated, reasons, evaluated}`. */
    fun checkProhibitions(action: Any?, constitution: Any?, state: Any?): Map<String, Any?> =
        SafeRegex.withBudget { checkInner(action, constitution, state) }

    private fun checkInner(action: Any?, constitution: Any?, state: Any?): Map<String, Any?> {
        try {
            val cp = validateConstitution(constitution)
            if (cp.isNotEmpty()) return structural("<constitution>", cp[0])
            if (!actionOk(action)) return structural("<action>", "malformed action")
            val sp = stateProblem(state)
            if (sp != null) return structural("<state>", sp)
            val evaluated = ArrayList<Any?>()
            for (invO in arr(obj(constitution)["invariants"])) {
                val inv = obj(invO)
                var r: Map<String, Any?>
                try {
                    r = evalOne(inv, obj(action), obj(state))
                } catch (e: Throwable) {
                    if (!Contain.ok(e)) throw e
                    r = bad("evaluation error (fail closed)")
                }
                val row = map("id", inv["id"], "kind", inv["kind"], "result", if (r["ok"] == true) "pass" else "violated")
                if (truthy(r["reason"])) row["reason"] = r["reason"]
                evaluated.add(row)
            }
            return summarize(evaluated)
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return structural("<monitor>", "monitor error (fail closed)")
        }
    }

    /** `{ok, violated, reasons, evaluated}` of a list of result rows. */
    internal fun summarize(evaluated: List<Any?>): Map<String, Any?> {
        val violated = ArrayList<Any?>()
        val reasons = ArrayList<Any?>()
        for (e in evaluated) {
            val row = obj(e)
            if (row["result"] != "violated") continue
            violated.add(row["id"])
            reasons.add(text(row["id"]) + ": " + (if (row.containsKey("reason")) text(row["reason"]) else "violated"))
        }
        return map("ok", violated.isEmpty(), "violated", violated, "reasons", reasons, "evaluated", evaluated)
    }

    private fun sumAmount(a: Any?, b: Any?): Any? = jn(dv(a) + dv(b))

    /** Pure state transition for an ADMITTED action: `{ok, state}` or `{ok: false, reason}`; never throws. `now` null = the state's own. */
    @JvmOverloads
    fun advanceStateStrict(action: Any?, constitution: Any?, state: Any?, now: Any? = null): Map<String, Any?> {
        val n = now ?: (if (state is Map<*, *>) state["now"] else null)
        return SafeRegex.withBudget { advanceInner(action, constitution, state, n) }
    }

    private fun advanceInner(action: Any?, constitution: Any?, state: Any?, now: Any?): Map<String, Any?> {
        try {
            val cp = validateConstitution(constitution)
            if (cp.isNotEmpty()) return bad(cp[0])
            val sp = stateProblem(state)
            if (sp != null) return bad(sp)
            if (!fin(now) || dv(now) < dv(obj(state)["now"])) return bad("clock regression")
            if (!actionOk(action)) return bad("malformed action")
            val canon = canonicalState(state)
            val prevDigest = Pca.hashCanonical(canon)
            val actionDigest = Pca.hashCanonical(action)
            val ledger = LinkedHashMap<String, Any?>()
            for ((k, v) in obj(canon["ledger"])) ledger[k] = ArrayList(arr(v))
            val latched = LinkedHashMap(obj(canon["latched"]))
            for (invO in arr(obj(constitution)["invariants"])) {
                val inv = obj(invO)
                val kind = inv["kind"] as String
                val id = inv["id"] as String
                if (kind == "cap" || kind == "rate") {
                    val prev = if (ledger.containsKey(id)) arr(ledger[id]) else emptyList()
                    val lo = if (inv["window_secs"] == null) Double.NEGATIVE_INFINITY else dv(now) - dv(inv["window_secs"]) * 1000
                    val kept = ArrayList<Map<String, Any?>>()
                    for (e in prev) if (dv(obj(e)["t"]) > lo) kept.add(obj(e))
                    if (ForbidWins.whenMatches(inv["when"], obj(action))) {
                        var amount: Any? = jn(1.0)
                        if (kind == "cap") {
                            val r = Predicates.resolvePath(obj(action), inv["amount"])
                            if (!r.found || !fin(r.value) || dv(r.value) < 0) return bad("$id: amount unresolvable")
                            amount = r.value
                        }
                        kept.add(map("t", now, "amount", amount))
                    }
                    kept.sortWith { a, b -> cmpEntry(a, b) }
                    if (kept.size > MAX_LEDGER) {
                        if (kind == "rate") return bad("$id: rate ledger overflow")
                        while (kept.size > MAX_LEDGER) {
                            val x = kept[0]
                            val y = kept[1] // merge the oldest two; keeps the LATER time => never under-counts a cap
                            kept.subList(0, 2).clear()
                            kept.add(0, map("t", y["t"], "amount", sumAmount(x["amount"], y["amount"])))
                        }
                    }
                    if (kept.isNotEmpty()) ledger[id] = ArrayList<Any?>(kept) else ledger.remove(id)
                } else if (kind == "never_after") {
                    // conservative match: an ambiguous trigger latches (stricter)
                    if (!latched.containsKey(id) && ForbidWins.whenMatches(inv["after"], obj(action))) latched[id] = now
                } else if (kind == "require_prior") {
                    // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
                    if (!latched.containsKey(id) && whenAffirmative(inv["prior"], obj(action))) latched[id] = now
                }
            }
            val next = map(
                "now", now, "seq", jn(dv(obj(state)["seq"]) + 1),
                "parent", Pca.hashCanonical(map("d", STATE_CHAIN_DOMAIN, "state", prevDigest, "action", actionDigest)), "ledger", ledger, "latched", latched,
            )
            if (stateProblem(next) != null) return bad("resulting state invalid")
            return map("ok", true, "state", next)
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return bad("advance error (fail closed)")
        }
    }

    /** Affirmative trigger match (plain permission semantics, unresolvable = not matched). */
    fun whenAffirmative(w: Any?, ctx: Map<String, Any?>?): Boolean = try {
        ForbidWins.validateWhen(w, "when") == null && Predicates.predicateMatches(w, ctx)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        false
    }

    // ---- per-action safety evidence

    /** The evidence a verifier re-checks. Never throws. */
    fun proveSafety(action: Any?, constitution: Any?, state: Any?): Map<String, Any?> =
        evidenceFrom(checkProhibitions(action, constitution, state), action, constitution, state)

    internal fun evidenceFrom(r: Map<String, Any?>, action: Any?, constitution: Any?, state: Any?): Map<String, Any?> {
        val cid = safe { constitutionId(obj(constitution)) }
        val adg = safe { Pca.hashCanonical(action) }
        val sdg = safe { stateDigest(state) }
        val extra = ArrayList<Any?>()
        if (cid == UNHASHABLE) extra.add("<constitution>")
        if (adg == UNHASHABLE) extra.add("<action>")
        if (sdg == UNHASHABLE) extra.add("<state>")
        val violated = ArrayList(arr(r["violated"]))
        for (x in extra) if (!violated.contains(x)) violated.add(x)
        val evaluated = ArrayList<Any?>()
        for (e in arr(r["evaluated"])) evaluated.add(LinkedHashMap(obj(e)))
        val now: Any? = if (state is Map<*, *> && fin(state["now"])) state["now"] else jn(0.0)
        return map(
            "v", jn(EVIDENCE_VERSION.toDouble()), "constitution", cid, "action_digest", adg, "state_digest", sdg, "now", now, "evaluated", evaluated,
            "ok", r["ok"] == true && extra.isEmpty(), "violated", violated,
        )
    }

    /** Recomputes the monitor and requires the evidence to match EXACTLY. Null when it does, else the reason. Never throws. */
    fun verifySafetyEvidence(evidence: Any?, action: Any?, constitution: Any?, state: Any?): String? = try {
        if (!isObj(evidence) || !isInteger(obj(evidence)["v"]) || dv(obj(evidence)["v"]) != EVIDENCE_VERSION.toDouble()) "unsupported evidence version"
        else {
            val ev = obj(evidence)
            val fresh = proveSafety(action, constitution, state)
            if (fresh["constitution"] != ev["constitution"]) "constitution mismatch"
            else if (fresh["action_digest"] != ev["action_digest"]) "action digest mismatch"
            else if (fresh["state_digest"] != ev["state_digest"]) "state digest mismatch"
            else if (Pca.hashCanonical(fresh) != Pca.hashCanonical(ev)) "evidence does not reproduce"
            else if (fresh["ok"] != true) "prohibition violated: " + joinIds(arr(fresh["violated"]))
            else null
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "verification error (fail closed)"
    }

    internal fun joinIds(l: List<Any?>): String = l.joinToString(",") { text(it) }

    /** The id the signer commits to: a hash of the evidence and the three digests it binds. */
    fun safetyBindingId(evidence: Map<String, Any?>, signer: String): String = Pca.hashCanonical(
        map(
            "d", SAFETY_EVIDENCE_SIG_DOMAIN, "signer", signer, "evidence", Pca.hashCanonical(evidence),
            "constitution", evidence["constitution"], "action_digest", evidence["action_digest"], "state_digest", evidence["state_digest"],
        ),
    )

    /** Signs evidence (it must be bound to real digests). Throws [IllegalArgumentException] otherwise. */
    fun signSafetyEvidence(evidence: Any?, signerSeed: ByteArray, signerPublic: String?): Map<String, Any?> {
        if (!isObj(evidence) || !isInteger(obj(evidence)["v"]) || dv(obj(evidence)["v"]) != EVIDENCE_VERSION.toDouble()) throw IllegalArgumentException("signSafetyEvidence: unsupported evidence")
        val ev = obj(evidence)
        for (k in listOf("constitution", "action_digest", "state_digest")) {
            val d = ev[k]
            if (d !is String || d.isEmpty() || d == UNHASHABLE) throw IllegalArgumentException("signSafetyEvidence: unbound evidence")
        }
        if (signerPublic == null || signerPublic.isEmpty()) throw IllegalArgumentException("signSafetyEvidence: signer missing")
        val id = safetyBindingId(ev, signerPublic)
        return map("evidence", ev, "signer", signerPublic, "id", id, "sig", Pca.b64(Keys.edFromSeed(signerSeed).sign(domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, id))))
    }

    /** JavaScript `Array.prototype.join(',')`: null and undefined read as the empty string. */
    private fun jsJoin(l: List<Any?>): String = l.joinToString(",") { if (it == null) "" else text(it) }

    /**
     * Verifies signed evidence offline: the signer pinned, the binding id, the signature, the bound digests, internal consistency and
     * (when action, constitution and state are all given) a full recomputation. `expected` carries `signer` (a key or a list),
     * `action` or `actionDigest`, `constitution` or `constitutionId`, `state` or `stateDigest`, optional `principal` and `requireOk`.
     * Null when it verifies, else the exact reason. Reads properties with JavaScript semantics and never throws.
     */
    fun verifySignedSafetyEvidence(signedO: Any?, expectedO: Any?): String? = try {
        verifySignedInner(signedO, expectedO)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "verification error (fail closed)"
    }

    private fun verifySignedInner(signedO: Any?, expectedO: Any?): String? {
        if (!isObj(signedO) || !isObj(obj(signedO)["evidence"]) || !isObj(expectedO)) return "malformed input"
        val signed = obj(signedO)
        val expected = obj(expectedO)
        val ev = obj(signed["evidence"])
        if (!isInteger(ev["v"]) || dv(ev["v"]) != EVIDENCE_VERSION.toDouble()) return "unsupported evidence version"
        val signers: List<Any?> = if (expected["signer"] is List<*>) arr(expected["signer"]) else listOf(get(expected, "signer"))
        var badSigner = signers.isEmpty()
        for (sg in signers) if (sg !is String || sg.isEmpty()) badSigner = true
        if (badSigner) return "no pinned signer"
        val signedSigner = signed["signer"]
        if (signedSigner !is String || !signers.contains(signedSigner)) return "signer not trusted"
        val hasAction = expected.containsKey("action")
        val hasConst = expected.containsKey("constitution")
        val hasState = expected.containsKey("state")
        if (!hasAction && !expected.containsKey("actionDigest")) return "unbound: action not specified"
        if (!hasConst && !expected.containsKey("constitutionId")) return "unbound: constitution not specified"
        if (!hasState && !expected.containsKey("stateDigest")) return "unbound: state not specified"
        val sid = signed["id"]
        if (sid !is String || sid != safetyBindingId(ev, signedSigner)) return "binding id mismatch"
        val sig = signed["sig"]
        if (sig !is String || !IntentJs.verifyEd(signedSigner, domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, sid), sig)) return "bad signature"

        val wantAction: Any? = if (hasAction) Pca.hashCanonical(expected["action"]) else expected["actionDigest"]
        if (hasAction && expected.containsKey("actionDigest") && expected["actionDigest"] != wantAction) return "expected action and digest disagree"
        if (ev["action_digest"] != wantAction) return "action digest mismatch (evidence bound to another action)"

        if (expected.containsKey("principal")) {
            val sc = expected["constitution"]
            if (!isObj(sc) || obj(sc)["sig"] !is String) return "principal pin requires a signed constitution"
            val vc = verifyConstitution(sc, expected["principal"] as? String ?: "\u0000no-principal")
            if (vc != null) return "constitution not authentic: $vc"
        }
        val wantConst: Any? = if (hasConst) constitutionId(obj(expected["constitution"])) else expected["constitutionId"]
        if (hasConst && expected.containsKey("constitutionId") && expected["constitutionId"] != wantConst) return "expected constitution and id disagree"
        if (ev["constitution"] != wantConst) return "constitution mismatch (evidence bound to another constitution)"
        // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row (undefined === undefined)
        if (hasConst) {
            val cp = validateConstitution(expected["constitution"])
            if (cp.isNotEmpty()) return "constitution malformed: " + cp[0]
        }

        val wantState: Any? = if (hasState) stateDigest(expected["state"]) else expected["stateDigest"]
        if (hasState && expected.containsKey("stateDigest") && expected["stateDigest"] != wantState) return "expected state and digest disagree"
        if (ev["state_digest"] != wantState) return "state digest mismatch (evidence bound to another state)"

        // internal consistency: the claimed verdict must follow from the claimed rows
        if (ev["evaluated"] !is List<*> || ev["violated"] !is List<*>) return "malformed evidence"
        val rows = arr(ev["evaluated"])
        val violated = arr(ev["violated"])
        for (r in rows) if (isObj(r) && obj(r).containsKey("id") && obj(r)["id"] !is String) return "malformed evidence"
        var badRows = 0
        for (r in rows) if (!(isObj(r) && obj(r)["result"] == "pass")) badRows++
        if ((badRows == 0 && violated.isEmpty()) != ev["ok"]) return "evidence verdict inconsistent with rows"

        if (hasAction && hasConst && hasState) {
            val full = verifySafetyEvidence(ev, expected["action"], expected["constitution"], expected["state"])
            if (full != null && ev["ok"] == true) return full
            if (full != null && ev["ok"] != true && !full.startsWith("prohibition violated")) return full
        } else if (ev["ok"] == true && hasConst) {
            val ids = arr(obj(expected["constitution"])["invariants"]).map { prop(it, "id") }
            var covered = rows.size == ids.size
            var i = 0
            while (covered && i < rows.size) {
                if (rows[i] == null) throw IllegalStateException("cannot read properties of null")
                if (prop(rows[i], "id") != ids[i]) covered = false
                i++
            }
            if (!covered) return "evidence does not cover every invariant"
        }
        if (expected["requireOk"] != false && ev["ok"] != true) return "prohibition violated: " + jsJoin(violated)
        return null
    }

    // ---- composition: permissions grant, prohibitions veto

    /** The pure kernel of the server's critical section: CAS guards, compose, evidence over the pre-state, next state on allow. `expectedSeq` / `expectedStateDigest` are nullable. */
    @JvmOverloads
    fun checkAndAdvance(permitted: Boolean, action: Any?, constitution: Any?, state: Any?, expectedSeq: Any? = null, expectedStateDigest: String? = null): Map<String, Any?> {
        val monitored = checkProhibitions(action, constitution, state)
        val evidence = evidenceFrom(monitored, action, constitution, state)
        val ok = monitored["ok"] == true
        val allow = permitted && ok
        val decidedBy = if (!ok) "prohibition" else if (permitted) "none" else "permission"
        try {
            if (expectedSeq != null && (!isObj(state) || !jsonNumEq(obj(state)["seq"], expectedSeq))) return refuse(state, evidence, monitored, "state", "stale state head (seq)")
            if (expectedStateDigest != null && expectedStateDigest != safe { stateDigest(state) }) return refuse(state, evidence, monitored, "state", "stale state head (digest)")
            if (!allow) return refuse(state, evidence, monitored, if (decidedBy == "none") "permission" else decidedBy, null)
            if (evidence["ok"] != true) return refuse(state, evidence, monitored, "prohibition", "evidence not attestable")
            val adv = advanceStateStrict(action, constitution, state, null)
            if (adv["ok"] != true) return refuse(state, evidence, monitored, "state", "advance failed: " + adv["reason"])
            return map("allow", true, "decidedBy", "none", "evidence", evidence, "prohibition", monitored, "next", adv["state"])
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return refuse(state, evidence, monitored, "state", "check-and-advance error (fail closed)")
        }
    }

    private fun jsonNumEq(a: Any?, b: Any?): Boolean {
        val x = Risk.fin(a)
        val y = Risk.fin(b)
        return x != null && y != null && x == y
    }

    private fun refuse(state: Any?, evidence: Map<String, Any?>, monitored: Map<String, Any?>, decidedBy: String, reason: String?): Map<String, Any?> {
        val out = map("allow", false, "decidedBy", decidedBy, "evidence", evidence, "prohibition", monitored, "next", state)
        if (!reason.isNullOrEmpty()) out["reason"] = reason
        return out
    }
}
