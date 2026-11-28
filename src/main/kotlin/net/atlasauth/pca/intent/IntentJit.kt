package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleFacts
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.SignersMore

/**
 * Lazy just-in-time elicitation: the ordered decision for a visited cell (schema violation, ceiling, intent denied, admit, intent required),
 * the cell coordinates of an `intent_required` question, the wallet's check of one, and the delta grant minted from an answer.
 */
@Suppress("UNCHECKED_CAST")
object IntentJit {
    const val INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"

    private fun lm() = LinkedHashMap<String, Any?>()

    private fun verbOf(o: Omega, verb: String): VerbSpace? = o.verbs.firstOrNull { it.verb == verb }

    private fun ints(a: IntArray): List<Any?> = a.map { it.toDouble() }

    private fun jsStr(o: Any?): String {
        if (o == null) return "undefined"
        if (IntentOmega.isNumber(o)) return AttestUtil.jsNumString(IntentOmega.dbl(o))
        return o.toString()
    }

    /**
     * The ordered decision of a visit. `conform`: {ok, code?, reason?} (the schema conformance of the plaintext action); `ceilings`: each must
     * admit the lifted outcome (a deny anywhere wins); `inEffective`: is the cell in the effective grant. Returns {kind, ...}.
     */
    @JvmStatic
    fun decideVisit(learner: IntentLearner, lifted: Outcome, conform: Map<String, Any?>, ceilings: List<(VerbSpace, Outcome) -> Boolean>?, inEffective: Boolean): Map<String, Any?> {
        val r = lm()
        if (conform["ok"] != true) {
            r["kind"] = "schema_violation"
            r["reason"] = jsStr(conform["code"]) + ": " + jsStr(conform["reason"])
            return r
        }
        val vs = verbOf(learner.omega, lifted.verb)
        val cell = if (vs == null) null else IntentOmega.cellOf(vs, lifted)
        if (vs == null || cell == null) {
            r["kind"] = "schema_violation"
            r["reason"] = "the lifted action lies outside Ω̃"
            return r
        }
        if (ceilings != null) for (c in ceilings) if (!c(vs, lifted)) { r["kind"] = "ceiling"; return r }
        val vetoed = learner.isVetoed(lifted)
        val p = learner.acceptance(lifted)
        if (vetoed || p <= 0) { r["kind"] = "intent_denied"; r["vetoed"] = vetoed; return r }
        if (inEffective) { r["kind"] = "admit"; r["cell"] = ints(cell); return r }
        r["kind"] = "intent_required"
        r["cell"] = ints(cell)
        r["p"] = p
        return r
    }

    /** The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). */
    @JvmStatic
    fun cellCoords(vs: VerbSpace, cell: IntArray): Map<String, Any?> {
        val out = lm()
        for (k in vs.dims.indices) {
            val d = vs.dims[k]
            val c = ArrayList<Any?>()
            if (d is NumDim) { c.add(cell[k].toDouble()); c.add(cell[k].toDouble()) }
            else c.add((d as CatDim).values[cell[k]].value)
            out[d.path] = c
        }
        return out
    }

    /** Coordinates to per-dimension cell indices (the inverse of [cellCoords] for one cell), or null. */
    @JvmStatic
    fun cellFromCoords(vs: VerbSpace, coords: Map<String, Any?>): DoubleArray? {
        if (coords.size != vs.dims.size) return null
        val out = DoubleArray(vs.dims.size)
        for (k in out.indices) {
            val d = vs.dims[k]
            if (!coords.containsKey(d.path) || coords[d.path] !is List<*>) return null
            val c = coords[d.path] as List<Any?>
            if (d is NumDim) {
                if (c.isEmpty() || !IntentOmega.isNumber(c[0]) || c.size < 2 || !IntentOmega.isNumber(c[1]) || IntentOmega.dbl(c[0]) != IntentOmega.dbl(c[1])) return null
                out[k] = IntentOmega.dbl(c[0])
            } else {
                if (c.size != 1 || c[0] !is String) return null
                var i = -1
                val vals = (d as CatDim).values
                for (j in vals.indices) if (vals[j].value == c[0]) { i = j; break }
                if (i < 0) return null
                out[k] = i.toDouble()
            }
        }
        return out
    }

    /** `intentActionDigest`: the content address of the action an intent_required question is about. */
    @JvmStatic
    fun intentActionDigest(action: Any?): String {
        val a = action as Map<*, *>
        val act = lm()
        for (k in listOf("verb", "resource", "params_digest", "reversibility_class")) act[k] = a[k]
        val m = lm()
        m["d"] = INTENT_ACTION_DOMAIN
        m["action"] = act
        return Pca.hashCanonical(IntentJs.normalize(m))
    }

    /**
     * The site's `pca-intent-required` body for a visited uncertain cell. `in`: session, mapDigest, schemaDigest, pcactn (JSON), questionId,
     * friction, deliveredTo, expiresAt; `vs` and `cell` locate the cell.
     */
    @JvmStatic
    fun intentRequiredBody(inp: Map<String, Any?>, vs: VerbSpace, cell: IntArray): Map<String, Any?> {
        val pcactn = IntentOmega.obj(inp["pcactn"])
        val b = lm()
        b["v"] = 1L
        b["kind"] = "pca-intent-required"
        b["session"] = inp["session"]
        b["map_digest"] = inp["mapDigest"]
        b["schema"] = inp["schemaDigest"]
        b["pcactn_digest"] = Pca.hashCanonical(IntentJs.normalize(pcactn))
        b["action_digest"] = intentActionDigest(pcactn["action"])
        val c = lm()
        c["verb"] = vs.verb
        c["coords"] = IntentJs.normalize(cellCoords(vs, cell)) // numbers as JSON numbers, which the signer canonicalizes
        b["cell"] = c
        b["reason"] = "uncertain"
        b["question_id"] = inp["questionId"]
        b["friction"] = inp["friction"]
        b["delivered_to"] = inp["deliveredTo"]
        b["expires_at"] = inp["expiresAt"]
        return b
    }

    @JvmStatic
    fun signedIntentRequired(inp: Map<String, Any?>, vs: VerbSpace, cell: IntArray, kid: String, site: Keys.SuiteKey): Map<String, Any?> =
        SignersMore.signIntentRequired(intentRequiredBody(inp, vs, cell), kid, site)

    private fun fail(reason: String): Map<String, Any?> {
        val r = lm()
        r["ok"] = false
        r["reason"] = reason
        return r
    }

    // ---- the verification of a site-signed intent_required body (the wallet bridge) ----

    private val BODY_KEYS = listOf("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig")
    private val QID = Regex("[A-Za-z0-9_-]{1,64}")

    private fun signedShapeError(bO: Any?): String? {
        if (bO !is Map<*, *>) return "not an object"
        for (k in bO.keys) if (k !in BODY_KEYS) return "unknown member '$k'"
        if (!OracleFacts.isOne(bO["v"]) || "pca-intent-required" != bO["kind"]) return "not a pca-intent-required v1"
        for (k in listOf("session", "map_digest", "schema", "pcactn_digest", "action_digest")) if (!IntentJs.b32(bO[k])) return "$k must be canonical base64url (32 bytes)"
        val cell = bO["cell"]
        if (cell !is Map<*, *> || cell.size != 2 || !cell.containsKey("coords") || cell["verb"] !is String || (cell["verb"] as String).isEmpty()) return "cell must be {verb, coords}"
        val ce = SignersMore.cellCoordsError(cell["coords"])
        if (ce != null) return ce
        if ("uncertain" != bO["reason"]) return "reason must be 'uncertain'"
        if (bO["question_id"] !is String || !QID.matches(bO["question_id"] as String)) return "question_id must match [A-Za-z0-9_-]{1,64}"
        if (bO["friction"] !in listOf("tap", "hold", "typed", "device")) return "unknown friction tier"
        if ("wallet" != bO["delivered_to"] && "agent" != bO["delivered_to"]) return "delivered_to must be 'wallet' or 'agent'"
        if (!IntentJs.isNonNeg(bO["expires_at"])) return "expires_at must be a non-negative safe integer"
        val s = bO["sig"]
        if (s is Map<*, *>) {
            val se = IntentJs.suiteError(s["alg"], s.containsKey("alg"))
            if (se != null) return "sig.alg: $se"
            if (s.containsKey("pq_value") && s["pq_value"] != null && s["pq_value"] !is String) return "sig.pq_value must be a string"
        }
        var okSig = s is Map<*, *>
        if (s is Map<*, *>) {
            for (k in s.keys) if (k !in listOf("alg", "kid", "value", "pq_value")) okSig = false
            if (Pq.resolveSigAlg(s["alg"], s.containsKey("alg")) == null || s["kid"] !is String || s["value"] !is String) okSig = false
        }
        if (!okSig) return "sig must be {alg, kid, value, pq_value?}"
        return null
    }

    /** Verify a site-signed intent_required body against the site's discovery keys at [now]: null when valid, else the reason. */
    private fun verifyIntentRequired(b: Any?, keys: Any?, now: Any?): String? {
        try {
            if (!IntentJs.isSafeInteger(now)) return "the verifier clock is not a safe integer (fail closed)"
            val e = signedShapeError(b)
            if (e != null) return e
            val s = b as Map<String, Any?>
            val sig = s["sig"] as Map<String, Any?>
            if (keys !is List<*>) return "the site keys must be an array"
            var key: Map<String, Any?>? = null
            for (k in keys) if (k is Map<*, *> && sig["kid"] == k["kid"]) { key = k as Map<String, Any?>; break }
            if (key == null) return "no site key with kid '${sig["kid"]}'"
            val kse = IntentJs.suiteError(key["alg"], key.containsKey("alg"))
            if (kse != null) return "site key: $kse"
            val ka = IntentJs.suiteOf(key)
            val sa = IntentJs.suiteOf(sig)
            if (ka == null || ka != sa) return "sig.alg does not match the pinned key suite"
            val pk = key["pk"] as String?
            val pin = if (key.containsKey("pq_pk") && key["pq_pk"] != null) IntentJs.pin(pk as String, key["pq_pk"]) else null
            val body = LinkedHashMap(s)
            body.remove("sig")
            val msg = IntentJs.message(SignersMore.INTENT_REQUIRED_DOMAIN, body)
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key["pq_pk"], msg, sig["value"], sig["pq_value"], pin)) return "site signature invalid"
            if (!(IntentJs.num(now)!! <= IntentJs.num(s["expires_at"])!!)) return "the question has expired"
            return null
        } catch (err: RuntimeException) {
            return "malformed intent_required: " + err.message
        }
    }

    /**
     * The wallet's check of an `intent_required`: the site signature under its discovery keys, the expiry, the session and map, and the CELL,
     * re-derived from the wallet's own space and the lifted action. Returns {ok: true, vs, cell} or {ok: false, reason}.
     */
    @JvmStatic
    fun walletCheckIntentRequired(body: Any?, keys: List<Any?>, now: Long, session: String, mapDigest: String, omegaTilde: Omega, lifted: Outcome, pcactn: Map<String, Any?>): Map<String, Any?> {
        val v = verifyIntentRequired(body, keys, now)
        if (v != null) return fail(v)
        val b = body as Map<*, *>
        if (session != b["session"] || mapDigest != b["map_digest"]) return fail("the question is for another session or map")
        if (Pca.hashCanonical(IntentJs.normalize(pcactn)) != b["pcactn_digest"] || intentActionDigest(pcactn["action"]) != b["action_digest"]) return fail("the question is about another action")
        val vs = verbOf(omegaTilde, lifted.verb)
        val mine = if (vs == null) null else IntentOmega.cellOf(vs, lifted)
        val bc = b["cell"] as Map<*, *>
        if (vs == null || mine == null || vs.verb != bc["verb"]) return fail("the wallet cannot place the action in Ω̃")
        val theirs = cellFromCoords(vs, bc["coords"] as Map<String, Any?>) ?: return fail("the site cell differs from the cell the wallet derives")
        for (k in theirs.indices) if (theirs[k] != mine[k].toDouble()) return fail("the site cell differs from the cell the wallet derives")
        val r = lm()
        r["ok"] = true
        r["vs"] = IntentOmega.verbSpaceToJson(vs)
        r["cell"] = ints(mine)
        return r
    }

    // ---- delta grants ----

    private fun join(a: IntArray): String = a.joinToString(",")

    /** Per verb, the cells the next learner's grant adds over the previous one's (both over the same space); verbs with no new cell are absent. */
    @JvmStatic
    fun deltaCells(prev: IntentLearner, next: IntentLearner): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        val prevIn = LinkedHashSet<String>()
        for (c in prev.cells()) if (c.inGrant) prevIn.add(c.verb + "|" + join(c.cell))
        val nextCells = next.cells()
        for (vs in next.omega.verbs) {
            val a = ByteArray(IntentOmega.verbCellCount(vs).toInt())
            var any = false
            for (c in nextCells) {
                if (c.verb != vs.verb || !c.inGrant || prevIn.contains(c.verb + "|" + join(c.cell))) continue
                a[IntentOmega.encodeCell(vs, c.cell).toInt()] = 1
                any = true
            }
            if (any) out[vs.verb] = a
        }
        return out
    }

    /** The predicates of a delta (one maximal box per covered region, per verb). */
    @JvmStatic
    fun deltaPredicates(omegaTilde: Omega, delta: Map<String, ByteArray>): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (vs in omegaTilde.verbs) {
            val d = delta[vs.verb] ?: continue
            out.addAll(IntentLearner.boxesToPredicates(vs, BooleanArray(d.size) { d[it].toInt() != 0 }))
        }
        return out
    }

    /**
     * Mint D_k from the k-th answer: null when the answer added no cell. `a`: holder, holderPq?, session, seq, prev?, root, mapDigest, mapForm?, caveats?,
     * agentBinding?, riskPolicy?, salt?, and `prevGrant` (the previous session grant, JSON). Returns {grant, goalSalt, cells}.
     */
    @JvmStatic
    fun mintDelta(prev: IntentLearner, next: IntentLearner, a: Map<String, Any?>, principal: Keys.SuiteKey): Map<String, Any?>? {
        val delta = deltaCells(prev, next)
        var cells = 0L
        for (v in delta.values) for (x in v) cells += x
        if (cells == 0L) return null
        val prevGrant = IntentOmega.obj(a["prevGrant"])
        if (a["prev"] != null && a["prev"] != prevGrant["id"]) throw IllegalArgumentException("mintDelta: prev must be the id of the previous session grant")
        val preds = ArrayList<Any?>(IntentJs.normalize(deltaPredicates(next.omega, delta)) as List<Any?>) // boundary values are numbers the strict canonicalizer takes as JSON numbers
        val caveats = a["caveats"] as List<Any?>?
        val binding = a["agentBinding"] as Map<String, Any?>?
        val risk = a["riskPolicy"] as Map<String, Any?>?
        val g = SignersMore.mintSessionGrant(
            principal, a["holder"] as String, a["session"] as String, IntentOmega.dbl(a["seq"]).toLong(), a["root"] as String,
            prevGrant["id"] as String?, a["mapDigest"] as String, a["mapForm"] as String?, preds, caveats, binding, risk, a["salt"] as String?, a["holderPq"] as String?,
        )
        val r = lm()
        r["grant"] = g.grant
        r["goalSalt"] = g.goalSalt
        r["cells"] = cells.toDouble()
        return r
    }
}
