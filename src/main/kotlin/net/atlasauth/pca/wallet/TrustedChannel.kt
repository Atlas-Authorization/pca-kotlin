package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.webauthn.Webauthn

/**
 * The trusted question channel, one instance per session, wallet side.
 *
 * 1. SELECTION belongs to the verifier: questions enter only as a site-signed intent_required (checked against the site's
 *    discovery keys, the session, the current map digest and the action digest; the wallet re-derives the cell itself).
 * 2. The wallet RENDERS the card itself from fixed templates; no agent text exists on this path.
 * 3. Typed and device questions are always alone on their screen; tap and hold questions share a screen.
 * 4. FRICTION scales with harm, never below the site's minimum.
 * 5. CANARIES are inserted with probability rho and rendered like real questions; their answers only update the noise counts.
 * 6. CAPS: at most perSession (default 6) questions per session and perHour (default 12) per hour across the principal's
 *    sessions; when the estimated false-yes rate passes eta_stop the session is frozen.
 * 7. A cell is asked at most once per session (clarified cells count as visited).
 * 8. Under estimated noise an irreversible cell needs two typed or device confirmations on screens at least two apart.
 *
 * What the channel returns for a real answer is the principal-signed observation. Results are maps shaped like the reference's.
 */
@Suppress("UNCHECKED_CAST")
class TrustedChannel(private val o: Options) {
    /** Value-dependent reversibility of a box (from the signed schema); null means the verb's own. */
    fun interface ReversibilityFn { fun of(vs: Map<String, Any?>, box: Array<IntArray>): String? }

    /** The principal's registered security keys. */
    class DeviceTrust {
        @JvmField var rpId: String? = null
        @JvmField var origins: List<Any?> = ArrayList()
        /** Credential id to public key (a JWK map or the COSE_Key bytes). */
        @JvmField var credentials: Map<String, Any?> = LinkedHashMap()
        /** Last accepted signature counter per credential id (absent = 0); updated on each accepted assertion. May be null. */
        @JvmField var signCounts: MutableMap<String, Any?>? = null
    }

    class Options {
        lateinit var omega: Map<String, Any?>
        lateinit var session: String
        lateinit var mapDigest: () -> String
        /** The principal's Ed25519 seed. */
        lateinit var principalSeed: ByteArray
        var siteOrigin: String? = null
        var siteName: String? = null
        /** The site's discovery keys: {kid, alg, pk, pq_pk?}. */
        var siteKeys: List<Any?> = ArrayList()
        /** The principal's own words, or null. */
        var statementText: String? = null
        var units: Map<String, Any?>? = null
        var reversibility: ReversibilityFn? = null
        var sensitivity: Map<String, Any?>? = null
        var identityPaths: List<String> = ArrayList()
        lateinit var view: WalletView
        var lift: ((Map<String, Any?>) -> Map<String, Any?>)? = null
        var liftCandidate: ((Map<String, Any?>) -> Map<String, Any?>)? = null
        var harm: WalletOmega.HarmModel? = null
        var frictionThresholds: Map<String, Any?>? = null
        var perSession: Int? = null
        var perHour: Int? = null
        lateinit var hourly: WalletNoise.SlidingWindowCounter
        lateinit var noise: () -> Map<String, Any?>
        lateinit var onNoise: (Map<String, Any?>) -> Unit
        var fatigue: Map<String, Any?>? = null
        var rho: Double? = null
        lateinit var rand: () -> Double
        lateinit var now: () -> Double
        var device: DeviceTrust? = null
        var maxPerScreen: Int? = null
        var maxBoxCells: Int? = null
    }

    private class Item {
        lateinit var id: String
        lateinit var kind: String
        lateinit var source: String
        lateinit var verb: String
        lateinit var box: Array<IntArray>
        lateinit var coords: Map<String, Any?>
        lateinit var card: Map<String, Any?>
        var action: Map<String, Any?>? = null
        lateinit var vs: Map<String, Any?>
        var first: Map<String, Any?>? = null
        var actionDigest: String? = null
        var irreversible = false
        var jit = false
        var expected: Int? = null
        var weight = 0.0
        var flat = 0.0
        var expiresAt: Double? = null
        var shownOn: Int? = null
        var notBefore: Int? = null

        fun copy(): Item {
            val c = Item()
            c.id = id; c.kind = kind; c.source = source; c.verb = verb; c.box = box; c.coords = coords; c.card = card; c.action = action; c.vs = vs; c.first = first
            c.actionDigest = actionDigest; c.irreversible = irreversible; c.jit = jit; c.expected = expected; c.weight = weight; c.flat = flat; c.expiresAt = expiresAt
            c.shownOn = shownOn; c.notBefore = notBefore
            return c
        }
    }

    private val pending = LinkedHashMap<String, Item>()
    private val asked = HashSet<String>()
    private val canaryUsed = HashSet<String>()
    private val knownYes = ArrayList<Map<String, Any?>>()
    private val confirmations = LinkedHashMap<String, List<Map<String, Any?>>>()
    private val refusedWhileFrozen = ArrayList<Any?>()
    private var sessionQuestions = 0
    private var canaries = 0
    private var screenNo = 0

    private fun perSession(): Int = o.perSession ?: 6

    private fun perHour(): Int = o.perHour ?: 12

    private fun fatigue(): Map<String, Any?> = o.fatigue ?: WalletNoise.defaultFatigue()

    private fun harm(): WalletOmega.HarmModel = o.harm ?: WalletOmega.DEFAULT_HARM

    /** The current noise state: {etaPos, etaPosBar, etaNegBar, frozen}. */
    fun noise(): Map<String, Any?> = WalletNoise.noiseState(o.noise(), o.hourly.count(o.now()).toDouble(), fatigue())

    /** The admission policy the learner should use now: {tau, etaPos, etaNeg, doubleConfirmIrreversible, falseAdmitBound}. */
    fun admission(): Map<String, Any?> = WalletNoise.admissionPolicy(noise(), fatigue())

    /** Questions asked so far in this session. */
    fun questionsAsked(): Int = sessionQuestions

    private fun newId(): String {
        val s = StringBuilder("q_")
        for (i in 0 until 10) s.append(B64U[(Math.floor(o.rand() * 64) % 64).toInt()])
        return if (pending.containsKey(s.toString())) newId() else s.toString()
    }

    /** {weight, meanHarm} of a box, or null when it covers too many cells. */
    private fun boxStats(vs: Map<String, Any?>, box: Array<IntArray>): DoubleArray? {
        val cells = WalletBox.boxCells(box)
        if (cells.size > (o.maxBoxCells ?: 4096)) return null
        var m = 0.0
        var mh = 0.0
        for (idx in cells) {
            val s = WalletOmega.cellStats(vs, idx, harm())
            m += s[0]
            mh += s[0] * s[1]
        }
        return doubleArrayOf(mh, if (m > 0) mh / m else 0.0)
    }

    private fun reversibilityOf(vs: Map<String, Any?>, box: Array<IntArray>): String? {
        val rv = o.reversibility
        return if (rv != null) rv.of(vs, box) else vs["reversibility"] as String?
    }

    private fun frictionOf(vs: Map<String, Any?>, box: Array<IntArray>, meanHarm: Double, siteMin: String?, irreversible: Boolean): String {
        val provenance = ArrayList<Any?>()
        var widensIdentity = false
        for (k in WalletOmega.dims(vs).indices) {
            val d = WalletOmega.dim(vs, k)
            val path = d["path"] as String
            if (path.startsWith("env.prov.") && "cat" == d["kind"]) {
                val param = path.substring("env.prov.".length)
                val levels = ArrayList<Any?>()
                for (i in box[k]) {
                    val v = WalletOmega.value(d, i)
                    val t = if ("prefix" == v["kind"]) v["value"].toString() + "*" else v["value"] as String
                    levels.addAll(t.split(PROV_SPLIT))
                }
                val sens = o.sensitivity?.get(param)
                provenance.add(Wallet.obj("path", param, "sensitivity", sens ?: "material", "levels", levels))
            }
            if ("cat" == d["kind"] && o.identityPaths.contains(path)) {
                for (i in box[k]) if ("exact" != WalletOmega.value(d, i)["kind"]) widensIdentity = true
            }
        }
        val inp = Wallet.obj("reversibility", reversibilityOf(vs, box), "expectedHarm", meanHarm, "provenance", provenance, "widensCriticalIdentity", widensIdentity)
        if (siteMin != null && siteMin.isNotEmpty()) inp["siteMin"] = siteMin
        var tier = Wallet.frictionFor(inp, o.frictionThresholds ?: Wallet.defaultFrictionThresholds())["tier"] as String
        if (irreversible && admission()["doubleConfirmIrreversible"] == true) tier = Wallet.maxFriction(listOf(tier, "typed"))
        return tier
    }

    /** The rendered card and its friction, or null when it cannot be rendered. */
    private fun render(kind: String, verb: String, coords: Map<String, Any?>, friction: String, action: Map<String, Any?>?, vs: Map<String, Any?>, box: Array<IntArray>, reason: String?): Map<String, Any?>? {
        val base = LinkedHashMap<String, Any?>()
        base["omega"] = o.omega
        base["verb"] = verb
        base["coords"] = coords
        base["site"] = Wallet.obj("origin", o.siteOrigin, "name", o.siteName)
        if (o.statementText != null) base["statementText"] = o.statementText
        base["reversibility"] = reversibilityOf(vs, box)
        if (o.units != null) base["units"] = o.units
        if (action != null) base["action"] = action
        base["kind"] = kind
        if (reason != null) base["reason"] = reason
        var inp = LinkedHashMap(base)
        inp["friction"] = friction
        var r = WalletCard.renderCard(inp)
        if (r["ok"] == true && Wallet.frictionRank(friction) == Wallet.frictionRank("typed") && (r["card"] as Map<String, Any?>)["typed"] == null) {
            inp = LinkedHashMap(base)
            inp["friction"] = "device"
            r = WalletCard.renderCard(inp)
        }
        return if (r["ok"] == true) r["card"] as Map<String, Any?> else null
    }

    private fun refusal(code: String, reason: String): Map<String, Any?> = Wallet.obj("ok", false, "code", code, "reason", reason)

    /** null when the gate is open, else the refusal. */
    private fun gate(): Map<String, Any?>? {
        if (noise()["frozen"] == true) return refusal("frozen", "the estimated false-yes rate is above η_stop: no more questions this session")
        if (sessionQuestions >= perSession()) return refusal("cap_session", "at most " + perSession() + " questions per session")
        val nowH = o.now()
        if (!(nowH.isFinite() && o.hourly.count(nowH) < perHour())) return refusal("cap_hour", "at most " + perHour() + " questions per hour")
        return null
    }

    private fun enqueue(it: Item) {
        var flat = Double.POSITIVE_INFINITY
        for (idx in WalletBox.boxCells(it.box)) flat = Math.min(flat, WalletBox.flatIndex(it.vs, idx))
        it.flat = flat
        pending[it.id] = it
    }

    private fun count() {
        sessionQuestions++
        if (!o.hourly.tryAdd(o.now(), 9007199254740991.0)) throw IllegalStateException("unreachable")
    }

    /** Insert a canary with probability rho (rendered and ordered like a real question). */
    private fun maybeCanary() {
        val exclude = HashSet<String>(canaryUsed)
        for (p in pending.values) for (idx in WalletBox.boxCells(p.box)) exclude.add(WalletNoise.cellKey(p.verb, idx))
        var lowHarm = true
        for (p in pending.values) if (!("real" != p.kind || Wallet.frictionRank(p.card["friction"]) <= Wallet.frictionRank("hold"))) lowHarm = false
        val ctx = WalletNoise.CanaryContext()
        ctx.omega = o.omega
        ctx.confirmed = o.view.confirmed()
        ctx.knownNo = WalletNoise.KnownNo { verb, idx -> if (o.view.outsideCeiling(verb, idx)) "ceiling" else if (o.view.vetoed(verb, idx)) "veto" else null }
        ctx.knownYes = knownYes
        ctx.exclude = exclude
        ctx.rand = o.rand
        ctx.rho = o.rho
        ctx.lowHarmSession = lowHarm
        ctx.canariesSoFar = canaries.toDouble()
        val c = WalletNoise.pickCanary(ctx) ?: return
        val verb = c["verb"] as String
        val cidx = WalletNoise.idxOf(c["idx"])
        val vs = WalletOmega.verbSpace(o.omega, verb)!!
        val box = Array(cidx.size) { intArrayOf(cidx[it]) }
        val st = boxStats(vs, box) ?: return
        val coords = WalletBox.coordsOfCell(vs, cidx)
        val action = Wallet.obj("verb", verb, "values", WalletOmega.cellRep(vs, cidx)["values"])
        val friction = frictionOf(vs, box, st[1], null, false)
        val card = render("question", verb, coords, friction, action, vs, box, null) ?: return
        canaries++
        canaryUsed.add(WalletNoise.cellKey(verb, cidx))
        val it = Item()
        it.id = newId()
        it.kind = "canary"; it.source = "elicitation"; it.verb = verb; it.box = box; it.coords = coords; it.card = card; it.action = action; it.irreversible = false
        it.expected = Wallet.nv(c["expected"]).toInt(); it.weight = st[0]; it.jit = false; it.vs = vs
        enqueue(it)
    }

    /**
     * Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the
     * agent attempted ({verb, resource, params, reversibility_class}). Every check fails closed. Returns {ok:true, questionId,
     * friction} or {ok:false, code, reason}.
     */
    fun receive(ir: Map<String, Any?>, action: Map<String, Any?>): Map<String, Any?> {
        val now = o.now()
        val bad = WalletBridge.verifyIntentRequired(ir, o.siteKeys, now)
        if (bad != null) return refusal("bad_site_signature", bad)
        if (o.session != ir["session"]) return refusal("wrong_session", "the question is for another session")
        if (o.mapDigest() != ir["map_digest"]) return refusal("stale_map", "the question names another map version")
        val irCell = ir["cell"] as Map<String, Any?>
        val verb = irCell["verb"] as String
        if (verb != action["verb"] || Wallet.pcaActionDigest(action) != ir["action_digest"])
            return refusal("action_mismatch", "the action does not match the signed action digest")
        val liftFn = o.lift
        val lifted = if (liftFn != null) liftFn(action) else Wallet.actionValuesOf(action)
        val coords = irCell["coords"] as Map<String, Any?>
        val r = WalletBox.resolveCoords(o.omega, verb, coords)
        if (!r.ok) return refusal("cell_mismatch", r.reason!!)
        val rvs = r.vs!!
        val rbox = r.box!!
        val at = WalletBox.cellOfAction(o.omega, lifted)
        if (at == null || !WalletBox.cellInBox(rbox, at.idx)) return refusal("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names")
        val st = boxStats(rvs, rbox) ?: return refusal("cell_too_large", "the question covers too many cells")
        val cells = WalletBox.boxCells(rbox)
        val rvVerb = rvs["verb"] as String
        for (idx in cells) {
            if (o.view.outsideCeiling(rvVerb, idx)) return refusal("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it")
            if (o.view.vetoed(rvVerb, idx)) return refusal("not_uncertain", "the cell was vetoed")
        }
        val pa = o.view.p(rvVerb, at.idx)
        if (!(pa > 0 && pa < 1)) return refusal("not_uncertain", if (pa <= 0) "the cell is denied" else "the cell is already in the grant")
        for (idx in cells) if (asked.contains(WalletNoise.cellKey(rvVerb, idx))) return refusal("already_asked", "a cell is asked at most once per session")
        val g = gate()
        if (g != null) {
            if ("frozen" == g["code"]) refusedWhileFrozen.add(Wallet.obj("verb", rvVerb, "coords", coords))
            return g
        }
        val irreversible = "irreversible" == reversibilityOf(rvs, rbox)
        val friction = frictionOf(rvs, rbox, st[1], ir["friction"] as String?, irreversible)
        val card = render("question", verb, coords, friction, lifted, rvs, rbox, null) ?: return refusal("render_failed", "the card could not be rendered")
        val qid = ir["question_id"] as String
        if (pending.containsKey(qid)) return refusal("already_asked", "duplicate question id")
        for (idx in cells) asked.add(WalletNoise.cellKey(rvVerb, idx))
        count()
        val it = Item()
        it.id = qid; it.kind = "real"; it.source = "elicitation"; it.verb = verb; it.box = rbox; it.coords = coords; it.card = card; it.action = lifted
        it.actionDigest = ir["action_digest"] as String; it.irreversible = irreversible; it.weight = st[0]; it.expiresAt = Wallet.nv(ir["expires_at"]); it.jit = true; it.vs = rvs
        enqueue(it)
        maybeCanary()
        return Wallet.obj("ok", true, "questionId", qid, "friction", card["friction"])
    }

    /**
     * An agent clarification: {candidates: [at most 8 structured actions], reason}, no text. Certain cells are answered at once
     * (dry run); among the uncertain ones the wallet picks the most informative and asks it. Returns {status, verdicts,
     * questionId?, refused?, error?}.
     */
    fun clarify(body: Any?): Map<String, Any?> {
        val parsed = WalletClarify.parseClarifyRequest(body)
        if (parsed["ok"] != true) return Wallet.obj("status", Js.n(400), "verdicts", ArrayList<Any?>(), "error", parsed["error"])
        val request = parsed["request"] as Map<String, Any?>
        val cands = ArrayList<Map<String, Any?>>()
        for (c in request["candidates"] as List<Any?>) cands.add(c as Map<String, Any?>)
        val st = noise()
        val etaPos = Math.min(0.5 - 1e-9, Wallet.nv(st["etaPosBar"]))
        val etaNeg = Math.min(0.5 - 1e-9, Wallet.nv(st["etaNegBar"]))
        val plan = WalletClarify.planClarification(o.omega, o.view, cands, o.liftCandidate, asked, etaPos, etaNeg, harm())
        val verdicts = ArrayList<Any?>(plan.verdicts)
        val ask = plan.ask ?: return Wallet.obj("status", Js.n(200), "verdicts", verdicts)
        val g = gate()
        if (g != null) return Wallet.obj("status", Js.n(if ("frozen" == g["code"]) 200L else 429L), "verdicts", verdicts, "refused", g["code"])
        val verb = ask["verb"] as String
        val vs = WalletOmega.verbSpace(o.omega, verb)!!
        val aidx = plan.askIdx!!
        val box = Array(aidx.size) { intArrayOf(aidx[it]) }
        val stats = boxStats(vs, box)!!
        val coords = WalletBox.coordsOfCell(vs, aidx)
        val raw = cands[Wallet.nv(ask["index"]).toInt()]
        val lc = o.liftCandidate
        val action = if (lc != null) lc(raw) else raw
        val irreversible = "irreversible" == reversibilityOf(vs, box)
        val friction = frictionOf(vs, box, stats[1], null, irreversible)
        val card = render("clarification", verb, coords, friction, action, vs, box, request["reason"] as String?)
            ?: return Wallet.obj("status", Js.n(200), "verdicts", verdicts, "refused", "render_failed")
        val id = newId()
        asked.add(WalletNoise.cellKey(verb, aidx))
        count()
        val it = Item()
        it.id = id; it.kind = "real"; it.source = "clarification"; it.verb = verb; it.box = box; it.coords = coords; it.card = card; it.action = action; it.irreversible = irreversible
        it.weight = stats[0]; it.jit = false; it.vs = vs
        enqueue(it)
        maybeCanary()
        return Wallet.obj("status", Js.n(200), "verdicts", verdicts, "questionId", id)
    }

    /** Pending items in display order: friction desc, E[h|c] mu(c) desc, cell index asc, id asc. */
    private fun ordered(): List<Item> {
        val l = ArrayList(pending.values)
        l.sortWith { a, b ->
            val f = Wallet.frictionRank(b.card["friction"]) - Wallet.frictionRank(a.card["friction"])
            if (f != 0) return@sortWith f
            val w = b.weight - a.weight
            if (w != 0.0 && !w.isNaN()) return@sortWith (if (w > 0) 1 else -1)
            val fl = a.flat - b.flat
            if (fl != 0.0 && !fl.isNaN()) return@sortWith (if (fl > 0) 1 else -1)
            val c = a.id.compareTo(b.id)
            if (c < 0) -1 else if (c > 0) 1 else 0
        }
        return l
    }

    /**
     * The next screen {screen, kind, questions:[{questionId, card}]} or null. A typed or device question is always alone; tap and
     * hold questions share up to maxPerScreen (default 3).
     */
    fun nextScreen(): Map<String, Any?>? {
        val now = o.now()
        for ((key, it) in ArrayList(pending.entries).map { Pair(it.key, it.value) }) {
            val ex = it.expiresAt
            if (ex != null && !(now <= ex)) pending.remove(key)
        }
        val items = ArrayList<Item>()
        for (it in ordered()) if (it.shownOn == null) items.add(it)
        if (items.isEmpty()) return null
        val next = screenNo + 1
        val eligible = ArrayList<Item>()
        for (it in items) if (it.notBefore == null || next >= it.notBefore!!) eligible.add(it)
        screenNo = next
        if (eligible.isEmpty()) return Wallet.obj("screen", Js.n(next.toLong()), "kind", "interstitial", "questions", ArrayList<Any?>())
        val first = eligible[0]
        val picked = ArrayList<Item>()
        picked.add(first)
        if (Wallet.frictionRank(first.card["friction"]) <= Wallet.frictionRank("hold")) {
            for (it in eligible.subList(1, eligible.size)) {
                if (picked.size >= (o.maxPerScreen ?: 3)) break
                if (Wallet.frictionRank(it.card["friction"]) <= Wallet.frictionRank("hold")) picked.add(it)
            }
        }
        val qs = ArrayList<Any?>()
        for (it in picked) {
            it.shownOn = next
            qs.add(Wallet.obj("questionId", it.id, "card", it.card))
        }
        return Wallet.obj("screen", Js.n(next.toLong()), "kind", "questions", "questions", qs)
    }

    private fun fail(code: String, reason: String): Map<String, Any?> = Wallet.obj("ok", false, "code", code, "reason", reason)

    private fun cardTier(it: Item): Any? = it.card["friction"]

    /**
     * The principal's response to a shown question: {answer: "no"} | {answer: "yes", holdMs?, typed?, webauthn?} | {answer:
     * "partly", partial, ...}. Returns {ok:true, kind, answer(s)} or {ok:false, code, reason}.
     */
    fun answer(questionId: String, response: Map<String, Any?>): Map<String, Any?> {
        val it = pending[questionId] ?: return fail("unknown_question", "no such pending question")
        val shownOn = it.shownOn ?: return fail("not_shown", "the question was never shown")
        val now = o.now()
        val ex = it.expiresAt
        if (ex != null && !(now <= ex)) {
            pending.remove(questionId)
            return fail("expired", "the question expired")
        }
        val y: Int
        var partial: Map<String, Any?>? = null
        val ans = response["answer"]
        if ("no" == ans) y = 0
        else if ("partly" == ans) {
            val e = WalletCard.partialError(it.card, response["partial"] as Map<String, Any?>)
            if (e != null) return fail("bad_response", e)
            y = 1
            partial = response["partial"] as Map<String, Any?>
        } else y = 1
        val ux = Wallet.obj("tier", cardTier(it), "rendered_digest", it.card["rendered_digest"], "canary", "canary" == it.kind)
        if (y == 1) {
            val ev = tierEvidence(it, response, questionId)
            if (ev["ok"] != true) return ev
            ux.putAll(ev["ux"] as Map<String, Any?>)
        }
        val plainYes = y == 1 && partial == null
        val ad = it.actionDigest
        if ("canary" != it.kind && it.jit && it.irreversible && plainYes && ad != null && ad.isNotEmpty() &&
            Wallet.frictionRank(cardTier(it)) >= Wallet.frictionRank("typed")) {
            ux["action_digest"] = ad
            ux["consent_for_action"] = true
        }
        val inp = Wallet.obj("map_digest", o.mapDigest(), "session", o.session, "question_id", questionId, "verb", it.verb, "cell", it.coords, "y", Js.n(y.toLong()))
        if (partial != null) inp["partial"] = partial
        inp["source"] = it.source
        inp["observed_at"] = now
        inp["ux"] = ux
        val answer = Wallet.signIntentAnswer(inp, o.principalSeed)
        pending.remove(questionId)
        if ("canary" == it.kind) {
            o.onNoise(WalletNoise.recordCanary(o.noise(), Js.n(it.expected!!.toLong()), Js.n(y.toLong())))
            return Wallet.obj("ok", true, "kind", "canary", "answer", answer)
        }
        if (y == 0) return Wallet.obj("ok", true, "kind", "veto", "answer", answer)
        var singles = true
        for (ids in it.box) if (ids.size != 1) singles = false
        if (plainYes && Wallet.frictionRank(cardTier(it)) >= Wallet.frictionRank("typed") && singles) {
            val idx = IntArray(it.box.size) { i -> it.box[i][0] }
            knownYes.add(Wallet.obj("verb", it.verb, "idx", WalletNoise.idxList(idx)))
        }
        if (plainYes && it.irreversible && admission()["doubleConfirmIrreversible"] == true) {
            val key = it.verb + "|" + WalletDelivery.jsonStringify(it.coords)
            val recs = ArrayList(confirmations[key] ?: ArrayList())
            recs.add(Wallet.obj("screen", Js.n(shownOn.toLong()), "tier", cardTier(it)))
            confirmations[key] = recs
            if ("confirmation" == it.kind && it.first != null && WalletNoise.doubleConfirmed(recs))
                return Wallet.obj("ok", true, "kind", "confirmed", "answers", arrayListOf<Any?>(it.first, answer))
            if ("confirmation" == it.kind) return Wallet.obj("ok", true, "kind", "pending_confirmation", "answer", answer)
            val second = it.copy()
            second.id = newId()
            second.kind = "confirmation"
            second.first = answer
            second.notBefore = shownOn + 2
            second.shownOn = null
            pending[second.id] = second
            return Wallet.obj("ok", true, "kind", "pending_confirmation", "answer", answer)
        }
        return Wallet.obj("ok", true, "kind", "answer", "answer", answer)
    }

    private fun challengeOf(it: Item, questionId: String): String {
        val a = it.actionDigest
        val ad = if (it.jit && it.irreversible && a != null && a.isNotEmpty()) a else null
        return Wallet.deviceChallenge(questionId, it.card["rendered_digest"] as String, 1, ad)
    }

    private fun tierEvidence(it: Item, response: Map<String, Any?>, questionId: String): Map<String, Any?> {
        val r: Map<String, Any?> = if ("no" == response["answer"]) LinkedHashMap() else response
        val tier = cardTier(it)
        if ("tap" == tier) return Wallet.obj("ok", true, "ux", LinkedHashMap<String, Any?>())
        if ("hold" == tier) {
            val h = r["holdMs"]
            if (!(Js.isNumber(h) && Wallet.nv(h) == Math.rint(Wallet.nv(h)) && !Wallet.nv(h).isInfinite() && Wallet.nv(h) >= Wallet.MIN_HOLD_MS))
                return fail("tier_evidence", "hold for at least " + Wallet.MIN_HOLD_MS + " ms")
            return Wallet.obj("ok", true, "ux", Wallet.obj("hold_ms", h))
        }
        if ("typed" == tier) {
            val t = it.card["typed"] as Map<String, Any?>?
            val act = it.action
            if (t == null || act == null || r["typed"] !is String) return fail("tier_evidence", "type the value shown on the card")
            val want = WalletCard.expectedTyped(it.card, act)
            val got = WalletCard.normalizeTyped(r["typed"] as String, t["mode"] as String, o.units?.get(t["path"]))
            if (want == null || got == null || got != want) return fail("typed_mismatch", "the typed value does not match the card")
            return Wallet.obj("ok", true, "ux", Wallet.obj("typed_digest", Wallet.typedDigest(questionId, got)))
        }
        if ("device" == tier) {
            val waO = r["webauthn"]
            val dev = o.device
            if (!Js.truthy(waO) || dev == null) return fail("tier_evidence", "a security-key assertion is required")
            val wa = waO as Map<String, Any?>
            val credId = wa["credential_id"]
            val pk = if (credId is String) dev.credentials[credId] else null
            val ad = Pca.decodeB64uStrict(wa["authenticator_data"], -1)
            val cd = Pca.decodeB64uStrict(wa["client_data_json"], -1)
            val sg = Pca.decodeB64uStrict(wa["signature"], -1)
            if (pk == null || ad == null || cd == null || sg == null) return fail("tier_evidence", "unknown credential or malformed assertion")
            val challenge = challengeOf(it, questionId)
            val assertion = Wallet.obj("authenticatorData", ad, "clientDataJSON", cd, "signature", sg, "publicKey", pk)
            val stored = dev.signCounts?.get(credId)
            val expect = Wallet.obj("expectedChallenge", challenge, "rpId", dev.rpId, "origins", dev.origins, "requireUV", true,
                "storedSignCount", stored ?: Js.n(0))
            val res = Webauthn.verifyAssertion(assertion, expect)
            if (res["ok"] != true) return fail("tier_evidence", "security key: " + res["reason"])
            dev.signCounts?.put(credId as String, res["signCount"])
            return Wallet.obj("ok", true, "ux", Wallet.obj("webauthn", LinkedHashMap(wa)))
        }
        throw IllegalStateException("unreachable friction tier")
    }

    /** The WebAuthn challenge the wallet UI passes to the credential API for a shown device-tier question, or null. */
    fun deviceChallengeFor(questionId: String): String? {
        val it = pending[questionId]
        if (it == null || it.shownOn == null || "device" != cardTier(it)) return null
        return challengeOf(it, questionId)
    }

    /** The end-of-session summary {frozen, refused:[{verb, coords}], asked, canaries}. */
    fun summary(): Map<String, Any?> =
        Wallet.obj("frozen", noise()["frozen"], "refused", ArrayList<Any?>(refusedWhileFrozen), "asked", Js.n(sessionQuestions.toLong()), "canaries", Js.n(canaries.toLong()))

    /** A stable digest of the channel's pending state (for tests and audit logs). */
    fun stateDigest(): String {
        val p = ArrayList<Any?>()
        for (i in ordered()) p.add(Wallet.obj("id", i.id, "k", i.kind, "d", i.card["rendered_digest"]))
        val a = asked.sorted()
        return Pca.hashCanonical(Wallet.obj("d", "atlas-pca/wallet-channel-state/v1", "p", p, "a", ArrayList<Any?>(a), "n", Js.n(sessionQuestions.toLong())))
    }

    private companion object {
        const val B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val PROV_SPLIT = Regex("[|,]")
    }
}
