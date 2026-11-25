package net.atlasauth.pca.verifier

import net.atlasauth.pca.jose.Js
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * The undo-window coordinator: admission, the durable ledger, the human surface and the real rollback (the reference's `server/undo`).
 *
 *  - `admit`     ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class
 *                is `reversible`, the [UndoEngine] (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating
 *                action is AUTHORIZED under the original grant (the policy VM releases it over the original PCActn's verified chain).
 *  - `open`      writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened` receipt,
 *                mints the one-click undo token and notifies the principal. A window nobody was told about is no window: a failed
 *                notification aborts the record and raises an alert.
 *  - `veto`      a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves `open -> vetoed` exactly once
 *                and starts the compensation.
 *  - `compensate` re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt
 *                through the operations store and the compensator. Success: `compensated`, the budget reservation released
 *                (`rollback`). Anything else: `compensation_failed`, the reservation kept and an alert raised (never silent).
 *  - `finalizeDue` closes the windows whose time is up (`open -> finalized`) and commits their budget reservations.
 *
 * Synchronous: every injected component is a plain call. Records, plans, admissions, notices and alerts are the reference's JSON objects
 * (maps with its member names); a [Map] argument is never modified.
 */

/** With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands). */
const val UNDO_RELAY_GRACE_MS: Long = 60_000

/** The source of confirmed reversibility. [plan] answers `{def_digest, compensation: {verb, params, def_digest, target_param?}, render?, render_digest?}` from SIGNED, reviewer-confirmed definitions only, or null (not undoable). */
fun interface UndoEngine {
    fun plan(op: Map<String, Any?>, operationId: String): Map<String, Any?>?
}

/** The grant by reference, from YOUR store (the same lookup [Authorize] uses). */
fun interface UndoGrantResolver {
    fun resolve(grantRef: String?, pcactn: Map<String, Any?>): Map<String, Any?>?
}

/** Runs a compensating action (your connector). Throw on failure. The call is `{operation, idempotencyKey, undoOf, originalResult?, record}`. */
fun interface UndoCompensator {
    fun compensate(call: Map<String, Any?>): Any?
}

/** The principal's channels. Answers `{delivered, reason?}`; an exception counts as not delivered. */
fun interface UndoNotifier {
    fun notify(notice: Map<String, Any?>): Map<String, Any?>?
}

/** Where a failure that needs a human goes (pager, SIEM): `{level, code, record, reason}`. Never silent. */
fun interface UndoAlertSink {
    fun alert(a: Map<String, Any?>)
}

/** Per-operation policy `{mode?: always|escalations|off, windowMs?, onRevocation?: keep|veto}`. */
fun interface UndoPolicyFn {
    fun policy(op: Map<String, Any?>, grant: Map<String, Any?>): Map<String, Any?>?
}

/** The value of the compensating action's target parameter (default: `effect.result.id` when it is a non-empty string). */
fun interface UndoTargetResolver {
    fun target(rec: Map<String, Any?>): String?
}

/** Vetoes received somewhere else (the hosted veto endpoint): each `{id, token, at}`. A relay that cannot be read (throws) finalizes NOTHING. */
fun interface UndoRelay {
    fun pending(): List<Map<String, Any?>>
}

/** A bond ledger whose [slashBond] re-verifies a fraud proof itself and refuses outside its challenge window. */
fun interface UndoBondLedger {
    fun slashBond(params: Map<String, Any?>): Any?
}

/** The release evidence of a budget reservation ([how] is `rollback` or `effect_not_run`); null releases without evidence. */
fun interface UndoReleaseEvidence {
    fun evidence(reservation: Map<String, Any?>, how: String): Map<String, Any?>?
}

/** Aggregate budgets held during the window: committed on finalize, released on compensation or abort. With no [evidence] the release carries none. */
class UndoBudget @JvmOverloads constructor(val ledger: BudgetLedger, val evidence: UndoReleaseEvidence? = null)

class UndoCoordinatorOptions @JvmOverloads constructor(
    /** REQUIRED: the durable undo ledger (`durable` true). */
    val store: UndoStore?,
    /** REQUIRED: confirmed reversibility and compensations. */
    val engine: UndoEngine?,
    /** REQUIRED: the undo service key (32-byte Ed25519 seed): signs tokens and receipts. */
    val signerSecret: ByteArray?,
    /** REQUIRED: this resource server's audience (bound into the token). */
    val audience: String?,
    val resolveGrant: UndoGrantResolver?,
    val compensate: UndoCompensator?,
    /** REQUIRED: at-most-once records for compensation attempts (shared and durable in production). */
    val operations: Operations.Store?,
    val notifier: UndoNotifier?,
    val alert: UndoAlertSink?,
    val policy: UndoPolicyFn? = null,
    /** `{minMs?, maxMs?, defaultMs?}`. */
    val window: Map<String, Any?>? = null,
    val resolveTarget: UndoTargetResolver? = null,
    val budget: UndoBudget? = null,
    /** Verifier-side PQ pins forwarded to the compensation decision. */
    val pqPins: Map<String, Any?>? = null,
    /** A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes. */
    val effectTimeoutMs: Long = 5 * 60_000,
    val now: (() -> Long)? = null,
    val relay: UndoRelay? = null,
    /** TESTS ONLY: accept a store whose `durable` is false (every open window is lost on restart). */
    val insecureVolatileStore: Boolean = false,
    /** Used by [UndoCoordinator.rollbackOnSlash] when it is not passed one. */
    val bonds: UndoBondLedger? = null,
)

/** The answer of a veto: ok with the [record] (and whether it was a replay), or a refusal with its [code] and [reason]. */
class UndoVetoResult private constructor(val ok: Boolean, val record: Map<String, Any?>?, val replayed: Boolean, val code: String?, val reason: String?) {
    companion object {
        internal fun ok(record: Map<String, Any?>, replayed: Boolean) = UndoVetoResult(true, record, replayed, null, null)

        internal fun refused(code: String, reason: String) = UndoVetoResult(false, null, false, code, reason)
    }
}

/** The names of the required coordinator components that are absent or malformed (empty when complete). */
fun missingUndoComponents(o: UndoCoordinatorOptions?): List<String> {
    val m = ArrayList<String>()
    if (o?.store == null) m.add("store")
    if (o?.engine == null) m.add("engine")
    if (o?.signerSecret == null || o.signerSecret.size != 32) m.add("signerSecret")
    if (o?.audience == null || o.audience.isEmpty()) m.add("audience")
    if (o?.resolveGrant == null) m.add("resolveGrant")
    if (o?.compensate == null) m.add("compensate")
    if (o?.operations == null) m.add("operations")
    if (o?.notifier == null) m.add("notifier")
    if (o?.alert == null) m.add("alert")
    return m
}

/** The undo service key's public half (b64u), for verifying tokens and receipts elsewhere (e.g. the hosted veto route). */
fun undoSignerPublic(seed: ByteArray): String = Keys.edFromSeed(seed).id()

/** Build the coordinator. Throws [UndoError] `config` for a missing component and `not_durable` for a volatile store (fail closed). */
fun createUndoCoordinator(opts: UndoCoordinatorOptions): UndoCoordinator {
    val missing = missingUndoComponents(opts)
    if (missing.isNotEmpty()) throw UndoError("config", "undo coordinator: missing required component(s): ${missing.joinToString(", ")}")
    if (!opts.store!!.durable && !opts.insecureVolatileStore) {
        throw UndoError("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation")
    }
    return UndoCoordinator(opts)
}

/** Null when [a] is a usable admission `{id, window_end, compensation: {verb}}`, else the reason. */
fun undoAdmissionError(a: Any?): String? {
    if (a !is Map<*, *>) return "an admission must be an object"
    val id = a["id"]
    if (id !is String || id.isEmpty() || id.length > 128) return "admission id must be a non-empty string of at most 128 characters"
    val w = a["window_end"]
    if (!Json.isSafeInt(w) || Json.asLong(w) < 0) return "admission window_end must be a non-negative safe integer"
    val c = a["compensation"]
    if (c !is Map<*, *> || (c["verb"] as? String).isNullOrEmpty()) return "admission compensation.verb must be a non-empty string"
    return null
}

/**
 * Execute-side report of an allowed result that carries an undo window: a committed effect is recorded (its result names the compensation
 * target), an effect that failed or never started aborts the window (nothing to undo; held budget released). [outcome] is
 * `{status, result?}`.
 */
fun reportUndoEffect(undo: UndoCoordinator, id: String, outcome: Map<String, Any?>): Map<String, Any?> {
    val status = outcome["status"]
    if (status == "committed") return undo.recordEffect(id, outcome["result"])
    if (status == "failed" || status == "aborted" || status == "refused") return undo.abort(id, "effect_$status")
    // pending / uncertain: unknown; the window keeps running and finalizeDue alerts if it closes without a report
    return undo.get(id) ?: throw UndoError("invalid", "no undo record $id")
}

private val ISO_MS: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

/**
 * An [UndoNotifier] over the existing approval channels (Slack, webhook, email, SMS, push). The notice becomes a step-up-shaped message whose
 * link is the one-click undo URL ([undoUrl]) and whose render is the WYSIWYS render of the action.
 */
@JvmOverloads
fun undoNotifierFromDispatcher(dispatcher: ApprovalChannels.ApprovalDispatcher, undoUrl: (token: String, id: String) -> String, inboxUrl: String? = null): UndoNotifier =
    UndoNotifier { n ->
        @Suppress("UNCHECKED_CAST")
        val r = n["record"] as Map<String, Any?>
        val act = r["action"] as Map<String, Any?>
        val verb = act["verb"]
        val resource = act["resource"]
        val until = ISO_MS.format(Instant.ofEpochMilli(IntentJs.lng(r["window_end"])))
        val kind = n["kind"]
        @Suppress("UNCHECKED_CAST")
        val comp = r["compensation"] as Map<String, Any?>
        val reason = when (kind) {
            "opened" -> "Already done: $verb on $resource. You can undo it until $until."
            "vetoed" -> "Undo started for $verb on $resource."
            "compensated" -> "Undone: $verb on $resource."
            "compensation_failed" -> "UNDO FAILED for $verb on $resource: ${(r["outcome"] as? Map<*, *>)?.get("reason") ?: "unknown"}. An operator has been alerted."
            "revoked" -> "The agent's grant was revoked. $verb on $resource can still be undone until $until."
            else -> "Final: $verb on $resource can no longer be undone."
        }
        val req = linkedMapOf<String, Any?>(
            "id" to "undo:${r["id"]}:$kind", "verb" to verb, "resource" to resource, "tier" to 3L, "reason" to reason, "goalCommit" to "",
            "lineage" to linkedMapOf<String, Any?>(
                "goalCommit" to "", "goalVerified" to false,
                "chain" to listOf(linkedMapOf<String, Any?>("kind" to "action", "label" to "$verb $resource", "detail" to "undo: ${comp["verb"]}")), "because" to reason,
            ),
            "r" to 0L, "requestedAt" to r["opened_at"],
        )
        if (n["render"] != null && r["render_digest"] != null) {
            req["render"] = n["render"]
            req["renderDigest"] = r["render_digest"]
        }
        val link: String? = if (kind == "opened" && n["token"] is String) undoUrl(n["token"] as String, r["id"] as String) else inboxUrl
        val ctx: Map<String, Any?>? = if (link != null) linkedMapOf<String, Any?>("inboxUrl" to link) else linkedMapOf()
        val out = dispatcher.notifyAll(req, ctx)
        if (out.any { it["delivered"] == true }) {
            linkedMapOf<String, Any?>("delivered" to true)
        } else {
            linkedMapOf<String, Any?>(
                "delivered" to false,
                "reason" to (out.joinToString("; ") { "${it["kind"]}: ${it["reason"] ?: "not delivered"}" }.ifEmpty { "no enabled channel" }),
            )
        }
    }

/** The HTTP transport of [hostedUndoVetoRelay]: answer the status and the body text of a GET. Throws on a network failure. */
fun interface UndoRelayFetch {
    fun get(url: String, headers: Map<String, String>): Pair<Int, String>
}

/**
 * The relay over a hosted undo ledger: `GET {baseUrl}/v1/pca/undo/vetoes` with the instance secret key. Pass it as [UndoCoordinatorOptions.relay].
 * A non-2xx answer or a malformed body throws (and so finalizes nothing).
 */
@JvmOverloads
fun hostedUndoVetoRelay(baseUrl: String, secretKey: String, fetch: UndoRelayFetch? = null, limit: Int = 200): UndoRelay {
    val f = fetch ?: UndoRelayFetch { url, headers -> SimpleHttp.request("GET", url, headers, null) }
    val base = baseUrl.trimEnd('/')
    return UndoRelay {
        val res = f.get("$base/v1/pca/undo/vetoes?limit=${minOf(200, maxOf(1, limit))}", linkedMapOf("authorization" to "Bearer $secretKey", "accept" to "application/json"))
        if (res.first !in 200..299) throw UndoError("invalid", "the veto relay answered ${res.first}")
        val body = try {
            Json.parseLenient(res.second)
        } catch (e: IllegalArgumentException) {
            throw UndoError("invalid", "the veto relay answered without a data list")
        }
        val data = (body as? Map<*, *>)?.get("data") as? List<*> ?: throw UndoError("invalid", "the veto relay answered without a data list")
        val out = ArrayList<Map<String, Any?>>()
        for (row in data) {
            val rm = row as? Map<*, *> ?: throw UndoError("invalid", "the veto relay answered a malformed entry")
            val v = rm["veto"] as? Map<*, *> ?: throw UndoError("invalid", "the veto relay answered a malformed entry")
            if (rm["record_id"] !is String || v["token"] !is String || Js.num(v["at"]) == null) throw UndoError("invalid", "the veto relay answered a malformed entry")
            out.add(linkedMapOf("id" to rm["record_id"], "token" to v["token"], "at" to v["at"]))
        }
        out
    }
}

/** The coordinator [createUndoCoordinator] builds. */
@Suppress("UNCHECKED_CAST")
class UndoCoordinator internal constructor(private val o: UndoCoordinatorOptions) {
    private val store: UndoStore = o.store!!
    private val engine: UndoEngine = o.engine!!
    private val secret: ByteArray = o.signerSecret!!.clone()
    private val notifier: UndoNotifier = o.notifier!!
    private val operations: Operations.Store = o.operations!!
    private val clock: () -> Long = o.now ?: { System.currentTimeMillis() }

    /** The undo service key's public half (b64u). */
    val signerPublic: String = Keys.edFromSeed(secret).id()

    // ---- plumbing ----

    private class Applied(val record: Map<String, Any?>?, val applied: Boolean, val refused: String? = null, val reason: String? = null)

    private fun m(x: Any?): Map<String, Any?> = x as Map<String, Any?>

    private fun lng(x: Any?): Long = IntentJs.lng(x)

    private fun now(): Long {
        val t = clock()
        if (t < -9007199254740991L || t > 9007199254740991L) throw UndoError("invalid", "the clock returned a non-finite time")
        return t
    }

    private fun strip(r: Map<String, Any?>): Map<String, Any?> = r.filterKeys { it != "pcactn" && it != "receipts" }

    private fun alert(level: String, code: String, record: String, reason: String) {
        val a = linkedMapOf<String, Any?>("level" to level, "code" to code, "record" to record, "reason" to reason)
        try {
            o.alert!!.alert(a)
        } catch (e: Exception) {
            // an alert sink that throws is itself a failure the operator must see: write it where a host always looks
            System.err.println("pca undo alert ($code) for $record: $reason")
        }
    }

    private fun notify(n: Map<String, Any?>): Map<String, Any?> = try {
        val r = notifier.notify(n)
        if (r != null && r["delivered"] == true) linkedMapOf("delivered" to true) else linkedMapOf("delivered" to false, "reason" to ((r?.get("reason") as? String) ?: "no channel delivered the notice"))
    } catch (e: Exception) {
        linkedMapOf("delivered" to false, "reason" to (e.message ?: "notifier error"))
    }

    /** Apply one event with compare-and-swap retries; returns the stored record and whether this call applied it, or the refusal. */
    private fun applyEvent(id: String, ev: Map<String, Any?>, checkAt: Long? = null): Applied {
        for (i in 0 until MAX_CAS) {
            val cur = store.get(id) ?: return Applied(null, false, "unknown", "no undo record $id")
            val t = now()
            // a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
            val tr = Undo.transition(cur, ev, checkAt ?: t)
            if (tr.outcome == "refused") return Applied(null, false, tr.code, tr.reason)
            if (tr.outcome == "replayed") return Applied(tr.record, false)
            val next = Undo.withReceipt(tr.record!!, tr.event!!, tr.note ?: "", t, secret)
            if (store.replace(id, lng(cur["ver"]), next)) return Applied(next, true)
        }
        throw UndoError("conflict_exhausted", "undo record $id kept changing")
    }

    private fun must(id: String, ev: Map<String, Any?>): Applied {
        val r = applyEvent(id, ev)
        if (r.refused != null) throw UndoError("invalid", "${r.refused}: ${r.reason}")
        return r
    }

    private fun settleBudget(rec: Map<String, Any?>, how: String) {
        val b = o.budget ?: return
        val list = rec["budget"] as? List<*> ?: return
        for (r0 in list) {
            val r = m(r0)
            val key = r["key"] as String
            val id = r["id"] as String
            try {
                val out = if (how == "commit") {
                    b.ledger.commit(key, id)
                } else {
                    b.ledger.release(key, id, b.evidence?.evidence(r, how))
                }
                if (out.outcome != "settled" && out.outcome != "replayed") alert("warning", "budget_settle_failed", rec["id"] as String, "$how of $key/$id: ${out.outcome}")
            } catch (e: Exception) {
                alert("warning", "budget_settle_failed", rec["id"] as String, "$how of $key/$id: ${e.message ?: "error"}")
            }
        }
    }

    private fun policyOf(op: Map<String, Any?>, grant: Map<String, Any?>): Map<String, Any?> = o.policy?.policy(op, grant) ?: emptyMap()

    /** The Policy VM on the compensating action under the original chain, at [at] (the admission time): {ok, reason}. */
    private fun compensationAllowed(pc: Map<String, Any?>, grant: Map<String, Any?>, op: Map<String, Any?>, at: Long): Pair<Boolean, String> {
        val inp = linkedMapOf<String, Any?>("grant" to grant, "trustedRoot" to grant, "chain" to pc["cap_chain"])
        if (o.pqPins != null) inp["pqPins"] = o.pqPins
        inp["action"] = linkedMapOf<String, Any?>("action" to linkedMapOf("verb" to op["verb"], "resource" to op["resource"], "params" to (op["params"] ?: LinkedHashMap<String, Any?>())))
        inp["risk"] = LinkedHashMap<String, Any?>()
        inp["budget"] = linkedMapOf<String, Any?>("B" to 0L, "tau" to at)
        inp["now"] = at
        val d = Decide.decide(inp)
        if (d["releaseGuardianShare"] == true) return Pair(true, "")
        val reasons = d["reasons"] as? List<*> ?: emptyList<Any?>()
        return Pair(false, (reasons.firstOrNull { it is String && !it.startsWith("risk input") } as? String) ?: "the grant does not authorize the compensating action")
    }

    private fun refused(reason: String): Map<String, Any?> = linkedMapOf("refused" to reason)

    // ---- the API ----

    /**
     * ELIGIBILITY: the admission `{id, opened_at, window_end, converted, plan, compensation, pcactn, grant, operation}`, or `{refused: reason}`.
     * [operation] is `{verb, resource, params?}`. Never throws.
     */
    @JvmOverloads
    fun admit(pcactn: Map<String, Any?>?, operation: Map<String, Any?>?, converted: Boolean, grant: Map<String, Any?>? = null): Map<String, Any?> = try {
        admitUnchecked(pcactn, operation, converted, grant)
    } catch (e: Exception) {
        refused("undo admission error (fail closed): ${e.message ?: "unknown"}")
    }

    private fun admitUnchecked(pc: Map<String, Any?>?, op: Map<String, Any?>?, converted: Boolean, grantIn: Map<String, Any?>?): Map<String, Any?> {
        if (pc == null || op == null || op["verb"] !is String || op["resource"] !is String) return refused("no operation")
        val grant = grantIn ?: o.resolveGrant!!.resolve(pc["grant_ref"] as? String, pc) ?: return refused("unknown grant")
        val pol = policyOf(op, grant)
        val mode = (pol["mode"] as? String) ?: "always"
        if (mode == "off") return refused("policy: undo windows are off")
        if (mode == "escalations" && !converted) return refused("policy: windows only replace approvals")
        // the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
        val act = pc["action"] as? Map<*, *>
        val signed = act?.get("reversibility_class")
        if (Revocation.classRank(signed) != 0) return refused("the signed class is ${if (act != null && act.containsKey("reversibility_class")) Js.template(signed) else "undefined"}")
        val id = Pca.hashCanonical(pc)
        val plan = engine.plan(op, id) ?: return refused("not confirmed reversible, or no confirmed compensating action")
        val pcmp = m(plan["compensation"])
        val comp = linkedMapOf<String, Any?>(
            "verb" to pcmp["verb"], "resource" to op["resource"], "params" to MemoryAtomicKv.copyTree(pcmp["params"]), "undo_of" to id, "def_digest" to pcmp["def_digest"],
        )
        if (pcmp["target_param"] != null) comp["target_param"] = pcmp["target_param"]
        val t = now()
        val allowed = compensationAllowed(pc, grant, linkedMapOf("verb" to comp["verb"], "resource" to comp["resource"], "params" to comp["params"]), t)
        if (!allowed.first) return refused("the compensating action is not authorized under the grant: ${allowed.second}")
        val w = o.window
        val windowMs = Undo.resolveWindow(pol["windowMs"], IntentJs.num(w?.get("minMs")), IntentJs.num(w?.get("maxMs")), IntentJs.num(w?.get("defaultMs")))
        return linkedMapOf(
            "id" to id, "opened_at" to t, "window_end" to t + windowMs, "converted" to converted, "plan" to plan, "compensation" to comp, "pcactn" to pc, "grant" to grant,
            "operation" to linkedMapOf("verb" to op["verb"], "resource" to op["resource"], "params" to MemoryAtomicKv.copyTree(op["params"] ?: LinkedHashMap<String, Any?>())),
        )
    }

    private fun infoOf(rec: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "id" to rec["id"], "window_end" to rec["window_end"], "converted" to rec["converted"],
        "compensation" to linkedMapOf("verb" to m(rec["compensation"])["verb"], "resource" to m(rec["compensation"])["resource"]),
        "token" to Undo.encodeToken(Undo.signToken(rec, secret)),
        "obligation" to linkedMapOf("kind" to "undo_window", "params" to linkedMapOf("id" to rec["id"], "window_end" to rec["window_end"]), "due" to rec["window_end"]),
    )

    /**
     * Write the record durably, sign the `opened` receipt, mint the one-click token and tell the principal: the window info
     * `{id, window_end, converted, compensation: {verb, resource}, token, obligation}`. [bond] is `{ref, challengeEndsAt}`.
     */
    @JvmOverloads
    fun open(adm: Map<String, Any?>, bond: Map<String, Any?>? = null): Map<String, Any?> {
        val pc = m(adm["pcactn"])
        val chain = pc["cap_chain"] as List<*>
        val windowEnd = if (bond != null) maxOf(lng(adm["window_end"]), Math.floor(IntentJs.num(bond["challengeEndsAt"])!!).toLong()) else lng(adm["window_end"])
        val comp = m(adm["compensation"])
        val cdig = Undo.compensationDigest(comp)
        val plan = m(adm["plan"])
        val op = m(adm["operation"])
        val base = LinkedHashMap<String, Any?>()
        base["v"] = 1L
        base["id"] = adm["id"]
        base["aud"] = o.audience
        base["grant_ref"] = pc["grant_ref"]
        base["holder"] = m(chain[chain.size - 1])["holder"]
        base["principal"] = m(adm["grant"])["issuer"]
        base["action"] = linkedMapOf("verb" to op["verb"], "resource" to op["resource"], "params_digest" to m(pc["action"])["params_digest"], "def_digest" to plan["def_digest"])
        base["compensation"] = comp
        base["compensation_digest"] = cdig
        if (plan["render_digest"] != null) base["render_digest"] = plan["render_digest"]
        base["opened_at"] = adm["opened_at"]
        base["window_end"] = windowEnd
        base["converted"] = adm["converted"]
        base["state"] = "open"
        base["ver"] = 0L
        base["pcactn"] = Issue.encode(pc)
        if (bond != null) base["bond_ref"] = bond["ref"]
        base["attempt"] = 0L
        base["receipts"] = ArrayList<Any?>()
        val rec = Undo.withReceipt(base, "opened", if (adm["converted"] == true) "converted" else "", lng(adm["opened_at"]), secret)
        val existing = store.create(rec)
        if (existing != null) {
            // a retry of the same admission returns the same window; anything else is a different action under the same id
            if (existing["compensation_digest"] != cdig || existing["state"] != "open") throw UndoError("invalid", "undo record ${adm["id"]} already exists with other terms or state ${existing["state"]}")
            return infoOf(existing)
        }
        val info = infoOf(rec)
        val notice = linkedMapOf<String, Any?>("kind" to "opened", "record" to strip(rec), "token" to info["token"])
        if (plan["render"] != null) notice["render"] = plan["render"]
        val n = notify(notice)
        if (n["delivered"] != true) {
            applyEvent(rec["id"] as String, linkedMapOf("kind" to "abort", "reason" to "notify_failed"))
            val why = (n["reason"] as? String) ?: "not delivered"
            alert("critical", "notify_failed", rec["id"] as String, "the principal could not be told about the undo window: $why")
            throw UndoError("invalid", "notify_failed: the undo window could not be announced ($why)")
        }
        return info
    }

    /** The coordinator as the [Authorize.UndoHook] of an authorization: an unanswered escalation runs under a veto window opened here. */
    fun asAuthorizeHook(): Authorize.UndoHook = Authorize.UndoHook { pcactn, grant, operation ->
        val adm = admit(pcactn, linkedMapOf("verb" to operation.verb, "resource" to operation.resource, "params" to operation.params), true, grant)
        if (adm["refused"] != null) {
            null
        } else {
            val info = open(adm)
            val c = m(info["compensation"])
            Undo.Admission(info["id"] as String, lng(info["window_end"]), c["verb"] as String, c["resource"] as String)
        }
    }

    fun get(id: String): Map<String, Any?>? = store.get(id)

    /** Hold aggregate budget reservations `[{key, id}]` until the window closes. */
    fun holdBudget(id: String, reservations: List<Map<String, Any?>>): Map<String, Any?> {
        for (i in 0 until MAX_CAS) {
            val cur = store.get(id) ?: throw UndoError("invalid", "no undo record $id")
            if (cur["state"] != "open" && cur["state"] != "vetoed") throw UndoError("invalid", "a ${cur["state"]} record holds no budget")
            val next = LinkedHashMap(cur)
            next["budget"] = ArrayList<Any?>((cur["budget"] as? List<*>) ?: emptyList<Any?>()) + reservations.map { linkedMapOf<String, Any?>("key" to it["key"], "id" to it["id"]) }
            next["ver"] = lng(cur["ver"]) + 1
            if (store.replace(id, lng(cur["ver"]), next)) return next
        }
        throw UndoError("conflict_exhausted", "undo record $id kept changing")
    }

    /** Report the original effect (its [result] names the compensation target). A veto that arrived while it ran is acted on now. */
    @JvmOverloads
    fun recordEffect(id: String, result: Any? = null): Map<String, Any?> {
        val ev = linkedMapOf<String, Any?>("kind" to "effect")
        if (result != null) ev["result"] = result
        val r = must(id, ev)
        return if (r.record!!["state"] == "vetoed") runCompensation(r.record) else r.record
    }

    /** The effect did not run: close the record and release the held budget. */
    fun abort(id: String, reason: String): Map<String, Any?> {
        val r = must(id, linkedMapOf("kind" to "abort", "reason" to reason))
        if (r.applied) settleBudget(r.record!!, "effect_not_run")
        return r.record!!
    }

    private fun finishCompensated(rec: Map<String, Any?>): Map<String, Any?> {
        if (rec["state"] == "compensated") {
            settleBudget(rec, "rollback")
            notify(linkedMapOf("kind" to "compensated", "record" to strip(rec)))
        }
        return rec
    }

    private fun runCompensation(rec0: Map<String, Any?>): Map<String, Any?> {
        var rec = rec0
        if (rec["state"] != "vetoed") return rec
        val t = now()
        val vetoAt = (rec["veto"] as? Map<*, *>)?.get("at")?.let { lng(it) } ?: t
        if (rec["effect"] == null && t - vetoAt < o.effectTimeoutMs) return rec // wait for the effect report (recordEffect resumes)
        val id = rec["id"] as String
        val pc = decodePcactn(rec["pcactn"] as String)
        val grant = o.resolveGrant!!.resolve(rec["grant_ref"] as? String, pc)

        fun fail(reason: String, code: String = "compensation_failed"): Map<String, Any?> {
            val r = applyEvent(id, linkedMapOf("kind" to "compensation_failed", "reason" to reason))
            val out = if (r.refused != null) (store.get(id) ?: rec) else r.record!!
            if (r.refused == null && r.applied) {
                alert("critical", code, id, reason)
                notify(linkedMapOf("kind" to "compensation_failed", "record" to strip(out)))
            }
            return out
        }

        if (grant == null) return fail("the grant is no longer known: the compensation cannot be authorized", "compensation_denied")
        val comp = m(rec["compensation"])
        val params = LinkedHashMap<String, Any?>(m(comp["params"]))
        val tp = comp["target_param"] as? String
        if (tp != null) {
            val target: String? = if (o.resolveTarget != null) {
                o.resolveTarget.target(rec)
            } else {
                val res = (rec["effect"] as? Map<*, *>)?.get("result") as? Map<*, *>
                (res?.get("id") as? String)?.takeIf { it.isNotEmpty() }
            }
            if (target == null) return fail("the target '$tp' of the compensation is unknown (no effect result names it)")
            params[tp] = target
        }
        val op = linkedMapOf<String, Any?>("verb" to comp["verb"], "resource" to comp["resource"], "params" to params)
        val dec = compensationAllowed(pc, grant, op, lng(rec["opened_at"]))
        if (!dec.first) return fail("the compensating action is not authorized under the grant: ${dec.second}", "compensation_denied")
        // at most once per attempt: the operation record is created before the compensator runs
        val attempt = lng(rec["attempt"])
        val opId = Pca.hashCanonical(linkedMapOf("d" to "atlas-pca/undo-compensation-op/v1", "record" to id, "attempt" to attempt))
        val orec = linkedMapOf<String, Any?>(
            "id" to opId, "state" to "pending", "verb" to op["verb"], "resource" to op["resource"], "params_digest" to Pca.hashCanonical(params),
            "reversibility" to "irreversible", "startedAt" to t,
        )
        val prev = operations.create(orec)
        if (prev != null) {
            val ps = prev["state"]
            if (ps == "committed") {
                val ev = linkedMapOf<String, Any?>("kind" to "compensated")
                if (prev["result"] != null) ev["result"] = prev["result"]
                val r = applyEvent(id, ev)
                rec = if (r.refused != null) rec else r.record!!
                return finishCompensated(rec)
            }
            if (ps == "failed" || ps == "uncertain") return fail("compensation attempt $attempt $ps: ${prev["error"] ?: ""}")
            if (ps == "aborted") {
                val r = applyEvent(id, linkedMapOf("kind" to "compensation_failed", "reason" to "attempt never started"))
                if (r.refused != null) return rec
                val again = applyEvent(id, linkedMapOf("kind" to "retry"))
                return if (again.refused != null) r.record!! else runCompensation(again.record!!)
            }
            // pending / executing: another worker holds it, or a crash; stale ones are settled here
            if (t - lng(prev["executingAt"] ?: prev["startedAt"]) > o.effectTimeoutMs) {
                val settled = LinkedHashMap(prev)
                if (ps == "pending") {
                    settled["state"] = "aborted"; settled["error"] = "never started"
                } else {
                    settled["state"] = "uncertain"; settled["error"] = "no outcome recorded: the compensation may or may not have run"
                }
                settled["finishedAt"] = t
                operations.transition(prev["id"] as String, ps as String, settled)
                return runCompensation(store.get(id) ?: rec)
            }
            return rec
        }
        // re-read under the record: a concurrent retry or resolution wins
        val cur = store.get(id)
        if (cur == null || cur["state"] != "vetoed" || lng(cur["attempt"]) != attempt) {
            val ab = LinkedHashMap(orec)
            ab["state"] = "aborted"; ab["error"] = "the undo record moved on"; ab["finishedAt"] = now()
            operations.transition(opId, "pending", ab)
            return cur ?: rec
        }
        val running = LinkedHashMap(orec)
        running["state"] = "executing"
        running["executingAt"] = now()
        if (!operations.transition(opId, "pending", running)) return store.get(id) ?: rec
        val call = linkedMapOf<String, Any?>("operation" to op, "idempotencyKey" to opId, "undoOf" to id)
        val orig = (rec["effect"] as? Map<*, *>)?.get("result")
        if (orig != null) call["originalResult"] = orig
        call["record"] = cur.filterKeys { it != "pcactn" }
        val result: Any? = try {
            o.compensate!!.compensate(call)
        } catch (e: Exception) {
            val error = e.message ?: e.toString()
            try {
                val f = LinkedHashMap(running)
                f["state"] = "failed"; f["error"] = error; f["finishedAt"] = now()
                operations.transition(opId, "executing", f)
            } catch (x: Exception) {
                // the failure record is best effort: the compensation failure below is what counts
            }
            return fail("the compensating action failed: $error")
        }
        try {
            val c = LinkedHashMap(running)
            c["state"] = "committed"
            if (result != null) c["result"] = result
            c["finishedAt"] = now()
            operations.transition(opId, "executing", c)
        } catch (x: Exception) {
            // the operation record is best effort once the compensator has run
        }
        val ev = linkedMapOf<String, Any?>("kind" to "compensated")
        if (result != null) ev["result"] = result
        val r = applyEvent(id, ev)
        if (r.refused != null) return store.get(id) ?: rec
        return finishCompensated(r.record!!)
    }

    private fun decodePcactn(text: String): Map<String, Any?> {
        if (Pca.artifactTooLarge(text)) throw IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON)
        val v = Json.parse(text)
        if (v !is Map<*, *>) throw IllegalArgumentException("decodePCActn: not an object")
        return v as Map<String, Any?>
    }

    private fun vetoImpl(id: String, token: Any?, hasToken: Boolean, at: Any?, operator: String?, prepared: Map<String, Any?>?): UndoVetoResult = try {
        val cur = store.get(id)
        if (cur == null) {
            UndoVetoResult.refused("unknown", "no undo record $id")
        } else {
            var t = now()
            var checkAt: Long? = null
            var refusal: UndoVetoResult? = null
            val v: Map<String, Any?>
            if (hasToken) {
                if (at != null) {
                    if (!Json.isSafeInt(at) || Json.asLong(at) > t || Json.asLong(at) < lng(cur["opened_at"])) {
                        refusal = UndoVetoResult.refused("malformed", "a relayed veto time must lie between the opening of the window and now")
                    } else {
                        t = Json.asLong(at)
                        checkAt = t
                    }
                }
                val tok = if (token is String) Undo.decodeToken(token) else token
                val chk = if (refusal == null) Undo.tokenCheck(tok, signerPublic, cur, t) else "ok"
                if (refusal == null && chk != "ok") refusal = UndoVetoResult.refused(chk, "the undo token was refused ($chk)")
                v = if (refusal == null) linkedMapOf("at" to t, "via" to "token", "by" to cur["principal"], "evidence" to Undo.tokenDigest(m(tok))) else LinkedHashMap<String, Any?>()
            } else if (operator != null) {
                if (operator.isEmpty()) refusal = UndoVetoResult.refused("malformed", "an operator veto names the operator")
                v = linkedMapOf("at" to t, "via" to "operator", "by" to operator)
            } else {
                val p = LinkedHashMap(prepared!!)
                p["at"] = t
                v = p
            }
            if (refusal != null) {
                refusal
            } else {
                val r = applyEvent(id, linkedMapOf("kind" to "veto", "veto" to v), checkAt)
                if (r.refused != null) {
                    UndoVetoResult.refused(r.refused, r.reason ?: "")
                } else {
                    if (r.applied) notify(linkedMapOf("kind" to "vetoed", "record" to strip(r.record!!)))
                    val done = runCompensation(r.record!!)
                    UndoVetoResult.ok(done, !r.applied)
                }
            }
        }
    } catch (e: Exception) {
        UndoVetoResult.refused("malformed", "veto error (fail closed): ${e.message ?: "unknown"}")
    }

    /**
     * Veto with the principal's one-click [token] (an encoded string or the token map). [at] is the time a relay received it (it must lie
     * between the opening of the window and now); null means now.
     */
    @JvmOverloads
    fun veto(id: String, token: Any?, at: Any? = null): UndoVetoResult = vetoImpl(id, token, true, at, null, null)

    /** Veto as an authenticated operator of this server. */
    fun vetoAsOperator(id: String, operator: String): UndoVetoResult = vetoImpl(id, null, false, null, operator, null)

    /** Apply the relay's pending vetoes now (also done by every [finalizeDue]). Throws when the relay cannot be read. */
    fun syncRelay(): List<UndoVetoResult> {
        val relay = o.relay ?: return emptyList()
        val list = relay.pending()
        val out = ArrayList<UndoVetoResult>()
        for (x in list) {
            val xid = x["id"] as? String ?: continue
            // a forged or late relay entry is refused by the same checks as any veto
            out.add(veto(xid, x["token"], x["at"]))
        }
        return out
    }

    /** Run (or resume) the compensation of a vetoed record. */
    fun compensate(id: String): Map<String, Any?> = runCompensation(store.get(id) ?: throw UndoError("invalid", "no undo record $id"))

    /** After `compensation_failed`: start another attempt. */
    fun retry(id: String): Map<String, Any?> = runCompensation(must(id, linkedMapOf("kind" to "retry")).record!!)

    /** Close the windows whose time is up (`open -> finalized`) and commit their budget reservations; the ids finalized. */
    fun finalizeDue(): List<String> {
        val out = ArrayList<String>()
        try {
            syncRelay()
        } catch (e: Exception) {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            alert("critical", "veto_relay_failed", "*", "the veto relay could not be read; no window was finalized: ${e.message ?: "error"}")
            return out
        }
        // with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
        for (rec in store.list(UndoQuery("open", windowEndedBy = now() - 1 - (if (o.relay != null) UNDO_RELAY_GRACE_MS else 0L)))) {
            val r = applyEvent(rec["id"] as String, linkedMapOf("kind" to "finalize"))
            if (r.refused != null || !r.applied) continue
            out.add(rec["id"] as String)
            if (r.record!!["effect"] == null) alert("warning", "effect_unknown", rec["id"] as String, "the window closed without an effect report: reconcile the original operation")
            settleBudget(r.record, "commit")
            notify(linkedMapOf("kind" to "finalized", "record" to strip(r.record)))
        }
        return out
    }

    /** Resume every vetoed record's compensation, then finalize what is due; the ids that moved on. */
    fun recover(): List<String> {
        val out = ArrayList<String>()
        for (rec in store.list(UndoQuery("vetoed"))) {
            val r = runCompensation(rec)
            if (r["state"] != "vetoed") out.add(rec["id"] as String)
        }
        out.addAll(finalizeDue())
        return out
    }

    /** The grant [grantRef] was revoked: per policy, veto its open windows (`onRevocation = veto`) or alert and keep them (default). */
    fun onRevocation(grantRef: String): List<String> {
        val out = ArrayList<String>()
        for (rec in store.list(UndoQuery("open", grantRef = grantRef))) {
            val pc = decodePcactn(rec["pcactn"] as String)
            val grant = o.resolveGrant!!.resolve(rec["grant_ref"] as? String, pc)
            val act = m(rec["action"])
            val pol = if (grant != null) policyOf(linkedMapOf("verb" to act["verb"], "resource" to act["resource"]), grant) else emptyMap()
            if (((pol["onRevocation"] as? String) ?: "keep") == "veto") {
                val v = vetoImpl(rec["id"] as String, null, false, null, null, linkedMapOf("at" to 0L, "via" to "revocation", "by" to grantRef))
                if (v.ok) out.add(rec["id"] as String)
            } else {
                alert("warning", "revoked_open_window", rec["id"] as String, "grant $grantRef was revoked while this window is open; the principal can still undo it")
                notify(linkedMapOf("kind" to "revoked", "record" to strip(rec)))
            }
        }
        return out
    }

    /** The settlement and the veto result of [rollbackOnSlash]. */
    class SlashRollback(val settlement: Any?, val veto: UndoVetoResult)

    /**
     * A bond was slashed: the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window; only then is the
     * effect undone. [params] carries `claimId`.
     */
    @JvmOverloads
    fun rollbackOnSlash(params: Map<String, Any?>, bondsIn: UndoBondLedger? = null): SlashRollback {
        val bonds = bondsIn ?: o.bonds ?: throw UndoError("config", "rollbackOnSlash needs a bond ledger (pass bonds to the coordinator or to this call)")
        val claim = params["claimId"] as? String ?: throw UndoError("invalid", "rollbackOnSlash needs a claimId")
        val settlement = bonds.slashBond(params)
        val evidence = Pca.hashCanonical(linkedMapOf("d" to "atlas-pca/undo-slash-ref/v1", "settlement" to settlement))
        val recs = store.list(UndoQuery("open", bondRef = claim))
        val target = recs.firstOrNull() ?: store.get(claim)
            ?: return SlashRollback(settlement, UndoVetoResult.refused("unknown", "no undo record for bond $claim"))
        val v = vetoImpl(target["id"] as String, null, false, null, null, linkedMapOf("at" to 0L, "via" to "fraud_proof", "by" to claim, "evidence" to evidence))
        if (!v.ok) alert("critical", "slash_after_window", target["id"] as String, "the bond was slashed but the effect could not be rolled back: ${v.reason}")
        return SlashRollback(settlement, v)
    }

    private companion object {
        const val MAX_CAS = 64
    }
}
