package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * UNDO WINDOWS, the pure layer (packages/pca/src/undo.ts; spec undo-windows): a reversible action runs at once and the principal
 * gets a veto window in which they can undo it. This object lets any service verify what the undo coordinator (TypeScript, or the
 * hosted ledger) issues: the signed one-click undo token, the signed and hash-chained audit receipts of a record, the record state
 * machine ([transition]) and the window clamp. Admission, the durable ledger, compensation and notification are the coordinator's;
 * [Authorize.authorize] only takes its admission through [Authorize.UndoHook].
 *
 *     open --veto (now <= window_end)--> vetoed --compensated--> compensated
 *       |                                  \--compensation_failed--> compensation_failed --retry--> vetoed
 *       +--finalize (now > window_end)--> finalized
 *       +--abort (the effect never ran)--> finalized
 *
 * Signatures are plain Ed25519 over `utf8(domain) || strictCanonical(body)`. Values are the [Json] tree. Every check is total and
 * never throws; the signers throw only on a bad key.
 */
@Suppress("UNCHECKED_CAST")
object Undo {
    const val TOKEN_DOMAIN = "atlas-pca/undo-token/v1\u0000"
    const val RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\u0000"
    const val COMPENSATION_DOMAIN = "atlas-pca/undo-compensation/v1"
    const val RECEIPT_REF_DOMAIN = "atlas-pca/undo-receipt-ref/v1"
    const val TOKEN_REF_DOMAIN = "atlas-pca/undo-token-ref/v1"
    const val TOKEN_KIND = "pca-undo-token"
    const val RECEIPT_KIND = "pca-undo-receipt"

    /** The floor of a veto window: a human must be able to react. */
    const val MIN_WINDOW_MS = 30_000L
    const val DEFAULT_WINDOW_MS = 900_000L
    const val MAX_WINDOW_MS = 86_400_000L

    val STATES: List<String> = listOf("open", "vetoed", "compensated", "compensation_failed", "finalized")
    val EVENTS: List<String> = listOf("opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect")
    val VETO_VIAS: List<String> = listOf("token", "operator", "fraud_proof", "revocation")
    private val TOKEN_MEMBERS = listOf("v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig")
    private const val ID_MAX = 256

    /** A record id: a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F). */
    fun idOk(s: Any?): Boolean = s is String && s.isNotEmpty() && s.length <= ID_MAX && s.none { it.code <= 0x1f }

    private fun isObj(x: Any?): Boolean = x is Map<*, *>
    private fun obj(x: Any?): Map<String, Any?> = x as Map<String, Any?>
    private fun safeInt(x: Any?): Boolean = IntentJs.isInt(x)

    /** `utf8(domain) || strictCanonical(body)`. */
    private fun message(domain: String, body: Any?): ByteArray = IntentJs.message(domain, body)

    // ---- digests ----

    /** `hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?})` of a compensation. */
    fun compensationDigest(c: Map<String, Any?>): String {
        val m = linkedMapOf<String, Any?>(
            "d" to COMPENSATION_DOMAIN, "verb" to c["verb"], "resource" to c["resource"], "params" to c["params"],
            "undo_of" to c["undo_of"], "def_digest" to c["def_digest"],
        )
        if (c.containsKey("target_param")) m["target_param"] = c["target_param"]
        return Pca.hashCanonical(m)
    }

    // ---- the one-click undo token ----

    private fun tokenBody(t: Map<String, Any?>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in TOKEN_MEMBERS) if (k != "sig") b[k] = t[k]
        return b
    }

    /**
     * Sign the undo token of a record `{id, aud, principal, compensation_digest, render_digest?, window_end}` with the undo service's
     * 32-byte Ed25519 seed. The token binds the record, the compensation it starts, the render the human was shown and the window end.
     */
    fun signToken(rec: Map<String, Any?>, seed: ByteArray): Map<String, Any?> {
        val key = Keys.edFromSeed(seed)
        val body = linkedMapOf<String, Any?>(
            "v" to 1L, "kind" to TOKEN_KIND, "record" to rec["id"], "aud" to rec["aud"], "principal" to rec["principal"],
            "compensation_digest" to rec["compensation_digest"], "render_digest" to (rec["render_digest"] ?: ""), "exp" to rec["window_end"],
            "signer" to key.id(),
        )
        val out = LinkedHashMap(body)
        out["sig"] = Pca.b64(key.sign(message(TOKEN_DOMAIN, body)))
        return out
    }

    /**
     * Check a token against the pinned undo service key and the stored record `{id, aud, principal, compensation_digest,
     * render_digest?, window_end}` at [now]. Returns the FIRST failing check: `malformed`, `signer`, `signature`, `record`, `binding`,
     * `expired` (valid THROUGH `exp` inclusive), else `ok`. Never throws.
     */
    fun tokenCheck(token: Any?, expectedSigner: String, rec: Map<String, Any?>, now: Any?): String = try {
        tokenCheckUnchecked(token, expectedSigner, rec, now)
    } catch (e: RuntimeException) {
        "malformed"
    }

    private fun tokenCheckUnchecked(token: Any?, expectedSigner: String, rec: Map<String, Any?>, now: Any?): String {
        if (!isObj(token)) return "malformed"
        val t = obj(token)
        if (t.size != TOKEN_MEMBERS.size || !TOKEN_MEMBERS.all { t.containsKey(it) }) return "malformed"
        if (!OracleFacts.isOne(t["v"]) || t["kind"] != TOKEN_KIND || !idOk(t["record"]) || t["aud"] !is String || t["principal"] !is String ||
            t["compensation_digest"] !is String || t["render_digest"] !is String || !safeInt(t["exp"]) || t["signer"] !is String ||
            Pca.decodeB64uStrict(t["sig"], 64) == null
        ) return "malformed"
        if (t["signer"] != expectedSigner) return "signer"
        if (!IntentJs.verifyEd(expectedSigner, message(TOKEN_DOMAIN, tokenBody(t)), t["sig"])) return "signature"
        if (t["record"] != rec["id"]) return "record"
        if (t["aud"] != rec["aud"] || t["principal"] != rec["principal"] || t["compensation_digest"] != rec["compensation_digest"] ||
            t["render_digest"] != (rec["render_digest"] ?: "") || IntentJs.num(t["exp"]) != IntentJs.num(rec["window_end"])
        ) return "binding"
        if (!safeInt(now) || IntentJs.num(now)!! > IntentJs.num(t["exp"])!!) return "expired"
        return "ok"
    }

    /** The token as a URL-safe string: base64url of its strict-canonical JSON. */
    fun encodeToken(t: Map<String, Any?>): String = Pca.b64(Json.canonicalizeStrict(t).toByteArray(StandardCharsets.UTF_8))

    /** Inverse of [encodeToken]: a non-empty string of at most 4096 chars, strict base64url, strict UTF-8, a JSON object; else null. */
    fun decodeToken(s: Any?): Map<String, Any?>? = try {
        if (s !is String || s.isEmpty() || s.length > 4096) null
        else {
            val b = Pca.decodeB64uStrict(s, -1)
            if (b == null) null
            else {
                val text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString()
                Json.parse(text) as? Map<String, Any?>
            }
        }
    } catch (e: Exception) {
        null
    }

    /** `hashCanonical({d: "atlas-pca/undo-token-ref/v1", t})`. */
    fun tokenDigest(t: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to TOKEN_REF_DOMAIN, "t" to t))

    // ---- receipts ----

    private val RECEIPT_BODY = listOf("v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer")

    /** `hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r})` (the receipt WITH its signature). */
    fun receiptDigest(r: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RECEIPT_REF_DOMAIN, "r" to r))

    /** Sign a receipt body `{record, event, state, at, compensation_digest, prev, note}` with the undo service's 32-byte Ed25519 seed. */
    fun signReceipt(body: Map<String, Any?>, seed: ByteArray): Map<String, Any?> {
        val key = Keys.edFromSeed(seed)
        val b = linkedMapOf<String, Any?>(
            "v" to 1L, "kind" to RECEIPT_KIND, "record" to body["record"], "event" to body["event"], "state" to body["state"], "at" to body["at"],
            "compensation_digest" to body["compensation_digest"], "prev" to body["prev"], "note" to body["note"], "signer" to key.id(),
        )
        val out = LinkedHashMap(b)
        out["sig"] = Pca.b64(key.sign(message(RECEIPT_DOMAIN, b)))
        return out
    }

    /** True iff [r] is a well-formed receipt (exactly 11 members, a known event and state) signed by [expectedSigner] over exactly its content. */
    fun verifyReceipt(r: Any?, expectedSigner: String): Boolean = try {
        if (!isObj(r)) false
        else {
            val x = obj(r)
            if (!OracleFacts.isOne(x["v"]) || x["kind"] != RECEIPT_KIND || !idOk(x["record"]) || x["event"] !in EVENTS || x["state"] !in STATES ||
                !safeInt(x["at"]) || x["compensation_digest"] !is String || x["prev"] !is String || x["note"] !is String ||
                x["signer"] != expectedSigner || Pca.decodeB64uStrict(x["sig"], 64) == null
            ) false
            else if (x.size != 11) false
            else {
                val body = LinkedHashMap<String, Any?>()
                for (k in RECEIPT_BODY) body[k] = x[k]
                IntentJs.verifyEd(expectedSigner, message(RECEIPT_DOMAIN, body), x["sig"])
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Verify a record's receipt chain (`rec` = `{id, compensation_digest, state, receipts}`): every receipt verifies, names this record
     * and its compensation, `prev` links each to the one before ('' for the first), the first is `opened`, `at` never decreases, and the
     * last state is the record's state. Null when sound, else the reason. Never throws.
     */
    fun receiptChainError(rec: Map<String, Any?>, expectedSigner: String): String? = try {
        val rs = rec["receipts"] as? List<*>
        if (rs == null || rs.isEmpty()) "no receipts"
        else {
            var prev = ""
            var at = Double.NEGATIVE_INFINITY
            var err: String? = null
            for ((i, ro) in rs.withIndex()) {
                if (!verifyReceipt(ro, expectedSigner)) { err = "receipt $i does not verify"; break }
                val r = obj(ro)
                if (r["record"] != rec["id"] || r["compensation_digest"] != rec["compensation_digest"]) { err = "receipt $i is for another record"; break }
                if (r["prev"] != prev) { err = "receipt $i does not link to the previous one"; break }
                if (i == 0 && r["event"] != "opened") { err = "the first receipt is not opened"; break }
                val t = IntentJs.num(r["at"])!!
                if (t < at) { err = "receipt $i goes back in time"; break }
                prev = receiptDigest(r)
                at = t
            }
            err ?: if (obj(rs[rs.size - 1])["state"] == rec["state"]) null else "the last receipt does not state the record state"
        }
    } catch (e: RuntimeException) {
        "malformed receipts"
    }

    // ---- the pure transitions ----

    /**
     * The result of [transition]: `outcome` is `applied` ([record] is the next record, version bumped; [event] and [note] name the
     * receipt the store layer signs and links), `replayed` (the same transition already happened: nothing to write) or `refused`
     * ([code]: `window_closed`, `window_open`, `finalized`, `not_vetoed`, `vetoed`, `effect_recorded`, `not_failed`, `invalid`).
     */
    class Transition internal constructor(
        val outcome: String,
        val code: String? = null,
        val reason: String? = null,
        val record: Map<String, Any?>? = null,
        val event: String? = null,
        val note: String? = null,
    )

    private fun refused(code: String, reason: String) = Transition("refused", code, reason)

    /**
     * The state machine, pure: [rec] is not modified. [ev] is `{kind: veto, veto: {at, via, by}}`, `{kind: finalize}`,
     * `{kind: abort, reason}`, `{kind: effect, result?}`, `{kind: compensated, result?}`, `{kind: compensation_failed, reason}` or
     * `{kind: retry}`; [now] the trusted server clock (a safe integer). Total; never throws.
     */
    fun transition(rec: Any?, ev: Any?, now: Any?): Transition = try {
        transitionUnchecked(rec, ev, now)
    } catch (e: RuntimeException) {
        refused("invalid", "evaluation error (fail closed)")
    }

    private fun transitionUnchecked(recAny: Any?, evAny: Any?, nowAny: Any?): Transition {
        if (!isObj(recAny)) return refused("invalid", "malformed record")
        val rec = obj(recAny)
        val state = rec["state"]
        if (state !in STATES || !safeInt(rec["window_end"]) || !safeInt(rec["ver"])) return refused("invalid", "malformed record")
        if (!safeInt(nowAny)) return refused("invalid", "now must be a safe integer")
        val now = IntentJs.lng(nowAny)
        val windowEnd = IntentJs.lng(rec["window_end"])
        val ev = evAny as? Map<String, Any?> ?: return refused("invalid", "unknown event")
        fun next(patch: Map<String, Any?>, event: String, note: String = ""): Transition {
            val r = LinkedHashMap(rec)
            r.putAll(patch)
            r["ver"] = IntentJs.lng(rec["ver"]) + 1
            return Transition("applied", record = r, event = event, note = note)
        }
        fun cut(x: Any?, present: Boolean, n: Int): String = K3Sig.jsText(x, present).let { if (it.length > n) it.substring(0, n) else it }
        val replayed = Transition("replayed", record = rec)
        return when (ev["kind"]) {
            "veto" -> {
                val v = ev["veto"]
                val vm = v as? Map<*, *>
                if (vm == null || !safeInt(vm["at"]) || vm["via"] !in VETO_VIAS || vm["by"] !is String || (vm["by"] as String).isEmpty()) refused("invalid", "malformed veto")
                else if (state == "vetoed" || state == "compensated" || state == "compensation_failed") replayed
                else if (state == "finalized") refused("finalized", "the window is closed and the action is final")
                else if (now > windowEnd) refused("window_closed", "the veto window closed at $windowEnd")
                else next(mapOf("state" to "vetoed", "veto" to LinkedHashMap(vm)), "vetoed", vm["via"] as String)
            }
            "finalize" ->
                if (state == "finalized") replayed
                else if (state != "open") refused("vetoed", "a $state record is not finalized")
                else if (now <= windowEnd) refused("window_open", "the veto window is open until $windowEnd")
                else next(mapOf("state" to "finalized", "outcome" to linkedMapOf<String, Any?>("at" to now, "status" to "finalized")), "finalized")
            "abort" ->
                if (state == "finalized" && (rec["outcome"] as? Map<*, *>)?.get("status") == "aborted") replayed
                else if (state != "open" && state != "vetoed") refused("finalized", "a $state record cannot be aborted")
                else if (rec.containsKey("effect")) refused("effect_recorded", "the effect ran: it can only be compensated or finalized")
                else next(
                    mapOf("state" to "finalized", "outcome" to linkedMapOf<String, Any?>("at" to now, "status" to "aborted", "reason" to cut(ev["reason"], ev.containsKey("reason"), 512))),
                    "aborted", cut(ev["reason"], ev.containsKey("reason"), 128),
                )
            "effect" ->
                if (rec.containsKey("effect")) replayed
                else if (state != "open" && state != "vetoed") refused("finalized", "a $state record takes no effect report")
                else next(mapOf("effect" to linkedMapOf<String, Any?>("at" to now).also { if (ev.containsKey("result")) it["result"] = ev["result"] }), "effect")
            "compensated" ->
                if (state == "compensated") replayed
                else if (state != "vetoed" && state != "compensation_failed") refused("not_vetoed", "a $state record is not being compensated")
                else next(
                    mapOf("state" to "compensated", "outcome" to linkedMapOf<String, Any?>("at" to now, "status" to "compensated").also { if (ev.containsKey("result")) it["result"] = ev["result"] }),
                    "compensated",
                )
            "compensation_failed" ->
                if (state == "compensation_failed") replayed
                else if (state != "vetoed") refused("not_vetoed", "a $state record is not being compensated")
                else next(
                    mapOf("state" to "compensation_failed", "outcome" to linkedMapOf<String, Any?>("at" to now, "status" to "compensation_failed", "reason" to cut(ev["reason"], ev.containsKey("reason"), 512))),
                    "compensation_failed", cut(ev["reason"], ev.containsKey("reason"), 128),
                )
            "retry" ->
                if (state != "compensation_failed") refused("not_failed", "a $state record is not retried")
                // an attempt counter that is not a safe integer is a malformed record (fail closed)
                else if (!safeInt(rec["attempt"])) refused("invalid", "malformed record")
                else next(mapOf("state" to "vetoed", "attempt" to IntentJs.lng(rec["attempt"]) + 1), "retried")
            else -> refused("invalid", "unknown event")
        }
    }

    // ---- the window ----

    /**
     * Clamp a requested window (ms) into [max(MIN_WINDOW_MS, minMs), min(maxMs, MAX_WINDOW_MS)] (the upper bound never below the lower);
     * a null or non-finite [requested] takes [defaultMs] (default [DEFAULT_WINDOW_MS]). Floors the result.
     */
    @JvmOverloads
    fun resolveWindow(requested: Any?, minMs: Double? = null, maxMs: Double? = null, defaultMs: Double? = null): Long {
        val min = maxOf(MIN_WINDOW_MS.toDouble(), minMs ?: MIN_WINDOW_MS.toDouble())
        val max = maxOf(min, minOf(maxMs ?: MAX_WINDOW_MS.toDouble(), MAX_WINDOW_MS.toDouble()))
        val r = IntentJs.num(requested)
        val want = if (r != null && r.isFinite()) r else (defaultMs ?: DEFAULT_WINDOW_MS.toDouble())
        return Math.floor(minOf(max, maxOf(min, want))).toLong()
    }

    // ---- the authorize admission ----

    /**
     * What an undo coordinator answers through [Authorize.UndoHook]: the action runs now under the veto window of record [id] until
     * [windowEnd] (epoch ms), undone by [compensationVerb] on [compensationResource]. The hook returns one ONLY after the record is
     * durably opened by the coordinator.
     */
    class Admission(val id: String, val windowEnd: Long, val compensationVerb: String, val compensationResource: String) {
        /** The `undo_window` obligation the allow carries: `{kind, params: {id, window_end}, due: window_end}`. */
        fun obligation(): Map<String, Any?> = linkedMapOf(
            "kind" to "undo_window", "params" to linkedMapOf<String, Any?>("id" to id, "window_end" to windowEnd), "due" to windowEnd,
        )
    }
}
