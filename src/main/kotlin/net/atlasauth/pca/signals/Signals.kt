package net.atlasauth.pca.signals

import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Json

/**
 * Shared Signals Framework (SSF / CAEP) for Proof-Carrying Authority: the active revocation and mid-run kill-switch channel.
 * A transmitter emits a Security Event Token (SET, RFC 8417: a JWT with an events claim); subscribers fold those events into local
 * [RevocationState] they consult on every request, next to the core verifier. This builds and verifies SETs for CAEP
 * session-revoked / credential-change and the PCA event types (grant-revoked, kill-switch, intent-revoked), keeps the
 * subscriber-side state, and offers the fail-closed [receiveSET] path. SETs are signed EdDSA; keys are JWK maps.
 */
@Suppress("UNCHECKED_CAST")
object Signals {
    /** RFC 8417 section 2.3: a SET carries typ "secevent+jwt" so it cannot be confused with an access or ID token. */
    const val SET_TYP = "secevent+jwt"

    /** The JWS algorithm SETs are signed and verified with. */
    const val SET_ALG = "EdDSA"

    const val SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    const val CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    const val GRANT_REVOKED = "https://atlasauth.net/caep/grant-revoked"
    const val KILL_SWITCH = "https://atlasauth.net/caep/kill-switch"
    const val INTENT_REVOKED = "https://atlasauth.net/caep/intent-revoked"
    const val VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification"
    const val RISK_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
    const val ASSURANCE_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

    /** Event-type URIs by the reference's member names. */
    @JvmField
    val EVENT_TYPES: Map<String, String> = linkedMapOf(
        "sessionRevoked" to SESSION_REVOKED,
        "credentialChange" to CREDENTIAL_CHANGE,
        "grantRevoked" to GRANT_REVOKED,
        "killSwitch" to KILL_SWITCH,
        "intentRevoked" to INTENT_REVOKED,
        "verification" to VERIFICATION,
        "riskLevelChange" to RISK_LEVEL_CHANGE,
        "assuranceLevelChange" to ASSURANCE_LEVEL_CHANGE,
    )

    /** OpenID RISC 1.0 event types that end an account's standing: treated as revoking every grant of the mapped agent. */
    @JvmField
    val RISC_EVENT_TYPES: Map<String, String> = linkedMapOf(
        "sessionsRevoked" to "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
        "accountDisabled" to "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        "accountPurged" to "https://schemas.openid.net/secevent/risc/event-type/account-purged",
        "credentialCompromise" to "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
    )

    /** Default capacity of [createInMemorySetReplayStore]. */
    const val SET_INMEMORY_MAX_ENTRIES = 100_000

    // ---- build / verify ----

    /**
     * Build a signed Security Event Token (RFC 8417): typ secevent+jwt, iss, iat, a random jti, aud, the events map and, when
     * given, sub plus a structured sub_id. args: {events, issuer, audience (string or list), subject?, key (a private Ed25519 JWK)}.
     */
    @JvmStatic
    fun buildSET(args: Map<String, Any?>): String {
        val events = JsV.member(args, "events")
        val keys = if (events is Map<*, *>) events.size else if (events is List<*>) events.size else 0
        if (!(events is Map<*, *> || events is List<*>) || keys == 0) {
            throw IllegalArgumentException("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)")
        }
        val payload = LinkedHashMap<String, Any?>()
        payload["events"] = events
        val hasSubject = JsV.has(args, "subject")
        if (hasSubject) {
            val sid = LinkedHashMap<String, Any?>()
            sid["format"] = "opaque"
            sid["id"] = args["subject"]
            payload["sub_id"] = sid
        }
        if (JsV.has(args, "issuer")) payload["iss"] = args["issuer"] // an absent one is undefined: omitted from the JSON
        payload["iat"] = Json.Num(Math.floorDiv(System.currentTimeMillis(), 1000L).toString())
        payload["jti"] = UUID.randomUUID().toString()
        if (JsV.has(args, "audience")) payload["aud"] = args["audience"]
        if (hasSubject) payload["sub"] = args["subject"]
        val header = LinkedHashMap<String, Any?>()
        header["alg"] = SET_ALG
        header["typ"] = SET_TYP
        return Jose.signJwt(header, payload, args["key"] as Map<String, Any?>)
    }

    /** The parsed result of a verified SET. [jti] is the SET id (RFC 8417 requires it): de-dup replays on this. [sub] is the SET-level subject or null. */
    class ParsedSet internal constructor(
        @JvmField val events: Map<String, Any?>,
        @JvmField val iss: String,
        @JvmField val jti: String,
        @JvmField val sub: String?,
        /** The full verified JWT payload. */
        @JvmField val payload: Map<String, Any?>,
    ) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["events"] = events
            m["iss"] = iss
            m["jti"] = jti
            if (sub != null) m["sub"] = sub
            m["payload"] = payload
            return m
        }
    }

    private fun parseEvents(raw: Any?): Map<String, Any?> {
        if (raw !is Map<*, *>) throw IllegalArgumentException("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)")
        if (raw.isEmpty()) throw IllegalArgumentException("SET invalid: `events` claim is empty (RFC 8417 §2.2)")
        for ((k, v) in raw) {
            if (v !is Map<*, *>) throw IllegalArgumentException("SET invalid: event payload for `$k` is not a JSON object (RFC 8417 §2.2)")
        }
        return raw as Map<String, Any?>
    }

    private fun strings(o: Any?, what: String): List<String> {
        val out = ArrayList<String>()
        if (o is String) out.add(o)
        else if (o is List<*>) {
            for (x in o) {
                if (x !is String) throw JsTypeError("$what must be a string or a list of strings")
                out.add(x)
            }
        } else throw JsTypeError("$what must be a string or a list of strings")
        return out
    }

    /**
     * Verify a SET's signature (EdDSA) and standard claims, then parse it. Throws on any invalid signature, wrong key, failed claim
     * check (iss / aud / typ / exp / nbf), or a malformed or empty events map. verifyKey is a public Ed25519 JWK. opts (may be
     * null): issuer and audience (string or list), clockTolerance (seconds), currentDate (epoch ms), typ, requireTyp (false skips
     * the typ check).
     */
    @JvmStatic
    fun verifySET(set: Any?, verifyKey: Any?, opts: Map<String, Any?>?): ParsedSet {
        Jose.assertCanonicalCompactJws(set) // canonical-spelling gate BEFORE the JOSE layer (one accepted string form)
        var issuer: String? = null
        var audience: List<String>? = null
        var clockTolerance: Double? = null
        var currentDateMs: Double? = null
        var typ: String? = null
        var issuerList: List<String>? = null
        if (JsV.has(opts, "issuer")) {
            val i = opts!!["issuer"]
            if (i is String) issuer = i else issuerList = strings(i, "issuer")
        }
        if (JsV.has(opts, "audience")) audience = strings(opts!!["audience"], "audience")
        if (JsV.has(opts, "clockTolerance")) {
            val c = opts!!["clockTolerance"]
            if (!JsV.isNumber(c)) throw JsTypeError("clockTolerance must be a number")
            clockTolerance = JsV.num(c)
        }
        if (JsV.has(opts, "currentDate")) {
            val c = opts!!["currentDate"]
            if (!JsV.isFinite(c)) throw JsTypeError("currentDate must be a finite epoch time in ms")
            currentDateMs = JsV.num(c)!!.toLong().toDouble()
        }
        if (JsV.opt(opts, "requireTyp") != false) typ = JsV.or(JsV.opt(opts, "typ"), SET_TYP) as String
        val jo = Jose.JwtOptions(typ = typ, issuer = issuer, audience = audience, clockTolerance = clockTolerance, currentDateMs = currentDateMs, algorithms = listOf(SET_ALG))
        val v = Jose.jwtVerify(set as String, verifyKey, jo)
        val payload = v.payload
        if (issuerList != null) {
            if (!payload.containsKey("iss")) throw Jose.JoseException("missing required \"iss\" claim")
            if (!issuerList.contains(payload["iss"])) throw Jose.JoseException("unexpected \"iss\" claim value")
        }
        val iss = payload["iss"] as? String ?: throw IllegalArgumentException("SET invalid: missing or non-string `iss`")
        val jti = payload["jti"] as? String ?: throw IllegalArgumentException("SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)")
        val events = parseEvents(payload["events"])
        return ParsedSet(events, iss, jti, payload["sub"] as? String, payload)
    }

    // ---- revocation state ----

    /** A fresh, empty revocation state. */
    @JvmStatic
    fun createRevocationState(): RevocationState = RevocationState()

    /** Object.entries over an events container: a null / absent one throws (as JavaScript does), a non-object has no entries. */
    private fun entries(events: Any?): List<Pair<String, Any?>> {
        if (events == null) throw JsTypeError("Cannot convert undefined or null to object")
        val out = ArrayList<Pair<String, Any?>>()
        if (events is Map<*, *>) for ((k, v) in events) out.add((k as String) to v)
        return out
    }

    private fun eventsOf(parsed: Any?): Any? = if (parsed is ParsedSet) parsed.events else JsV.member(parsed, "events")

    private fun payloadOf(parsed: Any?): Any? = if (parsed is ParsedSet) parsed.payload else JsV.member(parsed, "payload")

    private fun tsOf(ev: Any?): Double {
        val t = JsV.member(ev, "event_timestamp")
        return if (JsV.isNumber(t)) JsV.num(t)!! else 0.0
    }

    /**
     * Fold one verified SET into the state. grant-revoked adds its grant_ref to the revoked set; kill-switch revokes every grant
     * of its agent (and any explicit grant_ref); intent-revoked records its pca-intent: ids. Each key keeps the MAX event_timestamp
     * seen, so a stale event never regresses the state and, revocation being monotone, never un-revokes. The two CAEP standard
     * events are folded but do not by themselves revoke a PCA grant. parsed is a [ParsedSet] or its JSON form. Returns state.
     */
    @JvmStatic
    fun applySET(state: RevocationState, parsed: Any?): RevocationState {
        for ((type, ev) in entries(eventsOf(parsed))) {
            val ts = tsOf(ev)
            if (type == GRANT_REVOKED) {
                val ref = JsV.opt(ev, "grant_ref")
                if (JsV.nonEmpty(ref)) RevocationState.recordMax(state.revokedGrants, ref as String, ts)
            } else if (type == KILL_SWITCH) {
                val agent = JsV.opt(ev, "agent")
                val ref = JsV.opt(ev, "grant_ref")
                if (JsV.nonEmpty(agent)) RevocationState.recordMax(state.killedAgents, agent as String, ts)
                if (JsV.nonEmpty(ref)) RevocationState.recordMax(state.revokedGrants, ref as String, ts)
            } else if (type == INTENT_REVOKED) {
                val ids = JsV.opt(ev, "ids")
                if (ids is List<*>) {
                    for (id in ids) {
                        if (id is String && id.startsWith("pca-intent:")) {
                            val m = state.revokedIntentIds ?: LinkedHashMap<String, Double>().also { state.revokedIntentIds = it }
                            RevocationState.recordMax(m, id, ts)
                        }
                    }
                }
            }
        }
        return state
    }

    /** Has a pushed intent-revoked event named this intent revocation id? (Best effort; the epoch pull bound decides.) */
    @JvmStatic
    fun isIntentRevoked(state: RevocationState, id: Any?): Boolean = id is String && state.revokedIntentIds?.containsKey(id) == true

    /**
     * Is this grant revoked? True if the grant_ref was revoked directly, or (when agent is given) a kill-switch revoked that agent.
     * The check a resource server runs next to the core verifier: a revoked grant is denied even with a valid, in-budget PCActn.
     */
    @JvmStatic
    fun isRevoked(state: RevocationState, grantRef: Any?, agent: Any?): Boolean {
        if (grantRef is String && state.revokedGrants.containsKey(grantRef)) return true
        return agent is String && state.killedAgents.containsKey(agent)
    }

    private fun setTimestamp(parsed: Any?): Double {
        val events = eventsOf(parsed) ?: throw JsTypeError("Cannot convert undefined or null to object")
        var min = Double.POSITIVE_INFINITY
        val values: List<Any?> = if (events is Map<*, *>) ArrayList(events.values) else if (events is List<*>) ArrayList(events) else emptyList()
        for (ev in values) {
            val t = JsV.member(ev, "event_timestamp")
            if (JsV.isNumber(t) && JsV.num(t)!! < min) min = JsV.num(t)!!
        }
        return if (min.isNaN() || min.isInfinite()) 0.0 else min
    }

    /**
     * Fold a sequence of verified SETs into one state, applying them in event_timestamp order (ascending). applySET is itself
     * order-independent, so the order makes the fold deterministic whatever order a push stream delivers in. state may be null.
     */
    @JvmStatic
    fun streamProcessor(parsedSets: List<*>, state: RevocationState?): RevocationState {
        val s = state ?: createRevocationState()
        val keyed = parsedSets.map { it to setTimestamp(it) }
        val ordered = keyed.sortedWith(Comparator { a, b -> Math.signum(a.second - b.second).toInt() })
        for (p in ordered) applySET(s, p.first)
        return s
    }

    // ---- replay store ----

    /**
     * Single-process store, explicitly bounded: state is lost on restart and not shared across processes. When maxEntries live
     * (unexpired) entries are held, a further new jti makes addIfAbsent THROW (receiveSET then refuses with replay_store_error)
     * instead of evicting a live entry, so a flood can never reopen a replay window. opts (may be null): maxEntries.
     */
    @JvmStatic
    fun createInMemorySetReplayStore(opts: Map<String, Any?>?): SetReplayStore {
        val m = JsV.or(JsV.opt(opts, "maxEntries"), Json.Num(SET_INMEMORY_MAX_ENTRIES.toString()))
        val d = JsV.num(m)
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || d < 1) throw SignalsError("misconfigured", "maxEntries must be a positive integer")
        val max: Double = d
        val seen = LinkedHashMap<String, Double>()
        return SetReplayStore { jti, expiresAtSec, nowSec ->
            synchronized(seen) {
                if (!nowSec.isFinite() || !expiresAtSec.isFinite()) return@synchronized false
                val held = seen[jti]
                if (held != null && !(nowSec >= held)) return@synchronized false
                if (held == null && seen.size >= max) {
                    val it = seen.values.iterator()
                    while (it.hasNext()) if (nowSec >= it.next()) it.remove()
                    if (seen.size >= max) throw IllegalStateException("replay store is full")
                }
                seen[jti] = expiresAtSec
                true
            }
        }
    }

    /**
     * Conformance suite for a [SetReplayStore]. Returns the list of failed checks (empty = conformant). make returns a FRESH,
     * empty store on each call.
     */
    @JvmStatic
    fun runSetReplayStoreConformance(make: () -> SetReplayStore): List<String> {
        val failures = ArrayList<String>()
        val s = make()
        if (!s.addIfAbsent("a", 200.0, 100.0)) failures.add("first sight of a jti returns true")
        if (s.addIfAbsent("a", 200.0, 101.0)) failures.add("second sight of the same jti returns false")
        if (!s.addIfAbsent("b", 200.0, 101.0)) failures.add("a different jti is independent")
        if (s.addIfAbsent("a", 200.0, 199.0)) failures.add("still seen one second before expiry")
        val t = make()
        t.addIfAbsent("c", 200.0, 100.0)
        if (!t.addIfAbsent("c", 400.0, 200.0)) failures.add("an expired entry may be added again (nowSec >= expiresAtSec)")
        val u = make()
        val ex = Executors.newFixedThreadPool(16)
        var wins = 0
        try {
            val fs = (0 until 16).map { ex.submit(Callable { u.addIfAbsent("race", 200.0, 100.0) }) }
            for (f in fs) if (f.get()) wins++
        } finally {
            ex.shutdown()
        }
        if (wins != 1) failures.add("16 concurrent adds of one jti: exactly one wins (got $wins)")
        return failures
    }

    // ---- receiver ----

    /** The outcome of [receiveSET]: ok with the parsed SET, or a refusal code and reason. Every refusal is a value, never a throw. */
    class ReceiveSetResult internal constructor(
        @JvmField val ok: Boolean,
        @JvmField val parsed: ParsedSet?,
        /** misconfigured, oversize, malformed, verify_failed, iat_missing, iat_future, iat_stale, unmapped_subject, replay, replay_store_error. */
        @JvmField val code: String?,
        @JvmField val reason: String?,
    ) {
        fun toMap(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) m["parsed"] = parsed!!.toMap() else { m["code"] = code; m["reason"] = reason }
            return m
        }
    }

    private fun fails(code: String, reason: String) = ReceiveSetResult(false, null, code, reason)

    private fun msg(e: RuntimeException, dflt: String): String = e.message ?: dflt

    /**
     * The recommended receive path: size cap, canonical spelling, EdDSA signature, typ, required iss and aud, iat freshness window,
     * atomic jti replay guard, then fold into state. The jti is recorded only after every other check passed, so a forged token
     * cannot burn a real SET's id. Fails closed on every error, including a replay store that throws (the SET is NOT applied).
     * opts: issuer, audience, replayStore ([SetReplayStore]), state ([RevocationState]), maxAgeSec (all required),
     * clockSkewSec (default 60), nowSec, maxBytes (default 16384), standardRevocations (a map as for [planStandardRevocations]).
     */
    @JvmStatic
    fun receiveSET(set: Any?, verifyKey: Any?, opts: Map<String, Any?>?): ReceiveSetResult {
        if (opts == null || !JsV.has(opts, "issuer") || !JsV.has(opts, "audience") || opts["replayStore"] !is SetReplayStore ||
            !JsV.truthy(opts["state"]) || !JsV.isFinite(opts["maxAgeSec"]) || JsV.num(opts["maxAgeSec"])!! <= 0
        ) {
            return fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required")
        }
        val maxAge = JsV.num(opts["maxAgeSec"])!!
        val maxBytes = JsV.or(opts["maxBytes"], Json.Num("16384"))
        if (set !is String || set.length > JsV.num(maxBytes)!!) return fails("oversize", "SET is not a string or exceeds maxBytes")
        try {
            Jose.assertCanonicalCompactJws(set)
        } catch (e: RuntimeException) {
            return fails("malformed", msg(e, "not a canonical compact JWS"))
        }
        val nowSec = if (opts["nowSec"] != null) JsV.num(opts["nowSec"])!! else Math.floor(System.currentTimeMillis().toDouble() / 1000)
        val parsed: ParsedSet
        try {
            val vo = LinkedHashMap<String, Any?>()
            vo["issuer"] = opts["issuer"]
            vo["audience"] = opts["audience"]
            vo["currentDate"] = JsV.numOf(nowSec * 1000)
            parsed = verifySET(set, verifyKey, vo)
        } catch (e: RuntimeException) {
            return fails("verify_failed", msg(e, "verification failed"))
        }
        val iatO = parsed.payload["iat"]
        if (!JsV.isFinite(iatO)) return fails("iat_missing", "SET has no numeric iat")
        val iat = JsV.num(iatO)!!
        val skew = if (opts["clockSkewSec"] != null) JsV.num(opts["clockSkewSec"])!! else 60.0
        if (!(nowSec.isFinite() && skew.isFinite() && iat <= nowSec + skew)) return fails("iat_future", "SET iat is in the future")
        if (!(nowSec - iat <= maxAge)) return fails("iat_stale", "SET is older than " + JsV.str(JsV.numOf(maxAge)) + "s")
        var plan: StandardRevocationPlan? = null
        if (JsV.has(opts, "standardRevocations")) {
            try {
                plan = planStandardRevocations(parsed, opts["standardRevocations"] as Map<String, Any?>?)
            } catch (e: RuntimeException) {
                return fails("unmapped_subject", msg(e, "a revocation event could not be mapped to an agent"))
            }
        }
        val fresh: Boolean
        try {
            fresh = (opts["replayStore"] as SetReplayStore).addIfAbsent(parsed.jti, iat + maxAge + skew, nowSec)
        } catch (e: RuntimeException) {
            return fails("replay_store_error", msg(e, "replay store failed"))
        }
        if (!fresh) return fails("replay", "jti '${parsed.jti}' has already been received")
        val state = opts["state"] as RevocationState
        applySET(state, parsed)
        if (plan != null) applyStandardPlan(state, plan)
        return ReceiveSetResult(true, parsed, null, null)
    }

    // ---- standard (CAEP / RISC) revocation events ----

    /** What [planStandardRevocations] decided; applying it is a separate, infallible step. */
    class StandardRevocationPlan {
        /** (agent, event_timestamp) pairs to add to killedAgents. */
        @JvmField val agents: MutableList<Pair<Any?, Double>> = ArrayList()

        /** Event types that revoke but whose subject named no known agent (nothing was revoked for them). */
        @JvmField val unmapped: MutableList<String> = ArrayList()

        fun toMap(): Map<String, Any?> {
            val a = agents.map { listOf(it.first, JsV.numOf(it.second)) }
            val m = LinkedHashMap<String, Any?>()
            m["agents"] = a
            m["unmapped"] = ArrayList<Any?>(unmapped)
            return m
        }
    }

    /** Maps an event's RFC 9493 subject to the agent id a PCActn's agentOf yields; returns a non-string / empty value when the subject names no agent. */
    fun interface SubjectToAgent {
        fun apply(subject: Map<String, Any?>): Any?
    }

    private fun defaultSubjectToAgent(subject: Map<String, Any?>): Any? {
        val id = subject["id"]
        return if ("opaque" == subject["format"] && JsV.nonEmpty(id)) id else null
    }

    private fun isRevokingStandardEvent(type: String, ev: Any?): Boolean {
        if (type == SESSION_REVOKED) return true
        if (type == CREDENTIAL_CHANGE) return "create" != JsV.member(ev, "change_type") // unknown or absent counts as a change (fail closed)
        return RISC_EVENT_TYPES.containsValue(type)
    }

    /**
     * Decide, without touching any state, which agents a verified SET's standard events revoke: CAEP session-revoked, CAEP
     * credential-change (every change_type except create; an absent or unknown one counts as a change) and the RISC types in
     * [RISC_EVENT_TYPES]. The subject is the event's own subject, else the SET-level sub_id. A revoking event with no subject,
     * or one subjectToAgent cannot map, is listed in unmapped (or throws unmapped_subject under failOnUnmapped).
     * opts (may be null): subjectToAgent ([SubjectToAgent]), failOnUnmapped (true to throw).
     */
    @JvmStatic
    fun planStandardRevocations(parsed: Any?, opts: Map<String, Any?>?): StandardRevocationPlan {
        val custom = JsV.opt(opts, "subjectToAgent")
        val toAgent: SubjectToAgent = if (custom is SubjectToAgent) custom else SubjectToAgent { defaultSubjectToAgent(it) }
        val plan = StandardRevocationPlan()
        val sid = JsV.member(payloadOf(parsed), "sub_id")
        val setSubject = sid as? Map<String, Any?>
        for ((type, ev) in entries(eventsOf(parsed))) {
            if (!isRevokingStandardEvent(type, ev)) continue
            val evSubject = JsV.member(ev, "subject")
            val own = evSubject as? Map<String, Any?> ?: setSubject
            var agent: Any? = null
            if (own != null && own["format"] is String) {
                agent = try {
                    toAgent.apply(own)
                } catch (e: RuntimeException) {
                    null
                }
            }
            if (!JsV.nonEmpty(agent)) {
                if (JsV.opt(opts, "failOnUnmapped") == true) throw SignalsError("unmapped_subject", "event '$type' names no mappable agent")
                plan.unmapped.add(type)
                continue
            }
            plan.agents.add(agent to tsOf(ev))
        }
        return plan
    }

    private fun applyStandardPlan(state: RevocationState, plan: StandardRevocationPlan) {
        for (p in plan.agents) RevocationState.recordMax(state.killedAgents, p.first as String, p.second)
    }

    private fun assertRevocationState(state: RevocationState?): RevocationState =
        state ?: throw SignalsError("misconfigured", "state must come from createRevocationState()")

    /** [planStandardRevocations] then apply: monotone, max-timestamp, like [applySET]. Returns the plan that was applied. */
    @JvmStatic
    fun applyStandardRevocations(state: RevocationState?, parsed: Any?, opts: Map<String, Any?>?): StandardRevocationPlan {
        val st = assertRevocationState(state)
        val plan = planStandardRevocations(parsed, opts)
        applyStandardPlan(st, plan)
        return plan
    }

    // ---- adapters for authorize() ----

    /** A revocation hook over a verification context {pcactn, grant}: returns {enforced: true, ok: true} or {enforced: true, ok: false, reason}. */
    fun interface Hook {
        fun check(ctx: Map<String, Any?>): Map<String, Any?>
    }

    private fun leafHolderAgent(ctx: Map<String, Any?>): Any? {
        val chain = JsV.member(JsV.member(ctx, "pcactn"), "cap_chain") ?: throw JsTypeError("cap_chain is missing")
        if (chain !is List<*> || chain.isEmpty()) return null
        return JsV.opt(chain[chain.size - 1], "holder")
    }

    private fun revocationReason(state: RevocationState, pcactn: Any?, grant: Any?, agentOf: (Map<String, Any?>) -> Any?): String? {
        try {
            val ref = JsV.member(pcactn, "grant_ref")
            if (!JsV.nonEmpty(ref)) return "grant_ref is missing"
            if (state.revokedGrants.containsKey(ref as String)) return "grant revoked by signal"
            val gid = JsV.opt(grant, "id")
            if (gid is String && state.revokedGrants.containsKey(gid)) return "grant revoked by signal"
            val ctx = LinkedHashMap<String, Any?>()
            ctx["pcactn"] = pcactn
            ctx["grant"] = grant
            val agent = agentOf(ctx)
            if (!JsV.nonEmpty(agent)) return "agent could not be determined"
            if (state.killedAgents.containsKey(agent as String)) return "agent killed by signal"
            return null
        } catch (e: RuntimeException) {
            return "revocation check error (fail closed)"
        }
    }

    /**
     * A revocation hook for the core verifier. It reads state LIVE on every call, so SETs folded in by [receiveSET] take effect
     * on the next request. It always reports enforced: true; a revoked grant, a revoked or undeterminable agent, or any error denies.
     * agentOf (null = the PCActn's leaf holder key) names the agent a kill-switch targets.
     */
    @JvmStatic
    fun createRevocationHook(state: RevocationState?, agentOf: ((Map<String, Any?>) -> Any?)?): Hook {
        val st = assertRevocationState(state)
        val f: (Map<String, Any?>) -> Any? = agentOf ?: { leafHolderAgent(it) }
        return Hook { ctx ->
            val reason = revocationReason(st, JsV.opt(ctx, "pcactn"), JsV.opt(ctx, "grant"), f)
            val out = LinkedHashMap<String, Any?>()
            out["enforced"] = true
            out["ok"] = reason == null
            if (reason != null) out["reason"] = reason
            out
        }
    }

    /** The same decision in the shape authorizeExecution takes as isRevoked(grant, pcactn): true when revoked or undeterminable (fail closed). */
    @JvmStatic
    fun createIsRevoked(state: RevocationState?, agentOf: ((Map<String, Any?>) -> Any?)?): (Any?, Any?) -> Boolean {
        val st = assertRevocationState(state)
        val f: (Map<String, Any?>) -> Any? = agentOf ?: { leafHolderAgent(it) }
        return { grant, pcactn -> revocationReason(st, pcactn, grant, f) != null }
    }

    // ---- snapshot / restore ----

    /** Copy state into a plain JSON-safe snapshot {v: 1, grants, agents, intents} for you to persist. An empty state after a restart revokes nothing. */
    @JvmStatic
    fun snapshotRevocationState(state: RevocationState?): Map<String, Any?> {
        val m = assertRevocationState(state).toMap()
        val out = LinkedHashMap<String, Any?>()
        out["v"] = Json.Num("1")
        out["grants"] = m["grants"]
        out["agents"] = m["agents"]
        out["intents"] = m["intents"] ?: ArrayList<Any?>()
        return out
    }

    private fun pairs(v: Any?, what: String): List<Pair<String, Double>> {
        if (v !is List<*>) throw SignalsError("bad_snapshot", "$what is not an array")
        val out = ArrayList<Pair<String, Double>>()
        for (p in v) {
            if (p !is List<*> || p.size != 2 || !JsV.nonEmpty(p[0]) || !JsV.isFinite(p[1])) {
                throw SignalsError("bad_snapshot", "$what holds an entry that is not [string, number]")
            }
            out.add((p[0] as String) to JsV.num(p[1])!!)
        }
        return out
    }

    /**
     * Merge a snapshot into [into] (a fresh state by default). Strict: any shape error throws bad_snapshot, leaving [into] untouched.
     * Merging is monotone (max timestamp), so restoring never un-revokes anything.
     */
    @JvmStatic
    @JvmOverloads
    fun restoreRevocationState(snapshot: Any?, into: RevocationState? = createRevocationState()): RevocationState {
        val target = assertRevocationState(into)
        if (snapshot !is Map<*, *> || !JsV.isNumber(snapshot["v"]) || JsV.num(snapshot["v"]) != 1.0) {
            throw SignalsError("bad_snapshot", "snapshot is not a version 1 object")
        }
        for (k in snapshot.keys) {
            if (k !in listOf("v", "grants", "agents", "intents")) throw SignalsError("bad_snapshot", "snapshot has unknown member '$k'")
        }
        val grants = pairs(snapshot["grants"], "grants")
        val agents = pairs(snapshot["agents"], "agents")
        val intents = pairs(snapshot["intents"], "intents")
        for (p in grants) RevocationState.recordMax(target.revokedGrants, p.first, p.second)
        for (p in agents) RevocationState.recordMax(target.killedAgents, p.first, p.second)
        for (p in intents) {
            val m = target.revokedIntentIds ?: LinkedHashMap<String, Double>().also { target.revokedIntentIds = it }
            RevocationState.recordMax(m, p.first, p.second)
        }
        return target
    }
}
