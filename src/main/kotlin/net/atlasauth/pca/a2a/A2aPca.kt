package net.atlasauth.pca.a2a

import java.security.MessageDigest
import java.util.Locale
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.oauth.Oauth
import net.atlasauth.pca.verifier.A2a
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaGrant
import net.atlasauth.pca.verifier.Threshold

/**
 * The A2A (Agent2Agent) adapter for PCA: proof-carrying Tasks, signed Agent Cards, the AP2 payment-mandate envelope, the AUTH_REQUIRED
 * mapping, per-hop delegation, push tokens, signed task-update receipts and the extended Agent Card. Pure functions over parsed JSON
 * (Map, List, String, Boolean, [Json.Num], null); every verifier is fail-closed. The needs / chain-extension / push / receipt
 * verification core lives in [A2a] (package verifier); this object adds the rest and delegates to it.
 *
 * A PCActn is verified by a [PcaVerifier]: the default ([CORE_VERIFIER]) runs the core verifier ([Pca.verifyPcactn]) plus the checks the
 * options carry (plan authorization from `context.planAuthorized`, the params digest, a revocation predicate, PQ pins) and then demands
 * every required check to PASS; a check the verifier cannot evaluate (no revocation predicate, no authorized plan) is never reported
 * and so fails closed. Plug a full pipeline in as the [PcaVerifier] to enforce replay state and policy.
 */
@Suppress("UNCHECKED_CAST")
object A2aPca {
    const val PCA_A2A_EXTENSION_URI = "https://atlasauth.net/a2a/ext/pca/v2"
    const val TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"
    const val TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    const val A2A_RECEIPT_DOMAIN = A2a.RECEIPT_DOMAIN
    const val RECEIPT_KEY = "$PCA_A2A_EXTENSION_URI#receipt"
    private const val NEED_KEY = "$PCA_A2A_EXTENSION_URI#need"
    private const val PCA_PASSPORT_HEADER = "pca_passport"

    /** The `@context` of the PCA payment-mandate envelope (a PCA-defined envelope, not an AP2 credential). */
    @JvmField
    val A2A_AP2_CONTEXT: List<String> = listOf("https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2")
    private val TERMINAL = setOf("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")
    private val STATES = TERMINAL + setOf("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED")

    @JvmField
    val DEFAULT_REQUIRED_CHECKS: List<String> = listOf("counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")

    // ---- JavaScript-ish helpers ----

    /** Marks a member that is absent (JavaScript undefined) as opposed to JSON null. */
    private val UNDEF = Any()

    /** `o[k]`: UNDEF when absent; a null or undefined o throws (TypeError); a primitive or an array has no such member. */
    private fun at(o: Any?, k: String): Any? {
        if (o == null || o === UNDEF) throw IllegalStateException("TypeError: cannot read properties of null (reading '$k')")
        if (o is Map<*, *>) return if (o.containsKey(k)) o[k] else UNDEF
        return UNDEF
    }

    /** `o?.[k]`: UNDEF for null / non-objects / absent. */
    private fun opt(o: Any?, k: String): Any? = if (o == null || o === UNDEF) UNDEF else at(o, k)

    private fun jsonOf(v: Any?): Any? = if (v === UNDEF) null else v

    private fun isObj(o: Any?) = o is Map<*, *>

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    /** `{...o}`: own enumerable members of an object, the indices of an array or a string; nothing for other values. */
    @JvmStatic
    fun spread(o: Any?): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        when (o) {
            is Map<*, *> -> for ((k, v) in o) out[k as String] = v
            is List<*> -> for ((i, x) in o.withIndex()) out[i.toString()] = x
            is String -> for (i in o.indices) out[i.toString()] = o[i].toString()
        }
        return out
    }

    /** `[...x]`: a list copy; a string spreads by code point; null / non-iterables throw. */
    private fun spreadList(x: Any?): ArrayList<Any?> {
        if (x is List<*>) return ArrayList<Any?>(x)
        if (x is String) {
            val out = ArrayList<Any?>()
            var i = 0
            while (i < x.length) {
                val cp = x.codePointAt(i)
                out.add(String(Character.toChars(cp)))
                i += Character.charCount(cp)
            }
            return out
        }
        throw IllegalStateException("TypeError: not iterable")
    }

    private fun inSet(s: Set<String>, o: Any?): Boolean = o is String && o in s

    private fun safeNat(o: Any?): Boolean = Json.isSafeInt(o) && Json.asLong(o) >= 0

    /** JavaScript `a === b` for parsed JSON values; objects and arrays are never equal (distinct references). */
    private fun strictEq(a: Any?, b: Any?): Boolean {
        if (a === UNDEF || b === UNDEF) return a === b
        if (a == null || b == null) return a == null && b == null
        if (a is String && b is String) return a == b
        if (a is Boolean && b is Boolean) return a == b
        val x = Js.num(a)
        val y = Js.num(b)
        return x != null && y != null && x == y
    }

    /** `new Date(ms).toISOString()`; IllegalArgumentException (RangeError) for an invalid time value. */
    @JvmStatic
    fun toIsoString(msO: Any?): String {
        val d = Js.num(msO)
        if (d == null || d.isNaN() || d.isInfinite() || Math.abs(d) > 8.64e15) throw IllegalArgumentException("Invalid time value")
        val ms = d.toLong() // TimeClip truncates toward zero
        val days = Math.floorDiv(ms, 86_400_000L)
        val rem = Math.floorMod(ms, 86_400_000L)
        // civil-from-days over the proleptic Gregorian calendar
        val z = days + 719_468L
        val era = Math.floorDiv(z, 146_097L)
        val doe = z - era * 146_097L
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val day = doy - (153 * mp + 2) / 5 + 1
        val month = if (mp < 10) mp + 3 else mp - 9
        val y = yoe + era * 400 + (if (month <= 2) 1 else 0)
        val year = if (y in 0L..9999L) String.format(Locale.ROOT, "%04d", y) else (if (y < 0) "-" else "+") + String.format(Locale.ROOT, "%06d", Math.abs(y))
        val hh = rem / 3_600_000L
        val mm = rem / 60_000L % 60
        val ss = rem / 1000L % 60
        val milli = rem % 1000L
        return String.format(Locale.ROOT, "%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, month, day, hh, mm, ss, milli)
    }

    // ---- 1. proof-carrying Tasks ----

    private fun withPca(metadata: Any?, pcActn: Any?): LinkedHashMap<String, Any?> {
        val m = spread(metadata ?: LinkedHashMap<String, Any?>())
        m[PCA_A2A_EXTENSION_URI] = pcActn
        return m
    }

    /** Read a PCActn out of a metadata bag (fail-closed: a missing / non-object value yields null). */
    private fun readPca(metadata: Any?): Map<String, Any?>? {
        if (metadata !is Map<*, *>) return null
        val v = metadata[PCA_A2A_EXTENSION_URI]
        return if (v is Map<*, *>) map(v) else null
    }

    /** Attach a PCActn to a Task (a copy; the input is not mutated). */
    @JvmStatic
    fun attachPcaToA2ATask(task: Any?, pcActn: Any?): Map<String, Any?> {
        if (task == null) throw IllegalStateException("Cannot read properties of null (reading 'metadata')")
        val out = spread(task)
        out["metadata"] = withPca(out["metadata"], pcActn)
        return out
    }

    /** Attach a PCActn to a single Message (a copy). */
    @JvmStatic
    fun attachPcaToA2AMessage(message: Any?, pcActn: Any?): Map<String, Any?> = attachPcaToA2ATask(message, pcActn)

    /** The PCActn carried on a Task: task metadata, then the current status message, then the most recent history message. Null when none. */
    @JvmStatic
    fun extractPca(task: Any?): Map<String, Any?>? {
        if (task == null) return null
        val onTask = readPca(jsonOf(opt(task, "metadata")))
        if (onTask != null) return onTask
        val status = jsonOf(opt(task, "status"))
        if (status is Map<*, *>) {
            val onStatus = readPca(jsonOf(opt(jsonOf(opt(status, "message")), "metadata")))
            if (onStatus != null) return onStatus
        }
        val history = jsonOf(opt(task, "history"))
        if (history is List<*>) {
            for (i in history.size - 1 downTo 0) {
                val onMsg = readPca(jsonOf(opt(history[i], "metadata")))
                if (onMsg != null) return onMsg
            }
        }
        return null
    }

    /** The PCActn carried on a single Message (fail-closed). */
    @JvmStatic
    fun extractPcaFromMessage(message: Any?): Map<String, Any?>? = if (message == null) null else readPca(jsonOf(opt(message, "metadata")))

    // ---- verification ----

    /** What a [PcaVerifier] is asked. */
    class Request internal constructor(
        val grant: Map<String, Any?>,
        val aud: String?,
        val now: Long,
        val context: Map<String, Any?>,
        val allowedSuites: List<String>?,
        val pqPins: Map<String, Any?>?,
        val require: List<String>,
        val isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Boolean)?,
    )

    /** A verifier's verdict: [checks] name to "pass" | "fail" (a check it does not evaluate is absent). */
    class Outcome(val allow: Boolean, val checks: Map<String, String>, val reasons: List<String>) {
        internal fun toMap(): LinkedHashMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["allow"] = allow
            m["checks"] = LinkedHashMap<String, Any?>(checks)
            m["reasons"] = ArrayList<Any?>(reasons)
            return m
        }
    }

    /** The full PCActn verifier plugged into the A2A surfaces. Must not throw; a throw is a refusal. */
    fun interface PcaVerifier {
        fun verify(pcActn: Map<String, Any?>, request: Request): Outcome
    }

    /** The default verifier: the core verifier plus plan authorization, params digest, revocation and PQ pins; every required check must pass. */
    @JvmField
    val CORE_VERIFIER: PcaVerifier = PcaVerifier { p, r ->
        val checks = LinkedHashMap<String, String>()
        val reasons = ArrayList<String>()
        val plan = p["plan"]
        val root = if (plan is Map<*, *>) plan["root"] else null
        val pa = r.context["planAuthorized"]
        val roots: List<String>? = when {
            pa == true && root is String -> listOf(root)
            pa == false || pa == true -> emptyList()
            else -> null
        }
        val audience = if (r.aud != null) Pca.Audience.Of(r.aud) else Pca.Audience.Unset
        val v = Pca.verifyPcactn(p, r.grant, r.now, audience, r.allowedSuites, null, null, null, roots)
        var allow = v.allow
        for ((k, ok) in v.checks) checks[k] = if (ok) "pass" else "fail"
        if (v.reason.isNotEmpty()) reasons.add(v.reason)
        val pins = r.pqPins
        if (pins != null) {
            val issuer = r.grant["issuer"]
            val alg = r.grant["alg"]
            val pin = if (issuer is String) pins[issuer] else null
            val classical = alg == null || alg == "ed25519"
            val ok = if (pin == null) classical else !classical && pin == r.grant["pq_pk"]
            checks["pq_pin"] = if (ok) "pass" else "fail"
            if (!ok) { allow = false; reasons.add("pq_pin: the grant's post-quantum key is not the pinned one for its issuer") }
        }
        if (r.context["params"] is Map<*, *>) {
            val act = p["action"]
            val want = if (act is Map<*, *>) act["params_digest"] else null
            val ok = try { Pca.paramsDigest(r.context["params"]) == want } catch (e: RuntimeException) { false }
            checks["params_digest"] = if (ok) "pass" else "fail"
            if (!ok) { allow = false; reasons.add("params_digest: the params do not open action.params_digest") }
        }
        val rev = r.isRevoked
        if (rev != null) {
            val ok = try { !rev(p, r.grant) } catch (e: RuntimeException) { false }
            checks["revocation"] = if (ok) "pass" else "fail"
            if (!ok) { allow = false; reasons.add("revocation: the proof or its chain is revoked (or the revocation check failed)") }
        }
        for (name in r.require) {
            if (checks[name] != "pass") { allow = false; reasons.add("$name: required check did not pass (${if (checks.containsKey(name)) "failed" else "not enforced"})") }
        }
        Outcome(allow, checks, reasons)
    }

    /** Options shared by every PCActn verification surface. One of [grant] / [expectedRootIssuer] is required. */
    class VerifyOptions {
        /** This resource server / Atlas instance id; compared against the PCActn's signed aud. */
        var aud: String? = null

        /** Verification clock (epoch ms); null: the wall clock. */
        var now: Long? = null

        /** The grant from YOUR store: the chain root must be byte-identical to it. */
        var grant: Map<String, Any?>? = null

        /** The principal the chain must be rooted at (b64u). */
        var expectedRootIssuer: String? = null

        /** Verifier-side issuer to pq_pk pins. */
        var pqPins: Map<String, Any?>? = null
        var allowedSuites: List<String>? = null

        /** The resource server's view of the action: `params`, `plan`, `planAuthorized`, ...; per PCActn. */
        var context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null

        /** Checks that must PASS; null: [DEFAULT_REQUIRED_CHECKS]. */
        var requireChecks: List<String>? = null

        /** Revocation predicate `(pcActn, grant) -> revoked?`; absent: the revocation check is not enforced and a default-required run refuses. */
        var isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Boolean)? = null

        /** The verifier; null: [CORE_VERIFIER]. */
        var verifier: PcaVerifier? = null

        /** The human-present signer set of [verifyA2APaymentMandate]. */
        var humanSignerSet: List<Any?>? = null

        /** [pcaA2AMiddleware]: false lets a Task with no proof through (a present proof must still verify). Default true: required. */
        var requireProof: Boolean = true

        fun copy(): VerifyOptions {
            val o = VerifyOptions()
            o.aud = aud; o.now = now; o.grant = grant; o.expectedRootIssuer = expectedRootIssuer; o.pqPins = pqPins; o.allowedSuites = allowedSuites
            o.context = context; o.requireChecks = requireChecks; o.isRevoked = isRevoked; o.verifier = verifier; o.humanSignerSet = humanSignerSet
            o.requireProof = requireProof
            return o
        }
    }

    /** Thrown when an A2A verifier is configured without any authority (`grant` or `expectedRootIssuer`). */
    class A2AAuthorityError : RuntimeException("pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority") {
        val code: String = "authority_required"
    }

    private fun assertAuthority(o: VerifyOptions?) {
        val hasGrant = o != null && o.grant != null
        val hasIssuer = o != null && !o.expectedRootIssuer.isNullOrEmpty()
        if (!hasGrant && !hasIssuer) throw A2AAuthorityError()
    }

    /** The result of verifying a proof-carrying A2A artifact. */
    class Verification internal constructor(val ok: Boolean, val reason: String?, val result: Map<String, Any?>?, val pcActn: Any?, private val hasPcActn: Boolean = pcActn != null) {
        /** The JSON form: `ok`, then `reason`, `result`, `pcActn` when present. */
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (reason != null) m["reason"] = reason
            if (result != null) m["result"] = result
            if (hasPcActn) m["pcActn"] = pcActn // present when the reference echoed it, even as null or a primitive
            return m
        }
    }

    private fun bad(reason: String, pcActn: Any?): Verification = Verification(false, reason, null, if (pcActn is Map<*, *>) map(pcActn) else null)

    private fun verifyPcActn(pcActn: Any?, opts: VerifyOptions): Verification {
        assertAuthority(opts)
        if (pcActn !is Map<*, *> && pcActn !is List<*>) return bad("PCActn is not an object", null)
        val chain = if (pcActn is Map<*, *>) pcActn["cap_chain"] else null
        val root = if (chain is List<*> && chain.isNotEmpty()) chain[0] else null
        if (!Js.truthy(root)) return bad("PCActn carries no capability chain", pcActn)
        if (opts.expectedRootIssuer != null && !strictEq(jsonOf(opt(root, "issuer")), opts.expectedRootIssuer)) return bad("chain root issuer does not match the expected principal", pcActn)
        // Without a stored grant, the root is admitted only under the pinned principal; a non-Ed25519 root then needs a PQ pin.
        val grant: Map<String, Any?> = opts.grant ?: (if (root is Map<*, *>) map(root) else LinkedHashMap<String, Any?>())
        val pqPins: Map<String, Any?>? = if (opts.grant == null) (opts.pqPins ?: LinkedHashMap<String, Any?>()) else opts.pqPins
        val ctxFn = opts.context
        val context: Map<String, Any?> = (if (ctxFn != null) ctxFn(pcActn as Map<String, Any?>) else LinkedHashMap<String, Any?>()) ?: LinkedHashMap<String, Any?>()
        val req = Request(grant, opts.aud, opts.now ?: System.currentTimeMillis(), context, opts.allowedSuites, pqPins, opts.requireChecks ?: DEFAULT_REQUIRED_CHECKS, opts.isRevoked)
        val out: Outcome = try {
            (opts.verifier ?: CORE_VERIFIER).verify(pcActn as Map<String, Any?>, req)
        } catch (e: RuntimeException) {
            Outcome(false, LinkedHashMap(), listOf("verifier error (fail closed): " + e.javaClass.simpleName))
        }
        val reason = if (out.allow) null else (if (out.reasons.isEmpty()) "PCActn verification failed" else out.reasons.joinToString("; "))
        val result = out.toMap()
        if (reason != null) result["reason"] = reason
        return if (out.allow) Verification(true, null, result, map(pcActn)) else Verification(false, reason, result, map(pcActn))
    }

    /** Verify the proof-carrying action on an A2A Task; fail-closed (no PCActn, or one that does not verify, is rejected). */
    @JvmStatic
    fun verifyA2ATask(task: Any?, opts: VerifyOptions): Verification {
        assertAuthority(opts)
        val pcActn = extractPca(task) ?: return bad("no proof-carrying action attached to this task", null)
        return verifyPcActn(pcActn, opts)
    }

    /** The server guard of [pcaA2AMiddleware]: one Task in, a [Verification] out. */
    fun interface PcaA2AGuard {
        fun check(task: Any?): Verification
    }

    /** A guard that verifies the proof on each incoming Task. A present but invalid proof is always rejected; `opts.requireProof` false lets a Task with NO proof through. */
    @JvmStatic
    fun pcaA2AMiddleware(opts: VerifyOptions): PcaA2AGuard {
        assertAuthority(opts)
        val require = opts.requireProof
        return PcaA2AGuard { task ->
            val pcActn = extractPca(task)
            if (pcActn == null) {
                if (require) bad("proof-carrying action required but none attached to task", null) else Verification(true, null, null, null)
            } else verifyPcActn(pcActn, opts)
        }
    }

    // ---- 2. signed Agent Cards ----

    /** The canonical bytes a card signature covers: the card with `signatures` removed (RFC 8785). */
    @JvmStatic
    fun cardSigningBytes(card: Any?): ByteArray {
        val rest = spread(card)
        rest.remove("signatures")
        return A2aCard.jcsBytes(rest)
    }

    /** RFC 8785 canonical bytes (see [A2aCard.jcsBytes]). */
    @JvmStatic
    fun jcsBytes(value: Any?): ByteArray = A2aCard.jcsBytes(value)

    /** The A2A 1.0 `AgentCard` problems (see [A2aCard.validateAgentCard1]). */
    @JvmStatic
    fun validateAgentCard1(card: Any?): List<String> = A2aCard.validateAgentCard1(card)

    /** `alg` default EdDSA; `passport` (`id`, optional `uri`); `kid`; `profile` "pca-detached" | "a2a-1.0"; `schema` "a2a-1.0". */
    class IssueOptions {
        var alg: String? = null
        var passport: Map<String, Any?>? = null
        var kid: String? = null
        var profile: String? = null
        var schema: String? = null
    }

    /**
     * Issue a signed Agent Card: embed the passport reference, sign the canonicalized card (minus `signatures`) with the JWK, append the
     * `{protected, signature}`. Throws IllegalArgumentException for an invalid card schema, a missing kid under the a2a-1.0 profile or a
     * card with no canonical form; Jose.JoseException for a key that cannot sign.
     */
    @JvmStatic
    @JvmOverloads
    fun issueSignedAgentCard(card: Any?, signingKey: Map<String, Any?>, opts: IssueOptions = IssueOptions()): Map<String, Any?> {
        val alg = opts.alg ?: "EdDSA"
        val passport: Any?
        var passportIdMissing = false // the reference puts an undefined id into the card, which then has no canonical form
        val op = opts.passport
        if (op != null) {
            passportIdMissing = !op.containsKey("id")
            val pp = LinkedHashMap<String, Any?>()
            if (op.containsKey("id")) pp["id"] = op["id"]
            if (op.containsKey("uri") && op["uri"] != null) pp["uri"] = op["uri"]
            passport = pp
        } else {
            passport = jsonOf(opt(card, "pcaPassport"))
        }
        val toSign = spread(card)
        if (Js.truthy(passport)) toSign["pcaPassport"] = passport
        if (opts.schema == "a2a-1.0") {
            val problems = A2aCard.validateAgentCard1(toSign)
            if (problems.isNotEmpty()) throw IllegalArgumentException("issueSignedAgentCard: the card does not match the A2A 1.0 schema: " + problems.joinToString("; "))
        }
        if (passportIdMissing) throw IllegalArgumentException("jcs: unsupported type undefined")
        val payload = cardSigningBytes(toSign)
        val spec = opts.profile == "a2a-1.0"
        if (spec && opts.kid.isNullOrEmpty()) throw IllegalArgumentException("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid")
        var header: Map<String, Any?>? = null
        if (Js.truthy(passport) && at(passport, "id") !== UNDEF) header = linkedMapOf(PCA_PASSPORT_HEADER to at(passport, "id"))
        val signature = A2aJws.signDetached(payload, signingKey, alg, opts.kid, spec, header)
        val existing = toSign["signatures"]
        val sigs = if (existing == null) ArrayList<Any?>() else spreadList(existing)
        sigs.add(signature)
        toSign["signatures"] = sigs
        return toSign
    }

    /** `jwks` (a JWKS) or `key` (a JWK map), the importJWK `alg` (default EdDSA) and the optional `schema` "a2a-1.0". */
    class VerifyCardOptions {
        var jwks: Any? = null
        var key: Any? = null
        var alg: String? = null
        var schema: String? = null
    }

    /**
     * Validate an Agent Card against its signatures. Fail-closed: no signatures, an unresolvable key or ANY signature that does not verify is a refusal.
     * Result: `ok`, `reason` on a refusal; on success the `passportRef` the signature commits to and the card's `passport`.
     * `reason` wording after the first colon of a library failure is this port's own, not the reference library's.
     */
    @JvmStatic
    fun verifyAgentCard(card: Any?, opts: VerifyCardOptions): Map<String, Any?> = verifyCard(card, opts, false)

    /** Shared by the A2A and agent-card verifiers; [agentCardPkg] adds the live proof pointer and the agent-card wording of a malformed signature. */
    @JvmStatic
    fun verifyCard(card: Any?, opts: VerifyCardOptions, agentCardPkg: Boolean): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (card !is Map<*, *> && card !is List<*>) return refuse("agent card is not an object")
        val signatures = if (card is Map<*, *>) card["signatures"] else null
        if (signatures !is List<*> || signatures.isEmpty()) return refuse("agent card carries no signatures")
        if (opts.schema == "a2a-1.0") {
            val problems = A2aCard.validateAgentCard1(card)
            if (problems.isNotEmpty()) return refuse("agent card does not match the A2A 1.0 schema: " + problems.joinToString("; "))
        }
        val res = A2aJws.resolveVerifyKey(opts.jwks, opts.key, opts.alg)
        if (res.error != null) return refuse(res.error)
        val payload = try {
            cardSigningBytes(card)
        } catch (e: IllegalArgumentException) {
            return refuse("agent card has no canonical form: " + e.message)
        }
        var passportRef: String? = null
        for (i in signatures.indices) {
            val sig = signatures[i]
            if (!agentCardPkg) {
                if (!Js.truthy(sig) || at(sig, "protected") !is String || at(sig, "signature") !is String) return refuse("signature $i is malformed")
            } else if (!Js.truthy(sig)) return refuse("signature $i is missing")
            val r = A2aJws.verifyDetached(payload, sig, res.resolver!!)
            if (!r.ok) return refuse("signature $i did not verify: ${r.reason}")
            val ref = r.protectedHeader!![PCA_PASSPORT_HEADER]
            if (ref is String && passportRef == null) passportRef = ref
        }
        out["ok"] = true
        if (passportRef != null) out["passportRef"] = passportRef
        val pp = if (card is Map<*, *>) card["pcaPassport"] else null
        if (Js.truthy(pp)) out["passport"] = pp
        if (agentCardPkg) {
            val proof = if (card is Map<*, *>) card["pcaProof"] else null
            if (Js.truthy(proof)) out["pcaProof"] = proof
        }
        return out
    }

    private fun refuse(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    // ---- 3. AP2 payment profile ----

    private fun leafOfChain(chain: Any?): Any? = if (chain is List<*> && chain.isNotEmpty()) chain[chain.size - 1] else UNDEF

    private fun leafHolderOf(chain: Any?): Any? {
        val leaf = leafOfChain(chain)
        return if (leaf === UNDEF) UNDEF else opt(leaf, "holder")
    }

    /**
     * True only when the PCActn carries threshold shares that verify at t=3 under [signerSetO] (agent + guardian + principal, one distinct
     * key per role). Stricter than the reference in one respect: EVERY explicit share must verify (a stray invalid share refuses), and the agent
     * may be the leaf signature only for an Ed25519 leaf whose signer-set entry registers no post-quantum key. Never throws.
     */
    internal fun verifiedHumanPresent(pcActn: Map<String, Any?>, signerSetO: Any?): Boolean {
        try {
            if (signerSetO !is List<*>) return false
            val signerSet = signerSetO as List<Any?>
            val msg = Pca.thresholdMessage(pcActn)
            val th = pcActn["threshold"]
            val sh = if (th is Map<*, *>) th["shares"] else null
            val shares: List<Any?> = if (sh is List<*>) sh as List<Any?> else ArrayList()
            val good = HashSet<String>()
            for (s in shares) {
                if (s !is Map<*, *> || s["role"] !is String) return false
                val role = s["role"] as String
                if (!Threshold.verifyShare(role, msg, signerSet, 3, map(s))) return false
                good.add(role)
            }
            if ("agent" !in good && agentLeafBaseline(pcActn, signerSet, msg)) good.add("agent")
            return "agent" in good && "guardian" in good && "principal" in good
        } catch (e: RuntimeException) {
            return false
        }
    }

    private fun agentLeafBaseline(p: Map<String, Any?>, signerSet: List<Any?>, msg: ByteArray): Boolean {
        val holder = leafHolderOf(p["cap_chain"])
        val sig = p["sig"]
        val alg = p["alg"]
        if (holder !is String || sig !is String || (alg != null && alg != "ed25519")) return false
        var registered = false
        for (e in signerSet) {
            val m = e as Map<String, Any?>
            if (m["role"] == "agent" && holder == m["publicKey"]) {
                if (m.containsKey("pq_pk")) return false
                registered = true
            }
        }
        if (!registered) return false
        val pk = Pca.decodeB64uStrict(holder, 32)
        val sg = Pca.decodeB64uStrict(sig, 64)
        return pk != null && sg != null && Jose.verifyEd25519Strict(pk, msg, sg)
    }

    /**
     * Map a PCActn to an AP2 Payment Mandate. [opts]: `amount {currency, value}` (value a non-negative integer in minor units),
     * `paymentMethod`, `merchant`, `humanPresent`, `humanSignerSet`, `issuerPublic`, `now`.
     * Throws IllegalArgumentException on a bad amount or no issuer.
     */
    @JvmStatic
    fun a2aPaymentMandateFromPca(pcActnO: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val leaf = leafHolderOf(at(pcActnO, "cap_chain"))
        val issuerO = if (opts.containsKey("issuerPublic") && opts["issuerPublic"] != null) opts["issuerPublic"] else leaf
        if (issuerO === UNDEF) throw IllegalArgumentException("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain")
        val amount = opts["amount"]
        val value = at(amount, "value")
        val negZero = value is Json.Num && value.raw == "-0" // -0 is a safe integer and not below zero
        if (!negZero && !safeNat(value)) throw IllegalArgumentException("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units")
        val humanPresent: Any? =
            if (opts.containsKey("humanPresent") && opts["humanPresent"] != null) opts["humanPresent"]
            else Js.truthy(opts["humanSignerSet"]) && pcActnO is Map<*, *> && verifiedHumanPresent(map(pcActnO), opts["humanSignerSet"])
        val now: Any? = if (opts.containsKey("now") && opts["now"] != null) opts["now"] else System.currentTimeMillis()
        val xpca = LinkedHashMap<String, Any?>()
        xpca["pcactn_digest"] = Pca.hashCanonical(pcActnO)
        val action = at(pcActnO, "action")
        if (action === UNDEF) throw IllegalStateException("TypeError: cannot read properties of undefined (reading 'verb')")
        val fields = listOf("aud" to at(pcActnO, "aud"), "verb" to at(action, "verb"), "resource" to at(action, "resource"),
            "params_digest" to at(action, "params_digest"), "grant_ref" to at(pcActnO, "grant_ref"))
        for ((k, v) in fields) if (v !== UNDEF) xpca[k] = v
        xpca["leaf_holder"] = if (leaf === UNDEF || leaf == null) issuerO else leaf // `leaf ?? issuer`
        // x_pca member order: pcactn_digest, aud, verb, resource, params_digest, grant_ref, leaf_holder
        val contents = LinkedHashMap<String, Any?>()
        contents["amount"] = spread(amount)
        val pm = opts["paymentMethod"]
        contents["payment_method"] = spread(pm ?: LinkedHashMap<String, Any?>())
        contents["human_present"] = humanPresent
        if (opts.containsKey("merchant") && opts["merchant"] != null) contents["merchant"] = opts["merchant"]
        contents["x_pca"] = xpca
        val out = LinkedHashMap<String, Any?>()
        out["@context"] = ArrayList<Any?>(A2A_AP2_CONTEXT)
        out["type"] = arrayListOf<Any?>("VerifiableCredential", "PaymentMandate")
        out["issuer"] = issuerO
        out["issuanceDate"] = toIsoString(now)
        out["credentialSubject"] = contents
        return out
    }

    /** Read the PCA binding back out of an AP2 Payment Mandate (the round trip of `x_pca`). */
    @JvmStatic
    fun pcaBindingFromA2APaymentMandate(mandate: Any?): Map<String, Any?> = spread(at(at(mandate, "credentialSubject"), "x_pca"))

    private fun mandateBindingError(m: Any?, pcActn: Any?, params: Map<String, Any?>, opts: VerifyOptions): String? {
        val x = jsonOf(at(m, "x_pca"))
        if (!isObj(x)) return "payment mandate carries no x_pca binding"
        val action = opt(pcActn, "action")
        val leafHolder = if (leafOfChain(opt(pcActn, "cap_chain")) is Map<*, *>) opt(leafOfChain(opt(pcActn, "cap_chain")), "holder") else UNDEF
        // for a non-object chain / action the member reads as undefined, which never equals a string
        val bound = listOf("aud" to opt(pcActn, "aud"), "verb" to (if (action === UNDEF) UNDEF else opt(action, "verb")),
            "resource" to (if (action === UNDEF) UNDEF else opt(action, "resource")),
            "params_digest" to (if (action === UNDEF) UNDEF else opt(action, "params_digest")), "grant_ref" to opt(pcActn, "grant_ref"), "leaf_holder" to leafHolder)
        for ((k, want) in bound) {
            val have = at(x, k)
            if (have !is String || !strictEq(have, want)) return "payment mandate x_pca.$k is not the PCActn's"
        }
        val amt = jsonOf(at(m, "amount"))
        val av = if (isObj(amt)) at(amt, "value") else UNDEF
        if (!isObj(amt) || !safeNat(av) || at(amt, "currency") !is String)
            return "payment mandate amount is malformed (value must be a non-negative integer in minor units)"
        val pa = if (params.containsKey("amount")) params["amount"] else UNDEF
        if (pa === UNDEF || !safeNat(pa)) return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to"
        if (params["currency"] !is String) return "the PCActn params carry no currency to bind the mandate currency to"
        if (!strictEq(av, pa) || !strictEq(at(amt, "currency"), params["currency"])) return "payment mandate amount / currency differ from the authorized PCActn params"
        val merchant = at(m, "merchant")
        val pMerchant = if (params.containsKey("merchant")) params["merchant"] else UNDEF
        if (!strictEq(merchant, pMerchant)) return "payment mandate merchant differs from the authorized PCActn params"
        if (params.containsKey("payment_method")) {
            val same = try {
                val mpm = at(m, "payment_method")
                mpm !== UNDEF && Pca.hashCanonical(mpm) == Pca.hashCanonical(params["payment_method"])
            } catch (e: RuntimeException) {
                false
            }
            if (!same) return "payment mandate payment_method differs from the authorized PCActn params"
        }
        val hp = at(m, "human_present")
        if (hp !is Boolean) return "payment mandate human_present must be a boolean"
        if (hp && !(opts.humanSignerSet != null && pcActn is Map<*, *> && verifiedHumanPresent(map(pcActn), opts.humanSignerSet)))
            return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)"
        return null
    }

    /**
     * Verify an AP2 Payment Mandate against the PCActn it references (the mandate is unsigned: the PCActn must authorize every field a payer acts on).
     * `opts.context` must yield the action's plaintext `params`; the `params_digest` check is required on this path.
     */
    @JvmStatic
    fun verifyA2APaymentMandate(mandate: Any?, pcActn: Any?, opts: VerifyOptions): Verification {
        assertAuthority(opts)
        val pair: Pair<Any?, String> = try {
            val cs = at(mandate, "credentialSubject")
            if (cs === UNDEF) throw IllegalStateException("credentialSubject is undefined")
            val xp = at(cs, "x_pca")
            if (xp === UNDEF) throw IllegalStateException("x_pca is undefined")
            Pair(at(xp, "pcactn_digest"), Pca.hashCanonical(pcActn))
        } catch (e: RuntimeException) {
            return bad("malformed payment mandate or PCActn: " + e.message, null)
        }
        val bound = pair.first
        val digest = pair.second
        if (!strictEq(bound, digest)) return Verification(false, "payment mandate is not bound to this PCActn (pcactn_digest mismatch)", null, pcActn, true)
        if (pcActn !is Map<*, *> && pcActn !is List<*>) return bad("PCActn is not an object", null)
        val ctxFn = opts.context
        val context: Map<String, Any?> = if (ctxFn != null) {
            ctxFn(if (pcActn is Map<*, *>) map(pcActn) else LinkedHashMap<String, Any?>()) ?: throw IllegalStateException("TypeError: context is null")
        } else LinkedHashMap<String, Any?>()
        val params = context["params"]
        if (params !is Map<*, *>) return bad("context.params (the PCActn params plaintext) is required to bind the payment mandate", pcActn)
        val why = mandateBindingError(at(mandate, "credentialSubject"), pcActn, map(params), opts)
        if (why != null) return bad(why, pcActn)
        val require = ArrayList<String>(opts.requireChecks ?: DEFAULT_REQUIRED_CHECKS)
        if ("params_digest" !in require) require.add("params_digest")
        val o = opts.copy()
        val ctx = context
        o.context = { _ -> ctx }
        o.requireChecks = require
        return verifyPcActn(pcActn, o)
    }

    // ---- AUTH_REQUIRED mapping, extension, delegation, push ----

    /** The `AgentExtension` object to put in `capabilities.extensions`. */
    @JvmStatic
    @JvmOverloads
    fun pcaExtensionDeclaration(params: Any?, required: Boolean = true): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["uri"] = PCA_A2A_EXTENSION_URI
        m["description"] = "Per-action proofs of authority (PCActn) on tasks and messages"
        m["required"] = required
        m["params"] = params
        return m
    }

    private fun extFail(code: String): Map<String, Any?> = linkedMapOf("ok" to false, "code" to code)

    private val PARAM_KEYS = setOf("aud", "suites", "grants", "policy_digest")

    /** Read and validate the PCA extension from an Agent Card: `{ok:true, required, params, grants}` or `{ok:false, code}`. */
    @JvmStatic
    fun readPcaExtension(card: Any?): Map<String, Any?> {
        val caps = if (isObj(card)) map(card)["capabilities"] else null
        val exts = if (isObj(caps)) map(caps)["extensions"] else null
        if (exts !is List<*>) return extFail("not_declared")
        val found = ArrayList<Any?>()
        for (e in exts) if (isObj(e) && map(e)["uri"] == PCA_A2A_EXTENSION_URI) found.add(e)
        if (found.isEmpty()) return extFail("not_declared")
        if (found.size > 1) return extFail("bad_declaration")
        val e = map(found[0])
        if (e.containsKey("required") && e["required"] !is Boolean) return extFail("bad_declaration")
        val po = e["params"]
        if (!isObj(po)) return extFail("bad_params")
        val p = map(po)
        for (k in p.keys) if (k !in PARAM_KEYS) return extFail("bad_params")
        val aud = p["aud"]
        if (aud !is String || aud.isEmpty() || aud.length > 512) return extFail("bad_params")
        if (p.containsKey("suites")) {
            val s = p["suites"]
            val ok = s is List<*> && s.size <= 16 && s.all { it is String && it.isNotEmpty() && it.length <= 64 }
            if (!ok) return extFail("bad_params")
        }
        if (p.containsKey("policy_digest")) {
            val d = p["policy_digest"]
            if (d !is String || d.isEmpty() || d.length > 128) return extFail("bad_params")
        }
        var grants: List<Map<String, Any?>> = ArrayList()
        if (p.containsKey("grants")) {
            val g = PcaGrant.parse(p["grants"])
            if (g.code != null) return extFail("bad_grants")
            grants = g.details
        }
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = true
        out["required"] = e["required"] == true
        out["params"] = p
        out["grants"] = ArrayList<Any?>(grants)
        return out
    }

    /** True iff the `A2A-Extensions` service parameter lists the PCA extension (exact URI match in a comma-separated list). */
    @JvmStatic
    fun clientOptsIntoPca(header: Any?): Boolean {
        if (header !is String) return false
        for (u in header.split(",")) if (AttestUtil.jsTrim(u) == PCA_A2A_EXTENSION_URI) return true
        return false
    }

    /** AUTH_REQUIRED in the 1.0 enum spelling; the pre-1.0 `auth-required` is also read. */
    @JvmStatic
    fun isAuthRequired(state: Any?): Boolean = state == TASK_STATE_AUTH_REQUIRED || state == "auth-required"

    /**
     * The TaskStatus an agent sets to ask for authority: state AUTH_REQUIRED, a message with the typed need under the extension key.
     * [need] is validated by the need codec (IllegalArgumentException when malformed); [now] epoch ms (RangeError when invalid).
     */
    @JvmStatic
    fun authRequiredStatus(need: Map<String, Any?>, messageId: Any?, now: Any?, text: String?): Map<String, Any?> {
        val enc = Oauth.encodePcaNeed(need) // validates and bounds
        val msg = LinkedHashMap<String, Any?>()
        if (messageId != null) msg["messageId"] = messageId
        msg["role"] = "agent"
        val part = LinkedHashMap<String, Any?>()
        part["kind"] = "text"
        part["text"] = text ?: "Authority needed: ${need["verb"]} on ${need["resource"]}"
        msg["parts"] = arrayListOf<Any?>(part)
        msg["extensions"] = arrayListOf<Any?>(PCA_A2A_EXTENSION_URI)
        msg["metadata"] = linkedMapOf<String, Any?>(NEED_KEY to enc)
        val out = LinkedHashMap<String, Any?>()
        out["state"] = TASK_STATE_AUTH_REQUIRED
        out["timestamp"] = toIsoString(now)
        out["message"] = msg
        return out
    }

    private fun decoded(value: Any?): Map<String, Any?> {
        val d = A2a.decodeNeed(value)
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = d.need != null
        if (d.need != null) m["need"] = d.need else m["code"] = d.code
        return m
    }

    /** The need parked in a task status message, decoded (`{ok, need}` or `{ok:false, code}`); null when there is none. */
    @JvmStatic
    fun readAuthRequiredNeed(task: Any?): Map<String, Any?>? {
        val status = if (isObj(task)) map(task)["status"] else null
        val msg = if (isObj(status)) map(status)["message"] else null
        val md = if (isObj(msg)) map(msg)["metadata"] else null
        if (!isObj(md) || !map(md).containsKey(NEED_KEY)) return null
        return decoded(map(md)[NEED_KEY])
    }

    /** The answer message to put on the Task: a PCActn for exactly the parked need, plus the need's digest. */
    @JvmStatic
    fun answerMessage(need: Any?, pcActn: Any?, messageId: Any?): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["role"] = "user"
        if (messageId != null) out["messageId"] = messageId
        val part = LinkedHashMap<String, Any?>()
        part["kind"] = "text"
        part["text"] = "authority provided"
        out["parts"] = arrayListOf<Any?>(part)
        val md = LinkedHashMap<String, Any?>()
        md[PCA_A2A_EXTENSION_URI] = pcActn
        val nd = LinkedHashMap<String, Any?>()
        nd["d"] = "atlas-pca/need/v1"
        nd["need"] = need
        md[NEED_KEY] = Pca.hashCanonical(nd) // the digest is over whatever was given: the reference does not validate it here
        out["metadata"] = md
        return out
    }

    /** Pass as the proof action of [resumeGate] for "no proof". */
    @JvmField
    val NO_PROOF: Any = Any()

    /**
     * The pure gate of [resumeAuthRequired], in the order the checks run. [proofAction]: pass [NO_PROOF] for none; an action that is a
     * JSON null throws (the reference dereferences it). Returns the first refusal code, or null.
     */
    @JvmStatic
    fun resumeGate(state: Any?, needEncoded: Any?, answerNeedDigest: Any?, proofAction: Any?): String? {
        if (!isAuthRequired(state)) return "task_not_auth_required"
        val need = if (needEncoded === UNDEF) null else A2a.decodeNeed(needEncoded).need
        if (need == null) return "no_valid_need"
        if (!strictEq(answerNeedDigest, A2a.needDigest(need))) return "answer_not_bound_to_need"
        if (proofAction === NO_PROOF) return "no_proof"
        if (proofAction == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'verb')")
        if (!strictEq(jsonOf(opt(proofAction, "verb")), need["verb"]) || !strictEq(jsonOf(opt(proofAction, "resource")), need["resource"])) return "action_mismatch"
        return null
    }

    /** Does [next] (capability ids, root first) extend [prev]? */
    @JvmStatic
    fun chainExtends(prev: List<*>, next: List<*>): Boolean {
        if (next.size < prev.size) return false
        for (k in prev.indices) if (!strictEq(prev[k], next[k])) return false
        return true
    }

    /** The chain rule of [verifyA2ADelegation]: `{ok:true}` or `{ok:false, failedHop, reason}`. */
    @JvmStatic
    fun checkChainExtension(chainsO: Any?): Map<String, Any?> {
        if (chainsO == null || chainsO === UNDEF) throw IllegalStateException("TypeError: cannot read properties of null (reading 'length')")
        // a string has a length and character "hops" (never arrays); other non-arrays have no length, so nothing is checked
        val chains: List<Any?> = when {
            chainsO is List<*> -> chainsO
            chainsO is String && chainsO.isNotEmpty() -> listOf(chainsO[0].toString())
            else -> emptyList()
        }
        for (i in chains.indices) {
            val ids = chains[i]
            if (ids !is List<*> || ids.isEmpty()) return chainFail(i, "no_chain")
            if (i > 0 && !chainExtends(chains[i - 1] as List<*>, ids)) return chainFail(i, "chain_does_not_extend_previous_hop")
        }
        return linkedMapOf("ok" to true)
    }

    private fun chainFail(hop: Int, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "failedHop" to hop.toLong(), "reason" to reason)

    /**
     * Resume a Task parked in AUTH_REQUIRED: only when the Task is in AUTH_REQUIRED, its status carries a decodable need, the answer cites that
     * need's digest, carries a PCActn for the need's exact verb and resource, and that PCActn passes the full verifier.
     * `{ok:true, verification}` or `{ok:false, reason}`.
     */
    @JvmStatic
    fun resumeAuthRequired(task: Any?, answer: Any?, opts: VerifyOptions): Map<String, Any?> {
        val status = jsonOf(opt(task, "status"))
        val smsg = if (isObj(status)) map(status)["message"] else null
        val smd = if (isObj(smsg)) map(smsg)["metadata"] else null
        val statusMd: Map<String, Any?> = if (isObj(smd)) map(smd) else LinkedHashMap()
        val amd = if (isObj(answer)) map(answer)["metadata"] else null
        val md: Map<String, Any?> = if (isObj(amd)) map(amd) else LinkedHashMap()
        val p = extractPcaFromMessage(answer)
        val state = if (isObj(status)) map(status)["state"] else null
        val proofAction: Any? = if (p == null) NO_PROOF else (if (p.containsKey("action")) p["action"] else NO_PROOF)
        val refusal = resumeGate(state, if (statusMd.containsKey(NEED_KEY)) statusMd[NEED_KEY] else UNDEF, if (md.containsKey(NEED_KEY)) md[NEED_KEY] else UNDEF, proofAction)
        val out = LinkedHashMap<String, Any?>()
        if (refusal != null) { out["ok"] = false; out["reason"] = refusal; return out }
        val t = LinkedHashMap<String, Any?>()
        t["id"] = jsonOf(opt(task, "id"))
        t["status"] = linkedMapOf<String, Any?>("state" to "TASK_STATE_WORKING")
        t["metadata"] = linkedMapOf<String, Any?>(PCA_A2A_EXTENSION_URI to p)
        val v = verifyA2ATask(t, opts)
        if (v.ok) { out["ok"] = true; out["verification"] = v.toMap() } else { out["ok"] = false; out["reason"] = v.reason ?: "proof_rejected" }
        return out
    }

    /** One hop of [verifyA2ADelegation]: the Task and the options (own audience and authority) it is verified under. */
    class Hop(val task: Any?, val opts: VerifyOptions)

    /**
     * Verify a chain of delegated Tasks, one per A2A hop. Every hop is verified on its own (own PCActn, audience and authority); each hop's
     * capability chain must EXTEND the previous hop's. Stops at the first failure; empty input fails closed.
     * Result: `{ok, failedHop?, reason?, chains}`.
     */
    @JvmStatic
    fun verifyA2ADelegation(hops: List<Hop>): Map<String, Any?> {
        val chains = ArrayList<Any?>()
        val out = LinkedHashMap<String, Any?>()
        if (hops.isEmpty()) { out["ok"] = false; out["reason"] = "no_hops"; out["chains"] = chains; return out }
        for (i in hops.indices) {
            val h = hops[i]
            val v = verifyA2ATask(h.task, h.opts)
            if (!v.ok) return hopFail(i, v.reason ?: "rejected", chains)
            val p = extractPca(h.task)
            val cc = p?.get("cap_chain")
            if (cc !is List<*>) return hopFail(i, "no_chain", chains)
            val ids = ArrayList<Any?>()
            for (c in cc) ids.add(jsonOf(at(c, "id")))
            if (i > 0 && !chainExtends(chains[i - 1] as List<*>, ids)) return hopFail(i, "chain_does_not_extend_previous_hop", chains)
            chains.add(ids)
        }
        out["ok"] = true
        out["chains"] = chains
        return out
    }

    private fun hopFail(hop: Int, reason: String, chains: List<Any?>): Map<String, Any?> =
        linkedMapOf("ok" to false, "failedHop" to hop.toLong(), "reason" to reason, "chains" to chains)

    /** The per-task push token (A2A 3.1.7): a hash of the task id, the digest of the authorizing chain and a secret salt of at least 16 characters (else IllegalArgumentException). */
    @JvmStatic
    fun pcaPushToken(taskId: Any?, chainIds: List<String>, salt: Any?): String {
        if (salt !is String || salt.length < 16) throw IllegalArgumentException("pcaPushToken: the salt must be a secret of at least 16 characters")
        val m = LinkedHashMap<String, Any?>()
        m["d"] = "atlas-pca/a2a-push/v1"
        m["task_id"] = taskId
        m["chain"] = PcaGrant.chainDigest(chainIds)
        m["salt"] = salt
        return Pca.hashCanonical(m)
    }

    /**
     * Receiver-side check of a delivered push notification: the token must equal the one recomputed from the task, chain and salt, and the payload
     * must be about that task. `{ok:true}` or `{ok:false, reason}` (no_token, token_mismatch, task_mismatch). A short salt with a
     * presented token throws, as the reference does.
     */
    @JvmStatic
    fun checkPushNotification(taskId: String, chainIds: List<String>, salt: Any?, token: Any?, payload: Any?): Map<String, Any?> {
        if (token !is String || token.isEmpty()) return refuse("no_token")
        val want = pcaPushToken(taskId, chainIds, salt)
        if (!MessageDigest.isEqual(Json.utf8(want), Json.utf8(token))) return refuse("token_mismatch")
        val r = A2a.checkPush(taskId, chainIds, salt as String, token, payload)
        if (r != null) return refuse(r)
        return linkedMapOf("ok" to true)
    }

    /** The one error A2A servers return for "no such task" and "not yours" alike (no existence leak). */
    @JvmStatic
    fun uniformTaskNotFound(): Map<String, Any?> = linkedMapOf("code" to "TaskNotFoundError", "message" to "task not found")

    // ---- signed task-update receipts ----

    /** The content address the next receipt cites as `prev`. */
    @JvmStatic
    fun receiptDigest(r: Any?): String = A2a.receiptDigest(r)

    /**
     * Sign a receipt with an Ed25519 seed. [prev]: the previous receipt of the same task (null for the first). Throws IllegalArgumentException on
     * malformed input, a task id mismatch or a terminal [prev].
     */
    @JvmStatic
    fun signTaskReceipt(secret: ByteArray, taskId: Any?, state: Any?, chainIds: List<String>, issuedAt: Any?, prev: Map<String, Any?>?): Map<String, Any?> {
        if (taskId !is String || taskId.isEmpty() || taskId.length > 256 || !inSet(STATES, state) || !safeNat(issuedAt) || chainIds.isEmpty())
            throw IllegalArgumentException("signTaskReceipt: malformed input")
        if (prev != null && (!strictEq(prev["task_id"], taskId) || inSet(TERMINAL, prev["state"]))) throw IllegalArgumentException("signTaskReceipt: prev is for another task or already terminal")
        if (prev != null && !safeNat(prev["seq"])) throw IllegalArgumentException("signTaskReceipt: prev has no valid seq")
        val key = Keys.edFromSeed(secret)
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Json.Num("1")
        body["task_id"] = taskId
        body["state"] = state
        body["seq"] = if (prev != null) Json.Num((Json.asLong(prev["seq"]) + 1).toString()) else Json.Num("0")
        body["prev"] = if (prev != null) A2a.receiptDigest(prev) else null
        body["chain"] = PcaGrant.chainDigest(chainIds)
        body["issued_at"] = issuedAt
        body["signer"] = key.id()
        val msg = A2A_RECEIPT_DOMAIN.toByteArray(Charsets.UTF_8) + Json.canonicalizeStrict(body).toByteArray(Charsets.UTF_8)
        val out = LinkedHashMap<String, Any?>(body)
        out["sig"] = Keys.b64u(key.sign(msg))
        return out
    }

    /** Well formed and signed by [signer] (the key the receiver pinned) over exactly its content. Never throws. */
    @JvmStatic
    fun verifyTaskReceipt(r: Any?, signer: String): Boolean = A2a.verifyReceipt(r, signer)

    /** Check an ordered list of receipts for one task: `{ok:true, last, terminal}` or `{ok:false, code, at?}`. */
    @JvmStatic
    fun checkReceiptChain(receipts: Any?, signer: String, taskId: String, chainIds: List<String>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (receipts !is List<*> || receipts.isEmpty()) { out["ok"] = false; out["code"] = "empty"; return out }
        val l = receipts as List<Any?>
        val c = A2a.checkReceiptChain(l, signer, taskId, chainIds)
        if (c.code != null) {
            out["ok"] = false
            out["code"] = c.code
            out["at"] = c.at.toLong()
            return out
        }
        out["ok"] = true
        out["last"] = l[l.size - 1]
        out["terminal"] = c.terminal
        return out
    }

    /** May a workflow start its next step because of this task? Only on a verified, unbroken receipt chain ending in COMPLETED. */
    @JvmStatic
    fun mayTriggerNext(receipts: Any?, signer: String, taskId: String, chainIds: List<String>): Boolean =
        receipts is List<*> && receipts.isNotEmpty() && A2a.mayTriggerNext(receipts as List<Any?>, signer, taskId, chainIds)

    /** Put a receipt on a status update or message metadata (a copy). */
    @JvmStatic
    fun attachReceipt(carrier: Any?, r: Any?): Map<String, Any?> {
        if (carrier == null) throw IllegalStateException("Cannot read properties of null (reading 'metadata')")
        val out = spread(carrier)
        val md = out["metadata"]
        val m = spread(md ?: LinkedHashMap<String, Any?>())
        m[RECEIPT_KEY] = r
        out["metadata"] = m
        return out
    }

    /** The receipt carried by a push / stream payload (`statusUpdate.metadata`, `task.metadata`, `message.metadata`), or null. Unverified. */
    @JvmStatic
    fun receiptOfPayload(payload: Any?): Any? {
        if (!isObj(payload)) return null
        for (k in listOf("statusUpdate", "task", "message")) {
            val c = map(payload)[k]
            val md = if (isObj(c)) map(c)["metadata"] else null
            if (isObj(md) && map(md).containsKey(RECEIPT_KEY)) return map(md)[RECEIPT_KEY]
        }
        return null
    }

    // ---- extended Agent Card ----

    private fun policyKey(v: Any?): String = if (v === UNDEF) "\u0000undefined" else "v:" + Json.canonicalize(v)

    private fun defaultVerbOf(s: Any?): Any? {
        val tags = at(s, "tags")
        if (tags === UNDEF || tags == null) return UNDEF
        if (tags !is List<*>) throw IllegalStateException("TypeError: tags.find is not a function")
        for (x in tags) if (x is String && x.startsWith("pca-verb:")) return x.substring("pca-verb:".length)
        return UNDEF
    }

    /**
     * The extended Agent Card from a residual policy (A2A 3.1.11, 13.3): lists the hidden skills a caller may attempt. [o]: `authenticated`
     * (must be true), `hiddenSkills`, `envelopes` (`verb, status, policyDigest`); [verbOf] maps a skill to its PCA verb
     * (null: the skill's `pca-verb:<verb>` tag). A verb with no envelope, or a denied one, reveals nothing. The result is unsigned.
     */
    @JvmStatic
    @JvmOverloads
    fun extendedAgentCard(publicCard: Any?, o: Map<String, Any?>, verbOf: ((Any?) -> String?)? = null): Map<String, Any?> {
        if (o["authenticated"] != true) throw IllegalStateException("extendedAgentCard: the caller must be authenticated (A2A 13.3)")
        val envelopes = o["envelopes"] as List<Any?>
        val hidden = o["hiddenSkills"] as List<Any?>
        val digests = LinkedHashMap<String, Any?>()
        for (e in envelopes) {
            val d = at(e, "policyDigest")
            val k = policyKey(d)
            if (!digests.containsKey(k)) digests[k] = d
        }
        if (digests.size > 1) throw IllegalArgumentException("extendedAgentCard: envelopes were computed against different policies")
        val byVerb = LinkedHashMap<String, Any?>()
        for (e in envelopes) {
            val v = at(e, "verb")
            if (v is String) byVerb[v] = e
        }
        val revealed = ArrayList<Any?>()
        for (s in hidden) {
            val verb: Any? = if (verbOf != null) (verbOf(s) ?: UNDEF) else defaultVerbOf(s)
            val env = if (verb is String) byVerb[verb] else null
            if (env == null || at(env, "status") == "denied") continue
            val sk = spread(s)
            val tags = at(s, "tags")
            val nt = if (tags === UNDEF || tags == null) ArrayList<Any?>() else spreadList(tags)
            nt.add(if (at(env, "status") == "autonomous") "pca:autonomous" else "pca:needs-approval")
            sk["tags"] = nt
            revealed.add(sk)
        }
        if (publicCard == null) throw IllegalStateException("TypeError: cannot destructure null")
        val rest = spread(publicCard)
        rest.remove("signatures")
        val capsO = rest["capabilities"]
        val caps = spread(capsO ?: LinkedHashMap<String, Any?>())
        val extsO = caps["extensions"]
        val exts: List<Any?> = if (extsO is List<*>) extsO as List<Any?> else ArrayList()
        val policyDigest: Any? = if (digests.isEmpty()) UNDEF else digests.values.iterator().next()
        val next = ArrayList<Any?>()
        for (e in exts) {
            if (policyDigest !== UNDEF && PCA_A2A_EXTENSION_URI == (if (at(e, "uri") === UNDEF) null else at(e, "uri"))) {
                val ne = spread(e)
                val pm = at(e, "params")
                val np = spread(if (pm === UNDEF || pm == null) LinkedHashMap<String, Any?>() else pm)
                np["policy_digest"] = policyDigest
                ne["params"] = np
                next.add(ne)
            } else {
                next.add(e)
            }
        }
        val skillsO = rest["skills"]
        val skills = if (skillsO is List<*>) ArrayList<Any?>(skillsO) else ArrayList<Any?>()
        skills.addAll(revealed)
        caps["extensions"] = next
        rest["capabilities"] = caps
        rest["skills"] = skills
        return rest
    }
}
