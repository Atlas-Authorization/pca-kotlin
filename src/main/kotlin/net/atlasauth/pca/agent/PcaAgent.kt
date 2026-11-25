package net.atlasauth.pca.agent

import java.net.URI
import java.net.URLEncoder
import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Ledger
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.SimpleHttp

/** Why an agent call failed. [code] is one of `no_plan`, `unknown_node`, `no_secret`, `network`, `bad_response`, `build_failed`. */
class PcaAgentError(val code: String, message: String, val httpStatus: Int? = null) : RuntimeException(message)

/** The HTTP seam: one request in, the status and the (possibly non-JSON) body out. Tests inject a double; the default is a plain HttpURLConnection. */
fun interface FetchLike {
    fun fetch(method: String, url: String, headers: Map<String, String>, body: String?): FetchResponse
}

class FetchResponse(val status: Int, val body: String)

/** The trust budget a verdict reports: `B`, `tau` and the time it was `asOf`. */
class TrustBudget(val b: Double, val tau: Double, val asOf: Double)

/** The server's reply to an action; [raw] is the whole parsed verdict object (allow, checks, reason, budget, ...). */
class Verdict(val allow: Boolean, val raw: Map<String, Any?>, val budget: TrustBudget? = null)

/** A ledger receipt. `salt`, when the server discloses it, lets the client check the entry commits to THIS action. */
class Receipt(val raw: Map<String, Any?>) {
    val root: String? get() = raw["root"] as? String
    val commit: String? get() = raw["commit"] as? String
    val salt: String? get() = raw["salt"] as? String
    val inclusionProof: Any? get() = raw["inclusion_proof"]
}

/** The decided step-up: `status` is `approved`, `denied`, `expired` or `timeout`; [raw] carries the server's answer. */
class StepUpOutcome(val status: String, val raw: Map<String, Any?> = emptyMap(), val httpStatus: Int? = null) {
    @Suppress("UNCHECKED_CAST")
    val pcactn: Map<String, Any?>? get() = raw["pcactn"] as? Map<String, Any?>
}

sealed class ActResult {
    class Allowed(val verdict: Verdict, val receipt: Receipt, val pcactn: Map<String, Any?>) : ActResult()
    class Denied(val verdict: Verdict, val httpStatus: Int, val pcactn: Map<String, Any?>) : ActResult()
    class StepUp(val stepupId: String, val requiredT: Double, val pcactn: Map<String, Any?>) : ActResult()
    class Error(val error: PcaAgentError) : ActResult()
}

/** Optional signed slots of wire v2 (all signed into the PCActn when present; absent = current behaviour). */
class ActSlots(
    /** Uncertainty attestation in [0,1]; monotone (the verifier takes max with its own risk). */
    val caution: Any? = null,
    val rationaleCommitment: String? = null,
    val progressStep: Map<String, Any?>? = null,
    val prohibitionEvidence: Any? = null,
    /** The b64u(32) digest of the tool signature you will dispatch to. */
    val toolBinding: String? = null,
    /** Overrides the generated nonce. */
    val nonce: String? = null,
)

class CreateAgentOptions(
    val grant: Map<String, Any?>,
    /** Capability chain starting at the grant; defaults to `[grant]`. */
    val chain: List<Any?>? = null,
    /** The leaf holder's signing key. Null only for a sub-agent client you do not drive. */
    val agentKey: Keys.SuiteKey? = null,
    /** b64u public key of the agent (informational). */
    val agentPublic: String? = null,
    val rsBaseUrl: String,
    /** REQUIRED. The audience the PCActns are FOR (wire v2 `aud`): the Atlas instance id, or the id the resource server passes as its audience. */
    val audience: String,
    /** Lifetime stamped into each PCActn (`exp = iat + ttlMs`); null = the issuer default (20 min). */
    val ttlMs: Long? = null,
    val now: () -> Long = { System.currentTimeMillis() },
    /** Stamp a fresh random per-action `nonce`. */
    val nonce: Boolean = true,
    val fetch: FetchLike? = null,
    /** Verify the ledger inclusion proof of every receipt before reporting allowed (an allow whose receipt does not verify is an error). */
    val verifyReceipts: Boolean = true,
    /** The last counter used; the first act() uses counter + 1. */
    val counter: Long = 0L,
    val budget: TrustBudget? = null,
    /** The session's provenance recorder: every act appends the action receipt and sends the bundle as `pca_provenance`. */
    val provenance: ArgProvenance.Recorder? = null,
)

/**
 * The HTTP agent client: commits a plan to a resource server, builds and sends one signed PCActn per action, follows a step-up
 * and checks the ledger receipt of every allow. Not thread-safe (counters are handed out in order): one client per thread.
 */
class AgentClient internal constructor(private val opts: CreateAgentOptions, private val base: String, private val doFetch: FetchLike) {
    val grant: Map<String, Any?> = opts.grant
    val chain: List<Any?> = opts.chain ?: listOf<Any?>(opts.grant)
    val agentPublic: String? = opts.agentPublic
    var counter: Long = opts.counter
        private set
    var budget: TrustBudget? = opts.budget
        private set
    var planRoot: String? = null
        private set
    private var plan: List<Map<String, Any?>>? = null

    private class Reply(val status: Int, val json: Map<String, Any?>)

    @Suppress("UNCHECKED_CAST")
    private fun call(method: String, path: String, body: Any? = null): Reply {
        val res = doFetch.fetch(
            method, base + path, linkedMapOf("content-type" to "application/json", "accept" to "application/json"),
            if (body == null) null else Json.canonicalize(body),
        )
        val parsed = try { Json.parseLenient(res.body) } catch (e: IllegalArgumentException) { null } // a non-JSON body is an empty object
        return Reply(res.status, (parsed as? Map<String, Any?>) ?: emptyMap())
    }

    /** Commit the plan locally and with the server; the server must echo the same root. */
    fun commitPlan(nodes: List<Map<String, Any?>>): String {
        val local = Issue.commitPlan(nodes).root
        val res = try {
            call("POST", "/v1/pca/plans", linkedMapOf<String, Any?>("grant_ref" to grant["id"], "nodes" to nodes))
        } catch (e: java.io.IOException) {
            throw PcaAgentError("network", e.message ?: "plan commit failed")
        }
        if (res.status < 200 || res.status >= 300) throw PcaAgentError("bad_response", "plan commit failed (${res.status})", res.status)
        // The server must echo the root it committed: a missing root cannot be told apart from a server that stored another plan.
        val remote = res.json["plan_root"]
        if (remote !is String || remote != local) {
            throw PcaAgentError("bad_response", "server plan_root is missing or differs from the locally computed root", res.status)
        }
        plan = nodes.map { LinkedHashMap(it) }
        planRoot = local
        return local
    }

    private fun err(code: String, msg: String, status: Int? = null) = ActResult.Error(PcaAgentError(code, msg, status))

    private fun isNum(v: Any?): Double? = when (v) {
        is Json.Num -> v.raw.toDoubleOrNull()?.takeIf { it.isFinite() }
        is Number -> v.toDouble().takeIf { it.isFinite() }
        else -> null
    }

    private fun budgetOf(v: Any?): TrustBudget? {
        val m = v as? Map<*, *> ?: return null
        val b = isNum(m["B"]) ?: return null
        val t = isNum(m["tau"]) ?: return null
        val a = isNum(m["asOf"]) ?: return null
        return TrustBudget(b, t, a)
    }

    private fun receiptBinds(r: Receipt, pcactn: Map<String, Any?>): Boolean = try {
        val salt = r.salt
        salt != null && Pca.hashCanonical(linkedMapOf<String, Any?>("salt" to salt, "pcactn_digest" to Pca.hashCanonical(pcactn))) == r.commit
    } catch (e: RuntimeException) {
        false
    }

    /** Act on [nodeId] of the committed plan. Never throws for a server-side failure: every outcome is an [ActResult]. */
    @Suppress("UNCHECKED_CAST")
    fun act(nodeId: String, params: Map<String, Any?>? = null, slots: ActSlots? = null): ActResult {
        val p = plan ?: return err("no_plan", "commitPlan() first")
        val key = opts.agentKey ?: return err("no_secret", "no agentKey for this client")
        val node = p.firstOrNull { it["id"] == nodeId } ?: return err("unknown_node", "unknown plan node $nodeId")
        val next = counter + 1
        val pcactn: Map<String, Any?> = try {
            Issue.buildPCActn(
                Issue.ActSpec(
                    grant = grant, chain = chain, plan = Issue.commitPlan(p), nodeId = nodeId, counter = next, signer = key, aud = opts.audience,
                    params = params, iat = opts.now(), ttlMs = opts.ttlMs,
                    nonce = slots?.nonce ?: if (opts.nonce) Issue.randomB64u(16) else null,
                    caution = slots?.caution, rationaleCommitment = slots?.rationaleCommitment, progressStep = slots?.progressStep,
                    prohibitionEvidence = slots?.prohibitionEvidence, toolBinding = slots?.toolBinding,
                ),
            )
        } catch (e: RuntimeException) {
            return err("build_failed", e.message ?: "build failed")
        }
        counter = next // monotonic: never reuse a counter, even if the call fails
        val provenance: Map<String, Any?>? = try {
            opts.provenance?.forAction(node["verb"] as String, node["resource"] as String, params ?: emptyMap())
        } catch (e: RuntimeException) {
            return err("build_failed", e.message ?: "provenance failed")
        }
        val body = linkedMapOf<String, Any?>("pcactn" to pcactn)
        if (provenance != null) body["pca_provenance"] = provenance
        val res = try {
            call("POST", "/v1/pca/actions", body)
        } catch (e: java.io.IOException) {
            return err("network", e.message ?: "network error")
        }
        val j = res.json
        if (res.status == 202 || j["status"] == "step_up_required" || j["step_up_required"] == true) {
            val id = j["stepup_id"] ?: j["stepupId"] ?: j["id"]
            val t = isNum(j["required_t"] ?: j["requiredT"] ?: j["t"])
            if (id !is String) return err("bad_response", "step-up response missing stepup_id", res.status)
            return ActResult.StepUp(id, t ?: 2.0, pcactn)
        }
        val rawVerdict = j["verdict"]
        val vmap: Map<String, Any?> = if (rawVerdict is Map<*, *>) rawVerdict as Map<String, Any?> else linkedMapOf("allow" to (j["allow"] == true))
        // Allow only on an explicit boolean true from every place the server states it: a truthy string or a contradiction is a deny.
        val allowed = res.status in 200..299 && vmap["allow"] == true && (!j.containsKey("allow") || j["allow"] == true)
        val b = budgetOf(vmap["budget"])
        if (b != null) budget = b
        val verdict = Verdict(vmap["allow"] == true, vmap, b)
        if (allowed) {
            val rr = j["receipt"] as? Map<String, Any?> ?: return err("bad_response", "allow without receipt", res.status)
            val receipt = Receipt(rr)
            if (opts.verifyReceipts) {
                if (!verifyReceipt(receipt)) return err("bad_response", "allow receipt inclusion proof does not verify", res.status)
                if (receipt.salt != null && !receiptBinds(receipt, pcactn)) return err("bad_response", "allow receipt does not commit to this action", res.status)
            }
            return ActResult.Allowed(verdict, receipt, pcactn)
        }
        return ActResult.Denied(verdict, res.status, pcactn)
    }

    /** Poll a step-up until it is decided or [timeoutMs] passes. Only a 2xx answer can approve. */
    fun awaitStepUp(stepupId: String, pollMs: Long = 1000L, timeoutMs: Long = 5 * 60_000L): StepUpOutcome {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val res = try {
                // Long poll (the server answers as soon as the step-up is decided, at most 25 s); servers without it ignore `wait`.
                val wait = minOf(25L, (deadline - System.currentTimeMillis()) / 1000)
                val q = if (wait > 0) "?wait=$wait" else ""
                call("GET", "/v1/pca/stepups/" + URLEncoder.encode(stepupId, "UTF-8").replace("+", "%20") + q)
            } catch (e: java.io.IOException) {
                throw PcaAgentError("network", e.message ?: "network error")
            }
            val s = res.json["status"]
            val ok = res.status in 200..299
            if (ok && (s == "approved" || s == "denied" || s == "expired")) return StepUpOutcome(s as String, res.json)
            // 4xx other than 429 is final (unknown or foreign step-up): stop polling, never approve.
            if (res.status in 400..499 && res.status != 429) return StepUpOutcome("denied", emptyMap(), res.status)
            if (System.currentTimeMillis() + pollMs > deadline) return StepUpOutcome("timeout")
            try { Thread.sleep(pollMs) } catch (e: InterruptedException) { Thread.currentThread().interrupt(); throw PcaAgentError("network", "interrupted") }
        }
    }

    /** A sub-agent over the chain extended by one hop to [toPublic]; it signs with [agentKey] and its counter starts at 0. */
    fun delegate(toPublic: String, addedCaveats: List<Any?> = emptyList(), agentKey: Keys.SuiteKey? = null): AgentClient {
        val own = opts.agentKey ?: throw PcaAgentError("no_secret", "cannot delegate without agentKey")
        @Suppress("UNCHECKED_CAST")
        val child = Issue.delegate(chain.last() as Map<String, Any?>, toPublic, addedCaveats, own)
        return AgentClient(
            CreateAgentOptions(
                grant = grant, chain = chain + listOf<Any?>(child), agentKey = agentKey, agentPublic = toPublic, rsBaseUrl = base, audience = opts.audience,
                ttlMs = opts.ttlMs, now = opts.now, nonce = opts.nonce, fetch = doFetch, verifyReceipts = opts.verifyReceipts,
                counter = 0L, provenance = opts.provenance, // a sub-agent works in the same context session
            ),
            base, doFetch,
        )
    }

    /** True when the receipt's inclusion proof verifies against its root. */
    fun verifyReceipt(r: Receipt): Boolean {
        val root = r.root ?: return false
        val commit = r.commit ?: return false
        return try { Ledger.verifyInclusion(root, r.inclusionProof, commit) } catch (e: RuntimeException) { false }
    }
}

object PcaAgent {
    private val DEFAULT_FETCH = FetchLike { method, url, headers, body ->
        val r = SimpleHttp.request(method, url, headers, body)
        FetchResponse(r.first, r.second)
    }

    /** Build the HTTP agent client. Throws [PcaAgentError] (`build_failed`) when the audience or the base URL is unusable. */
    @JvmStatic
    fun createAgent(opts: CreateAgentOptions): AgentClient {
        if (opts.audience.isEmpty()) {
            throw PcaAgentError("build_failed", "createAgent: `audience` is required (the resource-server / Atlas instance id PCActns are for)")
        }
        val ok = try {
            val u = URI(opts.rsBaseUrl)
            u.isAbsolute && (u.scheme == "https" || u.scheme == "http") && !u.host.isNullOrEmpty()
        } catch (e: java.net.URISyntaxException) {
            false
        }
        if (!ok) throw PcaAgentError("build_failed", "createAgent: `rsBaseUrl` must be an absolute http(s) URL")
        return AgentClient(opts, opts.rsBaseUrl.trimEnd('/'), opts.fetch ?: DEFAULT_FETCH)
    }
}
