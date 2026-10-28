package net.atlasauth.pca.guard

import java.io.File
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Escalation
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Test data for the framework integrations: grants and PCActns signed by the reference implementation (the shared
 * `authorize-fixtures.json` and the `model-rules-vectors.json` escalate case). A missing file FAILS the test, never skips it.
 */
@Suppress("UNCHECKED_CAST")
object GuardFixtures {
    private fun findUp(vararg rels: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            for (rel in rels) {
                val c = File(dir, rel)
                if (c.exists()) return c
            }
            dir = dir.parentFile
        }
        throw IllegalStateException("${rels.toList()} is missing: the shared corpus must be present (never skipped)")
    }

    private fun load(vararg rels: String): Map<String, Any?> = Json.parseLenient(findUp(*rels).readText(Charsets.UTF_8)) as Map<String, Any?>

    private val authorizeFixtures: Map<String, Any?> by lazy { load("test-data/authorize-fixtures.json") }
    private val modelRules: Map<String, Any?> by lazy { load("packages/pca/conformance/model-rules-vectors.json", "conformance/model-rules-vectors.json") }
    private val keys: Map<String, Any?> by lazy { load("packages/pca/conformance/keys.json", "conformance/keys.json") }

    /** One signed request: the stored grant, the PCActn, the operation it is for, and the clock / audience it verifies under. */
    class Scenario(
        val grant: Map<String, Any?>, val pcactn: Map<String, Any?>, val operation: Authorize.Operation, val audience: String, val now: Long,
    ) {
        /** The `PCA-Action` header value: strict unpadded base64url of the PCActn JSON. */
        val header: String get() = headerOf(pcactn)

        /** The same PCActn as a body: `{"pcactn": ...}`. */
        val body: String get() = Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to pcactn))

        /** The same, with a different PCActn member (a copy with `edit` applied). */
        fun withPcactn(edit: (MutableMap<String, Any?>) -> Unit): Scenario {
            val copy = LinkedHashMap(pcactn)
            edit(copy)
            return Scenario(grant, copy, operation, audience, now)
        }

        fun config(authorize: Authorize.AuthorizeOptions?, signatureOnly: Boolean = false, executor: PcaExecutorConfig? = null): PcaGuardConfig =
            PcaGuardConfig(audience, { ref -> if (ref == grant["id"]) grant else null }, authorize, null, signatureOnly, { now }, executor)
    }

    fun headerOf(value: Any?): String = Pca.b64(Json.canonicalize(value).toByteArray(Charsets.UTF_8))

    private fun fromAuthorize(name: String, step: Int): Scenario {
        val c = (authorizeFixtures["cases"] as List<Map<String, Any?>>).first { it["name"] == name }
        val s = (c["steps"] as List<Map<String, Any?>>)[step]
        return Scenario(
            c["grant"] as Map<String, Any?>, s["pcactn"] as Map<String, Any?>, Authorize.Operation.fromJson(s["operation"])!!,
            authorizeFixtures["audience"] as String, Json.asLong(authorizeFixtures["now"]),
        )
    }

    /** A $50 payment under a $100 limit: allowed. */
    fun within(): Scenario = fromAuthorize("envelope-predicate-within", 0)

    /** A validly signed $400 payment under a $100 limit: refused by policy (403). */
    fun overLimit(): Scenario = fromAuthorize("envelope-predicate-400-refused", 0)

    /** A proof signed for another verb than the operation: refused by the operation binding (403). */
    fun otherVerb(): Scenario = fromAuthorize("operation-other-verb", 0)

    /** A proof for another audience: unauthenticated (401). */
    fun wrongAudience(): Scenario = fromAuthorize("wrong-audience", 0)

    /** A grant whose signed tighten rule asks a human: the decision is `escalate`, never an allow. */
    fun escalating(): Scenario {
        val c = (modelRules["cases"] as List<Map<String, Any?>>).first { it["name"] == "tighten-escalate" }
        return Scenario(
            c["grant"] as Map<String, Any?>, c["pcactn"] as Map<String, Any?>, Authorize.Operation.fromJson(c["operation"])!!,
            modelRules["audience"] as String, Json.asLong(modelRules["now"]),
        )
    }

    private val workflowFixtures: Map<String, Any?> by lazy {
        load("packages/pca/conformance/authorize-workflow-fixtures.json", "conformance/authorize-workflow-fixtures.json")
    }

    /** One step of a workflow fixture case: the signed request, the workflow step member it carries (null = none) and what it must answer. */
    class WorkflowCall(val scenario: Scenario, val member: Map<String, Any?>?, val expect: Map<String, Any?>) {
        /** The step as the per-request callback returns it. */
        val step: Authorize.WorkflowStep? get() = member?.let {
            Authorize.WorkflowStep(it["commitment"], it["receipts"], it["step"] as String?, (it["units"] as Map<String, Any?>?) ?: emptyMap(), it["goal_digest"] as String?)
        }

        /** The body transport: `{"pcactn": ..., "workflow": ...}` (the `workflow` member only when the step exists). */
        val body: String get() {
            val env = linkedMapOf<String, Any?>("pcactn" to scenario.pcactn)
            if (member != null) env["workflow"] = member
            return Json.canonicalize(env)
        }
    }

    /** Step `n` of the workflow fixture case `name`, with the case's `required` flag. */
    fun workflowCall(name: String, n: Int = 0): Pair<WorkflowCall, Boolean> {
        val c = (workflowFixtures["cases"] as List<Map<String, Any?>>).first { it["name"] == name }
        val st = (c["steps"] as List<Map<String, Any?>>)[n]
        val sc = Scenario(
            workflowFixtures["grant"] as Map<String, Any?>, st["pcactn"] as Map<String, Any?>, Authorize.Operation.fromJson(st["operation"])!!,
            workflowFixtures["audience"] as String, Json.asLong(workflowFixtures["now"]),
        )
        return Pair(WorkflowCall(sc, st["workflow"] as Map<String, Any?>?, st["expect"] as Map<String, Any?>), c["required"] == true)
    }

    /** Authorize options with the workflow gate pinned to the fixture's keys (and the fixture's authorized plan), or no gate. */
    fun workflowOptions(required: Boolean = false, gate: Boolean = true): Authorize.AuthorizeOptions =
        Authorize.AuthorizeOptions(
            Authorize.MemoryStateStore(), { _, _ -> false },
            context = { _ -> mapOf("plan" to workflowFixtures["plan"], "plan_authorized" to true) },
            workflow = if (gate) Authorize.WorkflowGate(workflowFixtures["principal"] as String, workflowFixtures["rs_signer"] as String, required) else null,
        )

    /** The pinned answering principal (an Ed25519 key pair from the shared key file). */
    private val principal: Map<String, Any?> get() = keys["principal"] as Map<String, Any?>
    val principalPublic: String get() = principal["public"] as String
    fun principals(): List<Escalation.Principal> = listOf(Escalation.Principal(principalPublic))

    /** The principal's signed `allow` answer for the first escalation of `s` (an empty replay history). */
    fun signedAllow(s: Scenario, last: Long? = null): Map<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Json.Num("1")
        body["kind"] = "pca-escalation-answer"
        body["principal"] = principalPublic
        body["policy_digest"] = Escalation.policyDigest(s.grant)
        body["action_digest"] = Escalation.actionDigest(s.pcactn)
        body["history_head"] = Escalation.historyHead(last)
        body["decision"] = "allow"
        body["iat"] = Json.Num((s.now - 1000).toString())
        body["expires_at"] = Json.Num((s.now + 600_000).toString())
        body["nonce"] = "CQkJCQkJCQkJCQkJCQkJCQ"
        val msg = Pca.concat(Escalation.ANSWER_DOMAIN.toByteArray(Charsets.UTF_8), Pca.canonBytes(body))
        val seed = Pca.decodeB64uStrict(principal["seed"], 32)!!
        val sig = ByteArray(64)
        Ed25519.sign(seed, 0, msg, 0, msg.size, sig, 0)
        body["sig"] = Pca.b64(sig)
        return body
    }

    /** The authorize options a guard test uses: a fresh in-memory replay store, nothing revoked. */
    fun options(principals: List<Escalation.Principal> = emptyList()): Authorize.AuthorizeOptions =
        Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, escalationPrincipals = principals, insecureUnboundApproval = true)

    /** Parse a refusal body. */
    fun parse(body: String): Map<String, Any?> = Json.parseLenient(body) as Map<String, Any?>

    /** An executor config over a fresh in-memory operation store; an irreversible operation passes its re-check unless `recheck` says otherwise. */
    fun executor(store: Operations.Store = Operations.MemoryStore(), recheck: (Operations.ExecutionHandle) -> Operations.Recheck = { Operations.Recheck.OK }): PcaExecutorConfig =
        PcaExecutorConfig(store, recheck)

    /** A store that already holds a record in `state` for the operation `s` is authorized for (an earlier, unfinished execution). */
    fun storeWith(s: Scenario, state: String): Operations.Store {
        val store = Operations.MemoryStore()
        val op = s.operation
        store.create(
            linkedMapOf(
                "id" to Pca.hashCanonical(s.pcactn), "state" to state, "verb" to op.verb, "resource" to op.resource,
                "params_digest" to Pca.paramsDigest(op.params), "reversibility" to "irreversible", "startedAt" to s.now,
                "executingAt" to s.now, "error" to "test",
            ),
        )
        return store
    }
}
