package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the authorize pipeline's 0.5 additions: test-data/k05-authorize.json.gz from
 * tools/pca-audit/k05-oracles/authorize-oracle.mts. tool_schema validation / evaluation, the risk policy and the envelope reader
 * compare exactly; every authorize() scenario compares, step by step, the canonical JSON of {allow, decision, status, checks (the
 * pipeline keys), failed, reasons (provenance_flow / undo_window / escalation / fresh_at), escalation ({request: true} on a
 * refusal), undo}.
 */
class K05AuthorizeDiffTest {
    companion object {
        private val KEY = listOf(
            "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature",
            "counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation", "params_digest", "delegated_caveats", "policy",
            "replay", "provenance_flow", "undo_window", "escalation",
        )
        private val OWN = listOf("provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: ")

        const val FILE = "k05-authorize.json.gz"

        fun of(fn: String): List<Map<String, Any?>> =
            K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }

        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        fun canon(v: Any?): String = Json.canonicalize(v)

        @Suppress("UNCHECKED_CAST") fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    }

    private fun check(fn: String, want: (Any?) -> String, got: (List<Any?>) -> String) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val w = want(c["out"])
            val g = try { got(args(c)) } catch (t: Throwable) { "THROWS $t" }
            if (w != g) bad.add("${c["name"]}\n  want: ${w.take(1500)}\n  got:  ${g.take(1500)}")
        }
        report(bad)
    }

    @Test fun argSchema() = check("validateArgSchema", { "$it" }) { "${Authorize.validateArgSchema(it[0])}" }

    @Test fun toolSchema() = check("evaluateToolSchema", { val o = mp(it); "${o["ok"]}|${o["reason"]}" }) {
        // the reference's call members toolSignature / toolSignatureDigest are the native tool_signature / tool_signature_digest
        val call = (it[1] as? Map<*, *>)?.let { c ->
            LinkedHashMap<String, Any?>().also { m ->
                for ((k, v) in c) m[when (k) { "toolSignature" -> "tool_signature"; "toolSignatureDigest" -> "tool_signature_digest"; else -> k as String }] = v
            }
        } ?: it[1]
        val r = Authorize.evaluateToolSchema(it[0], call)
        "${r.ok}|${r.reason}"
    }

    @Test fun riskPolicy() = check("validateRiskPolicy", { "$it" }) { "${KUtil.priv<String?>(Authorize, "validateRiskPolicy", it[0])}" }

    @Test fun attestationRequired() = check("requiresAttestation", { "$it" }) { "${KUtil.priv<Boolean>(Authorize, "requiresAttestation", it[0])}" }

    @Test fun envelope() = check("readEnvelope", { canon(it) }) { canon(Authorize.readEnvelope(it[0])) }

    // ---------------------------------------------------------------- authorize() scenarios

    /** The typed native hook cannot carry a non-integer window_end: such an admission is no admission (null), as the reference refuses it. */
    private fun admission(o: Any?): Undo.Admission? {
        val m = mp(o)
        if (!Json.isSafeInt(m["window_end"])) return null
        val c = mp(m["compensation"])
        return Undo.Admission(m["id"] as String, IntentJs.lng(m["window_end"]), c["verb"] as String, c["resource"] as String)
    }

    private fun scenario(sc: Map<String, Any?>): String {
        val grant = mp(sc["grant"])
        val cfg = mp(sc["config"])
        var revoked = false
        val actions = cfg["actions"] as Map<*, *>?
        val observed = cfg["observed"] as List<*>?
        val undo = cfg["undo"] as Map<*, *>?
        val esc = cfg["escalation"] as Map<*, *>?
        val render = esc?.get("render_digest") as String?
        val store = Authorize.MemoryStateStore()
        val out = ArrayList<Any?>()
        @Suppress("UNCHECKED_CAST")
        val actFn: ((Authorize.Operation) -> Map<String, Any?>?)? = actions?.let { a -> { op -> a[op.verb] as Map<String, Any?>? } }
        val obsFn: ((Map<String, Any?>, Authorize.Operation, String?) -> List<Any?>?)? = observed?.let { o -> { _, _, _ -> o.toList() } }
        val renderFn: ((Map<String, Any?>) -> String?)? = render?.let { rd -> { _ -> rd } }
        val undoHook: Authorize.UndoHook? = undo?.let { u -> Authorize.UndoHook { _, _, op -> u[op.verb]?.let { x -> admission(x) } } }
        val prov = Authorize.ProvenanceOptions((cfg["mediators"] as List<*>).map { mp(it) }, actFn, obsFn)
        for (st in sc["steps"] as List<*>) {
            val s = mp(st)
            revoked = s["revoked"] == true
            val r = Authorize.authorize(
                s["pcactn"],
                Authorize.Input(
                    operation = Authorize.Operation.fromJson(s["operation"]),
                    audience = cfg["audience"] as String,
                    resolveGrant = { ref -> if (ref == grant["id"]) grant else null },
                    stateStore = store,
                    isRevoked = { _, _ -> revoked },
                    now = IntentJs.lng(cfg["now"]),
                    plan = Authorize.SINGLE_STEP,
                    escalationPrincipals = (esc?.get("principals") as List<*>?).orEmpty().map { Escalation.Principal(it as String) },
                    escalationAnswer = s["escalationAnswer"],
                    freshAt = cfg["freshAt"]?.let { FreshAt.Policy.fromJson(it)!! },
                    escalationRender = renderFn,
                    insecureUnboundApproval = esc?.get("insecureUnboundApproval") == true,
                    provenanceOptions = prov,
                    provenance = s["provenance"],
                    undo = undoHook, risk = AuthorizeTestKit.calmRisk,
                ),
            )
            val u = r.undo
            // native check names: the core verifier's `chain` is the reference's `cap_chain`
            val checks = LinkedHashMap<String, String>()
            for ((k, v) in r.checks) checks[if (k == "chain") "cap_chain" else k] = v
            out.add(
                linkedMapOf(
                    "allow" to r.allow, "decision" to r.decision, "status" to r.status.toLong(),
                    "checks" to KEY.filter { checks[it] != null }.associateWith { checks[it] },
                    "failed" to KEY.filter { checks[it] == "fail" },
                    "reasons" to r.reasons.filter { x -> OWN.any { x.startsWith(it) } },
                    "escalation" to (if (r.escalation == null) null else if (r.allow) r.escalation else mapOf("request" to true)),
                    "undo" to u?.let {
                        linkedMapOf("id" to it.id, "window_end" to it.windowEnd, "compensation" to linkedMapOf("verb" to it.compensationVerb, "resource" to it.compensationResource))
                    },
                ),
            )
        }
        return canon(out)
    }

    /** The reference reports an unbound `attestation` as not-enforced; the native leaves the check out (it runs only when bound). */
    private fun wantScenario(o: Any?): String = canon(
        (o as List<*>).map { st ->
            val m = LinkedHashMap(mp(st))
            val c = LinkedHashMap(mp(m["checks"]))
            if (c["attestation"] == "not-enforced") c.remove("attestation")
            m["checks"] = c
            // the reference names its option escalation.render; the native one is Input.escalationRender
            m["reasons"] = (m["reasons"] as List<*>).map { r -> (r as String).replace("(set escalation.render,", "(set escalationRender,") }
            m
        },
    )

    @Test fun authorizeScenarios() = check("authorize", { wantScenario(it) }) { scenario(mp(it[0])) }
}
