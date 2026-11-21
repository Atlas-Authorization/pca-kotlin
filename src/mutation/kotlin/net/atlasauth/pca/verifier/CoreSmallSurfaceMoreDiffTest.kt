package net.atlasauth.pca.verifier

import net.atlasauth.pca.dataflow.Detectors
import net.atlasauth.pca.jose.Jose
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The rest of the small public surface of the reference (ref-core-small-surface): the cheap pre-authentication claims and chain checks, the goal
 * commitment, discharge requests, the named unmet limit, the reversibility class, thresholds, obligations, detector receipts and policy, the workflow
 * checks, discovery, revocation membership and staleness policy, canonical compact JWS forms and the payment approval profiles. CoreSmallSurfaceDiffTest
 * replays the other functions of the corpus; the last test asserts that together they are the whole corpus.
 */
@Suppress("UNCHECKED_CAST")
class CoreSmallSurfaceMoreDiffTest {
    private val mod = "ref-core-small-surface"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun str(o: Any?): String? = o as? String

    private fun tryOr(f: () -> Any?): Map<String, Any?> = try {
        linkedMapOf("v" to f(), "ok" to true)
    } catch (e: RuntimeException) {
        linkedMapOf("ok" to false)
    }

    private fun ok(f: () -> Any?): Boolean = try { f(); true } catch (e: RuntimeException) { false }

    @Test fun cheapClaimsAndChains() {
        OracleCases.each(mod, "pcactnCheapClaims") { a ->
            Pca.pcactnCheapClaims(map(a[0])!!, str(a[1])!!, IntentJs.num(a[2])!!)?.let { linkedMapOf("check" to it.check, "reason" to it.reason) }
        }
        OracleCases.each(mod, "verifyChainCheap") { a ->
            val r = Pca.verifyChainCheap(a[0] as? List<Any?>, str(a[1]), (a[2] as List<Any?>?)?.map { it as String })
            val out = linkedMapOf<String, Any?>("ok" to r.ok)
            if (r.ok) out["pqHops"] = r.pqHops else out["reason"] = r.reason
            out
        }
        OracleCases.each(mod, "holderPqKey") { a -> Pca.holderPqKey(a[0], str(a[1])!!, a[2], str(a[3])) }
    }

    @Test fun goalCommitAndDischarge() {
        OracleCases.each(mod, "goalCommitOf") { a -> Issue.goalCommit(str(a[0])!!, str(a[1])!!) }
        OracleCases.each(mod, "verifyGoalCommit") { a -> Issue.verifyGoalCommit(str(a[0])!!, str(a[1])!!, str(a[2])!!) }
        OracleCases.each(mod, "dischargeRequests") { a -> CaveatLang.dischargeRequests(a[0], a[1], str(a[2])) }
        OracleCases.each(mod, "namedUnmetLimitReason") { a -> Predicates.namedUnmetLimitReason(a[0], map(a[1])) }
        OracleCases.each(mod, "resolveReversibilityClass") { a -> Decide.resolveReversibilityClass(map(a[0]), a[1] as List<Any?>?, a[2]) }
    }

    @Test fun thresholdsAndObligations() {
        OracleCases.each(mod, "assembleThreshold") { a -> Threshold.assembleThreshold(a[0] as? List<Any?>) } // a non-array has no shares
        OracleCases.each(mod, "isBudgetAllocCaveat") { a -> Pca.isBudgetAllocCaveat(a[0]) }
        OracleCases.each(mod, "meetAll") { a -> PcaDecision.meetAll(list(a[0]).map { it as String }) }
        OracleCases.each(mod, "escalateThreshold") { a ->
            val rt = map(a[0])!!
            val r = Risk.escalateThreshold(Risk.Threshold(Json.asLong(rt["t"]).toInt(), rt["proof"] as String, rt["optimisticAllowed"] == true), Json.asLong(a[1]).toInt())
            linkedMapOf("t" to r.t, "proof" to r.proof, "optimisticAllowed" to r.optimisticAllowed)
        }
        OracleCases.each(mod, "collectObligations") { a ->
            val r = Obligations.collectObligations(a[0], map(a[1]))
            val out = linkedMapOf<String, Any?>("ok" to r.ok)
            if (r.ok) out["obligations"] = r.obligations else out["reason"] = r.reason
            out
        }
    }

    @Test fun detectorsAndWorkflow() {
        OracleCases.each(mod, "detectorReceiptShapeError") { a -> Detectors.detectorReceiptShapeError(a[0]) }
        OracleCases.each(mod, "detectorReceiptRef") { a -> Detectors.detectorReceiptRef(a[0]) }
        OracleCases.each(mod, "detectorPolicyError") { a -> Detectors.detectorPolicyError(a[0]) }
        OracleCases.each(mod, "workflowCommitmentError") { a -> Workflow.workflowCommitmentError(a[0], a[1], a[2]) }
        OracleCases.each(mod, "workflowReceiptError") { a -> Workflow.workflowReceiptError(map(a[0])!!, str(a[1])!!, list(a[2]), Json.asLong(a[3]))?.toLong() }
    }

    @Test fun discovery() {
        OracleCases.each(mod, "parseDiscoveryDocument") { a -> Discovery.parseDiscoveryDocument(a[0]) }
        OracleCases.each(mod, "parseDiscoveryIntent") { a -> Discovery.parseDiscoveryIntent(a[0]) }
        OracleCases.each(mod, "acceptsSuite") { a -> Discovery.acceptsSuite(map(a[0])!!, str(a[1])!!) }
        OracleCases.each(mod, "buildDiscoveryDocument") { a -> Discovery.buildDiscoveryDocument(map(a[0])!!) }
        OracleCases.each(mod, "fetchDiscovery") { a ->
            val mode = str(a[1])!!
            val urls = ArrayList<Any?>()
            val f = Discovery.Fetch { url, headers ->
                urls.add("$url|${headers["accept"]}")
                if (mode == "throw") throw IllegalStateException("boom")
                val body = if (mode == "bad") "{\"nope\":1}"
                else "{\"audience\":\"https://rs.example\",\"pca_versions\":[2],\"signature_suites\":[\"ed25519\",\"ml-dsa-65\"],\"action_header\":\"PCA-Action\"}"
                Pair(if (mode == "500") 500 else 200, body)
            }
            val out = linkedMapOf<String, Any?>()
            try {
                out["doc"] = Discovery.fetchDiscovery(str(a[0])!!, f)
            } catch (e: Exception) {
                out["error"] = true
            }
            out["urls"] = urls
            out
        }
    }

    @Test fun revocation() {
        OracleCases.each(mod, "verifyMembership") { a -> Revocation.verifyMembership(str(a[0])!!, map(a[1]), str(a[2])!!) }
        OracleCases.each(mod, "validateRevocationStaleness") { a ->
            // the corpus spells the policy as the reference does (maxRevocationAgeMs, staleness.{irreversible, rate_limited, costly}); each window must be a positive finite number
            fun window(present: Boolean, v: Any?, mk: (Double) -> Revocation.StalenessPolicy) {
                if (!present) return
                val d = IntentJs.num(v) ?: throw IllegalArgumentException("must be a positive number of milliseconds")
                mk(d)
            }
            linkedMapOf<String, Any?>("ok" to ok {
                val p = map(a[0]) ?: throw IllegalArgumentException("revocation staleness policy must be an object")
                window(p.containsKey("maxRevocationAgeMs"), p["maxRevocationAgeMs"]) { Revocation.StalenessPolicy(maxRevocationAgeMs = it) }
                val st = map(p["staleness"]) ?: LinkedHashMap()
                window(st.containsKey("irreversible"), st["irreversible"]) { Revocation.StalenessPolicy(irreversibleMs = it) }
                for (k in listOf("rate_limited", "costly")) window(st.containsKey(k), st[k]) { Revocation.StalenessPolicy(costlyMs = it) }
            })
        }
    }

    @Test fun canonicalJws() {
        OracleCases.each(mod, "isCanonicalCompactJws") { a -> ok { Jose.assertCanonicalCompactJws(a[0]) } }
        OracleCases.each(mod, "isCanonicalCompactJwsOpaque") { a -> ok { Jose.assertCanonicalCompactJws(a[0], 3, Jose.DEFAULT_MAX_JWS_BYTES, false) } }
        OracleCases.each(mod, "isCanonicalCompactJwsMax") { a -> ok { Jose.assertCanonicalCompactJws(a[0], 3, 40, true) } }
        OracleCases.each(mod, "isCanonicalCompactJwsFive") { a -> ok { Jose.assertCanonicalCompactJws(a[0], 5, Jose.DEFAULT_MAX_JWS_BYTES, true) } }
        OracleCases.each(mod, "assertCanonicalJwsSegments") { a ->
            try {
                val p = a[0]
                val s = a[1]
                if (p !is String || s !is String) throw IllegalArgumentException("not-a-string")
                if (p.length + s.length > Jose.DEFAULT_MAX_JWS_BYTES) throw IllegalArgumentException("too-long")
                if (p.isEmpty() || s.isEmpty()) throw IllegalArgumentException("empty-segment")
                val header = Jose.decodeCanonicalJsonSegment(p) as? Map<String, Any?> ?: throw IllegalArgumentException("not-an-object")
                Jose.decodeCanonicalBase64url(s)
                linkedMapOf("header" to header, "ok" to true)
            } catch (e: RuntimeException) {
                linkedMapOf("ok" to false)
            }
        }
    }

    @Test fun paymentApprovalProfiles() {
        OracleCases.each(mod, "spcExpectation") { a -> tryOr { Approval.spcExpectation(map(a[0])!!, "https://shop.example", if (a.size > 1 && a[1] is String) a[1] as String else "name") } }
        OracleCases.each(mod, "cibaApprovalDetails") { a -> tryOr { Approval.cibaApprovalDetails(map(a[0])!!) } }
    }

    /** Together with CoreSmallSurfaceDiffTest, every fn of the corpus and every case of it. */
    @Test fun theWholeSmallSurfaceCorpusIsReplayed() {
        val mine = setOf(
            "pcactnCheapClaims", "verifyChainCheap", "holderPqKey", "goalCommitOf", "verifyGoalCommit", "dischargeRequests", "namedUnmetLimitReason", "resolveReversibilityClass",
            "assembleThreshold", "isBudgetAllocCaveat", "meetAll", "escalateThreshold", "collectObligations", "detectorReceiptShapeError", "detectorReceiptRef", "detectorPolicyError",
            "workflowCommitmentError", "workflowReceiptError", "parseDiscoveryDocument", "parseDiscoveryIntent", "acceptsSuite", "buildDiscoveryDocument", "fetchDiscovery",
            "verifyMembership", "validateRevocationStaleness", "isCanonicalCompactJws", "isCanonicalCompactJwsOpaque", "isCanonicalCompactJwsMax", "isCanonicalCompactJwsFive",
            "assertCanonicalJwsSegments", "spcExpectation", "cibaApprovalDetails",
        )
        val other = setOf(
            "agentCaveatContext", "catalogReversibilityScore", "catalogRisk", "detectorSignal", "guardSeq", "listTemplates", "fromTemplate", "policyBuilder", "createLink", "slotsDigest",
            "linkDigest", "limits", "undoLifecycle", "undoStore",
        )
        assertEquals(mine + other, BaseOracle.fns("$mod.json.gz"))
        assertEquals(1113, (mine + other).sumOf { OracleCases.of(mod, it).size })
    }
}
