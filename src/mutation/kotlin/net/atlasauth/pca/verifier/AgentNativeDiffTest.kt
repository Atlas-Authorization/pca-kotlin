package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Replays every case of the reference oracle for the agent-native module (caution, rationale, tool-schema firewall, envelope
 * introspection, leases): 1632 cases, every fn dispatched, an unhandled fn fails the test. Total functions compare their returned
 * value (reason strings included); a {"$throws"} case needs the native to throw.
 */
@Suppress("UNCHECKED_CAST")
class AgentNativeDiffTest {
    private val mod = "ref-agent-native"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    /** {"$num": "NaN" | "Infinity" | "-Infinity"} is that double; {"$bytes": b64u} is the byte array. */
    private fun dec(v: Any?): Any? = when (v) {
        is List<*> -> v.map { dec(it) }
        is Map<*, *> -> when {
            v.size == 1 && v["\$num"] is String -> when (v["\$num"]) { "NaN" -> Double.NaN; "Infinity" -> Double.POSITIVE_INFINITY; else -> Double.NEGATIVE_INFINITY }
            v.size == 1 && v["\$bytes"] is String -> Keys.unb64u(v["\$bytes"] as String)
            else -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = dec(x) }
        }
        else -> v
    }

    private fun judge(spec: String): (String, Any?) -> Any? = when {
        spec == "true" -> ({ _, _ -> true })
        spec == "false" -> ({ _, _ -> false })
        spec == "throw" -> ({ _, _ -> throw IllegalStateException("judge") })
        spec == "truthy" -> ({ _, _ -> "yes" })
        spec.startsWith("contains:") -> ({ r, _ -> r.contains(spec.removePrefix("contains:")) })
        spec.startsWith("action-verb:") -> ({ _, a -> a is Map<*, *> && a["verb"] == spec.removePrefix("action-verb:") })
        else -> throw AssertionError("unknown judge spec $spec")
    }

    private fun firewall(r: Authorize.ToolSchemaResult): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["ok"] = r.ok
        if (r.reason != null) o["reason"] = r.reason
        return o
    }

    private fun call(fn: String, a: List<Any?>): Any? {
        fun arg(i: Int): Any? = a.getOrNull(i)
        return when (fn) {
            "signCaution" -> SignersMore.signCaution(m(arg(0)), Keys.edFromSeed(arg(1) as ByteArray))
            "signHeartbeat" -> SignersMore.signHeartbeat(m(arg(0)), Keys.edFromSeed(arg(1) as ByteArray))
            "verifyCaution" -> AgentNative.verifyCaution(arg(0), arg(1), arg(2))
            "combineCaution" -> AgentNative.combineCaution(arg(0), arg(1))
            "combineSignedCaution" -> AgentNative.combineSignedCaution(arg(0), arg(1), arg(2), arg(3))
            "checkCautionMonotone" -> AgentNative.checkCautionMonotone(arg(0))
            "isStrongSalt" -> AgentNative.isStrongSalt(arg(0))
            "bindRationale" -> AgentNative.bindRationale(arg(0), arg(1), arg(2))
            "verifyRationale" -> if (a.size < 3) AgentNative.verifyRationale(arg(0), arg(1)) else AgentNative.verifyRationale(arg(0), arg(1), arg(2))
            "auditRationale" -> AgentNative.auditRationale(arg(0), arg(1), arg(2), judge(arg(3) as String))
            "validateArgSchema" -> Authorize.validateArgSchema(arg(0))
            "toolSchemaCaveat" -> AgentNative.toolSchemaCaveat(arg(0), arg(1))
            "evaluateToolSchema" -> firewall(Authorize.evaluateToolSchema(arg(0), arg(1)))
            "toolSchemaEvaluator" -> AgentNative.toolSchemaEvaluator(arg(0), arg(1))
            "predicatesCaveat" -> AgentNative.predicatesCaveat(arg(0))
            "actionSpendUsd" -> AgentNative.actionSpendUsd(arg(0))
            "agentNativeCaveatEvaluator" -> AgentNative.agentNativeCaveatEvaluator(arg(0), arg(1))
            "describeEnvelope" -> AgentNative.describeEnvelope(arg(0), arg(1), arg(2) as String?, arg(3)?.let { m(it) })
            "envelopePermits" -> AgentNative.envelopePermits(arg(0), arg(1), arg(2), arg(3), arg(4))
            "envelopePermitsToolCall" -> AgentNative.envelopePermitsToolCall(arg(0), arg(1))
            "grantLease" -> AgentNative.grantLease(arg(0))
            "leaseState" -> AgentNative.leaseState(arg(0), arg(1))
            "renewLease" -> AgentNative.renewCapabilityLease(arg(0), arg(1), arg(2))
            "constants" -> AgentNative.constants()
            else -> throw AssertionError("unhandled fn $fn")
        }
    }

    private val handled = setOf(
        "signCaution", "verifyCaution", "combineCaution", "combineSignedCaution", "checkCautionMonotone", "isStrongSalt", "bindRationale",
        "verifyRationale", "auditRationale", "validateArgSchema", "toolSchemaCaveat", "evaluateToolSchema", "toolSchemaEvaluator", "predicatesCaveat",
        "actionSpendUsd", "agentNativeCaveatEvaluator", "describeEnvelope", "envelopePermits", "envelopePermitsToolCall", "grantLease", "leaseState",
        "signHeartbeat", "renewLease", "constants",
    )

    /** The oracle holds exactly the fns this test dispatches (a new fn in the corpus fails here, never passes unreplayed). */
    @Test fun everyFnIsHandled() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        assertEquals(1632, handled.sumOf { OracleCases.of(mod, it).size })
    }

    @Test fun replayAllCases() {
        for (fn in handled) OracleCases.each(mod, fn) { a -> call(fn, dec(a) as List<Any?>) }
    }
}
