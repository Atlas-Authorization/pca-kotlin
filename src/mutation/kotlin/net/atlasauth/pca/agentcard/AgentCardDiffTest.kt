package net.atlasauth.pca.agentcard

import net.atlasauth.pca.a2a.A2aPca
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the signed Agent Card / AgentFacts package through the native port. */
@Suppress("UNCHECKED_CAST")
class AgentCardDiffTest {
    private val m = "ref-agentcard"
    private val libReason = Regex("^(signature \\d+ did not verify|could not resolve verification key): ")

    private fun map(o: Any?) = o as Map<String, Any?>

    /** Reasons that quote the JOSE library are compared up to the first colon. */
    private fun norm(r: Map<String, Any?>): Any? {
        val c = LinkedHashMap(r)
        val reason = c["reason"]
        if (reason is String) libReason.find(reason)?.let { c["reason"] = it.groupValues[1] }
        if (c["attestations"] is List<*>) {
            c["attestations"] = (c["attestations"] as List<Any?>).map { a ->
                val x = LinkedHashMap(map(a))
                val rs = x["reason"]
                if (rs is String && rs.startsWith("signature did not verify: ")) x["reason"] = "signature did not verify"
                x
            }
        }
        return c
    }

    private fun issueOpts(a: List<Any?>): A2aPca.IssueOptions {
        val io = A2aPca.IssueOptions()
        if (a.size > 2) {
            val o = map(a[2])
            io.alg = o["alg"] as String?
            io.kid = o["kid"] as String?
            io.profile = o["profile"] as String?
            io.schema = o["schema"] as String?
            io.passport = if (o["passport"] == null) null else map(o["passport"])
        }
        return io
    }

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "DEFAULT_ALG" to AgentCards.DEFAULT_ALG,
            "PCA_ATTESTOR_ID" to AgentCards.PCA_ATTESTOR_ID,
            "WELL_KNOWN_AGENT_CARD_PATH" to AgentCards.WELL_KNOWN_AGENT_CARD_PATH,
            "WELL_KNOWN_AGENT_FACTS_PATH" to AgentCards.WELL_KNOWN_AGENT_FACTS_PATH,
            "AGENT_FACTS_CONTEXT" to ArrayList<Any?>(AgentCards.AGENT_FACTS_CONTEXT),
        )
    }

    @Test fun jcsBytes() = OracleCases.each(m, "jcsBytes") { a -> AgentCards.jcsBytes(a[0]) }
    @Test fun validateAgentCard1() = OracleCases.each(m, "validateAgentCard1") { a -> AgentCards.validateAgentCard1(a[0]) }
    @Test fun buildAgentCard() = OracleCases.each(m, "buildAgentCard") { a -> AgentCards.buildAgentCard(a[0], map(a[1])) }
    @Test fun issueSignedAgentCard() = OracleCases.each(m, "issueSignedAgentCard") { a -> AgentCards.issueSignedAgentCard(a[0], map(a[1]), issueOpts(a)) }

    @Test fun verifyAgentCard() = OracleCases.each(m, "verifyAgentCard") { a ->
        val o = map(a[1])
        val vo = A2aPca.VerifyCardOptions()
        vo.jwks = o["jwks"]
        vo.key = o["key"]
        vo.alg = o["alg"] as String?
        vo.schema = o["schema"] as String?
        norm(AgentCards.verifyAgentCard(a[0], vo))
    }

    @Test fun issueAgentFacts() = OracleCases.each(m, "issueAgentFacts") { a -> AgentCards.issueAgentFacts(a[0], map(a[1])) }
    @Test fun addAttestation() = OracleCases.each(m, "addAttestation") { a -> AgentCards.addAttestation(a[0], map(a[1])) }
    @Test fun verifyAgentFacts() = OracleCases.each(m, "verifyAgentFacts") { a -> norm(AgentCards.verifyAgentFacts(a[0], map(a[1]))) }

    private fun serve(h: AgentCards.PathHandler, req: Any?): Map<String, Any?>? = h.apply(req as String)

    @Test fun agentCardHandler() = OracleCases.each(m, "agentCardHandler") { a -> serve(AgentCards.agentCardHandler(a[0], a[1] as String?), a[2]) }
    @Test fun agentFactsHandler() = OracleCases.each(m, "agentFactsHandler") { a -> serve(AgentCards.agentFactsHandler(a[0], a[1] as String?), a[2]) }
    @Test fun toRegistryEntry() = OracleCases.each(m, "toRegistryEntry") { a -> AgentCards.toRegistryEntry(a[0], a[1]) }
}
