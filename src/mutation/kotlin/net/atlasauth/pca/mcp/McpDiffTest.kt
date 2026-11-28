package net.atlasauth.pca.mcp

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** Replays the TypeScript-reference vectors of the MCP adapter through the native port, plus the tool-call reader the oracle cannot reach. */
@Suppress("UNCHECKED_CAST")
class McpDiffTest {
    private val m = "ref-mcp"

    private fun map(o: Any?) = o as Map<String, Any?>

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "MCP_CLIENT_REVISIONS" to ArrayList<Any?>(Mcp.MCP_CLIENT_REVISIONS),
            "MCP_AUTH_CLIENT_ROWS" to ArrayList<Any?>(Mcp.mcpAuthClientRows()),
        )
    }

    @Test fun parseChallenges() = OracleCases.each(m, "parseChallenges") { a -> Mcp.parseChallenges(a[0]) }
    @Test fun pcaNeedProblem() = OracleCases.each(m, "pcaNeedProblem") { a -> Mcp.pcaNeedProblem(a[0]) }
    @Test fun planStepUp() = OracleCases.each(m, "planStepUp") { a -> Mcp.planStepUp(a[0], a[1], map(a[2])) }
    @Test fun checkAuthorizationResponseIss() = OracleCases.each(m, "checkAuthorizationResponseIss") { a -> Mcp.checkAuthorizationResponseIss(map(a[0])) }
    @Test fun guardToolResult() = OracleCases.each(m, "guardToolResult") { a -> Mcp.guardToolResult(a[0], a[1]) }
    @Test fun pcaHeaders() = OracleCases.each(m, "pcaHeaders") { a -> Mcp.pcaHeaders(a[0] as String) }
    @Test fun draftActionSchemaFromMcp() = OracleCases.each(m, "draftActionSchemaFromMcp") { a -> Mcp.draftActionSchemaFromMcp(a[0] as List<Any?>, map(a[1])) }
    @Test fun applySchemaDecisions() = OracleCases.each(m, "applySchemaDecisions") { a -> Mcp.applySchemaDecisions(a[0], map(a[1])) }
    @Test fun verbOfTool() = OracleCases.each(m, "verbOfTool") { a -> Mcp.verbOfTool(a[0], a[1]) }
    @Test fun conformToolCall() = OracleCases.each(m, "conformToolCall") { a -> Mcp.conformToolCall(a[0], a[1] as String, a[2]) }

    @Test fun toolCallOfReadsOnlyToolsCall() {
        val c = Mcp.toolCallOf("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":{\"a\":1}}}")
        assertNotNull(c)
        assertEquals("pay", c!!["name"])
        assertEquals(1, map(c["arguments"]).size)
        val noArgs = Mcp.toolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":[1]}}")
        assertNotNull(noArgs)
        assertEquals(0, map(noArgs!!["arguments"]).size) // arguments that are not an object count as none
        assertNull(Mcp.toolCallOf("{\"method\":\"tools/list\"}"))
        assertNull(Mcp.toolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":5}}"))
        assertNull(Mcp.toolCallOf("not json"))
        assertNull(Mcp.toolCallOf("[]"))
        assertNull(Mcp.toolCallOf(null))
    }
}
