package net.atlasauth.pca.authzen

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Replays the TypeScript-reference vectors of the AuthZEN package (guards, mapping, AARP, PDP refusal paths, handler, search), then the
 * permit paths over a real grant and signed PCActn (the default Policy-VM decision).
 */
@Suppress("UNCHECKED_CAST")
class AuthzenDiffTest {
    private val m = "ref-authzen"
    private val now = 1_000_000L

    private fun mm(o: Any?) = o as Map<String, Any?>

    // ---- PDP configs, by the names the vectors use ----

    private fun pdp(name: String): Authzen.AuthzenPdp {
        val c = linkedMapOf<String, Any?>("now" to { now })
        val none = Authzen.Resolver { null }
        when (name) {
            "none" -> c["resolve"] = none
            "throws" -> c["resolve"] = Authzen.Resolver { throw Exception("boom") }
            "noauth" -> c["resolve"] = Authzen.Resolver { linkedMapOf("grant" to linkedMapOf<String, Any?>(), "policy" to linkedMapOf<String, Any?>()) }
            "auth" -> {
                c["resolve"] = Authzen.Resolver { linkedMapOf("grant" to linkedMapOf<String, Any?>(), "policy" to linkedMapOf<String, Any?>()) }
                c["authorizer"] = Authzen.Authorizer { linkedMapOf("allow" to true) }
            }
            "max2" -> { c["resolve"] = none; c["maxEvaluations"] = 2 }
            "toolmap" -> { c["resolve"] = none; c["toolCapability"] = Authzen.ToolCapability { "cap.$it" } }
            "toolthrow" -> { c["resolve"] = none; c["toolCapability"] = Authzen.ToolCapability { throw Exception("bad tool") } }
            else -> throw IllegalArgumentException(name)
        }
        return Authzen.authzenPdp(c)
    }

    // ---- search providers, by name ----

    private fun user(id: String) = linkedMapOf<String, Any?>("type" to "user", "id" to id)
    private fun fn(f: (Map<String, Any?>) -> Map<String, Any?>) = Authzen.SearchFn { f(it) }

    private fun provider(name: String): Map<String, Any?> {
        val p = LinkedHashMap<String, Any?>()
        val boom = Authzen.SearchFn { throw Exception("x") }
        val empty = fn { linkedMapOf("results" to listOf<Any?>()) }
        when (name) {
            "none" -> {}
            "full" -> {
                p["searchSubject"] = fn {
                    linkedMapOf(
                        "results" to listOf(user("a"), user("b"), linkedMapOf("type" to "group", "id" to "g"), user("a"), linkedMapOf("id" to "a", "type" to "user")),
                        "page" to linkedMapOf("next_token" to "", "total" to Js.n(3), "properties" to linkedMapOf("k" to Js.n(1))), "context" to linkedMapOf("c" to Js.n(1)),
                    )
                }
                p["searchResource"] = fn {
                    linkedMapOf(
                        "results" to listOf(linkedMapOf("type" to "doc", "id" to "1"), linkedMapOf("type" to "doc", "id" to "2"), linkedMapOf("type" to "user", "id" to "x")),
                        "page" to linkedMapOf("next_token" to "n1"),
                    )
                }
                p["searchAction"] = fn {
                    linkedMapOf(
                        "results" to listOf(
                            linkedMapOf("name" to "read"), linkedMapOf("name" to "write"), linkedMapOf("name" to "read"),
                            linkedMapOf("name" to "read", "properties" to linkedMapOf("p" to Js.n(1))),
                        ),
                    )
                }
            }
            "nopage" -> {
                p["searchSubject"] = fn { linkedMapOf("results" to listOf(user("a"), user("b"))) }
                p["searchResource"] = empty
                p["searchAction"] = empty
            }
            "emptyprops" -> p["searchSubject"] = fn {
                linkedMapOf("results" to listOf(user("a")), "page" to linkedMapOf("next_token" to "z", "properties" to linkedMapOf<String, Any?>()), "context" to linkedMapOf<String, Any?>())
            }
            "bad" -> {
                p["searchSubject"] = fn { linkedMapOf("results" to listOf<Any?>(null)) }
                p["searchResource"] = fn { linkedMapOf("results" to listOf<Any?>(Js.n(5))) }
                p["searchAction"] = fn { linkedMapOf("results" to listOf<Any?>(null, Js.n(5))) }
            }
            "notarray" -> {
                p["searchSubject"] = fn { linkedMapOf("results" to "x") }
                p["searchResource"] = fn { linkedMapOf() }
                p["searchAction"] = fn { linkedMapOf("results" to null) }
            }
            "throws" -> { p["searchSubject"] = boom; p["searchResource"] = boom; p["searchAction"] = boom }
            "echo" -> for (k in listOf("searchSubject", "searchResource", "searchAction")) p[k] = fn { r -> linkedMapOf("results" to listOf<Any?>(), "context" to linkedMapOf("saw" to r)) }
            "partial" -> p["searchResource"] = empty
            else -> throw IllegalArgumentException(name)
        }
        return p
    }

    @Test fun isAccessEvaluationRequest() = OracleCases.each(m, "isAccessEvaluationRequest") { Authzen.isAccessEvaluationRequest(it[0]) }
    @Test fun isAccessEvaluationsRequest() = OracleCases.each(m, "isAccessEvaluationsRequest") { Authzen.isAccessEvaluationsRequest(it[0]) }
    @Test fun isCoazToolAuthorizationRequest() = OracleCases.each(m, "isCoazToolAuthorizationRequest") { Authzen.isCoazToolAuthorizationRequest(it[0]) }
    @Test fun isAuthzenSubject() = OracleCases.each(m, "isAuthzenSubject") { Authzen.isAuthzenSubject(it[0]) }
    @Test fun isAuthzenAction() = OracleCases.each(m, "isAuthzenAction") { Authzen.isAuthzenAction(it[0]) }
    @Test fun isAuthzenResource() = OracleCases.each(m, "isAuthzenResource") { Authzen.isAuthzenResource(it[0]) }
    @Test fun isSubjectSearch() = OracleCases.each(m, "isSubjectSearch") { Authzen.isSubjectSearch(it[0]) }
    @Test fun isResourceSearch() = OracleCases.each(m, "isResourceSearch") { Authzen.isResourceSearch(it[0]) }
    @Test fun isActionSearch() = OracleCases.each(m, "isActionSearch") { Authzen.isActionSearch(it[0]) }
    @Test fun defaultToAction() = OracleCases.each(m, "defaultToAction") { Authzen.defaultToAction(mm(it[0])) }
    @Test fun approvalOf() = OracleCases.each(m, "approvalOf") { Authzen.approvalOf(it[0]) }
    @Test fun isApprovalRequired() = OracleCases.each(m, "isApprovalRequired") { Authzen.isApprovalRequired(it[0]) }
    @Test fun pdpEvaluate() = OracleCases.each(m, "pdp.evaluate") { pdp(it[0] as String).evaluate(it[1]) }
    @Test fun pdpEvaluations() = OracleCases.each(m, "pdp.evaluations") { pdp(it[0] as String).evaluations(it[1]) }
    @Test fun pdpEvaluateTool() = OracleCases.each(m, "pdp.evaluateTool") { pdp(it[0] as String).evaluateTool(mm(it[1])) }
    @Test fun authzenHandler() = OracleCases.each(m, "authzenHandler") { pdp(it[0] as String).handle(mm(it[1])) }
    @Test fun authzenSearchHandler() = OracleCases.each(m, "authzenSearchHandler") { Authzen.authzenSearchHandler(provider(it[0] as String), mm(it[1])) }
    @Test fun searchMetadata() = OracleCases.each(m, "searchMetadata") { Authzen.searchMetadata(it[0] as String, provider(it[1] as String)) }

    // ---- permit paths: a real grant and signed PCActn ----

    private fun corePdp(d: Map<String, Any?>): Authzen.AuthzenPdp {
        val c = linkedMapOf<String, Any?>("now" to { net.atlasauth.pca.verifier.BaseOracle.T0 })
        val ctx = linkedMapOf<String, Any?>("grant" to d["grant"], "policy" to (d["policy"] ?: linkedMapOf("predicates" to listOf<Any?>(), "caveats" to listOf<Any?>())))
        for (k in listOf("budget", "risk", "plan")) if (d[k] != null) ctx[k] = d[k]
        c["resolve"] = Authzen.Resolver { ctx }
        for (k in listOf("audience", "insecureSkipPlanRootCheck", "authorizedPlanRoots", "requireAuthorizer", "requireProof")) if (d.containsKey(k)) c[k] = d[k]
        if (d["authorizer"] == true) c["authorizer"] = Authzen.Authorizer { linkedMapOf("allow" to true) }
        return Authzen.authzenPdp(c)
    }

    @Test fun coreEvaluate() = OracleCases.each("ref-authzen-java-extra", "evaluate") { a -> corePdp(mm(a[0])).evaluate(a[1]) }

    @Test fun constants() {
        assertEquals("/access/v1/evaluation", Authzen.EVALUATION_PATH)
        assertEquals("/access/v1/evaluations", Authzen.EVALUATIONS_PATH)
        assertEquals("/access/v1/mcp/tool/evaluation", Authzen.COAZ_TOOL_PATH)
        assertEquals("/access/v1/search/subject", Authzen.SEARCH_SUBJECT_PATH)
        assertEquals(1000, Authzen.MAX_SEARCH_LIMIT)
        assertEquals(100, Authzen.DEFAULT_MAX_EVALUATIONS)
    }
}
