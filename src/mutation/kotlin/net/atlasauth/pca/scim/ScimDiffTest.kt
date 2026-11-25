package net.atlasauth.pca.scim

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle for the SCIM provisioning package (see the oracle header for the case shapes). */
@Suppress("UNCHECKED_CAST")
class ScimDiffTest {
    private val m = "ref-scim"
    private val seedT = "2027-01-15T08:00:00.000Z"

    private fun mm(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun n(o: Any?) = o.toString().toLong()

    @Test fun issuePassport() = OracleCases.each(m, "issuePassport") { Scim.issuePassport(mm(it[0])) }
    @Test fun passportFingerprint() = OracleCases.each(m, "passportFingerprint") { Scim.passportFingerprint(mm(it[0])) }

    @Test fun registry() = OracleCases.each(m, "registry") { a ->
        val r = Scim.buildRegistry(l(a[0]).map { mm(it) })
        val id = a[1] as String
        linkedMapOf("all" to r.all(), "has" to r.has(id), "get" to r.get(id))
    }

    private fun metaOf(x: Any?): Scim.MetaInput = if (x is Map<*, *>) meta(mm(x)) else Scim.MetaInput(now = { x.toString().toDouble().toLong() }) // a bare number is a fixed clock (Date truncates)

    private fun meta(x: Map<String, Any?>): Scim.MetaInput {
        val rest = LinkedHashMap(x)
        val nowMs = rest.remove("nowMs")
        return Scim.MetaInput.of(rest, nowMs?.let { v -> { n(v) } })
    }

    @Test fun passportToScim() = OracleCases.each(m, "passportToScim") { Scim.passportToScim(mm(it[0]), mm(it[1]), metaOf(it[2])) }

    @Test fun scimToProvisioningRequest() = OracleCases.each(m, "scimToProvisioningRequest") {
        val r = Scim.scimToProvisioningRequest(it[0])
        linkedMapOf("identity" to r.identity, "projection" to r.projection)
    }

    @Test fun scimError() = OracleCases.each(m, "scimError") { 
        val e = Scim.scimError(n(it[0]).toInt(), it[1] as String, it.getOrNull(2) as String?)
        if (it.size > 2 && it[2] == null) LinkedHashMap(e).also { x -> x["scimType"] = null } else e // an explicit null scimType is kept by the reference
    }

    @Test fun scimListResponse() = OracleCases.each(m, "scimListResponse") { Scim.scimListResponse(l(it[0]).map { x -> mm(x) }, n(it[1]), n(it[2])) }

    @Test fun parseFilter() = OracleCases.each(m, "parseFilter") {
        val f = Scim.parseFilter(it[0])
        linkedMapOf("attr" to f.attr, "value" to f.value)
    }

    @Test fun toEntraAgentPayload() = OracleCases.each(m, "toEntraAgentPayload") { Scim.toEntraAgentPayload(mm(it[0])) }
    @Test fun toOktaScimPayload() = OracleCases.each(m, "toOktaScimPayload") { Scim.toOktaScimPayload(mm(it[0])) }

    private fun fakeFetch(mode: String, calls: MutableList<Any?>) = Scim.FetchLike { url, headers, body ->
        calls.add(linkedMapOf("url" to url, "init" to linkedMapOf("method" to "POST", "headers" to LinkedHashMap<String, Any?>(headers), "body" to body)))
        val (ok, status, json) = when (mode) {
            "badjson" -> Triple(true, 204, "\$bad")
            "ok201" -> Triple(true, 201, linkedMapOf<String, Any?>("id" to "obj-1"))
            "err500" -> Triple(false, 500, linkedMapOf<String, Any?>("detail" to "x"))
            else -> Triple(true, 200, null)
        }
        object : Scim.FetchResponse {
            override fun ok() = ok
            override fun status() = status
            override fun json(): Any? = if (json == "\$bad") throw IllegalStateException("bad json") else json
        }
    }

    private fun pushOut(calls: List<Any?>, r: Scim.PushResult) =
        linkedMapOf("result" to linkedMapOf("ok" to r.ok, "status" to Js.n(r.status.toLong()), "body" to r.body), "calls" to calls)

    private fun push(a: List<Any?>): Any? {
        val calls = ArrayList<Any?>()
        val target = Scim.PushTarget("https://dir.example/scim/Agents", "TOK", fakeFetch(a[2] as String, calls))
        val r = if (a[0] == "pushToEntra") Scim.pushToEntra(mm(a[1]), target) else Scim.pushToOkta(mm(a[1]), target)
        return pushOut(calls, r)
    }

    @Test fun pushToEntra() = OracleCases.each(m, "pushToEntra") { push(it) }
    @Test fun pushToOkta() = OracleCases.each(m, "pushToOkta") { push(it) }

    @Test fun pushProvision() = OracleCases.each(m, "pushProvision") { a ->
        val calls = ArrayList<Any?>()
        pushOut(calls, Scim.pushProvision(Scim.toEntraAgentPayload(mm(a[0])), Scim.PushTarget("e", "t", fakeFetch(a[1] as String, calls))))
    }

    private val t0 = 1_700_000_000_000L
    private val base = "https://scim.acme.com/scim/v2"

    private fun handlerOptions(name: String): Scim.ScimHandlerOptions {
        var ticks = 0L
        val o = Scim.ScimHandlerOptions(now = { t0 })
        when (name) {
            "open" -> { o.baseUrl = base; o.authenticate = Scim.Authenticator { true } }
            "slash" -> { o.baseUrl = "$base///"; o.authenticate = Scim.Authenticator { true } }
            "nobase" -> o.allowUnauthenticated = true
            "tick" -> { o.baseUrl = "https://x.example"; o.now = { t0 + 1000 * ticks++ }; o.authenticate = Scim.Authenticator { true } }
            "deny" -> o.authenticate = Scim.Authenticator { false }
            "throwauth" -> o.authenticate = Scim.Authenticator { throw IllegalStateException("x") }
            "truthy" -> o.authenticate = Scim.Authenticator { "yes" }
            "noauth", "notfn" -> {} // no usable authenticator: construction refuses
            else -> throw IllegalArgumentException(name)
        }
        return o
    }

    @Test fun scimSession() = OracleCases.each(m, "scimSession") { a ->
        val h = Scim.scimHandler(Scim.createMemoryStore(), handlerOptions(a[0] as String))
        fun run(ro: Any?): Map<String, Any?> {
            val r = mm(ro)
            // a non-string id has its text form in the reference's lookups; a non-object query has no members
            val id = if (r.containsKey("id")) Js.template(r["id"]) else null // an explicit null id is a present value ("null")
            val method = if (r.containsKey("method")) Js.template(r["method"]) else null
            val q = r["query"]
            return h.handle(Scim.ScimRequest(method, id, if (q is Map<*, *>) mm(q) else null, r["body"])).toJson()
        }
        for (r in l(a[1])) run(r)
        l(a[2]).map { run(it) }
    }
}
