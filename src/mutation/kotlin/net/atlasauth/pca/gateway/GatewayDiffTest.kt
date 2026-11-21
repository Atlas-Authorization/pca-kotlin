package net.atlasauth.pca.gateway

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/**
 * Replays the reference oracle over the gateway: the request binding, canonical query, path hardening, replay guard, provenance log,
 * the decision pipeline over real signed proofs (signature-only mode) and the Envoy / Lambda shapes. Verdict objects and the strict-JSON
 * parser's own message are masked (see the oracle header).
 */
@Suppress("UNCHECKED_CAST")
class GatewayDiffTest {
    private val MOD = "ref-gateway"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun list(o: Any?): List<Any?> = o as List<Any?>
    private fun str(o: Any?): String? = o as? String

    private fun request(m: Map<String, Any?>): Gateway.GatewayRequest {
        val r = Gateway.GatewayRequest()
        r.method = str(m["method"])
        r.path = str(m["path"])
        r.query = str(m["query"])
        r.authority = str(m["authority"])
        r.bodySha256 = str(m["bodySha256"])
        r.body = str(m["body"])
        if (m["headers"] is Map<*, *>) r.headers = map(m["headers"])
        return r
    }

    private val UNDECODABLE = Regex("undecodable PCA-Action header: (?!PCA-Action header)[\\s\\S]*")

    private fun mask(s: Any?): Any? {
        if (s is String) return UNDECODABLE.replace(s, "undecodable PCA-Action header: <json>")
        if (s is List<*>) return s.map { mask(it) }
        if (s is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, v) in s) {
                if ((k == "x-pca-verdict" || k == "pcaVerdict") && v is String && v.isNotEmpty()) out[k as String] = "<verdict>"
                else out[k as String] = mask(v)
            }
            val h = out["header"]
            if (h is Map<*, *> && h["key"] == "x-pca-verdict" && h["value"] != "") {
                val nh = LinkedHashMap<String, Any?>(h as Map<String, Any?>)
                nh["value"] = "<verdict>"
                out["header"] = nh
            }
            return out
        }
        return s
    }

    private fun bindOpts(o: Any?): Gateway.BindRequestOptions? {
        if (o == null) return null
        val m = map(o)
        val b = Gateway.BindRequestOptions()
        b.authority = m["authority"] == true
        b.body = if (m.containsKey("body")) m["body"] as Boolean? else null
        return b
    }

    @Test fun canonicalQuery() = OracleCases.each(MOD, "canonicalQuery") { a -> 
        // a JSON null is a present value in the reference (null.startsWith throws); the typed API's absent query is Kotlin null
        if (a[0] == null) throw IllegalArgumentException("Cannot read properties of null (reading 'startsWith')")
        Gateway.canonicalQuery(a[0] as String?)
    }

    @Test fun requestBinding() = OracleCases.each(MOD, "requestBinding") { a -> Gateway.requestBinding(request(map(a[0])), bindOpts(if (a.size > 1) a[1] else null)) }

    @Test fun bindParams() = OracleCases.each(MOD, "bindParams") { a -> Gateway.bindParams(map(a[0]), if (a.size > 1 && a[1] != null) map(a[1]) else null) }

    @Test fun ambiguousPathReason() = OracleCases.each(MOD, "ambiguousPathReason") { a -> Gateway.ambiguousPathReason(a[0] as String) }

    @Test fun replayScenario() = OracleCases.each(MOD, "replayScenario") { a ->
        val spec = map(a[0])
        var clock = Js.num(spec["clock"])!!.toLong()
        val g = Gateway.memoryReplayGuard(Js.num(spec["max"])!!.toInt()) { clock }
        val out = ArrayList<Any?>()
        for (o in list(spec["ops"])) {
            val op = map(o)
            if (op.containsKey("setClock")) { clock = Js.num(op["setClock"])!!.toLong(); continue }
            try {
                val now = if (op["now"] == null) null else Js.num(op["now"])
                out.add(g.claim(op["key"] as String, Js.num(op["exp"])!!, now))
            } catch (e: Exception) {
                out.add(linkedMapOf<String, Any?>("threw" to e.message))
            }
        }
        out
    }

    @Test fun provenanceLogScenario() = OracleCases.each(MOD, "provenanceLogScenario") { a ->
        val spec = map(a[0])
        val l = Gateway.memoryProvenanceLog(Js.num(spec["max"])!!.toInt())
        val out = ArrayList<Any?>()
        for (o in list(spec["ops"])) {
            val op = map(o)
            if (op.containsKey("add")) { l.add(op["session"] as String, map(op["o"])); out.add("added") }
            else out.add(ArrayList<Any?>(l.seen(op["session"] as String)))
        }
        out
    }

    private fun kind(k: Any?): Gateway.FullPolicy {
        val p = Gateway.FullPolicy()
        p.paramsFromBody = k == "body"
        if (!p.paramsFromBody) p.paramsFn = { LinkedHashMap() }
        return p
    }

    @Test fun presentedProvenance() = OracleCases.each(MOD, "presentedProvenance") { a ->
        val m = LinkedHashMap(map(a[0]))
        m["method"] = "POST"
        m["path"] = "/"
        val v = Gateway.presentedProvenance(request(m), kind(a[1]))
        if (v === Gateway.ABSENT) linkedMapOf<String, Any?>("undef" to true) else v
    }

    @Test fun presentedArtifacts() = OracleCases.each(MOD, "presentedArtifacts") { a ->
        val m = LinkedHashMap(map(a[0]))
        m["method"] = "POST"
        m["path"] = "/"
        Gateway.presentedArtifacts(request(m), kind(a[1]))
    }

    // ---- scenarios ----

    private fun obj(k: String, v: Any?, reason: String? = null): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m[k] = v
        if (reason != null) m["reason"] = reason
        return m
    }

    private fun options(spec: Map<String, Any?>): Gateway.GatewayOptions {
        val now = Js.num(spec["now"])!!.toLong()
        val o = Gateway.GatewayOptions()
        o.audience = spec["audience"] as String?
        for (r in list(spec["routes"])) {
            val m = map(r)
            val c = map(m["capability"])
            o.routes.add(Gateway.RouteRule(str(m["method"]), m["path"] as String, Gateway.RequiredCapability(c["verb"] as String, str(c["resource"]))))
        }
        val grants = map(spec["grants"])
        o.resolveGrant = Gateway.GrantResolver { ref, _ -> if (ref is String && grants[ref] != null) map(grants[ref]) else null }
        o.now = { now }
        val br = spec["bindRequest"]
        if (br == "off") o.bindRequestOff = true else if (br != null) o.bindRequest = bindOpts(br)
        o.unmatchedRoute = str(spec["unmatched"])
        o.pathPolicy = str(spec["pathPolicy"])
        if (spec["requireChecks"] != null) o.requireChecks = list(spec["requireChecks"]).map { it as String }
        o.realm = str(spec["realm"])
        o.insecureSkipPlanRootCheck = spec["skipPlan"] == true
        if (spec["planRoots"] != null) o.authorizedPlanRoots = list(spec["planRoots"]).map { it as String }
        when (spec["replay"] as String) {
            "always" -> o.replayGuard = Gateway.ReplayGuard { _, _, _ -> true }
            "false" -> o.replayGuard = Gateway.ReplayGuard { _, _, _ -> false }
            "throws" -> o.replayGuard = Gateway.ReplayGuard { _, _, _ -> throw RuntimeException("store down") }
            "memory" -> o.replayGuard = Gateway.memoryReplayGuard(100_000) { now }
            "memory-full" -> o.replayGuard = Gateway.memoryReplayGuard(1) { now }
            else -> {}
        }
        when (spec["revocation"] as String) {
            "ok" -> o.revocation = Gateway.RevocationHook { _, _, _ -> Gateway.HookResult(true, true, null) }
            "revoked" -> o.revocation = Gateway.RevocationHook { _, _, _ -> Gateway.HookResult(true, false, "grant revoked") }
            "revoked-noreason" -> o.revocation = Gateway.RevocationHook { _, _, _ -> Gateway.HookResult(true, false, null) }
            "notEnforced" -> o.revocation = Gateway.RevocationHook { _, _, _ -> Gateway.HookResult(false, false, null) }
            "throws" -> o.revocation = Gateway.RevocationHook { _, _, _ -> throw RuntimeException("rev down") }
            else -> {}
        }
        val cp = str(spec["checkProof"])
        if (cp != null) {
            o.checkProof = when (cp) {
                "true" -> Gateway.CheckProof { true }
                "false" -> Gateway.CheckProof { false }
                "obj-true" -> Gateway.CheckProof { obj("allow", true) }
                "obj-false" -> Gateway.CheckProof { obj("allow", false) }
                "obj-false-reason" -> Gateway.CheckProof { obj("allow", false, "over limit") }
                else -> Gateway.CheckProof { throw RuntimeException("policy down") }
            }
        }
        when (spec["policy"] as String) {
            "sig" -> o.policyMode = "signature-only"
            "bogus" -> o.policyMode = "bogus"
            "full-missing" -> { o.policyMode = "full"; o.full = Gateway.FullPolicy() }
        }
        return o
    }

    private fun project(d: Gateway.Decision): Any? {
        val m = LinkedHashMap<String, Any?>()
        m["allow"] = d.allow
        m["status"] = d.status
        m["code"] = d.code
        m["reason"] = d.reason
        m["headers"] = LinkedHashMap<String, Any?>(d.headers)
        if (d.matched != null) {
            val r = LinkedHashMap<String, Any?>()
            r["verb"] = d.matched.verb
            if (d.matched.resource != null) r["resource"] = d.matched.resource
            m["matched"] = r
        }
        if (d.pcactn != null && d.pcactn["grant_ref"] != null) m["grant"] = d.pcactn["grant_ref"]
        if (d.verdict != null) m["verdictAllow"] = d.verdict["allow"]
        return mask(m)
    }

    @Test fun authorizeScenario() = OracleCases.each(MOD, "authorizeScenario") { a ->
        val spec = map(a[0])
        val gw = try { Gateway.createGateway(options(spec)) } catch (e: RuntimeException) { return@each obj("create", e.message) }
        val out = ArrayList<Any?>()
        for (r in list(spec["requests"])) {
            try { out.add(project(gw(request(map(r))))) } catch (e: RuntimeException) { out.add(obj("threw", e.message)) }
        }
        out
    }

    private fun adapter(fn: String, make: (Gateway.GatewayOptions) -> (Map<String, Any?>) -> Map<String, Any?>) =
        OracleCases.each(MOD, fn) { a ->
            val spec = map(a[0])
            val handler = try { make(options(spec)) } catch (e: RuntimeException) { return@each obj("create", e.message) }
            try {
                mask(handler(map(list(spec["events"])[0])))
            } catch (e: RuntimeException) {
                obj("threw", e.message)
            }
        }

    @Test fun envoyScenario() = adapter("envoyScenario") { Gateway.envoyExtAuthz(it) }

    @Test fun grpcScenario() = adapter("grpcScenario") { Gateway.envoyGrpcExtAuthz(it) }

    @Test fun lambdaScenario() = adapter("lambdaScenario") { Gateway.lambdaAuthorizer(it) }

    @Test fun lambdaSimpleScenario() = adapter("lambdaSimpleScenario") { Gateway.lambdaSimpleAuthorizer(it) }

    @Test fun workerScenario() = OracleCases.each("ref-gateway-worker", "workerScenario") { a ->
        val spec = map(a[0])
        val ev = map(list(spec["events"])[0])
        val view = { r: GatewayWorker.WorkerRequest ->
            val h = java.util.TreeMap<String, Any?>()
            for ((k, v) in r.headers) h[k.lowercase(java.util.Locale.ROOT)] = v
            val m = LinkedHashMap<String, Any?>()
            m["method"] = r.method
            m["url"] = r.url
            m["headers"] = h
            obj("forwarded", m)
        }
        val rewrite: ((GatewayWorker.WorkerRequest, List<String>) -> GatewayWorker.WorkerRequest)? = when (ev["rewrite"]) {
            "null" -> null
            "custom" -> { r, drop ->
                val h = LinkedHashMap<String, String>()
                for ((k, v) in r.headers) if (!drop.contains(k.lowercase(java.util.Locale.ROOT))) h[k] = v
                h["x-rewritten"] = drop.joinToString(",")
                GatewayWorker.WorkerRequest(r.method, r.url, h)
            }
            else -> GatewayWorker.DEFAULT_REWRITE
        }
        val opts = GatewayWorker.WorkerOptions<Any?>(
            options(spec), { r -> view(r) },
            { body, status, headers -> val m = LinkedHashMap<String, Any?>(); m["status"] = status; m["headers"] = LinkedHashMap<String, Any?>(headers); m["body"] = net.atlasauth.pca.verifier.Json.parse(body); m },
            rewrite,
        )
        val w = try { GatewayWorker.cloudflareWorker(opts) } catch (e: RuntimeException) { return@each obj("create", e.message) }
        val headers = LinkedHashMap<String, String>()
        for ((k, v) in map(ev["headers"])) headers[k] = v as String
        mask(w(GatewayWorker.WorkerRequest(ev["method"] as String, ev["url"] as String, headers)))
    }
}
