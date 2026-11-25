package net.atlasauth.pca.connectors

import net.atlasauth.pca.connect.ConnectionStore
import net.atlasauth.pca.connect.InMemoryConnectionStore
import net.atlasauth.pca.connect.Refresh
import net.atlasauth.pca.connect.StoredConnection
import net.atlasauth.pca.connect.TokenVault
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the TypeScript-reference vectors of the connector catalog through the native port. */
@Suppress("UNCHECKED_CAST")
class ConnectorsDiffTest {
    private val M = "ref-connectors"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String>? = if (o == null) null else l(o).map { it as String }
    private fun strMap(o: Any?): Map<String, String>? {
        if (o == null) return null
        val out = LinkedHashMap<String, String>()
        for ((k, v) in m(o)) out[k] = v as String
        return out
    }
    private fun num(o: Any?): Double = Js.num(o)!!

    /** The reference's `guard`: {ok:true, value} or the error as data (a non-ConnectorError failure is just {name:"Error"}). */
    private fun guard(t: () -> Any?): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        try {
            val v = t()
            out["ok"] = true
            out["value"] = v
        } catch (e: Exception) {
            out.clear()
            out.putAll(errOut(e))
        }
        return out
    }

    private fun errOut(e: Exception): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["ok"] = false
        if (e is ConnectorError) {
            o["name"] = e.errorName
            o["message"] = e.message
            if (e is ConnectorError.ManifestValidationError) o["issues"] = ArrayList<Any?>(e.issues)
        } else {
            o["name"] = "Error"
        }
        return o
    }

    // ---- manifests ----

    @Test fun validateManifest() = OracleCases.each(M, "validateManifest") { a ->
        val r = Manifest.validateManifest(a[0])
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = r.ok
        if (r.ok) out["manifest"] = r.manifest!!.toMap() else out["issues"] = ArrayList<Any?>(r.issues)
        out
    }

    @Test fun assertManifest() = OracleCases.each(M, "assertManifest") { a -> guard { Manifest.assertManifest(a[0]).toMap() } }

    @Test fun manifestDigest() = OracleCases.each(M, "manifestDigest") { a -> Manifest.manifestDigest(Manifest.assertManifest(a[0])) }

    // ---- catalog and registry ----

    @Test fun catalog() = OracleCases.each(M, "catalog") { _ ->
        val out = LinkedHashMap<String, Any?>()
        val ids = ArrayList<Any?>()
        val all = ArrayList<Any?>()
        for (p in ProviderRegistry.listProviders()) { ids.add(p.id); all.add(p.toMap()) }
        out["ids"] = ids
        out["manifests"] = all
        out["digest"] = ProviderRegistry.catalogDigest()
        out["google"] = ProviderRegistry.getProvider("google")!!.toMap()
        out["nope"] = if (ProviderRegistry.getProvider("nope") == null) null else "present"
        out
    }

    @Test fun registry() = OracleCases.each(M, "registry") { a ->
        val s = m(a[0])
        val r = if (s["empty"] == true) ProviderRegistry() else ProviderRegistry.createDefaultRegistry()
        val out = ArrayList<Any?>()
        for (oo in l(s["ops"])) {
            val op = m(oo)
            val kind = op["op"] as String
            out.add(guard {
                when (kind) {
                    "register" -> {
                        var ro: ProviderRegistry.RegisterOptions? = null
                        if (op["opts"] != null) {
                            val po = m(op["opts"])
                            ro = ProviderRegistry.RegisterOptions(po["replace"] == true, po["expectedDigest"] as String?)
                        }
                        r.register(op["manifest"], ro).toMap()
                    }
                    "get" -> r.get(op["id"] as String)?.toMap()
                    "require" -> r.require(op["id"] as String).toMap()
                    "has" -> r.has(op["id"] as String)
                    "list" -> r.list().map { it.toMap() }
                    "ids" -> ArrayList<Any?>(r.ids())
                    else -> ProviderRegistry.catalogDigest(r)
                }
            })
        }
        out
    }

    // ---- authorize ----

    @Test fun substituteVars() = OracleCases.each(M, "substituteVars") { a ->
        // an explicit null is a value whose member read fails (a TypeError), unlike absent variables, which are an unsupplied variable
        guard { if (a[1] == null && Regex("\\{\\w+\\}").containsMatchIn(a[0] as String)) throw IllegalArgumentException("Cannot read properties of null"); Authorize.substituteVars(a[0] as String, if (a[1] == null) null else m(a[1])) }
    }

    @Test fun pkceChallenge() = OracleCases.each(M, "pkceChallenge") { a ->
        guard { if (a.size > 1) Authorize.pkceChallenge(a[0] as String, a[1] as String?) else Authorize.pkceChallenge(a[0] as String) }
    }

    private fun registryWith(customs: Any?): ProviderRegistry {
        val r = ProviderRegistry.createDefaultRegistry()
        if (customs != null) for (c in l(customs)) r.register(c)
        return r
    }

    @Test fun buildAuthorizeUrl() = OracleCases.each(M, "buildAuthorizeUrl") { a ->
        guard { Authorize.buildAuthorizeUrl(a[0] as String, m(a[1]), registryWith(a.getOrNull(2))).toMap() }
    }

    /** A manifest object used as is (not validated), with only the members applyAccessToken reads. */
    private fun raw(o: Any?): ProviderManifest {
        val mm = m(o)
        val p = ProviderManifest()
        p.id = mm["id"] as String? ?: ""
        p.tokenPlacement = mm["tokenPlacement"] as String? ?: ""
        p.headerName = mm["headerName"] as String?
        p.queryParam = mm["queryParam"] as String?
        return p
    }

    @Test fun applyAccessToken() = OracleCases.each(M, "applyAccessToken") { a -> guard { Authorize.applyAccessToken(raw(a[0]), a[1]) } }

    // ---- exchange ----

    private fun creds(o: Any?): Exchange.ProviderCredentials {
        val c = m(o)
        return Exchange.ProviderCredentials(c["clientId"] as String?, c["clientSecret"] as String?, if (c["vars"] == null) null else m(c["vars"]))
    }

    @Test fun manifestToProviderConfig() = OracleCases.each(M, "manifestToProviderConfig") { a ->
        guard { Exchange.manifestToProviderConfig(ProviderRegistry.getProvider(a[0] as String)!!, creds(a[1])).toMap() }
    }

    @Test fun buildVaultProviders() = OracleCases.each(M, "buildVaultProviders") { a ->
        guard {
            val inp = LinkedHashMap<String, Exchange.ProviderCredentials>()
            for ((k, v) in m(a[0])) inp[k] = creds(v)
            val out = LinkedHashMap<String, Any?>()
            for ((k, v) in Exchange.buildVaultProviders(inp, null)) out[k] = v.toMap()
            out
        }
    }

    /** The scripted token-endpoint transport: replays the case's responses in order (the last one repeats) and logs every request. */
    private inner class Script(val script: List<Any?>, val log: MutableList<Any?>) : Refresh.VaultFetch {
        var i = 0

        override fun call(url: String, init: Refresh.VaultHttpRequest): Refresh.VaultHttpResponse {
            val entry = LinkedHashMap<String, Any?>()
            entry["url"] = url
            entry["method"] = init.method
            entry["headers"] = LinkedHashMap<String, Any?>(init.headers)
            entry["body"] = init.body
            log.add(entry)
            val r = m(script[Math.min(i++, script.size - 1)])
            if (r["throws"] != null) throw RuntimeException(r["throws"] as String)
            return object : Refresh.VaultHttpResponse {
                override fun ok(): Boolean = r["ok"] == true
                override fun status(): Int = num(r["status"]).toInt()
                override fun json(): Any? {
                    if (r["jsonThrows"] == true) throw Exception("bad json")
                    return r["json"]
                }
                override fun text(): String {
                    if (r["textThrows"] == true) throw Exception("bad text")
                    return if (r["text"] == null) "" else r["text"] as String
                }
            }
        }
    }

    private fun transport(script: Any?, log: MutableList<Any?>): Refresh.VaultFetch? = if (script == null) null else Script(l(script), log)

    private fun tokenRun(exchange: Boolean, c: Map<String, Any?>): Map<String, Any?> {
        val log = ArrayList<Any?>()
        val store = InMemoryConnectionStore()
        val vo = TokenVault.Options()
        vo.strict = false
        vo.insecureSkipPlanRootCheck = true
        vo.store = store
        val now = num(c["now"]).toLong()
        vo.now = { now }
        val vault = TokenVault(vo)
        val bind = m(c["bind"])
        val b = Exchange.ConnectionBinding()
        b.vault = vault
        b.agentId = bind["agentId"] as String?
        b.connectionId = bind["connectionId"] as String?
        b.principal = bind["principal"] as String?
        b.authorityScopes = strs(bind["scopes"])
        b.audience = bind["audience"] as String?
        val reg = registryWith(c["customs"])
        val result = LinkedHashMap<String, Any?>()
        try {
            val sc: StoredConnection
            if (exchange) {
                val x = Exchange.ExchangeCodeArgs()
                x.providerId = c["providerId"] as String?
                x.clientId = c["clientId"] as String?
                x.clientSecret = c["clientSecret"] as String?
                x.code = c["code"] as String?
                x.redirectUri = c["redirectUri"] as String?
                x.codeVerifier = c["codeVerifier"] as String?
                x.scopes = strs(c["scopes"])
                x.fetch = transport(c["script"], log)
                x.bind = b
                x.now = num(c["now"])
                x.registry = reg
                x.vars = if (c["vars"] == null) null else m(c["vars"])
                x.extraParams = strMap(c["extraParams"])
                sc = Exchange.exchangeCode(x)
            } else {
                val x = Exchange.RefreshArgs()
                x.providerId = c["providerId"] as String?
                x.clientId = c["clientId"] as String?
                x.clientSecret = c["clientSecret"] as String?
                x.refreshToken = c["refreshToken"] as String?
                x.scopes = strs(c["scopes"])
                x.fetch = transport(c["script"], log)
                x.bind = b
                x.now = num(c["now"])
                x.registry = reg
                x.vars = if (c["vars"] == null) null else m(c["vars"])
                x.extraParams = strMap(c["extraParams"])
                sc = Exchange.refresh(x)
            }
            result["ok"] = true
            result["value"] = sc.toMap()
        } catch (e: RuntimeException) {
            result.putAll(errOut(e))
        }
        val g = store.get(ConnectionStore.Key(b.agentId!!, c["providerId"] as String, b.connectionId ?: "default"))
        val out = LinkedHashMap<String, Any?>()
        out["result"] = result
        out["fetchCalls"] = log
        out["stored"] = g?.toMap()
        return out
    }

    @Test fun exchange() = OracleCases.each(M, "exchange") { a -> tokenRun(true, m(a[0])) }

    @Test fun refresh() = OracleCases.each(M, "refresh") { a -> tokenRun(false, m(a[0])) }

    // ---- what the oracle cannot pin (random state / verifier) and the I/O seams ----

    @Test fun randomStateAndVerifierAreGenerated() {
        val opts = LinkedHashMap<String, Any?>()
        opts["clientId"] = "cid"
        opts["redirectUri"] = "https://app.example.com/cb"
        val a = Authorize.buildAuthorizeUrl("google", opts)
        val b = Authorize.buildAuthorizeUrl("google", opts)
        assertTrue("a random 32-byte state", a.state.length >= 43)
        assertFalse(a.state == b.state)
        assertNotNull("google declares PKCE: a verifier is generated", a.pkce)
        assertTrue(Regex("[A-Za-z0-9._~-]{43,128}").matches(a.pkce!!.verifier))
        assertFalse(a.pkce!!.verifier == b.pkce!!.verifier)
        assertEquals(Authorize.pkceChallenge(a.pkce!!.verifier), a.pkce!!.challenge)
        assertTrue(a.url.contains("code_challenge=" + a.pkce!!.challenge))
        assertTrue(a.url.contains("state=" + a.state))
        val gh = Authorize.buildAuthorizeUrl("github", opts)
        assertNull("github does not use PKCE", gh.pkce)
        val forced = LinkedHashMap<String, Any?>(opts)
        forced["pkce"] = true
        assertNotNull("pkce: true forces a generated verifier", Authorize.buildAuthorizeUrl("github", forced).pkce)
    }

    @Test fun missingTransportFailsClosed() {
        val store = InMemoryConnectionStore()
        val vo = TokenVault.Options()
        vo.strict = false
        vo.store = store
        val b = Exchange.ConnectionBinding()
        b.vault = TokenVault(vo)
        b.agentId = "a"
        b.principal = "p"
        val x = Exchange.ExchangeCodeArgs()
        x.providerId = "github"
        x.clientId = "cid"
        x.code = "c"
        x.redirectUri = "https://app.example.com/cb"
        x.bind = b
        assertThrows(ConnectorError::class.java) { Exchange.exchangeCode(x) }
    }

    @Test fun catalogIsTheFifteenReviewedProviders() {
        assertEquals(15, Providers.BUILTIN_MANIFESTS.size)
        for (p in Providers.BUILTIN_MANIFESTS) assertEquals(p.toMap().toString(), Manifest.assertManifest(p.toMap()).toMap().toString())
        assertEquals(ProviderRegistry.createDefaultRegistry().ids(), ProviderRegistry.defaultRegistry().ids())
    }
}
