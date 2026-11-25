package net.atlasauth.pca.connect

import java.util.concurrent.atomic.AtomicInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference vectors of the outbound connection/token vault through the native port. */
@Suppress("UNCHECKED_CAST")
class ConnectDiffTest {
    private val M = "ref-connect"

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

    // ---- small functions ----

    @Test fun oauthScopeCaveat() = OracleCases.each(M, "oauthScopeCaveat") { a -> Authority.oauthScopeCaveat(a[0] as String, strs(a[1])!!) }

    @Test fun isOAuthScopeCaveat() = OracleCases.each(M, "isOAuthScopeCaveat") { a -> Authority.isOAuthScopeCaveat(a[0]) }

    @Test fun grantedOAuthScopes() = OracleCases.each(M, "grantedOAuthScopes") { a ->
        Authority.grantedOAuthScopes(a[0], a[1] as String)?.sorted()
    }

    private fun spec(o: Any?): Proxy.HttpRequestSpec {
        val s = m(o)
        val r = Proxy.HttpRequestSpec()
        r.method = s["method"] as String
        r.url = s["url"] as String
        r.query = strs(s["query"])
        r.body = s["body"] as String?
        r.fixed = if (s["fixed"] == null) null else m(s["fixed"])
        return r
    }

    private fun request(o: Any?): Proxy.ProxyRequest {
        val s = m(o)
        // only the content-type header is read; another header value may be any JSON value (its text form is irrelevant)
        val hs = s["headers"]?.let { h -> LinkedHashMap<String, String>().also { out -> for ((k, v) in m(h)) out[k] = if (v is String) v else Js.template(v) } }
        return Proxy.ProxyRequest(s["method"] as String?, s["url"] as String?, hs, s["body"] as String?)
    }

    @Test fun httpExtractor() = OracleCases.each(M, "httpExtractor") { a -> Proxy.httpExtractor(spec(a[0]))(request(a[1])) }

    @Test fun checkProxyHeaders() = OracleCases.each(M, "checkProxyHeaders") { a -> Proxy.checkProxyHeaders(strMap(a[0]), strs(a[1])!!) }

    @Test fun defaultProxyHeaders() = OracleCases.each(M, "DEFAULT_PROXY_HEADERS") { _ -> ArrayList(Proxy.DEFAULT_PROXY_HEADERS) }

    @Test fun outboundRequestDigest() = OracleCases.each(M, "outboundRequestDigest") { a ->
        Proxy.outboundRequestDigest(a[0] as String?, a[1] as String?, strMap(a[2])!!, a[3] as String?)
    }

    private fun key(seedB64: Any?): Keys.EdKey = Keys.edFromSeed(Keys.unb64u(seedB64 as String))

    @Test fun signReleaseReceipt() = OracleCases.each(M, "signReleaseReceipt") { a -> Proxy.signReleaseReceipt(m(a[0]), key(a[1])) }

    @Test fun verifyReleaseReceipt() = OracleCases.each(M, "verifyReleaseReceipt") { a -> Proxy.verifyReleaseReceipt(m(a[0]), a[1] as String) }

    @Test fun receiptActionDigest() = OracleCases.each(M, "receiptActionDigest") { a -> Proxy.receiptActionDigest(m(a[0])) }

    // ---- scripted transport ----

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

    // a primitive PCActn has no members: the vault then finds no capability chain (not authorized); null still throws
    private fun pcActnOf(o: Any?): Map<String, Any?> = if (o is Map<*, *>) m(o) else if (o == null) m(o) else LinkedHashMap()

    private fun transport(script: Any?, log: MutableList<Any?>): Refresh.VaultFetch? = if (script == null) null else Script(l(script), log)

    private fun errOut(e: RuntimeException): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["ok"] = false
        if (e is VaultError) {
            o["name"] = e.errorName
            o["code"] = e.code
            if (e.code != "not_authorized") o["message"] = e.message
            if (e is VaultError.RefreshFailedError && e.status != null) o["status"] = Js.n(e.status.toLong())
            if (e is VaultError.ScopeExceededError) o["missing"] = ArrayList<Any?>(e.missing)
        } else {
            o["name"] = "Error"
        }
        return o
    }

    private fun conn(o: Any?): StoredConnection {
        val c = m(o)
        val s = StoredConnection()
        s.agentId = c["agentId"] as String
        s.provider = c["provider"] as String
        s.connectionId = c["connectionId"] as String
        s.accessToken = c["accessToken"] as String
        s.refreshToken = c["refreshToken"] as String?
        s.expiresAt = num(c["expiresAt"])
        s.scopes = strs(c["scopes"])!!
        val au = m(c["authority"])
        s.authority.provider = au["provider"] as String?
        s.authority.principal = au["principal"] as String?
        s.authority.scopes = strs(au["scopes"])!!
        s.authority.audience = au["audience"] as String?
        s.createdAt = num(c["createdAt"])
        s.lastUsedAt = if (c["lastUsedAt"] == null) null else num(c["lastUsedAt"])
        s.useCount = num(c["useCount"]).toLong()
        return s
    }

    private fun config(o: Any?): Refresh.ProviderConfig? {
        if (o == null) return null
        val c = m(o)
        val p = Refresh.ProviderConfig(c["tokenEndpoint"] as String?, c["clientId"] as String?)
        p.clientSecret = c["clientSecret"] as String?
        p.supportsScopeNarrowing = c["supportsScopeNarrowing"] as Boolean?
        p.extraParams = strMap(c["extraParams"])
        return p
    }

    @Test fun refreshConnection() = OracleCases.each(M, "refreshConnection") { a ->
        val c = m(a[0])
        val log = ArrayList<Any?>()
        val out = LinkedHashMap<String, Any?>()
        try {
            val ra = Refresh.Args()
            ra.connection = conn(c["connection"])
            ra.config = config(c["config"])
            ra.refreshToken = c["refreshToken"] as String
            ra.requested = strs(c["requested"])!!
            ra.fetch = transport(c["script"], log)
            ra.now = num(c["now"])
            ra.defaultTokenLifetimeMs = num(c["defaultTokenLifetimeMs"])
            val r = Refresh.refreshConnection(ra)
            out["ok"] = true
            val v = LinkedHashMap<String, Any?>()
            v["accessToken"] = r.accessToken
            v["expiresAt"] = Js.jsNum(r.expiresAt)
            v["scopes"] = ArrayList<Any?>(r.scopes)
            v["refreshToken"] = r.refreshToken
            out["value"] = v
        } catch (e: RuntimeException) {
            out.putAll(errOut(e))
        }
        out["calls"] = log
        out
    }

    @Test fun decryptRecord() = OracleCases.each(M, "decryptRecord") { a ->
        val c = m(a[0])
        val inner = InMemoryConnectionStore()
        inner.set(conn(c["record"]))
        val ring = LinkedHashMap<String, ByteArray>()
        for ((k, v) in m(c["ring"])) ring[k] = Keys.unb64u(v as String)
        val store = EncryptedConnectionStore(inner, LocalKeyWrapper(ring, c["active"] as String))
        val k = m(c["key"])
        val out = LinkedHashMap<String, Any?>()
        try {
            val r = store.get(ConnectionStore.Key(k["agentId"] as String, k["provider"] as String, k["connectionId"] as String))
            out["ok"] = true
            out["value"] = r?.toMap()
        } catch (e: RuntimeException) {
            out.putAll(errOut(e))
        }
        out
    }

    // ---- TokenVault scenarios ----

    private fun action(t: Map<String, Any?>): TokenVault.VaultAction {
        val v = TokenVault.VaultAction()
        v.verb = t["verb"] as String?
        v.defDigest = t["def_digest"] as String?
        v.confirmed = t["confirmed"] == true
        val up = m(t["upstream"])
        v.provider = up["provider"] as String?
        v.scopesMin = strs(up["scopes_min"])
        if (t["extract"] != null) v.extract = Proxy.httpExtractor(spec(t["extract"]))
        return v
    }

    private fun vault(s: Map<String, Any?>): Map<String, Any?> {
        val nowRef = longArrayOf(num(s["nowMs"]).toLong())
        val store = InMemoryConnectionStore()
        val fetchLog = ArrayList<Any?>()
        val proxyLog = ArrayList<Any?>()
        val receipts = ArrayList<Any?>()
        val op: Map<String, Any?> = if (s["opts"] == null) LinkedHashMap() else m(s["opts"])
        val actionsTable: Map<String, Any?>? = if (s["actionsTable"] == null) null else m(s["actionsTable"])

        val o = TokenVault.Options()
        o.strict = false
        o.store = store
        o.now = { nowRef[0] }
        o.fetch = transport(s["fetchScript"], fetchLog)
        o.insecureBearerRelease = op["insecureBearerRelease"] == true
        o.insecureSkipPlanRootCheck = op["insecureSkipPlanRootCheck"] == true
        if (op["authorizedPlanRoots"] != null) o.authorizedPlanRoots = strs(op["authorizedPlanRoots"])
        if (op["audience"] != null) o.audience = op["audience"] as String
        if (op["expiryLeewayMs"] != null) o.expiryLeewayMs = num(op["expiryLeewayMs"])
        if (op["defaultTokenLifetimeMs"] != null) o.defaultTokenLifetimeMs = num(op["defaultTokenLifetimeMs"])
        if (op["requireActionBinding"] != null) o.requireActionBinding = op["requireActionBinding"] as Boolean
        if (op.containsKey("useVerb")) o.useVerb = op["useVerb"] as String?
        if (op["defaultConnectionId"] != null) o.defaultConnectionId = op["defaultConnectionId"] as String
        if (op["providers"] != null) for ((k, v) in m(op["providers"])) o.providers[k] = config(v)!!
        if (op["pqPins"] != null) o.pqPins = strMap(op["pqPins"])
        if (op["maxProxyResponseBytes"] != null) o.maxProxyResponseBytes = num(op["maxProxyResponseBytes"]).toLong()
        if (op["replay"] == true) o.replay = Authorize.MemoryStateStore()
        val revoked = op["revoked"]
        if (revoked != null) {
            o.isRevoked = TokenVault.IsRevoked { _ ->
                if ("throws" == revoked) throw Exception("src down")
                "yes" == revoked
            }
        }
        if (actionsTable != null) o.actions = TokenVault.Actions { verb -> if (actionsTable[verb] == null) null else action(m(actionsTable[verb])) }
        if (op["proxy"] == true) {
            val script = l(s["proxyScript"])
            val pi = AtomicInteger()
            o.proxyFetch = Proxy.ProxyFetch { method, url, headers, body ->
                val e = LinkedHashMap<String, Any?>()
                e["method"] = method
                e["url"] = url
                e["headers"] = LinkedHashMap<String, Any?>(headers)
                e["body"] = body
                e["redirect"] = "manual"
                proxyLog.add(e)
                val r = m(script[Math.min(pi.getAndIncrement(), script.size - 1)])
                if (r["throws"] != null) throw Exception("net")
                Proxy.ProxyResponse(num(r["status"]).toInt(), strMap(r["headers"]), r["body"] as String?)
            }
        }
        if (op["receiptSeed"] != null) {
            val rc = TokenVault.Receipts()
            rc.secretKey = key(op["receiptSeed"])
            rc.sink = { r ->
                receipts.add(r)
                if (op["failingSink"] == true) throw RuntimeException("sink")
            }
            o.receipts = rc
        }
        val vault = TokenVault(o)

        val results = ArrayList<Any?>()
        for (co in l(s["calls"])) {
            val c = m(co)
            val kind = c["op"] as String
            if (kind == "now") { nowRef[0] = num(c["now"]).toLong(); continue }
            var res: Map<String, Any?> = LinkedHashMap()
            try {
                val value: Any? = when (kind) {
                    "put" -> {
                        val g = m(c["args"])
                        val p = TokenVault.PutConnectionArgs()
                        p.agentId = g["agentId"] as String?
                        p.provider = g["provider"] as String?
                        p.connectionId = g["connectionId"] as String?
                        p.accessToken = g["accessToken"] as String?
                        p.refreshToken = g["refreshToken"] as String?
                        p.expiresAt = num(g["expiresAt"])
                        p.scopes = strs(g["scopes"])
                        val au = m(g["authority"])
                        p.principal = au["principal"] as String?
                        p.authorityScopes = strs(au["scopes"])
                        p.audience = au["audience"] as String?
                        vault.putConnection(p).toMap()
                    }
                    "get" -> {
                        val g = m(c["args"])
                        vault.getConnectionToken(pcActnOf(c["pcActn"]), TokenVault.GetConnectionTokenArgs(g["provider"] as String, g["connectionId"] as String?, strs(g["scopes"]))).toMap()
                    }
                    "proxy" -> {
                        val g = m(c["args"])
                        val r = vault.proxyCall(pcActnOf(c["pcActn"]), request(c["request"]), TokenVault.ProxyCallArgs(g["provider"] as String, g["connectionId"] as String?, strs(g["scopes"])))
                        val v = LinkedHashMap<String, Any?>()
                        val rs = LinkedHashMap<String, Any?>()
                        rs["status"] = Js.n(r.response.status.toLong())
                        rs["headers"] = LinkedHashMap<String, Any?>(r.response.headers!!)
                        rs["body"] = r.response.body
                        v["response"] = rs
                        if (r.receipt != null) v["receipt"] = r.receipt
                        v
                    }
                    "delete" -> {
                        vault.deleteConnection(c["agentId"] as String, c["provider"] as String, c["connectionId"] as String?)
                        null
                    }
                    else -> throw IllegalStateException("unknown op $kind")
                }
                val ok = LinkedHashMap<String, Any?>()
                ok["ok"] = true
                ok["value"] = value
                res = ok
            } catch (e: RuntimeException) {
                res = errOut(e)
            }
            results.add(res)
        }
        val out = ArrayList<Any?>()
        if (s["watch"] != null) {
            for (k in l(s["watch"])) {
                val kk = m(k)
                val g = store.get(ConnectionStore.Key(kk["agentId"] as String, kk["provider"] as String, kk["connectionId"] as String))
                out.add(g?.toMap())
            }
        }
        val r = LinkedHashMap<String, Any?>()
        r["results"] = results
        r["store"] = out
        r["receipts"] = receipts
        r["fetchCalls"] = fetchLog
        r["proxyCalls"] = proxyLog
        return r
    }

    @Test fun vault() = OracleCases.each(M, "vault") { a -> vault(m(a[0])) }

    // ---- what the oracle cannot pin (random IVs): round trips and tamper detection ----

    @Test fun encryptedStoreRoundTripAndTamper() {
        val ring = HashMap<String, ByteArray>()
        ring["k1"] = ByteArray(32)
        val k2 = ByteArray(32)
        k2.fill(7)
        ring["k2"] = k2
        val w = LocalKeyWrapper(ring, "k1")
        val inner = InMemoryConnectionStore()
        val store = EncryptedConnectionStore(inner, w)
        val c = StoredConnection()
        c.agentId = "agent"
        c.provider = "google"
        c.connectionId = "default"
        c.accessToken = "AT-secret"
        c.refreshToken = "RT-secret"
        c.expiresAt = 1000.0
        c.scopes = arrayListOf("read")
        c.authority.provider = "google"
        c.authority.principal = "p"
        c.authority.scopes = arrayListOf("read")
        store.set(c)
        val key = ConnectionStore.Key("agent", "google", "default")
        val raw = inner.get(key)!!
        assertTrue("the token must be an envelope at rest", raw.accessToken.startsWith("pca1."))
        assertFalse(raw.accessToken.contains("AT-secret"))
        assertTrue(store.encrypted())
        val back = store.get(key)!!
        assertEquals("AT-secret", back.accessToken)
        assertEquals("RT-secret", back.refreshToken)
        // rotation: a record sealed under k1 still opens after k2 becomes active, and re-encrypts under k2
        w.setActive("k2")
        assertEquals("AT-secret", store.get(key)!!.accessToken)
        assertTrue(store.reencrypt(key))
        w.removeKey("k1")
        assertEquals("RT-secret", store.get(key)!!.refreshToken)
        // a ciphertext moved to another connection fails to open
        val moved = inner.get(key)!!
        moved.connectionId = "other"
        inner.set(moved)
        try {
            store.get(ConnectionStore.Key("agent", "google", "other"))
            fail("a moved ciphertext must not open")
        } catch (expected: VaultError.StoreError) {
            assertEquals("store_error", expected.code)
        }
    }

    @Test fun strictModeRequiresTheProductionPieces() {
        val o = TokenVault.Options()
        try {
            TokenVault(o)
            fail("strict mode must refuse a bare configuration")
        } catch (e: IllegalArgumentException) {
            assertEquals("TokenVault strict mode requires an encrypting store, replay, isRevoked, audience", e.message)
        }
        o.strict = false
        try {
            TokenVault(o)
            fail("a store is required")
        } catch (e: IllegalArgumentException) {
            assertEquals("TokenVault requires a store", e.message)
        }
    }
}
