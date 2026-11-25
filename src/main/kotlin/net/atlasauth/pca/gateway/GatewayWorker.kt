package net.atlasauth.pca.gateway

import java.util.Locale
import java.util.TreeSet
import net.atlasauth.pca.siem.JsFmt

/**
 * The fetch-style (Cloudflare Worker) adapter, free of any runtime: a request is a method, a URL and headers, and the two plug points
 * are injected, so it runs wherever a handler of that shape does. On allow the request goes to [WorkerOptions.next] with every inbound
 * `x-pca-*` header removed (a client cannot forge the headers the gateway owns); on deny [WorkerOptions.respond] builds the answer
 * (a JSON `{error, reason}` body, the guard's status and its `WWW-Authenticate` challenge). The upstream is never reached on a deny.
 */
object GatewayWorker {
    /** The subset of a fetch request the adapter reads. [body] is read only by full-policy mode with the body as the params. */
    class WorkerRequest(val method: String, val url: String, headers: Map<String, String>, val body: (() -> String)? = null) {
        val headers: Map<String, String> = LinkedHashMap(headers)

        /** The first header with this name (case-insensitive), or null. */
        fun header(name: String): String? {
            val n = name.lowercase(Locale.ROOT)
            for ((k, v) in headers) if (k.lowercase(Locale.ROOT) == n) return v
            return null
        }
    }

    /** The copy of a request without the named (lower-case) headers: the default rewrite. */
    val DEFAULT_REWRITE: (WorkerRequest, List<String>) -> WorkerRequest = { r, drop ->
        val kept = LinkedHashMap<String, String>()
        for ((k, v) in r.headers) if (!drop.contains(k.lowercase(Locale.ROOT))) kept[k] = v
        WorkerRequest(r.method, r.url, kept, r.body)
    }

    /**
     * The gateway options plus the plug points: [next] forwards upstream on allow; [respond] builds a response from (body, status, headers);
     * [rewriteRequest] returns the request without the dropped headers (default: [DEFAULT_REWRITE]); null opts out, and a request that then
     * carries an `x-pca-*` header is answered 400 instead of forwarded.
     */
    class WorkerOptions<Res>(
        val gateway: Gateway.GatewayOptions,
        val next: (WorkerRequest) -> Res,
        val respond: (String, Int, Map<String, String>) -> Res,
        val rewriteRequest: ((WorkerRequest, List<String>) -> WorkerRequest)? = DEFAULT_REWRITE,
    )

    /** The names (lower-case, sorted) of the inbound `x-pca-*` headers a client sent. */
    private fun inboundPcaHeaders(r: WorkerRequest): List<String> {
        val found = TreeSet<String>()
        for (k in r.headers.keys) { val l = k.lowercase(Locale.ROOT); if (l.startsWith("x-pca-")) found.add(l) }
        for (n in Gateway.PCA_INJECTED_HEADERS) if (r.header(n) != null) found.add(n)
        return ArrayList(found)
    }

    /** The path, authority and query of a request URL, without a URL parser. */
    private fun pathFromUrl(url: String): Triple<String, String, String> {
        var rest = url
        var authority = ""
        val scheme = rest.indexOf("://")
        if (scheme >= 0) {
            rest = rest.substring(scheme + 3)
            val slash = rest.indexOf('/')
            if (slash >= 0) { authority = rest.substring(0, slash); rest = rest.substring(slash) } else { authority = rest; rest = "/" }
        }
        var mark = -1
        for (i in rest.indices) if (rest[i] == '?' || rest[i] == '#') { mark = i; break }
        val path = if (mark >= 0) rest.substring(0, mark) else rest
        return Triple(if (path.isEmpty()) "/" else path, authority, Gateway.queryOfTarget(rest))
    }

    /** A `(request) -> Res` middleware. Throws like [Gateway.createGateway] when the gateway options are incomplete. */
    @JvmStatic
    fun <Res> cloudflareWorker(o: WorkerOptions<Res>): (WorkerRequest) -> Res {
        val gateway = Gateway.createGateway(o.gateway)
        return { request ->
            val (path, authority, query) = pathFromUrl(request.url)
            val headers = LinkedHashMap<String, Any?>()
            request.header(Gateway.PCA_HEADER)?.let { headers[Gateway.PCA_HEADER.lowercase(Locale.ROOT)] = it }
            for (h in listOf("pca-discharges", "pca-narrow")) request.header(h)?.let { headers[h] = it }
            val g = Gateway.GatewayRequest(request.method, path, headers)
            g.query = query
            g.authority = authority
            if (o.gateway.policyMode == "full" && o.gateway.full?.paramsFromBody == true && request.body != null) g.body = request.body.invoke()
            val d = gateway(g)
            if (d.allow) {
                val forged = inboundPcaHeaders(request)
                if (forged.isEmpty()) o.next(request)
                else if (o.rewriteRequest != null) o.next(o.rewriteRequest.invoke(request, forged))
                else o.respond(
                    JsFmt.stringify(linkedMapOf<String, Any?>("error" to "forged-pca-header", "reason" to "inbound x-pca-* header cannot be removed")),
                    400, linkedMapOf("content-type" to "application/json"),
                )
            } else {
                val h = linkedMapOf("content-type" to "application/json")
                h.putAll(d.headers)
                o.respond(JsFmt.stringify(linkedMapOf<String, Any?>("error" to d.code, "reason" to d.reason)), d.status, h)
            }
        }
    }
}
