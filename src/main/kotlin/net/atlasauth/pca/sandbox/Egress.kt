package net.atlasauth.pca.sandbox

import java.security.MessageDigest
import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Egress admission for non-WASM tools: the one outbound request an authorized operation maps to, matched exactly (host, port,
 * method, path, query, body hash). The proxy server itself (sockets, TLS tunnelling) is a runtime concern and not part of this port.
 */
object Egress {
    private val HOST_RE = Regex("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
    private val METHOD_RE = Regex("[A-Z]+")
    private val BAD_PATH = Regex("[?#\\\\]|%2e|%2f|%5c|(^|/)\\.\\.?(/|\\z)", RegexOption.IGNORE_CASE)
    private val ENCODED_PATH = Regex("%2e|%2f|%5c|\\\\", RegexOption.IGNORE_CASE)
    private val CONNECT_RE = Regex("([a-z0-9.-]+|\\[[0-9a-f:]+\\]):(\\d{1,5})", RegexOption.IGNORE_CASE)
    private val V4_TAIL = Regex("(.*:)(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)")
    private val GROUP = Regex("[0-9a-f]{1,4}")

    // Node's net.isIPv4 / net.isIPv6 grammar.
    private const val V4SEG = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
    private const val V4 = "(?:$V4SEG\\.){3}$V4SEG"
    private const val V6SEG = "(?:[0-9a-fA-F]{1,4})"
    private val IPV4 = Regex(V4)
    private val IPV6 = Regex(
        "(?:" +
            "(?:$V6SEG:){7}(?:$V6SEG|:)|" +
            "(?:$V6SEG:){6}(?:$V4|:$V6SEG|:)|" +
            "(?:$V6SEG:){5}(?::$V4|(?::$V6SEG){1,2}|:)|" +
            "(?:$V6SEG:){4}(?:(?::$V6SEG){0,1}:$V4|(?::$V6SEG){1,3}|:)|" +
            "(?:$V6SEG:){3}(?:(?::$V6SEG){0,2}:$V4|(?::$V6SEG){1,4}|:)|" +
            "(?:$V6SEG:){2}(?:(?::$V6SEG){0,3}:$V4|(?::$V6SEG){1,5}|:)|" +
            "(?:$V6SEG:){1}(?:(?::$V6SEG){0,4}:$V4|(?::$V6SEG){1,6}|:)|" +
            "(?::(?:(?::$V6SEG){0,5}:$V4|(?::$V6SEG){1,7}|:))" +
            ")(?:%[0-9a-zA-Z.:-]{1,})?",
    )

    internal fun isIPv4(s: String): Boolean = IPV4.matches(s)
    internal fun isIPv6(s: String): Boolean = IPV6.matches(s)

    private fun privateV4(a: Int, b: Int): Boolean =
        a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 100 && b in 64..127) || a >= 224

    private fun part(h: String): List<String> = if (h.isEmpty()) emptyList() else h.split(":")

    /** The eight 16-bit groups of an IPv6 literal (any spelling Node accepts: compressed or expanded, a dotted v4 tail, any case), or null; a zone id is not parsed. */
    private fun ipv6Groups(ip: String): IntArray? {
        if (!isIPv6(ip) || ip.indexOf('%') >= 0) return null
        var s = ip.lowercase(Locale.ROOT)
        val t = V4_TAIL.matchEntire(s)
        if (t != null) {
            val g = t.groupValues
            s = g[1] + Integer.toHexString((g[2].toInt() shl 8) or g[3].toInt()) + ":" + Integer.toHexString((g[4].toInt() shl 8) or g[5].toInt())
        }
        val halves = s.split("::")
        if (halves.size > 2) return null
        val head = part(halves[0])
        val rest = if (halves.size > 1) part(halves[1]) else emptyList()
        val fill = 8 - head.size - rest.size
        if (if (halves.size == 1) fill != 0 else fill < 1) return null
        val groups = ArrayList(head)
        var i = 0
        while (halves.size > 1 && i < fill) { groups.add("0"); i++ }
        groups.addAll(rest)
        val g = IntArray(8)
        for (k in 0 until 8) {
            if (!GROUP.matches(groups[k])) return null
            g[k] = groups[k].toInt(16)
        }
        return g
    }

    /**
     * Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not its
     * spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address follows its
     * embedded IPv4 address; a zoned address (`%id`) is link-scoped, so private. Anything that is not an IP literal (or not a string)
     * counts as private.
     */
    @JvmStatic
    fun isPrivateAddress(ipArg: Any?): Boolean {
        if (ipArg !is String) return true
        if (isIPv4(ipArg)) {
            val p = ipArg.split(".")
            return privateV4(p[0].toInt(), p[1].toInt())
        }
        val g = ipv6Groups(ipArg) ?: return true
        val zero80 = g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0
        val nat64 = g[0] == 0x64 && g[1] == 0xff9b && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0
        if ((zero80 && (g[5] == 0 || g[5] == 0xffff)) || nat64) return privateV4(g[6] shr 8, g[6] and 0xff)
        return g[0] < 0x2000 || g[0] >= 0x4000
    }

    private fun sha256b64u(b: ByteArray): String = Keys.b64u(MessageDigest.getInstance("SHA-256").digest(b))

    private class Admission(
        val opId: String, val verb: String, val resource: String, val params: Any?, val method: String, val scheme: String, val host: String,
        val port: Int, val path: String, val pathPrefix: Boolean, val query: Any?, val hasBodySha256: Boolean, val bodySha256: String?,
        val tunnel: Boolean, var uses: Long, val expiresAt: Double,
    )

    /** The set of admitted requests: one authorized operation, one request template. [now] is the clock in epoch ms (default the system clock). */
    class EgressPolicy @JvmOverloads constructor(now: (() -> Double)? = null) {
        private val admissions = ArrayList<Admission>()
        private val now: () -> Double = now ?: { System.currentTimeMillis().toDouble() }

        /**
         * Admit the request that [operation] maps to. Throws unless [result] allows exactly [operation] and the template is well formed.
         * [uses] (default 1) and [expiresAt] (default never) are JSON numbers or null.
         */
        fun admit(result: Authorize.Result, operation: Authorize.Operation, toRequest: (Authorize.Operation) -> Map<String, Any?>?, uses: Any?, expiresAt: Any?) {
            if (!Authorize.isAuthorizedFor(result, operation)) throw IllegalArgumentException("not_authorized: result does not allow exactly this operation")
            val t = toRequest(operation) ?: throw IllegalArgumentException("no_egress_for_operation")
            val host = t["host"]
            if (host !is String) throw IllegalArgumentException("bad_template_host")
            if (!(isIPv4(host) || isIPv6(host) || HOST_RE.matches(host)) || host != host.lowercase(Locale.ROOT)) throw IllegalArgumentException("bad_template_host")
            val scheme = t["scheme"]
            if ("http" != scheme && "https" != scheme) throw IllegalArgumentException("bad_template_scheme")
            val portV: Any? = t["port"] ?: (if ("http" == scheme) 80L else 443L)
            val pd = Js.num(portV)
            if (pd == null || pd.isNaN() || pd.isInfinite() || pd != Math.rint(pd) || pd < 1 || pd > 65535) throw IllegalArgumentException("bad_template_port")
            val method = t["method"]
            if (method !is String || !METHOD_RE.matches(method)) throw IllegalArgumentException("bad_template_method")
            val path = t["path"]
            if (path !is String) throw JsTypeError("path is not a string")
            if (!path.startsWith("/") || BAD_PATH.containsMatchIn(path)) throw IllegalArgumentException("bad_template_path")
            val ud = Js.num(uses ?: 1L)
            if (ud == null || ud.isNaN() || ud.isInfinite() || ud != Math.rint(ud) || ud < 1) throw IllegalArgumentException("bad_uses")
            val ex = if (expiresAt == null) null else Js.num(expiresAt)
            admissions.add(
                Admission(
                    result.operation?.id ?: "", operation.verb, operation.resource, operation.params, method, scheme as String, host, pd.toInt(), path,
                    Js.truthy(t["path_prefix"]), t["query"] ?: "", t.containsKey("body_sha256"), t["body_sha256"] as? String, t["tunnel"] == true,
                    ud.toLong(), ex ?: Double.POSITIVE_INFINITY,
                ),
            )
        }

        /**
         * Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason. Returns
         * `{allow:true, op_id, admission:{verb, resource, params_digest}}` or `{allow:false, reason}`.
         */
        fun claim(method: Any?, url: Any?, bodyIn: ByteArray?): Map<String, Any?> {
            if (method !is String) throw JsTypeError("method is not a string")
            val parsed = parseTarget(method, if (url is String) url else Js.template(url))
            if (parsed.reason != null) return deny(parsed.reason!!)
            val body = bodyIn ?: ByteArray(0)
            var why = "no_admission"
            for (a in admissions) {
                if (parsed.connect != a.tunnel) continue
                if (a.method != method.uppercase(Locale.ROOT) && !parsed.connect) continue
                if (parsed.scheme != a.scheme && !parsed.connect) continue
                if (parsed.host != a.host || parsed.port != a.port) continue
                if (!parsed.connect) {
                    val pathOk = if (a.pathPrefix) parsed.path == a.path || parsed.path.startsWith(if (a.path.endsWith("/")) a.path else a.path + "/") else parsed.path == a.path
                    if (!pathOk) continue
                    if (parsed.query != a.query) { why = "query_mismatch"; continue }
                    if (body.isNotEmpty() && (!a.hasBodySha256 || sha256b64u(body) != a.bodySha256)) { why = "body_mismatch"; continue }
                    if (body.isEmpty() && a.hasBodySha256 && sha256b64u(body) != a.bodySha256) { why = "body_mismatch"; continue }
                }
                val t = now()
                if (a.uses < 1 || !(t.isFinite() && t < a.expiresAt)) { why = "spent"; continue } // reported only when the request would otherwise have matched
                a.uses -= 1
                return linkedMapOf(
                    "allow" to true, "op_id" to a.opId,
                    "admission" to linkedMapOf<String, Any?>("verb" to a.verb, "resource" to a.resource, "params_digest" to Pca.hashCanonical(a.params)),
                )
            }
            return deny(why)
        }

        private fun deny(reason: String): Map<String, Any?> = linkedMapOf("allow" to false, "reason" to reason)
    }

    private class Target {
        var reason: String? = null
        var connect = false
        var scheme = ""
        var host = ""
        var path = ""
        var query = ""
        var port = 0
    }

    private fun refuse(r: String): Target = Target().also { it.reason = r }

    private fun parseTarget(method: String, url: String): Target {
        val t = Target()
        if (method.uppercase(Locale.ROOT) == "CONNECT") {
            val m = CONNECT_RE.matchEntire(url) ?: return refuse("bad_connect_target")
            t.connect = true
            t.scheme = "https"
            var h = m.groupValues[1]
            if (h.startsWith("[")) h = h.substring(1)
            if (h.endsWith("]")) h = h.substring(0, h.length - 1)
            t.host = h.lowercase(Locale.ROOT)
            t.port = m.groupValues[2].toInt()
            return t
        }
        val u = EgressUrl.parse(url) ?: return refuse("not_absolute_url")
        if ((u.scheme != "http" && u.scheme != "https") || u.credentials || u.hash) return refuse("bad_url")
        // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
        if (ENCODED_PATH.containsMatchIn(u.path)) return refuse("encoded_path")
        t.connect = false
        t.scheme = u.scheme
        t.host = u.host
        t.port = if (u.port >= 0) u.port else if (u.scheme == "http") 80 else 443
        t.path = u.path
        t.query = u.query
        return t
    }
}
