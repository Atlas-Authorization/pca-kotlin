package net.atlasauth.pca.grants

import net.atlasauth.pca.gnap.GnapJs
import net.atlasauth.pca.verifier.K3Sig

/** Framework-neutral HTTP binding of the grant management resource: plain request and response objects, no servlet dependency. */
object GrantHttp {
    const val GRANTS_PATH = "/pca/grants"
    const val NEEDS_PATH = "/pca/needs"

    /** [path] is the path below the mount point (for example `/pca/grants/g_1/amend`); [body] is a parsed JSON value or null. */
    class Request(val method: String, val path: String, query: Map<String, String>?, val body: Any?) {
        val query: Map<String, String> = query ?: HashMap()
    }

    class Response(val status: Int, val body: Any?)

    /** Who is calling, as the host authenticated them. [principal] limits every read and write to that principal's grants. */
    class Caller(val principal: String?, val admin: Boolean)

    fun interface Authenticate {
        @Throws(Exception::class)
        fun authenticate(req: Request): Caller?
    }

    fun interface Handler { fun handle(req: Request): Response }

    private val STATUS = mapOf(
        "not_found" to 404, "conflict" to 409, "bad_request" to 400, "not_narrower" to 422,
        "signature_required" to 401, "bad_signature" to 401, "step_up_required" to 403, "not_active" to 409,
        "need_not_lowered_only" to 422, "need_not_adjustable" to 422, "forbidden" to 403,
    )

    internal fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return m
    }

    private fun err(e: Exception): Response {
        if (e is GrantResource.GrantError) return Response(STATUS[e.code] ?: 500, obj("error" to e.code, "message" to e.message))
        return Response(500, obj("error" to "server_error"))
    }

    /** Discovery fragment for `/.well-known/pca-configuration`. */
    @JvmStatic
    fun grantManagementMetadata(base: String): Map<String, Any?> = obj(
        "grant_management" to obj(
            "grants_endpoint" to base + GRANTS_PATH, "needs_endpoint" to base + NEEDS_PATH,
            "amend_actions" to arrayListOf<Any?>("narrow", "merge", "replace"),
            "revoke_scopes" to arrayListOf<Any?>("grant", "agent", "subtree"),
            "widening" to "new_grant_id_with_supersedes",
        ),
    )

    private val JS_NUMBER = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")

    /** JavaScript `Number(s)` for a decimal string; NaN when it is not one (hex, binary and other forms are not recognised). */
    internal fun jsNumber(s: String): Double {
        var a = 0
        var b = s.length
        while (a < b && GnapJs.isWs(s[a].code)) a++
        while (b > a && GnapJs.isWs(s[b - 1].code)) b--
        val t = s.substring(a, b)
        if (t.isEmpty()) return 0.0
        if (t == "Infinity" || t == "+Infinity") return Double.POSITIVE_INFINITY
        if (t == "-Infinity") return Double.NEGATIVE_INFINITY
        return if (JS_NUMBER.matches(t)) t.toDouble() else Double.NaN
    }

    internal fun segments(path: String): List<String> = path.split("/").filter { it.isNotEmpty() }

    private fun has(s: String?): Boolean = s != null && s.isNotEmpty()

    @JvmStatic
    fun grantResourceHandler(svc: GrantResource.GrantService, authenticate: Authenticate): Handler = Handler { req ->
        try {
            val who = authenticate.authenticate(req)
            if (who == null || (!who.admin && !has(who.principal))) return@Handler Response(401, obj("error" to "unauthenticated"))
            val seg = segments(req.path)
            val q = req.query
            val b: Map<String, Any?> = K3Sig.map(req.body) ?: LinkedHashMap()
            if (seg.isEmpty() || seg[0] != "pca") return@Handler Response(404, obj("error" to "not_found"))
            val s1 = seg.getOrNull(1)
            val s2 = seg.getOrNull(2)
            val s3 = seg.getOrNull(3)
            if (s1 == "grants") {
                if (seg.size == 2 && req.method == "GET") {
                    val status = q["status"]
                    if (status != null && status != "active" && status != "revoked" && status != "superseded") throw GrantResource.GrantError("bad_request", "bad status")
                    val principal = if (who.admin) q["principal"] else who.principal
                    var limit: Long? = null
                    if (q["limit"] != null) {
                        val d = jsNumber(q["limit"]!!)
                        if (!d.isNaN() && !d.isInfinite()) limit = d.toLong() // truncates toward zero, like the reference's (long) cast
                    }
                    val f = GrantResource.ListFilter(
                        principal = if (has(principal)) principal else null,
                        agent = if (has(q["agent"])) q["agent"] else null,
                        status = if (has(status)) status else null,
                        limit = limit,
                        cursor = if (has(q["cursor"])) q["cursor"] else null,
                    )
                    return@Handler Response(200, svc.list(f))
                }
                if (s2 == null) return@Handler Response(404, obj("error" to "not_found"))
                val g = svc.inspect(s2)
                if (!who.admin && g["principal"] != who.principal) throw GrantResource.GrantError("not_found", "no such grant")
                if (seg.size == 3 && req.method == "GET") return@Handler Response(200, g)
                if (seg.size == 3 && req.method == "DELETE") {
                    val scope = q["scope"] ?: "grant"
                    val sig = b["sig"] as? String
                    // A principal-scoped caller must still sign; only an admin may revoke without a principal signature.
                    val adminNoSig = who.admin && !has(sig)
                    return@Handler Response(200, svc.revoke(s2, scope, if (adminNoSig) null else (sig ?: ""), adminNoSig))
                }
                if (seg.size == 4 && s3 == "amend" && req.method == "POST") {
                    val r = svc.amend(s2, b)
                    return@Handler Response(if (r["created"] == true) 201 else 200, r["grant"])
                }
                if (seg.size == 4 && s3 == "needs" && req.method == "POST") return@Handler Response(201, svc.requestNeeds(s2, b["needs"]))
            }
            if (s1 == "needs" && s2 != null && s3 == "approve" && req.method == "POST") {
                ownNeed(svc, who, s2)
                val sig = b["sig"]
                val approved = b["approved"]
                if (sig !is String || approved !is List<*>) throw GrantResource.GrantError("bad_request", "sig and approved are required")
                val r = svc.approveNeeds(s2, approved, sig, b["step_up_ref"] as? String)
                return@Handler Response(201, r["grant"])
            }
            if (s1 == "needs" && s2 != null && s3 == "deny" && req.method == "POST") {
                ownNeed(svc, who, s2)
                svc.denyNeeds(s2)
                return@Handler Response(200, obj("status" to "denied"))
            }
            Response(404, obj("error" to "not_found"))
        } catch (e: Exception) {
            err(e)
        }
    }

    private fun ownNeed(svc: GrantResource.GrantService, who: Caller, needId: String) {
        val g = svc.inspect(svc.needGrantId(needId))
        if (!who.admin && g["principal"] != who.principal) throw GrantResource.GrantError("not_found", "no such grant")
    }
}
