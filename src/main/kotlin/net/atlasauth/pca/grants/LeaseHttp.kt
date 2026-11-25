package net.atlasauth.pca.grants

import net.atlasauth.pca.grants.GrantHttp.Response
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Lease

/**
 * Hosted lease routes (framework-neutral, same shape as the grant resource). The server only stores records the lease authority already
 * signed; it never mints one, so a compromised host cannot extend a lease.
 * ```
 *   POST /pca/leases             body {lease, chain?}   issue (seq 1) or renew (seq n+1)
 *   GET  /pca/leases/:id                                the newest record and its renewal ledger
 *   POST /pca/leases/:id/check   body {lease}           is this record a live lease
 *   POST /pca/leases/revoke      body {revocation}      a signed revoke by lease, prefix or grant
 * ```
 */
object LeaseHttp {
    const val LEASES_PATH = "/pca/leases"

    /** Who is calling; a non-admin sees and checks only leases it holds. */
    class Caller(val admin: Boolean, val principal: String?)

    fun interface Authenticate {
        @Throws(Exception::class)
        fun authenticate(req: GrantHttp.Request): Caller?
    }

    private val STATUS = mapOf(
        "bad_record" to 400, "bad_seq" to 409, "stale_seq" to 409, "lease_fork" to 409, "renewal_mismatch" to 422,
        "over_max_ttl" to 422, "ttl_ceiling" to 422, "not_extending" to 422, "stale_justification" to 422,
        "expired_lease" to 409, "revoked" to 409, "sod" to 403, "unknown_authority" to 403, "store_unreachable" to 503,
    )

    @JvmStatic
    fun leaseManagementMetadata(base: String): Map<String, Any?> =
        GrantHttp.obj("leases" to GrantHttp.obj("leases_endpoint" to base + LEASES_PATH, "revoke_targets" to arrayListOf<Any?>("lease", "prefix", "grant")))

    // a lease belongs to its holder: a non-admin sees and checks only leases it holds
    private fun visible(who: Caller, lease: Map<String, Any?>): Boolean = who.admin || who.principal == lease["holder"]

    private fun historyJson(reg: Lease.Registry, id: String): List<Any?> {
        val out = ArrayList<Any?>()
        for (h in reg.history(id)) out.add(GrantHttp.obj("seq" to h.seq, "renewed_at" to h.renewedAt, "expires_at" to h.expiresAt, "justification_digest" to h.justificationDigest))
        return out
    }

    /** The lease routes over [reg]. A refused accept carries the registry's own `message` (for `sod` the separation-of-duties rule that failed). */
    @JvmStatic
    @JvmOverloads
    fun leaseResourceHandler(reg: Lease.Registry, authenticate: Authenticate, now: (() -> Long)? = null): GrantHttp.Handler {
        val clock: () -> Long = now ?: { System.currentTimeMillis() }
        return GrantHttp.Handler { req ->
            try {
                val who = authenticate.authenticate(req)
                if (who == null || (!who.admin && who.principal.isNullOrEmpty())) return@Handler Response(401, GrantHttp.obj("error" to "unauthenticated"))
                val seg = GrantHttp.segments(req.path)
                val b: Map<String, Any?> = K3Sig.map(req.body) ?: LinkedHashMap()
                if (seg.size < 2 || seg[0] != "pca" || seg[1] != "leases") return@Handler Response(404, GrantHttp.obj("error" to "not_found"))
                if (seg.size == 2 && req.method == "POST") {
                    if (!who.admin) return@Handler Response(403, GrantHttp.obj("error" to "forbidden"))
                    val chain = ArrayList<String>()
                    val c = b["chain"]
                    if (c is List<*> && c.all { it is String }) for (x in c) chain.add(x as String)
                    val r = reg.accept(b["lease"], chain)
                    if (r.code == null) return@Handler Response(if (r.replaced) 201 else 200, GrantHttp.obj("ok" to true, "replaced" to r.replaced, "seq" to r.seq))
                    val err = GrantHttp.obj("error" to r.code)
                    val msg = r.reason
                    if (!msg.isNullOrEmpty()) err["message"] = msg
                    return@Handler Response(STATUS[r.code] ?: 400, err)
                }
                if (seg.size == 3 && seg[2] == "revoke" && req.method == "POST") {
                    if (!who.admin) return@Handler Response(403, GrantHttp.obj("error" to "forbidden"))
                    val r = reg.revoke(b["revocation"])
                    if (r.code == null) return@Handler Response(200, GrantHttp.obj("ok" to true, "revoked" to r.revoked.toLong()))
                    return@Handler Response(if (r.code == "store_unreachable") 503 else if (r.code == "unknown_authority") 403 else 400, GrantHttp.obj("error" to r.code))
                }
                val id = seg.getOrNull(2) ?: return@Handler Response(404, GrantHttp.obj("error" to "not_found"))
                if (seg.size == 3 && req.method == "GET") {
                    val cur = reg.get(id)
                    if (cur == null || !visible(who, cur)) return@Handler Response(404, GrantHttp.obj("error" to "not_found"))
                    return@Handler Response(200, GrantHttp.obj("lease" to cur, "history" to historyJson(reg, id)))
                }
                if (seg.size == 4 && seg[3] == "check" && req.method == "POST") {
                    val cur = reg.get(id)
                    if (cur == null || !visible(who, cur)) return@Handler Response(404, GrantHttp.obj("error" to "not_found"))
                    val d = Lease.checkLease(b["lease"], reg, clock())
                    val body = GrantHttp.obj("decision" to d.decision)
                    if (d.code != null) body["code"] = d.code
                    if (d.leaseId != null) body["lease_id"] = d.leaseId
                    if (d.expiresAt != null) body["expires_at"] = d.expiresAt
                    return@Handler Response(if (d.decision == "allow") 200 else 403, body)
                }
                Response(404, GrantHttp.obj("error" to "not_found"))
            } catch (e: Exception) {
                Response(500, GrantHttp.obj("error" to "server_error"))
            }
        }
    }
}
