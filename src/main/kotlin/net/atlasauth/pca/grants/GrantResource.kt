package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.GrantResource as GrantVerify

/**
 * Grant management resource: list / inspect / amend / revoke and incremental authorization for principals. Nothing widens in place: a
 * widening merge or replace needs a fresh principal signature and a satisfied step-up and creates a NEW grant id with `supersedes`. The
 * pure decisions (verifyAmendment, verifyRevokeSignature, verifyNeedApproval, compareAuthority, authorityDigest) are [GrantVerify]; this
 * object holds the extra message builders, the store and the service. Records are parsed-JSON maps: a grant is `{id, principal, agent,
 * parent?, status, authority, rev, chain_digest, supersedes?, superseded_by?, adjustable?, created_at, history[]}`; a need request is
 * `{id, grant_id, needs[], status, created_at, result_grant_id?}`.
 */
object GrantResource {
    const val GRANT_AMEND_DOMAIN = GrantVerify.GRANT_AMEND_DOMAIN
    const val GRANT_REVOKE_DOMAIN = GrantVerify.GRANT_REVOKE_DOMAIN
    const val NEED_APPROVE_DOMAIN = GrantVerify.NEED_APPROVE_DOMAIN
    const val NEED_REQUEST_DOMAIN = "atlas-pca/need-request/v1\u0000"
    const val GRANT_STEPUP_DOMAIN = "atlas-pca/grant-stepup/v1\u0000"

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return m
    }

    @JvmStatic
    fun needRequestMessage(grantId: String, rev: Any?, needs: Any?): Map<String, Any?> = obj("grant" to grantId, "rev" to rev, "needs" to needs)

    @JvmStatic
    fun stepUpMessage(grantId: String, challengeId: String, nonce: String): Map<String, Any?> = obj("grant" to grantId, "challenge" to challengeId, "nonce" to nonce)

    @JvmStatic
    fun signGrantBody(domain: String, body: Any?, secret: Keys.EdKey): String = GrantSigning.signBody(domain, body, secret)

    class GrantError(
        /** not_found conflict bad_request not_narrower signature_required bad_signature step_up_required not_active need_not_lowered_only need_not_adjustable forbidden */
        val code: String,
        message: String?,
    ) : RuntimeException(message)

    /** Persistence of grants and need requests. Implementations must return copies (a caller mutates what it gets, then puts it back). */
    interface GrantStore {
        fun get(id: String): MutableMap<String, Any?>?
        fun put(g: Map<String, Any?>)
        fun list(): List<MutableMap<String, Any?>>
        fun getNeed(id: String): MutableMap<String, Any?>?
        fun putNeed(n: Map<String, Any?>)
        fun listNeeds(grantId: String): List<MutableMap<String, Any?>>
    }

    class MemoryGrantStore : GrantStore {
        private val g = LinkedHashMap<String, Map<String, Any?>>()
        private val n = LinkedHashMap<String, Map<String, Any?>>()

        @Suppress("UNCHECKED_CAST")
        private fun copy(m: Map<String, Any?>?): MutableMap<String, Any?>? = if (m == null) null else norm(m) as MutableMap<String, Any?>

        @Synchronized override fun get(id: String) = copy(g[id])

        @Synchronized override fun put(g: Map<String, Any?>) { this.g[g["id"] as String] = copy(g)!! }

        @Synchronized override fun list(): List<MutableMap<String, Any?>> = g.values.map { copy(it)!! }

        @Synchronized override fun getNeed(id: String) = copy(n[id])

        @Synchronized override fun putNeed(n: Map<String, Any?>) { this.n[n["id"] as String] = copy(n)!! }

        @Synchronized override fun listNeeds(grantId: String): List<MutableMap<String, Any?>> = n.values.filter { grantId == it["grant_id"] }.map { copy(it)!! }
    }

    /** Confirms a satisfied step-up for a widening change. */
    fun interface StepUp { fun verify(ref: String, grant: Map<String, Any?>): Boolean }

    fun interface OnRevoke { fun revoked(ids: List<String>, scope: String, root: Map<String, Any?>) }

    /** kind: amend | revoke | supersede | need. */
    fun interface OnChange { fun changed(kind: String, grant: Map<String, Any?>) }

    /** Hooks and providers. Every field except [store], [now] and [newId] may be null. */
    class Options(
        val store: GrantStore,
        val now: () -> Long,
        /** kind is `grant` or `need`. */
        val newId: (String) -> String,
        val usage: ((Map<String, Any?>) -> Any?)? = null,
        val remainingBudget: ((Map<String, Any?>) -> Any?)? = null,
        val policyCard: ((Map<String, Any?>) -> Any?)? = null,
        val residual: ((Map<String, Any?>) -> Any?)? = null,
        /** Absent: widening is refused (fail closed). */
        val verifyStepUp: StepUp? = null,
        val onRevoke: OnRevoke? = null,
        val onChange: OnChange? = null,
        /** Typed validation of a need: an error string refuses. */
        val validateNeed: ((Map<String, Any?>) -> String?)? = null,
    )

    private val FAIL_MESSAGE = mapOf(
        "not_found" to "no such grant",
        "conflict" to "conflict",
        "bad_request" to "malformed request",
        "not_narrower" to "a narrow amendment must be strictly narrower",
        "signature_required" to "the amendment is signed (by the principal when it widens)",
        "bad_signature" to "the signature does not verify for this grant revision",
        "step_up_required" to "widening needs a satisfied step-up",
        "not_active" to "grant is not active",
        "need_not_lowered_only" to "an approval may only lower amounts of the requested needs",
        "need_not_adjustable" to "the need is not adjustable",
        "forbidden" to "not authorised",
    )

    private fun finiteNonNeg(v: Any?): Boolean {
        if (v !is Number && v !is Json.Num) return false
        val d = if (v is Json.Num) v.raw.toDoubleOrNull() ?: return false else (v as Number).toDouble()
        return !d.isNaN() && !d.isInfinite() && d >= 0
    }

    private fun limitsOk(l: Any?): Boolean {
        val m = K3Sig.map(l) ?: return false
        for (v in m.values) if (!finiteNonNeg(v)) return false
        return true
    }

    private fun checkAuthority(a: Any?) {
        val m = K3Sig.map(a)
        val verbs = K3Sig.list(m?.get("verbs"))
        val resources = K3Sig.list(m?.get("resources"))
        var ok = m != null && verbs != null && verbs.size <= 256 && resources != null && resources.size <= 1024
        if (ok) for (v in verbs!!) ok = ok && K3Sig.isStr(v, 128)
        if (ok) for (v in resources!!) ok = ok && K3Sig.isStr(v, 512)
        ok = ok && (!m!!.containsKey("limits") || limitsOk(m["limits"])) && (!m.containsKey("expires_at") || K3Sig.isSafeInt(m["expires_at"]))
        if (!ok) throw GrantError("bad_request", "malformed authority")
    }

    private fun n(o: Any?): Long = Json.asLong(o)

    /** A deep copy through the strict canonical form (fresh mutable maps and lists, numbers as [Json.Num]). */
    internal fun norm(v: Any?): Any? = Json.parse(Json.canonicalizeStrict(v))

    private fun hist(rev: Long, authority: Any?, at: Long, action: String?): Map<String, Any?> =
        obj("rev" to rev, "authority_digest" to GrantVerify.authorityDigest(K3Sig.map(authority)!!), "at" to at, "action" to action)

    /** List filter: any member may be null. */
    class ListFilter(val principal: String? = null, val agent: String? = null, val status: String? = null, val limit: Long? = null, val cursor: String? = null)

    @Suppress("UNCHECKED_CAST")
    private fun histOf(g: Map<String, Any?>): MutableList<Any?> = g["history"] as MutableList<Any?>

    class GrantService(private val o: Options) {
        /** Create a grant record: `{id, principal, agent, parent?, authority, chain_digest, ...}` (status optional, default active). */
        fun register(g: Map<String, Any?>): Map<String, Any?> {
            checkAuthority(g["authority"])
            if (o.store.get(g["id"] as String) != null) throw GrantError("conflict", "grant id exists")
            val now = o.now()
            val rec = LinkedHashMap<String, Any?>(g)
            rec["status"] = g["status"] ?: "active"
            rec["rev"] = 1L
            rec["created_at"] = now
            rec["history"] = arrayListOf<Any?>(hist(1, g["authority"], now, "create"))
            o.store.put(rec)
            return rec
        }

        fun list(f: ListFilter): Map<String, Any?> {
            val limit = minOf(maxOf(f.limit ?: 50L, 1L), 200L)
            val all = o.store.list().filter {
                (f.principal == null || f.principal == it["principal"]) && (f.agent == null || f.agent == it["agent"]) && (f.status == null || f.status == it["status"])
            }.sortedBy { it["id"] as String }
            val filtered = all.filter { f.cursor == null || (it["id"] as String) > f.cursor }
            val page = filtered.subList(0, minOf(limit, filtered.size.toLong()).toInt())
            val views = ArrayList<Any?>()
            for (g in page) views.add(view(g, false))
            val out = LinkedHashMap<String, Any?>()
            out["grants"] = views
            if (filtered.size > limit) out["next_cursor"] = page[page.size - 1]["id"]
            return out
        }

        fun inspect(id: String): Map<String, Any?> = view(must(id), true)

        private fun view(g: Map<String, Any?>, rich: Boolean): Map<String, Any?> {
            val v = LinkedHashMap<String, Any?>(g)
            v.remove("history")
            v["authority_digest"] = GrantVerify.authorityDigest(K3Sig.map(g["authority"])!!)
            val needs = ArrayList<Any?>()
            for (nr in o.store.listNeeds(g["id"] as String)) if (nr["status"] == "pending") needs.add(nr["id"])
            v["pending_needs"] = needs
            if (rich) {
                put(v, "usage", o.usage, g)
                put(v, "remaining_budget", o.remainingBudget, g)
                put(v, "policy_card", o.policyCard, g)
                put(v, "residual", o.residual, g)
            }
            return v
        }

        private fun put(v: MutableMap<String, Any?>, k: String, p: ((Map<String, Any?>) -> Any?)?, g: Map<String, Any?>) {
            if (p == null) return
            val r = p(g)
            if (r != null) v[k] = r // a provider with nothing to report returns null (the reference's undefined, dropped from JSON)
        }

        private fun must(id: String): MutableMap<String, Any?> = o.store.get(id) ?: throw GrantError("not_found", "no such grant")

        private fun truthy(v: Any?): Boolean = if (v is String) v.isNotEmpty() else v != null && v != false

        /**
         * The grant that replaces [cur] for a widening change: a fresh id, `supersedes` set, history restarted. The caller stores it and the
         * superseded [cur].
         */
        private fun superseding(cur: MutableMap<String, Any?>, nid: String, authority: Map<String, Any?>, now: Long, action: String): LinkedHashMap<String, Any?> {
            val fresh = LinkedHashMap<String, Any?>(cur)
            fresh["id"] = nid
            fresh["authority"] = authority
            fresh["rev"] = 1L
            fresh["status"] = "active"
            fresh["supersedes"] = cur["id"]
            fresh["created_at"] = now
            fresh["history"] = arrayListOf<Any?>(hist(1, authority, now, action))
            fresh.remove("superseded_by")
            cur["status"] = "superseded"
            cur["superseded_by"] = nid
            return fresh
        }

        /** Amend; returns `{grant, created}`. [req] = `{action, authority, sig?, signed_by?, step_up_ref?}`. */
        fun amend(id: String, req: Map<String, Any?>): Map<String, Any?> {
            val cur = must(id)
            var v = GrantVerify.verifyAmendment(cur, req, false)
            // Evaluate the (possibly consuming) step-up only when everything else already passed.
            val ref = req["step_up_ref"]
            val su = o.verifyStepUp
            if (!v.ok && v.code == "step_up_required" && truthy(ref) && su != null && su.verify("$ref", cur)) v = GrantVerify.verifyAmendment(cur, req, true)
            if (!v.ok) throw GrantError(v.code, FAIL_MESSAGE[v.code])
            // The verdict carries the digest of the resulting authority; rebuild it and refuse on any disagreement.
            val reqAuth = K3Sig.map(req["authority"])!!
            val next = if (req["action"] == "merge") GrantVerify.mergeAuthority(K3Sig.map(cur["authority"])!!, reqAuth) else reqAuth
            if (GrantVerify.authorityDigest(next) != v.nextDigest) throw GrantError("bad_request", FAIL_MESSAGE["bad_request"])
            val now = o.now()
            if (!v.widens) {
                cur["authority"] = next
                val rev = n(cur["rev"]) + 1
                cur["rev"] = rev
                histOf(cur).add(hist(rev, next, now, req["action"] as String?))
                o.store.put(cur)
                o.onChange?.changed("amend", cur)
                return obj("grant" to view(cur, true), "created" to false)
            }
            val nid = o.newId("grant")
            val fresh = superseding(cur, nid, next, now, "supersedes:" + cur["id"])
            o.store.put(fresh)
            o.store.put(cur)
            o.onChange?.changed("supersede", fresh)
            return obj("grant" to view(fresh, true), "created" to true)
        }

        /**
         * Revoke, authorised by the principal's signature over `{grant id, scope}` ([sig] non-null) or by a host-authenticated admin
         * ([sig] null and [admin] true). Returns `{revoked: [ids]}`.
         */
        fun revoke(id: String, scope: String, sig: String?, admin: Boolean): Map<String, Any?> {
            if (scope != "grant" && scope != "agent" && scope != "subtree") throw GrantError("bad_request", "unknown scope")
            val root = must(id)
            if (sig != null) {
                val rv = GrantVerify.verifyRevokeSignature(root, scope, sig)
                if (!rv.ok) throw GrantError(rv.code, FAIL_MESSAGE[rv.code])
            } else if (!admin) throw GrantError("forbidden", "not authorised")
            val all = o.store.list()
            val hit = ArrayList<MutableMap<String, Any?>>()
            if (scope == "grant") hit.add(root)
            else if (scope == "agent") {
                for (g in all) if (g["agent"] == root["agent"] && g["principal"] == root["principal"]) hit.add(g)
            } else {
                val ids = HashSet<Any?>()
                ids.add(id)
                var grew = true
                while (grew) {
                    grew = false
                    for (g in all) if (g["parent"] != null && g["parent"] in ids && g["id"] !in ids) { ids.add(g["id"]); grew = true }
                }
                for (g in all) if (g["id"] in ids) hit.add(g)
            }
            val revoked = ArrayList<String>()
            for (g in hit) {
                if (g["status"] == "revoked") continue
                g["status"] = "revoked"
                histOf(g).add(hist(n(g["rev"]), g["authority"], o.now(), "revoke:$scope"))
                o.store.put(g)
                revoked.add(g["id"] as String)
            }
            o.onRevoke?.revoked(revoked, scope, root)
            o.onChange?.changed("revoke", root)
            return obj("revoked" to ArrayList<Any?>(revoked))
        }

        /** Agent side: ask for more. Typed needs only; no authority changes until the principal approves. */
        fun requestNeeds(grantId: String, needs: Any?): Map<String, Any?> {
            val g = must(grantId)
            if (g["status"] != "active") throw GrantError("not_active", "grant is ${g["status"]}")
            val list = K3Sig.list(needs)
            if (list == null || list.size < 1 || list.size > 32) throw GrantError("bad_request", "1..32 needs")
            for (no in list) {
                val nd = K3Sig.map(no)
                if (nd == null || !K3Sig.isStr(nd["verb"], 128) || !K3Sig.isStr(nd["resource"], 512) || (nd["limits"] != null && !limitsOk(nd["limits"]))) throw GrantError("bad_request", "malformed need")
                val vn = o.validateNeed
                if (vn != null) {
                    val e = vn(nd)
                    if (!e.isNullOrEmpty()) throw GrantError("bad_request", e)
                }
            }
            val nr = obj("id" to o.newId("need"), "grant_id" to grantId, "needs" to norm(needs), "status" to "pending", "created_at" to o.now())
            o.store.putNeed(nr)
            o.onChange?.changed("need", g)
            return nr
        }

        /** The authority a verified approval yields: the grant's authority merged with the approved delta (limits default to 0, never absent). */
        private fun approvedAuthority(g: Map<String, Any?>, approved: Any?): Map<String, Any?> {
            val verbs = ArrayList<Any?>()
            val resources = ArrayList<Any?>()
            val limits = LinkedHashMap<String, Any?>()
            for (a0 in K3Sig.list(approved)!!) {
                val a = K3Sig.map(a0)!!
                verbs.add(a["verb"])
                resources.add(a["resource"])
                val al = K3Sig.map(a["limits"])
                if (al != null) for ((k, v) in al) {
                    val cur = limits[k] ?: Json.Num("0")
                    limits[k] = if ((IntentJs.num(v) ?: Double.NEGATIVE_INFINITY) > (IntentJs.num(cur) ?: Double.NEGATIVE_INFINITY)) v else cur
                }
            }
            val delta = obj("verbs" to verbs, "resources" to resources, "limits" to limits)
            return GrantVerify.mergeAuthority(K3Sig.map(g["authority"])!!, delta)
        }

        /** Principal side: approve the delta (a widening merge). Returns `{grant, created}`. */
        fun approveNeeds(needId: String, approved: Any?, sig: String?, stepUpRef: String?): Map<String, Any?> {
            val nr = o.store.getNeed(needId) ?: throw GrantError("not_found", "no such need request")
            if (nr["status"] != "pending") throw GrantError("conflict", "need request is ${nr["status"]}")
            val g = must(nr["grant_id"] as String)
            var v = GrantVerify.verifyNeedApproval(nr, g, approved, sig, false)
            val su = o.verifyStepUp
            if (!v.ok && v.code == "step_up_required" && !stepUpRef.isNullOrEmpty() && su != null && su.verify(stepUpRef, g)) v = GrantVerify.verifyNeedApproval(nr, g, approved, sig, true)
            if (!v.ok) throw GrantError(v.code, FAIL_MESSAGE[v.code])
            val authority = approvedAuthority(g, approved)
            if (GrantVerify.authorityDigest(authority) != v.authorityDigest) throw GrantError("bad_request", FAIL_MESSAGE["bad_request"])
            val nid = o.newId("grant")
            val now = o.now()
            val fresh = superseding(g, nid, authority, now, "needs:$needId")
            nr["status"] = "approved"
            nr["result_grant_id"] = nid
            o.store.put(fresh)
            o.store.put(g)
            o.store.putNeed(nr)
            o.onChange?.changed("supersede", fresh)
            return obj("grant" to view(fresh, true), "created" to true)
        }

        /** The grant a need request belongs to. */
        fun needGrantId(needId: String): String {
            val nr = o.store.getNeed(needId) ?: throw GrantError("not_found", "no such need request")
            return nr["grant_id"] as String
        }

        fun denyNeeds(needId: String) {
            val nr = o.store.getNeed(needId) ?: throw GrantError("not_found", "no such need request")
            if (nr["status"] != "pending") throw GrantError("conflict", "need request is ${nr["status"]}")
            nr["status"] = "denied"
            o.store.putNeed(nr)
        }
    }
}
