package net.atlasauth.pca.verifier

/**
 * Grant management decisions (packages/pca-grants/src/grant-resource.ts), VERIFICATION only: authority comparison and digest, and the pure
 * verdicts for an amendment, a revocation and a needs approval, given the current grant facts (no store, no clock). Signatures are
 * Ed25519 over `domain || strictCanonical(body)` (see [K3Sig]). Nothing widens without the PRINCIPAL's signature and a satisfied step-up
 * (`stepUpOk` is the already-evaluated step-up verdict). Total: malformed input is a failure code, never an exception.
 *
 * An authority is the JSON object `{verbs: [..], resources: [..], limits?: {name: number}, expires_at?: number}`; a grant's facts are
 * `{id, rev, principal, agent, status, authority}`.
 */
object GrantResource {
    const val GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\u0000"
    const val GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\u0000"
    const val NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\u0000"

    /** The strings of a list (anything else is skipped); not a list: empty. Plain loops throughout (no inline-lambda bytecode). */
    private fun strs(o: Any?): List<String> {
        val out = ArrayList<String>()
        if (o is List<*>) for (x in o) if (x is String) out.add(x)
        return out
    }

    private fun covers(p: String, r: String): Boolean = if (p.endsWith("*")) r.startsWith(p.dropLast(1)) else p == r

    private fun resCovered(s: String, big: List<String>): Boolean {
        // the reference also asks `!s.endsWith("*") || b.endsWith("*") || b == s`: implied by covers(b, s) (a non-wildcard b covers only itself)
        for (b in big) if (covers(b, s)) return true
        return false
    }

    private fun resSubset(small: List<String>, big: List<String>): Boolean {
        for (s in small) if (!resCovered(s, big)) return false
        return true
    }

    private fun verbSubset(small: List<String>, big: List<String>): Boolean {
        for (v in small) if (!big.contains(v)) return false
        return true
    }

    private fun allStr(xs: List<Any?>, max: Int): Boolean {
        for (x in xs) if (!K3Sig.isStr(x, max)) return false
        return true
    }

    /** Everything `a` allows, `b` allows. */
    private fun le(a: Map<String, Any?>, b: Map<String, Any?>): Boolean {
        if (!verbSubset(strs(a["verbs"]), strs(b["verbs"])) || !resSubset(strs(a["resources"]), strs(b["resources"]))) return false
        val al = K3Sig.map(a["limits"])
        val bl = K3Sig.map(b["limits"])
        if (al != null) for ((k, v) in al) {
            // a non-number never compares (NaN, as the reference's `v <= bv` on a non-numeric string): fail closed, not "0"
            if (bl != null && bl.containsKey(k) && !((IntentJs.num(v) ?: Double.NaN) <= (IntentJs.num(bl[k]) ?: Double.NaN))) return false
        }
        if (bl != null) for (k in bl.keys) if (al == null || !al.containsKey(k)) return false
        val ae = IntentJs.num(a["expires_at"]) ?: Double.POSITIVE_INFINITY
        val be = IntentJs.num(b["expires_at"]) ?: Double.POSITIVE_INFINITY
        return ae <= be
    }

    /** `narrower`, `equal`, `wider` or `incomparable` (the order of `new` against `old`). */
    @JvmStatic
    fun compareAuthority(old: Map<String, Any?>, new: Map<String, Any?>): String {
        val nle = le(new, old)
        val ole = le(old, new)
        return if (nle && ole) "equal" else if (nle) "narrower" else if (ole) "wider" else "incomparable"
    }

    private val UTF8 = Comparator<String> { x, y -> Json.compareUtf8(x, y) }

    /** Content address of an authority; verb and resource order do not matter. */
    @JvmStatic
    fun authorityDigest(a: Map<String, Any?>): String {
        val body = LinkedHashMap<String, Any?>(a)
        // UTF-8 byte order, as the reference's compareUtf8 (String.compareTo is UTF-16 order: differs above U+FFFF)
        body["verbs"] = strs(a["verbs"]).sortedWith(UTF8)
        body["resources"] = strs(a["resources"]).sortedWith(UTF8)
        return K3Sig.digestOf("d" to "atlas-pca/authority/v1", "a" to body)
    }

    private fun higher(a: Any?, b: Any?): Any? = if ((IntentJs.num(b) ?: Double.NEGATIVE_INFINITY) > (IntentJs.num(a) ?: Double.NEGATIVE_INFINITY)) b else a

    /** Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept (use `replace` to drop it). */
    @JvmStatic
    fun mergeAuthority(a: Map<String, Any?>, d: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["verbs"] = LinkedHashSet(strs(a["verbs"]) + strs(d["verbs"])).toList()
        out["resources"] = LinkedHashSet(strs(a["resources"]) + strs(d["resources"])).toList()
        val limits = LinkedHashMap<String, Any?>()
        val dl = K3Sig.map(d["limits"])
        val al = K3Sig.map(a["limits"])
        // higher(v, absent) is v, so no containsKey test
        if (al != null) for ((k, v) in al) limits[k] = if (dl != null) higher(v, dl[k]) else v
        if (limits.isNotEmpty()) out["limits"] = limits
        val exp = a["expires_at"]
        if (exp != null) out["expires_at"] = higher(exp, d["expires_at"])
        return out
    }

    /** Well formed authority (bounded lists of bounded strings, finite non-negative ceilings, a safe-integer expiry). */
    @JvmStatic
    fun authorityOk(a: Any?): Boolean {
        val m = K3Sig.map(a) ?: return false
        val verbs = K3Sig.list(m["verbs"])
        val resources = K3Sig.list(m["resources"])
        if (verbs == null || verbs.size > 256 || !allStr(verbs, 128)) return false
        if (resources == null || resources.size > 1024 || !allStr(resources, 512)) return false
        if (m.containsKey("limits")) {
            val l = K3Sig.map(m["limits"]) ?: return false
            for (v in l.values) if (!IntentJs.isFinite(v) || IntentJs.num(v)!! < 0.0) return false
        }
        return !m.containsKey("expires_at") || K3Sig.isSafeInt(m["expires_at"])
    }

    /** The message an amendment signature covers: `{grant, rev, action, authority: authorityDigest}`. */
    @JvmStatic
    fun amendMessage(grant: Map<String, Any?>, action: Any?, authority: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["grant"] = grant["id"]
        m["rev"] = grant["rev"]
        m["action"] = action
        m["authority"] = authorityDigest(authority)
        return m
    }

    /** `ok`: whether the change [widens] and the digest of the resulting authority. Otherwise the error [code]. */
    class Amendment(val ok: Boolean, val widens: Boolean = false, val nextDigest: String = "", val code: String = "") {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) {
                m["widens"] = widens
                m["next_digest"] = nextDigest
            } else m["code"] = code
            return m
        }
    }

    private fun no(code: String) = Amendment(false, code = code)

    /**
     * Decide an amendment against the current grant facts. Check order is normative: request shape, authority shape, grant active,
     * classification (a `narrow` that changes nothing or widens is `not_narrower`), signature (`signature_required`, then `bad_signature`;
     * widening needs the PRINCIPAL), step-up for a widening.
     */
    @JvmStatic
    fun verifyAmendment(cur: Map<String, Any?>, req: Any?, stepUpOk: Boolean): Amendment {
        return try {
            val r = K3Sig.map(req)
            val action = r?.get("action")
            if (r == null || (action != "narrow" && action != "merge" && action != "replace")) return no("bad_request")
            val authority = K3Sig.map(r["authority"])
            if (authority == null || !authorityOk(authority)) return no("bad_request")
            if (cur["status"] != "active") return no("not_active")
            val curAuth = K3Sig.map(cur["authority"]) ?: return no("bad_request")
            val next = if (action == "merge") mergeAuthority(curAuth, authority) else authority
            val order = compareAuthority(curAuth, next)
            val widens = order == "wider" || order == "incomparable"
            if (!widens && action == "narrow" && order == "equal") return no("not_narrower")
            if (widens && action == "narrow") return no("not_narrower")
            val sig = r["sig"]
            val signedBy = r["signed_by"]
            if (sig !is String || (signedBy != "holder" && signedBy != "principal")) return no("signature_required")
            if (widens && signedBy != "principal") return no("signature_required")
            val signer = if (signedBy == "principal") cur["principal"] else cur["agent"]
            if (!K3Sig.verifyBody(GRANT_AMEND_DOMAIN, amendMessage(cur, action, authority), signer, sig)) return no("bad_signature")
            if (widens && !stepUpOk) return no("step_up_required")
            Amendment(true, widens, authorityDigest(next))
        } catch (e: RuntimeException) {
            no("bad_request")
        }
    }

    /** `ok`: the revoked [scope]. Otherwise the error [code]. */
    class Revocation(val ok: Boolean, val scope: String = "", val code: String = "") {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) m["scope"] = scope else m["code"] = code
            return m
        }
    }

    /** The message a revocation signature covers: `{grant, scope}`. */
    @JvmStatic
    fun grantRevokeMessage(id: Any?, scope: Any?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["grant"] = id
        m["scope"] = scope
        return m
    }

    /** Decide a revocation's authority: the principal's signature over (grant id, scope). Admin authority is the host's, not a wire fact. */
    @JvmStatic
    fun verifyRevokeSignature(root: Map<String, Any?>, scope: Any?, sig: Any?): Revocation {
        if (scope != "grant" && scope != "agent" && scope != "subtree") return Revocation(false, code = "bad_request")
        if (!K3Sig.verifyBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage(root["id"], scope), root["principal"], sig)) return Revocation(false, code = "bad_signature")
        return Revocation(true, scope = scope as String)
    }

    /** The message a needs approval covers: `{need, grant, rev, approved}`. */
    @JvmStatic
    fun needApproveMessage(nr: Map<String, Any?>, rev: Any?, approved: Any?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["need"] = nr["id"]
        m["grant"] = nr["grant_id"]
        m["rev"] = rev
        m["approved"] = approved
        return m
    }

    /** `ok`: the digest of the merged authority. Otherwise the error [code]. */
    class Approval(val ok: Boolean, val authorityDigest: String = "", val code: String = "") {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) m["authority_digest"] = authorityDigest else m["code"] = code
            return m
        }
    }

    private fun refuse(code: String) = Approval(false, code = code)

    /**
     * Decide a needs approval: principal signature over (need, grant, rev, approved), then the same count, each approved need naming the
     * same verb and resource with amounts only LOWERED and only when the need is `adjustable`, then the step-up. Yields the merged authority.
     */
    @JvmStatic
    fun verifyNeedApproval(nr: Map<String, Any?>, g: Map<String, Any?>, approved: Any?, sig: Any?, stepUpOk: Boolean): Approval {
        return try {
            if (nr["status"] != "pending") return refuse("conflict")
            if (!K3Sig.verifyBody(NEED_APPROVE_DOMAIN, needApproveMessage(nr, g["rev"], approved), g["principal"], sig)) return refuse("bad_signature")
            val needs = K3Sig.list(nr["needs"]) ?: return refuse("need_not_lowered_only")
            val appr = K3Sig.list(approved)
            if (appr == null || appr.size != needs.size) return refuse("need_not_lowered_only")
            val verbs = ArrayList<Any?>()
            val resources = ArrayList<Any?>()
            val limits = LinkedHashMap<String, Any?>()
            for (i in appr.indices) {
                val a = K3Sig.map(appr[i]) ?: return refuse("need_not_lowered_only")
                val want = K3Sig.map(needs[i]) ?: return refuse("need_not_lowered_only")
                if (a["verb"] != want["verb"] || a["resource"] != want["resource"]) return refuse("need_not_lowered_only")
                val wl = K3Sig.map(want["limits"])
                val al = K3Sig.map(a["limits"])
                if (al != null) for ((k, v) in al) {
                    val w = if (wl != null) wl[k] else null
                    val vn = IntentJs.num(v)
                    val wn = IntentJs.num(w)
                    if (wn == null || vn == null || vn > wn) return refuse("need_not_lowered_only")
                    if (vn < wn && want["adjustable"] != true) return refuse("need_not_adjustable")
                }
                verbs.add(a["verb"])
                resources.add(a["resource"])
                // A limit the need names but the principal omitted is not granted at all (omission is the lowest amount).
                if (al != null) for ((k, v) in al) limits[k] = higher(limits[k] ?: Json.Num("0"), v)
            }
            if (!stepUpOk) return refuse("step_up_required")
            val delta = LinkedHashMap<String, Any?>()
            delta["verbs"] = verbs
            delta["resources"] = resources
            delta["limits"] = limits // an empty map merges exactly like an absent one (mergeAuthority reads only `a`'s limit names)
            val authority = K3Sig.map(g["authority"]) ?: return refuse("bad_request")
            Approval(true, authorityDigest(mergeAuthority(authority, delta)))
        } catch (e: RuntimeException) {
            refuse("bad_request")
        }
    }
}
