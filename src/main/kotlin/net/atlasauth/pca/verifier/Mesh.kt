package net.atlasauth.pca.verifier

/**
 * Cross-domain mesh proofs (the agent mesh, mesh.ts `verifyMeshProof`). A mesh proof carries a capability chain, one witnessed head
 * per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action. [verifyMeshProof]
 * checks all of it offline and returns the reference's reason and failing hop.
 *
 * Scope: everything verifyMeshProof does, including RFC 9162 consistency proofs from a pinned head. The witness side (cosigning,
 * head publication) is not here: a verifier only needs to check what they produced. Total: any malformed input is a verdict.
 */
object Mesh {
    const val HEAD_DOMAIN = "atlas-pca/mesh-head/v1\u0000"
    const val COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\u0000"
    const val BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\u0000"
    const val ACTION_DOMAIN = "atlas-pca/mesh-action/v1\u0000"

    private const val DEFAULT_MAX_HEAD_AGE_MS = 5.0 * 60_000
    private const val DEFAULT_MAX_SKEW_MS = 60_000.0
    private const val DEFAULT_MAX_CHAIN = 64L
    private const val MAX_COSIGS = 256
    private const val MAX_PATH = 128
    private const val REVSET_PREFIX = "pca-revset/v1\u0000"

    /** The result of [verifyMeshProof]. `hop` is -1 when no hop is named. */
    class Verdict(val ok: Boolean, val reason: String, val hop: Int) {
        override fun toString(): String = "Mesh.Verdict(ok=$ok, reason=$reason, hop=$hop)"
    }

    private fun fail(reason: String, hop: Int) = Verdict(false, reason, hop)

    @Suppress("UNCHECKED_CAST")
    private fun rec(x: Any?): Map<String, Any?>? = x as? Map<String, Any?>

    private fun str(x: Any?): String? = x as? String
    private fun nat(x: Any?): Boolean = Json.isSafeInt(x) && IntentJs.isNonNeg(x)
    private fun num(x: Any?): Boolean = IntentJs.num(x)?.let { !it.isNaN() && !it.isInfinite() } ?: false
    private fun natV(x: Any?): Long = if (Json.isSafeInt(x)) Json.asLong(x) else 0L
    private fun f(x: Any?): Double = IntentJs.num(x) ?: Double.NaN

    private fun msg(domain: String, body: Any?): ByteArray? = try {
        (domain + Json.canonicalizeStrict(body)).toByteArray(Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        null
    }

    private fun validHead(h: Any?): Map<String, Any?>? {
        val m = rec(h) ?: return null
        if (str(m["domain"]) == null) return null
        val root = str(m["root"]) ?: return null
        if (str(m["rev_root"]) == null) return null
        if (!nat(m["size"]) || !nat(m["rev_size"]) || !num(m["timestamp"])) return null
        return if ((natV(m["size"]) == 0L) == (root == "")) m else null
    }

    private fun validConsistency(c: Any?): Map<String, Any?>? {
        val m = rec(c) ?: return null
        if (!nat(m["oldSize"]) || !nat(m["newSize"])) return null
        val path = m["path"] as? List<*> ?: return null
        if (path.size > MAX_PATH) return null
        for (p in path) if (str(p) == null) return null
        return m
    }

    private fun validInclusion(i: Any?): Map<String, Any?>? {
        val m = rec(i) ?: return null
        if (!nat(m["index"]) || !nat(m["size"])) return null
        val path = m["path"] as? List<*> ?: return null
        return if (path.size <= MAX_PATH) m else null
    }

    private fun validAction(a: Any?): Map<String, Any?>? {
        val m = rec(a) ?: return null
        for (k in listOf("type", "resource", "service_domain", "nonce")) if (str(m[k]) == null) return null
        if (!num(m["at"])) return null
        if (m.containsKey("amount") && !num(m["amount"])) return null
        return m
    }

    // ---- effective authority ----

    private class Authority {
        var actions: List<String> = emptyList()
        var hasAct = false
        val prefixes = ArrayList<String>()
        var maxAmount = 0.0
        var hasAmount = false
        var expiresAt = 0.0
        var hasExp = false
        var audience: List<String> = emptyList()
        var hasAud = false
        var maxHops = 0.0
        var hasHops = false
    }

    private fun intersect(have: Boolean, a: List<String>, b: List<String>): List<String> {
        if (!have) {
            val seen = HashSet<String>()
            val out = ArrayList<String>()
            for (x in b) if (seen.add(x)) out.add(x)
            return out.sortedWith { x, y -> Json.compareUtf8(x, y) }
        }
        return a.filter { x -> b.contains(x) }
    }

    private fun strings(v: Any?): List<String>? {
        val arr = v as? List<*> ?: return null
        val out = ArrayList<String>(arr.size)
        for (x in arr) out.add(str(x) ?: return null)
        return out
    }

    private fun minOf(have: Boolean, cur: Double, v: Double): Double = if (!have) v else Math.min(cur, v)

    /** `effectiveAuthority`: the conjunction of the caveats into `e`; "" or the error (an unknown or malformed caveat is an error). */
    private fun effective(caveats: Any?, e: Authority): String {
        val arr = caveats as? List<*> ?: return "malformed proof"
        for (cv in arr) {
            val c = rec(cv) ?: return "malformed proof"
            when (c["type"] as? String ?: "") {
                "scope" -> {
                    val a = strings(c["actions"]) ?: return "malformed scope caveat"
                    e.actions = intersect(e.hasAct, e.actions, a)
                    e.hasAct = true
                }
                "resource" -> {
                    val p = str(c["prefix"]) ?: return "malformed resource caveat"
                    e.prefixes.add(p)
                }
                "max_amount" -> {
                    if (!num(c["max"])) return "malformed max_amount caveat"
                    e.maxAmount = minOf(e.hasAmount, e.maxAmount, f(c["max"]))
                    e.hasAmount = true
                }
                "expires" -> {
                    if (!num(c["at"])) return "malformed expires caveat"
                    e.expiresAt = minOf(e.hasExp, e.expiresAt, f(c["at"]))
                    e.hasExp = true
                }
                "audience" -> {
                    val d = strings(c["domains"]) ?: return "malformed audience caveat"
                    e.audience = intersect(e.hasAud, e.audience, d)
                    e.hasAud = true
                }
                "max_hops" -> {
                    if (!num(c["n"])) return "malformed max_hops caveat"
                    e.maxHops = minOf(e.hasHops, e.maxHops, f(c["n"]))
                    e.hasHops = true
                }
                else -> return "unknown caveat type \"${IntentRevocation.jsText(IntentJs.normalize(c["type"]), c.containsKey("type"))}\" (fail closed)"
            }
        }
        return ""
    }

    private fun subset(child: List<String>, parent: List<String>): Boolean = child.all { parent.contains(it) }

    private fun narrows(child: Authority, parent: Authority): Boolean {
        if (parent.hasAct && (!child.hasAct || !subset(child.actions, parent.actions))) return false
        if (parent.hasAud && (!child.hasAud || !subset(child.audience, parent.audience))) return false
        if (parent.hasAmount && (!child.hasAmount || child.maxAmount > parent.maxAmount)) return false
        if (parent.hasExp && (!child.hasExp || child.expiresAt > parent.expiresAt)) return false
        if (parent.hasHops && (!child.hasHops || child.maxHops > parent.maxHops)) return false
        return subset(parent.prefixes, child.prefixes)
    }

    private fun admits(e: Authority, a: Map<String, Any?>, now: Double, chainLen: Int): String {
        val typ = a["type"] as? String ?: ""
        val res = a["resource"] as? String ?: ""
        val svc = a["service_domain"] as? String ?: ""
        if (e.hasAct && !subset(listOf(typ), e.actions)) return "action \"$typ\" not in scope"
        for (p in e.prefixes) {
            if (!res.startsWith(p)) return "resource \"$res\" outside prefix \"$p\""
        }
        if (e.hasAmount) {
            if (!a.containsKey("amount") || f(a["amount"]) > e.maxAmount) return "amount exceeds ceiling ${AttestUtil.jsNumString(e.maxAmount)}"
        }
        if (e.hasExp && now > e.expiresAt) return "capability expired"
        if (e.hasAud && !subset(listOf(svc), e.audience)) return "service domain not in audience"
        if (e.hasHops && chainLen.toDouble() > e.maxHops) return "chain exceeds max_hops ${AttestUtil.jsNumString(e.maxHops)}"
        return ""
    }

    // ---- revocation sets and Merkle proofs ----

    private fun revNode(l: ByteArray, r: ByteArray): ByteArray = Pca.sha(byteArrayOf(1), l, r)

    private fun bindRevRoot(size: Long, tree: String): String =
        Pca.b64(Pca.sha(REVSET_PREFIX.toByteArray(Charsets.UTF_8), IntentJs.canonBytes(linkedMapOf<String, Any?>("size" to IntentJs.ofLong(size), "tree" to tree))))

    private fun emptyRevTree(): String = Pca.b64(Pca.sha(ByteArray(0)))

    private fun leafOk(root: String, size: Long, id: String, proof: Map<String, Any?>): Boolean {
        if (!Json.isSafeInt(proof["size"]) || !Json.isSafeInt(proof["index"])) return false
        val psize = Json.asLong(proof["size"])
        val index = Json.asLong(proof["index"])
        if (psize != size || index < 0 || index >= size) return false
        val sides = Pca.pathShape(index, size)
        val path = proof["path"] as? List<*> ?: return false
        if (path.size != sides.size) return false
        var h = try { Pca.leafHash(id) } catch (e: IllegalArgumentException) { return false }
        for ((i, s) in path.withIndex()) {
            val step = rec(s) ?: return false
            val side = step["side"] as? String ?: ""
            val hs = step["hash"] as? String ?: ""
            if (side != sides[i]) return false
            val sib = Pca.decodeB64uStrict(hs, 32) ?: return false
            h = if (side == "L") revNode(sib, h) else revNode(h, sib)
        }
        return bindRevRoot(size, Pca.b64(h)) == root
    }

    /** `verifyNonMembership` over an expanded proof `{size, lo?, hi?}`. */
    private fun nonMembership(root: String, nm: Map<String, Any?>, id: String): Boolean {
        if (!Json.isSafeInt(nm["size"])) return false
        val size = Json.asLong(nm["size"])
        if (size < 0) return false
        val lo = rec(nm["lo"])
        val hi = rec(nm["hi"])
        if (size == 0L) return lo == null && hi == null && bindRevRoot(0, emptyRevTree()) == root
        if (lo == null && hi == null) return false
        var loIdx = 0L
        var hiIdx = 0L
        if (lo != null) {
            val loId = lo["id"] as? String ?: ""
            val lp = rec(lo["proof"])
            if (lp == null || !(Json.compareUtf8(loId, id) < 0) || !leafOk(root, size, loId, lp)) return false
            loIdx = natV(lp["index"])
            if (hi == null && loIdx != size - 1) return false
        }
        if (hi != null) {
            val hiId = hi["id"] as? String ?: ""
            val hp = rec(hi["proof"])
            if (hp == null || !(Json.compareUtf8(id, hiId) < 0) || !leafOk(root, size, hiId, hp)) return false
            hiIdx = natV(hp["index"])
            if (lo == null && hiIdx != 0L) return false
        }
        if (lo != null && hi != null && hiIdx != loIdx + 1) return false
        return true
    }

    /** `verifyLedgerConsistency` (RFC 9162 section 2.1.4.2), with strict 32-byte base64url hashes. */
    private fun consistency(oldRoot: String, newRoot: String, proof: Map<String, Any?>): Boolean {
        if (!Json.isSafeInt(proof["oldSize"]) || !Json.isSafeInt(proof["newSize"])) return false
        val first = Json.asLong(proof["oldSize"])
        val second = Json.asLong(proof["newSize"])
        if (first < 0 || first > second) return false
        val raw = (proof["path"] as? List<*>) ?: emptyList<Any?>()
        if (raw.size > MAX_PATH) return false
        val empty = emptyRevTree()
        if (first == 0L) {
            if (raw.isNotEmpty() || oldRoot != empty) return false
            if (second == 0L) return newRoot == empty
            return true
        }
        if (first == second) return raw.isEmpty() && oldRoot == newRoot
        val path = ArrayList<ByteArray>(raw.size + 1)
        if ((first and (first - 1)) == 0L) path.add(Pca.decodeB64uStrict(oldRoot, 32) ?: return false)
        for (p in raw) path.add(Pca.decodeB64uStrict(p as? String ?: "", 32) ?: return false)
        if (path.isEmpty()) return false
        var fn = first - 1
        var sn = second - 1
        while ((fn and 1L) == 1L) {
            fn = fn ushr 1
            sn = sn ushr 1
        }
        var fr = path[0]
        var sr = path[0]
        for (i in 1 until path.size) {
            val c = path[i]
            if (sn == 0L) return false
            if ((fn and 1L) == 1L || fn == sn) {
                fr = revNode(c, fr)
                sr = revNode(c, sr)
                while ((fn and 1L) == 0L && fn != 0L) {
                    fn = fn ushr 1
                    sn = sn ushr 1
                }
            } else sr = revNode(sr, c)
            fn = fn ushr 1
            sn = sn ushr 1
        }
        return sn == 0L && Pca.b64(fr) == oldRoot && Pca.b64(sr) == newRoot
    }

    // ---- heads ----

    private fun checkHeadAdvance(prev: Any?, next: Any?, proof: Any?): String {
        val p = validHead(prev) ?: return "malformed head"
        val n = validHead(next) ?: return "malformed head"
        if (p["domain"] != n["domain"]) return "head is for a different domain"
        if (natV(n["size"]) < natV(p["size"]) || natV(n["rev_size"]) < natV(p["rev_size"])) return "head rolls back"
        if (natV(n["size"]) == natV(p["size"])) {
            if (n["root"] != p["root"]) return "equivocation (same size, different log)"
        } else {
            val c = validConsistency(proof)
            if (c == null || natV(c["oldSize"]) != natV(p["size"]) || natV(c["newSize"]) != natV(n["size"])) return "consistency proof required for a larger head"
            if (!consistency(p["root"] as String, n["root"] as String, c)) return "head is not consistent with the previous head (fork or rewrite)"
        }
        if (natV(n["rev_size"]) == natV(p["rev_size"]) && n["rev_root"] != p["rev_root"]) return "equivocation (revocation set)"
        return ""
    }

    private class Trust(
        val human: String, val witnesses: Set<String>, val threshold: Long, val now: Double, val maxHeadAge: Double, val maxSkew: Double,
        val maxActionAge: Double, val hasActionAge: Boolean, val maxChain: Long, val allowed: List<String>, val rootDomain: String,
        val issuerDoms: Map<String, Any?>?, val pinned: Map<String, Any?>?, val pqPins: Map<String, Any?>?,
    )

    private fun opt(t: Map<String, Any?>, k: String, def: Double): Double? {
        if (!t.containsKey(k)) return def
        val v = t[k]
        if (!num(v) || f(v) < 0) return null
        return f(v)
    }

    /** The validated trust configuration, or the reason it is invalid. */
    private fun validTrust(traw: Any?): Pair<Trust?, String> {
        val bad = "invalid trust configuration"
        val t = rec(traw) ?: return Pair(null, bad)
        val human = str(t["humanPrincipal"])
        val ws = strings(t["witnesses"])
        if (human == null || ws == null) return Pair(null, bad)
        val witnesses = ws.toSet()
        if (!nat(t["threshold"]) || natV(t["threshold"]) < 1 || natV(t["threshold"]) > witnesses.size) return Pair(null, "$bad: threshold")
        val threshold = natV(t["threshold"])
        if (!num(t["now"])) return Pair(null, "$bad: now")
        val now = f(t["now"])
        val maxHeadAge = opt(t, "maxHeadAgeMs", DEFAULT_MAX_HEAD_AGE_MS) ?: return Pair(null, "$bad: maxHeadAgeMs")
        val maxSkew = opt(t, "maxClockSkewMs", DEFAULT_MAX_SKEW_MS) ?: return Pair(null, "$bad: maxClockSkewMs")
        var maxActionAge = 0.0
        var hasActionAge = false
        if (t.containsKey("maxActionAgeMs")) {
            maxActionAge = opt(t, "maxActionAgeMs", 0.0) ?: return Pair(null, "$bad: maxActionAgeMs")
            hasActionAge = true
        }
        var maxChain = DEFAULT_MAX_CHAIN
        if (t.containsKey("maxChainLength")) {
            val v = t["maxChainLength"]
            if (!nat(v) || natV(v) < 1) return Pair(null, "$bad: maxChainLength")
            maxChain = natV(v)
        }
        val ad = strings(t["allowedDomains"])
        if (ad == null || ad.isEmpty()) return Pair(null, "$bad: allowedDomains is required")
        val rd = str(t["rootDomain"])
        if (rd == null || !subset(listOf(rd), ad)) return Pair(null, "$bad: rootDomain is required and must be in allowedDomains")
        var issuerDoms: Map<String, Any?>? = null
        if (t.containsKey("issuerDomains")) {
            val m = rec(t["issuerDomains"]) ?: return Pair(null, "$bad: issuerDomains")
            for (x in m.values) if (str(x) == null) return Pair(null, "$bad: issuerDomains")
            issuerDoms = m
        }
        var pinned: Map<String, Any?>? = null
        if (t.containsKey("pinnedHeads")) pinned = rec(t["pinnedHeads"]) ?: return Pair(null, "$bad: pinnedHeads")
        var pqPins: Map<String, Any?>? = null
        if (t.containsKey("pqPins")) {
            val m = rec(t["pqPins"])
            if (m != null) {
                val pins = LinkedHashMap<String, Any?>()
                for ((k, x) in m) if (x is String) pins[k] = x
                pqPins = pins
            }
        }
        return Pair(Trust(human, witnesses, threshold, now, maxHeadAge, maxSkew, maxActionAge, hasActionAge, maxChain, ad, rd, issuerDoms, pinned, pqPins), "")
    }

    /** JavaScript truthiness for a decoded JSON value. */
    private fun truthy(v: Any?): Boolean = when (v) {
        null -> false
        is Boolean -> v
        is String -> v.isNotEmpty()
        else -> IntentJs.num(v)?.let { it != 0.0 && !it.isNaN() } ?: true
    }

    private fun checkCosignedHead(ch: Any?, expectedDomain: String, t: Trust, pinProof: Any?): String {
        val chm = rec(ch)
        val h = rec(chm?.get("head"))
        if (chm == null || h == null || h["domain"] != expectedDomain) return "head is for a different domain"
        if (validHead(h) == null) return "malformed head"
        val sig = str(chm["sig"]) ?: return "malformed head"
        val domain = h["domain"] as String
        val m = msg(HEAD_DOMAIN, h)
        if (m == null || !Pca.verifyB64u(domain, m, sig)) return "head not signed by its domain key"
        val cosigs = chm["cosigs"] as? List<*>
        if (cosigs == null || cosigs.size > MAX_COSIGS) return "malformed head"
        val good = HashSet<String>()
        val cm = msg(COSIG_DOMAIN, h)
        for (c in cosigs) {
            val cr = rec(c) ?: continue
            val w = str(cr["witness"])
            val s = str(cr["sig"])
            if (w != null && s != null && t.witnesses.contains(w) && !good.contains(w) && cm != null && Pca.verifyB64u(w, cm, s)) good.add(w)
        }
        if (good.size < t.threshold) return "head has ${good.size}/${t.threshold} trusted witness cosignatures"
        val ts = f(h["timestamp"])
        if (ts > t.now + t.maxSkew) return "head timestamp is in the future"
        if (t.now - ts > t.maxHeadAge) return "head is stale"
        val pinned = t.pinned
        if (pinned != null && pinned.containsKey(domain) && truthy(pinned[domain])) {
            val why = checkHeadAdvance(pinned[domain], h, pinProof)
            if (why != "") return "$why (vs pinned head)"
        }
        return ""
    }

    private fun expandNm(c: Any?, leaves: List<*>): Map<String, Any?>? {
        val m = rec(c) ?: return null
        if (!nat(m["size"])) return null
        val out = LinkedHashMap<String, Any?>()
        out["size"] = m["size"]
        for (side in listOf("lo", "hi")) {
            if (!m.containsKey(side)) continue
            val ix = m[side]
            if (!nat(ix) || natV(ix) >= leaves.size) return null
            out[side] = leaves[natV(ix).toInt()]
        }
        return out
    }

    /** Verifies a mesh proof end to end, offline. Both arguments are parsed JSON ([Json.parseLenient] values). Total. */
    @JvmStatic
    fun verifyMeshProof(proof: Any?, trust: Any?): Verdict = try {
        verify(proof, trust)
    } catch (e: RuntimeException) {
        fail("malformed proof", -1)
    } catch (e: StackOverflowError) {
        fail("malformed proof", -1)
    }

    private fun verify(proof: Any?, trust: Any?): Verdict {
        val (t, bad) = validTrust(trust)
        if (t == null) return fail(bad, -1)
        val p = rec(proof) ?: return fail("malformed proof", -1)
        val chain = p["chain"] as? List<*>
        val hops = p["hops"] as? List<*>
        val heads = p["heads"] as? List<*>
        val revLeaves = p["rev_leaves"] as? List<*>
        if (chain == null || hops == null || heads == null || revLeaves == null) return fail("malformed proof", -1)
        val actionSig = str(p["action_sig"])
        val action = validAction(p["action"])
        if (actionSig == null || action == null) return fail("malformed action", -1)
        if (p.containsKey("pin_proofs")) {
            val arr = p["pin_proofs"] as? List<*>
            if (arr == null || arr.size > MAX_COSIGS) return fail("malformed pin proofs", -1)
            for (x in arr) {
                val xm = rec(x) ?: return fail("malformed pin proofs", -1)
                if (str(xm["domain"]) == null) return fail("malformed pin proofs", -1)
                if (validConsistency(xm["proof"]) == null) return fail("malformed pin proofs", -1)
            }
        }
        if (chain.size < 1 || chain.size.toLong() > t.maxChain) return fail("chain length out of bounds", -1)
        if (heads.size > chain.size || revLeaves.size > 2 * chain.size) return fail("evidence tables exceed chain size", -1)
        val chainWhy = Pca.verifyChain(chain, t.human, true, null, t.pqPins, null)
        if (chainWhy != "") return fail("chain: $chainWhy", -1)
        if (hops.size != chain.size) return fail("hop evidence count does not match chain length", -1)
        for (l in revLeaves) {
            val lm = rec(l) ?: return fail("malformed revocation leaves", -1)
            if (str(lm["id"]) == null) return fail("malformed revocation leaves", -1)
            if (validInclusion(lm["proof"]) == null) return fail("malformed revocation leaves", -1)
        }
        val used = HashSet<Long>()
        for (h in hops) {
            val ev = rec(h)
            if (ev != null && nat(ev["head"])) used.add(natV(ev["head"]))
        }
        if (used.size != heads.size) return fail("unreferenced or missing head in evidence table", -1)

        val headErrs = HashMap<Long, String>()
        val headDone = HashSet<Long>()
        var prev = Authority()
        var havePrev = false
        for (i in chain.indices) {
            val cap = rec(chain[i]) ?: emptyMap()
            val ev = rec(hops[i]) ?: return fail("malformed hop evidence", i)
            val domain = str(ev["domain"])
            val revOk = rec(ev["revocation"]) != null
            if (domain == null || !nat(ev["head"]) || natV(ev["head"]) >= heads.size || !revOk) return fail("malformed hop evidence", i)
            if (!subset(listOf(domain), t.allowed)) return fail("issuing domain not allowed by policy", i)
            if (i == 0 && domain != t.rootDomain) return fail("root capability must be anchored in the pinned root domain", i)
            val issuer = cap["issuer"] as? String ?: ""
            val issuerDoms = t.issuerDoms
            if (i > 0 && issuerDoms != null && issuerDoms.containsKey(issuer) && issuerDoms[issuer] != domain)
                return fail("issuer key is pinned to a different domain", i)
            val hi = natV(ev["head"])
            val ch = heads[hi.toInt()]
            if (!headDone.contains(hi)) {
                val dom = rec(rec(ch)?.get("head"))?.get("domain") as? String ?: ""
                var pinProof: Any? = null
                val pps = p["pin_proofs"] as? List<*>
                if (pps != null) for (x in pps) {
                    val xm = rec(x)
                    if (xm != null && xm["domain"] == dom) { pinProof = xm["proof"]; break }
                }
                headErrs[hi] = checkCosignedHead(ch, dom, t, pinProof)
                headDone.add(hi)
            }
            val chm = rec(ch)
            val hv = chm?.get("head")
            if (chm == null || hv == null) return fail("malformed proof", -1) // `ch.head.domain` throws in the reference
            val headM = rec(hv)
            if (headM == null || headM["domain"] != domain) return fail("source-domain anchor: head is for a different domain", i)
            val e = headErrs[hi] ?: ""
            if (e != "") return fail("source-domain anchor: $e", i)

            val incl = validInclusion(ev["inclusion"])
            if (incl == null || natV(incl["size"]) != natV(headM["size"])) return fail("hop not included in the issuing domain log", i)
            val root = headM["root"] as? String ?: ""
            val capDigest = try { Pca.capHash(cap) } catch (x: RuntimeException) { return fail("hop not included in the issuing domain log", i) }
            if (!Pca.verifyInclusion(root, incl, capDigest)) return fail("hop not included in the issuing domain log", i)

            if (i > 0) {
                val b = rec(ev["binding"])
                val role = str(b?.get("role"))
                val bsig = str(b?.get("sig"))
                if (b == null || role == null || bsig == null || b["agent"] != cap["issuer"] || b["domain"] != ev["domain"]) return fail("missing or mismatched domain binding for issuer", i)
                val m = msg(BINDING_DOMAIN, linkedMapOf<String, Any?>("agent" to b["agent"], "domain" to b["domain"], "role" to role))
                if (m == null || !Pca.verifyB64u(domain, m, bsig)) return fail("domain binding signature invalid", i)
            }

            val rev = rec(ev["revocation"]) ?: emptyMap()
            val revRoot = headM["rev_root"] as? String ?: ""
            val id = cap["id"] as? String ?: ""
            val nmCap = expandNm(rev["cap"], revLeaves)
            if (nmCap == null || !nonMembership(revRoot, nmCap, id)) return fail("capability revoked (or revocation proof invalid)", i)
            val nmKey = expandNm(rev["issuer_key"], revLeaves)
            if (nmKey == null || !nonMembership(revRoot, nmKey, "key:$issuer")) return fail("issuer key revoked (or revocation proof invalid)", i)

            val eff = Authority()
            val why = effective(cap["caveats"], eff)
            if (why != "") return fail(why, i)
            if (havePrev && !narrows(eff, prev)) return fail("hop widens authority", i)
            prev = eff
            havePrev = true
        }

        val actTs = f(action["at"])
        if (actTs > t.now + t.maxSkew) return fail("action timestamp is in the future", -1)
        if (t.hasActionAge && t.now - actTs > t.maxActionAge) return fail("action is stale", -1)
        val tip = rec(chain[chain.size - 1]) ?: emptyMap()
        val tipHash = try { Pca.capHash(tip) } catch (e: RuntimeException) { null }
        val holder = tip["holder"] as? String ?: ""
        val am = msg(ACTION_DOMAIN, linkedMapOf<String, Any?>("action" to action, "tip" to tipHash))
        if (tipHash == null || am == null || !Pca.verifyB64u(holder, am, actionSig)) return fail("action not signed by the chain tip holder", -1)
        val denied = admits(prev, action, t.now, chain.size)
        if (denied != "") return fail("action not admitted: $denied", -1)
        return Verdict(true, "", -1)
    }
}
