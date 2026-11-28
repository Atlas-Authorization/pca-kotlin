package net.atlasauth.pca.analyzer

import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates
import java.security.MessageDigest

/**
 * LEAST PRIVILEGE FROM OBSERVED BEHAVIOUR. `suggestNarrowing(policy, observed)` proposes a narrower replacement for a grant from what
 * its holder really did, plus the unused-permission findings ranked by blast radius and reversibility. It is a REVIEW artefact, never
 * applied: it only narrows (the proposal is "the original predicate AND extra conditions", then PROVEN subsumed by the original; if the proof
 * is not exact the proposal is withheld), only ledger-sourced observations count, a denied attempt never loosens a grant (it becomes an
 * access request for a human), and an optional decay appends an `expires` caveat.
 */
object Narrowing {
    const val ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\u0000"

    private fun revWeight(r: String): Int = Analyzer.REVERSIBILITY_ORDER.indexOf(r) + 1

    private fun commonPrefix(rs: List<String?>): String {
        var p = if (rs.isEmpty()) "" else rs[0]!!
        for (r in rs) {
            var i = 0
            while (i < p.length && i < r!!.length && p[i] == r[i]) i++
            p = p.substring(0, i)
        }
        val cut = p.lastIndexOf('/')
        return if (cut >= 0) p.substring(0, cut + 1) else ""
    }

    private fun upperBoundOf(where: Any?, path: String): Double {
        var ub = Double.POSITIVE_INFINITY
        if (where is List<*>) {
            for (c in where) {
                val op = AJs.get(c, "op")
                if (c is Map<*, *> && AJs.has(c, "field") && path == AJs.get(c, "field") && (op == "lte" || op == "lt") && AJs.isNum(AJs.get(c, "value"))) {
                    ub = Math.min(ub, AJs.num(AJs.get(c, "value"))!!)
                }
            }
        }
        return ub
    }

    private fun ctxOf(a: Any?): Map<String, Any?> {
        val p = AJs.get(a, "params")
        return AJs.obj("action", AJs.obj("verb", AJs.get(a, "verb"), "resource", AJs.get(a, "resource"), "params", p ?: AJs.obj()))
    }

    private fun matches(p: Any?, a: Any?): Boolean = Predicates.predicateMatches(p, ctxOf(a))

    private fun resolveAction(catalog: Catalog, verb: String): Catalog.Spec {
        val s = catalog.get(verb)
        if (s != null) return s
        // an unknown verb is treated as irreversible with maximum blast radius
        val parts = verb.split(".")
        val action = if (parts.size > 1) parts.subList(1, parts.size).joinToString(".") else verb
        return Catalog.Spec(parts[0], action, verb, "irreversible", 1.0, null, "(uncatalogued) $verb")
    }

    private fun paramOf(a: Any?, name: String): Any? {
        val p = AJs.get(a, "params")
        return if (p is Map<*, *>) p[name] else null
    }

    private fun hasParam(a: Any?, name: String): Boolean {
        val p = AJs.get(a, "params")
        return p is Map<*, *> && p.containsKey(name)
    }

    private val STR_ORDER = Comparator<String?> { a, b -> a!!.compareTo(b!!) }

    private fun build(base: List<Any?>, trusted: List<Any?>, narrowResources: Boolean, margin: Double, minSamples: Double, enumLimit: Double): List<Any?> {
        val out = ArrayList<Any?>()
        for (p in base) {
            val hits = trusted.filter { matches(p, it) }
            if (hits.isEmpty()) continue
            val vs = LinkedHashSet<String?>()
            val rs = LinkedHashSet<String?>()
            for (h in hits) { vs.add(AJs.get(h, "verb") as String?); rs.add(AJs.get(h, "resource") as String?) }
            val verbs = ArrayList(vs).also { it.sortWith(STR_ORDER) }
            val resources = ArrayList(rs).also { it.sortWith(STR_ORDER) }
            val next = AJs.obj("verb", if (verbs.size == 1) verbs[0] else ArrayList<Any?>(verbs))
            if (narrowResources) {
                if (resources.size == 1) next["resource"] = resources[0]
                else {
                    val pre = commonPrefix(resources)
                    if (pre.length > 1) next["resource"] = "$pre*"
                    else if (AJs.has(p, "resource")) next["resource"] = AJs.get(p, "resource")
                }
            } else if (AJs.has(p, "resource")) next["resource"] = AJs.get(p, "resource")
            val where = ArrayList<Any?>()
            val pw = AJs.get(p, "where")
            if (pw is List<*>) where.addAll(pw)
            val nameSet = LinkedHashSet<String>()
            for (h in hits) { val hp = AJs.get(h, "params"); if (hp is Map<*, *>) for (k in hp.keys) nameSet.add(k as String) }
            val names = ArrayList(nameSet).also { it.sort() }
            for (name in names) {
                val path = "action.params.$name"
                val vals = hits.map { paramOf(it, name) }
                val anyUndef = hits.any { !hasParam(it, name) }
                if (vals.size < minSamples || anyUndef) continue
                val allNum = vals.all { AJs.isFin(it) }
                val allStr = vals.all { it is String }
                if (allNum) {
                    var mx = Double.NEGATIVE_INFINITY
                    var allInt = true
                    for (v in vals) { val d = AJs.num(v)!!; mx = Math.max(mx, d); if (d != Math.rint(d)) allInt = false }
                    val v2 = mx * (1 + margin)
                    val ceil = if (allInt) Math.ceil(v2) else v2
                    if (ceil < upperBoundOf(pw, path)) where.add(AJs.obj("field", path, "op", "lte", "value", AJs.n(ceil)))
                } else if (allStr) {
                    val sorted = ArrayList(LinkedHashSet(vals.map { it as String })).also { it.sort() }
                    if (sorted.size <= enumLimit) where.add(AJs.obj("field", path, "op", "in", "value", ArrayList<Any?>(sorted)))
                }
            }
            if (where.isNotEmpty()) next["where"] = where
            out.add(next)
        }
        return out
    }

    private fun rankOrder(a: Any?, b: Any?): Int {
        val d = AJs.num(AJs.get(b, "rank"))!! - AJs.num(AJs.get(a, "rank"))!!
        if (d != 0.0 && !d.isNaN()) return if (d < 0) -1 else 1
        return java.lang.Double.compare(AJs.num(AJs.get(a, "predicate"))!!, AJs.num(AJs.get(b, "predicate"))!!)
    }

    private fun finding(kind: String, i: Int, verb: Any?, detail: String, s: Catalog.Spec): MutableMap<String, Any?> {
        val fd = AJs.obj("kind", kind, "predicate", AJs.n(i))
        if (verb != null) fd["verb"] = verb
        fd["detail"] = detail
        fd["blastRadius"] = AJs.n(s.blastRadius)
        fd["reversibility"] = s.reversibility
        fd["rank"] = AJs.n(s.blastRadius * revWeight(s.reversibility))
        return fd
    }

    /**
     * Propose a narrower grant from what the holder did, and list what was never used. Never applies anything. `observed` items are
     * {verb, resource, params?, source: "ledger" | "agent", outcome?: "allowed" | "denied", entry?}. Options: margin (default 0.1), minSamples (5),
     * enumLimit (8), taskBinding, decay {nowSec, expiresInSecs}. [catalog] null = the built-in connector catalog.
     */
    fun suggestNarrowing(policy: Any?, observed: List<Any?>, o: Map<String, Any?>?, catalog: Catalog? = null): Map<String, Any?> {
        val margin = if (AJs.get(o, "margin") == null) 0.1 else AJs.toNum(AJs.get(o, "margin"))
        val minSamples = if (AJs.get(o, "minSamples") == null) 5.0 else AJs.toNum(AJs.get(o, "minSamples"))
        val enumLimit = if (AJs.get(o, "enumLimit") == null) 8.0 else AJs.toNum(AJs.get(o, "enumLimit"))
        val cat = catalog ?: Catalog.DEFAULT
        val model = Enumerate.toModel(policy)
        val digest = Residual.policyDigestOf(model)

        val trusted = ArrayList<Any?>()
        val refused = ArrayList<Any?>()
        var rejected = 0
        for (x in observed) {
            val ledger = "ledger" == AJs.get(AJs.req(x), "source")
            if (!ledger) rejected++
            val denied = "denied" == AJs.get(x, "outcome")
            if (ledger && !denied) trusted.add(x)
            if (ledger && denied) refused.add(x)
        }
        val findings = ArrayList<Any?>()
        val bp = AJs.get(policy, "predicates")
        val base: List<Any?> = if (bp is List<*>) AJs.list(bp) else ArrayList()

        for (i in base.indices) {
            val p = base[i]
            val hit = trusted.any { matches(p, it) }
            val pv = AJs.get(p, "verb")
            val verbs: List<Any?> = if (pv is String) AJs.arr(pv) else if (pv is List<*>) AJs.list(pv) else ArrayList()
            if (!hit) {
                val v: Any = if (verbs.isEmpty() || verbs[0] == null) "*" else verbs[0]!!
                val s = resolveAction(cat, if (v == "*") "unknown.any" else v as String)
                val joined = verbs.joinToString(", ") { it.toString() }
                findings.add(AJs.obj("kind", "unused-predicate", "predicate", AJs.n(i), "verb", v, "detail", "no observed action used predicate " + i + " (" + (if (joined.isEmpty()) "*" else joined) + ")",
                    "blastRadius", AJs.n(s.blastRadius), "reversibility", s.reversibility, "rank", AJs.n(s.blastRadius * revWeight(s.reversibility))))
                continue
            }
            for (v in verbs) {
                if ("*" == v) continue
                val used = trusted.any { AJs.strictEq(AJs.get(it, "verb"), v) && matches(p, it) }
                if (!used) {
                    val s = resolveAction(cat, v as String)
                    findings.add(finding("unused-verb", i, v, "verb $v is granted by predicate $i but never used", s))
                }
            }
            val pw = AJs.get(p, "where")
            if (pw is List<*>) for (c in pw) {
                val f = AJs.get(c, "field")
                val op = AJs.get(c, "op")
                if (c is Map<*, *> && f is String && (op == "lte" || op == "lt") && AJs.isNum(AJs.get(c, "value")) && f.startsWith("action.params.")) {
                    val name = f.substring("action.params.".length)
                    val vals = ArrayList<Double>()
                    for (a in trusted) if (matches(p, a)) { val pv2 = paramOf(a, name); if (AJs.isNum(pv2)) vals.add(AJs.num(pv2)!!) }
                    var mx = Double.NEGATIVE_INFINITY
                    for (d in vals) mx = Math.max(mx, d)
                    val cv = AJs.num(AJs.get(c, "value"))!!
                    if (vals.size >= minSamples && mx < cv / 2) {
                        val v0 = if (verbs.isEmpty()) null else verbs[0]
                        val s = resolveAction(cat, if (v0 != null) v0 as String else "unknown.any")
                        findings.add(finding("unreached-cap", i, if (AJs.truthy(v0)) v0 else null, name + " <= " + AJs.fmt(cv) + " but the largest observed value is " + AJs.fmt(mx), s))
                    }
                }
            }
        }
        // rank descending, then predicate ascending (stable)
        findings.sortWith(Comparator { a, b -> rankOrder(a, b) })

        val groups = LinkedHashMap<String, MutableMap<String, Any?>>()
        for (a in refused) {
            val k = AJs.get(a, "verb").toString() + "\u0000" + AJs.get(a, "resource").toString()
            val g = groups[k]
            if (g != null) g["denied_count"] = AJs.n(AJs.num(g["denied_count"])!! + 1)
            else {
                val r = AJs.obj("v", AJs.n(1), "kind", "pca-access-request", "verb", AJs.get(a, "verb"), "resource", AJs.get(a, "resource"),
                    "example_params", AJs.copy(AJs.get(a, "params")), "denied_count", AJs.n(1), "policy_digest", digest)
                if (AJs.truthy(AJs.get(o, "taskBinding"))) r["task_binding"] = AJs.get(o, "taskBinding")
                groups[k] = r
            }
        }
        val reqs = ArrayList(groups.values)
        reqs.sortWith(Comparator { a, b ->
            val d = AJs.num(b["denied_count"])!! - AJs.num(a["denied_count"])!!
            if (d != 0.0 && !d.isNaN()) (if (d < 0) -1 else 1) else if ((a["verb"] as String) < (b["verb"] as String)) -1 else 1
        })

        val res = AJs.obj("used", AJs.n(trusted.size), "rejected", AJs.n(rejected), "denied", AJs.n(refused.size), "coversObserved", false,
            "findings", findings, "accessRequests", ArrayList<Any?>(reqs))
        if (AJs.truthy(AJs.get(o, "taskBinding"))) res["taskBinding"] = AJs.get(o, "taskBinding")

        val caveats = ArrayList<Any?>(model.caveats)
        val decay = AJs.get(o, "decay")
        if (AJs.truthy(decay)) caveats.add(AJs.obj("type", "expires", "at", AJs.n(AJs.numOrNaN(decay, "nowSec") + AJs.numOrNaN(decay, "expiresInSecs"))))
        for (narrowResources in booleanArrayOf(true, false)) {
            val proposal = AJs.obj("predicates", build(base, trusted, narrowResources, margin, minSamples, enumLimit), "caveats", caveats, "vetoes", model.vetoes, "tighten", model.tighten)
            if (AJs.list(proposal["predicates"]).isEmpty()) {
                res["reason"] = "no ledger observation matches any predicate"
                return res
            }
            val proof = Analyzer.subsumes(policy, proposal)
            if (proof["subsumes"] != true || proof["approximate"] == true) {
                res["reason"] = if (proof.containsKey("reason")) proof["reason"] else "the proposal could not be proven narrower than the original"
                continue
            }
            res.remove("reason")
            res["proposal"] = proposal
            var covers = true
            for (a in trusted) {
                val act = AJs.obj("verb", AJs.get(a, "verb"), "resource", AJs.get(a, "resource"), "params", AJs.copy(AJs.get(a, "params")))
                if (!Analyzer.admitsConcrete(proposal, act)) { covers = false; break }
            }
            res["coversObserved"] = covers
            res["diff"] = Exposure.diffPolicies(policy, proposal, null)
            return res
        }
        return res
    }

    // ---- access requests ----

    private fun requestMessage(r: Any?): ByteArray {
        val pre = ACCESS_REQUEST_SIG_DOMAIN.toByteArray(Charsets.UTF_8)
        val d = MessageDigest.getInstance("SHA-256").digest(Pca.hashCanonical(r).toByteArray(Charsets.UTF_8))
        return pre + d
    }

    /** The agent's (or its holder's) signed ask: {request, signer, sig}. A request for a human to read; nothing here turns it into authority. */
    fun signAccessRequest(r: Map<String, Any?>, secret: Keys.EdKey, signerPublic: String): Map<String, Any?> =
        AJs.obj("request", r, "signer", signerPublic, "sig", Keys.b64u(secret.sign(requestMessage(r))))

    /** Is the signed request well formed and signed by the signer ([expectedSigner] null = any)? Never throws. */
    fun verifyAccessRequest(s: Any?, expectedSigner: String?): Boolean = try {
        val req = AJs.get(s, "request")
        val v = AJs.get(req, "v")
        if (s !is Map<*, *> || req !is Map<*, *> || "pca-access-request" != AJs.get(req, "kind")) false
        else if (!AJs.isNum(v) || AJs.num(v) != 1.0) false
        else if (expectedSigner != null && expectedSigner != AJs.get(s, "signer")) false
        else {
            val sig = AJs.get(s, "sig")
            val signer = AJs.get(s, "signer")
            sig is String && signer is String && Pca.verifyB64u(signer, requestMessage(req), sig)
        }
    } catch (e: RuntimeException) {
        false
    }
}
