package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Blueprint
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Lease
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test
import net.atlasauth.pca.verifier.FreshAt as FreshAtVerify
import net.atlasauth.pca.verifier.GrantResource as GrantVerify

/** Replays the reference oracle for the grants operational plane (signing, log, replay, shadow, list-authorized, grant service, leases, blueprints). */
@Suppress("UNCHECKED_CAST")
class GrantsDiffTest {
    private val module = "ref-grants"
    private val t0 = net.atlasauth.pca.verifier.BaseOracle.T0

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun n(o: Any?): Long = o.toString().toLong()
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for ((k, v) in kv) r[k] = v; return r }
    private fun strs(o: Any?): List<String> = l(o).map { it as String }
    private fun copy(o: Map<String, Any?>) = LinkedHashMap(o)

    private fun err(e: Throwable): Any? = obj("\$err" to when (e) {
        is GrantResource.GrantError -> e.code
        is ListAuthorized.ListError -> e.code
        else -> "x"
    })

    private val keys = HashMap<String, Keys.EdKey>()
    private fun key(label: String): Keys.EdKey = keys.getOrPut(label) { Keys.edFromSeed(OracleCases.seed(label)) }
    private fun pub(label: String) = key(label).id()

    /** Replace "$key:LABEL" strings and {"$sign": ...} objects, recursively. */
    private fun resolve(v: Any?): Any? {
        if (v is String) return if (v.startsWith("\$key:")) pub(v.substring(5)) else v
        if (v is List<*>) return v.map { resolve(it) }
        if (v is Map<*, *>) {
            val mm = v as Map<String, Any?>
            if (mm.containsKey("\$sign")) {
                val s = m(mm["\$sign"])
                val k = key(s["label"] as String)
                val f = m(resolve(s["fields"]))
                return when (s["kind"] as String) {
                    "lease" -> GrantSigning.signLease(k, f)
                    "leaseOver" -> GrantSigning.signLeaseUnsafeOverCap(k, f)
                    "revocation" -> GrantSigning.signLeaseRevocation(k, f)
                    "blueprint" -> GrantSigning.signBlueprint(k, f)
                    "breakglass" -> GrantSigning.signBreakGlass(k, f)
                    "review" -> GrantSigning.signBreakGlassReview(k, f)
                    else -> throw IllegalArgumentException("bad kind")
                }
            }
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in mm) out[k] = resolve(x)
            return out
        }
        return v
    }

    // ---- pure signing ----
    @Test fun signerOf() = OracleCases.each(module, "signerOf") { a -> pub(a[0] as String) }
    @Test fun signBody() = OracleCases.each(module, "signBody") { a -> GrantSigning.signBody(a[0] as String, a[1], key(a[2] as String)) }
    @Test fun verifyBody() = OracleCases.each(module, "verifyBody") { a -> GrantSigning.verifyBody(a[0] as String, a[1], a[2] as String, a[3]) }
    @Test fun signLease() = OracleCases.each(module, "signLease") { a -> GrantSigning.signLease(key(a[0] as String), m(a[1])) }
    @Test fun signLeaseUnsafeOverCap() = OracleCases.each(module, "signLeaseUnsafeOverCap") { a -> GrantSigning.signLeaseUnsafeOverCap(key(a[0] as String), m(a[1])) }
    @Test fun signLeaseRevocation() = OracleCases.each(module, "signLeaseRevocation") { a -> GrantSigning.signLeaseRevocation(key(a[0] as String), m(a[1])) }
    @Test fun signBlueprint() = OracleCases.each(module, "signBlueprint") { a -> GrantSigning.signBlueprint(key(a[0] as String), m(a[1])) }
    @Test fun signBreakGlass() = OracleCases.each(module, "signBreakGlass") { a -> GrantSigning.signBreakGlass(key(a[0] as String), m(a[1])) }
    @Test fun signBreakGlassReview() = OracleCases.each(module, "signBreakGlassReview") { a -> GrantSigning.signBreakGlassReview(key(a[0] as String), m(a[1])) }

    // ---- bundles ----
    @Test fun signBundle() = OracleCases.each(module, "signBundle") { a -> Bundle.signBundle(m(a[0]), key(a[1] as String)) }
    @Test fun assembleBundle() = OracleCases.each(module, "assembleBundle") { a -> Bundle.assembleBundle(m(a[0]), l(a[1])) }
    @Test fun maskRecord() = OracleCases.each(module, "maskRecord") { a -> Bundle.maskRecord(m(a[0]), strs(a[1])) }

    @Test fun logScenario() = OracleCases.each(module, "logScenario") { a ->
        val spec = m(a[0])
        val k = key(spec["label"] as String)
        val mask = if (spec["mask"] != null) strs(spec["mask"]) else emptyList()
        val log = Bundle.DecisionLog(k, mask)
        val recs = ArrayList<Any?>()
        for (r in l(spec["records"])) recs.add(log.append(m(r)))
        val signer = k.id()
        val now = n(spec["now"])
        val head = log.head(now)
        val out = obj("recs" to recs, "head" to head, "size" to log.size().toLong())
        val proofs = ArrayList<Any?>()
        val incl = ArrayList<Any?>()
        val batches = ArrayList<Any?>()
        val pi = if (spec["proofs"] == null) ArrayList<Any?>() else l(spec["proofs"])
        for (i in pi) {
            try { proofs.add(log.proof(n(i).toInt())) } catch (e: RuntimeException) { proofs.add(obj("\$err" to true)) }
        }
        for (j in pi.indices) {
            val p = proofs[j]
            incl.add(if (m(p).containsKey("\$err")) obj("\$err" to true) else net.atlasauth.pca.verifier.Bundle.verifyRecordInclusion(recs[n(pi[j]).toInt()], p, head, signer))
        }
        val bs = if (spec["batches"] == null) ArrayList<Any?>() else l(spec["batches"])
        for (bo in bs) {
            val b = m(bo)
            try {
                val bt = Bundle.nextBatch(log, b["from"], b["max"], spec["now"])
                val from = n(b["from"])
                val last = if (from == 0L) "" else net.atlasauth.pca.verifier.Bundle.recordCommit(recs[from.toInt() - 1])
                var tampered = bt
                val brecs = l(bt["records"])
                if (brecs.isNotEmpty()) {
                    val first = copy(m(brecs[0]))
                    first["at"] = 1L
                    val tr = ArrayList<Any?>(brecs)
                    tr[0] = first
                    tampered = copy(bt)
                    (tampered as LinkedHashMap<String, Any?>)["records"] = tr
                }
                val bv = net.atlasauth.pca.verifier.Bundle
                batches.add(obj(
                    "bt" to bt, "verdict" to bv.verifyBatch(bt, from, last, signer).toJson(), "tampered" to bv.verifyBatch(tampered, from, last, signer).toJson(),
                    "wrong" to bv.verifyBatch(bt, from, last, pub("zz")).toJson(),
                ))
            } catch (e: RuntimeException) {
                batches.add(obj("\$err" to true))
            }
        }
        out["proofs"] = proofs
        out["incl"] = incl
        out["batches"] = batches
        out
    }

    private fun table(t: Any?): (Any?) -> String? = { i -> m(t)[i as String] as String? }

    @Test fun replayScenario() = OracleCases.each(module, "replayScenario") { a ->
        val spec = m(a[0])
        obj(
            "diff" to Bundle.semanticDiff(l(spec["cases"]), table(spec["oldT"]), table(spec["newT"])),
            "audit" to Bundle.auditReplay(l(spec["records"]), l(spec["cases"])) { i, rev -> m(spec["revT"])["$i@$rev"] as String? },
        )
    }

    // ---- fresh_at ----
    @Test fun mergeFreshAt() = OracleCases.each(module, "mergeFreshAt") { a -> FreshAt.mergeFreshAt(m(a[0]), m(a[1])) }

    @Test fun gateDecision() = OracleCases.each(module, "gateDecision") { a ->
        val v = m(a[1])
        FreshAt.gateDecision(a[0] as String, FreshAtVerify.Verdict(v["decision"] as String, v["code"] as String?, emptyList()))
    }

    @Test fun freshScenario() = OracleCases.each(module, "freshScenario") { a ->
        val spec = m(a[0])
        val iss = FreshAt.Issuer(key(spec["label"] as String), spec["scope"] as String, m(spec["init"]))
        val out = ArrayList<Any?>()
        var last: Map<String, Any?>? = null
        for (so in l(spec["steps"])) {
            val s = m(so)
            try {
                when (s["op"] as String) {
                    "advance" -> { last = iss.advance(m(s["patch"]), n(s["now"])); out.add(last) }
                    "check" -> {
                        val tok = if ("last" == s["token"]) last else s["token"]
                        val max = if (s["maxAge"] == null) null else s["maxAge"].toString().toDouble().toLong()
                        out.add(iss.check(tok, n(s["now"]), max).toJson())
                    }
                    "current" -> out.add(iss.current())
                    "tamper" -> {
                        val t = copy(last!!)
                        t["policy_revision"] = n(last["policy_revision"]) + 1
                        out.add(iss.check(t, n(s["now"]), null).toJson())
                    }
                }
            } catch (e: RuntimeException) {
                out.add(obj("\$err" to true))
            }
        }
        out
    }

    // ---- shadow ----
    private fun shadowFn(t: Any?): (Any?) -> String? = { i ->
        val d = m(t)[i as String]
        if ("throw" == d) throw IllegalStateException("boom")
        if ("junk" == d) "weird" else d as String?
    }

    @Test fun shadowScenario() = OracleCases.each(module, "shadowScenario") { a ->
        val spec = m(a[0])
        val log = Shadow.ShadowLog(key(spec["label"] as String))
        val runs = ArrayList<Any?>()
        val diffsOut = LinkedHashMap<String, Any?>()
        val out = obj("runs" to runs, "diffs" to diffsOut)
        for (oo in l(spec["obs"])) {
            val ob = m(oo)
            val cands = l(spec["cands"]).map { Shadow.Candidate(m(it)["digest"] as String, shadowFn(m(it)["T"])) }
            val run = Shadow.runShadow(ob["input"], shadowFn(spec["enforcedT"]), cands)
            runs.add(obj("decision" to run.decision, "shadow" to run.shadow.map { it.toMap() }))
            for (oc in run.shadow) log.observe(spec["enforcedDigest"] as String, ob["action_digest"] as String, run.decision, oc, n(ob["at"]))
        }
        val stats = LinkedHashMap<String, Any?>()
        val flat = ArrayList<Any?>()
        for (co in l(spec["cands"])) {
            val d = m(co)["digest"] as String
            stats[d] = log.stats(d).toMap()
            val ds = ArrayList<Any?>(log.diffs(d))
            diffsOut[d] = ds
            flat.addAll(ds)
        }
        out["stats"] = stats
        val verify = ArrayList<Any?>()
        for (d in flat) {
            val dm = m(d)
            val badSig = copy(dm)
            badSig["sig"] = (dm["sig"] as String).substring(1) + "A"
            val badAt = copy(dm)
            badAt["at"] = n(dm["at"]) + 1
            verify.add(arrayListOf<Any?>(
                Shadow.verifyShadowDiff(d, log.signer()), Shadow.verifyShadowDiff(d, null), Shadow.verifyShadowDiff(d, pub("zz")),
                Shadow.verifyShadowDiff(badSig, log.signer()), Shadow.verifyShadowDiff(badAt, null),
            ))
        }
        out["verify"] = verify
        out["signer"] = log.signer()
        val g = if (spec["gate"] == null) null else m(spec["gate"])
        if (g != null) {
            val principals = ArrayList<Any?>()
            if (g["principals"] != null) for (p in l(g["principals"])) principals.add(pub(p as String))
            val explanations = ArrayList<Any?>()
            if (g["explain"] != null) for (eo in l(g["explain"])) {
                val e = m(eo)
                explanations.add(Shadow.signWideningExplanation(key(e["label"] as String), obj("shadow_digest" to e["shadow_digest"], "action_digest" to e["action_digest"], "reason_digest" to e["reason_digest"])))
            }
            var approval: Map<String, Any?>? = null
            if (g["approval"] != null) {
                val ap = m(g["approval"])
                approval = Shadow.signPromotionApproval(key(ap["label"] as String), obj("shadow_digest" to ap["shadow_digest"], "enforced_digest" to ap["enforced_digest"], "at" to ap["at"]))
            }
            out["explanations"] = explanations
            out["approval"] = approval
            val opts = if (g["options"] == null) LinkedHashMap<String, Any?>() else copy(m(g["options"]))
            if (opts["principals"] == null) opts["principals"] = principals
            if (opts["explanations"] == null) opts["explanations"] = explanations
            if (approval != null) opts["approval"] = approval
            val gate = Shadow.promotionGate(log, opts)
            out["gate"] = gate
            if (spec["promote"] != null) {
                val pr = m(spec["promote"])
                try {
                    val usedGate = if (pr["useGate"] == false) obj("ok" to false, "code" to "bad_input", "reason" to "x") else gate
                    out["promoted"] = Shadow.promoteShadow(m(pr["enforced"]), m(pr["candidate"]), usedGate, pr["now"])
                } catch (e: RuntimeException) {
                    out["promoted"] = obj("\$err" to true)
                }
            }
        }
        out
    }

    // ---- list-authorized ----
    @Test fun windowAcc() = OracleCases.each(module, "windowAcc") { a ->
        val acc = ListAuthorized.WindowReadAccumulator(n(a[0]), n(a[1]))
        l(a[2]).map { o -> acc.charge(m(o)["key"] as String, n(m(o)["units"]), n(m(o)["now"])) }
    }

    private fun pageOf(list: List<String>, cursor: String?, limit: Int, spec: Map<String, Any?>): ListAuthorized.CandidatePage {
        val idx = if (cursor == null) 0 else cursor.toInt()
        val end = minOf(idx + limit + (if (spec["overfetch"] == true) 3 else 0), list.size)
        val objects = if (idx >= list.size) ArrayList<String>() else ArrayList(list.subList(idx, end))
        val next = if (idx + limit < list.size) (idx + limit).toString() else if (spec["emptyNext"] == true) "" else null
        return ListAuthorized.CandidatePage(objects, next)
    }

    @Test fun listScenario() = OracleCases.each(module, "listScenario") { a ->
        val spec = m(a[0])
        val acc = ListAuthorized.WindowReadAccumulator(n(spec["cap"]), n(spec["windowMs"]))
        val universe = strs(spec["universe"])
        val relSpec = if (spec["relation"] == null) null else m(spec["relation"])
        val allowed = HashSet<String>()
        if (relSpec != null) allowed.addAll(strs(relSpec["allowed"]))
        val useList = relSpec != null && relSpec["useList"] == true
        val rel = object : ListAuthorized.RelationSource {
            override fun check(subject: String, relation: String, obj: String): Boolean = allowed.contains(obj)
            override fun supportsListObjects(): Boolean = useList
            override fun listObjects(subject: String, relation: String, type: String, cursor: String?, limit: Int) =
                pageOf(if (relSpec!!["listed"] != null) strs(relSpec["listed"]) else universe, cursor, limit, spec)
        }
        val permitted = if (spec["permitted"] == null) null else HashSet(strs(spec["permitted"]))
        val tamper = if (spec["tamper"] == null) null else m(spec["tamper"])
        val out = ArrayList<Any?>()
        var cursor: String? = null
        var p = 0L
        while (p < n(spec["pages"])) {
            val t = if (tamper != null && p == n(tamper["page"])) tamper else null
            try {
                val candidates = if (relSpec != null && relSpec["asCandidates"] == true) ListAuthorized.candidatesFromRelation(rel, spec["subject"] as String, relSpec["name"] as String)
                else ListAuthorized.CandidateSource { _, cur, limit -> pageOf(universe, cur, limit, spec) }
                val useCursor = !(t != null && t["dropCursor"] == true) && cursor != null
                val args = ListAuthorized.Args(
                    subject = if (t != null && t["subject"] != null) t["subject"] as String else spec["subject"] as String,
                    resourceType = spec["type"] as String,
                    permits = { x -> permitted == null || permitted.contains(x) },
                    candidates = candidates,
                    filterId = if (t != null && t["filterId"] != null) t["filterId"] as String else spec["filterId"] as String,
                    policyDigest = spec["policyDigest"] as String,
                    freshAtDigest = spec["freshAt"] as String,
                    limit = if (t != null && t["limit"] != null) n(t["limit"]) else n(spec["limit"]),
                    reads = acc,
                    now = t0 + p * (if (spec["nowStep"] == null) 1L else n(spec["nowStep"])),
                    signingSecret = key(if (t != null && t["label"] != null) t["label"] as String else spec["label"] as String),
                    relationSource = if (relSpec != null) rel else null,
                    relation = if (relSpec != null) (if (t != null && t["relation"] != null) t["relation"] as String else relSpec["name"] as String) else null,
                    cursor = if (useCursor) (if (t != null && t.containsKey("cursor")) t["cursor"] as String? else cursor) else null,
                    maxScan = if (spec["maxScan"] != null) n(spec["maxScan"]) else null,
                )
                val r = ListAuthorized.listAuthorized(args)
                out.add(r.toMap())
                cursor = r.nextCursor
            } catch (e: Exception) {
                out.add(err(e))
                if (t == null) break
            }
            p++
        }
        out
    }

    // ---- grant management ----
    private fun sec(by: String) = if (by == "principal") "\$P" else if (by == "holder") "\$A" else "\$X"

    @Test fun grantScenario() = OracleCases.each(module, "grantScenario") { a ->
        val spec = m(a[0])
        val store = GrantResource.MemoryGrantStore()
        val events = ArrayList<Any?>()
        var gc = 0L
        var nc = 0L
        val providers = spec["providers"] == true
        val usageFn: (Map<String, Any?>) -> Any? = { g -> obj("rev" to g["rev"]) }
        val budgetFn: (Map<String, Any?>) -> Any? = { _ -> obj("left" to 5L) }
        val residualFn: (Map<String, Any?>) -> Any? = { g -> obj("id" to g["id"]) }
        val needFn: (Map<String, Any?>) -> String? = { nd -> if ("forbidden" == nd["verb"]) "verb not allowed" else null }
        val o = GrantResource.Options(
            store = store,
            now = { t0 },
            newId = { k -> if (k == "grant") "g_" + (++gc) else "n_" + (++nc) },
            usage = if (providers) usageFn else null,
            remainingBudget = if (providers) budgetFn else null,
            residual = if (providers) residualFn else null,
            verifyStepUp = if (spec["stepUp"] == true) GrantResource.StepUp { ref, _ -> ref == "ok-step" } else null,
            onRevoke = GrantResource.OnRevoke { ids, scope, root -> events.add(obj("revoked" to ArrayList<Any?>(ids), "scope" to scope, "root" to root["id"])) },
            onChange = GrantResource.OnChange { kind, g -> events.add(obj("change" to kind, "id" to g["id"], "rev" to g["rev"])) },
            validateNeed = if (spec["validateNeed"] == true) needFn else null,
        )
        val svc = GrantResource.GrantService(o)
        var caller: GrantHttp.Caller? = null
        val handler = GrantHttp.grantResourceHandler(svc) { caller }
        val out = ArrayList<Any?>()
        for (raw in l(spec["steps"])) {
            val s = m(resolve(raw))
            try {
                val r: Any? = when (s["op"] as String) {
                    "register" -> svc.register(m(s["grant"]))
                    "list" -> {
                        val fm = if (s["filter"] == null) LinkedHashMap<String, Any?>() else m(s["filter"])
                        svc.list(GrantResource.ListFilter(fm["principal"] as String?, fm["agent"] as String?, fm["status"] as String?, if (fm["limit"] == null) null else n(fm["limit"]), fm["cursor"] as String?))
                    }
                    "inspect" -> svc.inspect(s["id"] as String)
                    "amend" -> {
                        val g = svc.inspect(s["id"] as String)
                        val req = obj("action" to s["action"], "authority" to s["authority"])
                        if ("none" != s["by"]) {
                            val by = s["by"] as String
                            req["signed_by"] = if (s["signed_by"] != null) s["signed_by"] else if (by == "holder") "holder" else "principal"
                            req["sig"] = GrantSigning.signBody(GrantResource.GRANT_AMEND_DOMAIN, GrantVerify.amendMessage(g, s["action"] as String, m(s["authority"])), key(sec(by)))
                        }
                        if (s["stepUp"] != null) req["step_up_ref"] = s["stepUp"]
                        svc.amend(s["id"] as String, req)
                    }
                    "revoke" -> {
                        val g = svc.inspect(s["id"] as String)
                        val by = s["by"] as String
                        val scope = s["scope"] as String
                        if (by == "admin") svc.revoke(s["id"] as String, scope, null, true)
                        else if (by == "noauth") svc.revoke(s["id"] as String, scope, null, false)
                        else svc.revoke(s["id"] as String, scope, GrantSigning.signBody(GrantResource.GRANT_REVOKE_DOMAIN, GrantVerify.grantRevokeMessage(g["id"] as String, scope), key(sec(by))), false)
                    }
                    "needs" -> svc.requestNeeds(s["id"] as String, s["needs"])
                    "approve" -> {
                        val needId = s["needId"] as String
                        val nid = svc.needGrantId(needId)
                        val g = svc.inspect(nid)
                        val sig = GrantSigning.signBody(GrantResource.NEED_APPROVE_DOMAIN, GrantVerify.needApproveMessage(obj("id" to needId, "grant_id" to nid), g["rev"], s["approved"]), key(sec(s["by"] as String)))
                        svc.approveNeeds(needId, s["approved"], sig, s["stepUp"] as String?)
                    }
                    "deny" -> { svc.denyNeeds(s["needId"] as String); null }
                    "http" -> {
                        val w = if (s["who"] == null) null else m(s["who"])
                        caller = if (w == null) null else GrantHttp.Caller(w["principal"] as String?, w["admin"] == true)
                        val q = LinkedHashMap<String, String>()
                        if (s["query"] != null) for ((k, v) in m(s["query"])) q[k] = v as String
                        val res = handler.handle(GrantHttp.Request(s["method"] as String, s["path"] as String, q, s["body"]))
                        obj("status" to res.status.toLong(), "body" to res.body)
                    }
                    else -> throw IllegalStateException("bad op")
                }
                out.add(r)
            } catch (e: RuntimeException) {
                out.add(err(e))
            }
        }
        val grants = ArrayList<Any?>(store.list())
        grants.sortBy { m(it)["id"] as String }
        obj("steps" to out, "events" to events, "grants" to grants)
    }

    // ---- leases ----
    private fun acceptMap(r: Lease.Accept): Map<String, Any?> {
        val mm = obj("ok" to (r.code == null))
        if (r.code == null) { mm["replaced"] = r.replaced; mm["seq"] = r.seq } else { mm["code"] = r.code; if (r.reason != null) mm["reason"] = r.reason }
        return mm
    }

    private fun decisionMap(d: Lease.Decision): Map<String, Any?> {
        val mm = obj("decision" to d.decision)
        if (d.code != null) mm["code"] = d.code
        if (d.leaseId != null) mm["lease_id"] = d.leaseId
        if (d.expiresAt != null) mm["expires_at"] = d.expiresAt
        return mm
    }

    @Test fun leaseScenario() = OracleCases.each(module, "leaseScenario") { a ->
        val spec = m(a[0])
        val pm = if (spec["policy"] != null) m(spec["policy"]) else null
        val policy = Lease.Policy(
            listOf(pub("auth")),
            minApprovals = if (pm?.get("minApprovals") != null) n(pm["minApprovals"]) else 1L,
            eligibleApprovers = if (pm?.get("eligibleApprovers") != null) strs(pm["eligibleApprovers"]) else null,
            maxTtlCeiling = if (pm?.get("maxTtlCeiling") != null) n(pm["maxTtlCeiling"]) else null,
        )
        val reg = Lease.Registry(policy, MemoryAtomicKv(), if (spec["shards"] == null) 4 else n(spec["shards"]).toInt()) { t0 }
        var lw: LeaseHttp.Caller? = null
        val handler = LeaseHttp.leaseResourceHandler(reg, { lw }, { t0 })
        val out = ArrayList<Any?>()
        for (raw in l(spec["steps"])) {
            val s = m(resolve(raw))
            try {
                val r: Any? = when (s["op"] as String) {
                    "accept" -> acceptMap(reg.accept(s["lease"], // a chain entry that is not a string never equals an approver
if (s["chain"] == null) ArrayList<String>() else l(s["chain"]).filterIsInstance<String>()))
                    "revoke" -> {
                        val rv = reg.revoke(s["rev"])
                        val mm = obj("ok" to (rv.code == null))
                        if (rv.code == null) mm["revoked"] = rv.revoked.toLong() else mm["code"] = rv.code
                        mm
                    }
                    "get" -> reg.get(s["id"] as String)
                    "history" -> reg.history(s["id"] as String).map { h -> obj("seq" to h.seq, "renewed_at" to h.renewedAt, "expires_at" to h.expiresAt, "justification_digest" to h.justificationDigest) }
                    "shardRevs" -> reg.shardRevocations(n(s["i"]).toInt())
                    "renew" -> {
                        val ro = Leases.RenewOptions()
                        ro.now = s["now"]
                        ro.increment = s["increment"]
                        ro.justificationDigest = s["just"] as String?
                        if (s["approvers"] != null) ro.approvers = l(s["approvers"])
                        if (s["vetoSeq"] != null) { val vs = n(s["vetoSeq"]); ro.veto = { c -> n(c["seq"]) >= vs } }
                        if (s["chain"] != null) ro.chain = strs(s["chain"])
                        val rr = Leases.renewLease(key(if (s["label"] == null) "auth" else s["label"] as String), reg, s["id"] as String, ro)
                        if (rr["ok"] == true) rr else obj("ok" to false, "code" to rr["code"])
                    }
                    "check" -> decisionMap(Lease.checkLease(s["lease"], reg, s["now"]))
                    "http" -> {
                        val w = if (s["who"] == null) null else m(s["who"])
                        lw = if (w == null) null else LeaseHttp.Caller(w["admin"] == true, w["principal"] as String?)
                        val res = handler.handle(GrantHttp.Request(s["method"] as String, s["path"] as String, null, s["body"]))
                        val body = res.body
                        obj("status" to res.status.toLong(), "body" to body)
                    }
                    else -> throw IllegalStateException("bad op")
                }
                out.add(r)
            } catch (e: RuntimeException) {
                out.add(err(e))
            }
        }
        out
    }

    // ---- blueprints ----
    @Test fun blueprintScenario() = OracleCases.each(module, "blueprintScenario") { a ->
        val spec = m(a[0])
        val reg = Blueprint.Registry(listOf(pub("op")), MemoryAtomicKv())
        val adm = Blueprints.AdmissionRegistry()
        val revoked = ArrayList<Any?>()
        val init = obj("revocation_epoch" to 0L, "ledger_tree_size" to 0L, "budget_version" to 0L, "policy_revision" to 0L, "policy_digest" to "pd")
        val fresh = FreshAt.Issuer(key("iss"), "scope", init)
        val out = ArrayList<Any?>()
        for (raw in l(spec["steps"])) {
            val s = m(resolve(raw))
            try {
                val r: Any? = when (s["op"] as String) {
                    "accept" -> {
                        val ac = reg.accept(s["bp"])
                        val mm = obj("ok" to (ac.code == null))
                        if (ac.code == null) mm["replaced"] = ac.replaced else mm["code"] = ac.code
                        mm
                    }
                    "epoch" -> reg.epoch()
                    "kill" -> {
                        val rv = if (s["revoker"] == true) Blueprints.IssuerRevoker { value, reason, at -> revoked.add(obj("kind" to "issuer", "value" to value, "reason" to reason, "revokedAt" to at)) } else null
                        Blueprints.groupKill(key(if (s["label"] == null) "op" else s["label"] as String), reg, s["key"] as String, n(s["now"]), s["reason"] as String?, rv, if (s["fresh"] == true) fresh else null)
                    }
                    "revoked" -> revoked
                    "admit" -> { adm.admit(s["instance"] as String, GrantSigning.blueprintGet(reg, s["key"] as String)!!, n(s["until"])); true }
                    "admitRevoke" -> adm.revoke(s["instance"] as String, s["key"] as String)
                    "admitCheck" -> adm.checker(n(s["now"]))(s["instance"] as String, GrantSigning.blueprintGet(reg, s["key"] as String)!!)
                    else -> throw IllegalStateException("bad op")
                }
                out.add(r)
            } catch (e: Exception) {
                out.add(err(e))
            }
        }
        out
    }

    @Test fun admitWithEvidence() = OracleCases.each(module, "admitWithEvidence") { a ->
        val e = a[1]
        Blueprints.admitWithEvidence(m(a[0])) {
            if (e is Map<*, *> && e.containsKey("\$throw")) throw ClassCastException("boom") // the oracle throws a TypeError
            e
        }
    }
}
