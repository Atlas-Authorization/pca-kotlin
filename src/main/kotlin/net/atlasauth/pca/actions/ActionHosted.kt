package net.atlasauth.pca.actions

import java.util.IdentityHashMap
import java.util.TreeSet
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.ActionsRegistry
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The hosted action registry of one instance: the publish gate (what a new version of a namespace may change without a reviewer) and the verifier's view of the
 * active versions (provenance facts, trait floors for rule 22, undo eligibility, the server reversibility class, compiled business rules). Pure: storage, keys
 * and time are the caller's. Fail closed everywhere: an action the view does not know, one that is not confirmed by a reviewer key the instance pins, or a
 * deprecated one gets the top of the trait registry (every floor) and no provenance facts, is irreversible, and is never undoable. Everything is a JSON tree.
 */
@Suppress("UNCHECKED_CAST")
object ActionHosted {
    const val RULES_DOC_KIND: String = "pca-action-rules"
    const val HOSTED_VERSION_DOMAIN: String = "atlas-pca/hosted-action-version/v1"
    private val PLAIN_SEMVER = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
    private val EFFECTIVE_DIMS = listOf("confirmation", "effective.traits", "effective.profile")
    private val CAVEAT_KINDS = listOf("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap")
    private val SERVER_CLASS = mapOf("reversible" to "reversible", "rate_limited" to "costly", "irreversible" to "irreversible")

    private fun plainObject(x: Any?): Boolean = x is Map<*, *>

    private fun truthy(v: Any?): Boolean {
        if (v == null || v == false || v == "") return false
        val d = J.num(v)
        return d == null || !(d == 0.0 || d.isNaN())
    }

    private fun fail(code: String, reason: String?, verbs: List<String>?): MutableMap<String, Any?> {
        val m = J.obj("ok", false, "code", code, "reason", reason)
        if (verbs != null) m["verbs"] = J.objs(verbs)
        return m
    }

    /** The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies. */
    fun registryOfTraits(traits: List<*>): Map<String, Map<String, Any?>> = if (traits.isEmpty()) Actions.CORE_REGISTRY else Actions.extendRegistry(Actions.CORE_REGISTRY, ArrayList<Any?>(traits))

    /** The attestation check the instance pins give (null without pins: nothing is confirmed). */
    fun reviewOptsOf(pins: Any?, reg: Map<String, Map<String, Any?>>): ((Map<String, Any?>) -> Boolean)? = if (pins == null) null else ActionUndoEngine.attestationVerifier(pins, reg)

    /** Null iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors. */
    fun rulesDocError(x: Any?, ns: String, defs: List<*>): String? {
        if (!plainObject(x)) return "rules must be a pca-action-rules document"
        val r = J.m(x)
        for (k in r.keys) if (!listOf("v", "kind", "ns", "rules", "reviews").contains(k)) return "rules: unknown member '$k'"
        val v = J.num(r["v"])
        if (v == null || v != 1.0 || RULES_DOC_KIND != r["kind"]) return "rules: not a $RULES_DOC_KIND v1 document"
        if (ns != r["ns"]) return "rules: ns '" + (if (r.containsKey("ns")) J.jsStr(r["ns"]) else "undefined") + "' is not the pack's '" + ns + "'"
        if (!plainObject(r["rules"])) return "rules.rules must map verbs to rules blocks"
        if (r.containsKey("reviews") && !plainObject(r["reviews"])) return "rules.reviews must map verbs to rules reviews"
        val byVerb = LinkedHashMap<String, Map<String, Any?>>()
        for (d in defs) byVerb[J.get(d, "verb") as String] = J.m(d)
        for ((k, rv) in J.m(r["rules"])) {
            val d = byVerb[k] ?: return "rules: '$k' is not an action of the pack"
            val errs = ArrayList<String>()
            for (f in ActionBusinessRules.lintBusinessRules(d, rv)) if ("error" == J.get(f, "severity")) errs.add(J.get(f, "message") as String)
            if (errs.isNotEmpty()) return "rules for '$k': " + errs.joinToString("; ")
        }
        if (r.containsKey("reviews")) for (verb in J.m(r["reviews"]).keys) if (!byVerb.containsKey(verb)) return "rules.reviews: '$verb' is not an action of the pack"
        return null
    }

    /** The content address of a version: the digest of `{pack, rules, traits, deprecated}`. */
    fun hostedVersionDigest(v: Map<String, Any?>): String {
        val dep = ArrayList<String>()
        for (x in J.a(v["deprecated"])) dep.add(x as String)
        dep.sort()
        return Pca.hashCanonical(J.obj("d", HOSTED_VERSION_DOMAIN, "pack", v["pack"], "rules", v["rules"], "traits", v["traits"], "deprecated", J.objs(dep)))
    }

    private fun safeConfirmed(d: Map<String, Any?>, review: ((Map<String, Any?>) -> Boolean)?): Boolean = try { ActionEffective.isConfirmed(d, review) } catch (e: RuntimeException) { false }

    /** diffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions). */
    private fun diffDefsAcross(o: Map<String, Any?>, n: Map<String, Any?>, oReg: Map<String, Map<String, Any?>>, nReg: Map<String, Map<String, Any?>>, oRev: ((Map<String, Any?>) -> Boolean)?, nRev: ((Map<String, Any?>) -> Boolean)?): Map<String, Any?> {
        val base = ActionDiff.diffDefs(o, n, nReg, nRev)
        if (oReg === nReg) return base
        val eo = J.m(ActionEffective.effective(o, oReg, oRev)["eff"])
        val en = J.m(ActionEffective.effective(n, nReg, nRev)["eff"])
        val rel: String? = if (ActionEffective.leq(eo, en)) (if (ActionEffective.leq(en, eo)) null else "narrow") else if (ActionEffective.leq(en, eo)) "widen" else "incomparable"
        if (rel == null) return base
        val reasons = ArrayList<String>()
        for (r in J.a(base["reasons"])) if (!(r as String).startsWith("effective.profile")) reasons.add(r)
        reasons.add("effective.profile: $rel")
        reasons.sort()
        val bc = base["class"]
        val inc = rel == "incomparable" || "incomparable" == bc || (rel == "widen" && "narrow" == bc) || (rel == "narrow" && "widen" == bc)
        val cls = if (inc) "incomparable" else if (rel == "widen" || "widen" == bc) "widen" else "narrow"
        return J.obj("class", cls, "reasons", J.objs(reasons))
    }

    private fun byVerbKey(a: Any?, b: Any?): Int = (J.get(a, "verb") as String).compareTo(J.get(b, "verb") as String)

    /**
     * Decide whether a version may become the active one of its namespace, and compute what it changes. `i`: `{current?, pack, rules?, traits?,
     * publisherKeys, pins?, pin?}`. Returns `{ok:true, version}` or `{ok:false, code, reason, verbs?, changes?}` where code is one of
     * bad_pack, bad_rules, bad_traits, bad_version, ns_mismatch, not_newer, widen_unreviewed.
     */
    fun publishGate(i: Map<String, Any?>): Map<String, Any?> {
        var traits: MutableList<Any?> = ArrayList()
        if (i.containsKey("traits")) {
            if (i["traits"] !is List<*>) return fail("bad_traits", "traits must be a list of trait definitions", null)
            traits = J.a(i["traits"])
        }
        val reg = try { registryOfTraits(traits) } catch (e: RuntimeException) { return fail("bad_traits", e.message, null) }
        val pv = ActionBuild.verifyPack(i["pack"], i["publisherKeys"], reg)
        if (pv["ok"] != true) return fail("bad_pack", pv["reason"] as String?, null)
        val pack = J.m(i["pack"])
        val packVersion = pack["version"] as String
        val packNs = pack["ns"] as String
        if (!PLAIN_SEMVER.matches(packVersion)) return fail("bad_version", "version '$packVersion' must be MAJOR.MINOR.PATCH", null)
        val cur: Map<String, Any?>? = if (i["current"] is Map<*, *>) J.m(i["current"]) else null
        if (cur != null && packNs != cur["ns"]) return fail("ns_mismatch", "the active namespace is '${cur["ns"]}', the pack is '$packNs'", null)
        if (cur != null && !truthy(i["pin"]) && ActionsRegistry.compareVersions(packVersion, cur["version"] as String) <= 0) return fail("not_newer", "version $packVersion is not above the active ${cur["version"]}", null)
        val rulesIn: Any? = if (i.containsKey("rules")) i["rules"] else J.obj("v", J.n(1), "kind", RULES_DOC_KIND, "ns", packNs, "rules", LinkedHashMap<String, Any?>())
        val packDefs = J.a(pack["defs"])
        val re = rulesDocError(rulesIn, packNs, packDefs)
        if (re != null) return fail("bad_rules", re, null)
        val rules = J.m(rulesIn)
        val ruleBlocks = J.m(rules["rules"])

        val review = reviewOptsOf(i["pins"], reg)
        var prevReg = reg
        if (cur != null) { prevReg = try { registryOfTraits(J.a(cur["traits"])) } catch (e: RuntimeException) { reg } }
        val prevReview = reviewOptsOf(i["pins"], prevReg)
        val changes = ArrayList<Any?>()
        val blocked = ArrayList<String>()
        val reasons = ArrayList<String>()
        val oldDefs = LinkedHashMap<String, Map<String, Any?>>()
        if (cur != null) for (d in J.a(J.get(cur["pack"], "defs"))) oldDefs[J.get(d, "verb") as String] = J.m(d)
        val oldDep = HashSet<Any?>(if (cur != null) J.a(cur["deprecated"]) else emptyList<Any?>())
        val newVerbs = HashSet<Any?>()
        for (d in packDefs) newVerbs.add(J.get(d, "verb"))
        for (n0 in packDefs) {
            val n = J.m(n0)
            val verb = n["verb"] as String
            val o = oldDefs[verb]
            val hasNewRules = ruleBlocks.containsKey(verb)
            val newRules = ruleBlocks[verb]
            val confirmed = safeConfirmed(n, review)
            val change: MutableMap<String, Any?>
            if (o == null || oldDep.contains(verb)) {
                change = J.obj("verb", verb, "class", "added", "reasons", ArrayList<Any?>())
                if (confirmed) change["reviewed"] = true
            } else {
                val d = diffDefsAcross(o, n, prevReg, reg, prevReview, review)
                change = J.obj("verb", verb, "class", d["class"], "reasons", d["reasons"])
                var effWidens = false
                for (r in J.a(d["reasons"])) for (dim in EFFECTIVE_DIMS) if ((r as String).startsWith("$dim: widen") || r.startsWith("$dim: incomparable")) effWidens = true
                if (effWidens) {
                    if (confirmed) change["reviewed"] = true
                    else { blocked.add(verb); reasons.add("$verb: its effective authority widens without a valid confirmation of the new definition") }
                }
            }
            val oldRules = if (o != null && !oldDep.contains(verb)) J.get(J.get(cur!!["rules"], "rules"), verb) else null
            if (oldRules != null || hasNewRules) {
                var rd: Map<String, Any?>
                try {
                    rd = ActionBusinessRules.diffBusinessRules(n, if (oldRules == null) null else J.m(oldRules), if (newRules == null) null else J.m(newRules))
                } catch (e: RuntimeException) {
                    rd = J.obj("class", "incomparable", "reasons", J.list("rules: " + e.message))
                }
                // rules apply to confirmed and unconfirmed actions alike, so any widening of them needs a reviewer, whatever the state of the definition
                if ("equal" != rd["class"]) change["rules"] = rd
                if ("widen" == rd["class"] || "incomparable" == rd["class"]) {
                    // removing every rule is reviewed as the empty block
                    val err = ActionBusinessRules.rulesReviewError(J.get(rules["reviews"], verb), n, if (newRules == null) LinkedHashMap() else J.m(newRules), i["pins"])
                    if (err == null) change["reviewed"] = true
                    else {
                        blocked.add(verb)
                        val rr = ArrayList<String>()
                        for (x in J.a(rd["reasons"])) rr.add(x as String)
                        reasons.add("$verb: its business rules widen (" + rr.joinToString(", ") + ") without a valid rules review: " + err)
                    }
                }
            }
            if ("equal" != change["class"] || change.containsKey("rules")) changes.add(change)
        }
        val deprecated = TreeSet<String>()
        for (v in oldDep) if (!newVerbs.contains(v)) deprecated.add(v as String)
        for (v in oldDefs.keys) {
            if (newVerbs.contains(v) || oldDep.contains(v)) continue
            deprecated.add(v)
            changes.add(J.obj("verb", v, "class", "deprecated", "reasons", J.list("removed from the namespace: treated as unknown")))
        }
        changes.sortWith { a, b -> byVerbKey(a, b) }
        if (blocked.isNotEmpty()) {
            val out = fail("widen_unreviewed", reasons.joinToString("\n"), ArrayList(TreeSet(blocked)))
            out["changes"] = changes
            return out
        }
        val depList = J.objs(ArrayList(deprecated))
        val body = J.obj("pack", pack, "rules", rules, "traits", traits, "deprecated", depList)
        val version = J.obj("ns", packNs, "version", packVersion, "digest", hostedVersionDigest(body), "prev", if (cur != null && cur["digest"] != null) cur["digest"] else null)
        version.putAll(body)
        version["changes"] = changes
        return J.obj("ok", true, "version", version)
    }

    // ---- the verifier's view --------------------------------------------------------------------------------------------------

    /** A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear). */
    private fun brokenRules(verb: String): Map<String, Any?> = J.obj(
        "v", J.n(1), "verb", verb, "rules_digest", "", "def_digest", "",
        "tighten", J.list(J.obj("id", "rules_broken", "when", J.obj("field", "action.verb", "op", "eq", "value", verb), "signal", "deny", "reason", "the business rules of this action no longer compile")),
        "accumulators", ArrayList<Any?>(),
    )

    private class Entry(val def: Map<String, Any?>, val reg: Map<String, Map<String, Any?>>, val review: ((Map<String, Any?>) -> Boolean)?, val rules: Map<String, Any?>?)

    /** The verifier's view of the active versions of an instance. */
    class View internal constructor(vs: List<*>, pins: Any?) {
        @JvmField val versions: MutableList<String> = ArrayList()
        private val byVerb = LinkedHashMap<String, Entry>()
        private val deprecated = HashSet<String>()
        private val broken = LinkedHashSet<String>()
        private val prov = HashMap<String, Map<String, Any?>>()
        private val cache = HashMap<String, Map<String, Any?>>()
        private val undoByReg = IdentityHashMap<Any, ActionUndoEngine>()
        private val top: Map<String, Any?>
        private val topTraitIds: List<Any?>

        init {
            val regs = ArrayList<Map<String, Map<String, Any?>>>()
            for (v in vs) {
                versions.add("${J.get(v, "ns")}@${J.get(v, "version")}")
                val reg = try {
                    registryOfTraits(J.a(J.get(v, "traits")))
                } catch (e: RuntimeException) {
                    val defs = J.get(J.get(v, "pack"), "defs")
                    if (defs is List<*>) for (d in defs) if (J.get(d, "verb") is String) broken.add(J.get(d, "verb") as String)
                    continue
                }
                regs.add(reg)
                val review = reviewOptsOf(pins, reg)
                val blocks = J.get(J.get(v, "rules"), "rules")
                for (d in J.a(J.get(J.get(v, "pack"), "defs"))) {
                    val verb = J.get(d, "verb") as String
                    if (byVerb.containsKey(verb)) continue
                    val rb = if (blocks is Map<*, *>) J.m(blocks)[verb] else null
                    byVerb[verb] = Entry(J.m(d), reg, review, if (rb is Map<*, *>) J.m(rb) else null)
                }
                for (x in J.a(J.get(v, "deprecated"))) deprecated.add(x as String)
            }
            for (x in deprecated) byVerb.remove(x)
            for (x in broken) byVerb.remove(x)
            // the strictest profile any active registry has (an unknown verb could be anything)
            var t: Map<String, Any?>? = null
            val used: List<Map<String, Map<String, Any?>>> = if (regs.isEmpty()) listOf(Actions.CORE_REGISTRY) else regs
            for (r in used) {
                val p = Actions.floorOf(r, Actions.topTraits(r))
                t = if (t == null) p else if (ActionEffective.leq(t, p)) p else if (ActionEffective.leq(p, t)) t else ActionEffective.join(t, p)
            }
            top = t!!
            val ids = TreeSet<String>()
            for (r in used) ids.addAll(Actions.topTraits(r))
            topTraitIds = ArrayList<Any?>(ids)
            for ((k, e) in byVerb) {
                try { if (safeConfirmed(e.def, e.review)) prov[k] = ActionProvenance.provenanceInfoOf(e.def, e.reg, e.review) } catch (ex: RuntimeException) { /* unknown: sensitive */ }
            }
            val groups = IdentityHashMap<Any, MutableList<Any?>>()
            val order = ArrayList<Map<String, Map<String, Any?>>>()
            for (e in byVerb.values) {
                if (!groups.containsKey(e.reg)) { groups[e.reg] = ArrayList(); order.add(e.reg) }
                groups[e.reg]!!.add(e.def)
            }
            for (r in order) undoByReg[r] = ActionUndoEngine.undoEngine(groups[r]!!, pins, r)
        }

        /** What the view knows of a verb: `{verb, confirmed, known, deprecated, def_digest?, idempotency_param?, profile, traits, serverClass, rules?}`. */
        fun lookup(verb: String): Map<String, Any?> {
            val hit = cache[verb]
            if (hit != null) return hit
            val e = byVerb[verb]
            val out = J.obj("verb", verb, "confirmed", false, "known", e != null, "deprecated", deprecated.contains(verb), "profile", top, "traits", topTraitIds, "serverClass", "irreversible")
            if (e == null && broken.contains(verb) && !deprecated.contains(verb)) { out["known"] = true; out["rules"] = brokenRules(verb) }
            if (e != null) {
                try {
                    val eff = ActionEffective.effective(e.def, e.reg, e.review)
                    val confirmed = eff["confirmed"] == true
                    val idem = e.def["idempotency"]
                    val idemParam = if (idem != null && "key_param" == J.get(idem, "mode")) J.get(idem, "param") else null
                    val digest = Actions.defDigest(e.def)
                    val serverClass = if (confirmed) SERVER_CLASS[J.get(eff["eff"], "rev") as String?] else null
                    out["def_digest"] = digest
                    if (idemParam != null) out["idempotency_param"] = idemParam
                    out["confirmed"] = confirmed
                    if (confirmed) { out["profile"] = eff["eff"]; out["traits"] = eff["traits"]; out["serverClass"] = serverClass }
                    // rules apply whether or not the action is confirmed: they only tighten
                    if (e.rules != null) out["rules"] = ActionBusinessRules.compileBusinessRules(e.def, e.rules)
                } catch (ex: RuntimeException) {
                    // a def or rules block that no longer compiles: unknown-strict, and its rules cannot be dropped silently
                    out["confirmed"] = false
                    out["profile"] = top
                    out["traits"] = topTraitIds
                    out["serverClass"] = "irreversible"
                    out["rules"] = brokenRules(verb)
                }
            }
            cache[verb] = out
            return out
        }

        /** The provenance facts of a confirmed, non-deprecated exact verb; null otherwise (sensitive). */
        fun provenance(verb: String): Map<String, Any?>? = prov[verb]

        /** Undo eligibility from confirmed definitions (exact verb; a deprecated action never): the plan or null. */
        fun undoPlan(op: Map<String, Any?>): Map<String, Any?>? {
            val e = byVerb[op["verb"] as String]
            return if (e == null) null else undoByReg[e.reg]!!.plan(op)
        }

        /** Rule 22: the floor decision for this action under what the grant provides (`{caveats, max_esc, preauth_esc}`) and the call context the server observed. */
        fun floor(verb: String, grant: Map<String, Any?>, callContext: List<*>): String {
            try {
                val kinds = ArrayList<Any?>()
                for (c in J.a(grant["caveats"])) if (CAVEAT_KINDS.contains(c)) kinds.add(c)
                val maxEsc = grant["max_esc"]
                val pre = grant["preauth_esc"]
                if (!nonNeg(maxEsc) || !nonNeg(pre)) return "deny"
                val rho = J.m(lookup(verb)["profile"])
                val esc = J.num(rho["esc"])!!
                if (esc > J.num(maxEsc)!!) return "deny"
                if (!kinds.containsAll(J.a(rho["caveats"])) || !callContext.containsAll(J.a(rho["context"])) || esc > J.num(pre)!!) return "escalate"
                return "allow"
            } catch (e: RuntimeException) {
                return "deny"
            }
        }

        private fun nonNeg(v: Any?): Boolean = J.isInt(v) && J.num(v)!! >= 0
    }

    /** Build the verifier's view from the active versions of an instance (`pins` may be null). */
    fun hostedView(versions: List<*>, pins: Any?): View = View(versions, pins)

    /** Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers. */
    fun grantFactsOf(grant: Any?): Map<String, Any?> {
        val env = Authorize.readEnvelope(grant)
        val a = env?.get("actions")
        val caveats = ArrayList<Any?>()
        val ec = env?.get("caveats")
        if (ec is List<*>) for (c in ec) { val t = J.get(c, "type"); if (t is String) caveats.add(t) }
        val ac = J.get(a, "caveats")
        if (ac is List<*>) for (t in ac) if (t is String) caveats.add(t)
        return J.obj("caveats", caveats, "max_esc", J.n(tier(J.get(a, "max_esc"), 3)), "preauth_esc", J.n(tier(J.get(a, "preauth_esc"), 0)))
    }

    private fun tier(v: Any?, d: Long): Long = if (J.isInt(v) && J.num(v)!! >= 0 && J.num(v)!! <= 3) J.num(v)!!.toLong() else d

    /** The context keys the hosted server itself establishes for a call: it always checks revocation fresh; an idempotency key present. */
    fun hostedCallContext(lookup: Map<String, Any?>?, params: Map<String, Any?>?): List<Any?> {
        val out = J.list("fresh_revocation")
        val k = lookup?.get("idempotency_param")
        if (k is String && params != null && params[k] is String && (params[k] as String).isNotEmpty()) out.add("idempotency")
        return out
    }

    private fun msNum(v: Double): Json.Num = Json.Num(AttestUtil.jsNumString(v))

    /**
     * The event keys of a rules block's rate limits: `[{id, ms, key?}]`. A key names the verb, the window and the scope id (never a rule index or the
     * rules digest), so editing or reordering the rules never resets a count. `who`: `{principal?, org?}`.
     */
    fun rateKeysOf(c: Map<String, Any?>, who: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (a in J.a(c["accumulators"])) {
            val scope = if ("org" == J.get(a, "scope")) "org" else "principal"
            val id = who[if (scope == "org") "org" else "principal"]
            val win = J.get(a, "win")
            val ms: Double = if ("task" == J.get(win, "kind")) 0.0 else J.num(J.get(win, "ms"))!!
            val r = J.obj("id", J.get(a, "id"), "ms", msNum(ms))
            if (id is String && id.isNotEmpty() && ms > 0) r["key"] = "${c["verb"]}|${J.jsStr(msNum(ms))}|$scope:$id"
            out.add(r)
        }
        return out
    }
}
