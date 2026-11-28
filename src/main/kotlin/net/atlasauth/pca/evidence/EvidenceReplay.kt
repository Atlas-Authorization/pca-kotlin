package net.atlasauth.pca.evidence

import net.atlasauth.pca.intent.IntentJit
import net.atlasauth.pca.intent.IntentMapKit
import net.atlasauth.pca.intent.IntentStatement
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.IntentAcc
import net.atlasauth.pca.verifier.IntentClassifier
import net.atlasauth.pca.verifier.IntentHistory
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.IntentRevocation
import net.atlasauth.pca.verifier.IntentSession
import net.atlasauth.pca.verifier.IntentV2
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Ledger
import net.atlasauth.pca.verifier.OracleFacts
import net.atlasauth.pca.verifier.ParamProvenance
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore
import net.atlasauth.pca.wallet.Wallet
import net.atlasauth.pca.webauthn.Webauthn

/**
 * `verifyEvidenceBundle`: deterministic replay of a dispute evidence bundle. Every finding is recomputed from the signed artifacts;
 * the output is a findings report whose text comes from fixed templates, so two readers of the same bundle with the same trust inputs
 * get byte-identical reports (`report_digest`). Statuses: `pass`, `fail`, `unverified` (never reported as a pass). A
 * `trust.verifiers.<name>` port overrides the core default for the artifacts that have one.
 */
@Suppress("UNCHECKED_CAST")
object EvidenceReplay {
    /** A verifier for one artifact: `{ok: true}` or `{ok: false, reason}`. For artifacts with a core verifier it overrides the default. */
    fun interface Port {
        fun verify(artifact: Any?, bundle: Map<String, Any?>): Map<String, Any?>?
    }

    private fun interface Core {
        fun get(): Map<String, Any?>?
    }

    private val TEMPLATES: Map<String, String> = linkedMapOf(
        "shape" to "The bundle is well formed (pca-intent-evidence v1, closed members)",
        "principal.pinned" to "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
        "trust.principals" to "The pinned principal keys (trust.principals) are well formed",
        "statement.commit" to "The session root commits to the intent statement the bundle names",
        "statement.opening" to "The opened statement is signed by a principal and hashes to the committed ref",
        "session_root.signature" to "The session root is signed by one of its principal keys",
        "schema.signature" to "The action schema is signed by a site key",
        "schema.digest" to "The session root binds this action schema",
        "schema.anchor" to "The action schema is anchored in a transparency log",
        "map.replay" to "The task map replays to its committed digest",
        "root_grant" to "The root intent grant G_0 is principal-signed and bound to the session",
        "delta.signature" to "The delta grant is a root capability signed by a principal of the session",
        "delta.chain" to "The delta grant chains to the session (session, seq, prev, root)",
        "delta.backed" to "Every delta grant is backed by a principal \"yes\" answer",
        "answer.signature" to "The answer is signed by a principal of the session, for this session",
        "answer.map" to "The answer refers to a map version in the bundle",
        "answer.tier" to "The answer meets the site minimum friction tier for the verb",
        "answer.typed" to "The typed-tier value re-derives the signed typed digest",
        "answer.device" to "The device-tier WebAuthn assertion verifies with user verification",
        "canaries.summary" to "The canary summary equals the one recomputed from the signed canary answers",
        "pcactn.verify" to "The PCActn verifies (signature, chain, audience, validity at its issue time)",
        "pcactn.root" to "The PCActn's root capability is G_0 or a bundled delta grant",
        "pcactn.session" to "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        "subject.present" to "The subject PCActn is in the bundle",
        "jit.consent" to "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
        "accumulator.declared" to "The accumulator is declared in the session root",
        "accumulator.arithmetic" to "The accumulator posts are the running values of the counted events",
        "accumulator.cap" to "Every accumulator post is within the admitting grant's cap",
        "accumulator.receipts" to "The sequencer reservation receipt verifies and is consistent",
        "acc.keysets.equivocation" to "No two different sequencer key sets share one root and version",
        "acc.keysets" to "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        "trust.acc" to "The verifier freshness configuration (trust.acc) is well formed",
        "effect.binding" to "The effect record is bound to the PCActn's signed params",
        "effect.charged" to "The charged amount is within the confirmed value",
        "effect.frame" to "No monitored state outside the write set changed",
        "effect.signature" to "The effect record is signed by the site",
        "verdict.signature" to "The site verdict record verifies",
        "fact.signature" to "The oracle fact verifies under a pinned oracle key",
        "classifier.signature" to "The classifier verdict verifies under a pinned judge key",
        "offer_set.signature" to "The offer set is signed by a site key, for this session",
        "labels.signature" to "The label receipt is signed by a pinned site key, for this session",
        "settlement.signature" to "The settlement record verifies",
        "revocation.history" to "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
        "revocation.epoch" to "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
        "anchor.inclusion" to "The anchored artifact is included under a guardian-signed head of the intent log",
    )

    private val STATUS_TEXT = mapOf("pass" to "verified", "fail" to "REFUTED", "unverified" to "not verified here")

    private val NOT_PROVEN = listOf(
        "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
        "That the site's signed schema describes what its endpoints really do (SCH).",
        "That the site's effect records and any oracle facts are true (EFF, ORC).",
        "Acceptance of this bundle by any card network, court or regulator.",
    )

    // ---- small JSON helpers ----

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun mn(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun l(o: Any?): List<Any?> = if (o is List<*>) o as List<Any?> else ArrayList()
    private fun get(o: Any?, k: Any?): Any? = if (o is Map<*, *>) o[k] else null
    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    private fun num(o: Any?): Double? = IntentJs.num(o)
    private fun isNum(o: Any?): Boolean { val d = num(o); return d != null && !d.isNaN() && !d.isInfinite() }
    private fun numEq(a: Any?, b: Any?): Boolean { val x = num(a); val y = num(b); return x != null && y != null && x == y }
    private fun lng(o: Any?): Long = num(o)!!.toLong()
    private fun str(o: Any?, v: Any?): Boolean = o == v
    private fun n(v: Long): Json.Num = Js.n(v)
    private fun js(d: Double): String = Js.template(if (d == 0.0) 0.0 else d)
    private fun cmp(a: String, b: String): Int = Integer.signum(a.compareTo(b))
    private fun id(o: Any?): String = Js.template(o)
    private fun <V> Map<String, V>.at(k: Any?): V? = if (k is String) this[k] else null

    private fun vd(ok: Boolean, reason: String?): Map<String, Any?> {
        val v = LinkedHashMap<String, Any?>()
        v["ok"] = ok
        if (!ok) v["reason"] = reason
        return v
    }

    private fun nul(e: String?): Map<String, Any?> = vd(e == null, e)
    private fun ok(v: Map<String, Any?>): Boolean = v["ok"] == true

    // ---- findings ----

    private class Findings {
        val list = ArrayList<Map<String, Any?>>()

        fun add(code: String, status: String, refs: List<String> = emptyList(), detail: String? = null) {
            val text = TEMPLATES[code] + ": " + STATUS_TEXT[status] + (if (!detail.isNullOrEmpty()) " ($detail)" else "") + "."
            val f = LinkedHashMap<String, Any?>()
            f["code"] = code
            f["status"] = status
            f["text"] = text
            f["refs"] = ArrayList<Any?>(refs)
            list.add(f)
        }

        fun addB(code: String, pass: Boolean, refs: List<String>) = add(code, if (pass) "pass" else "fail", refs, null)

        fun verdict(code: String, v: Map<String, Any?>, refs: List<String>) {
            if (ok(v)) add(code, "pass", refs, null) else add(code, "fail", refs, v["reason"] as String?)
        }

        /** Run [port] if supplied, else the core default; with neither (or a null core verdict) the artifact stays unverified. */
        fun check(code: String, port: Port?, core: Core?, artifact: Any?, bundle: Map<String, Any?>, refs: List<String>, what: String) {
            var v: Map<String, Any?>?
            try {
                v = if (port != null) port.verify(artifact, bundle) else core?.get()
            } catch (e: Exception) {
                v = vd(false, "verifier threw: " + e.message)
            }
            if (v == null) add(code, "unverified", refs, "no verifier for $what") else verdict(code, v, refs)
        }
    }

    private fun one(x: Any?): List<Any?> = arrayListOf(x)
    private fun refs(vararg r: String): List<String> = ArrayList(r.asList())

    private fun pass(f: Findings, code: String): Boolean {
        var any = false
        for (x in f.list) {
            if (code != x["code"]) continue
            if ("fail" == x["status"]) return false
            if ("pass" == x["status"]) any = true
        }
        return any
    }

    // ---- entry ----

    internal fun emptySummary(): MutableMap<String, Any?> {
        val s = LinkedHashMap<String, Any?>()
        s["admitted_under"] = null
        s["principal_keys"] = ArrayList<Any?>()
        val a = LinkedHashMap<String, Any?>()
        for (k in listOf("total", "yes", "no", "partial", "canaries")) a[k] = n(0)
        s["answers"] = a
        s["refusals"] = ArrayList<Any?>()
        s["consent"] = null
        s["charged"] = null
        val ca = LinkedHashMap<String, Any?>()
        ca["correct"] = n(0)
        ca["asked"] = n(0)
        s["canary_accuracy"] = ca
        val at = LinkedHashMap<String, Any?>()
        at["pinned"] = false
        at["keys_to_check"] = ArrayList<Any?>()
        s["attribution"] = at
        s["proven"] = ArrayList<Any?>()
        s["not_proven"] = ArrayList<Any?>(NOT_PROVEN)
        return s
    }

    private fun finish(f: Findings, digest: String?, summary: MutableMap<String, Any?>): Map<String, Any?> {
        val findings = ArrayList(f.list)
        findings.sortWith(Comparator { a, b ->
            var c = cmp(a["code"] as String, b["code"] as String)
            if (c != 0) return@Comparator c
            c = cmp(Js.join(l(a["refs"]), ","), Js.join(l(b["refs"]), ","))
            if (c != 0) return@Comparator c
            c = cmp(a["status"] as String, b["status"] as String)
            if (c != 0) c else cmp(a["text"] as String, b["text"] as String)
        })
        var anyFail = false
        var anyUnverified = false
        var pinPass = false
        var pinOther = false
        for (x in findings) {
            val st = x["status"]
            if ("fail" == st) anyFail = true
            if ("unverified" == st) anyUnverified = true
            if ("principal.pinned" == x["code"]) { if ("pass" == st) pinPass = true else pinOther = true }
        }
        val consistent = findings.isNotEmpty() && !anyFail
        val attributed = pinPass && !pinOther
        val ok = consistent && attributed
        val complete = !anyUnverified
        val notProven = l(summary["not_proven"]) as MutableList<Any?>
        val toCheck = l(get(summary["attribution"], "keys_to_check"))
        if (consistent && !attributed && toCheck.isNotEmpty()) {
            notProven.add(0, "The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: " + Js.join(toCheck, ", ") + ".")
        }
        val codes = java.util.TreeSet<String>()
        for (x in findings) if ("unverified" == x["status"]) codes.add(x["code"] as String)
        if (codes.isNotEmpty()) notProven.add("Checked only through a supplied verifier, or not at all: " + codes.joinToString(", ") + ".")
        val body = LinkedHashMap<String, Any?>()
        body["ok"] = ok
        body["consistent"] = consistent
        body["attributed"] = attributed
        body["complete"] = complete
        body["digest"] = digest
        body["findings"] = ArrayList<Any?>(findings)
        body["summary"] = summary
        val w = LinkedHashMap<String, Any?>()
        w["d"] = EvidenceVerify.EVIDENCE_REPORT_DOMAIN
        w["r"] = body
        val out = LinkedHashMap<String, Any?>(body)
        out["report_digest"] = Pca.hashCanonical(w)
        return out
    }

    fun verify(input: Any?, trustIn: Map<String, Any?>?, ports: Map<String, Port>?): Map<String, Any?> {
        val trust: Map<String, Any?> = trustIn ?: LinkedHashMap()
        val f = Findings()
        val summary = emptySummary()
        if (trust.containsKey("acc")) {
            val te = EvidenceVerify.accTrustError(trust["acc"])
            if (te != null) { f.add("trust.acc", "fail", emptyList(), te); return finish(f, null, summary) }
        }
        if (trust.containsKey("principals")) {
            val pe = EvidenceVerify.principalsTrustError(trust["principals"])
            if (pe != null) { f.add("trust.principals", "fail", emptyList(), pe); return finish(f, null, summary) }
        }
        val bad = EvidenceBundle.bundleShapeError(input)
        if (bad != null) { f.add("shape", "fail", emptyList(), bad); return finish(f, null, summary) }
        val b: Map<String, Any?>
        val digest: String
        try {
            b = EvidenceBundle.normalizeBundle(input)
            digest = EvidenceBundle.evidenceDigest(b)
        } catch (e: RuntimeException) {
            f.add("shape", "fail", emptyList(), "not canonicalizable: " + e.message)
            return finish(f, null, summary)
        }
        f.add("shape", "pass")
        try {
            replay(b, digest, trust, ports ?: emptyMap(), f, summary)
        } catch (e: RuntimeException) {
            f.add("shape", "fail", emptyList(), "replay aborted: " + e.message)
        }
        return finish(f, digest, summary)
    }

    // ---- the replay ----

    private class Grant(val cap: Map<String, Any?>, val seq: Int)

    private class KeySetsAt {
        var sets: MutableList<Any?> = ArrayList()
        var minV: Double? = null
        var tracked: MutableMap<String, Any?>? = null
    }

    private fun orZero(o: Any?): Double {
        val d = num(o)
        return if (d == null || d.isNaN()) 0.0 else d
    }

    /** `{verbs: doc.verbs}`: the schema view the accumulator value rule reads. */
    private fun verbsOnly(doc: Map<String, Any?>): Any? {
        val v = LinkedHashMap<String, Any?>()
        v["verbs"] = doc["verbs"]
        return v
    }

    /** The verifier context `acc` for a candidate action: {state: pre-states of the site-local accumulators, monitors: monitor states}. */
    private fun accContextFor(root: Map<String, Any?>, history: List<Any?>, candParams: Map<String, Any?>, candT: Any?, schema: Any?): Map<String, Any?> {
        val state = LinkedHashMap<String, Any?>()
        val accs = root["accumulators"]
        if (accs !is List<*>) throw IllegalArgumentException("session root accumulators is not iterable")
        for (ao in accs) {
            val a = IntentJs.obj(ao)
            if ("site_local" != IntentJs.get(a["holder"], "kind")) continue
            if (IntentHistory.accKeyOf(a, candParams) == null) continue // the verifier fails the claim (missing key)
            state[a["id"] as String] = IntentHistory.accPreState(a, history, candParams, candT, schema)
        }
        val monitors = LinkedHashMap<String, Any?>()
        val ms = root["monitors"]
        if (ms !is List<*>) throw IllegalArgumentException("session root monitors is not iterable")
        for (mo in ms) {
            val mm = IntentJs.obj(mo)
            monitors[mm["id"] as String] = IntentHistory.monitorState(mm, history)
        }
        val out = LinkedHashMap<String, Any?>()
        out["state"] = state
        out["monitors"] = monitors
        return out
    }

    /** Rule 15 receipt check against a sequenced holder; [minKeySetVersion] (null = none) is a bare version floor. Null ages take the core defaults. */
    private fun receiptAgainstHolder(
        r: Map<String, Any?>, holder: Map<String, Any?>, keySets: List<Any?>, now: Double, maxReceiptAgeMs: Double?, maxKeySetAgeMs: Double?,
        tracked: Map<String, Any?>?, minKeySetVersion: Double?,
    ): Boolean {
        val sets = ArrayList(keySets)
        if (minKeySetVersion != null) {
            val fl = minKeySetVersion
            if (!(fl.isFinite() && fl == Math.rint(fl) && fl >= 0 && fl <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(fl))) return false
            sets.removeAll { k -> val v = IntentJs.num(IntentJs.get(k, "version")); v != null && v < fl }
        }
        return IntentAcc.verifyReceiptAgainstHolder(
            r, holder, sets, now, maxReceiptAgeMs ?: IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble(),
            maxKeySetAgeMs ?: IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble(), tracked,
        )
    }

    private fun replay(b: Map<String, Any?>, digest: String, trust: Map<String, Any?>, ports: Map<String, Port>, f: Findings, summary: MutableMap<String, Any?>) {
        val S = m(b["session_root"])
        val subjectM = m(b["subject"])
        val session = subjectM["session"] as String
        val subjectAud = subjectM["aud"] as String
        val principals = ArrayList<String>()
        for (p in l(S["principals"])) principals.add(get(p, "key") as String)
        principals.sort()
        val principalsAny: List<Any?> = principals
        summary["principal_keys"] = ArrayList<Any?>(principals)
        val sRef: String = if (trust["sessionRootDigest"] is String) trust["sessionRootDigest"] as String else IntentSession.rootDigest(S)
        val pqPins = LinkedHashMap<String, Any?>()
        if (trust["principals"] is List<*>) for (p in trust["principals"] as List<*>) if (get(p, "pq_pk") is String) pqPins[get(p, "key") as String] = get(p, "pq_pk")
        val siteKeys: List<Any?>? = if (trust["siteKeys"] is List<*>) trust["siteKeys"] as List<Any?> else null
        val schemaM = m(b["schema"])
        val schemaDoc = m(schemaM["doc"])

        // -- session root
        if (!str(S["session"], session)) f.add("session_root.signature", "fail", refs("session_root"), "session root is for another session")
        else f.check("session_root.signature", ports["sessionRoot"], Core { nul(IntentSession.verifyRoot(S, pqPins)) }, S, b, refs("session_root"), "the session root")

        // -- statement
        val stmt = m(b["statement"])
        f.addB("statement.commit", str(S["intent_ref"], stmt["commit"]), refs("statement"))
        val opening = stmt["opening"]
        val hasOpening = stmt.containsKey("opening")
        if (!hasOpening) f.add("statement.opening", "unverified", refs("statement"), "the statement was not opened (it stays a commitment)")
        else {
            val v = IntentStatement.verifyIntent(opening)
            if (!ok(v)) f.add("statement.opening", "fail", refs("statement"), v["reason"] as String?)
            else if (IntentStatement.intentRef(opening) != stmt["commit"]) f.add("statement.opening", "fail", refs("statement"), "the opening does not hash to the commitment")
            else if (!principalsAny.contains(get(opening, "principal"))) f.add("statement.opening", "fail", refs("statement"), "signed by a key that is not a principal of the session")
            else f.add("statement.opening", "pass", refs("statement"))
        }

        // -- schema
        f.check(
            "schema.signature", ports["schema"], if (siteKeys != null) Core { nul(ActionSchema.verify(schemaDoc, siteKeys)) } else null,
            schemaDoc, b, refs("schema"), "the action schema (no site keys supplied)",
        )
        val schemaDigest = ActionSchema.digest(schemaDoc)
        f.addB("schema.digest", str(get(S["schema"], "digest"), schemaDigest) && str(get(S["schema"], "aud"), subjectAud), refs("schema"))

        // -- maps
        val mapCommits = HashSet<Any?>()
        for (mo in l(b["maps"])) mapCommits.add(get(mo, "commit"))
        for (mo in l(b["maps"])) {
            val ref = refs("map:" + id(get(mo, "seq")))
            if (!Js.truthy(get(mo, "map"))) { f.add("map.replay", "unverified", ref, "committed map not revealed"); continue }
            val r = IntentMapKit.verifyIntentMap(get(mo, "map"))
            if (r["ok"] != true) {
                val pr = l(r["problems"])
                f.add("map.replay", "fail", ref, Js.join(pr.subList(0, Math.min(3, pr.size)), "; "))
            } else if (IntentMapKit.intentMapDigest(get(mo, "map")) != get(mo, "commit")) f.add("map.replay", "fail", ref, "the revealed map does not hash to its commit")
            else f.add("map.replay", "pass", ref)
        }

        // -- grants: G_0 and the delta chain
        val grants = LinkedHashMap<String, Grant>()
        val g0 = m(b["root_grant"])
        run {
            val cv = IntentSession.grantSessionCaveat(g0)
            val chain = Pca.verifyChain(one(g0), g0["issuer"] as String, true, null, pqPins, null)
            if (chain.isNotEmpty()) f.add("root_grant", "fail", refs("G_0"), chain)
            else if (!principalsAny.contains(g0["issuer"])) f.add("root_grant", "fail", refs("G_0"), "not signed by a principal of the session")
            else if (cv == null || IntentSession.caveatError(cv) != null) f.add("root_grant", "fail", refs("G_0"), if (cv != null) IntentSession.caveatError(cv) else "no intent_session caveat")
            else if (!str(cv["session"], session) || !numEq(cv["seq"], n(0)) || !str(cv["root"], sRef)) f.add("root_grant", "fail", refs("G_0"), "intent_session caveat does not bind seq 0 of this session root")
            else {
                f.add("root_grant", "pass", refs("G_0"))
                grants[g0["id"] as String] = Grant(g0, 0)
            }
        }
        var prevId = g0["id"] as String
        val deltas = l(b["deltas"])
        for (i in deltas.indices) {
            val d = m(deltas[i])
            val want = i + 1
            val ref = refs("D_$want")
            val chain = Pca.verifyChain(one(d), d["issuer"] as String, true, null, pqPins, null)
            if (chain.isNotEmpty() || !principalsAny.contains(d["issuer"]) || d.containsKey("parent")) {
                f.add("delta.signature", "fail", ref, if (chain.isNotEmpty()) chain else "not a principal-signed root capability")
                continue
            }
            f.add("delta.signature", "pass", ref)
            val cv = IntentSession.grantSessionCaveat(d)
            var nCv = 0
            for (k in l(d["caveats"])) if (str(get(k, "type"), "intent_session")) nCv++
            var why: String? = null
            if (cv == null || nCv != 1) why = "no single intent_session caveat"
            else if (IntentSession.caveatError(cv) != null) why = IntentSession.caveatError(cv)
            else if (!str(cv["session"], session)) why = "bound to another session"
            else if (!str(cv["root"], sRef)) why = "bound to another session root"
            else if (!numEq(cv["seq"], n(want.toLong()))) why = "seq " + id(cv["seq"]) + " where " + want + " was expected (gap, duplicate or reorder)"
            else if (!str(cv["prev"], prevId)) why = "prev does not name the previous grant"
            if (why != null) f.add("delta.chain", "fail", ref, why)
            else {
                f.add("delta.chain", "pass", ref)
                grants[d["id"] as String] = Grant(d, want)
            }
            prevId = d["id"] as String
        }

        // -- answers
        val verified = ArrayList<Map<String, Any?>>()
        for (ao in l(b["answers"])) {
            val a = m(ao)
            val ref = refs("answer:" + id(a["question_id"]))
            val v = Wallet.verifyIntentAnswer(a, principals)
            if (!ok(v)) { f.add("answer.signature", "fail", ref, v["reason"] as String?); continue }
            if (!str(a["session"], session)) { f.add("answer.signature", "fail", ref, "answer for another session"); continue }
            f.add("answer.signature", "pass", ref)
            verified.add(a)
            f.addB("answer.map", mapCommits.contains(a["map_digest"]), ref)
            val ux = m(a["ux"])
            if (Js.truthy(ux["canary"]) || !numEq(a["y"], n(1))) continue
            val min = get(trust["minTier"], a["verb"])
            if (min != null) f.add("answer.tier", if (Wallet.frictionRank(ux["tier"]) >= Wallet.frictionRank(min)) "pass" else "fail", ref, id(ux["tier"]) + " vs minimum " + id(min))
            if (str(ux["tier"], "typed")) {
                val tv = get(trust["typedValues"], a["question_id"])
                if (tv == null) f.add("answer.typed", "unverified", ref, "the typed value is not known to this verifier")
                else f.addB("answer.typed", Wallet.typedDigest(a["question_id"] as String, tv as String) == ux["typed_digest"], ref)
            }
            if (str(ux["tier"], "device")) {
                val wa = ux["webauthn"]
                val cred = if (wa is Map<*, *>) get(trust["credentials"], get(wa, "credential_id")) else null
                if (wa !is Map<*, *> || cred == null) f.add("answer.device", "unverified", ref, "unknown authenticator")
                else {
                    val assertion = LinkedHashMap<String, Any?>()
                    assertion["authenticatorData"] = Keys.unb64u(get(wa, "authenticator_data") as String)
                    assertion["clientDataJSON"] = Keys.unb64u(get(wa, "client_data_json") as String)
                    assertion["signature"] = Keys.unb64u(get(wa, "signature") as String)
                    assertion["publicKey"] = get(cred, "publicKey")
                    val expect = LinkedHashMap<String, Any?>()
                    expect["expectedChallenge"] = Wallet.deviceChallenge(
                        a["question_id"] as String, ux["rendered_digest"] as String, lng(a["y"]),
                        if (ux.containsKey("action_digest")) ux["action_digest"] as String? else null,
                    )
                    expect["rpId"] = get(cred, "rpId")
                    expect["origins"] = get(cred, "origins")
                    expect["requireUV"] = true
                    expect["storedSignCount"] = if (has(cred, "signCount") && get(cred, "signCount") != null) get(cred, "signCount") else n(0)
                    val r = Webauthn.verifyAssertion(assertion, expect)
                    f.add("answer.device", if (r["ok"] == true) "pass" else "fail", ref, if (r["ok"] == true) null else r["reason"] as String?)
                }
            }
        }
        val real = ArrayList<Map<String, Any?>>()
        val canaries = ArrayList<Map<String, Any?>>()
        for (a in verified) (if (Js.truthy(get(a["ux"], "canary"))) canaries else real).add(a)
        var yes = 0L
        var no = 0L
        var partial = 0L
        var yesAny = 0L
        val refusals = ArrayList<Any?>()
        for (a in real) {
            if (numEq(a["y"], n(1)) && !a.containsKey("partial")) yes++
            if (numEq(a["y"], n(0))) { no++; refusals.add(a["question_id"]) }
            if (a.containsKey("partial")) partial++
            if (numEq(a["y"], n(1))) yesAny++
        }
        val ans = summary["answers"] as MutableMap<String, Any?>
        ans["total"] = n(real.size.toLong())
        ans["yes"] = n(yes)
        ans["no"] = n(no)
        ans["partial"] = n(partial)
        ans["canaries"] = n(canaries.size.toLong())
        refusals.sortWith(Comparator { x, y -> cmp(x as String, y as String) })
        summary["refusals"] = refusals
        f.add("delta.backed", if (yesAny >= deltas.size) "pass" else "fail", emptyList(), "${deltas.size} delta(s), $yesAny principal yes answer(s)")

        // -- canaries
        run {
            val labels = LinkedHashMap<String, Any?>()
            for (c in l(b["canary_labels"])) labels[get(c, "question_id") as String] = get(c, "label")
            var falseYes = 0L
            var falseNo = 0L
            var missing = 0L
            for (a in canaries) {
                val qid = a["question_id"] as String
                var label = get(trust["canaryLabels"], qid)
                if (label == null) label = labels[qid]
                if (label == null) missing++
                else if (numEq(label, n(0)) && numEq(a["y"], n(1))) falseYes++
                else if (numEq(label, n(1)) && numEq(a["y"], n(0))) falseNo++
            }
            val ca = summary["canary_accuracy"] as MutableMap<String, Any?>
            ca["correct"] = n(canaries.size - missing - falseYes - falseNo)
            ca["asked"] = n(canaries.size.toLong())
            val c = m(b["canaries"])
            if (missing > 0) f.add("canaries.summary", "fail", emptyList(), "$missing canary answer(s) without a known label")
            else if (!numEq(c["asked"], n(canaries.size.toLong())) || !numEq(c["false_yes"], n(falseYes)) || !numEq(c["false_no"], n(falseNo))) {
                f.add("canaries.summary", "fail", emptyList(), "claimed " + id(c["asked"]) + "/" + id(c["false_yes"]) + "/" + id(c["false_no"]) + ", recomputed " + canaries.size + "/" + falseYes + "/" + falseNo)
            } else f.add("canaries.summary", "pass", emptyList(), "${canaries.size} asked, $falseYes false yes, $falseNo false no")
        }

        // -- sequencer key sets (rule 15)
        val acc = m(b["accumulator"])
        val rootHolders = LinkedHashMap<String, Map<String, Any?>>()
        for (ao in l(S["accumulators"])) {
            val h = get(ao, "holder")
            if (str(get(h, "kind"), "sequenced")) rootHolders[get(h, "root") as String] = m(h)
        }
        val acceptedKeySets = ArrayList<Map<String, Any?>>()
        val verifiedKeySets = ArrayList<Map<String, Any?>>()
        val equivocatedSlots = HashSet<String>()
        run {
            val sets = ArrayList<Any?>(if (acc["sequencer_keys"] is List<*>) acc["sequencer_keys"] as List<Any?> else emptyList())
            sets.sortWith(Comparator { x, y ->
                var c = java.lang.Double.compare(orZero(get(x, "issued_at")), orZero(get(y, "issued_at")))
                if (c != 0) return@Comparator c
                c = java.lang.Double.compare(orZero(get(x, "version")), orZero(get(y, "version")))
                if (c != 0) c else cmp(Pca.hashCanonical(x), Pca.hashCanonical(y))
            })
            val tracked = LinkedHashMap<String, Double>()
            val byVersion = LinkedHashMap<String, Array<String>>()
            for (i in sets.indices) {
                val ko = sets[i]
                val ref = "keyset#" + i + ":" + (if (ko is Map<*, *>) id(get(ko, "version")) else "?")
                val holder = if (ko is Map<*, *> && get(ko, "sequencer") is String) rootHolders.at(get(ko, "sequencer")) else null
                if (holder == null) { f.add("acc.keysets", "fail", refs(ref), "not signed by a sequencer root the session root pins"); continue }
                val root = holder["root"] as String
                if (!IntentAcc.verifyKeySet(ko, root, holder["root_pq_pk"], holder.containsKey("root_pq_pk"))) {
                    f.add("acc.keysets", "fail", refs(ref), "the key set does not verify under its pinned root")
                    continue
                }
                val k = m(ko)
                val ver = num(k["version"])!!
                val prev = tracked[root]
                if (prev != null && ver < prev) { f.add("acc.keysets", "fail", refs(ref), "version " + id(k["version"]) + " rolls back the tracked version " + js(prev)); continue }
                val slot = root + "#" + id(k["version"])
                val dg = IntentAcc.keySetDigest(k)
                val seen = byVersion[slot]
                if (seen != null && seen[0] != dg) {
                    equivocatedSlots.add(slot)
                    verifiedKeySets.add(k)
                    f.add("acc.keysets.equivocation", "fail", refs(seen[1], ref), "two different key sets under version " + id(k["version"]) + " of one sequencer root")
                    continue
                }
                if (seen == null) byVersion[slot] = arrayOf(dg, ref)
                verifiedKeySets.add(k)
                tracked[root] = Math.max(prev ?: 0.0, ver)
                acceptedKeySets.add(k)
                f.add("acc.keysets", "pass", refs(ref))
            }
            for (i in acceptedKeySets.size - 1 downTo 0) {
                val k = acceptedKeySets[i]
                if (equivocatedSlots.contains(Js.template(k["sequencer"]) + "#" + id(k["version"]))) acceptedKeySets.removeAt(i)
            }
        }
        val keySetsAt = { root: String, t: Double ->
            val r = KeySetsAt()
            var newest: Map<String, Any?>? = null
            for (k in verifiedKeySets) {
                if (root != k["sequencer"] || !(num(k["issued_at"])!! <= t)) continue
                if (newest == null || num(k["version"])!! > num(newest["version"])!!) newest = k
            }
            val poisoned = newest != null && equivocatedSlots.contains(root + "#" + id(newest["version"]))
            val floor = if (newest == null) 0.0 else num(newest["version"])!!
            for (k in acceptedKeySets) {
                if (root == k["sequencer"] && num(k["issued_at"])!! <= t + IntentAcc.RECEIPT_SKEW_MS && num(k["version"])!! >= floor) r.sets.add(k)
            }
            r.minV = if (newest == null) null else num(newest["version"])
            if (newest != null && !poisoned) {
                val tr = LinkedHashMap<String, Any?>()
                tr["version"] = newest["version"]
                tr["digest"] = IntentAcc.keySetDigest(newest)
                r.tracked = tr
            }
            r
        }

        // -- PCActns
        val byDigest = LinkedHashMap<String, Map<String, Any?>>()
        val rootSeq = LinkedHashMap<String, Int>()
        val effects = l(b["effects"])
        val effectOf = { d: String ->
            var found: Map<String, Any?>? = null
            for (e in effects) if (d == get(e, "pcactn_digest")) { found = m(e); break }
            found
        }
        val digestOf = { p: Map<String, Any?> -> try { Pca.hashCanonical(p) } catch (e: RuntimeException) { null } }
        val grantsBySeq = ArrayList<Map<String, Any?>>()
        run {
            val gs = ArrayList(grants.values)
            gs.sortWith(Comparator { x, y -> Integer.compare(x.seq, y.seq) })
            for (g in gs) grantsBySeq.add(g.cap)
        }
        val epochs = l(b["revocation_epochs"])
        val epochIdxAt = { t: Double ->
            var idx = -1
            for (i in epochs.indices) if (num(get(get(epochs[i], "epoch"), "issued_at"))!! <= t) idx = i
            idx
        }
        val pcactns = l(b["pcactns"])
        val events = l(acc["events"])
        val history = ArrayList<Any?>()
        for (evo in events) {
            val pd = get(evo, "pcactn_digest") as String
            var dup = false
            for (h in history) if (pd == get(h, "id")) { dup = true; break }
            if (dup) continue
            var p: Map<String, Any?>? = null
            for (x in pcactns) { if (pd == digestOf(m(x))) { p = m(x); break } }
            val eff = effectOf(pd)
            val params = eff?.get("params")
            if (p != null && params != null) {
                val h = LinkedHashMap<String, Any?>()
                h["id"] = pd
                h["verb"] = get(p["action"], "verb")
                h["resource"] = get(p["action"], "resource")
                h["params"] = params
                h["t"] = p["iat"]
                h["status"] = if (has(evo, "status") && get(evo, "status") != null) get(evo, "status") else "committed"
                history.add(h)
            }
        }
        val schemaVerbsOnly = verbsOnly(schemaDoc)
        val receiptsAll: List<Any?> = if (acc["receipts"] is List<*>) l(acc["receipts"]) else ArrayList()
        val trustAcc: Map<String, Any?>? = if (trust["acc"] is Map<*, *>) m(trust["acc"]) else null
        val v2Context = fn@{ p: Map<String, Any?>, d: String, seq: Int? ->
            val eff = effectOf(d)
            val params = eff?.get("params")
            if (params !is Map<*, *> || seq == null) return@fn null
            var idx = -1
            for (i in history.indices) if (d == get(history[i], "id")) { idx = i; break }
            val before = ArrayList<Any?>()
            if (idx >= 0) before.addAll(history.subList(0, idx))
            else for (h in history) if (num(get(h, "t"))!! <= num(p["iat"])!!) before.add(h)
            val accCtx = accContextFor(S, before, m(params), p["iat"], schemaVerbsOnly)
            val ri = epochIdxAt(num(p["iat"])!!)
            val rev = if (ri >= 0) epochs[ri] else null
            val revLast = if (ri > 0) epochs[ri - 1] else null
            val ctx = LinkedHashMap<String, Any?>()
            ctx["params"] = params
            val sch = LinkedHashMap<String, Any?>()
            sch["docs"] = arrayListOf<Any?>(schemaDoc)
            sch["keys"] = siteKeys ?: ArrayList<Any?>()
            ctx["schema"] = sch
            val sess = LinkedHashMap<String, Any?>()
            sess["root"] = S
            sess["grants"] = ArrayList<Any?>(grantsBySeq.subList(0, Math.min(seq, grantsBySeq.size)))
            sess["pq_pins"] = pqPins
            if (rev != null) sess["revocation"] = rev
            if (revLast != null) sess["revocation_last"] = revLast
            ctx["session"] = sess
            val accOut = LinkedHashMap<String, Any?>(accCtx)
            accOut["receipts"] = receiptsAll
            val keys = ArrayList<Any?>()
            val versions = LinkedHashMap<String, Any?>()
            for (root in rootHolders.keys) {
                val ks = keySetsAt(root, num(p["iat"])!!)
                keys.addAll(ks.sets)
                if (ks.tracked != null) versions[root] = ks.tracked
            }
            accOut["sequencer_keys"] = keys
            accOut["keyset_versions"] = versions
            ctx["acc"] = accOut
            if (trustAcc != null) {
                val pol = LinkedHashMap<String, Any?>()
                pol["acc"] = trustAcc
                ctx["policy"] = pol
            }
            ctx as Map<String, Any?>?
        }
        val v2Checks = setOf("schema", "intent_session", "accumulators")
        for (po in pcactns) {
            val p = m(po)
            val d = digestOf(p)
            if (d == null) { f.add("pcactn.verify", "fail", refs("pcactn:?"), "not canonicalizable"); continue }
            byDigest[d] = p
            val ref = refs("pcactn:$d")
            val capChain = p["cap_chain"]
            val root = if (capChain is List<*> && capChain.isNotEmpty()) capChain[0] else null
            if (!Js.truthy(root)) { f.add("pcactn.verify", "fail", ref, "empty capability chain"); continue }
            val g = grants.at(get(root, "id"))
            val sameRoot = g != null && Pca.hashCanonical(g.cap) == Pca.hashCanonical(root)
            val hasIs = p.containsKey("intent_session")
            val isM: Map<String, Any?>? = if (hasIs) mn(p["intent_session"]) else null
            val ctx = if (hasIs && sameRoot) v2Context(p, d, g!!.seq) else null
            val opts = PcaCore.Options(m(root))
            opts.insecureSkipPlanRootCheck = true
            opts.grantFromArtifact = true
            opts.pqPins = pqPins
            opts.nowEpoch = lng(p["iat"])
            opts.audience = Pca.Audience.Of(subjectAud)
            if (ctx != null) opts.intentV2 = IntentV2.Context.fromJson(ctx)
            val r = PcaCore.verify(p, opts)
            val failed = ArrayList<String>()
            for ((k, v) in r.checks) if (PcaCore.FAIL == v) failed.add(k)
            failed.sort()
            val v1f = ArrayList<String>()
            val v2f = ArrayList<String>()
            for (k in failed) (if (v2Checks.contains(k)) v2f else v1f).add(k)
            f.add("pcactn.verify", if (v1f.isEmpty()) "pass" else "fail", ref, if (v1f.isEmpty()) null else v1f.joinToString(", ") + ": " + (r.reason ?: ""))
            if (sameRoot) {
                f.add("pcactn.root", "pass", ref, if (g!!.seq == 0) "G_0" else "D_${g.seq}")
                rootSeq[d] = g.seq
            } else f.add("pcactn.root", "fail", ref, "rooted at a grant that is not G_0 or a verified delta of this session")
            if (hasIs) {
                var why: String? = null
                if (!str(get(isM, "session"), session)) why = "another session"
                else if (!str(get(isM, "root"), sRef)) why = "another session root"
                else if (!str(get(isM, "schema"), schemaDigest)) why = "another schema"
                else if (g != null && !numEq(get(isM, "seq"), n(g.seq.toLong()))) why = "seq " + id(get(isM, "seq")) + " but rooted at seq " + g.seq
                else {
                    val isAcc = get(isM, "acc")
                    for (c in if (isAcc is List<*>) isAcc else emptyList<Any?>()) {
                        var found: Any? = null
                        for (e in events) if (d == get(e, "pcactn_digest") && get(e, "acc") == get(c, "id")) { found = e; break }
                        if (found == null || !numEq(get(found, "post"), get(c, "post"))) why = "the signed claim " + id(get(c, "id")) + ".post = " + id(get(c, "post")) + " has no matching accumulator event"
                    }
                }
                if (why == null && v2f.isNotEmpty()) why = "core v2 checks failed: " + v2f.joinToString(", ")
                if (why != null) f.add("pcactn.session", "fail", ref, why)
                else if (ctx == null) f.add("pcactn.session", "unverified", ref, "the core v2 checks need the plaintext params of the effect record")
                else f.add("pcactn.session", "pass", ref)
            }
        }
        val subject = byDigest.at(subjectM["pcactn_digest"])
        f.addB("subject.present", subject != null, refs("pcactn:" + subjectM["pcactn_digest"]))
        val sSeq = rootSeq.at(subjectM["pcactn_digest"])
        summary["admitted_under"] = if (sSeq == null) null else if (sSeq == 0) "G_0" else "D_$sSeq"

        // -- effects
        for (eo in effects) {
            val e = m(eo)
            val ref = refs("effect:" + e["pcactn_digest"])
            val p = byDigest.at(e["pcactn_digest"])
            if (p == null) { f.add("effect.binding", "fail", ref, "no such PCActn in the bundle"); continue }
            if (!e.containsKey("params")) f.add("effect.binding", "unverified", ref, "no raw params to bind")
            else f.addB("effect.binding", Pca.paramsDigest(e["params"]) == get(p["action"], "params_digest"), ref)
            if (Js.truthy(e["charged"])) {
                val ch = m(e["charged"])
                val chRef = ch["ref"] as String
                val name = if (chRef.startsWith("action.params.")) chRef.substring("action.params.".length) else null
                val bound = if (name != null && Js.truthy(e["params"])) get(e["params"], name) else null
                if (!isNum(bound) || !isNum(ch["amount"])) f.add("effect.charged", "unverified", ref, "no numeric $chRef to compare")
                else {
                    f.add("effect.charged", if (num(ch["amount"])!! <= num(bound)!!) "pass" else "fail", ref, id(ch["amount"]) + " vs " + id(bound))
                    if (e["pcactn_digest"] == subjectM["pcactn_digest"]) {
                        val cs = LinkedHashMap<String, Any?>()
                        cs["amount"] = ch["amount"]
                        cs["bound"] = bound
                        summary["charged"] = cs
                    }
                }
            }
            if (e.containsKey("frame_violations")) {
                val fv = l(e["frame_violations"])
                val sorted = ArrayList<String>()
                for (x in fv) sorted.add(x as String)
                sorted.sort()
                f.add("effect.frame", if (fv.isEmpty()) "pass" else "fail", ref, if (fv.isEmpty()) null else sorted.joinToString(", "))
            }
            f.check("effect.signature", ports["effect"], null, e, b, ref, "effect records (no core format yet)")
        }

        // -- JIT consent for an irreversible subject action
        if (subject != null && str(get(subject["action"], "reversibility_class"), "irreversible")) {
            val ref = refs("pcactn:" + subjectM["pcactn_digest"])
            val ad = IntentJit.intentActionDigest(subject["action"])
            val needO = trust["jitTier"]
            val need = needO ?: "typed"
            var c: Map<String, Any?>? = null
            for (a in real) {
                val ux = m(a["ux"])
                if (numEq(a["y"], n(1)) && ux["consent_for_action"] == true && ad == ux["action_digest"] && Wallet.frictionRank(ux["tier"]) >= Wallet.frictionRank(need)) { c = a; break }
            }
            val cx = c
            if (cx != null) {
                f.add("jit.consent", "pass", ref, "question " + id(cx["question_id"]) + ", " + id(get(cx["ux"], "tier")) + " tier")
                val cs = LinkedHashMap<String, Any?>()
                cs["question_id"] = cx["question_id"]
                cs["tier"] = get(cx["ux"], "tier")
                cs["signer"] = cx["signer"]
                summary["consent"] = cs
            } else f.add("jit.consent", "fail", ref, "no principal yes at " + id(need) + " tier or above bound to this action digest")
        }

        // -- accumulators
        val decls = LinkedHashMap<String, Map<String, Any?>>()
        for (ao in l(S["accumulators"])) decls[get(ao, "id") as String] = m(ao)
        val valueOf = { decl: Map<String, Any?>, d: String ->
            val p = byDigest[d]
            val eff = effectOf(d)
            val params = eff?.get("params")
            if (p == null || params !is Map<*, *>) null
            else {
                val av = IntentAcc.accValueOf(decl, get(p["action"], "verb") as String, m(params), schemaVerbsOnly)
                if (av.reason == null) av.value else null
            }
        }
        val running = LinkedHashMap<String, Double>()
        for (i in events.indices) {
            val ev = m(events[i])
            val ref = refs("acc:" + id(ev["acc"]) + "#" + i)
            val decl = decls.at(ev["acc"])
            if (decl == null) { f.add("accumulator.declared", "fail", ref); continue }
            val p = byDigest.at(ev["pcactn_digest"])
            val counted = !str(ev["status"], "released") && !str(ev["status"], "reverted")
            val prev = running[ev["acc"] as String] ?: 0.0
            var expected: Double? = null
            if (!counted) expected = prev
            else if (str(decl["agg"], "count")) expected = prev + 1
            else if (str(decl["agg"], "sum") || str(decl["agg"], "max")) {
                val v = valueOf(decl, ev["pcactn_digest"] as String)
                if (v != null) expected = if (str(decl["agg"], "sum")) prev + v else Math.max(prev, v.toDouble())
            }
            val post = num(ev["post"])!!
            if (p == null) f.add("accumulator.arithmetic", "fail", ref, "event names a PCActn that is not in the bundle")
            else if (expected == null) f.add("accumulator.arithmetic", if (post >= prev) "unverified" else "fail", ref, if (post >= prev) "contribution not recomputable" else "post decreased")
            else f.add("accumulator.arithmetic", if (post == expected) "pass" else "fail", ref, if (post == expected) null else "post " + id(ev["post"]) + ", recomputed " + js(expected))
            running[ev["acc"] as String] = if (counted) post else prev
            if (!counted) continue
            val seq: Int? = if (p != null) rootSeq.at(ev["pcactn_digest"]) else null
            if (has(ev, "delta") && seq != null && !numEq(ev["delta"], n(seq.toLong()))) { f.add("accumulator.cap", "fail", ref, "the event names a different admitting grant from the PCActn root"); continue }
            var grant: Grant? = null
            for (gg in grants.values) {
                if (if (seq != null) gg.seq == seq else (has(ev, "delta") && numEq(ev["delta"], n(gg.seq.toLong())))) { grant = gg; break }
            }
            val caps = ArrayList<Double>()
            val c1 = if (grant != null && p != null) EvidenceVerify.capOf(grant.cap, ev["acc"] as String, get(p["action"], "verb") as String) else null
            if (c1 != null) caps.add(c1)
            if (isNum(decl["domain_max"])) caps.add(num(decl["domain_max"])!!)
            if (isNum(decl["cap"])) caps.add(num(decl["cap"])!!)
            if (caps.isEmpty()) f.add("accumulator.cap", "unverified", ref, "no cap stated for this accumulator")
            else {
                val cap = caps.minOrNull()!!
                f.add("accumulator.cap", if (isNum(ev["post"]) && post <= cap) "pass" else "fail", ref, "post " + id(ev["post"]) + ", cap " + js(cap))
            }
        }
        val receipts = receiptsAll
        if (str(acc["holder"], "sequenced") && receipts.isEmpty()) f.add("accumulator.receipts", "fail", refs("accumulator"), "a sequenced accumulator without receipts")
        for (i in receipts.indices) {
            val r = m(receipts[i])
            val core = Core {
                val decl = decls.at(r["acc"])
                if (decl == null || !str(get(decl["holder"], "kind"), "sequenced")) return@Core vd(false, "the receipt names an accumulator that is not sequenced in the session root")
                val holder = m(decl["holder"])
                if (!str(r["session"], session) || !str(r["aud"], subjectAud)) return@Core vd(false, "receipt for another session or audience")
                var d: String? = null
                for ((k, v) in byDigest) {
                    if (IntentAcc.pcactnReservationDigest(v) == r["pcactn_digest"]) { d = k; break }
                }
                if (d == null) return@Core vd(false, "the receipt reserves for a PCActn that is not in the bundle")
                val admittedAt = num(byDigest[d]!!["iat"])!!
                val ks = keySetsAt(holder["root"] as String, admittedAt)
                val maxR = if (trustAcc != null && trustAcc.containsKey("max_receipt_age_s")) num(trustAcc["max_receipt_age_s"])!! * 1000 else null
                val maxK = if (trustAcc != null && trustAcc.containsKey("max_keyset_age_s")) num(trustAcc["max_keyset_age_s"])!! * 1000 else null
                if (!receiptAgainstHolder(r, holder, ks.sets, admittedAt, maxR, maxK, ks.tracked, if (ks.tracked == null) ks.minV else null)) {
                    return@Core vd(false, "not signed by a key the pinned sequencer root listed, or not fresh, at admission time")
                }
                if (!(isNum(admittedAt) && isNum(r["expires_at"]) && admittedAt <= num(r["expires_at"])!!)) return@Core vd(false, "the receipt had expired when the action was admitted")
                val v = valueOf(decl, d) ?: return@Core null
                if (!IntentAcc.receiptArithmeticOk(decl["agg"], r, v)) return@Core vd(false, "pre + delta does not give post for the reserved value")
                vd(true, null)
            }
            f.check(
                "accumulator.receipts", ports["receipt"], core, r, b,
                refs("receipt:" + id(r["acc"]) + "#" + (if (r.containsKey("seq")) id(r["seq"]) else i.toString())), "the reserved contribution (the effect params were withheld)",
            )
        }

        // -- W-B artifacts
        val facts: List<Any?> = if (b["facts"] is List<*>) l(b["facts"]) else ArrayList()
        for (i in facts.indices) {
            val x = facts[i]
            val pk = if (x is Map<*, *> && get(x, "oracle") is String) get(trust["oracleKeys"], get(x, "oracle")) else null
            val core = if (pk == null) null else Core {
                val w = OracleFacts.validateFactWire(x)
                if (w != null) vd(false, w)
                else if (net.atlasauth.pca.verifier.IntentArtifacts.verifyArtifactSig(OracleFacts.FACT_DOMAIN, m(x), pk, null)) vd(true, null) else vd(false, "bad oracle signature")
            }
            f.check("fact.signature", ports["fact"], core, x, b, refs("fact:$i"), "this fact (oracle key not pinned)")
        }
        val classifier: List<Any?> = if (b["classifier"] is List<*>) l(b["classifier"]) else ArrayList()
        for (i in classifier.indices) {
            val x = classifier[i]
            val judge = if (x is Map<*, *> && get(x, "judge") is String) get(x, "judge") as String else null
            val judges = if (trust["judges"] is List<*>) trust["judges"] as List<*> else emptyList<Any?>()
            val core = if (judge == null || !judges.contains(judge)) null else Core {
                val w = IntentClassifier.validateVerdictWire(x)
                if (w != null) vd(false, w)
                else if (!str(get(x, "session"), session)) vd(false, "verdict for another session")
                else if (net.atlasauth.pca.verifier.IntentArtifacts.verifyArtifactSig(IntentClassifier.INTENT_CLASSIFIER_DOMAIN, m(x), judge, null)) vd(true, null) else vd(false, "bad judge signature")
            }
            f.check("classifier.signature", ports["classifier"], core, x, b, refs("classifier:$i"), "this classifier verdict (judge not pinned)")
        }
        val offerSets: List<Any?> = if (b["offer_sets"] is List<*>) l(b["offer_sets"]) else ArrayList()
        for (i in offerSets.indices) {
            val x = offerSets[i]
            var key: Any? = null
            if (siteKeys != null && x is Map<*, *>) for (k in siteKeys) if (get(k, "kid") != null && get(k, "kid") == get(x, "kid") && str(get(k, "alg"), "ed25519")) { key = k; break }
            val fkey = key
            val core = if (key == null) null else Core {
                val w = OracleFacts.validateOfferSetWire(x)
                if (w != null) vd(false, w)
                else if (!str(get(x, "session"), session)) vd(false, "offer set for another session")
                else if (net.atlasauth.pca.verifier.IntentArtifacts.verifyArtifactSig(OracleFacts.OFFER_SET_DOMAIN, m(x), get(fkey, "pk"), null)) vd(true, null) else vd(false, "bad site signature")
            }
            f.check("offer_set.signature", ports["offerSet"], core, x, b, refs("offer_set:$i"), "this offer set (site key not pinned)")
        }
        val labelKeys = ArrayList<Any?>()
        if (trust["labelKeys"] is List<*>) labelKeys.addAll(trust["labelKeys"] as List<*>)
        else if (siteKeys != null) {
            for (k in siteKeys) {
                if (!str(get(k, "alg"), "ed25519")) continue
                val lk = LinkedHashMap<String, Any?>()
                lk["site"] = schemaDoc["site"]
                lk["kid"] = get(k, "kid")
                lk["pk"] = get(k, "pk")
                labelKeys.add(lk)
            }
        }
        val labels: List<Any?> = if (b["labels"] is List<*>) l(b["labels"]) else ArrayList()
        for (i in labels.indices) {
            val x = labels[i]
            val core = if (labelKeys.isEmpty()) null else Core {
                val e = ParamProvenance.verifyLabels(x, labelKeys)
                if (e == null && !str(get(x, "session"), session)) vd(false, "label receipt for another session") else nul(e)
            }
            f.check("labels.signature", ports["labels"], core, x, b, refs("labels:$i"), "this label receipt (no site keys)")
        }

        // -- ported artifacts with no core format
        for (v in l(b["verdicts"])) f.check("verdict.signature", ports["verdict"], null, v, b, refs("verdict:" + id(get(v, "pcactn_digest"))), "site verdicts (no core format yet)")
        val settlements: List<Any?> = if (b["settlements"] is List<*>) l(b["settlements"]) else ArrayList()
        for (i in settlements.indices) f.check("settlement.signature", ports["settlement"], null, settlements[i], b, refs("settlement:$i"), "settlement records (no core format yet)")

        // -- revocation
        if (epochs.isEmpty()) f.add("revocation.epoch", "unverified", emptyList(), "no revocation epoch in the bundle")
        else if (!Js.truthy(S["revocation"])) f.add("revocation.epoch", "fail", emptyList(), "the session root names no revocation authority")
        else {
            val revO = S["revocation"]
            val authority = get(revO, "key") as String
            val maxAgeMs = (if (has(revO, "max_age_s") && get(revO, "max_age_s") != null) num(get(revO, "max_age_s"))!! else 300.0) * 1000
            var pin: Map<String, Any?>? = null
            if (get(revO, "pq_pk") != null) pin = linkedMapOf(authority to get(revO, "pq_pk"))
            var historyOk = true
            for (i in epochs.indices) {
                val ev = epochs[i]
                val last = if (i > 0) epochs[i - 1] else null
                val e = IntentRevocation.checkSessionRevocation(ev, session, authority, ArrayList<Any?>(), num(get(get(ev, "epoch"), "issued_at"))!!, maxAgeMs, null, pin, last != null, last)
                if (e != null) historyOk = false
                f.verdict("revocation.history", nul(e), refs("epoch#" + i + ":" + id(get(get(ev, "epoch"), "epoch"))))
            }
            if (subject == null) f.add("revocation.epoch", "unverified", emptyList(), "no subject action time")
            else {
                val ids = ArrayList<Any?>()
                ids.add(IntentRevocation.sessionRevocationId(session))
                for (mo in l(b["maps"])) ids.add(IntentRevocation.mapRevocationId(get(mo, "commit") as String))
                for (d in deltas) ids.add(IntentRevocation.deltaRevocationId(get(d, "id") as String))
                val idx = epochIdxAt(num(subject["iat"])!!)
                val ev = if (idx >= 0) epochs[idx] else null
                if (ev == null) f.add("revocation.epoch", "fail", emptyList(), "every epoch was issued after the action")
                else if (!historyOk) f.add("revocation.epoch", "fail", refs("epoch:" + id(get(get(ev, "epoch"), "epoch"))), "the bundled epochs are not one append-only chain")
                else {
                    val last = if (idx > 0) epochs[idx - 1] else null
                    f.verdict(
                        "revocation.epoch",
                        nul(IntentRevocation.checkSessionRevocation(ev, session, authority, ids, num(subject["iat"])!!, maxAgeMs, null, pin, last != null, last)),
                        refs("epoch:" + id(get(get(ev, "epoch"), "epoch"))),
                    )
                }
            }
        }

        // -- anchors
        if (Js.truthy(schemaM["anchor"])) f.add("schema.anchor", "unverified", refs("schema"), "the anchor names a log position without an inclusion proof")
        val anchors = l(b["anchors"])
        var anyEvidenceAnchor = false
        for (a in anchors) if (str(get(a, "kind"), "evidence")) anyEvidenceAnchor = true
        if (!anyEvidenceAnchor) f.add("anchor.inclusion", "unverified", refs("anchor:evidence"), "the bundle is not anchored")
        for (ao in anchors) {
            val kind = get(ao, "kind") as String
            val dg = get(ao, "digest") as String
            val ref = refs("anchor:$kind:" + id(get(ao, "index")))
            val anchorable: Boolean = when (kind) {
                "evidence" -> dg == digest
                "statement" -> dg == stmt["commit"]
                "map" -> mapCommits.contains(dg)
                "schema" -> dg == schemaDigest
                "observation" -> verified.any { Wallet.answerRef(it) == dg }
                else -> false
            }
            if (!anchorable) { f.add("anchor.inclusion", "fail", ref, "the anchor names an artifact that is not this one"); continue }
            val g = trust["anchorGuardian"]
            if (!Js.truthy(g)) { f.add("anchor.inclusion", "unverified", ref, "no anchor-log guardian key supplied"); continue }
            val h = get(ao, "signed_tree_head")
            val proof = get(ao, "proof")
            val okA = str(get(h, "principal"), EvidenceVerify.INTENT_ANCHOR_LOG) &&
                str(get(h, "instance_id"), get(g, "instance")) &&
                Ledger.verifyTreeHead(h, get(g, "public") as String, null) &&
                numEq(get(proof, "index"), get(ao, "index")) &&
                numEq(get(proof, "size"), get(h, "size")) &&
                Ledger.verifyInclusion(get(h, "root") as String, proof, EvidenceVerify.anchorCommit(kind, dg))
            f.addB("anchor.inclusion", okA, ref)
        }

        // -- attribution
        val signing = LinkedHashSet<String?>()
        signing.add(S["signer"] as String?)
        signing.add(g0["issuer"] as String?)
        for (d in deltas) signing.add(get(d, "issuer") as String?)
        for (a in l(b["answers"])) signing.add(get(a, "signer") as String?)
        if (hasOpening) signing.add(get(opening, "principal") as String?)
        signing.remove(null)
        val keys = ArrayList<String>(signing.filterNotNull())
        keys.sort()
        (summary["attribution"] as MutableMap<String, Any?>)["keys_to_check"] = ArrayList<Any?>(keys)
        if (!trust.containsKey("principals")) f.add("principal.pinned", "unverified", keys, "no pinned principal keys: the bundle names its own principals; verify these keys out of band")
        else {
            val pins = LinkedHashMap<String, Any?>()
            for (p in l(trust["principals"])) pins[get(p, "key") as String] = p
            val unpinned = ArrayList<String>()
            val pqMismatch = ArrayList<String>()
            for (k in keys) if (!pins.containsKey(k)) unpinned.add(k)
            for (k in keys) {
                val pin = pins[k]
                var sp: Any? = null
                for (x in l(S["principals"])) if (k == get(x, "key")) { sp = x; break }
                if (pin != null && get(pin, "pq_pk") != get(sp, "pq_pk")) pqMismatch.add(k)
            }
            if (unpinned.isNotEmpty()) f.add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals")
            else if (pqMismatch.isNotEmpty()) f.add("principal.pinned", "fail", pqMismatch, "the session root binds a different PQ key than the pin")
            else {
                f.add("principal.pinned", "pass", keys)
                (summary["attribution"] as MutableMap<String, Any?>)["pinned"] = true
            }
        }

        // -- plain-language facts (only what passed)
        val proven = ArrayList<Any?>()
        val pinned = get(summary["attribution"], "pinned") == true
        val adm = summary["admitted_under"]
        if (adm != null && pass(f, "pcactn.verify")) proven.add("The subject action was signed by the agent under $adm, a grant signed by the session principal" + (if (pinned) " (pinned)" else " (NOT pinned)") + ".")
        val consent = mn(summary["consent"])
        if (consent != null) {
            val sg = consent["signer"] as String
            val who = if (pinned) "Pinned principal key $sg" else "Session-root key $sg (NOT pinned: not attributed to a known principal)"
            proven.add(who + " signed a " + consent["tier"] + "-tier \"yes\" bound to this exact action (question " + id(consent["question_id"]) + ").")
        }
        val ch = mn(summary["charged"])
        if (ch != null && num(ch["amount"])!! <= num(ch["bound"])!!) proven.add("The charged amount " + id(ch["amount"]) + " is within the confirmed value " + id(ch["bound"]) + ".")
        if (refusals.isNotEmpty()) proven.add("The principal refused " + refusals.size + " question(s): " + Js.join(refusals, ", ") + ".")
        val asked = lng(get(summary["canary_accuracy"], "asked"))
        if (asked != 0L) proven.add("Canary accuracy " + id(get(summary["canary_accuracy"], "correct")) + "/" + asked + ".")
        if (pass(f, "accumulator.cap")) proven.add("Every accumulator post is within the cap of the grant that admitted it.")
        if (pass(f, "effect.frame")) proven.add("The site reports no change to monitored state outside the write set.")
        summary["proven"] = proven
    }
}
