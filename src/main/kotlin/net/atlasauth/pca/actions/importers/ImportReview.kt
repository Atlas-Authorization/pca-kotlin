package net.atlasauth.pca.actions.importers

import java.util.TreeSet
import net.atlasauth.pca.actions.ActionConfirmation
import net.atlasauth.pca.actions.ActionDerive
import net.atlasauth.pca.actions.ActionEffective
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The confirmation flow and signed review attestations. This is the ONE non-monotone step in the system: a def WITHOUT a valid
 * attestation has the top of the registry as its effective traits, and a valid one sets them to exactly what the reviewer signed. It counts
 * only when a key pinned with the `reviewer` role has signed this exact def digest. Any change to the def or to the trait registry the
 * reviewer saw makes the attestation stale and the def reverts to unconfirmed. Defs, pins and verdicts are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object ImportReview {
    private val TRAIT_ID_RE = Regex("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}")

    private fun fail(reason: String, detail: String): Map<String, Any?> = Jx.obj("ok", false, "reason", reason, "detail", detail)

    private fun strings(v: Any?): Boolean {
        if (v !is List<*>) return false
        for (x in v) if (x !is String) return false
        return true
    }

    private fun sortUniq(xs: Any?): List<String> {
        val s = TreeSet<String>()
        if (xs is List<*>) for (x in xs) s.add(x as String)
        return ArrayList(s)
    }

    /**
     * Is this def's confirmation valid? True only if: state is `confirmed`; the attestation covers THIS def digest and an accepted
     * registry digest; its final traits are the def's declared traits; the signer is pinned with the `reviewer` role (and not as a
     * machine key) and the timestamp is inside the key's validity; the signature verifies. Never throws. Returns `{ok: true, kid}` or
     * `{ok: false, reason, detail}`.
     */
    fun verifyAttestation(def: Map<String, Any?>, pins: Map<String, Any?>, registry: Map<String, Map<String, Any?>>): Map<String, Any?> {
        try {
            val pe = ActionConfirmation.reviewerPinsError(pins)
            if (pe != null) return fail("bad_pins", pe)
            val review = def["review"]
            if ("confirmed" != Jx.get(review, "state")) return fail("not_confirmed", "review.state is not confirmed")
            val ao = Jx.get(review, "attestation")
            if (!Jx.has(review, "attestation")) return fail("no_attestation", "a confirmed def carries an attestation")
            val a = Jx.m(ao)
            if (a["sig"] !is String) return fail("no_signature", "the attestation is unsigned")
            if (a["facts_digest"] !is String) return fail("malformed", "the attestation facts_digest must be a string")
            // shape before meaning: a missing / null / "" final_traits must not read as "no traits" for a read def
            var dismissedOk = a["dismissed"] is List<*>
            if (dismissedOk) for (d in Jx.a(a["dismissed"])) if (d !is Map<*, *> || Jx.m(d)["trait"] !is String || Jx.m(d)["reason"] !is String) { dismissedOk = false; break }
            if (!strings(a["final_traits"]) || !dismissedOk || !Jx.isInt(a["ts"]) || a["reviewer_kid"] !is String)
                return fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed")
            if (Actions.defDigest(def) != a["def_digest"]) return fail("digest_mismatch", "the def changed after it was reviewed")
            val accepted = LinkedHashSet<Any?>()
            accepted.add(Actions.traitsDigest(registry))
            if (pins["traits_digests"] is List<*>) accepted.addAll(Jx.a(pins["traits_digests"]))
            if (!accepted.contains(a["traits_digest"])) return fail("traits_digest_mismatch", "the trait registry changed since the review")
            if (sortUniq(a["final_traits"]) != sortUniq(def["traits"])) return fail("final_traits_mismatch", "the attested final traits are not the def's declared traits")
            val fin = LinkedHashSet<Any?>(Jx.a(a["final_traits"]))
            for (d in Jx.a(a["dismissed"])) if (fin.contains(Jx.m(d)["trait"]) || ActionConfirmation.blankReason(Jx.m(d)["reason"] as String)) return fail("dismissed_conflict", "a dismissed trait is also final, or has no reason")
            var key: Map<String, Any?>? = null
            for (k in Jx.a(pins["keys"])) if (a["reviewer_kid"] == Jx.m(k)["kid"]) { key = Jx.m(k); break }
            if (key == null) return fail("unknown_reviewer", "no pinned key '" + a["reviewer_kid"] + "'")
            if (!Jx.a(key["roles"]).contains("reviewer")) return fail("not_a_reviewer", "key '" + key["kid"] + "' does not hold the reviewer role")
            val ts = Jx.num(a["ts"])!!
            if ((key.containsKey("not_before") && ts < Jx.num(key["not_before"])!!) || (key.containsKey("not_after") && ts > Jx.num(key["not_after"])!!)) return fail("outside_validity", "the attestation time is outside the key validity")
            val body = LinkedHashMap<String, Any?>(a)
            body.remove("sig")
            return if (Pca.verifyB64u(key["pk"] as String?, ActionConfirmation.reviewMessage(body), a["sig"] as String?))
                Jx.obj("ok", true, "kid", key["kid"]) else fail("bad_signature", "the attestation signature is invalid")
        } catch (e: RuntimeException) {
            return fail("malformed", e.message.toString())
        }
    }

    /** The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed). */
    fun reviewStatus(def: Map<String, Any?>, pins: Map<String, Any?>, registry: Map<String, Map<String, Any?>>): Any? {
        if (def["review"] == null) throw IllegalArgumentException("Cannot read properties of undefined (reading 'state')")
        val st = Jx.get(def["review"], "state")
        if ("confirmed" != st) return st
        return if (verifyAttestation(def, pins, registry)["ok"] == true) "confirmed" else "stale"
    }

    /** Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped). Others are returned as they are. */
    fun revertStale(def: Map<String, Any?>, pins: Map<String, Any?>, registry: Map<String, Map<String, Any?>>): Map<String, Any?> {
        if ("stale" != reviewStatus(def, pins, registry)) return def
        val review = LinkedHashMap<String, Any?>(Jx.m(def["review"]))
        review.remove("attestation")
        review["state"] = "unreviewed"
        val out = LinkedHashMap<String, Any?>(def)
        out["review"] = review
        return out
    }

    // ---- review view and confirm ----

    private val SUSPECT = listOf("pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication")
    private val NEXT = listOf("pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence")

    /** The profile the def would have once reviewed (its own facts and traits, without the review marker that every unreviewed def shares). */
    private fun intrinsic(def: Map<String, Any?>, registry: Map<String, Map<String, Any?>>): Map<String, Any?> =
        Jx.m(ActionEffective.effective(def, registry, null)["hint"])

    /** Review queue priority: 0 = a core suspect trait, 1 = other risky, 2 = the rest. Lower first. */
    fun reviewPriority(def: Map<String, Any?>, registry: Map<String, Map<String, Any?>>): Int {
        val cl = LinkedHashSet<Any?>(Jx.a(intrinsic(def, registry)["closure"]))
        for (t in SUSPECT) if (cl.contains(t)) return 0
        for (t in NEXT) if (cl.contains(t)) return 1
        return 2
    }

    private class Row(val def: Map<String, Any?>, val prio: Int, val risk: Double)

    /** Defs in review order: suspect traits first, then by risk (highest first), then by verb. Deterministic. */
    fun reviewQueueOrder(defs: List<Map<String, Any?>>, registry: Map<String, Map<String, Any?>>): List<Map<String, Any?>> {
        val rows = ArrayList<Row>()
        for (d in defs) rows.add(Row(d, reviewPriority(d, registry), Jx.num(Jx.m(intrinsic(d, registry)["eff"])["risk"])!!))
        // stable, like the reference sort
        val sorted = rows.sortedWith { x, y ->
            val p = x.prio.compareTo(y.prio)
            if (p != 0) p else {
                val r = y.risk.compareTo(x.risk)
                if (r != 0) r else Jx.m(x.def)["verb"].toString().compareTo(Jx.m(y.def)["verb"].toString())
            }
        }
        val out = ArrayList<Map<String, Any?>>()
        for (r in sorted) out.add(r.def)
        return out
    }

    /** Traits implied by the def's own facts (effects, roles, tags, scope, reversibility). */
    internal fun impliedTraits(def: Map<String, Any?>): List<String> {
        val n = Actions.normalize(def)
        val ps = ArrayList<Map<String, Any?>>()
        for (p in Jx.m(n["params"]).values) ps.add(Jx.m(p))
        return Actions.impliedFromFacts(Jx.a(n["effects"]), ps, Jx.m(n["resource"])["scope"] as String?, Actions.worstReversibility(n["reversibility"], Jx.m(n["params"]) as Map<String, Map<String, Any?>>))
    }

    /** The reviewer's view of a def: facts, implied and suggested traits, the effective profile, the policy card, what changed since [previous]. */
    @JvmOverloads
    fun prepareReview(def: Map<String, Any?>, registry: Map<String, Map<String, Any?>>, previous: Map<String, Any?>? = null): Map<String, Any?> {
        val eff = ActionEffective.effective(def, registry, null)
        // the card shows what the reviewer would be signing (the hint), not the all-traits view that applies until they sign
        val shown = LinkedHashMap<String, Any?>(eff)
        shown.putAll(Jx.m(eff["hint"]))
        shown["confirmed"] = true
        val sbo = Jx.get(def["review"], "suggested_by")
        val added = Jx.get(sbo, "added")
        val changes = ArrayList<Any?>()
        if (previous != null) {
            val a = strip(previous)
            val b = strip(def)
            val ks = TreeSet<String>(a.keys)
            ks.addAll(b.keys)
            for (k in ks) if (!Jx.sameJsonMember(a, b, k)) changes.add(k)
        }
        return Jx.obj(
            "verb", def["verb"], "def_digest", Actions.defDigest(def), "state", Jx.get(def["review"], "state"),
            "declared_traits", ArrayList<Any?>(sortUniq(def["traits"])), "implied_traits", ArrayList<Any?>(impliedTraits(def)),
            "suggested", added ?: Jx.obj("traits", ArrayList<Any?>(), "roles", LinkedHashMap<String, Any?>(), "tags", LinkedHashMap<String, Any?>()),
            "effective", eff, "card", ActionDerive.cardOf(def, shown, registry), "changes", changes, "priority", Jx.n(reviewPriority(def, registry).toLong()),
        )
    }

    private fun strip(d: Map<String, Any?>): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>(d)
        for (k in listOf("review", "examples", "source", "since")) o.remove(k)
        return o
    }

    /**
     * Review one def: validates the decision, writes the final traits, signs an attestation over the resulting digest and returns the
     * confirmed def. Throws ActionKitError (`bad_confirm`, `undismissed_suggestion`, `not_reviewer`) rather than guessing.
     *
     * @param pins when not null, the reviewer must be pinned with the `reviewer` role under this key
     * @param finalTraits the final DECLARED trait set (the reviewer's decision)
     * @param dismissed `[{trait, reason}]` or null: every suggested trait left out of the final set needs a reason
     * @param ts seconds, a non-negative safe integer
     */
    fun confirmDef(
        def: Map<String, Any?>, registry: Map<String, Map<String, Any?>>, reviewerKid: String, reviewerSecret: ByteArray, pins: Map<String, Any?>?,
        finalTraits: List<Any?>, dismissed: List<Any?>?, ts: Any?,
    ): Map<String, Any?> {
        if (!Jx.isInt(ts) || Jx.num(ts)!! < 0) throw ActionKitError("bad_confirm", "ts must be a non-negative integer")
        val fin: List<Any?> = sortUniq(finalTraits)
        if (fin.size != finalTraits.size) throw ActionKitError("bad_confirm", "final traits must be distinct")
        for (t0 in fin) {
            val t = t0 as String
            if (!TRAIT_ID_RE.matches(t) || !registry.containsKey(t)) throw ActionKitError("bad_confirm", "unknown trait '$t'")
            if (t == "pca.unreviewed") throw ActionKitError("bad_confirm", "'pca.unreviewed' is the review marker, not a final trait")
        }
        // copied: a batch shares one dismissal list across defs
        val dis = ArrayList<Any?>()
        if (dismissed != null) for (d in dismissed) dis.add(Jx.obj("trait", Jx.get(d, "trait"), "reason", Jx.get(d, "reason")))
        val dset = LinkedHashSet<Any?>()
        for (d in dis) {
            val reason = Jx.get(d, "reason")
            val trait = Jx.get(d, "trait")
            if (reason !is String || Jx.jsTrim(reason).isEmpty() || reason.length > 256) throw ActionKitError("bad_confirm", "dismissed trait '" + Jx.jsStr(trait) + "' needs a reason (1..256 characters)")
            if (dset.contains(trait)) throw ActionKitError("bad_confirm", "trait '" + Jx.jsStr(trait) + "' is dismissed twice")
            dset.add(trait)
            if (fin.contains(trait)) throw ActionKitError("bad_confirm", "trait '" + Jx.jsStr(trait) + "' is both final and dismissed")
        }
        // what the reviewer was shown: the importer's and the suggesters' traits, plus what the def already declares
        val sbAdded = Jx.get(Jx.get(def["review"], "suggested_by"), "added")
        val shownAll = ArrayList<Any?>()
        if (def["traits"] is List<*>) shownAll.addAll(Jx.a(def["traits"]))
        if (Jx.get(sbAdded, "traits") is List<*>) shownAll.addAll(Jx.a(Jx.get(sbAdded, "traits")))
        val shown = sortUniq(shownAll)
        val seed = ArrayList<Any?>(fin)
        seed.addAll(impliedTraits(def))
        val covered = LinkedHashSet<String>(Actions.closure(registry, sortUniq(seed)))
        for (t in shown) {
            if (fin.contains(t) || covered.contains(t)) continue
            if (!dset.contains(t)) throw ActionKitError("undismissed_suggestion", "trait '$t' was suggested and is not in the final set: record it as dismissed with a reason")
        }
        for (t in dset) if (!(shown as List<Any?>).contains(t)) throw ActionKitError("bad_confirm", "trait '" + Jx.jsStr(t) + "' was never suggested; nothing to dismiss")
        if (pins != null) {
            val pe = ActionConfirmation.reviewerPinsError(pins)
            if (pe != null) throw ActionKitError("bad_confirm", pe)
            var key: Map<String, Any?>? = null
            for (k in Jx.a(pins["keys"])) if (reviewerKid == Jx.m(k)["kid"]) { key = Jx.m(k); break }
            if (key == null || !Jx.a(key["roles"]).contains("reviewer")) throw ActionKitError("not_reviewer", "key '$reviewerKid' is not pinned with the reviewer role")
            if (Keys.edFromSeed(reviewerSecret).id() != key["pk"]) throw ActionKitError("not_reviewer", "the secret does not belong to the pinned key '$reviewerKid'")
        }
        val body = LinkedHashMap<String, Any?>(def)
        if (fin.isEmpty()) body.remove("traits") else body["traits"] = ArrayList<Any?>(fin)
        val digest = Actions.defDigest(body)
        // the facts of the verb this definition publishes: the verifier will recompute them from the schema and compare
        val verb = Jx.m(ActionDerive.toSchemaVerb(body, registry, null)["verb"])
        val att = ActionConfirmation.signReview(
            Jx.obj(
                "def_digest", digest, "traits_digest", Actions.traitsDigest(registry), "facts_digest", ActionConfirmation.factsDigest(verb),
                "final_traits", ArrayList<Any?>(fin), "dismissed", dis, "reviewer_kid", reviewerKid, "ts", ts,
            ),
            reviewerSecret,
        )
        val review = LinkedHashMap<String, Any?>(Jx.m(def["review"]))
        review["state"] = "confirmed"
        review["attestation"] = att
        val out = LinkedHashMap<String, Any?>(body)
        out["review"] = review
        val bad = Actions.validateDef(out)
        if (bad != null) throw ActionKitError("bad_confirm", "the confirmed def is invalid: $bad")
        return out
    }
}
