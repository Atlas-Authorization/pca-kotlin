package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The signed human confirmation of an action: the only thing that can set an action's effective trait set below the top of the
 * registry ("unconfirmed means maximally dangerous"). Signing, and the verifier's view of a confirmation on a schema verb.
 */
@Suppress("UNCHECKED_CAST")
object ActionConfirmation {
    const val REVIEW_DOMAIN: String = "atlas-pca/action-review/v2"
    const val VERB_FACTS_DOMAIN: String = "atlas-pca/action-verb-facts/v1"
    @JvmField val KEY_ROLES: List<String> = listOf("reviewer", "importer", "model", "publisher")

    private fun jsSpace(c: Char): Boolean = J.jsSpace(c) || (c.code in 0x1c..0x1f)

    /** A dismissal reason with no content: only white space (which, as in Java's isWhitespace / isSpaceChar, includes U+001C..U+001F). */
    fun blankReason(s: String): Boolean {
        for (c in s) if (!jsSpace(c)) return false
        return true
    }

    /** The verb as published minus the members a confirmation decides or carries, hashed with its domain. */
    fun factsDigest(verb: Map<String, Any?>): String = Actions.factsDigest(verb)

    /** Null if the pin set is sound (distinct kids, canonical keys, known roles, no key both reviewer and machine). */
    fun reviewerPinsError(pins: Any?): String? = Actions.reviewerPinsError(pins)

    /** The bytes a reviewer signs: `REVIEW_DOMAIN \0` then the strict canonical body. */
    fun reviewMessage(b: Map<String, Any?>): ByteArray {
        val dis = ArrayList(J.a(b["dismissed"]))
        dis.sortWith { x, y -> (J.get(x, "trait") as String).compareTo(J.get(y, "trait") as String) }
        val dm = ArrayList<Any?>()
        for (d in dis) dm.add(J.obj("trait", J.get(d, "trait"), "reason", J.get(d, "reason")))
        val body = J.obj(
            "def_digest", b["def_digest"], "traits_digest", b["traits_digest"], "facts_digest", b["facts_digest"],
            "final_traits", J.objs(J.sortUniq(b["final_traits"])), "dismissed", dm, "reviewer_kid", b["reviewer_kid"], "ts", b["ts"],
        )
        val dom = (REVIEW_DOMAIN + "\u0000").toByteArray(Charsets.UTF_8)
        val bd = Json.canonicalizeStrict(body).toByteArray(Charsets.UTF_8)
        return dom + bd
    }

    /** Sign a review body (`def_digest, traits_digest, facts_digest, final_traits, dismissed, reviewer_kid, ts`) with an Ed25519 seed. */
    fun signReview(b: Map<String, Any?>, secret: ByteArray): Map<String, Any?> {
        val norm = LinkedHashMap(b)
        norm["final_traits"] = J.objs(J.sortUniq(b["final_traits"]))
        val dis = ArrayList(J.a(b["dismissed"]))
        dis.sortWith { x, y -> if ((J.get(x, "trait") as String).compareTo(J.get(y, "trait") as String) < 0) -1 else 1 }
        norm["dismissed"] = dis
        val out = LinkedHashMap<String, Any?>(norm)
        out["sig"] = Keys.b64u(Keys.edFromSeed(secret).sign(reviewMessage(norm)))
        return out
    }

    /**
     * Null iff the verb carries a VALID human confirmation: an attestation over exactly the def digest the verb names, against an accepted
     * trait registry digest, whose final traits are carried by the verb, signed by a key pinned with the reviewer role inside its validity
     * window. Anything else is a reason string and the verb is UNCONFIRMED. Never throws.
     */
    fun verbConfirmationError(v: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, pins: Any?): String? {
        try {
            if (pins == null) return "no reviewer keys are pinned"
            val pe = reviewerPinsError(pins)
            if (pe != null) return "bad pins: $pe"
            if (!v.containsKey("confirmation")) return "no confirmation"
            val a = v["confirmation"]
            if (a !is Map<*, *> && a !is List<*>) return "confirmation is not an object" // an array is an object in the reference: it has no members
            val am: Map<String, Any?> = if (a is Map<*, *>) J.m(a) else emptyMap()
            if (am["sig"] !is String) return "the confirmation is unsigned"
            if (v["def"] !is String || v["def"] != am["def_digest"]) return "the confirmation covers a different def digest"
            val accepted = HashSet<Any?>()
            accepted.add(Actions.traitsDigest(reg))
            val extra = J.get(pins, "traits_digests")
            if (extra is List<*>) accepted.addAll(extra)
            if (!accepted.contains(am["traits_digest"])) return "the confirmation was made against a different trait registry"
            if (am["facts_digest"] !is String || am["facts_digest"] != factsDigest(v)) return "the verb facts differ from the facts the reviewer confirmed"
            if (am["final_traits"] !is List<*> || am["dismissed"] !is List<*> || !J.isInt(am["ts"]) || am["reviewer_kid"] !is String) return "malformed confirmation"
            val tr = v["traits"]
            val carried = HashSet<Any?>(if (tr is List<*>) tr else emptyList<Any?>())
            for (t in J.a(am["final_traits"])) if (t !is String || !carried.contains(t)) return "the verb does not carry every trait the reviewer signed"
            val fin = HashSet<Any?>(J.a(am["final_traits"]))
            for (d in J.a(am["dismissed"])) {
                val tt = J.get(d, "trait")
                val rr = J.get(d, "reason")
                if (tt !is String || rr !is String || fin.contains(tt) || blankReason(rr)) return "a dismissed trait is also final, or has no reason"
            }
            var key: Map<String, Any?>? = null
            for (k in J.a(J.get(pins, "keys"))) if (J.get(k, "kid") == am["reviewer_kid"]) { key = J.m(k); break }
            if (key == null) return "no pinned key '${am["reviewer_kid"]}'"
            if (!J.a(key["roles"]).contains("reviewer")) return "key '${key["kid"]}' does not hold the reviewer role"
            val ts = J.num(am["ts"])!!
            if ((key.containsKey("not_before") && ts < J.num(key["not_before"])!!) || (key.containsKey("not_after") && ts > J.num(key["not_after"])!!)) return "the confirmation time is outside the key validity"
            val body = LinkedHashMap(am)
            body.remove("sig")
            val pk = Pca.decodeB64uStrict(key["pk"], 32)
            val sg = Pca.decodeB64uStrict(am["sig"], 64)
            return if (pk != null && sg != null && Pca.verifyB64u(key["pk"] as String, reviewMessage(body), am["sig"] as String)) null else "the confirmation signature is invalid"
        } catch (e: RuntimeException) {
            return "malformed confirmation: ${e.message}"
        }
    }
}
