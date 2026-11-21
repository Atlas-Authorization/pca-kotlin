package net.atlasauth.pca.evidence

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca

/** The dispute-evidence replay helpers: the anchor leaf, the grant cap reader and the trust-input validators. */
object EvidenceVerify {
    const val EVIDENCE_REPORT_DOMAIN = "atlas-pca/intent-evidence-report/v1"
    const val INTENT_ANCHOR_DOMAIN = "atlas-pca/intent-anchor/v1"
    const val INTENT_ANCHOR_LOG = "pca-intent:v1"

    /** The intent-log leaf for an anchored artifact (the `intentAnchorCommit` construction, any kind). */
    fun anchorCommit(kind: String, digest: String): String =
        Pca.hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_ANCHOR_DOMAIN, "kind" to kind, "digest" to digest))

    private fun isGroup(c: Any?): Boolean = c is Map<*, *> && (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not"))

    private fun isLeaf(c: Any?): Boolean = c is Map<*, *> && !isGroup(c) && c["field"] is String

    private fun leafCaps(conds: Any?, path: String, out: MutableList<Double>) {
        if (conds == null) return
        if (conds is String) return // iterating a string yields characters, none of them a condition
        if (conds !is List<*>) throw JsTypeError("TypeError: conditions are not iterable")
        for (c in conds) {
            if (isLeaf(c)) {
                val m = c as Map<*, *>
                // `c.ref !== undefined`: a JSON null member is a defined value
                val value = Js.num(m["value"])
                if (path != m["field"] || m.containsKey("ref") || value == null) continue
                if ("lte" == m["op"]) out.add(value) else if ("lt" == m["op"]) out.add(value - 1)
            } else if (isGroup(c) && (c as Map<*, *>).containsKey("all_of")) {
                leafCaps(c["all_of"], path, out)
            }
        }
    }

    /**
     * The cap `env.acc.<id>.post <= v` the grant's envelope states for [verb]: per predicate the tightest bound in its `where`
     * (descending into `all_of`); across predicates the loosest. Null when a predicate admitting the verb states no bound, or none admits it.
     */
    fun capOf(grant: Any?, accId: String, verb: String): Double? {
        val env = Authorize.readEnvelope(grant) ?: return null
        val path = "env.acc.$accId.post"
        var cap: Double? = null
        for (p in env["predicates"] as List<*>) {
            val pv = Js.member(p, "verb")
            val verbs = ArrayList<String>()
            if (pv is List<*>) for (x in pv) verbs.add(Js.template(x)) else verbs.add(Js.template(pv))
            if (!verbs.contains(verb) && !verbs.contains("*")) continue
            val caps = ArrayList<Double>()
            leafCaps(Js.get(p, "where"), path, caps)
            if (caps.isEmpty()) return null
            var m = Double.POSITIVE_INFINITY
            for (d in caps) { if (d.isNaN()) { m = Double.NaN; break }; m = Math.min(m, d) }
            val cur = cap
            cap = if (cur == null) m else if (cur.isNaN() || m.isNaN()) Double.NaN else Math.max(cur, m)
        }
        return cap
    }

    /** Validate `trust.principals`: a non-empty array of closed {key, pq_pk?} with canonical keys. Null = valid. */
    fun principalsTrustError(p: Any?): String? {
        if (p !is List<*> || p.isEmpty()) return "trust.principals must be a non-empty array of {key, pq_pk?}"
        for (i in p.indices) {
            val x = p[i]
            if (x !is Map<*, *>) return "trust.principals[$i] must be an object {key, pq_pk?}"
            for (k in EvidenceBundle.jsKeys(x)) {
                if (k != "key" && k != "pq_pk") return "trust.principals[$i]: unknown member '$k'"
            }
            if (Pca.decodeB64uStrict(x["key"], 32) == null) return "trust.principals[$i].key must be canonical base64url (32 bytes)"
            if (x.containsKey("pq_pk") && Pca.decodeB64uStrict(x["pq_pk"], -1) == null) return "trust.principals[$i].pq_pk must be canonical base64url"
        }
        return null
    }

    /** Validate `trust.acc` like core `policy.acc`: closed members, non-negative safe integers. Null = valid. */
    fun accTrustError(a: Any?): String? {
        if (a !is Map<*, *>) return "trust.acc must be an object"
        for (k in EvidenceBundle.jsKeys(a)) {
            if (k != "max_receipt_age_s" && k != "max_keyset_age_s") return "trust.acc: unknown member '$k'"
            if (!EvidenceBundle.isNonNegInt(a[k])) return "trust.acc.$k must be a non-negative safe integer"
        }
        return null
    }

    /**
     * Replay a bundle (spec section 3.11). [trust] is the reader's trust input as a JSON tree (siteKeys, principals, minTier, typedValues,
     * credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, jitTier, sessionRootDigest); [verifiers] are the optional
     * ports keyed sessionRoot, schema, receipt, fact, classifier, offerSet, labels, effect, verdict, settlement. Never throws: a malformed
     * bundle is a report with a failed `shape` finding.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyEvidenceBundle(input: Any?, trust: Map<String, Any?>?, verifiers: Map<String, EvidenceReplay.Port>? = null): Map<String, Any?> =
        EvidenceReplay.verify(input, trust, verifiers)
}
