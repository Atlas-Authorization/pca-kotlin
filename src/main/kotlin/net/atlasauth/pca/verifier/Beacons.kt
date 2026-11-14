package net.atlasauth.pca.verifier

/**
 * Dead-man liveness beacons v2: a port of packages/pca/src/beacons.ts (verify, ref) and of the beacon decision of the verdict combinator.
 * A beacon is `{v, instance, scope, epoch, seq, issued_at, not_after, issuer, sig}` (plus `alg` / `pq_pk` / `pq_sig` for a post-quantum suite)
 * signed by a pinned issuer. Authority is live only while a valid beacon covers the moment; a PCActn binds one through its signed
 * `freshness.beacon_ref` (= [beaconRef]). Verification never throws: any failure is a refusal.
 */
object Beacons {
    const val GLOBAL_SCOPE = "*"
    const val EPOCH_MS = 60_000L
    const val MAX_VALIDITY_MS = 60L * 60_000L
    const val CLOCK_SKEW_MS = 30_000L
    private const val DOMAIN = "atlas-pca/beacon/v2\u0000"

    /** The beacon a host supplies for one request: the record, the pinned issuer keys, this instance, and the issuers' pinned PQ keys. */
    class Supplied @JvmOverloads constructor(val beacon: Map<String, Any?>, val issuers: List<String>, val instance: String, val pqPins: Map<String, Any?>? = null)

    class Verdict(val ok: Boolean, val reason: String? = null)

    private fun message(b: Map<String, Any?>): ByteArray {
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer")) body[k] = b[k]
        val suite = Pq.resolveSigAlg(b["alg"], b.containsKey("alg"))
        if (suite != null && suite.alg != "ed25519") {
            body["alg"] = suite.alg
            body["pq_pk"] = b["pq_pk"]
        }
        return Pca.concat(IntentJs.utf8(DOMAIN), IntentJs.canonBytes(body))
    }

    /** What the PCActn commits in `freshness.beacon_ref`. */
    fun beaconRef(b: Any?): String = Pca.hashCanonical(b)

    private fun isInteger(x: Any?): Boolean {
        val d = IntentJs.num(x) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.floor(d)
    }

    /** Signature, pinned issuer, instance and scope binding, the hard maximum validity and the freshness window. */
    fun verify(b: Any?, issuers: Any?, now: Long, instance: String?, scope: String? = null, pqPins: Map<String, Any?>? = null): Verdict = try {
        val m = b as? Map<String, Any?>
        if (m == null || !(IntentJs.num(m["v"]) == 2.0) || Pq.resolveSigAlg(m["alg"], m.containsKey("alg")) == null) Verdict(false, "malformed beacon")
        else if (m["instance"] != instance) Verdict(false, "wrong instance")
        else if (issuers !is List<*> || !issuers.contains(m["issuer"])) Verdict(false, "issuer not pinned")
        else {
            val issuer = m["issuer"] as? String
            val pq = PinnedPq.resolve(issuer, m["pq_pk"], pqPins = pqPins)
            if (!Pq.verifySuite(m["alg"], m.containsKey("alg"), issuer, pq, message(m), m["sig"], m["pq_sig"])) Verdict(false, "bad signature")
            else if (!listOf("epoch", "seq", "issued_at", "not_after").all { isInteger(m[it]) } || IntentJs.lng(m["seq"]) < 0) Verdict(false, "malformed window")
            else {
                val issued = IntentJs.lng(m["issued_at"])
                val notAfter = IntentJs.lng(m["not_after"])
                if (notAfter <= issued || notAfter - issued > MAX_VALIDITY_MS) Verdict(false, "validity exceeds the hard maximum")
                else if (IntentJs.lng(m["epoch"]) != Math.floorDiv(issued, EPOCH_MS)) Verdict(false, "epoch does not match issued_at")
                else if (now + CLOCK_SKEW_MS < issued) Verdict(false, "not yet valid")
                else if (now > notAfter) Verdict(false, "expired")
                else if (scope != null && m["scope"] != GLOBAL_SCOPE && m["scope"] != scope) Verdict(false, "scope not covered")
                else Verdict(true)
            }
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        Verdict(false, "malformed beacon")
    }

    /** The beacon decision: `not-enforced` | `rejected` | `replayed` | `unbound` | `pass`. */
    fun decision(supplied: Boolean, verifierOk: Boolean, replayed: Boolean, refBinds: Boolean): String = when {
        !supplied -> "not-enforced"
        !verifierOk -> "rejected"
        replayed -> "replayed"
        !refBinds -> "unbound"
        else -> "pass"
    }
}
