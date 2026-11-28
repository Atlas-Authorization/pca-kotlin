package net.atlasauth.pca.verifier

/**
 * Dead-man liveness beacons v2: a port of packages/pca/src/beacons.ts (verify, ref) and of the beacon decision of the verdict combinator.
 * A beacon is `{v, instance, scope, epoch, seq, issued_at, not_after, issuer, sig}` (plus `alg` / `pq_pk` / `pq_sig` for a post-quantum suite)
 * signed by a pinned issuer. Authority is live only while a valid beacon covers the moment; a PCActn binds one through its signed
 * `freshness.beacon_ref` (= [beaconRef]). Verification never throws: any failure is a refusal.
 */
@Suppress("UNCHECKED_CAST")
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
        for (k in listOf("v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer")) {
            // an absent member has no canonical form (the reference's undefined)
            if (!b.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            body[k] = b[k]
        }
        val suite = Pq.resolveSigAlg(b["alg"], b.containsKey("alg"))
        if (suite != null && suite.alg != "ed25519") {
            body["alg"] = suite.alg
            if (!b.containsKey("pq_pk")) throw IllegalArgumentException("canonicalize: unsupported type undefined") // a missing PQ key has no canonical form
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

    // ---- the reference's own surface: message, issuing, raw verification, acceptance, the frozen check, the durable acceptor ----

    private val J = net.atlasauth.pca.compliance.ComplianceJs

    /** The exact bytes a beacon signs: `"atlas-pca/beacon/v2\0" || strictCanonical({v, instance, scope, epoch, seq, issued_at, not_after, issuer} + alg, pq_pk for a non-ed25519 suite)`. */
    @JvmStatic fun livenessBeaconMessage(body: Any?): ByteArray = message(body as? Map<String, Any?> ?: throw IllegalArgumentException("Cannot read properties of ${if (body == null) "null" else "undefined"} (reading 'v')"))

    private fun isIntegerValue(x: Any?): Boolean = IntentJs.num(x)?.let { !it.isNaN() && !it.isInfinite() && it == Math.floor(it) } ?: false

    /**
     * Issue a beacon as `issuer` (Ed25519, ML-DSA-65 or hybrid). `seq` and `issuedAt` must be non-negative integers, `validityMs` (null: 300000) an integer in (0, 3600000];
     * `scope` (null: "*") and `instance` are carried as given (an absent instance, [net.atlasauth.pca.compliance.ComplianceJs.UNDEF], has no canonical form and throws).
     */
    @JvmStatic @JvmOverloads
    fun issueLivenessBeacon(issuer: Keys.SuiteKey, instance: Any?, seq: Any?, issuedAt: Any?, scope: Any? = null, validityMs: Any? = null): Map<String, Any?> {
        val validity = validityMs ?: Json.Num((5 * EPOCH_MS).toString())
        if (!isIntegerValue(seq) || IntentJs.num(seq)!! < 0) throw IllegalArgumentException("issueLivenessBeacon: seq must be a non-negative integer")
        if (!isIntegerValue(issuedAt) || IntentJs.num(issuedAt)!! < 0) throw IllegalArgumentException("issueLivenessBeacon: issuedAt must be an integer")
        val v = IntentJs.num(validity)
        if (!isIntegerValue(validity) || v!! <= 0 || v > MAX_VALIDITY_MS) throw IllegalArgumentException("issueLivenessBeacon: validity must be in (0, $MAX_VALIDITY_MS] ms")
        if (instance === J.UNDEF) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        val at = IntentJs.num(issuedAt)!!
        fun n(d: Double) = if (d == 0.0 && 1.0 / d < 0) Json.Num("-0") else Json.Num(J.numStr(d))
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Json.Num("2")
        body["instance"] = instance
        body["scope"] = scope ?: GLOBAL_SCOPE
        body["epoch"] = n(Math.floor(at / EPOCH_MS))
        body["seq"] = if (seq is Json.Num) seq else n(IntentJs.num(seq)!!)
        body["issued_at"] = if (issuedAt is Json.Num) issuedAt else n(at)
        body["not_after"] = n(at + v)
        body["issuer"] = (issuer.ed ?: throw IllegalArgumentException("issueLivenessBeacon: the issuer needs an Ed25519 identity")).id()
        return Issue.signArtifact(DOMAIN, body, issuer)
    }

    /** SameValueZero membership of `issuer` in a list of pinned issuers, or JavaScript's substring `includes` over a string; anything else cannot be searched. */
    private fun pinned(issuers: Any?, issuer: Any?): Boolean = when (issuers) {
        is List<*> -> issuers.any { ZkJs.strictEq(it, issuer) }
        is String -> issuers.contains(ZkJs.string(issuer))
        else -> throw IllegalArgumentException("o.issuers.includes is not a function")
    }

    /**
     * The reference's verdict over `check = {issuers, now, instance, scope?, pqPins?}` (decoded JSON, JavaScript comparison semantics): the shape and suite, the instance, the
     * pinned issuer, the signature (a PQ key only as pinned), integer window members, the hard maximum validity, the epoch, the freshness window and the scope. Never throws.
     * The legacy `allowUnboundPq` option is not offered.
     */
    @JvmStatic fun verifyLivenessBeacon(b: Any?, check: Any?): Verdict = try {
        val m = b as? Map<String, Any?>
        if (m == null || IntentJs.num(m["v"]) != 2.0 || Pq.resolveSigAlg(m["alg"], m.containsKey("alg")) == null) Verdict(false, "malformed beacon")
        else if (check == null) throw IllegalArgumentException("Cannot read properties of null (reading 'instance')")
        else if (!ZkJs.strictEq(ZkJs.get(m, "instance"), ZkJs.get(check, "instance"))) Verdict(false, "wrong instance")
        else if (!pinned(ZkJs.get(check, "issuers"), ZkJs.get(m, "issuer"))) Verdict(false, "issuer not pinned")
        else {
            val issuer = m["issuer"] as? String
            val pins = ZkJs.get(check, "pqPins") as? Map<String, Any?>
            if (!IntentJs.verifyPinnedSuite(m["alg"], m.containsKey("alg"), issuer, m["pq_pk"], message(m), m["sig"], m["pq_sig"], pins)) Verdict(false, "bad signature")
            else if (!listOf("epoch", "seq", "issued_at", "not_after").all { isIntegerValue(m[it]) } || IntentJs.num(m["seq"])!! < 0) Verdict(false, "malformed window")
            else {
                val issued = IntentJs.num(m["issued_at"])!!
                val notAfter = IntentJs.num(m["not_after"])!!
                val nowRaw = J.own(check, "now")
                val nowPlusSkew = if (nowRaw is String) J.toNumber(nowRaw + CLOCK_SKEW_MS.toString()) else J.toNumber(nowRaw) + CLOCK_SKEW_MS
                val scope = ZkJs.get(check, "scope")
                if (notAfter <= issued || notAfter - issued > MAX_VALIDITY_MS) Verdict(false, "validity exceeds the hard maximum")
                else if (IntentJs.num(m["epoch"])!! != Math.floor(issued / EPOCH_MS)) Verdict(false, "epoch does not match issued_at")
                else if (nowPlusSkew < issued) Verdict(false, "not yet valid")
                else if (!(J.toNumber(nowRaw) <= notAfter)) Verdict(false, "expired")
                else if (scope !== ZkJs.UNDEF && !ZkJs.strictEq(m["scope"], GLOBAL_SCOPE) && !ZkJs.strictEq(ZkJs.get(m, "scope"), scope)) Verdict(false, "scope not covered")
                else Verdict(true)
            }
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        Verdict(false, "malformed beacon")
    }

    /**
     * Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher `seq`. A beacon needs a non-negative safe-integer `seq` (negative zero refused). `prev`
     * is the previously accepted beacon (null: none); a replay names both sequences as the reference prints them.
     */
    @JvmStatic fun acceptBeacon(prev: Any?, next: Any?): Verdict {
        if (next !is Map<*, *> || !IntentJs.isNonNeg(next["seq"])) return Verdict(false, "malformed beacon")
        if (J.truthy(prev)) {
            val ps = if (prev is Map<*, *>) J.own(prev, "seq") else J.UNDEF
            val ns = IntentJs.num(next["seq"])!!
            if (!(ns > J.toNumber(ps))) return Verdict(false, "replayed beacon: seq ${J.numStr(ns)} <= ${J.tpl(ps)}")
        }
        return Verdict(true)
    }

    /** Frozen unless at least one beacon verifies for the check (absence is a freeze). */
    @JvmStatic fun isFrozenLiveness(beacons: Any?, check: Any?): Boolean {
        if (beacons !is List<*>) throw IllegalArgumentException("beacons.some is not a function")
        return beacons.none { verifyLivenessBeacon(it, check).ok }
    }

    /** The durable store key of a beacon's sequence slot: per (instance, scope, issuer). */
    @JvmStatic fun beaconKey(b: Map<String, Any?>): String = "beacon-seq/v1/" + net.atlasauth.pca.jose.Js.stringify(listOf(b["instance"], b["scope"], b["issuer"]))

    /**
     * Durable replay protection: keeps the highest accepted `seq` per (instance, scope, issuer) in an [AtomicKv] under one atomic read-modify-write, so a captured old beacon cannot
     * be replayed after a restart. FAIL CLOSED: a store that throws, or holds anything but a non-negative safe integer, refuses with `beacon state unavailable`.
     */
    class BeaconAcceptor internal constructor(private val kv: AtomicKv) {
        /** Verify `b` against `check` ([verifyLivenessBeacon]), then record its `seq` iff strictly above the stored one. Never throws. */
        fun accept(b: Any?, check: Any?): Verdict {
            val v = verifyLivenessBeacon(b, check)
            if (!v.ok) return v
            val m = b as Map<String, Any?>
            var replayOf: Any? = null
            var replay = false
            try {
                kv.update(beaconKey(m)) { prev ->
                    if (prev != null && !(IntentJs.isNonNeg(prev))) throw IllegalStateException("junk on disk")
                    if (prev != null && !(IntentJs.num(m["seq"])!! > IntentJs.num(prev)!!)) {
                        replayOf = prev
                        replay = true
                        null
                    } else m["seq"]
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Verdict(false, "beacon state unavailable")
            }
            return if (!replay) Verdict(true) else Verdict(false, "replayed beacon: seq ${J.tpl(m["seq"])} <= ${J.tpl(replayOf)}")
        }
    }

    /** A durable beacon acceptor over `kv`; throws when no store is given. */
    @JvmStatic fun createBeaconAcceptor(kv: AtomicKv?): BeaconAcceptor = BeaconAcceptor(kv ?: throw IllegalArgumentException("createBeaconAcceptor: a DurableKv is required"))

    /** The beacon decision: `not-enforced` | `rejected` | `replayed` | `unbound` | `pass`. */
    fun decision(supplied: Boolean, verifierOk: Boolean, replayed: Boolean, refBinds: Boolean): String = when {
        !supplied -> "not-enforced"
        !verifierOk -> "rejected"
        replayed -> "replayed"
        !refBinds -> "unbound"
        else -> "pass"
    }
}
