package net.atlasauth.pca.research

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.StoreJs

/**
 * The behavioural immune system: the per-principal risk baseline, the observation fold ([observe]), the state validation and the threat
 * read ([assess]), the adaptation of a base policy to a threat ([adapt]) with its no-widen check, signed tightening proposals and a durable
 * store. A heuristic (EWMA and z-score over one principal's history): it can be gamed by a slow attacker who drifts the baseline and is no
 * proof that an agent is compromised or benign.
 *
 * An immune state is `{baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}`; an observation is `{r, at, stepUp?, denied?}`.
 */
@Suppress("UNCHECKED_CAST")
object Immune {
    private const val MAX_COUNT = 1e9

    /** The tuning of the observation fold and the threat read: the EWMA weight of the newest sample, the half life of the step-up and deny counters, and the values at which each signal saturates to 1. */
    class Config @JvmOverloads constructor(
        @JvmField val alpha: Double = 0.3, @JvmField val halfLifeMs: Double = 3_600_000.0,
        @JvmField val driftZSat: Double = 3.0, @JvmField val stepUpSat: Double = 5.0, @JvmField val denySat: Double = 3.0,
    )

    /** The reference tuning. */
    @JvmField val DEFAULT_CONFIG = Config()

    // ---- JavaScript value semantics over parsed JSON ----
    private fun n(d: Double): Json.Num = StoreJs.num(d)
    private fun n(l: Long): Json.Num = StoreJs.num(l)
    private fun isNum(x: Any?): Boolean = IntentJs.num(x)?.let { !it.isNaN() } == true
    private fun isFinite(x: Any?): Boolean = IntentJs.isFinite(x)
    private fun d(x: Any?): Double = IntentJs.num(x)!!
    private fun obj(): MutableMap<String, Any?> = LinkedHashMap()
    private fun map(o: Any?): MutableMap<String, Any?>? = o as? MutableMap<String, Any?>

    private fun str(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val x = IntentJs.num(v)
        if (x != null) return AttestUtil.jsNumString(x)
        if (v is List<*>) return v.joinToString(",") { if (it == null) "" else str(it) }
        return "[object Object]"
    }

    /** JavaScript `x.toFixed(digits)` (exact decimal expansion, ties away from zero on the magnitude). */
    private fun toFixed(x: Double, digits: Int): String {
        if (x.isNaN()) return "NaN"
        if (x.isInfinite()) return if (x > 0) "Infinity" else "-Infinity"
        if (Math.abs(x) >= 1e21) return AttestUtil.jsNumString(x)
        val s = BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString()
        return (if (x < 0) "-" else "") + s // like JavaScript, a negative value that rounds to zero keeps its sign
    }

    private fun truthy(v: Any?): Boolean {
        if (v == null) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        val x = IntentJs.num(v) ?: return true
        return !(x == 0.0 || x.isNaN())
    }

    // ---- state ----

    /** The empty baseline `{n: 0, mean: 0, m2: 0}`. */
    @JvmStatic
    fun emptyBaseline(): Map<String, Any?> {
        val b = obj()
        b["n"] = n(0L)
        b["mean"] = n(0L)
        b["m2"] = n(0L)
        return b
    }

    /** The state of a principal with no history. */
    @JvmStatic
    fun initialState(): Map<String, Any?> {
        val s = obj()
        s["baseline"] = emptyBaseline()
        s["ewma"] = n(0L)
        s["stepUps"] = n(0L)
        s["denies"] = n(0L)
        s["lastAt"] = n(0L)
        s["seeded"] = false
        return s
    }

    /** Welford update of a baseline with one risk sample (a non-finite sample counts as 0). */
    @JvmStatic
    fun updateBaseline(b: Map<String, Any?>, r: Double): Map<String, Any?> {
        val x = if (r.isNaN() || r.isInfinite()) 0.0 else r
        val cnt = d(b["n"]) + 1
        val delta = x - d(b["mean"])
        val mean = d(b["mean"]) + delta / cnt
        val m2 = d(b["m2"]) + delta * (x - mean)
        val out = obj()
        out["n"] = n(cnt)
        out["mean"] = n(mean)
        out["m2"] = n(m2)
        return out
    }

    /** Population standard deviation of the baseline (0 until at least 2 samples). */
    @JvmStatic
    fun baselineStd(b: Map<String, Any?>): Double {
        val cnt = d(b["n"])
        return if (cnt >= 2) Math.sqrt(d(b["m2"]) / cnt) else 0.0
    }

    /** 2^(-1/1024) rounded to the nearest double (the decimal literal parses identically everywhere). */
    private const val DECAY_STEP = 0.9993233275026507

    /**
     * Exponential decay by a half-life from exactly rounded operations only (no pow, exp or log, which differ in the last digit between
     * platforms): the elapsed time is counted down to whole 1/1024ths of a half-life, and the factor is 0.5 multiplied floor(u / 1024) times and
     * then 2^(-1/1024) multiplied (u mod 1024) times, one multiplication at a time in that order.
     */
    private fun decay(count: Double, dtMs: Double, halfLifeMs: Double): Double {
        if (dtMs <= 0 || count == 0.0) return count
        val u = Math.floor((dtMs * 1024.0) / halfLifeMs)
        if (u.isNaN()) return Double.NaN
        if (u >= 1024.0 * 1100) return count * 0.0 // 0.5^1100 underflows
        val k = Math.floor(u / 1024.0)
        val m = (u - k * 1024.0).toLong()
        var f = 1.0
        for (i in 0 until k.toLong()) f *= 0.5
        for (i in 0 until m) f *= DECAY_STEP
        return count * f
    }

    /** Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters). */
    @JvmStatic
    @JvmOverloads
    fun observe(state: Map<String, Any?>, obs: Map<String, Any?>, cfg: Config = DEFAULT_CONFIG): Map<String, Any?> {
        val r = Math.max(0.0, Math.min(1.0, if (isFinite(obs["r"])) d(obs["r"]) else 0.0))
        val lastAt = d(state["lastAt"])
        val at = if (isFinite(obs["at"])) d(obs["at"]) else lastAt
        val seeded = state["seeded"] == true
        val dt = if (seeded) Math.max(0.0, at - lastAt) else 0.0
        val baseline = updateBaseline(map(state["baseline"])!!, r)
        val ewma = if (seeded) cfg.alpha * r + (1 - cfg.alpha) * d(state["ewma"]) else r
        val stepUps = decay(d(state["stepUps"]), dt, cfg.halfLifeMs) + (if (truthy(obs["stepUp"])) 1 else 0)
        val denies = decay(d(state["denies"]), dt, cfg.halfLifeMs) + (if (truthy(obs["denied"])) 1 else 0)
        val s = obj()
        s["baseline"] = baseline
        s["ewma"] = n(ewma)
        s["stepUps"] = n(stepUps)
        s["denies"] = n(denies)
        s["lastAt"] = n(at)
        s["seeded"] = true
        return s
    }

    private fun inRange(x: Any?, lo: Double, hi: Double): Boolean = isFinite(x) && d(x) >= lo && d(x) <= hi

    private fun isInteger(x: Any?): Boolean = d(x).let { it == Math.floor(it) }

    private fun negZero(x: Any?): Boolean = d(x).let { it == 0.0 && 1 / it < 0 }

    /** The reason a state is malformed (non-finite, negative, out of bound), or null. */
    @JvmStatic
    fun validateImmuneState(s: Any?): String? {
        if (s is List<*>) return "baseline missing" // an array is an object to the reference, with no baseline member
        val x = map(s) ?: return "state must be an object"
        val b = map(x["baseline"]) ?: return "baseline missing"
        if (!inRange(b["n"], 0.0, MAX_COUNT) || !isInteger(b["n"]) || negZero(b["n"])) return "baseline.n must be an integer in [0, 1e9]"
        if (!inRange(b["mean"], 0.0, 1.0)) return "baseline.mean must be in [0, 1]"
        if (!inRange(b["m2"], 0.0, MAX_COUNT)) return "baseline.m2 must be finite and >= 0"
        if (!inRange(x["ewma"], 0.0, 1.0)) return "ewma must be in [0, 1]"
        if (!inRange(x["stepUps"], 0.0, MAX_COUNT)) return "stepUps must be finite and >= 0"
        if (!inRange(x["denies"], 0.0, MAX_COUNT)) return "denies must be finite and >= 0"
        if (!inRange(x["lastAt"], 0.0, 9007199254740991.0)) return "lastAt must be a finite non-negative time"
        if (x["seeded"] !is Boolean) return "seeded must be a boolean"
        return null
    }

    private fun clamp01(x: Double): Double = Math.max(0.0, Math.min(1.0, x))

    /**
     * The current threat from the immune state: `{level: calm|elevated|high, score, signals, components: {drift, volatility, violation}}`.
     * The score is the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A malformed state is
     * the maximal threat.
     */
    @JvmStatic
    @JvmOverloads
    fun assess(state: Any?, cfg: Config = DEFAULT_CONFIG): Map<String, Any?> {
        val bad = validateImmuneState(state)
        if (bad != null) return threat("high", 1.0, listOf("invalid immune state: $bad"), 1.0, 1.0, 1.0)
        val st = map(state)!!
        val base = map(st["baseline"])!!
        val std = baselineStd(base)
        val signals = ArrayList<String>()
        var drift = 0.0
        if (d(base["n"]) >= 5 && std > 1e-9) {
            val z = (d(st["ewma"]) - d(base["mean"])) / std
            drift = clamp01(z / cfg.driftZSat)
            if (drift > 0.33) signals.add("risk drifted " + toFixed(z, 1) + "σ above baseline")
        }
        val stepUps = d(st["stepUps"])
        val denies = d(st["denies"])
        val volatility = clamp01(stepUps / cfg.stepUpSat)
        if (volatility > 0.33) signals.add("elevated step-up rate (" + toFixed(stepUps, 1) + ")")
        val violation = clamp01(denies / cfg.denySat)
        if (violation > 0.33) signals.add("repeated policy violations (" + toFixed(denies, 1) + ")")
        val score = Math.max(drift, Math.max(volatility, violation))
        return threat(if (score >= 0.66) "high" else if (score >= 0.33) "elevated" else "calm", score, signals, drift, volatility, violation)
    }

    private fun threat(level: String, score: Double, signals: List<String>, drift: Double, volatility: Double, violation: Double): Map<String, Any?> {
        val t = obj()
        t["level"] = level
        t["score"] = n(score)
        t["signals"] = ArrayList<Any?>(signals)
        val c = obj()
        c["drift"] = n(drift)
        c["volatility"] = n(volatility)
        c["violation"] = n(violation)
        t["components"] = c
        return t
    }

    // ---- adaptation ----

    private fun num(x: Any?): Double = StoreJs.dbl(x) ?: Double.NaN

    /** JavaScript ToNumber of the member [k] of [m]: an absent member is undefined (NaN), null is 0, a boolean 0/1, a string its numeric reading (blank 0, else NaN). */
    private fun jsNum(m: Map<String, Any?>, k: String): Double {
        if (!m.containsKey(k)) return Double.NaN
        val v = m[k]
        if (v == null) return 0.0
        if (v is Boolean) return if (v) 1.0 else 0.0
        StoreJs.dbl(v)?.let { return it }
        if (v is String) {
            val t = v.trim { it.isWhitespace() || it == '\uFEFF' }
            if (t.isEmpty()) return 0.0
            return if (Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?").matches(t)) t.toDouble() else Double.NaN
        }
        return Double.NaN
    }

    /** The adapted policy for a threat assessment, derived from the BASE policy (never compounded): `{policy, changed, rationale}`. Default caps: kappa x3, theta x0.4. */
    @JvmStatic
    @JvmOverloads
    fun adapt(baseIn: Any?, assessment: Map<String, Any?>, maxKappaMult: Double = 3.0, minThetaMult: Double = 0.4): Map<String, Any?> {
        val base: Map<String, Any?> = if (baseIn is Map<*, *>) map(baseIn)!! else obj() // a non-object spreads to nothing
        val s = if (isFinite(assessment["score"])) clamp01(d(assessment["score"])) else 1.0 // a non-finite score is the worst case, never calm
        if (s == 0.0) return adaptation(baseIn, false, "calm — baseline policy")
        if (baseIn == null) throw IllegalArgumentException("base policy missing")
        val kappaMult = 1 + (maxKappaMult - 1) * s
        val thetaMult = 1 - (1 - minThetaMult) * s
        val policy = LinkedHashMap<String, Any?>(base)
        val w = map(base["weights"])
        policy["weights"] = if (w == null) obj() else LinkedHashMap<String, Any?>(w)
        policy["kappa"] = n(jsNum(base, "kappa") * kappaMult)
        policy["theta1"] = n(clamp01(jsNum(base, "theta1") * thetaMult))
        policy["theta2"] = n(clamp01(jsNum(base, "theta2") * thetaMult))
        var bad = Authorize.riskPolicyError(policy)
        if (bad == null) bad = noWidenViolation(base, policy)
        if (bad != null) return adaptation(baseIn, false, "adaptation rejected ($bad) — kept baseline")
        val sig = assessment["signals"] as List<*>
        val why = if (sig.isNotEmpty()) sig.joinToString("; ") { str(it) } else "threat score " + toFixed(s, 2)
        return adaptation(policy, true, str(assessment["level"]) + ": " + why + " → κ ×" + toFixed(kappaMult, 2) + ", θ ×" + toFixed(thetaMult, 2))
    }

    private fun adaptation(policy: Any?, changed: Boolean, rationale: String): Map<String, Any?> {
        val a = obj()
        a["policy"] = policy
        a["changed"] = changed
        a["rationale"] = rationale
        return a
    }

    private fun same(a: Any?, b: Any?): Boolean {
        val x = StoreJs.dbl(a)
        val y = StoreJs.dbl(b)
        return if (x != null && y != null) x == y else a == b
    }

    /** Why [adapted] is looser than [base], or null when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as looser. */
    @JvmStatic
    fun noWidenViolation(base: Map<String, Any?>, adapted: Map<String, Any?>): String? {
        // null and booleans coerce to numbers in a relational comparison: a value that is not a number is a violation before any comparison
        if (!(IntentJs.isNumber(adapted["kappa"]) && IntentJs.isNumber(adapted["theta1"]) && IntentJs.isNumber(adapted["theta2"]))) return "kappa and theta must be numbers"
        if (!(jsNum(adapted, "kappa") >= jsNum(base, "kappa"))) return "kappa decreased"
        if (!(jsNum(adapted, "theta1") <= jsNum(base, "theta1"))) return "theta1 increased"
        if (!(jsNum(adapted, "theta2") <= jsNum(base, "theta2"))) return "theta2 increased"
        for (k in listOf("lambda", "rho", "bMax")) if (!same(adapted[k], base[k])) return "$k changed"
        val bw = map(base["weights"]) ?: throw IllegalArgumentException("base.weights missing")
        val aw = map(adapted["weights"]) ?: throw IllegalArgumentException("adapted.weights missing")
        for (k in bw.keys) if (!same(aw[k], bw[k])) return "weights.$k changed"
        return null
    }

    /** Throws unless [adapted] only tightens [base]. */
    @JvmStatic
    fun assertNoWiden(base: Map<String, Any?>, adapted: Map<String, Any?>) {
        val v = noWidenViolation(base, adapted)
        if (v != null) throw IllegalStateException("immune: adaptation widens the policy ($v)")
    }

    // ---- signed tightening proposals ----

    const val TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\u0000"

    private fun tighteningMessage(claim: Map<String, Any?>): ByteArray =
        TIGHTENING_DOMAIN.toByteArray(Charsets.UTF_8) + Json.canonicalize(claim).toByteArray(Charsets.UTF_8)

    @JvmStatic
    fun policyDigest(policy: Map<String, Any?>): String = StoreJs.hashLenient(policy)

    @JvmStatic
    fun immuneStateDigest(state: Map<String, Any?>): String = StoreJs.hashLenient(state)

    /**
     * Derive and sign the tightening for [state]; throws on a malformed base, an epoch that is not an integer >= 1, a non-finite [now] or a
     * malformed state (never an unsigned loosening). [guardianSecret] is the 32-byte Ed25519 seed.
     */
    @JvmStatic
    fun issueTighteningProposal(base: Map<String, Any?>, state: Any?, epoch: Any?, now: Any?, guardianSecret: ByteArray): Map<String, Any?> {
        val bad = Authorize.riskPolicyError(base)
        if (bad != null) throw IllegalArgumentException("issueTighteningProposal: $bad")
        if (!IntentJs.isInt(epoch) || IntentJs.lng(epoch) < 1) throw IllegalArgumentException("issueTighteningProposal: epoch must be an integer >= 1")
        if (!isFinite(now)) throw IllegalArgumentException("issueTighteningProposal: now must be finite")
        val key = Keys.edFromSeed(guardianSecret)
        val ad = adapt(base, assess(state))
        val claim = obj()
        claim["v"] = n(1L)
        claim["base_digest"] = policyDigest(base)
        claim["state_digest"] = StoreJs.hashLenient(state)
        claim["epoch"] = epoch
        claim["issued_at"] = now
        claim["policy"] = ad["policy"]
        claim["rationale"] = ad["rationale"]
        claim["guardian"] = key.id()
        val p = LinkedHashMap<String, Any?>(claim)
        p["sig"] = Keys.b64u(key.sign(tighteningMessage(claim)))
        return p
    }

    private fun refused(reason: String): Map<String, Any?> {
        val o = obj()
        o["ok"] = false
        o["reason"] = reason
        return o
    }

    /**
     * Verify a proposal and return `{ok: true, policy, epoch}` or `{ok: false, reason}`; never throws. [o] holds the pinned `guardian`
     * (b64u, required), `lastEpoch`, `now`, `maxAgeMs` and optionally `state` (a recompute check).
     */
    @JvmStatic
    fun applyTightening(base: Map<String, Any?>?, p: Map<String, Any?>?, o: Map<String, Any?>): Map<String, Any?> = try {
        applyUnchecked(base, p, o)
    } catch (e: RuntimeException) {
        refused("malformed")
    }

    private fun applyUnchecked(base: Map<String, Any?>?, p: Map<String, Any?>?, o: Map<String, Any?>): Map<String, Any?> {
        if (p == null || !same(p["v"], n(1L)) || p["sig"] !is String || p["guardian"] !is String) return refused("malformed")
        if (o["guardian"] !is String || o["guardian"] != p["guardian"]) return refused("guardian")
        val claim = LinkedHashMap<String, Any?>(p)
        claim.remove("sig")
        if (!Pca.verifyB64u(p["guardian"] as String, tighteningMessage(claim), p["sig"] as String)) return refused("signature")
        val pol = map(p["policy"])
        if (base == null || Authorize.riskPolicyError(base) != null || Authorize.riskPolicyError(p["policy"]) != null) return refused("invalid-policy")
        if (p["base_digest"] != policyDigest(base)) return refused("base")
        val now = num(o["now"])
        val at = num(p["issued_at"])
        if (now.isNaN() || now.isInfinite() || at.isNaN() || at.isInfinite() || !(at <= now) || !(now - at <= jsNum(o, "maxAgeMs"))) return refused("stale")
        val epoch = p["epoch"]
        if (!IntentJs.isInt(epoch) || !(num(epoch) > jsNum(o, "lastEpoch"))) return refused("replayed-epoch")
        if (noWidenViolation(base, pol!!) != null) return refused("widens")
        val st = o["state"]
        if (truthy(st) && (p["state_digest"] != StoreJs.hashLenient(st) || policyDigest(map(adapt(base, assess(st))["policy"])!!) != policyDigest(pol))) return refused("state-mismatch")
        val ok = obj()
        ok["ok"] = true
        ok["policy"] = pol
        ok["epoch"] = epoch
        return ok
    }

    // ---- durable state ----

    /** Immune state and applied epoch for one subject over an atomic kv, so a restart keeps the history and the replay floor. */
    @JvmStatic
    fun createImmuneStore(kv: AtomicKv, subject: String): ImmuneStore = ImmuneStore(kv, subject)

    class ImmuneStore internal constructor(private val kv: AtomicKv, subject: String) {
        private val sKey = "immune/state/$subject"
        private val eKey = "immune/epoch/$subject"

        /** The stored state, or the initial one. */
        fun get(): Map<String, Any?>? {
            val v = kv.get(sKey)
            if (v === AtomicKv.JSON_NULL) return null // a stored JSON null is returned as it is, never read as absent
            return v?.let { map(it) } ?: initialState()
        }

        /** Folds one observation atomically; throws when the stored state is malformed (it is never silently reset to calm). */
        fun observe(obs: Map<String, Any?>): Map<String, Any?> = map(kv.update(sKey) { prev ->
            if (prev === AtomicKv.JSON_NULL) throw IllegalStateException("immune store: stored state invalid (state must be an object)")
            val cur = prev ?: initialState()
            val bad = validateImmuneState(cur)
            if (bad != null) throw IllegalStateException("immune store: stored state invalid ($bad)")
            Immune.observe(map(cur)!!, obs)
        })!!

        fun lastEpoch(): Long = kv.get(eKey).let { v -> if (isNum(v)) d(v).toLong() else 0L }

        /** Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. [o] is as for [applyTightening] without lastEpoch. */
        fun apply(base: Map<String, Any?>, p: Map<String, Any?>?, o: Map<String, Any?>): Map<String, Any?> {
            var out: Map<String, Any?> = refused("malformed")
            kv.update(eKey) { prev ->
                val oo = LinkedHashMap<String, Any?>(o)
                oo["lastEpoch"] = if (isNum(prev)) prev else n(0L)
                out = applyTightening(base, p, oo)
                if (out["ok"] == true) out["epoch"] else null
            }
            return out
        }
    }
}
