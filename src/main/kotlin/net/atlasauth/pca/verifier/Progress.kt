package net.atlasauth.pca.verifier

import java.security.SecureRandom

/**
 * Proof of progress toward a committed goal (progress.ts). A goal (objective, potential id, embedder, metric, epsilon, exploration budget) is
 * hashed into a commitment; each step is a hash-chained body binding goal, action digest, before / after state digests, seq and prev; the
 * verifier recomputes the integer potential and the mode (progress, or exploration charged to a budget). Steps can be Ed25519-signed by the
 * holder, post-states can carry a source's signed attestation, and the trajectory head can be anchored in the transparency ledger.
 *
 * Goals, steps and states are JSON trees (maps, lists, strings, booleans, [Json.Num]). All hashes are the STRICT canonical hash (the wire
 * form): a state with no strict encoding has no digest.
 */
@Suppress("UNCHECKED_CAST")
object Progress {
    const val PROGRESS_VERSION = 2
    const val PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"
    const val TRAJECTORY_ANCHOR_DOMAIN = "atlas-pca/trajectory-anchor/v1"
    const val STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\u0000"
    private const val GENESIS = "genesis"
    private const val MAX_SAFE = 9007199254740991.0

    private fun n(d: Double): Json.Num = StoreJs.num(d)
    private fun n(l: Long): Json.Num = StoreJs.num(l)
    private fun num(o: Any?): Double? = IntentJs.num(o)
    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = Issue.obj(*kv)
    private fun isObj(x: Any?): Boolean = x is Map<*, *>
    private fun isStr(x: Any?): Boolean = x is String
    private fun isSafeInt(x: Any?): Boolean = num(x)?.let { !it.isNaN() && !it.isInfinite() && it == Math.rint(it) && Math.abs(it) <= MAX_SAFE } == true
    private fun safeD(d: Double): Boolean = !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE
    private fun typeError(m: String) = IllegalArgumentException(m)
    private fun assertInt(x: Any?, what: String): Double {
        if (!isSafeInt(x)) throw typeError("$what: safe integer required")
        return num(x)!!
    }

    /** `JSON.parse(canonicalize(v))`: a detached, lenient-canonical copy. */
    private fun snapshot(v: Any?): Any? = Json.parseLenient(Json.canonicalize(v))

    // ---- potentials ----

    /** A potential: maps (objective, state) to a non-negative safe integer; what it returns is validated by the callers. May throw. */
    fun interface PotentialFn {
        fun apply(objective: Any?, state: Any?): Any?
    }

    class PotentialSpec(val fn: PotentialFn, val embedder: String = "")

    /** Safe-integer L1 distance between `objective.target` and `state.x` (equal-length integer arrays), the running sum checked at every element. */
    @JvmField
    val l1FeaturePotential = PotentialFn { objective, state ->
        val t = map(objective)?.get("target")
        val x = map(state)?.get("x")
        if (t !is List<*> || x !is List<*> || t.size != x.size) throw typeError("l1-feature-v1: bad shape")
        var d = 0.0
        for (i in t.indices) {
            val a = assertInt(t[i], "target")
            val b = assertInt(x[i], "x")
            d += Math.abs(a - b)
            assertInt(n(d), "distance")
        }
        n(d)
    }

    private fun key(v: Any?): Any? = num(v) ?: v

    /** Sum of the costs of the tasks of `objective.tasks` not in `state.done`. */
    @JvmField
    val dagRemainingPotential = PotentialFn { objective, state ->
        val tasks = map(objective)?.get("tasks")
        val done = map(state)?.get("done")
        if (tasks !is List<*> || done !is List<*>) throw typeError("dag-remaining-v1: bad shape")
        val ids = LinkedHashSet<Any?>()
        for (t in tasks) ids.add(key((t as? Map<*, *> ?: if (t == null) throw typeError("null task") else null)?.get("id")))
        if (ids.size != tasks.size) throw typeError("dag-remaining-v1: duplicate task id")
        val doneSet = LinkedHashSet<Any?>(done.map { key(it) })
        for (d in doneSet) if (!ids.contains(d)) throw typeError("dag-remaining-v1: unknown task $d")
        var rem = 0.0
        for (t in tasks) {
            val tm = t as? Map<*, *>
            val cost = assertInt(tm?.get("cost"), "cost")
            if (cost < 0) throw typeError("negative cost")
            if (!doneSet.contains(key(tm?.get("id")))) rem += cost
            assertInt(n(rem), "remaining")
        }
        n(rem)
    }

    /** Like [dagRemainingPotential] over a task DAG: dependencies must exist, be acyclic, and `done` must be dependency-closed. */
    @JvmField
    val dagWeightedPotential = PotentialFn { objective, state ->
        val tasks = map(objective)?.get("tasks")
        val done = map(state)?.get("done")
        if (tasks !is List<*> || done !is List<*>) throw typeError("dag-weighted-v1: bad shape")
        class T(val cost: Double, val deps: List<String>)
        val byId = LinkedHashMap<String, T>()
        for (t in tasks) {
            val tm = map(t)
            val id = tm?.get("id")
            if (tm == null || id !is String || id.isEmpty()) throw typeError("dag-weighted-v1: bad task")
            if (byId.containsKey(id)) throw typeError("dag-weighted-v1: duplicate task id")
            val cost = assertInt(tm["cost"], "cost")
            if (cost < 0) throw typeError("negative cost")
            val deps = tm["deps"] ?: ArrayList<Any?>()
            if (deps !is List<*> || !deps.all { it is String }) throw typeError("dag-weighted-v1: bad deps")
            byId[id] = T(cost, deps.map { it as String })
        }
        val indeg = LinkedHashMap<String, Int>()
        val rev = HashMap<String, MutableList<String>>()
        for ((id, t) in byId) {
            indeg[id] = t.deps.toSet().size
            for (d in LinkedHashSet(t.deps)) {
                if (d == id || !byId.containsKey(d)) throw typeError("dag-weighted-v1: bad dependency $d")
                rev.getOrPut(d) { ArrayList() }.add(id)
            }
        }
        val q = ArrayDeque(indeg.filter { it.value == 0 }.keys)
        var seen = 0
        while (q.isNotEmpty()) {
            val id = q.removeLast()
            seen++
            for (nx in rev[id] ?: emptyList<String>()) {
                val k = indeg[nx]!! - 1
                indeg[nx] = k
                if (k == 0) q.addLast(nx)
            }
        }
        if (seen != byId.size) throw typeError("dag-weighted-v1: cycle")
        val doneSet = LinkedHashSet<String>()
        for (d in done) {
            if (d !is String || !byId.containsKey(d)) throw typeError("dag-weighted-v1: unknown task $d")
            if (!doneSet.add(d)) throw typeError("dag-weighted-v1: duplicate done")
        }
        for (d in doneSet) for (dep in byId[d]!!.deps) if (!doneSet.contains(dep)) throw typeError("dag-weighted-v1: $d done before dependency $dep")
        var rem = 0.0
        for ((id, t) in byId) {
            if (!doneSet.contains(id)) rem += t.cost
            assertInt(n(rem), "remaining")
        }
        n(rem)
    }

    /** Potentials by id: an id of 1..128 UTF-16 units, registered once, optionally bound to an embedder id; freezable. */
    class PotentialRegistry {
        private val m = LinkedHashMap<String, PotentialSpec>()
        private var frozen = false

        @JvmOverloads
        fun register(id: Any?, fn: PotentialFn, embedder: Any? = ""): PotentialRegistry {
            if (frozen) throw IllegalStateException("registry is frozen")
            if (id !is String || id.isEmpty() || id.length > 128) throw typeError("potential id: 1..128 chars")
            if (embedder !is String) throw typeError("embedder must be a string")
            if (m.containsKey(id)) throw IllegalStateException("potential $id already registered")
            m[id] = PotentialSpec(fn, embedder)
            return this
        }

        fun get(id: String): PotentialSpec? = m[id]
        fun has(id: String): Boolean = m.containsKey(id)

        /** The ids sorted by UTF-16 code units. */
        fun ids(): List<String> = m.keys.sorted()

        fun freeze(): PotentialRegistry { frozen = true; return this }

        companion object {
            /** A registry from a plain record: own keys only, each value a [PotentialFn] or a [PotentialSpec]. */
            @JvmStatic
            fun from(rec: Map<String, Any?>): PotentialRegistry {
                val r = PotentialRegistry()
                for ((k, v) in rec) when (v) {
                    is PotentialFn -> r.register(k, v)
                    is PotentialSpec -> r.register(k, v.fn, v.embedder)
                    else -> throw typeError("potential must be a function")
                }
                return r
            }

            /** A mutable registry with the three built-ins. */
            @JvmStatic
            fun defaults(): PotentialRegistry = PotentialRegistry()
                .register("l1-feature-v1", l1FeaturePotential).register("dag-remaining-v1", dagRemainingPotential).register("dag-weighted-v1", dagWeightedPotential)
        }
    }

    /** The default registry: frozen, the three built-ins. */
    @JvmField
    val DEFAULT_POTENTIALS: PotentialRegistry = PotentialRegistry.defaults().freeze()

    private fun toRegistry(r: Any?): PotentialRegistry = when (r) {
        null -> DEFAULT_POTENTIALS
        is PotentialRegistry -> r
        is Map<*, *> -> PotentialRegistry.from(r as Map<String, Any?>)
        else -> throw typeError("registry")
    }

    // ---- goal commitment ----

    private fun validateGoal(goal: Any?) {
        val g = map(goal) ?: throw typeError("goal must be an object")
        val eps = assertInt(g["epsilon"], "epsilon")
        val budget = assertInt(g["explorationBudget"], "explorationBudget")
        if (eps < 1) throw IllegalArgumentException("epsilon must be >= 1")
        if (budget < 0) throw IllegalArgumentException("explorationBudget must be >= 0")
        if (g["potential"] !is String || (g["potential"] as String).isEmpty()) throw typeError("potential id required")
        if (g["metric"] !is String) throw typeError("metric must be a string")
        if (g.containsKey("embedder") && g["embedder"] !is String) throw typeError("embedder must be a string")
    }

    fun goalDigest(goal: Any?): String {
        validateGoal(goal)
        val g = map(goal)!!
        if (!g.containsKey("objective")) throw typeError("canonicalize: unsupported type undefined")
        return Pca.hashCanonical(
            obj(
                "t" to "pca-goal", "v" to n(PROGRESS_VERSION.toLong()), "objective" to g["objective"], "potential" to g["potential"], "embedder" to (g["embedder"] ?: ""),
                "metric" to g["metric"], "epsilon" to g["epsilon"], "explorationBudget" to g["explorationBudget"],
            ),
        )
    }

    /** `{goal: <canonical snapshot>, commitment}`. */
    fun commitGoal(goal: Any?): Map<String, Any?> {
        val c = goalDigest(goal)
        return obj("goal" to snapshot(goal), "commitment" to c)
    }

    fun verifyGoalCommitment(goal: Any?, commitment: Any?): Boolean = try {
        goalDigest(goal) == commitment
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        false
    }

    // ---- steps and digests ----

    private fun stepBodyDigest(body: Map<String, Any?>): String {
        val m = obj("t" to "pca-progress-step", "v" to n(PROGRESS_VERSION.toLong()))
        m.putAll(body)
        return Pca.hashCanonical(m)
    }

    fun stateDigest(state: Any?): String = Pca.hashCanonical(obj("t" to "pca-state", "state" to state))

    fun trajectoryHead(steps: List<Any?>): Any? = if (steps.isNotEmpty()) map(steps[steps.size - 1])!!["digest"] else GENESIS

    fun progressStepDigest(step: Map<String, Any?>): Any? = step["digest"]

    fun trajectoryAnchorCommit(salt: Any?, head: Any?): String {
        if (salt !is String || salt.isEmpty() || head !is String || head.isEmpty()) throw typeError("trajectoryAnchorCommit: salt and head must be non-empty strings")
        return Pca.hashCanonical(obj("t" to TRAJECTORY_ANCHOR_DOMAIN, "salt" to salt, "head" to head))
    }

    fun verifyTrajectoryAnchor(commit: Any?, salt: Any?, head: Any?): Boolean = try {
        trajectoryAnchorCommit(salt, head) == commit
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        false
    }

    /** Anchor the trajectory head in a transparency log with a salted commitment: `{head, salt, commit, index, ledgerHead}`. [salt] defaults to 16 random bytes. */
    @JvmOverloads
    fun anchorTrajectoryHead(ledger: MerkleLog, steps: List<Any?>, salt: String? = null): Map<String, Any?> {
        val head = trajectoryHead(steps)
        val s = salt ?: Pca.b64(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val commit = trajectoryAnchorCommit(s, head)
        val index = ledger.appendCommitment(commit)
        return obj("head" to head, "salt" to s, "commit" to commit, "index" to n(index.toLong()), "ledgerHead" to ledger.head())
    }

    // ---- the denial reasons ----

    private class ProgressError(val code: String, msg: String) : RuntimeException(msg)

    private fun resolve(goal: Map<String, Any?>, reg: PotentialRegistry): PotentialSpec {
        val spec = reg.get(goal["potential"] as String) ?: throw ProgressError("unknown-potential", "unknown potential ${goal["potential"]}")
        if (spec.embedder != ((goal["embedder"] as String?) ?: "")) throw ProgressError("embedder-mismatch", "embedder mismatch")
        return spec
    }

    private fun potentialOf(goal: Map<String, Any?>, reg: PotentialRegistry, state: Any?): Double {
        val spec = resolve(goal, reg)
        val p: Double
        try {
            p = assertInt(spec.fn.apply(goal["objective"], state), "potential")
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            throw ProgressError("bad-potential", e.message ?: "")
        }
        if (p < 0) throw ProgressError("bad-potential", "potential must be >= 0")
        return p
    }

    private fun denialOf(e: Throwable): String = if (e is ProgressError) e.code else "bad-potential"

    private fun classify(pb: Double, pa: Double, epsilon: Double): Pair<String, Double> {
        val required = pb - epsilon
        if (pa <= required || (pa == 0.0 && pb > 0)) return Pair("progress", 0.0)
        val charge = pa - required
        if (!safeD(charge)) throw ProgressError("bad-potential", "charge: safe integer required")
        return Pair("exploration", charge)
    }

    /** A guard over a step about to be taken; only the value `true` allows it (a throw or a truthy non-boolean denies). */
    fun interface StepGuard {
        fun test(seq: Double, before: Any?, after: Any?, actionDigest: String): Any?
    }

    /** Verifies the attestation of a step's post-state; only `true` passes. */
    fun interface StateAttestationVerifier {
        fun verify(step: Map<String, Any?>): Any?
    }

    private fun runGuard(g: StepGuard, seq: Double, before: Any?, after: Any?, action: String): Boolean = try {
        g.test(seq, before, after, action) == true
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        false
    }

    // ---- state sources and attestations ----

    /** Observes the world after an action: `{state, state_digest, source, evidence?}`; a null result or a throw is a mismatch. */
    interface StateSource {
        val id: String
        fun observe(req: Map<String, Any?>): Map<String, Any?>?
    }

    class InMemoryStateSource @JvmOverloads constructor(initial: Any?, override val id: String = "in-memory") : StateSource {
        private var cur: Any? = snapshot(initial)
        private var count = 0L
        val requests = ArrayList<Map<String, Any?>>()

        fun apply(next: Any?) { cur = snapshot(next) }

        override fun observe(req: Map<String, Any?>): Map<String, Any?> {
            requests.add(req)
            val state = snapshot(cur)
            return obj(
                "state" to state, "state_digest" to stateDigest(state), "source" to id,
                "evidence" to obj("kind" to "in-memory", "n" to n(count++), "prior" to req["prior_digest"], "action" to req["action_digest"]),
            )
        }
    }

    private fun stateAttestationMessage(a: Map<String, Any?>, alg: Any?, algPresent: Boolean, pqPk: Any?, pqPresent: Boolean): ByteArray {
        val base = obj(
            "source" to a["source"], "goal_commitment" to a["goal_commitment"], "action_digest" to a["action_digest"], "prior_digest" to a["prior_digest"],
            "state_digest" to a["state_digest"],
        )
        return Pca.concat(Json.utf8(STATE_ATTESTATION_DOMAIN), Pca.canonBytes(IntentJs.bindSuiteFields(base, alg, algPresent, pqPk, pqPresent)))
    }

    /** Verify a state attestation `{source, goal_commitment, action_digest, prior_digest, state_digest, sig, alg?, pq_pk?, pq_sig?}` under the trusted key. Never throws. */
    @JvmOverloads
    fun verifyStateAttestation(att: Any?, trustedPublicKey: Any?, pin: Map<String, Any?>? = null): Boolean = try {
        val a = map(att)
        when {
            a == null || a["sig"] !is String || a["source"] !is String -> false
            trustedPublicKey !is String || trustedPublicKey.isEmpty() -> false
            Pq.resolveSigAlg(a["alg"], a.containsKey("alg")) == null -> false
            else -> IntentJs.verifyPinnedSuite(
                a["alg"], a.containsKey("alg"), trustedPublicKey, a["pq_pk"], stateAttestationMessage(a, a["alg"], a.containsKey("alg"), a["pq_pk"], a.containsKey("pq_pk")),
                a["sig"], a["pq_sig"], map(pin?.get("pqPins")),
            )
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        false
    }

    /** A state source that signs what it observes: the observation's evidence is the signed attestation, kept in [attestations]. */
    class AttestedStateSource(override val id: String, private val signer: Keys.SuiteKey, private val observeState: (Map<String, Any?>) -> Any?) : StateSource {
        init {
            if (id.isEmpty()) throw IllegalArgumentException("AttestedStateSource: id is required")
        }

        val publicKey: String = signer.id() ?: throw IllegalArgumentException("AttestedStateSource: the signer needs an Ed25519 identity")
        private val log = ArrayList<Map<String, Any?>>()
        val attestations: List<Map<String, Any?>> get() = ArrayList(log)

        override fun observe(req: Map<String, Any?>): Map<String, Any?> {
            val state = snapshot(observeState(req))
            val sd = stateDigest(state)
            val stmt = obj("source" to id, "goal_commitment" to req["goal_commitment"], "action_digest" to req["action_digest"], "prior_digest" to req["prior_digest"], "state_digest" to sd)
            val suite = signer.alg != "ed25519"
            val pqPk = if (suite) signer.pqPk() else null
            val (sig, pqSig) = signer.sign(stateAttestationMessage(stmt, if (suite) signer.alg else null, suite, pqPk, suite && pqPk != null))
            val att = LinkedHashMap(stmt)
            if (suite) { att["alg"] = signer.alg; if (pqPk != null) att["pq_pk"] = pqPk }
            att["sig"] = sig
            if (pqSig != null) att["pq_sig"] = pqSig
            log.add(att)
            return obj("state" to state, "state_digest" to sd, "source" to id, "evidence" to att)
        }
    }

    private fun attestationKey(action: String, prior: String, state: String): String = "$action\u0000$prior\u0000$state"

    /**
     * The attestation hook over a set of signed attestations: per step the trusted key of the step's state source (`opts.trustedKeys`), the
     * attestation of exactly this transition, whose strict hash equals the step's evidence digest, and its signature (`opts.pqPins` for PQ suites).
     */
    fun attestedStateVerifier(opts: Map<String, Any?>): StateAttestationVerifier {
        val byKey = HashMap<String, Map<String, Any?>>()
        for (att in (opts["attestations"] as List<Any?>?) ?: emptyList()) {
            val a = map(att)
            if (a != null && a["action_digest"] is String && a["prior_digest"] is String && a["state_digest"] is String) {
                byKey[attestationKey(a["action_digest"] as String, a["prior_digest"] as String, a["state_digest"] as String)] = a
            }
        }
        return StateAttestationVerifier { step ->
            try {
                val pub = map(opts["trustedKeys"])?.get(step["state_source"])
                if (pub !is String || pub.isEmpty()) return@StateAttestationVerifier false
                val att = byKey[attestationKey(step["action_digest"] as String, step["before_digest"] as String, step["after_digest"] as String)]
                if (att == null || att["source"] != step["state_source"]) return@StateAttestationVerifier false
                if (Pca.hashCanonical(obj("t" to "pca-evidence", "e" to att)) != step["evidence_digest"]) return@StateAttestationVerifier false
                verifyStateAttestation(att, pub, opts)
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                false
            }
        }
    }

    // ---- the tracker ----

    /** A running proof of progress: each step is checked, charged and chained; `{ok: true, step, spent, remaining}` or `{ok: false, reason, stepUp}`. */
    class ProgressTracker @JvmOverloads constructor(goal: Map<String, Any?>, val commitment: String, initial: Any?, registry: Any? = null, private val guard: StepGuard? = null) {
        private var seq = 0L
        private var head = GENESIS
        private var spentTotal = 0.0
        private var cur: Any?
        private var curDigest: String
        private val log = ArrayList<Map<String, Any?>>()
        private val reg: PotentialRegistry
        val goal: Map<String, Any?>
        private val epsilon: Double
        private val budget: Double

        init {
            if (!verifyGoalCommitment(goal, commitment)) throw IllegalStateException("goal does not match commitment")
            this.goal = snapshot(goal) as Map<String, Any?>
            reg = toRegistry(registry)
            cur = snapshot(initial)
            curDigest = stateDigest(cur)
            epsilon = num(this.goal["epsilon"])!!
            budget = num(this.goal["explorationBudget"])!!
            potentialOf(this.goal, reg, cur) // fail fast: unknown id / embedder / bad initial state
        }

        val spent: Double get() = spentTotal
        val remaining: Double get() = budget - spentTotal
        val state: Any? get() = cur
        val currentStateDigest: String get() = curDigest
        val reached: Boolean get() = potentialOf(goal, reg, cur) == 0.0
        val steps: List<Map<String, Any?>> get() = ArrayList(log)

        fun step(after: Any?, actionDigest: Any?): Map<String, Any?> = advance(after, actionDigest, "", "")

        fun stepObserved(source: StateSource, actionDigest: Any?): Map<String, Any?> {
            try {
                val obs = source.observe(obj("action_digest" to actionDigest, "goal_commitment" to commitment, "prior_digest" to curDigest))
                if (obs == null || obs["source"] != source.id || obs["state_digest"] != stateDigest(obs["state"])) {
                    return obj("ok" to false, "reason" to "state-source-mismatch", "stepUp" to false)
                }
                return advance(obs["state"], actionDigest, source.id, Pca.hashCanonical(obj("t" to "pca-evidence", "e" to obs["evidence"])))
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return obj("ok" to false, "reason" to "state-source-mismatch", "stepUp" to false)
            }
        }

        private fun denied(reason: String, stepUp: Boolean = false): Map<String, Any?> = obj("ok" to false, "reason" to reason, "stepUp" to stepUp)

        private fun advance(afterIn: Any?, actionDigest: Any?, stateSource: String, evidenceDigest: String): Map<String, Any?> {
            if (actionDigest !is String || actionDigest.isEmpty()) return denied("malformed")
            val after: Any?
            val afterDigest: String
            val pb: Double
            val pa: Double
            val cls: Pair<String, Double>
            try {
                after = snapshot(afterIn)
                afterDigest = stateDigest(after)
                pb = potentialOf(goal, reg, cur)
                pa = potentialOf(goal, reg, after)
                cls = classify(pb, pa, epsilon)
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return denied(denialOf(e))
            }
            if (guard != null && !runGuard(guard, seq.toDouble(), cur, after, actionDigest)) return denied("prohibited")
            val nextSpent = spentTotal + cls.second
            if (!safeD(nextSpent) || nextSpent > budget) return denied("exploration-exhausted", true)
            val body = obj(
                "goal_commitment" to commitment, "seq" to n(seq), "before" to cur, "after" to after, "before_digest" to curDigest, "after_digest" to afterDigest,
                "action_digest" to actionDigest, "mode" to cls.first, "potential_before" to n(pb), "potential_after" to n(pa), "charge" to n(cls.second),
                "state_source" to stateSource, "evidence_digest" to evidenceDigest, "prev" to head,
            )
            val step = LinkedHashMap(body)
            step["digest"] = stepBodyDigest(body)
            log.add(step)
            seq++
            head = step["digest"] as String
            spentTotal = nextSpent
            cur = after
            curDigest = afterDigest
            return obj("ok" to true, "step" to step, "spent" to n(spentTotal), "remaining" to n(remaining))
        }
    }

    // ---- verification ----

    private fun fail(reason: String): Map<String, Any?> = obj("ok" to false, "reason" to reason)

    private fun isStep(s: Any?): Boolean {
        val m = map(s) ?: return false
        return isStr(m["goal_commitment"]) && isSafeInt(m["seq"]) && num(m["seq"])!! >= 0 && isStr(m["before_digest"]) && isStr(m["after_digest"]) &&
            isStr(m["action_digest"]) && (m["mode"] == "progress" || m["mode"] == "exploration") && isSafeInt(m["potential_before"]) && isSafeInt(m["potential_after"]) &&
            isSafeInt(m["charge"]) && isStr(m["state_source"]) && isStr(m["evidence_digest"]) && isStr(m["prev"]) && isStr(m["digest"]) && m.containsKey("before") && m.containsKey("after")
    }

    private fun optGuard(o: Map<String, Any?>): StepGuard? = o["guard"] as StepGuard?

    /**
     * Verify one step against a goal and its commitment; the first failing check names the denial: `{ok: true, charge}` or `{ok: false, reason}`.
     * [opts]: expectedSeq / expectedPrev / expectedActionDigest / expectedBeforeDigest / expectedAfterDigest, registry (a [PotentialRegistry] or record),
     * guard ([StepGuard]), trustedStateSources (list), requireAttestedState (default true), attestation ([StateAttestationVerifier]).
     */
    @JvmOverloads
    fun verifyProgressStep(goal: Any?, commitment: Any?, step: Any?, opts: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        try {
            if (!verifyGoalCommitment(goal, commitment)) return fail("goal-mismatch")
            if (!isStep(step)) return fail("malformed")
            val s = map(step)!!
            val g = map(goal)!!
            if (s["goal_commitment"] != commitment) return fail("goal-mismatch")
            if (opts.containsKey("expectedSeq") && num(s["seq"]) != num(opts["expectedSeq"])) return fail("seq-mismatch")
            if (opts.containsKey("expectedPrev") && s["prev"] != opts["expectedPrev"]) return fail("chain-break")
            if (opts.containsKey("expectedActionDigest") && s["action_digest"] != opts["expectedActionDigest"]) return fail("action-mismatch")
            if (opts.containsKey("expectedBeforeDigest") && s["before_digest"] != opts["expectedBeforeDigest"]) return fail("state-mismatch")
            if (opts.containsKey("expectedAfterDigest") && s["after_digest"] != opts["expectedAfterDigest"]) return fail("state-mismatch")
            val body = LinkedHashMap(s)
            val digest = body.remove("digest")
            if (stepBodyDigest(body) != digest) return fail("digest-mismatch")
            if (stateDigest(s["before"]) != s["before_digest"] || stateDigest(s["after"]) != s["after_digest"]) return fail("state-digest-mismatch")
            val reg = toRegistry(opts["registry"])
            val pb: Double
            val pa: Double
            val cls: Pair<String, Double>
            try {
                pb = potentialOf(g, reg, s["before"])
                pa = potentialOf(g, reg, s["after"])
                cls = classify(pb, pa, num(g["epsilon"])!!)
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return fail(denialOf(e))
            }
            if (pb != num(s["potential_before"]) || pa != num(s["potential_after"])) return fail("potential-mismatch")
            if (s["mode"] != cls.first) return fail("mode-mismatch")
            if (num(s["charge"]) != cls.second) return fail("charge-mismatch")
            val trusted = opts["trustedStateSources"]
            if (ZkJs.truthy(trusted) && !(trusted as List<Any?>).contains(s["state_source"])) return fail("untrusted-state-source")
            if (opts["requireAttestedState"] != false && s["state_source"] == "") return fail("untrusted-state-source")
            val guard = optGuard(opts)
            if (guard != null && !runGuard(guard, num(s["seq"])!!, s["before"], s["after"], s["action_digest"] as String)) return fail("prohibited")
            val att = opts["attestation"] as StateAttestationVerifier?
            if (att != null) {
                val ok = try { att.verify(s) == true } catch (e: Throwable) { if (!Contain.ok(e)) throw e; false }
                if (!ok) return fail("attestation-failed")
            }
            return obj("ok" to true, "charge" to n(cls.second))
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return fail("malformed")
        }
    }

    private fun failAt(reason: String, at: Long): Map<String, Any?> = obj("ok" to false, "reason" to reason, "at" to n(at))

    /**
     * Verify a whole trajectory: per step the step check (seq, chain, action digest), the state continuity, then the exploration budget.
     * [opts] as [verifyProgressStep] plus initial / initialDigest / expectedActionDigests.
     */
    @JvmOverloads
    fun verifyTrajectory(goal: Any?, commitment: Any?, steps: Any?, opts: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        if (!verifyGoalCommitment(goal, commitment)) return failAt("goal-mismatch", -1)
        if (steps !is List<*>) return failAt("malformed", -1)
        val g = map(goal)!!
        val expected = opts["expectedActionDigests"]
        if (ZkJs.truthy(expected) && (expected as List<Any?>).size != steps.size) return failAt("action-mismatch", Math.min(expected.size, steps.size).toLong())
        var anchor: Any?
        try {
            anchor = if (opts.containsKey("initialDigest") && opts["initialDigest"] != null) opts["initialDigest"] else if (!opts.containsKey("initial")) null else stateDigest(opts["initial"])
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return failAt("malformed", -1)
        }
        var prev = GENESIS
        var spent = 0.0
        var finalPotential = -1.0
        if (steps.isEmpty() && opts.containsKey("initial")) {
            try {
                finalPotential = potentialOf(g, toRegistry(opts["registry"]), opts["initial"])
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return failAt(denialOf(e), -1)
            }
        }
        val budget = num(g["explorationBudget"])!!
        for (i in steps.indices) {
            val s = map(steps[i])
            val o = LinkedHashMap(opts)
            o["expectedSeq"] = n(i.toLong())
            o["expectedPrev"] = prev
            if (ZkJs.truthy(expected)) o["expectedActionDigest"] = (expected as List<Any?>).getOrNull(i) else o.remove("expectedActionDigest")
            if (expected == null || !ZkJs.truthy(expected)) o.remove("expectedActionDigest")
            val r = verifyProgressStep(goal, commitment, steps[i], o)
            if (r["ok"] != true) return failAt(r["reason"] as String, i.toLong())
            if (anchor != null && s!!["before_digest"] != anchor) return failAt("discontinuous-state", i.toLong())
            spent += num(r["charge"])!!
            if (!safeD(spent) || spent > budget) return failAt("budget-exceeded", i.toLong())
            anchor = s!!["after_digest"]
            prev = s["digest"] as String
            finalPotential = num(s["potential_after"])!!
        }
        return obj(
            "ok" to true, "spent" to n(spent), "remaining" to n(budget - spent), "reached" to (finalPotential == 0.0), "finalPotential" to n(finalPotential),
            "steps" to n(steps.size.toLong()), "head" to prev,
        )
    }

    // ---- signed steps ----

    private fun sigMessage(step: Map<String, Any?>, holder: String): ByteArray = Pca.canonBytes(
        obj(
            "d" to PROGRESS_SIG_DOMAIN,
            "b" to obj(
                "holder" to holder, "goal_commitment" to step["goal_commitment"], "action_digest" to step["action_digest"], "before_digest" to step["before_digest"],
                "after_digest" to step["after_digest"], "seq" to step["seq"], "prev" to step["prev"], "step_digest" to step["digest"],
            ),
        ),
    )

    /** `{step, holder, sig}`: Ed25519 over the domain-separated binding of the step to the holder (deterministic). */
    fun signProgressStep(step: Map<String, Any?>, secretKey: Keys.EdKey, holderPublicKey: String): Map<String, Any?> =
        obj("step" to step, "holder" to holderPublicKey, "sig" to Pca.b64(secretKey.sign(sigMessage(step, holderPublicKey))))

    private fun isSigned(s: Any?): Boolean {
        val m = map(s) ?: return false
        return isStr(m["holder"]) && isStr(m["sig"]) && isStep(m["step"])
    }

    /** Verify a signed step: shape, holder, action, goal, signature, then [verifyProgressStep]. [opts] carries expectedHolder and expectedActionDigest. */
    fun verifySignedProgressStep(goal: Any?, commitment: Any?, signed: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        try {
            if (!isSigned(signed)) return fail("malformed")
            val sm = map(signed)!!
            val step = map(sm["step"])!!
            if (sm["holder"] != opts["expectedHolder"]) return fail("holder-mismatch")
            if (step["action_digest"] != opts["expectedActionDigest"]) return fail("action-mismatch")
            if (step["goal_commitment"] != commitment) return fail("goal-mismatch")
            if (!Pca.verifyB64u(sm["holder"] as String, sigMessage(step, sm["holder"] as String), sm["sig"] as String)) return fail("bad-signature")
            return verifyProgressStep(goal, commitment, step, opts)
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return fail("malformed")
        }
    }

    /** Verify a signed trajectory: every step's shape, holder, action and signature, then [verifyTrajectory] over the unsigned steps. */
    fun verifySignedTrajectory(goal: Any?, commitment: Any?, signed: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        if (signed !is List<*>) return failAt("malformed", -1)
        val expected = opts["expectedActionDigests"] as List<Any?>
        if (expected.size != signed.size) return failAt("action-mismatch", Math.min(expected.size, signed.size).toLong())
        for (i in signed.indices) {
            try {
                if (!isSigned(signed[i])) return failAt("malformed", i.toLong())
                val sp = map(signed[i])!!
                val step = map(sp["step"])!!
                if (sp["holder"] != opts["expectedHolder"]) return failAt("holder-mismatch", i.toLong())
                if (step["action_digest"] != expected[i]) return failAt("action-mismatch", i.toLong())
                if (!Pca.verifyB64u(sp["holder"] as String, sigMessage(step, sp["holder"] as String), sp["sig"] as String)) return failAt("bad-signature", i.toLong())
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return failAt("malformed", i.toLong())
            }
        }
        val rest = LinkedHashMap(opts)
        rest.remove("expectedHolder")
        return verifyTrajectory(goal, commitment, signed.map { map(it)!!["step"] }, rest)
    }
}
