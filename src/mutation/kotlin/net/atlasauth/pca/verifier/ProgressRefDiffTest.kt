package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Proof of progress against the reference corpus (ref-progress, 723 cases): the potentials and their registry, goal commitments, step digests, trajectory
 * anchoring, signed state attestations and the attested state source, the progress tracker, step and trajectory verification, signed steps. Every function,
 * every case. The reference's legacy `allowUnboundPq` opt-out is not offered by any native verifier: the cases that the reference accepts only through it are
 * asserted REFUSED here (and counted).
 */
@Suppress("UNCHECKED_CAST")
class ProgressRefDiffTest {
    private val mod = "ref-progress"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun nd(o: Any?): Double? = IntentJs.num(o)

    private fun a(x: List<Any?>, i: Int): Any? = OracleCases.decNum(x[i])

    private fun enc(v: Any?): Any? = when (v) {
        is Json.Num -> if (v.raw == "NaN" || v.raw == "Infinity" || v.raw == "-Infinity") linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is List<*> -> v.map { enc(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = enc(x) }
        else -> v
    }

    private fun kindFn(k: String): Progress.PotentialFn = when {
        k == "l1-feature-v1" -> Progress.l1FeaturePotential
        k == "dag-remaining-v1" -> Progress.dagRemainingPotential
        k == "dag-weighted-v1" -> Progress.dagWeightedPotential
        k.startsWith("const:") -> Progress.PotentialFn { _, _ -> StoreJs.num(k.substring(6).toDouble()) }
        k == "v" -> Progress.PotentialFn { _, s -> map(s)?.get("v") }
        k == "throws" -> Progress.PotentialFn { _, _ -> throw RuntimeException("potential boom") }
        k == "negative" -> Progress.PotentialFn { _, _ -> StoreJs.num(-1L) }
        k == "frac" -> Progress.PotentialFn { _, _ -> StoreJs.num(0.5) }
        k == "nan" -> Progress.PotentialFn { _, _ -> Json.Num("NaN") }
        k == "big" -> Progress.PotentialFn { _, _ -> StoreJs.num(9007199254740992.0) }
        else -> throw IllegalArgumentException("bad potential kind $k")
    }

    private fun registry(s: Any?): Any? {
        val m = map(s) ?: return null
        val pots = list(m["potentials"])
        if (m["mode"] == "record") {
            val rec = LinkedHashMap<String, Any?>()
            for (p in pots) { val l = list(p); rec[l[0] as String] = if (l.size < 3 || l[2] == null) kindFn(l[1] as String) else Progress.PotentialSpec(kindFn(l[1] as String), l[2] as String) }
            return rec
        }
        val r = Progress.PotentialRegistry()
        for (p in pots) { val l = list(p); if (l.size < 3 || l[2] == null) r.register(l[0], kindFn(l[1] as String)) else r.register(l[0], kindFn(l[1] as String), l[2]) }
        return r
    }

    private fun guard(g: Any?): Progress.StepGuard? {
        if (g == null) return null
        val s = g as String
        return when {
            s == "allow" -> Progress.StepGuard { _, _, _, _ -> true }
            s == "deny" -> Progress.StepGuard { _, _, _, _ -> false }
            s == "throws" -> Progress.StepGuard { _, _, _, _ -> throw RuntimeException("guard boom") }
            s == "truthy" -> Progress.StepGuard { _, _, _, _ -> "yes" }
            s.startsWith("action:") -> Progress.StepGuard { _, _, _, act -> act != s.substring(7) }
            s.startsWith("seq:") -> Progress.StepGuard { seq, _, _, _ -> seq != s.substring(4).toDouble() }
            s.startsWith("after-v:") -> Progress.StepGuard { _, _, after, _ -> nd(map(after)?.get("v")) != s.substring(8).toDouble() }
            else -> throw IllegalArgumentException("bad guard $s")
        }
    }

    /** Hooks over a pinned PQ key never get the reference's `allowUnboundPq` opt-out. */
    private fun att(av: Any?): Progress.StateAttestationVerifier? {
        if (av == null) return null
        if (av is String) return when (av) {
            "allow" -> Progress.StateAttestationVerifier { true }
            "deny" -> Progress.StateAttestationVerifier { false }
            "throws" -> Progress.StateAttestationVerifier { throw RuntimeException("att boom") }
            "truthy" -> Progress.StateAttestationVerifier { "yes" }
            else -> throw IllegalArgumentException("bad attestation hook")
        }
        return Progress.attestedStateVerifier(map(map(av)!!["attested"])!!)
    }

    private fun opts(o: Any?): Map<String, Any?> {
        val out = LinkedHashMap(map(o) ?: LinkedHashMap())
        if (out.containsKey("registry")) out["registry"] = registry(out["registry"])
        if (out.containsKey("guard")) out["guard"] = guard(out["guard"])
        if (out.containsKey("attestation")) out["attestation"] = att(out["attestation"])
        return out
    }

    private fun source(s: Map<String, Any?>): Triple<Progress.StateSource, (Any?) -> Unit, Progress.AttestedStateSource?> {
        val id = s["id"] as String
        val initial = s["initial"]
        if (s["kind"] == "attested") {
            var world: Any? = snap(initial)
            // the typed signer carries a registered suite; a corpus alg that names none is what the reference's constructor refuses
            if (s.containsKey("alg") && Pq.resolveSigAlg(s["alg"], true) == null) throw IllegalArgumentException("AttestedStateSource: unknown signature alg '${s["alg"]}'")
            val signer = Keys.ed25519(Keys.edFromSeed(Keys.unb64u(s["signerSecret"] as String)))
            val at = Progress.AttestedStateSource(id, signer) { world }
            return Triple(at, { n -> world = snap(n) }, at)
        }
        val mem = Progress.InMemoryStateSource(initial, id)
        val kind = s["kind"] as String
        val wrapped = object : Progress.StateSource {
            override val id: String = id
            override fun observe(req: Map<String, Any?>): Map<String, Any?>? {
                if (kind == "throws") throw RuntimeException("source boom")
                if (kind == "null") return null
                val ob = LinkedHashMap(mem.observe(req))
                if (kind == "liar-digest") ob["state_digest"] = "x".repeat(43)
                if (kind == "liar-source") ob["source"] = "someone-else"
                return ob
            }
        }
        return Triple(wrapped, { n -> mem.apply(n) }, null)
    }

    private fun snap(v: Any?): Any? = Json.parseLenient(Json.canonicalize(v))

    /** A PQ-signed attestation verified under `allowUnboundPq`: the opt-out is never offered, so the case is refused (ruling). */
    private fun unboundPq(c: Map<String, Any?>): Boolean {
        val args = c["args"] as List<Any?>
        val alg = map(args[0])?.get("alg")
        return map(args[2])?.get("allowUnboundPq") == true && alg != null && alg != "ed25519"
    }

    @Test fun everyFunction() {
        OracleCases.each(mod, "constants") { _ ->
            linkedMapOf(
                "PROGRESS_VERSION" to Progress.PROGRESS_VERSION, "PROGRESS_SIG_DOMAIN" to Progress.PROGRESS_SIG_DOMAIN,
                "TRAJECTORY_ANCHOR_DOMAIN" to Progress.TRAJECTORY_ANCHOR_DOMAIN, "STATE_ATTESTATION_DOMAIN" to Progress.STATE_ATTESTATION_DOMAIN,
            )
        }
        OracleCases.each(mod, "l1FeaturePotential") { x -> Progress.l1FeaturePotential.apply(a(x, 0), a(x, 1)) }
        OracleCases.each(mod, "dagRemainingPotential") { x -> Progress.dagRemainingPotential.apply(a(x, 0), a(x, 1)) }
        OracleCases.each(mod, "dagWeightedPotential") { x -> Progress.dagWeightedPotential.apply(a(x, 0), a(x, 1)) }
        OracleCases.each(mod, "registryOps") { x ->
            var r: Progress.PotentialRegistry? = null
            list(x[0]).map { o ->
                val op = list(o)
                try {
                    when (op[0] as String) {
                        "new" -> { r = Progress.PotentialRegistry(); null }
                        "defaults" -> { r = Progress.PotentialRegistry.defaults(); null }
                        "default-frozen" -> { r = Progress.DEFAULT_POTENTIALS; null }
                        "from" -> {
                            val rec = LinkedHashMap<String, Any?>()
                            for ((id, v) in map(op[1])!!) rec[id] = if (v is String) kindFn(v) else Progress.PotentialSpec(kindFn(map(v)!!["fn"] as String), (map(v)!!["embedder"] as String?) ?: "")
                            r = Progress.PotentialRegistry.from(rec); null
                        }
                        "register" -> { if (op.size < 4 || op[3] == null) r!!.register(op[1], kindFn(op[2] as String)) else r!!.register(op[1], kindFn(op[2] as String), op[3]); null }
                        "get" -> r!!.get(op[1] as String)?.let { linkedMapOf<String, Any?>("embedder" to it.embedder) }
                        "has" -> r!!.has(op[1] as String)
                        "ids" -> r!!.ids()
                        "freeze" -> { r!!.freeze(); null }
                        else -> throw IllegalArgumentException("bad op")
                    }
                } catch (e: RuntimeException) {
                    linkedMapOf<String, Any?>("\$err" to e.message)
                }
            }
        }
        OracleCases.each(mod, "goalDigest") { x -> Progress.goalDigest(a(x, 0)) }
        OracleCases.each(mod, "commitGoal") { x -> Progress.commitGoal(a(x, 0)) }
        OracleCases.each(mod, "verifyGoalCommitment") { x -> Progress.verifyGoalCommitment(a(x, 0), a(x, 1)) }
        OracleCases.each(mod, "stateDigest") { x -> Progress.stateDigest(a(x, 0)) }
        OracleCases.each(mod, "trajectoryHead") { x -> Progress.trajectoryHead(list(a(x, 0))) }
        OracleCases.each(mod, "progressStepDigest") { x -> a(x, 0).let { s -> if (s == null || s is Map<*, *>) Progress.progressStepDigest(map(s)!!) else null } } // .digest of a list / string / number is undefined
        OracleCases.each(mod, "trajectoryAnchorCommit") { x -> Progress.trajectoryAnchorCommit(a(x, 0), a(x, 1)) }
        OracleCases.each(mod, "verifyTrajectoryAnchor") { x -> Progress.verifyTrajectoryAnchor(a(x, 0), a(x, 1), a(x, 2)) }
        OracleCases.each(mod, "anchorTrajectoryHead") { x ->
            val l = MerkleLog()
            for (c in list(x[2])) l.appendCommitment(c as String)
            Progress.anchorTrajectoryHead(l, list(a(x, 0)), x[1] as String?)
        }
        val verifyAtt = { x: List<Any?> -> Progress.verifyStateAttestation(a(x, 0), a(x, 1), map(a(x, 2))) }
        val attCases = OracleCases.of(mod, "verifyStateAttestation")
        val bad = attCases.filter { !unboundPq(it) }.mapNotNull { OracleCases.diff(it, it["out"], verifyAtt) }
        assertTrue("${bad.size} divergent verifyStateAttestation case(s):\n" + bad.take(20).joinToString("\n"), bad.isEmpty())
        val unbound = attCases.filter { unboundPq(it) }
        assertEquals(2, unbound.size) // ml-dsa-65 and the hybrid: the reference accepts both only through allowUnboundPq
        for (c in unbound) {
            assertEquals(true, c["out"])
            assertEquals(false, verifyAtt(c["args"] as List<Any?>))
        }
        OracleCases.each(mod, "attestedStateVerifier") { x -> Progress.attestedStateVerifier(map(a(x, 0))!!).verify(map(a(x, 1))!!) }
        OracleCases.each(mod, "attestedSource") { x ->
            val (src, _, at) = source(map(x[0])!!)
            val obs = list(x[1]).map { r -> try { src.observe(map(r)!!) } catch (e: RuntimeException) { linkedMapOf<String, Any?>("\$err" to e.message) } }
            linkedMapOf("observations" to obs, "attestations" to at?.attestations)
        }
        OracleCases.each(mod, "tracker") { x ->
            val sources = list(x[5]).map { source(map(it)!!) }
            val goal = map(a(x, 0))!!
            val commitment = (x[1] as String?) ?: Progress.goalDigest(goal)
            val t = Progress.ProgressTracker(goal, commitment, a(x, 2), registry(x[3]), guard(x[4]))
            list(x[6]).map { o ->
                val op = list(o)
                try {
                    when (op[0] as String) {
                        "step" -> t.step(a(op, 1), op[2])
                        "stepObserved" -> t.stepObserved(sources[(nd(op[1]))!!.toInt()].first, op[2])
                        "apply" -> { sources[nd(op[1])!!.toInt()].second(op[2]); null }
                        "steps" -> t.steps
                        "state" -> t.state
                        "currentStateDigest" -> t.currentStateDigest
                        "spent" -> StoreJs.num(t.spent)
                        "remaining" -> StoreJs.num(t.remaining)
                        "reached" -> t.reached
                        else -> throw IllegalArgumentException("bad op")
                    }
                } catch (e: RuntimeException) {
                    linkedMapOf<String, Any?>("\$err" to e.message)
                }
            }
        }
        OracleCases.each(mod, "verifyProgressStep") { x -> Progress.verifyProgressStep(a(x, 0), a(x, 1), a(x, 2), opts(a(x, 3))) }
        OracleCases.each(mod, "verifyTrajectory") { x -> Progress.verifyTrajectory(a(x, 0), a(x, 1), a(x, 2), opts(a(x, 3))) }
        OracleCases.each(mod, "verifySignedProgressStep") { x -> Progress.verifySignedProgressStep(a(x, 0), a(x, 1), a(x, 2), opts(a(x, 3))) }
        OracleCases.each(mod, "verifySignedTrajectory") { x -> Progress.verifySignedTrajectory(a(x, 0), a(x, 1), a(x, 2), opts(a(x, 3))) }
        OracleCases.each(mod, "signProgressStep") { x ->
            val sk = Keys.edFromSeed(Keys.unb64u(map(x[1])!!["\$bytes"] as String))
            Progress.signProgressStep(map(a(x, 0))!!, sk, x[2] as String)
        }
        val fns = setOf(
            "constants", "l1FeaturePotential", "dagRemainingPotential", "dagWeightedPotential", "registryOps", "goalDigest", "commitGoal", "verifyGoalCommitment", "stateDigest",
            "trajectoryHead", "progressStepDigest", "trajectoryAnchorCommit", "verifyTrajectoryAnchor", "anchorTrajectoryHead", "verifyStateAttestation", "attestedStateVerifier",
            "attestedSource", "tracker", "verifyProgressStep", "verifyTrajectory", "verifySignedProgressStep", "verifySignedTrajectory", "signProgressStep",
        )
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(723, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
