package net.atlasauth.pca.invariants

import net.atlasauth.pca.verifier.Json
import java.math.BigDecimal

/**
 * Generators of WELL-FORMED random inputs for the PCA core, driven by a seeded [Rng] (the same shapes as the reference's property-test
 * arbitraries): Ed25519 seeds, multi-hop chain models whose every hop legally attenuates, predicates, action and caveat contexts, risk
 * policies / inputs / budgets. Everything is plain data fed to the real core; nothing re-implements the model it checks. Caveat contexts
 * use the native snake_case member names (`blast_radius`, `recent_action_times`, ...).
 */
object Arbitraries {
    private val VERBS = listOf("read", "write", "delete", "transfer", "list", "admin")
    private val RESOURCES = listOf("/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/")
    private val LEAF_OPS = listOf("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists")
    private val LEAF_FIELDS = listOf("subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount")
    private val REVERSIBILITY = listOf("reversible", "rate_limited", "irreversible", "teleport")

    private fun obj(vararg kv: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*kv)

    /** [n] items from [f], n drawn first (the reference draws the length before the elements). */
    private fun <T> times(n: Long, f: () -> T): MutableList<Any?> {
        val out = ArrayList<Any?>()
        var i = n
        while (i > 0) { out.add(f()); i-- }
        return out
    }

    // ---- keys ----------------------------------------------------------------------------------------------------

    /** 32 random bytes: a reproducible Ed25519 secret seed. */
    @JvmStatic fun seed32(r: Rng): ByteArray = r.bytes(32)

    @JvmStatic fun keyPair(r: Rng): Invariants.GenKeyPair = Invariants.keyPairFromSeed(seed32(r))

    // ---- predicates ----------------------------------------------------------------------------------------------

    @JvmStatic fun verb(r: Rng): String = r.pick(VERBS)

    @JvmStatic fun resource(r: Rng): String = if (r.bool()) r.pick(RESOURCES) else r.string(0, 10)

    /** A known-operator leaf comparison (so a generated leaf is a decidable, well-formed condition). */
    @JvmStatic fun leafCondition(r: Rng): Map<String, Any?> {
        val value: Any? = when (r.integer(0, 3).toInt()) {
            0 -> r.string(0, 10)
            1 -> r.integer(-10, 10)
            2 -> r.bool()
            else -> times(r.integer(0, 3)) { r.string(0, 10) }
        }
        return obj("field" to r.pick(LEAF_FIELDS), "op" to r.pick(LEAF_OPS), "value" to value)
    }

    @JvmStatic fun predicate(r: Rng): Map<String, Any?> {
        val verb: Any? = when (r.integer(0, 2).toInt()) {
            0 -> verb(r)
            1 -> times(r.integer(1, 3)) { verb(r) }
            else -> "*"
        }
        val p = obj("verb" to verb)
        when (r.integer(0, 4).toInt()) {
            0 -> {} // resource absent
            1 -> p["resource"] = "*"
            2 -> p["resource"] = r.pick("/acct/*", "/docs/*")
            else -> p["resource"] = resource(r)
        }
        if (r.bool()) p["where"] = times(r.integer(0, 2)) { leafCondition(r) }
        return p
    }

    @JvmStatic fun predicateList(r: Rng): List<Any?> = times(r.integer(1, 4)) { predicate(r) }

    // ---- action + caveat contexts -----------------------------------------------------------------------------------

    @JvmStatic fun actionContext(r: Rng): Map<String, Any?> {
        val action = obj("verb" to verb(r), "resource" to resource(r))
        if (r.bool()) {
            val params = LinkedHashMap<String, Any?>()
            for (k in listOf("amount", "target", "reason")) {
                if (params.size >= 3 || !r.bool()) continue
                params[k] = when (r.integer(0, 2).toInt()) {
                    0 -> r.string(0, 10)
                    1 -> r.integer(-5, 100)
                    else -> r.bool()
                }
            }
            action["params"] = params
        }
        val role = r.pick("admin", "user", "guest")
        val tier = r.integer(0, 5)
        val ip = r.string(0, 10)
        val withSubject = r.bool()
        val withEnv = r.bool()
        val ctx = obj("action" to action)
        if (withSubject) ctx["subject"] = obj("role" to role, "tier" to tier)
        if (withEnv) ctx["env"] = obj("ip" to ip)
        return ctx
    }

    @JvmStatic fun caveatContext(r: Rng): Map<String, Any?> {
        val ctx = obj("now" to r.integer(0, 10_000_000))
        if (r.bool()) ctx["blast_radius"] = r.real(0.0, 1.0)
        if (r.bool()) ctx["reversibility_class"] = r.pick(REVERSIBILITY)
        if (r.bool()) ctx["delegation_depth"] = r.integer(0, 20)
        if (r.bool()) ctx["recent_action_times"] = times(r.integer(0, 6)) { r.integer(0, 10_000_000) }
        return ctx
    }

    /** An action context and a caveat context together: one point at which to probe a chain's effective authority. */
    @JvmStatic fun evalPoint(r: Rng): Map<String, Any?> {
        val action = actionContext(r)
        return obj("action" to action, "cavCtx" to caveatContext(r))
    }

    // ---- attenuating delegation chains ----------------------------------------------------------------------------------

    /** A well-formed, built-in, evaluator-decidable caveat spec; `budget_frac` becomes a monotone non-increasing allocation. */
    @JvmStatic fun caveatSpec(r: Rng): Map<String, Any?> = when (r.integer(0, 6).toInt()) {
        0 -> obj("k" to "expires", "at" to r.integer(0, 10_000_000))
        1 -> obj("k" to "not_before", "at" to r.integer(0, 10_000_000))
        2 -> { val max = r.integer(1, 10); obj("k" to "rate", "max" to max, "per_secs" to r.integer(1, 3600)) }
        // quantized to 3 decimals so the limit is canonical-wire-safe
        3 -> obj("k" to "max_blast_radius", "max" to Json.Num(BigDecimal.valueOf(r.integer(0, 1000), 3).stripTrailingZeros().toPlainString()))
        4 -> obj("k" to "reversibility_max", "cls" to r.pick("reversible", "rate_limited", "irreversible"))
        5 -> obj("k" to "delegation_depth", "max" to r.integer(0, 20))
        else -> obj("k" to "budget_frac", "frac" to r.real(0.0, 1.0))
    }

    private fun specs(r: Rng, min: Long, max: Long): List<Any?> = times(r.integer(min, max)) { caveatSpec(r) }

    /** A chain model for [Invariants.buildChain]; the built chain is {caps, predicates, rootIssuer, holders}. */
    @JvmStatic fun chainModel(r: Rng): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["principalSeed"] = seed32(r)
        m["holder0Seed"] = seed32(r)
        m["rootSpecs"] = specs(r, 1, 4)
        m["hops"] = times(r.integer(0, 5)) { val s = seed32(r); obj("holderSeed" to s, "addedSpecs" to specs(r, 0, 3)) }
        m["predicates"] = predicateList(r)
        return m
    }

    @JvmStatic fun chain(r: Rng): Map<String, Any?> = Invariants.buildChain(chainModel(r))

    // ---- risk policy / inputs / budget -------------------------------------------------------------------------------------

    /** A well-formed risk policy (passes the core validation): kappa > 0, 0 <= theta1 <= theta2, the rest finite and >= 0. */
    @JvmStatic fun riskPolicy(r: Rng): Map<String, Any?> {
        val w = obj("alpha" to r.real(0.0, 2.0), "beta" to r.real(0.0, 2.0), "gamma" to r.real(0.0, 2.0), "delta" to r.real(0.0, 2.0), "epsilon" to r.real(0.0, 2.0), "zeta" to r.real(0.0, 2.0))
        val theta1 = r.real(0.0, 1.0)
        val gap = r.real(0.0, 1.0)
        val kappa = r.real(0.001, 5.0)
        val lambda = r.real(0.0, 0.01)
        val rho = r.real(0.0, 2.0)
        return obj("weights" to w, "theta1" to theta1, "theta2" to theta1 + gap, "kappa" to kappa, "lambda" to lambda, "rho" to rho, "bMax" to r.real(0.0, 10.0))
    }

    @JvmStatic fun riskInputs(r: Rng): Map<String, Any?> = obj(
        "semanticDistance" to r.real(0.0, 1.0), "reversibility" to r.real(0.0, 1.0), "blastRadius" to r.real(0.0, 1.0),
        "taint" to r.real(0.0, 1.0), "confidence" to r.real(0.0, 1.0), "age" to r.real(0.0, 1.0),
    )

    @JvmStatic fun trustBudget(r: Rng): Map<String, Any?> {
        val b = obj("B" to r.real(0.0, 10.0), "tau" to r.integer(0, 10_000_000))
        if (r.bool()) b["asOf"] = r.integer(0, 10_000_000)
        return b
    }

    /** Non-negative deltas for a pointwise-worse risk input (the monotonicity property). */
    @JvmStatic fun riskDeltas(r: Rng): Map<String, Any?> = obj(
        "dSem" to r.real(0.0, 1.0), "dBlast" to r.real(0.0, 1.0), "dTaint" to r.real(0.0, 1.0),
        "dAge" to r.real(0.0, 1.0), "dRev" to r.real(0.0, 1.0), "dConf" to r.real(0.0, 1.0),
    )
}
