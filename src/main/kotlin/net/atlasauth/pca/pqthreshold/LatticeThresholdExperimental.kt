package net.atlasauth.pca.pqthreshold

import java.math.BigInteger
import java.security.SecureRandom

/**
 * EXPERIMENTAL lattice-threshold sketch (NOT PRODUCTION; no security proof, timing-unsafe): the Raccoon / Ringtail-style design as data
 * ([RACCOON_DESIGN]) and a toy additive secret sharing of a lattice key vector over Z_q. The sharing is n-of-n, not t-of-n, and this is not a
 * signature scheme. The shippable post-quantum threshold step-up is the hybrid in [PqThreshold] (a classical FROST threshold plus an ML-DSA
 * co-signature quorum). Every routine is gated behind an explicit opt-in; without it the banner is thrown.
 */
object LatticeThresholdExperimental {
    const val EXPERIMENTAL_BANNER: String =
        "EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. " +
            "The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign."

    /** The explicit, loud opt-in a caller must pass to run any experimental routine: it must be `true`. */
    class ExperimentalOptIn(val iUnderstandThisIsNotProduction: Boolean)

    private fun assertOptIn(o: ExperimentalOptIn?) {
        if (o == null || !o.iUnderstandThisIsNotProduction) throw IllegalStateException("$EXPERIMENTAL_BANNER Pass { iUnderstandThisIsNotProduction: true } to proceed.")
    }

    /** The documented research design. DATA describing the approach: it performs no cryptography. */
    @JvmField
    val RACCOON_DESIGN: Map<String, Any?> = java.util.Collections.unmodifiableMap(linkedMapOf<String, Any?>(
        "scheme" to "Raccoon/Ringtail-style lattice threshold (RESEARCH)",
        "status" to "research-prototype",
        "productionReady" to false,
        "banner" to EXPERIMENTAL_BANNER,
        "assumption" to "Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.",
        "construction" to listOf(
            "1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.",
            "2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.",
            "3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.",
            "4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.",
            "5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem.",
        ),
        "whyNoLibraryYet" to listOf(
            "Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.",
            "Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.",
            "No constant-time, side-channel-hardened reference implementation has been published and audited.",
            "The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial.",
        ),
        "shippableAlternative" to
            "Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.",
        "parameterSets" to listOf(
            java.util.Collections.unmodifiableMap(linkedMapOf<String, Any?>("name" to "Raccoon-128 (illustrative)", "nistCategory" to 1, "note" to "Research parameters only; not implemented here.")),
            java.util.Collections.unmodifiableMap(linkedMapOf<String, Any?>("name" to "Raccoon-192 (illustrative)", "nistCategory" to 3, "note" to "Matches ML-DSA-65 category; not implemented here.")),
        ),
        "references" to listOf(
            "Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).",
            "Ringtail: two-round threshold signatures from lattices.",
            "FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror.",
        ),
    ))

    /** Toy lattice parameters: a tiny modulus for demonstration (NOT a real ML-DSA setting) and the key dimension. */
    class ToyLatticeParams(val q: BigInteger, val dim: Int)

    /** The default illustrative ML-DSA modulus, used purely so the arithmetic looks familiar. */
    @JvmField
    val TOY_DEFAULT_PARAMS: ToyLatticeParams = ToyLatticeParams(BigInteger.valueOf(8380417L), 4)

    /** One party's additive share of the toy lattice key: a coefficient vector mod q. `index` is 1-based. */
    class LatticeKeyShare(val index: Int, val coeffs: List<BigInteger>)

    /** A source of a random coefficient in [0, q). Injectable so tests are deterministic. */
    fun interface CoeffSampler {
        fun sample(q: BigInteger): BigInteger
    }

    private val SECURE = SecureRandom()

    private val DEFAULT_SAMPLER = CoeffSampler { q -> BigInteger(64, SECURE).mod(q) }

    /**
     * EXPERIMENTAL. Additively secret-share a toy lattice key vector into `n` shares over Z_q, per coefficient: shares 1..n-1 are random, the last absorbs the
     * remainder so the shares sum to the key (mod q). n-of-n (ALL n shares reconstruct); NOT t-of-n and NOT a signature scheme. Gated behind the opt-in.
     */
    @JvmStatic @JvmOverloads
    fun additiveShareLatticeKey(
        key: List<BigInteger>, n: Int, optIn: ExperimentalOptIn?, params: ToyLatticeParams = TOY_DEFAULT_PARAMS, sampler: CoeffSampler = DEFAULT_SAMPLER,
    ): List<LatticeKeyShare> {
        assertOptIn(optIn)
        if (n < 1 || n > 1024) throw IllegalArgumentException("additiveShareLatticeKey: n must be an integer in [1, 1024]")
        if (key.size != params.dim) throw IllegalArgumentException("additiveShareLatticeKey: key must have ${params.dim} coefficients")
        val shares = Array(n) { Array<BigInteger>(params.dim) { BigInteger.ZERO } }
        for (c in 0 until params.dim) {
            val target = key[c].mod(params.q)
            var running = BigInteger.ZERO
            for (i in 0 until n - 1) {
                val r = sampler.sample(params.q).mod(params.q)
                shares[i][c] = r
                running = running.add(r).mod(params.q)
            }
            shares[n - 1][c] = target.subtract(running).mod(params.q)
        }
        return shares.mapIndexed { i, coeffs -> LatticeKeyShare(i + 1, coeffs.toList()) }
    }

    /**
     * EXPERIMENTAL. Reconstruct the toy lattice key by summing ALL shares' coefficient vectors mod q. Because the sharing is additive (n-of-n), every share
     * must be present; a repeated share index is refused. Gated behind the opt-in.
     */
    @JvmStatic @JvmOverloads
    fun reconstructLatticeKey(shares: List<LatticeKeyShare>, optIn: ExperimentalOptIn?, params: ToyLatticeParams = TOY_DEFAULT_PARAMS): List<BigInteger> {
        assertOptIn(optIn)
        if (shares.isEmpty()) throw IllegalArgumentException("reconstructLatticeKey: need at least one share")
        val out = Array<BigInteger>(params.dim) { BigInteger.ZERO }
        // additive sharing is n-of-n: a repeated share index would be counted twice and silently yield a wrong key
        if (shares.map { it.index }.toSet().size != shares.size) throw IllegalArgumentException("reconstructLatticeKey: duplicate share index")
        for (s in shares) {
            if (s.coeffs.size != params.dim) throw IllegalArgumentException("reconstructLatticeKey: a share has the wrong dimension")
            for (c in 0 until params.dim) out[c] = out[c].add(s.coeffs[c]).mod(params.q)
        }
        return out.toList()
    }
}
