package net.atlasauth.pca.invariants

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * The deterministic building blocks of the PCA safety-invariant harness: Ed25519 key pairs derived from seeds, the builder of legally
 * attenuating signed delegation chains from a model, the "pointwise worse risk input" helper and the registry constants. The property
 * layer lives beside it: [Arbitraries] (seeded generators over [Rng]), [InvariantProperties] (the twelve properties, the registry and
 * `checkInvariants`), with no property-testing dependency.
 */
object Invariants {
    const val DEFAULT_SEED = 20260108L
    const val DEFAULT_NUM_RUNS = 1000

    /** The names of the twelve safety invariants, in registry order. */
    @JvmField val INVARIANT_NAMES: List<String> = listOf(
        "attenuation-monotonicity", "risk-wellformed-and-monotone", "admission-soundness", "cumulative-budget-bound",
        "fail-closed:undecidable-leaf", "fail-closed:undecidable-groups", "fail-closed:member-of-cycle-safe", "fail-closed:unknown-caveat-type",
        "fail-closed:forged-chain-rejected", "fail-closed:garbage-chain-rejected", "forbid-monotone", "determinism",
    )

    /** An Ed25519 key pair whose 32-byte secret IS the seed; [pub] is the b64u public key used as `issuer` / `holder`. */
    class GenKeyPair internal constructor(val secretKey: ByteArray, val key: Keys.EdKey) {
        val publicKey: ByteArray = key.pub
        val pub: String = key.id()

        /** {secretKey, publicKey, pub}. */
        fun toMap(): Map<String, Any?> = linkedMapOf("secretKey" to secretKey, "publicKey" to publicKey, "pub" to pub)
    }

    /** The key pair whose secret is [seed] (32 bytes; any other length throws). */
    @JvmStatic fun keyPairFromSeed(seed: ByteArray?): GenKeyPair {
        require(seed != null && seed.size == 32) { "private key of length 32 expected, got " + (seed?.size ?: 0) }
        return GenKeyPair(seed!!.clone(), Keys.edFromSeed(seed))
    }

    private const val BUDGET_ALLOC_BASE = 1_000_000.0

    private fun caveat(type: String, vararg kv: Pair<String, Any?>): Map<String, Any?> = linkedMapOf<String, Any?>("type" to type).also { it.putAll(kv) }

    /** One caveat spec to a concrete caveat, threading the running budget allocation (monotone non-increasing). */
    private fun specToCaveat(spec: Map<String, Any?>, running: DoubleArray): Map<String, Any?> = when (val k = spec["k"]) {
        "expires" -> caveat("expires", "at" to spec["at"])
        "not_before" -> caveat("not_before", "at" to spec["at"])
        "rate" -> caveat("rate", "max" to spec["max"], "per_secs" to spec["per_secs"])
        "max_blast_radius" -> caveat("max_blast_radius", "max" to spec["max"])
        "reversibility_max" -> caveat("reversibility_max", "class" to spec["cls"])
        "delegation_depth" -> caveat("delegation_depth", "max" to spec["max"])
        "budget_frac" -> {
            val base = if (!running[0].isNaN() && !running[0].isInfinite()) running[0] else BUDGET_ALLOC_BASE
            // frac in [0,1] and base a non-negative integer: the floor is an integer in [0, base], never above the previous allocation
            val limit = Math.floor(base * Js.num(spec["frac"])!!)
            running[0] = limit
            caveat("budget_alloc", "limit" to Json.Num(limit.toLong().toString()))
        }
        // a spec of no known kind falls through the reference's switch and yields undefined, which cannot be signed
        else -> throw IllegalArgumentException("unknown caveat spec kind: " + Js.template(k))
    }

    @Suppress("UNCHECKED_CAST")
    private fun specs(o: Any?): List<Any?> = (o as List<Any?>?) ?: emptyList()

    /**
     * Build a signed, legally attenuating chain from a model: `principalSeed`, `holder0Seed` (32-byte seeds), `rootSpecs`, `hops`
     * (`holderSeed`, `addedSpecs`) and the fixed envelope `predicates`. Returns {caps, predicates, rootIssuer, holders}.
     */
    @Suppress("UNCHECKED_CAST")
    @JvmStatic fun buildChain(m: Map<String, Any?>): Map<String, Any?> {
        val running = doubleArrayOf(Double.POSITIVE_INFINITY)
        val principal = keyPairFromSeed(m["principalSeed"] as ByteArray?)
        val holder0 = keyPairFromSeed(m["holder0Seed"] as ByteArray?)
        val rootCaveats = specs(m["rootSpecs"]).map { specToCaveat(it as Map<String, Any?>, running) }
        val root = Issue.mintRoot(Keys.ed25519(principal.key), holder0.pub, null, rootCaveats)
        val caps = arrayListOf<Any?>(root)
        val holders = arrayListOf<Any?>(holder0.pub)
        var prev = root
        var signer = holder0 // the next hop is signed by the key the parent is bound to
        for (ho in specs(m["hops"])) {
            val hop = ho as Map<String, Any?>
            val to = keyPairFromSeed(hop["holderSeed"] as ByteArray?)
            val added = specs(hop["addedSpecs"]).map { specToCaveat(it as Map<String, Any?>, running) }
            val cap = Issue.delegate(prev, to.pub, added, Keys.ed25519(signer.key), null)
            caps.add(cap)
            holders.add(to.pub)
            prev = cap
            signer = to
        }
        return linkedMapOf("caps" to caps, "predicates" to m["predicates"], "rootIssuer" to principal.pub, "holders" to holders)
    }

    private fun clamp01(x: Double): Double = if (x < 0) 0.0 else if (x > 1) 1.0 else x

    private fun dn(o: Any?): Double = Js.num(o)!!

    /**
     * A risk input that is at least [base] in every risk-increasing axis and at most it in every protective axis. [d] holds the
     * non-negative deltas `dSem`, `dBlast`, `dTaint`, `dAge`, `dRev`, `dConf`.
     */
    @JvmStatic fun worsen(base: Map<String, Any?>, d: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "semanticDistance" to clamp01(dn(base["semanticDistance"]) + dn(d["dSem"])),
        "blastRadius" to clamp01(dn(base["blastRadius"]) + dn(d["dBlast"])),
        "taint" to clamp01(dn(base["taint"]) + dn(d["dTaint"])),
        "age" to clamp01(dn(base["age"]) + dn(d["dAge"])),
        "reversibility" to clamp01(dn(base["reversibility"]) - dn(d["dRev"])),
        "confidence" to clamp01(dn(base["confidence"]) - dn(d["dConf"])),
    )
}
