package net.atlasauth.pca.oprf

import net.atlasauth.pca.verifier.Json

/**
 * The PCA layer over the RFC 9497 OPRF core: private revocation checks (the service learns nothing about which capability id is
 * queried) and private rate-limiting (a POPRF token keyed by a public window, the identifier stays hidden).
 */
object OprfPca {
    /** UTF-8 encode STRICTLY: an unpaired surrogate is refused instead of silently collapsing to U+FFFD (two ids must never share a counter). */
    internal fun encodeStrict(s: String?, what: String): ByteArray {
        requireNotNull(s) { "$what must be a string" }
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) i++
                else throw IllegalArgumentException("$what contains an unpaired surrogate (ill-formed UTF-16)")
            } else if (Character.isLowSurrogate(c)) {
                throw IllegalArgumentException("$what contains an unpaired surrogate (ill-formed UTF-16)")
            }
            i++
        }
        return Json.utf8(s)
    }

    private fun revocationMode(mode: String) {
        require(mode == "oprf" || mode == "voprf") { "revocation mode must be oprf or voprf" }
    }

    /** The published revocation set: lowercase-hex OPRF outputs, the mode, and (voprf) the service public key. */
    class RevocationSet(outputs: Set<String>, val mode: String, val publicKey: ByteArray?) {
        val outputs: Set<String> = java.util.Collections.unmodifiableSet(outputs)
    }

    /** The only thing that crosses client to service: a blinded element in, an evaluation (plus proof for voprf) out. */
    fun interface BlindEvaluator {
        fun evaluate(blindedElement: ByteArray): Oprf.EvaluateResult
    }

    @JvmStatic
    fun buildRevocationSet(secretKey: ByteArray, revokedCapIds: Collection<String>, mode: String): RevocationSet {
        revocationMode(mode)
        val outputs = LinkedHashSet<String>()
        for (id in revokedCapIds) outputs.add(Oprf.toHex(Oprf.evaluate(secretKey, encodeStrict(id, "capability id"), mode)))
        return RevocationSet(outputs, mode, if (mode == "voprf") Oprf.publicKeyFor(secretKey) else null)
    }

    @JvmStatic
    fun makeRevocationEvaluator(secretKey: ByteArray, mode: String): BlindEvaluator {
        revocationMode(mode)
        val publicKey = if (mode == "voprf") Oprf.publicKeyFor(secretKey) else null
        return BlindEvaluator { blinded -> Oprf.blindEvaluate(secretKey, blinded, mode, publicKey, null) }
    }

    /** Is [capId] in the published set, learned obliviously? A voprf set verifies the service's DLEQ proof (a lying service is refused). */
    @JvmStatic
    fun isRevokedPrivate(capId: String?, blindEval: BlindEvaluator, revokedSet: RevocationSet): Boolean {
        val input = encodeStrict(capId, "capability id")
        val mode = revokedSet.mode
        val b = Oprf.blind(input, mode)
        val res = blindEval.evaluate(b.blindedElement)
        val output = if (mode == "voprf") {
            if (res.proof == null || revokedSet.publicKey == null) throw IllegalStateException("isRevokedPrivate(voprf): missing DLEQ proof or service public key")
            Oprf.finalizeOprf(input, b.blind, res.evaluatedElement, "voprf", res.proof, revokedSet.publicKey, b.blindedElement)
        } else {
            Oprf.finalizeOprf(input, b.blind, res.evaluatedElement, "oprf", null, null, null)
        }
        return revokedSet.outputs.contains(Oprf.toHex(output))
    }

    /** A POPRF blind-evaluation oracle: the window is the public info tag. */
    fun interface RateBlindEvaluator {
        fun evaluate(blindedElement: ByteArray, window: String): Oprf.EvaluateResult
    }

    @JvmStatic
    fun rateToken(secretKey: ByteArray, identifier: String?, window: String?): ByteArray =
        Oprf.evaluatePoprf(secretKey, encodeStrict(identifier, "identifier"), encodeStrict(window, "window"))

    @JvmStatic
    fun rateTokenHex(secretKey: ByteArray, identifier: String?, window: String?): String = Oprf.toHex(rateToken(secretKey, identifier, window))

    @JvmStatic
    fun makeRateEvaluator(secretKey: ByteArray): RateBlindEvaluator =
        RateBlindEvaluator { blinded, window -> Oprf.blindEvaluatePoprf(secretKey, blinded, encodeStrict(window, "window"), null) }

    /** The rate token for (identifier, window) without revealing the identifier; equals [rateToken] for the same key. */
    @JvmStatic
    fun privateRateToken(identifier: String?, window: String?, blindEval: RateBlindEvaluator, publicKey: ByteArray): ByteArray {
        val input = encodeStrict(identifier, "identifier")
        val info = encodeStrict(window, "window")
        val b = Oprf.blindPoprf(input, info, publicKey, null)
        val res = blindEval.evaluate(b.blindedElement, window!!)
        val proof = res.proof ?: throw IllegalStateException("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof")
        return Oprf.finalizePoprf(input, b.blind, res.evaluatedElement, info, proof, b.blindedElement, b.tweakedKey)
    }

    /** A tiny in-memory counter over rate tokens (the identifier is never stored). */
    class RateWindowCounter(private val limit: Int) {
        private val counts = HashMap<String, Int>()

        init {
            require(limit >= 1) { "RateWindowCounter: limit must be a positive integer" }
        }

        /** Record one use of [token]: returns (count, allowed). */
        @Synchronized
        fun hit(token: ByteArray): Pair<Int, Boolean> {
            val key = Oprf.toHex(token)
            val count = (counts[key] ?: 0) + 1
            counts[key] = count
            return Pair(count, count <= limit)
        }

        @Synchronized
        fun count(token: ByteArray): Int = counts[Oprf.toHex(token)] ?: 0

        @Synchronized
        fun reset() = counts.clear()
    }
}
