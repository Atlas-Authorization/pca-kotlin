package net.atlasauth.pca.verifier

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner

/**
 * B4 — post-quantum crypto-agility, mirroring `packages/pca/src/pq.ts` (and the Java / Go / Swift / .NET SDKs).
 *
 * An ADDITIVE, backward-compatible algorithm-agility slot for the PCActn leaf signature. An absent `alg`
 * (or `alg == "ed25519"`) is BYTE-IDENTICAL to the pre-B4 wire — the signed bytes, the `sig` field and every
 * verdict are unchanged — so every existing conformance vector and all the other SDK verifiers remain valid.
 * B4 only adds OPTIONAL post-quantum suites alongside it:
 *  - `ed25519`                     classical 64-byte Ed25519 `sig` (unchanged).
 *  - `ml-dsa-65`                   pure PQ: `sig` carries an ML-DSA-65 (FIPS-204) signature, verified under
 *                                  the ML-DSA public key in `pq_pk`.
 *  - `hybrid-ed25519-ml-dsa-65`    BOTH: `sig` is the Ed25519 signature (under the leaf holder key, exactly
 *                                  as today) AND `pq_sig` is an ML-DSA-65 signature (under `pq_pk`), over the
 *                                  SAME canonical message; BOTH must verify.
 *
 * `alg` and `pq_pk` are SIGNED (part of the canonical body hashed by `thresholdMessage`), so a downgrade of the
 * suite or a swap of the ML-DSA key invalidates every signature. `sig` and `pq_sig` are the signatures
 * themselves and are EXCLUDED from the signed body (like `sig` / `threshold`).
 *
 * The ML-DSA primitive is BouncyCastle's `MLDSASigner` with `MLDSAParameters.ml_dsa_65` (CRYSTALS-Dilithium /
 * FIPS-204, 192-bit category-3 parameter set), pure variant with an EMPTY context — byte-compatible with
 * `@noble/post-quantum`'s `ml_dsa65` and circl's `mldsa65`. ML-DSA-65 sizes: public key 1952 bytes, signature
 * 3309 bytes. Requires BouncyCastle >= 1.80 (final FIPS-204 naming).
 *
 * Suite capability (`packages/pca/conformance/SUITES.md`): every registered suite BouncyCastle provides is implemented,
 * pure mode, EMPTY context: ML-DSA-65 / ML-DSA-87 (FIPS 204, `MLDSASigner`), SLH-DSA-SHA2-128f / SLH-DSA-SHA2-256s
 * (FIPS 205, `SLHDSASigner`), their `hybrid-ed25519-*` forms (the Ed25519 half is checked first) and the SUF-CMA
 * `hybrid-nested-ed25519-ml-dsa-65` (the PQ half signs msg || the Ed25519 signature bytes). FN-DSA (BouncyCastle ships
 * round-3 Falcon, not the FIPS 206 encoding) is refused with the distinct reason `unsupported_suite: <alg>`; so is LESS
 * unless [LessNative] has a runtime and `libatlas_less` (its signature is variable-length, see [Prim.sigLenOk]).
 */
object Pq {
    /** ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes. */
    const val ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    const val ML_DSA_65_SIGNATURE_BYTES = 3309

    /** Ed25519 signature length, in bytes (unchanged classical suite). */
    const val ED25519_SIGNATURE_BYTES = 64

    /** The reason token of a registered suite this verifier does not implement (full reason `unsupported_suite: <alg>`). */
    const val UNSUPPORTED_SUITE = "unsupported_suite"

    /** The closed TS suite registry (`SIG_SUITES` in pq.ts), in registry order. */
    val REGISTERED_SUITES: List<String> = listOf(
        "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
        "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1",
    )

    /** The post-quantum primitive of a suite, with its (public key, signature) byte lengths. */
    enum class Prim(val pkBytes: Int, val sigBytes: Int) {
        ML_DSA_65(ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES),
        ML_DSA_87(2592, 4627),
        SLH_DSA_SHA2_128F(32, 17088),
        SLH_DSA_SHA2_256S(64, 29792),

        /** LESS (less-252-45) through [LessNative]; `sigBytes` is the MAXIMUM signature length. */
        LESS_CAT1(LessNative.PUBLIC_KEY_BYTES, LessNative.SIGNATURE_MAX_BYTES),
        ;

        /** `n` is a signature length of this primitive: its fixed length, or (LESS) any length the parameter set produces. */
        fun sigLenOk(n: Int): Boolean = if (this == LESS_CAT1) LessNative.sigLenOk(n) else n == sigBytes
    }

    /** A signature suite: the decoded `sig` byte length, its PQ primitive (null for ed25519) and which fields it requires. */
    data class Suite(
        val alg: String,
        val sigBytes: Int,
        val hasEd25519: Boolean,
        val pq: Prim?,
        val needsPqPk: Boolean,
        val needsPqSig: Boolean,
        /** SUF-CMA nested hybrid: the PQ half signs msg || the Ed25519 signature bytes. */
        val nested: Boolean = false,
    )

    /** The default suite used when `alg` is absent — the pre-B4 default. MUST stay "ed25519" forever. */
    const val DEFAULT_SIG_ALG = "ed25519"

    private fun pure(alg: String, p: Prim) = alg to Suite(alg, p.sigBytes, false, p, true, false)
    private fun hybrid(alg: String, p: Prim, nested: Boolean = false) =
        alg to Suite(alg, ED25519_SIGNATURE_BYTES, true, p, true, true, nested)

    /** The suites this verifier implements (a subset of [REGISTERED_SUITES]). `ed25519` first: the common path. */
    private val SUITES: Map<String, Suite> = linkedMapOf(
        "ed25519" to Suite("ed25519", ED25519_SIGNATURE_BYTES, true, null, false, false),
        pure("ml-dsa-65", Prim.ML_DSA_65),
        hybrid("hybrid-ed25519-ml-dsa-65", Prim.ML_DSA_65),
        hybrid("hybrid-nested-ed25519-ml-dsa-65", Prim.ML_DSA_65, nested = true),
        pure("slh-dsa-sha2-128f", Prim.SLH_DSA_SHA2_128F),
        hybrid("hybrid-ed25519-slh-dsa-sha2-128f", Prim.SLH_DSA_SHA2_128F),
        pure("ml-dsa-87", Prim.ML_DSA_87),
        hybrid("hybrid-ed25519-ml-dsa-87", Prim.ML_DSA_87),
        pure("slh-dsa-sha2-256s", Prim.SLH_DSA_SHA2_256S),
        hybrid("hybrid-ed25519-slh-dsa-sha2-256s", Prim.SLH_DSA_SHA2_256S),
    ).apply {
        if (LessNative.available) {
            this += pure("less-cat1", Prim.LESS_CAT1)
            this += hybrid("hybrid-ed25519-less-cat1", Prim.LESS_CAT1)
        }
    }

    /** The capability manifest: the registered suites this verifier implements, in registry order. */
    fun supportedSuites(): List<String> = REGISTERED_SUITES.filter { it in SUITES }

    /** The refusal of an `alg` this verifier does not resolve: `unsupported_suite: <alg>` for a registered suite, else
     *  `unknown signature alg '<alg>'`. */
    fun refusal(alg: Any?): String =
        if (alg is String && alg in REGISTERED_SUITES) "$UNSUPPORTED_SUITE: $alg" else "unknown signature alg '$alg'"

    /**
     * Resolve the suite for a PCActn `alg` value. `algPresent` is false when the field is absent (=> default
     * `ed25519`). Returns the default or a known suite, else null (FAIL-CLOSED: the caller rejects it).
     */
    fun resolveSigAlg(alg: Any?, algPresent: Boolean): Suite? {
        if (!algPresent) return SUITES[DEFAULT_SIG_ALG]
        if (alg !is String) return null
        return SUITES[alg]
    }

    /** Canonical base64url whose decoded length is a signature length of `p`. */
    internal fun pqSigOk(p: Prim, v: Any?): Boolean = Pca.decodeB64uStrict(v, -1)?.let { p.sigLenOk(it.size) } ?: false

    /** The primary `sig`: the PQ signature for a pure suite (its length rule), else the 64-byte Ed25519 one. */
    private fun sigFieldOk(suite: Suite, v: Any?): Boolean =
        if (suite.pq != null && !suite.needsPqSig) pqSigOk(suite.pq, v) else Pca.decodeB64uStrict(v, suite.sigBytes) != null

    // ---- ML-DSA-65 verification -------------------------------------------------------------

    /** PQ verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    fun pqVerify(p: Prim, pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean {
        if (pk == null || sig == null || pk.size != p.pkBytes || !p.sigLenOk(sig.size)) return false
        if (p == Prim.LESS_CAT1) return LessNative.verify(pk, msg, sig)
        return try {
            when (p) {
                Prim.ML_DSA_65, Prim.ML_DSA_87 -> {
                    val ps = if (p == Prim.ML_DSA_65) MLDSAParameters.ml_dsa_65 else MLDSAParameters.ml_dsa_87
                    val v = MLDSASigner() // pure ML-DSA, empty context (matches @noble / circl)
                    v.init(false, MLDSAPublicKeyParameters(ps, pk))
                    v.update(msg, 0, msg.size)
                    v.verifySignature(sig)
                }
                Prim.SLH_DSA_SHA2_128F, Prim.SLH_DSA_SHA2_256S -> {
                    val ps = if (p == Prim.SLH_DSA_SHA2_128F) SLHDSAParameters.sha2_128f else SLHDSAParameters.sha2_256s
                    val v = SLHDSASigner() // pure SLH-DSA, empty context
                    v.init(false, SLHDSAPublicKeyParameters(ps, pk))
                    v.verifySignature(msg, sig)
                }
                Prim.LESS_CAT1 -> false // handled above
            }
        } catch (e: RuntimeException) {
            false
        }
    }

    /** ML-DSA-65 verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    fun mlDsa65Verify(pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean = pqVerify(Prim.ML_DSA_65, pk, msg, sig)

    /** [pqVerify] over base64url-encoded key and signature; false on any decoding error. */
    fun pqVerifyB64u(p: Prim, pkB64u: Any?, msg: ByteArray, sigB64u: Any?): Boolean {
        val pk = Pca.decodeB64uStrict(pkB64u, p.pkBytes)
        val sg = Pca.decodeB64uStrict(sigB64u, -1)?.takeIf { p.sigLenOk(it.size) }
        if (pk == null || sg == null) return false
        return pqVerify(p, pk, msg, sg)
    }

    /** [mlDsa65Verify] over base64url-encoded key and signature; false on any decoding error. */
    fun mlDsa65VerifyB64u(pkB64u: Any?, msg: ByteArray, sigB64u: Any?): Boolean = pqVerifyB64u(Prim.ML_DSA_65, pkB64u, msg, sigB64u)

    // ---- wire-shape validation of the signature fields --------------------------------------

    /**
     * Validate the signature-carrying fields (`alg`, `sig`, `pq_pk`, `pq_sig`) per suite. Returns null when
     * well-formed, else a short reason. Strict + fail-closed: unknown alg, wrong sizes, or a field not used by
     * the suite being present, all fail.
     */
    fun validateSignatureWire(p: Map<String, Any?>): String? {
        val algPresent = p.containsKey("alg")
        val algV = p["alg"]
        if (algPresent && algV !is String) return "'alg' must be a string"
        val suite = resolveSigAlg(algV, algPresent) ?: return refusal(algV)

        if (!sigFieldOk(suite, p["sig"]))
            return "'sig' is not canonical base64url (${suite.sigBytes} bytes) for alg '${suite.alg}'"

        if (suite.needsPqPk) {
            val pkLen = suite.pq!!.pkBytes
            if (Pca.decodeB64uStrict(p["pq_pk"], pkLen) == null)
                return "'pq_pk' is not canonical base64url ($pkLen bytes)"
        } else if (p.containsKey("pq_pk")) {
            return "'pq_pk' must be absent for alg '${suite.alg}'"
        }
        if (suite.needsPqSig) {
            val pqSigLen = suite.pq!!.sigBytes
            if (!pqSigOk(suite.pq!!, p["pq_sig"]))
                return "'pq_sig' is not canonical base64url ($pqSigLen bytes)"
        } else if (p.containsKey("pq_sig")) {
            return "'pq_sig' must be absent for alg '${suite.alg}'"
        }
        return null
    }

    /**
     * 0.4.1: wire-shape validation of ONE threshold share's signature fields, per suite (it used to be a fixed 64-byte
     * `sig`, so a pure post-quantum share could never be carried). Mirrors `validateShareSignatureWire` in
     * packages/pca/src/pq.ts: `alg` absent == ed25519; present and not a string (JSON null included) or unknown fails;
     * `sig` must be canonical base64url of the suite's signature length; `pq_sig` is required (3309 bytes) for the hybrid
     * and must be absent otherwise. A share's `pq_pk` is NOT judged here: it is an optional echo that [Threshold] checks
     * against the signer set. Returns null when well-formed, else a short reason.
     */
    fun validateShareSignatureWire(s: Map<String, Any?>): String? {
        val algPresent = s.containsKey("alg")
        val algV = s["alg"]
        if (algPresent && algV !is String) return "'alg' must be a string"
        val suite = resolveSigAlg(algV, algPresent) ?: return refusal(algV)
        if (!sigFieldOk(suite, s["sig"]))
            return "'sig' is not canonical base64url (${suite.sigBytes} bytes) for alg '${suite.alg}'"
        if (suite.needsPqSig) {
            val pqSigLen = suite.pq!!.sigBytes
            if (!pqSigOk(suite.pq!!, s["pq_sig"]))
                return "'pq_sig' is not canonical base64url ($pqSigLen bytes) for alg '${suite.alg}'"
        } else if (s.containsKey("pq_sig")) {
            return "'pq_sig' must be absent for alg '${suite.alg}'"
        }
        return null
    }

    // ---- the leaf signature SEAM ------------------------------------------------------------

    /**
     * Verify the leaf signature under the PCActn's suite. The single agility seam; everything above it (the full
     * verifier) is unchanged. FAIL-CLOSED: an unknown `alg`, a missing component, or any invalid component
     * returns false. Never throws.
     *  - ed25519:   Ed25519 `sig` under `holder` — byte-identical to the pre-B4 path.
     *  - ml-dsa-65: ML-DSA-65 `sig` under `pq_pk`.
     *  - hybrid:    Ed25519 `sig` under `holder` AND ML-DSA-65 `pq_sig` under `pq_pk`, both over `msg`;
     *               BOTH must verify.
     * CALLER-VOUCHED: this overload verifies under the ARTIFACT'S OWN `pq_pk`, so it proves nothing about who issued
     * the artifact. It is for surfaces whose key is authorised elsewhere (threshold shares, the `pq_artifact` conformance
     * primitives). The chain and the PCActn leaf never call it; they go through [verifySuite] with a [PinnedPq].
     */
    fun verifyLeafSuite(
        alg: Any?,
        algPresent: Boolean,
        holder: String?,
        pqPk: Any?,
        msg: ByteArray,
        sig: Any?,
        pqSig: Any?,
    ): Boolean = verifySuite(alg, algPresent, holder, PinnedPq.resolve(null, pqPk, trustedPk = pqPk as? String), msg, sig, pqSig)

    /**
     * The key-authorised seam. The PQ half verifies ONLY under [pq] (a [PinnedPq], minted solely by [PinnedPq.resolve]), never
     * under a `pq_pk` read off the artifact. A missing key fails closed. The chain hops and the PCActn leaf call THIS.
     */
    internal fun verifySuite(
        alg: Any?,
        algPresent: Boolean,
        holder: String?,
        pq: PinnedPq?,
        msg: ByteArray,
        sig: Any?,
        pqSig: Any?,
    ): Boolean {
        val suite = resolveSigAlg(alg, algPresent) ?: return false
        if (sig !is String) return false
        val prim = suite.pq ?: return Pca.verifyB64u(holder, msg, sig)
        if (pq == null) return false
        if (!suite.needsPqSig) return pqVerifyB64u(prim, pq.key, msg, sig) // pure PQ: `sig` is the PQ signature
        // hybrid: the cheap Ed25519 half first (R6-API-04), then the PQ `pq_sig` (nested: over msg || Ed25519 sig bytes)
        if (pqSig !is String || !Pca.verifyB64u(holder, msg, sig)) return false
        val pqMsg = if (suite.nested) {
            val edSig = Pca.decodeB64uStrict(sig, ED25519_SIGNATURE_BYTES) ?: return false
            msg + edSig
        } else msg
        return pqVerifyB64u(prim, pq.key, pqMsg, pqSig)
    }

    /**
     * Verify a NON-LEAF transparency/authority ARTIFACT signature (STH, revocation, beacon, bond-settlement,
     * safety-certificate, judge-verdict, software-attestation) over `msg` under suite `alg` — the SAME agility
     * seam as the leaf ([verifyLeafSuite]). `edPub` is the Ed25519 key, `pqPk` the ML-DSA key. Fail-closed: an
     * unknown / unimplemented suite or any invalid component returns false; never throws.
     */
    fun verifyArtifactSignature(alg: String?, edPub: String?, pqPk: Any?, msg: ByteArray, sig: Any?, pqSig: Any?): Boolean =
        verifyLeafSuite(alg, true, edPub, pqPk, msg, sig, pqSig)
}

/**
 * An opaque PQ verification key (R3-01 choke point). The type and its resolver are MODULE-INTERNAL (R5-B2k: a
 * public resolver let any caller mint a pinned key from the artifact's own `pq_pk`). The constructor is private: the only way to obtain one is
 * [PinnedPq.resolve], so [Pq.verifySuite] cannot be reached with a `pq_pk` read straight off the artifact being verified.
 */
internal class PinnedPq private constructor(val key: String, val source: String) {
    companion object {
        /**
         * THE choke point (R3-01), mirroring resolvePqVerifyKey in packages/pca/src/pq.ts. Returns the key to verify under, or
         * null (REFUSE) when no verifier-side authority vouches for the artifact's `pq_pk`:
         *  1. [trustedPk]: a key the verifier itself holds (the stored grant). Used as is.
         *  2. [pqPins]`[identity]` (own entry only): the artifact key MUST equal the pin; a differing pin is a refusal.
         *  3. [holderPq]: the artifact key must hash to the signer's committed `holder_pq` (F-2).
         * Natives have no allowUnboundPq: an artifact's own key is never enough.
         */
        fun resolve(
            identity: String?,
            artifactPk: Any?,
            holderPq: Any? = null,
            pqPins: Map<String, Any?>? = null,
            trustedPk: String? = null,
        ): PinnedPq? {
            if (trustedPk != null && trustedPk.isNotEmpty()) return PinnedPq(trustedPk, "trusted")
            if (artifactPk !is String || artifactPk.isEmpty()) return null
            if (pqPins != null && identity != null && pqPins.containsKey(identity)) {
                return if (pqPins[identity] == artifactPk) PinnedPq(artifactPk, "pin") else null
            }
            if (holderPq is String && Pca.holderPqCommitment(artifactPk) == holderPq) return PinnedPq(artifactPk, "holder-commitment")
            return null
        }
    }
}
