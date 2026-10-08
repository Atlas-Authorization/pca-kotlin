package net.atlasauth.pca.verifier

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

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
 */
object Pq {
    /** ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes. */
    const val ML_DSA_65_PUBLIC_KEY_BYTES = 1952
    const val ML_DSA_65_SIGNATURE_BYTES = 3309

    /** Ed25519 signature length, in bytes (unchanged classical suite). */
    const val ED25519_SIGNATURE_BYTES = 64

    /** A signature suite: the decoded `sig` byte length and which components / fields it requires. */
    data class Suite(
        val alg: String,
        val sigBytes: Int,
        val hasEd25519: Boolean,
        val hasMlDsa: Boolean,
        val needsPqPk: Boolean,
        val needsPqSig: Boolean,
    )

    /** The default suite used when `alg` is absent — the pre-B4 default. MUST stay "ed25519" forever. */
    const val DEFAULT_SIG_ALG = "ed25519"

    /** The closed algorithm registry. `ed25519` is first so the default path is the common one. */
    private val SUITES: Map<String, Suite> = linkedMapOf(
        "ed25519" to Suite("ed25519", ED25519_SIGNATURE_BYTES, true, false, false, false),
        "ml-dsa-65" to Suite("ml-dsa-65", ML_DSA_65_SIGNATURE_BYTES, false, true, true, false),
        "hybrid-ed25519-ml-dsa-65" to
            Suite("hybrid-ed25519-ml-dsa-65", ED25519_SIGNATURE_BYTES, true, true, true, true),
    )

    /**
     * Resolve the suite for a PCActn `alg` value. `algPresent` is false when the field is absent (=> default
     * `ed25519`). Returns the default or a known suite, else null (FAIL-CLOSED: the caller rejects it).
     */
    fun resolveSigAlg(alg: Any?, algPresent: Boolean): Suite? {
        if (!algPresent) return SUITES[DEFAULT_SIG_ALG]
        if (alg !is String) return null
        return SUITES[alg]
    }

    // ---- ML-DSA-65 verification -------------------------------------------------------------

    /** ML-DSA-65 verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    fun mlDsa65Verify(pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean {
        if (pk == null || sig == null || pk.size != ML_DSA_65_PUBLIC_KEY_BYTES || sig.size != ML_DSA_65_SIGNATURE_BYTES)
            return false
        return try {
            val pub = MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk)
            val v = MLDSASigner() // pure ML-DSA, empty context (matches @noble / circl)
            v.init(false, pub)
            v.update(msg, 0, msg.size)
            v.verifySignature(sig)
        } catch (e: RuntimeException) {
            false
        }
    }

    /** [mlDsa65Verify] over base64url-encoded key and signature; false on any decoding error. */
    fun mlDsa65VerifyB64u(pkB64u: Any?, msg: ByteArray, sigB64u: Any?): Boolean {
        val pk = Pca.decodeB64uStrict(pkB64u, ML_DSA_65_PUBLIC_KEY_BYTES)
        val sg = Pca.decodeB64uStrict(sigB64u, ML_DSA_65_SIGNATURE_BYTES)
        if (pk == null || sg == null) return false
        return mlDsa65Verify(pk, msg, sg)
    }

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
        val suite = resolveSigAlg(algV, algPresent) ?: return "unknown signature alg '$algV'"

        if (Pca.decodeB64uStrict(p["sig"], suite.sigBytes) == null)
            return "'sig' is not canonical base64url (${suite.sigBytes} bytes) for alg '${suite.alg}'"

        if (suite.needsPqPk) {
            if (Pca.decodeB64uStrict(p["pq_pk"], ML_DSA_65_PUBLIC_KEY_BYTES) == null)
                return "'pq_pk' is not canonical base64url ($ML_DSA_65_PUBLIC_KEY_BYTES bytes)"
        } else if (p.containsKey("pq_pk")) {
            return "'pq_pk' must be absent for alg '${suite.alg}'"
        }
        if (suite.needsPqSig) {
            if (Pca.decodeB64uStrict(p["pq_sig"], ML_DSA_65_SIGNATURE_BYTES) == null)
                return "'pq_sig' is not canonical base64url ($ML_DSA_65_SIGNATURE_BYTES bytes)"
        } else if (p.containsKey("pq_sig")) {
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
     */
    fun verifyLeafSuite(
        alg: Any?,
        algPresent: Boolean,
        holder: String?,
        pqPk: Any?,
        msg: ByteArray,
        sig: Any?,
        pqSig: Any?,
    ): Boolean {
        val suite = resolveSigAlg(alg, algPresent) ?: return false
        if (sig !is String) return false
        return when (suite.alg) {
            "ed25519" -> Pca.verifyB64u(holder, msg, sig)
            "ml-dsa-65" -> mlDsa65VerifyB64u(pqPk, msg, sig)
            "hybrid-ed25519-ml-dsa-65" -> {
                if (pqSig !is String) return false
                Pca.verifyB64u(holder, msg, sig) && mlDsa65VerifyB64u(pqPk, msg, pqSig)
            }
            else -> false
        }
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
