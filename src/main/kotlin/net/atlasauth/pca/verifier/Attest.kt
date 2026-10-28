package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Hardware attestation verifiers: AMD SEV-SNP, Intel TDX (DCAP v4), Azure MAA, Google Confidential Space and NVIDIA GPU
 * (SPDM), plus the strict DER / X.509 readers they share. Each vendor verifier answers exactly what the reference verifiers of
 * `@atlasauth/pca` answer, reason text included (an OpenSSL / node:crypto message inside a reason is compared by its stable
 * prefix), and fails closed on anything it cannot establish. No network I/O: collateral arrives with the evidence.
 *
 * Build one from the language-neutral configuration documented by the conformance vectors with [verifierFromConfig]; hand it
 * to [Passport] as [DefaultHardware], or call [VendorVerifier.verify] directly.
 */
object Attest {
    /** The vendors [verifierFromConfig] builds a verifier for. */
    val VENDORS: List<String> = listOf("amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm")

    /**
     * What a vendor quote's bound value must equal: the server-known holder key, grant, epoch and nonce. `epoch` is a double
     * because the wire form carries a JSON number; only a non-negative safe integer is constructible.
     */
    class Binding(val holderPub: String, val grantRef: String, val epoch: Double, val nonce: String)

    /** A verifier's answer (the reference `HardwareAttestationResult`). `reason` is empty when `ok`. */
    class Result(
        val ok: Boolean,
        val bound: Boolean,
        val reason: String,
        val measured: Map<String, Any?>? = null,
        val hostAsserted: Map<String, String>? = null,
    ) {
        /** The language-neutral form (what the conformance vectors record in `expect`). */
        fun wire(): Map<String, Any?> {
            if (!ok) return linkedMapOf("ok" to false, "reason" to reason)
            val out = LinkedHashMap<String, Any?>()
            out["ok"] = true
            out["bound"] = bound
            if (measured != null) out["measured"] = measured
            if (hostAsserted != null) out["hostAsserted"] = LinkedHashMap<String, Any?>(hostAsserted)
            return out
        }

        override fun toString(): String = "Attest.Result(ok=$ok, bound=$bound, reason=$reason)"
    }

    internal fun fail(reason: String) = Result(false, false, reason)

    internal interface VendorImpl {
        fun verify(ev: Map<String, Any?>?, expected: Binding?, nowMs: Long): Result
    }

    /** Verifies the hardware evidence of one vendor under a fixed configuration. Safe for concurrent use. */
    class VendorVerifier internal constructor(val vendor: String, private val impl: VendorImpl, private val overrides: Map<String, Any?>?) {
        /**
         * Verify the vendor evidence (null: none supplied for this action) against the expected binding at the clock `nowMs`
         * (epoch milliseconds). Never throws: anything unexpected is a failed result.
         */
        fun verify(evidence: Map<String, Any?>?, expected: Binding?, nowMs: Long): Result = try {
            val r = impl.verify(evidence, expected, nowMs)
            if (r.ok && r.measured != null && overrides != null && overrides.isNotEmpty()) {
                val merged = LinkedHashMap<String, Any?>(r.measured)
                merged.putAll(overrides)
                Result(r.ok, r.bound, r.reason, merged, r.hostAsserted)
            } else r
        } catch (e: RuntimeException) {
            fail("${ERROR_PREFIX[vendor] ?: ""}${e.message ?: e.javaClass.simpleName}")
        } catch (e: StackOverflowError) {
            fail("${ERROR_PREFIX[vendor] ?: ""}StackOverflowError")
        }
    }

    private val ERROR_PREFIX = mapOf(
        "amd-sev-snp" to "amd-snp verification error (fail closed): ",
        "intel-tdx-dcap" to "intel-dcap verification error (fail closed): ",
        "azure-maa" to "azure-maa verification error (fail closed): ",
        "gcp-confidential-space" to "gcp-confidential-space verification error (fail closed): ",
        "nvidia-gpu-spdm" to "nvidia-spdm verification error (fail closed): ",
    )

    /**
     * Build the verifier for (vendor, config). The [IllegalArgumentException] is the constructor's refusal of the configuration
     * (a missing allowlist, an absent trust anchor, a malformed pin: there is no accept-all). `identity_overrides`, if present,
     * are merged over the measured identity of every successful verification.
     */
    @JvmStatic
    fun verifierFromConfig(vendor: String, config: Map<String, Any?>?): VendorVerifier {
        val cfg: Map<String, Any?> = config ?: LinkedHashMap()
        val impl: VendorImpl = when (vendor) {
            "amd-sev-snp" -> AttestAmd.create(cfg)
            "intel-tdx-dcap" -> AttestIntel.create(cfg)
            "azure-maa" -> AttestMaa.create(cfg)
            "gcp-confidential-space" -> AttestGcp.create(cfg)
            "nvidia-gpu-spdm" -> AttestNvidia.create(cfg)
            else -> throw IllegalArgumentException("unknown attestation vendor \"$vendor\"")
        }
        @Suppress("UNCHECKED_CAST")
        val ov = cfg["identity_overrides"] as? Map<String, Any?>
        return VendorVerifier(vendor, impl, ov)
    }

    /**
     * The built-in hardware verifier of [Passport.verify], used when no integrator attester is given. `evidence` returns the
     * vendor evidence object for the passport's evidence document (null = none); when it is null the document itself is the
     * vendor evidence.
     */
    class DefaultHardware(val verifier: VendorVerifier, val evidence: ((Map<String, Any?>) -> Map<String, Any?>?)? = null) {
        internal fun attester(nowMs: Long): HardwareAttester = { doc, expected ->
            val ev: Map<String, Any?>? = if (evidence != null) evidence.invoke(doc) else doc
            verifier.verify(ev, expected, nowMs)
        }
    }

    /** `SHA-512("atlas-pca/attest-bind/v1" || 0x00 || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce))`. */
    @JvmStatic
    fun bindingBytes(e: Binding): ByteArray {
        require(e.holderPub.isNotEmpty()) { "binding: holderPub required" }
        require(e.grantRef.isNotEmpty()) { "binding: grantRef required" }
        require(e.nonce.isNotEmpty()) { "binding: nonce required" }
        require(!(e.epoch.isNaN() || e.epoch != Math.floor(e.epoch) || e.epoch < 0 || e.epoch > 9007199254740991.0)) { "binding: epoch must be a non-negative safe integer" }
        val buf = java.io.ByteArrayOutputStream()
        buf.write(AttestUtil.BIND_DOMAIN.toByteArray(StandardCharsets.UTF_8))
        buf.write(lp(e.holderPub))
        buf.write(lp(e.grantRef))
        buf.write(ByteBuffer.allocate(8).putLong(e.epoch.toLong()).array())
        buf.write(lp(e.nonce))
        return AttestUtil.sha512(buf.toByteArray())
    }

    private fun lp(s: String): ByteArray {
        val b = s.toByteArray(StandardCharsets.UTF_8)
        return ByteBuffer.allocate(4 + b.size).putInt(b.size).put(b).array()
    }
}
