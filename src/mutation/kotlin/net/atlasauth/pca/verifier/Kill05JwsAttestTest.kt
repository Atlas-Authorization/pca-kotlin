package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The vendor-neutral attestation surface: result wire form, the verifier wrapper (overrides, never-throws), construction, binding. */
class Kill05JwsAttestTest {
    private val b = Attest.Binding("h", "g", 3.0, "n")

    private fun impl(f: (Map<String, Any?>?) -> Attest.Result) = object : Attest.VendorImpl {
        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result = f(ev)
    }

    private val measured = linkedMapOf<String, Any?>("model_id" to "", "operator" to "")

    @Test
    fun resultWireAndText() {
        assertEquals(linkedMapOf<String, Any?>("ok" to true, "bound" to true), Attest.Result(true, true, "").wire())
        assertEquals(linkedMapOf<String, Any?>("ok" to true, "bound" to false, "measured" to measured, "hostAsserted" to mapOf("a" to "b")),
            Attest.Result(true, false, "", measured, mapOf("a" to "b")).wire())
        assertEquals(linkedMapOf<String, Any?>("ok" to false, "reason" to "r"), Attest.Result(false, false, "r", measured).wire())
        assertEquals("Attest.Result(ok=false, bound=true, reason=why)", Attest.Result(false, true, "why").toString())
        val f = Attest.fail("x")
        assertEquals("Attest.Result(ok=false, bound=false, reason=x)", f.toString())
        assertNull(f.measured)
        assertNull(f.hostAsserted)
    }

    @Test
    fun overridesMergeOnlyIntoASuccessWithAMeasuredIdentity() {
        val host = mapOf("k" to "v")
        val good = Attest.Result(true, false, "", measured, host)
        val ov = mapOf<String, Any?>("operator" to "op")
        val merged = Attest.VendorVerifier("azure-maa", impl { good }, ov).verify(null, b, 0)
        assertEquals(linkedMapOf<String, Any?>("model_id" to "", "operator" to "op"), merged.measured)
        assertTrue(merged.ok)
        assertEquals(false, merged.bound)
        assertSame(host, merged.hostAsserted)
        assertSame(good, Attest.VendorVerifier("azure-maa", impl { good }, emptyMap()).verify(null, b, 0))
        assertSame(good, Attest.VendorVerifier("azure-maa", impl { good }, null).verify(null, b, 0))
        val noMeasured = Attest.Result(true, true, "")
        assertSame(noMeasured, Attest.VendorVerifier("azure-maa", impl { noMeasured }, ov).verify(null, b, 0))
        val failed = Attest.Result(false, false, "no", measured)
        assertSame(failed, Attest.VendorVerifier("azure-maa", impl { failed }, ov).verify(null, b, 0))
        // the evidence is handed through as given
        val seen = Attest.VendorVerifier("x", impl { ev -> Attest.fail(ev?.get("k") as String) }, null).verify(mapOf("k" to "got"), b, 0)
        assertEquals("got", seen.reason)
        assertEquals("azure-maa", Attest.VendorVerifier("azure-maa", impl { good }, null).vendor)
    }

    @Test
    fun neverThrows() {
        val prefixes = listOf(
            "amd-sev-snp" to "amd-snp verification error (fail closed): ",
            "intel-tdx-dcap" to "intel-dcap verification error (fail closed): ",
            "azure-maa" to "azure-maa verification error (fail closed): ",
            "gcp-confidential-space" to "gcp-confidential-space verification error (fail closed): ",
            "nvidia-gpu-spdm" to "nvidia-spdm verification error (fail closed): ",
            "other" to "",
        )
        for ((vendor, prefix) in prefixes) {
            fun run(t: Throwable): Attest.Result = Attest.VendorVerifier(vendor, impl { throw t }, null).verify(null, b, 0)
            val boom = run(IllegalStateException("boom"))
            assertEquals(vendor, prefix + "boom", boom.reason)
            assertTrue(vendor, !boom.ok && !boom.bound)
            assertEquals(vendor, prefix + "IllegalStateException", run(IllegalStateException()).reason)
            assertEquals(vendor, prefix + "StackOverflowError", run(StackOverflowError()).reason)
        }
    }

    @Test
    fun verifierFromConfigDispatch() {
        fun refusal(vendor: String, cfg: Map<String, Any?>?): String = try {
            Attest.verifierFromConfig(vendor, cfg)
            "built"
        } catch (e: IllegalArgumentException) {
            e.message ?: "null"
        }
        assertEquals("unknown attestation vendor \"other\"", refusal("other", null))
        assertEquals("unknown attestation vendor \"\"", refusal("", emptyMap()))
        val maa = "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"
        assertEquals(maa, refusal("azure-maa", null))
        assertEquals(maa, refusal("azure-maa", emptyMap()))
        assertEquals("createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs", refusal("gcp-confidential-space", null))
        assertEquals("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)", refusal("nvidia-gpu-spdm", null))
        assertTrue(refusal("amd-sev-snp", null).startsWith("createAmdSnpVerifier: "))
        assertTrue(refusal("intel-tdx-dcap", null).startsWith("createIntelDcapVerifier: "))
        val cfg = Kill05JwsKit.obj("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]},"identity_overrides":5}""")
        val v = Attest.verifierFromConfig("azure-maa", cfg)
        assertEquals("azure-maa", v.vendor)
        assertEquals("no Azure MAA token for this action", v.verify(null, b, 0).reason)
    }

    @Test
    fun defaultHardwarePicksTheEvidence() {
        val ver = Attest.VendorVerifier("x", impl { ev -> Attest.fail((ev?.get("k") as? String) ?: "none") }, null)
        val doc = mapOf<String, Any?>("k" to "doc", "inner" to mapOf("k" to "inner"))
        val plain = Attest.DefaultHardware(ver)
        assertNull(plain.evidence)
        assertSame(ver, plain.verifier)
        assertEquals("doc", plain.attester(0)(doc, b).reason)
        @Suppress("UNCHECKED_CAST")
        val picked = Attest.DefaultHardware(ver) { d -> d["inner"] as Map<String, Any?> }
        assertEquals("inner", picked.attester(0)(doc, b).reason)
        assertEquals("none", Attest.DefaultHardware(ver) { null }.attester(0)(doc, b).reason)
    }

    @Test
    fun bindingEpochBounds() {
        // known answer (also pins the u64be epoch encoding)
        assertEquals(
            "a96a474bee436996d639ac056ef40b906991ac6732d192214c9ff400ee7f60597bea43c2cef340b5439bd38ddc63fbf24dd1b2da311650a7e9a8e0bdbc8e16c3",
            AttestUtil.hex(Attest.bindingBytes(b)),
        )
        for (e in listOf(0.0, 1.0, 9007199254740991.0)) assertEquals(64, Attest.bindingBytes(Attest.Binding("h", "g", e, "n")).size)
        for (e in listOf(-1.0, -0.5, 1.5, 9007199254740992.0, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            try {
                Attest.bindingBytes(Attest.Binding("h", "g", e, "n"))
                throw AssertionError("epoch $e must be refused")
            } catch (x: IllegalArgumentException) {
                assertEquals("binding: epoch must be a non-negative safe integer", x.message)
            }
        }
        for ((bad, want) in listOf(
            Attest.Binding("", "g", 0.0, "n") to "binding: holderPub required",
            Attest.Binding("h", "", 0.0, "n") to "binding: grantRef required",
            Attest.Binding("h", "g", 0.0, "") to "binding: nonce required",
        )) {
            try {
                Attest.bindingBytes(bad)
                throw AssertionError(want)
            } catch (x: IllegalArgumentException) {
                assertEquals(want, x.message)
            }
        }
    }
}
