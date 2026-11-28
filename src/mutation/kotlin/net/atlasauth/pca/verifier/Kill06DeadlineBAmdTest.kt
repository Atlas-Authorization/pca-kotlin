package net.atlasauth.pca.verifier

import java.security.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline test for AttestAmd.verifyReport's reserved-byte scan (nonZero): a genuine report walks every zero byte, a stuck cursor must fail fast. */
class Kill06DeadlineBAmdTest {
    private val k = Kill05GcpAmdKit
    private val oidHwid = "1.3.6.1.4.1.3704.1.4"
    private val splOids = listOf("1.3.6.1.4.1.3704.1.3.1", "1.3.6.1.4.1.3704.1.3.2", "1.3.6.1.4.1.3704.1.3.3", "1.3.6.1.4.1.3704.1.3.8")
    private val splValues = listOf(1L, 2L, 10L, 11L) // reported_tcb 0x0b0a000000000201

    private class Keys(val ark: KeyPair, val ask: KeyPair, val vcek: KeyPair)

    private fun run(reserved: Int?): Attest.Result {
        val ks = Keys(k.ecKey("secp384r1"), k.ecKey("secp384r1"), k.ecKey("secp384r1"))
        val chipId = ByteArray(64) { 0x5a.toByte() }
        val measurement = ByteArray(48) { 0x3c.toByte() }
        val vcekDer = k.certSpki(
            "VCEK", "SEV-Milan", k.NB, k.NA, ks.vcek.public.encoded, ks.ask,
            k.ext(oidHwid, false, chipId),
            k.ext(splOids[0], false, k.integer(splValues[0])), k.ext(splOids[1], false, k.integer(splValues[1])),
            k.ext(splOids[2], false, k.integer(splValues[2])), k.ext(splOids[3], false, k.integer(splValues[3])),
        )
        val pem = k.pem(k.cert("SEV-Milan", "ARK-Milan", ks.ask, ks.ark, k.basicConstraints(true, 0), k.keyUsageCertSign())) +
            k.pem(k.cert("ARK-Milan", "ARK-Milan", ks.ark, ks.ark, k.basicConstraints(true, 1), k.keyUsageCertSign()))
        val r = ByteArray(0x4a0)
        r[0] = 2
        k.putLe(r, 0x034, 1, 4)
        Attest.bindingBytes(k.BINDING).copyInto(r, 0x050)
        measurement.copyInto(r, 0x090)
        k.putLe(r, 0x180, 0x0b0a000000000201L, 8)
        chipId.copyInto(r, 0x1a0)
        val sig = k.signRaw(ks.vcek, "SHA384withECDSA", r.copyOfRange(0, 0x2a0), 48)
        for (i in 0 until 48) {
            r[0x2a0 + i] = sig[47 - i]
            r[0x2e8 + i] = sig[95 - i]
        }
        if (reserved != null) r[reserved] = 1 // inside the reserved signature padding
        val pin = AttestUtil.hex(AttestUtil.sha384(ks.ark.public.encoded))
        val cfg = ParityVectors.obj(
            "{\"family\":\"milan\",\"binding\":\"report-data\",\"trustAnchorArkSpkiSha384\":\"$pin\"," +
                "\"policy\":{\"measurements\":[\"${AttestUtil.hex(measurement)}\"]}}",
        )
        val ev = linkedMapOf<String, Any?>("report" to k.b64(r), "vcekDer" to k.b64(vcekDer), "askArkPem" to pem)
        return ParityVectors.harnessVerifier("amd-sev-snp", cfg).verify(ev, k.BINDING, k.NOW)
    }

    @Test
    fun genuineReportScansReservedBytes() = Deadline.within {
        val ok = run(null)
        assertEquals("", ok.reason)
        assertTrue(ok.ok && ok.bound)
        // the tail after the S padding (0x330..) is the first range the scan reads: a non-zero byte there is found
        assertEquals("SEV-SNP report invalid: report signature block has non-zero reserved bytes", run(0x2e8 + 71 + 1).reason)
    }
}
