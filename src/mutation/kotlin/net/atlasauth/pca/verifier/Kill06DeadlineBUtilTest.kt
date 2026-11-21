package net.atlasauth.pca.verifier

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/** Deadline tests for AttestUtil loops (jsTrim, leToBig, parseDerSig lengths, the Azure runtime-data check): a stuck cursor fails fast. */
class Kill06DeadlineBUtilTest {
    @Test
    fun jsTrimStripsBothEnds() = Deadline.within {
        assertEquals("x y", AttestUtil.jsTrim("  \t x y　 \n"))
        assertEquals("", AttestUtil.jsTrim(" \t "))
        assertEquals("a", AttestUtil.jsTrim("a"))
    }

    @Test
    fun leToBigReadsLittleEndian() = Deadline.within {
        assertEquals(BigInteger("0201", 16), AttestUtil.leToBig(byteArrayOf(1, 2)))
        assertEquals(BigInteger("ff0001", 16), AttestUtil.leToBig(byteArrayOf(1, 0, -1)))
        assertEquals(BigInteger.ZERO, AttestUtil.leToBig(ByteArray(0)))
    }

    private fun big(bits: Int, sub: Long) = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.valueOf(sub))

    @Test
    fun parseDerSigShortAndLongLengths() = Deadline.within {
        val r = big(255, 1)
        val s = big(250, 7)
        val short = AttestUtil.derSig(r, s)
        assertEquals(0x30, short[0].toInt())
        assertEquals(r to s, AttestUtil.parseDerSig(short))
        // 66-byte halves with the top bit set: body 138 bytes, so the SEQUENCE length takes the 0x81 long form
        val r5 = big(528, 1)
        val s5 = big(528, 3)
        val mid = AttestUtil.derSig(r5, s5)
        assertEquals(0x81, mid[1].toInt() and 0xff)
        assertEquals(r5 to s5, AttestUtil.parseDerSig(mid))
        // a 264-byte INTEGER: both the INTEGER and the SEQUENCE lengths need two bytes (0x82)
        val rb = big(2100, 1).toByteArray()
        val one = byteArrayOf(2, 1, 1)
        val rInt = byteArrayOf(2, 0x82.toByte(), (rb.size shr 8).toByte(), rb.size.toByte()) + rb
        val body = rInt + one
        val long = byteArrayOf(0x30, 0x82.toByte(), (body.size shr 8).toByte(), body.size.toByte()) + body
        assertEquals(big(2100, 1) to BigInteger.ONE, AttestUtil.parseDerSig(long))
        // refusals around the same readers
        assertEquals(null, AttestUtil.parseDerSig(byteArrayOf(0x30, 0x81.toByte(), 5, 2, 1, 1, 2, 1, 1)))
        assertEquals(null, AttestUtil.parseDerSig(short + byteArrayOf(0)))
    }

    @Test
    fun azureRuntimeDataBinding() = Deadline.within {
        val binding = Kill05GcpAmdKit.BINDING
        val want = AttestUtil.hex(Attest.bindingBytes(binding))
        val runtime = "{\"user-data\":\"$want\"}".toByteArray(Charsets.UTF_8)
        val rd = AttestUtil.sha256(runtime) + ByteArray(32)
        assertEquals("", AttestUtil.checkAzureRuntimeDataBinding(rd, runtime, binding))
        val dirty = rd.copyOf()
        dirty[40] = 1
        assertEquals("report_data[32:64] is not zero (not an Azure runtime-data hash)", AttestUtil.checkAzureRuntimeDataBinding(dirty, runtime, binding))
        val last = rd.copyOf()
        last[63] = 1
        assertEquals("report_data[32:64] is not zero (not an Azure runtime-data hash)", AttestUtil.checkAzureRuntimeDataBinding(last, runtime, binding))
        assertEquals("report_data is not 64 bytes", AttestUtil.checkAzureRuntimeDataBinding(ByteArray(63), runtime, binding))
        assertNotNull(runtime)
        assertArrayEquals(rd.copyOf(32), AttestUtil.sha256(runtime))
    }
}
