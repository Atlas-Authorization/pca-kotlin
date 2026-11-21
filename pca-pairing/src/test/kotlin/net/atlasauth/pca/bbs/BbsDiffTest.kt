package net.atlasauth.pca.bbs

import java.math.BigInteger
import net.atlasauth.pca.aggsig.Oracle
import net.atlasauth.pca.aggsig.Oracle.bytes
import net.atlasauth.pca.aggsig.Oracle.bytesList
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference corpus (test-data/ref-bbs.json.gz) through the native BBS port. */
@Suppress("UNCHECKED_CAST")
class BbsDiffTest {
    private val m = "ref-bbs"

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun unhex(s: Any?): BigInteger = BigInteger(s as String, 16)

    private fun hex(n: BigInteger): String = String.format("%064x", n)

    // a JSON null index (the reference passes NaN) is out of range for any list; the length check comes first in the cases that carry one
    private fun ints(list: Any?): List<Int> = (list as List<Any?>).map { if (it == null) Int.MIN_VALUE else it.toString().toInt() }

    private fun result(r: Bbs.Result): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["ok"] = r.ok
        if (!r.ok) o["reason"] = r.reason
        return o
    }

    @Test fun hashToScalar() = Oracle.each(m, "hashToScalar") { a -> hex(Bbs.hashToScalar(bytes(a[0]), a[1] as String)) }
    @Test fun mapMessageToScalarAsHash() = Oracle.each(m, "mapMessageToScalarAsHash") { a -> hex(Bbs.mapMessageToScalarAsHash(bytes(a[0]))) }

    @Test fun createGenerators() = Oracle.each(m, "createGenerators") { a -> Bbs.createGenerators(a[0].toString().toInt()) }

    @Test fun keyGen() = Oracle.each(m, "keyGen") { a -> hex(Bbs.keyGen(bytes(a[0]), bytes(a[1]))) }
    @Test fun skToPk() = Oracle.each(m, "skToPk") { a -> Bbs.skToPk(unhex(a[0])) }

    @Test fun sign() = Oracle.each(m, "sign") { a -> Bbs.sign(unhex(a[0]), bytes(a[1]), bytes(a[2]), bytesList(a[3])) }

    @Test fun verifyDetailed() = Oracle.each(m, "verifyDetailed") { a ->
        result(Bbs.verifyDetailed(bytes(a[0]), bytes(a[1]), bytes(a[2]), bytesList(a[3])))
    }

    @Test fun proofGen() = Oracle.each(m, "proofGen") { a ->
        val rs = (a[6] as List<Any?>).map { unhex(it) }
        Bbs.proofGen(bytes(a[0]), bytes(a[1]), bytes(a[2]), bytes(a[3]), bytesList(a[4]), ints(a[5]), rs)
    }

    @Test fun proofVerifyDetailed() = Oracle.each(m, "proofVerifyDetailed") { a ->
        result(Bbs.proofVerifyDetailed(bytes(a[0]), bytes(a[1]), bytes(a[2]), bytes(a[3]), bytesList(a[4]), ints(a[5])))
    }

    @Test fun capabilityAttributes() = Oracle.each(m, "capabilityAttributes") { a -> BbsCredential.capabilityAttributes(map(a[0])) }

    @Test fun issueCapabilityCredential() = Oracle.each(m, "issueCapabilityCredential") { a ->
        BbsCredential.issueCapabilityCredential(map(a[0]), unhex(a[1]), bytes(a[2]), bytes(a[3]))
    }

    @Test fun verifyCredential() = Oracle.each(m, "verifyCredential") { a -> BbsCredential.verifyCredential(map(a[0])) }

    @Test fun verifyPresentation() = Oracle.each(m, "verifyPresentation") { a ->
        val opts = map(a[1])
        BbsCredential.verifyPresentation(
            map(a[0]),
            if (opts.containsKey("pk")) bytes(opts["pk"]) else null,
            if (opts.containsKey("disclosed")) opts["disclosed"] as List<Map<String, Any?>> else null,
            if (opts.containsKey("presentationHeader")) bytes(opts["presentationHeader"]) else null,
        )
    }

    /** Presentation round trip through the randomized presentCredential. */
    @Test fun presentRoundTrip() {
        val sk = Bbs.keyGen(ByteArray(32))
        val pk = Bbs.skToPk(sk)
        val cv = linkedMapOf<String, Any?>("type" to "amount")
        val cap = linkedMapOf<String, Any?>("issuer" to "i", "holder" to "h", "caveats" to listOf(cv))
        val cred = BbsCredential.issueCapabilityCredential(cap, sk, pk, null)
        assertTrue(BbsCredential.verifyCredential(cred))
        val pres = BbsCredential.presentCredential(cred, listOf("iss"), byteArrayOf(1))
        assertTrue(BbsCredential.verifyPresentation(pres, null, null, null))
        assertTrue(BbsCredential.verifyPresentation(pres, pk, null, byteArrayOf(1)))
        assertFalse(BbsCredential.verifyPresentation(pres, null, null, byteArrayOf(2)))
        try {
            BbsCredential.presentCredential(cred, listOf("nope"), null)
            fail("unknown attribute must throw")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
