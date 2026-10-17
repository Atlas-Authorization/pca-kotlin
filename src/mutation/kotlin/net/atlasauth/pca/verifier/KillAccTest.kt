package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for IntentAcc.kt (rule 15: accumulator / monitor declarations, values, pre-states, reservation receipts,
 * sequencer key sets, receipt-against-holder). Oracle: the TS reference packages/pca/src/intent-acc.ts, run on targeted
 * inputs by tools/pca-audit/kotlin-mutate/killAcc-oracle-gen.mjs -> test-data/killAcc.json. Every case pins one boundary or
 * one disjunct; reasons are the reference's exact strings.
 */
class KillAccTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val cases: Map<String, List<Map<String, Any?>>> by lazy {
            val root = Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killAcc.json")), Charsets.UTF_8)) as Map<String, Any?>
            (root["cases"] as List<Map<String, Any?>>).groupBy { it["fn"] as String }
        }
        const val NOW = 1_800_000_000_000.0
    }

    private fun of(fn: String): List<Map<String, Any?>> = cases[fn]!!.also { assertTrue(fn, it.isNotEmpty()) }
    @Suppress("UNCHECKED_CAST") private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun lng(o: Any?): Long = (o as Json.Num).raw.toLong()
    private fun dbl(o: Any?): Double = (o as Json.Num).raw.toDouble()

    private fun reasons(fn: String, f: (Any?) -> String?) {
        for (c in of(fn)) assertEquals(c["name"] as String, c["expect"], f(c["in"]))
    }

    @Test fun accumulatorDecl() = reasons("acc") { IntentAcc.accumulatorDeclError(it) }
    @Test fun monitorDecl() = reasons("mon") { IntentAcc.monitorDeclError(it) }
    @Test fun receiptShape() = reasons("rshape") { IntentAcc.receiptShapeError(it) }
    @Test fun keySetShape() = reasons("ksshape") { IntentAcc.keySetShapeError(it) }
    @Test fun trackedKeySet() = reasons("tracked") { IntentAcc.trackedKeySetError(mp(it)["t"]) }
    @Test fun distinctKey() = reasons("dkey") { IntentAcc.distinctKey(mp(it)["x"]) }

    @Test fun monitorStates() {
        for (c in of("states")) assertEquals(c["name"] as String, c["expect"], IntentAcc.monitorStates(mp(c["in"])))
    }

    @Test fun accSelects() {
        for (c in of("sel")) {
            val i = mp(c["in"])
            assertEquals(c["name"] as String, c["expect"], IntentAcc.accSelects(mp(i["a"]), i["verb"] as String, i["schema"]))
        }
    }

    @Test fun accValueOf() {
        for (c in of("val")) {
            val i = mp(c["in"])
            val e = mp(c["expect"])
            val v = IntentAcc.accValueOf(mp(i["a"]), i["verb"] as String, mp(i["params"]), i["schema"])
            val n = c["name"] as String
            assertEquals(n, e["reason"], v.reason)
            assertEquals(n, lng(e["value"]), v.value)
            assertEquals(n, e["key"], v.key)
        }
    }

    @Test fun preState() {
        for (c in of("pre")) {
            val i = mp(c["in"])
            assertEquals(c["name"] as String, c["expect"], IntentAcc.preStateError(i["agg"], i["s"]))
        }
    }

    @Test fun combineAndPreValue() {
        for (c in of("combine")) {
            val i = mp(c["in"])
            val got = IntentAcc.combineAcc(i["agg"], mp(i["pre"]), IntentAcc.AccValue(null, lng(i["value"]), i["key"] as String?))
            assertEquals(c["name"] as String, c["expect"]?.let { lng(it) }, got)
        }
        for (c in of("prev")) {
            val i = mp(c["in"])
            assertEquals(c["name"] as String, lng(c["expect"]), IntentAcc.preValue(i["agg"], mp(i["pre"])))
        }
    }

    @Test fun receiptArithmetic() {
        for (c in of("arith")) {
            val i = mp(c["in"])
            assertEquals(c["name"] as String, c["expect"], IntentAcc.receiptArithmeticOk(i["agg"], mp(i["r"]), lng(i["value"])))
        }
    }

    @Test fun digests() {
        for (c in of("resdig")) assertEquals(c["name"] as String, c["expect"], IntentAcc.pcactnReservationDigest(mp(mp(c["in"])["p"])))
        for (c in of("rdig")) assertEquals(c["name"] as String, c["expect"], IntentAcc.receiptDigest(mp(c["in"])["r"]))
        for (c in of("ksdig")) assertEquals(c["name"] as String, c["expect"], IntentAcc.keySetDigest(mp(c["in"])["k"]))
    }

    @Test fun receiptSignature() {
        for (c in of("rsig")) {
            val i = mp(c["in"])
            val pin = if (i.containsKey("pin")) mp(i["pin"]) else null
            assertEquals(c["name"] as String, c["expect"], IntentAcc.verifyReceiptSignature(mp(i["r"]), i["signer"] as String, pin))
        }
    }

    @Test fun keySetSignature() {
        for (c in of("ksverify")) {
            val i = mp(c["in"])
            assertEquals(c["name"] as String, c["expect"], IntentAcc.verifyKeySet(i["k"], i["root"] as String, i["rootPqPk"], i.containsKey("rootPqPk")))
        }
    }

    private fun holder(i: Map<String, Any?>, now: Double = dbl(i["now"]), maxR: Double? = null, maxK: Double? = null): Boolean =
        IntentAcc.verifyReceiptAgainstHolder(
            mp(i["r"]), mp(i["holder"]), i["keySets"], now,
            maxR ?: if (i.containsKey("maxR")) dbl(i["maxR"]) else IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble(),
            maxK ?: if (i.containsKey("maxK")) dbl(i["maxK"]) else IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble(),
            i["tracked"],
        )

    @Test fun receiptAgainstHolder() {
        for (c in of("holder")) assertEquals(c["name"] as String, c["expect"], holder(mp(c["in"])))
    }

    /** Values JSON cannot carry (NaN, infinities): the reference's isInt / isNonNeg refuse them all. */
    @Test fun receiptAgainstHolderNonFinite() {
        val valid = mp(of("holder").first { it["name"] == "holder/valid" }["in"])
        assertTrue(holder(valid))
        for (bad in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            assertFalse("now $bad", holder(valid, now = bad))
            assertFalse("maxR $bad", holder(valid, maxR = bad))
            assertFalse("maxK $bad", holder(valid, maxK = bad))
        }
        assertFalse(holder(valid, maxR = -0.0))
        assertFalse(holder(valid, maxK = -0.0))
        assertTrue(holder(valid, maxR = 0.0 + 900_000))
        assertNull(IntentAcc.trackedKeySetError(mapOf("version" to 1L, "digest" to Pca.b64(ByteArray(32)))))
    }
}
