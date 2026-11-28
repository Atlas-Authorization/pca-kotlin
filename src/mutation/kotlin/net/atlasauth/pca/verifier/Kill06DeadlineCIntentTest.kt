package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deadline tests: Bundle.compareVersion, IntentAcc (exactKeys through the receipt / window shapes, verifyReceiptAgainstHolder),
 * IntentRevocation.revokedListError and IntentV2.Context.get / has. The receipt fixture is the reference-verified
 * `holder/valid` case of test-data/killAcc.json (TS packages/pca/src/intent-acc.ts says true).
 */
class Kill06DeadlineCIntentTest {
    @Test fun compareVersionOrdersNumericPartsAndPadsWithZero() {
        Deadline.within {
            assertEquals(-1, Bundle.compareVersion("1.2.3", "1.10.0"))
            assertEquals(1, Bundle.compareVersion("2.0.0", "1.99.9"))
            assertEquals(0, Bundle.compareVersion("1.0", "1.0.0"))
            assertEquals(1, Bundle.compareVersion("1.0.1", "1.0"))
            assertEquals(-1, Bundle.compareVersion("1.0", "1.0.1"))
            assertEquals(-1, Bundle.compareVersion("0.9", "1.0"))
            assertEquals(0, Bundle.compareVersion("3.4.5", "3.4.5"))
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun holderValid(): Map<String, Any?> {
        val root = Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killAcc.json")), Charsets.UTF_8)) as Map<String, Any?>
        val c = (root["cases"] as List<Map<String, Any?>>).first { it["name"] == "holder/valid" }
        return c["in"] as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun receiptAgainstHolderAndItsShapes() {
        val i = holderValid()
        val r = i["r"] as Map<String, Any?>
        val now = IntentJs.num(i["now"])!!
        Deadline.within {
            // exactKeys: the ledger member {head, index} is checked for exactly these keys
            assertNull(IntentAcc.receiptShapeError(r))
            val extra = LinkedHashMap(r); extra["ledger"] = LinkedHashMap(r["ledger"] as Map<String, Any?>).also { it["x"] = 1L }
            assertEquals("receipt.ledger must be {index, head}", IntentAcc.receiptShapeError(extra))
            val short = LinkedHashMap(r); short["ledger"] = linkedMapOf<String, Any?>("index" to 7L, "zzzz" to "x")
            assertEquals("receipt.ledger must be {index, head}", IntentAcc.receiptShapeError(short))
            assertTrue(IntentAcc.verifyReceiptAgainstHolder(r, i["holder"] as Map<String, Any?>, i["keySets"], now, IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble(), IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble(), i["tracked"]))
            // a holder whose root is not the key set's sequencer finds no key set to verify against
            val wrong = LinkedHashMap(i["holder"] as Map<String, Any?>); wrong["root"] = r["signer"]
            assertFalse(IntentAcc.verifyReceiptAgainstHolder(r, wrong, i["keySets"], now, IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble(), IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble(), null))
            assertFalse(IntentAcc.verifyReceiptAgainstHolder(r, i["holder"] as Map<String, Any?>, ArrayList<Any?>(), now, IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble(), IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble(), null))
        }
    }

    @Test fun accumulatorWindowsCheckTheirExactKeys() {
        fun acc(win: Map<String, Any?>) = linkedMapOf<String, Any?>(
            "id" to "trip_spend", "agg" to "sum", "unit" to "usd_cents", "sel" to linkedMapOf<String, Any?>("accumulates_into" to "spend.usd_cents"),
            "win" to win, "key" to null, "domain_max" to 500000L, "holder" to linkedMapOf<String, Any?>("kind" to "site_local"),
        )
        Deadline.within {
            assertNull(IntentAcc.accumulatorDeclError(acc(linkedMapOf("kind" to "sliding", "ms" to 1L))))
            assertNull(IntentAcc.accumulatorDeclError(acc(linkedMapOf("kind" to "period", "ms" to 5L, "t0" to 7L))))
            val at = "accumulator 'trip_spend'"
            assertEquals("$at: win sliding needs a positive ms", IntentAcc.accumulatorDeclError(acc(linkedMapOf("kind" to "sliding", "ms" to 1L, "t0" to 0L))))
            assertEquals("$at: win period needs a positive ms and t0 >= 0", IntentAcc.accumulatorDeclError(acc(linkedMapOf("kind" to "period", "ms" to 5L))))
            assertEquals("$at: win period needs a positive ms and t0 >= 0", IntentAcc.accumulatorDeclError(acc(linkedMapOf("kind" to "period", "ms" to 5L, "t0" to 7L, "extra" to 1L))))
        }
    }

    @Test fun revokedListIsCheckedInOrderAgainstItsEpoch() {
        fun epoch(list: List<String>, size: Long = list.size.toLong()) =
            linkedMapOf<String, Any?>("set_size" to size, "epoch" to size, "root" to IntentRevocation.revsetRoot(list))
        Deadline.within {
            for (l in listOf(emptyList(), listOf("a"), listOf("a", "b", "c", "d"), listOf("a", "b", "é", "😀"))) {
                assertNull(l.toString(), IntentRevocation.revokedListError(epoch(l), ArrayList<Any?>(l)))
            }
            val order = "revoked must be sorted by UTF-8 bytes and distinct"
            assertEquals(order, IntentRevocation.revokedListError(epoch(listOf("a", "c", "b")), ArrayList<Any?>(listOf("a", "c", "b"))))
            assertEquals(order, IntentRevocation.revokedListError(epoch(listOf("a", "a")), ArrayList<Any?>(listOf("a", "a"))))
            assertEquals(order, IntentRevocation.revokedListError(epoch(listOf("a", "b", "c", "d", "c")), ArrayList<Any?>(listOf("a", "b", "c", "d", "c"))))
            assertEquals("the epoch must be numbered by its set size and list exactly set_size ids", IntentRevocation.revokedListError(epoch(listOf("a", "b"), 3L), ArrayList<Any?>(listOf("a", "b"))))
            assertEquals("the revoked list is not the signed set (root mismatch)", IntentRevocation.revokedListError(epoch(listOf("a", "b")), ArrayList<Any?>(listOf("a", "x"))))
        }
    }

    @Test fun contextGetAndHaveWalkEveryPathStep() {
        val ctx = IntentV2.Context.fromJson(
            linkedMapOf<String, Any?>(
                "session" to linkedMapOf<String, Any?>("root" to "R", "grants" to linkedMapOf<String, Any?>("g" to linkedMapOf<String, Any?>("deep" to 3L))),
                "acc" to linkedMapOf<String, Any?>("last_seq" to 4L),
            ),
        )
        Deadline.within {
            assertEquals("R", ctx.get("session", "root"))
            assertEquals(3.0, IntentJs.num(ctx.get("session", "grants", "g", "deep")))
            assertEquals(4.0, IntentJs.num(ctx.get("acc", "last_seq")))
            assertNull(ctx.get("session", "nope", "deep"))
            assertNull(ctx.get("nope"))
            assertTrue(ctx.has("session"))
            assertTrue(ctx.has("session", "root"))
            assertTrue(ctx.has("session", "grants", "g", "deep"))
            assertFalse(ctx.has("session", "grants", "g", "other"))
            assertFalse(ctx.has("session", "nope", "deep"))
            assertFalse(ctx.has("acc", "session", "root"))
        }
    }
}
