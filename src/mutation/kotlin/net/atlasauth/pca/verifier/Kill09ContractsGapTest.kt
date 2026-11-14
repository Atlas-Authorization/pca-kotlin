package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.canon
import net.atlasauth.pca.verifier.K08K4.contract
import net.atlasauth.pca.verifier.K08K4.num
import net.atlasauth.pca.verifier.K08K4.state0
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger

/**
 * Contracts, ContractEnforcer and the small helpers they share: the Java-facing overloads and static bridges of the defaulted entry
 * points, a fatal error crossing the contract advance, the JavaScript number text of a non-finite value, the session revocation
 * primitive on non-canonical number spellings, the SQLite file helpers as Java sees them, and a budget profile run with no rounds.
 */
@Suppress("UNCHECKED_CAST")
class Kill09ContractsGapTest {
    // ---- the omitted-argument overloads of advanceContract / checkAndAdvanceContract

    @Test fun advanceContractOverloadsAgreeWithTheDefaultedCalls() {
        val c = contract()
        val a = act("read")
        val s = state0()
        val any = Any::class.java
        val three = Contracts::class.java.getMethod("advanceContract", any, any, any)
        val four = Contracts::class.java.getMethod("advanceContract", any, any, any, any)
        val five = Contracts::class.java.getMethod("advanceContract", any, any, any, any, any)
        val r3 = three.invoke(Contracts, s, a, c) as Map<String, Any?>
        assertEquals(true, r3["ok"])
        assertEquals(canon(Contracts.advanceContract(s, a, c)), canon(r3))
        val later = num(K08K4.NOW + 9.0)
        val r4 = four.invoke(Contracts, s, a, c, later) as Map<String, Any?>
        assertEquals(true, r4["ok"])
        assertEquals("1700000000009", canon((r4["next"] as Map<String, Any?>)["now"]))
        assertEquals(canon(Contracts.advanceContract(s, a, c, later)), canon(r4))
        val r5 = five.invoke(Contracts, s, a, c, null, num(0.0)) as Map<String, Any?>
        assertEquals(true, r5["ok"])
        assertEquals(canon(Contracts.advanceContract(s, a, c, null, num(0.0))), canon(r5))
        val stale = five.invoke(Contracts, s, a, c, null, num(4.0)) as Map<String, Any?>
        assertEquals(false, stale["ok"])
        assertEquals(listOf("<state>: stale state head (seq)"), stale["reasons"])
    }

    @Test fun checkAndAdvanceContractOverloadsAgreeWithTheDefaultedCalls() {
        val c = contract()
        val a = act("read")
        val s = state0()
        val any = Any::class.java
        val bool = java.lang.Boolean.TYPE
        val four = Contracts::class.java.getMethod("checkAndAdvanceContract", bool, any, any, any)
        val five = Contracts::class.java.getMethod("checkAndAdvanceContract", bool, any, any, any, any)
        val six = Contracts::class.java.getMethod("checkAndAdvanceContract", bool, any, any, any, any, any)
        for (permitted in listOf(true, false)) {
            val r4 = four.invoke(Contracts, permitted, s, a, c) as Map<String, Any?>
            assertEquals(permitted, r4["allow"])
            assertEquals(canon(Contracts.checkAndAdvanceContract(permitted, s, a, c)), canon(r4))
            val r5 = five.invoke(Contracts, permitted, s, a, c, num(K08K4.NOW + 3.0)) as Map<String, Any?>
            assertEquals(permitted, r5["allow"])
            assertEquals(canon(Contracts.checkAndAdvanceContract(permitted, s, a, c, num(K08K4.NOW + 3.0))), canon(r5))
            val r6 = six.invoke(Contracts, permitted, s, a, c, null, num(0.0)) as Map<String, Any?>
            assertEquals(permitted, r6["allow"])
            assertEquals(canon(Contracts.checkAndAdvanceContract(permitted, s, a, c, null, num(0.0))), canon(r6))
            val stale = six.invoke(Contracts, permitted, s, a, c, null, num(2.0)) as Map<String, Any?>
            assertEquals(false, stale["allow"])
        }
    }

    // ---- a fatal error is never swallowed by the contract advance; a contained one is a refusal

    @Test fun aFatalErrorCrossesAdvanceContractAndAContainedOneIsRefused() {
        val c = contract()
        val fatalState = K08K4.Probe(state0(), "now", 0) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { Contracts.advanceContract(fatalState, act("read"), c) }
        val contained = K08K4.Probe(state0(), "now", 0) { K08K4.boom() }
        val r = Contracts.advanceContract(contained, act("read"), c)
        assertEquals(false, r["ok"])
        assertTrue((r["reasons"] as List<Any?>).contains("<state>: advance error (fail closed)"))
    }

    // ---- ContractEnforcer.signReset as the static Java entry point

    @Test fun signResetIsReachableAsAStaticMethodAndSignsTheContractAndSequence() {
        val seed = K08K4.key.seed
        val method = ContractEnforcer::class.java.getMethod("signReset", ByteArray::class.java, String::class.java, java.lang.Long.TYPE)
        val viaJava = method.invoke(null, seed, "c1", 3L) as String
        assertTrue(viaJava.isNotEmpty())
        assertEquals(ContractEnforcer.signReset(seed, "c1", 3L), viaJava)
        assertFalse(viaJava == method.invoke(null, seed, "c1", 4L))
        assertFalse(viaJava == method.invoke(null, seed, "c2", 3L))
    }

    // ---- JavaScript number text of a non-finite value

    @Test fun nonFiniteNumbersPrintAsJavaScriptPrintsThem() {
        for ((raw, text) in listOf("NaN" to "NaN", "Infinity" to "Infinity", "-Infinity" to "-Infinity", "1.5" to "1.5", "-0" to "0", "1e21" to "1e+21")) {
            assertEquals(raw, text, IntentRevocation.jsText(Json.Num(raw), true))
        }
        assertEquals("NaN", AttestUtil.jsNumString(Double.NaN))
        assertEquals("Infinity", AttestUtil.jsNumString(Double.POSITIVE_INFINITY))
        assertEquals("-Infinity", AttestUtil.jsNumString(Double.NEGATIVE_INFINITY))
        assertEquals("1.5", AttestUtil.jsNumString(1.5))
        assertEquals("-2", AttestUtil.jsNumString(-2.0))
    }

    // ---- the session revocation primitive normalises its numbers before verifying the signed epoch

    @Test fun thePrimitiveVerifiesAnEpochWhoseNumbersAreSpelledNonCanonically() {
        val key = K08K4.key
        val guardian = key.id()
        val grant = IntentRevocation.sessionRevocationScope("s1")
        val root = IntentRevocation.revsetRoot(emptyList())
        val signedBody = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to grant, "epoch" to 0L, "set_size" to 0L, "root" to root,
            "issued_at" to 1800000000000L, "not_after" to 1800000600000L,
        )
        val sig = Pca.b64(key.sign(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(signedBody))))
        fun primitive(epoch: Json.Num, setSize: Json.Num, issued: Json.Num, notAfter: Json.Num): Map<String, Any?> {
            val ep = linkedMapOf<String, Any?>(
                "instance_id" to "i", "grant_ref" to grant, "epoch" to epoch, "set_size" to setSize, "root" to root,
                "issued_at" to issued, "not_after" to notAfter, "guardian" to guardian, "sig" to sig,
            )
            return linkedMapOf<String, Any?>(
                "epoch" to ep, "revoked" to ArrayList<Any?>(), "session" to "s1", "authority" to guardian, "ids" to ArrayList<Any?>(),
                "now" to Json.Num("1800000000100"), "max_age_ms" to Json.Num("1000000"),
            )
        }
        val canonical = primitive(Json.Num("0"), Json.Num("0"), Json.Num("1800000000000"), Json.Num("1800000600000"))
        assertEquals(null, IntentRevocation.primitiveReason(canonical))
        assertTrue(IntentRevocation.checkPrimitive(canonical))
        val spelled = primitive(Json.Num("0.0"), Json.Num("0e0"), Json.Num("1800000000000.0"), Json.Num("1.8000006e12"))
        assertEquals(null, IntentRevocation.primitiveReason(spelled))
        assertTrue(IntentRevocation.checkPrimitive(spelled))
        // the same epoch under a different session is for a different grant
        val other = LinkedHashMap(spelled).also { it["session"] = "s2" }
        assertNotNull(IntentRevocation.primitiveReason(other))
        assertFalse(IntentRevocation.checkPrimitive(other))
    }

    // ---- the SQLite file helpers as Java sees them (static methods of the outer class)

    @Test fun theSqliteFileHelpersAreStaticMethodsOfTheStore() {
        val dir = Files.createTempDirectory("pca-sqlite")
        try {
            val file = dir.resolve("a").resolve("b.db")
            val url = "jdbc:sqlite:" + file.toString()
            val find = PcaJdbcStateStore::class.java.getMethod("sqliteFile", String::class.java)
            val ensure = PcaJdbcStateStore::class.java.getMethod("ensureSqliteFile", String::class.java)
            assertEquals(file.toAbsolutePath(), find.invoke(null, url))
            assertEquals(null, find.invoke(null, "jdbc:sqlite::memory:"))
            assertEquals(null, find.invoke(null, "jdbc:h2:mem:x"))
            assertFalse(Files.exists(file))
            assertEquals(file.toAbsolutePath(), ensure.invoke(null, url))
            assertTrue(Files.isRegularFile(file))
            assertEquals(file.toAbsolutePath(), ensure.invoke(null, url))
            assertEquals(null, ensure.invoke(null, "jdbc:sqlite::memory:"))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    // ---- the budget profile with no rounds runs none: only the setup CAS reaches the burst key

    private class CountingBudgets : Authorize.BudgetStore {
        val map = HashMap<String, Risk.Budget>()
        val burstCas = AtomicInteger()

        @Synchronized override fun budget(key: String): Risk.Budget? = map[key]

        @Synchronized override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean {
            if (key.startsWith("b3:")) burstCas.incrementAndGet()
            if (map[key] != old) return false
            map[key] = new
            return true
        }
    }

    @Test fun aBudgetProfileWithZeroRoundsRunsNoBurst() {
        val none = CountingBudgets()
        val report = StoreConformance.runBudgetStore({ none }, durable = false, threads = 3, rounds = 0, name = "counting")
        assertTrue(report.render(), report.render().contains("pass budget-burst: 0 rounds x 3 threads"))
        assertEquals(1, none.burstCas.get())
        val one = CountingBudgets()
        val report1 = StoreConformance.runBudgetStore({ one }, durable = false, threads = 3, rounds = 1, name = "counting")
        assertTrue(report1.render(), report1.render().contains("pass budget-burst: 1 rounds x 3 threads"))
        assertEquals(1 + 3, one.burstCas.get())
    }
}
