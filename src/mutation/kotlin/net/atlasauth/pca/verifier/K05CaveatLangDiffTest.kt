package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the caveat language v2 (caveat-lang.ts) and the K1 request headers
 * (require-pca.ts presentedK1): test-data/k05-caveatlang.json.gz from tools/pca-audit/k05-oracles/caveatlang-oracle.mts.
 * Every shape check asserts the EXACT reason (or null), every verdict the exact JSON result. Typed-port mappings:
 *  - a clock (`now`) that is not a safe integer (fractional, -0, beyond 2^53) passes as Long.MAX_VALUE, which the verifier refuses
 *    exactly like the reference;
 *  - verifyNarrow(n, grant, chain, {now, action_digest}) -> verifyNarrow(n, grant, chain, now, actionDigest);
 *  - k1 objects go through K1Input.fromJson (non-object = no K1 input), ctx {now, action} -> (now, action);
 *  - a "... error (fail closed): <message>" reason compares up to the colon (the message is the host runtime's exception text).
 * Skipped: dischargeRequests (the escalation request builder is not part of the Kotlin SDK); verifyDischarge with a binding
 * whose `pins` is not an array (DischargeBinding.pins is a typed List: the reference's 'no issuer is pinned' is unrepresentable).
 */
class K05CaveatLangDiffTest {
    companion object {
        const val FILE = "k05-caveatlang.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(fn: String, bad: List<String>) = assertTrue("$fn: ${bad.size} divergent case(s):\n" + bad.take(60).joinToString("\n"), bad.isEmpty())

        /** A reference clock: a safe integer (not -0) passes as is, anything else as a value the verifier refuses. */
        fun clock(v: Any?): Long = if (IntentJs.isInt(v)) IntentJs.lng(v) else Long.MAX_VALUE

        /** "x error (fail closed): <runtime message>" -> "x error (fail closed):" (the message is host-specific). */
        fun fc(r: Any?): Any? {
            if (r !is String) return r
            val i = r.indexOf(" error (fail closed): ")
            return if (i < 0) r else r.substring(0, i + " error (fail closed):".length)
        }

        @Suppress("UNCHECKED_CAST")
        fun fcOut(o: Any?): Any? {
            if (o !is Map<*, *>) return o
            val m = LinkedHashMap(o as Map<String, Any?>)
            if (m.containsKey("reason")) m["reason"] = fc(m["reason"])
            if (m["reasons"] is List<*>) m["reasons"] = (m["reasons"] as List<*>).map { fc(it) }
            return m
        }

        fun show(v: Any?): String = runCatching { Json.canonicalize(v) }.getOrElse { v.toString() }

        fun bound(b: List<CaveatLang.BoundCaveat>?): Any? = b?.map { linkedMapOf<String, Any?>("caveat" to it.caveat, "hop" to it.hop, "cap_hash" to it.capHash) }
    }

    private fun diff(fn: String, run: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val want = fcOut(c["out"])
            val got = try { fcOut(run(args(c))) } catch (t: Throwable) { "THROWS $t" }
            if (!IntentJs.jsonEquals(want, got)) bad.add("${c["name"]}\n  want: ${show(want)}\n  got:  $got")
        }
        report(fn, bad)
    }

    // ---- shape checks: exact reason or null ----
    @Test fun spiffeIdError() = diff("spiffeIdError") { CaveatLang.spiffeIdError(it[0]) }
    @Test fun needsDischargeError() = diff("needsDischargeError") { CaveatLang.needsDischargeError(it[0]) }
    @Test fun dischargeShapeError() = diff("dischargeShapeError") { CaveatLang.dischargeShapeError(it[0]) }
    @Test fun narrowShapeError() = diff("narrowShapeError") { CaveatLang.narrowShapeError(it[0]) }
    @Test fun maxUsesError() = diff("maxUsesError") { CaveatLang.maxUsesError(it[0]) }
    @Test fun spiffeBoundError() = diff("spiffeBoundError") { CaveatLang.spiffeBoundError(it[0]) }
    @Test fun deriveError() = diff("deriveError") { CaveatLang.deriveError(it[0]) }
    @Test fun maxUsesSlotKey() = diff("maxUsesSlotKey") { CaveatLang.maxUsesSlotKey(it[0] as String, it[1] as String, IntentJs.lng(it[2]).toInt()) }

    @Test fun evaluateDerive() = diff("evaluateDerive") { a ->
        val inp = IntentJs.obj(a[1])
        @Suppress("UNCHECKED_CAST")
        val claims = (inp["claims"] as Map<String, Any?>).mapValues { (it.value as? Map<String, Any?>) ?: emptyMap() } // a non-object claim set reads as no claims (reference ownGet)
        CaveatLang.evaluateDerive(IntentJs.obj(a[0]), clock(inp["now"]), inp["action"], inp["history"] as? List<*>, claims)
    }

    @Test fun verifyDischarge() {
        val bad = ArrayList<String>()
        var skipped = 0
        for (c in of("verifyDischarge")) {
            val a = args(c)
            val b = IntentJs.obj(a[2])
            val pins = b["pins"]
            if (pins !is List<*>) { skipped++; continue } // typed pins: see the class comment
            val want = fcOut(c["out"])
            val got = try {
                val bind = CaveatLang.DischargeBinding(
                    capHash = b["cap_hash"] as String,
                    actionDigest = b["action_digest"] as? String,
                    pins = pins.map { CaveatLang.DischargePin.fromJson(it) },
                    now = clock(b["now"]),
                    revoked = (b["revoked"] as? List<*>)?.filterIsInstance<String>(), // the reference ignores a non-array list
                )
                val r = CaveatLang.verifyDischarge(a[0], a[1], bind)
                fcOut(if (r.ok) linkedMapOf<String, Any?>("ok" to true, "digest" to r.digest, "claims" to r.claims) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason))
            } catch (t: Throwable) { "THROWS $t" }
            if (!IntentJs.jsonEquals(want, got)) bad.add("${c["name"]}\n  want: ${show(want)}\n  got:  $got")
        }
        assertEquals(2, skipped)
        report("verifyDischarge", bad)
    }

    @Test fun verifyNarrow() = diff("verifyNarrow") { a ->
        val b = IntentJs.obj(a[3])
        val r = CaveatLang.verifyNarrow(a[0], a[1], a[2], clock(b["now"]), b["action_digest"] as? String)
        if (r.ok) linkedMapOf<String, Any?>("ok" to true, "caveats" to r.caveats) else linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
    }

    @Test fun boundCaveats() = diff("boundCaveats") { a -> bound(if (a.size > 1) CaveatLang.boundCaveats(a[0], a[1]) else CaveatLang.boundCaveats(a[0])) }

    @Test fun dischargeRequestsIsNotPorted() {
        // the escalation request builder (dischargeRequests) is not part of the Kotlin SDK: nothing to replay
        assertEquals(20, of("dischargeRequests").size)
    }

    @Test fun evaluateK1() = diff("evaluateK1") { a ->
        val ctx = a[3] as? Map<*, *>
        val r = CaveatLang.evaluateK1(a[0], a[1], CaveatLang.K1Input.fromJson(a[2]), clock(ctx?.get("now")), ctx?.get("action"))
        linkedMapOf<String, Any?>("ok" to r.ok, "failed" to r.failed, "reasons" to r.reasons, "plain" to r.plain, "bound" to bound(r.bound))
    }

    @Test fun evaluateCaveatsK1() = diff("evaluateCaveatsK1") { a ->
        val r = CaveatLang.evaluateCaveatsK1(a[0], a[1], CaveatLang.K1Input.fromJson(a[2]), a[3])
        linkedMapOf<String, Any?>("allow" to r.ok, "failed" to r.failed)
    }

    @Test fun presentedK1() {
        val bad = ArrayList<String>()
        for (c in of("presentedK1")) {
            val h = (args(c)[0] as Map<*, *>).entries.associate { it.key as String to it.value as String? }
            val want = IntentJs.obj(c["out"])
            val r = try { CaveatLang.presentedK1(h) } catch (t: Throwable) { bad.add("${c["name"]} THROWS $t"); continue }
            var ok = r.ok == want["ok"]
            if (ok && r.ok) {
                val v = IntentJs.obj(want["value"])
                ok = (if (v.containsKey("discharges")) r.discharges != null && IntentJs.jsonEquals(v["discharges"], r.discharges) else r.discharges == null) &&
                    (if (v.containsKey("narrow")) r.narrow !== CaveatLang.K1Input.ABSENT && IntentJs.jsonEquals(v["narrow"], r.narrow) else r.narrow === CaveatLang.K1Input.ABSENT)
            }
            if (!ok) bad.add("${c["name"]}\n  want: ${show(want)}\n  got:  ok=${r.ok} discharges=${r.discharges} narrow=${if (r.narrow === CaveatLang.K1Input.ABSENT) "<absent>" else r.narrow} error=${r.error}")
        }
        report("presentedK1", bad)
    }

    // ---- targeted kills for what the oracle cannot see (Kotlin-only surface: typed results, k1Of, the fail-closed catches) ----

    private fun okNarrow(): List<Any?> = args(of("verifyNarrow").first { it["name"] == "verifyNarrow/one ok" })

    @Test fun theClockBoundsAreTheSafeIntegerRange() {
        val a = okNarrow()
        val max = 9007199254740991L
        assertEquals("the narrow block has expired", CaveatLang.verifyNarrow(a[0], a[1], a[2], max).reason)
        assertEquals("the narrow block is from the future", CaveatLang.verifyNarrow(a[0], a[1], a[2], -max).reason)
        assertEquals("the verifier clock is not a safe integer (fail closed)", CaveatLang.verifyNarrow(a[0], a[1], a[2], max + 1).reason)
        assertEquals("the verifier clock is not a safe integer (fail closed)", CaveatLang.verifyNarrow(a[0], a[1], a[2], -max - 1).reason)
        val ok = CaveatLang.verifyNarrow(a[0], a[1], a[2], 1800000000000L)
        assertTrue(ok.ok)
        assertNull(ok.reason)
    }

    private fun throwing(src: Map<*, *>, t: Throwable): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST") val base = src as Map<String, Any?>
        return object : LinkedHashMap<String, Any?>(base) {
            override fun get(key: String): Any? = throw t
        }
    }

    @Test fun anExceptionInsideAVerifierIsAFailClosedRefusal() {
        val dc = args(of("verifyDischarge").first { it["name"] == "verifyDischarge/base" })
        val bind = CaveatLang.DischargeBinding("c", null, emptyList(), 1800000000000L)
        assertEquals("discharge error (fail closed): boom", CaveatLang.verifyDischarge(throwing(dc[0] as Map<*, *>, IllegalStateException("boom")), dc[1], bind).reason)
        assertEquals("discharge error (fail closed): unknown", CaveatLang.verifyDischarge(throwing(dc[0] as Map<*, *>, IllegalStateException()), dc[1], bind).reason)
        assertEquals("discharge error (fail closed): unknown", CaveatLang.verifyDischarge(throwing(dc[0] as Map<*, *>, StackOverflowError()), dc[1], bind).reason)
        val n = okNarrow()
        assertEquals("narrow error (fail closed): boom", CaveatLang.verifyNarrow(throwing(n[0] as Map<*, *>, IllegalStateException("boom")), n[1], n[2], 1800000000000L).reason)
        assertEquals("narrow error (fail closed): unknown", CaveatLang.verifyNarrow(throwing(n[0] as Map<*, *>, StackOverflowError()), n[1], n[2], 1800000000000L).reason)
        assertFalse(CaveatLang.verifyNarrow(throwing(n[0] as Map<*, *>, StackOverflowError()), n[1], n[2], 1800000000000L).ok)
    }

    @Test fun reserveMaxUsesCatchesAndSpendsNothingOnRefusal() {
        val b = listOf(CaveatLang.BoundCaveat(linkedMapOf<String, Any?>("type" to "max_uses", "id" to "u", "n" to Json.Num("1"), "until" to Json.Num("100")), 0, Pca.b64(ByteArray(32) { 1 })))
        val silent = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw IllegalStateException()
        }
        val r = CaveatLang.reserveMaxUses(silent, b, 10L)
        assertEquals("max_uses error (fail closed): unknown", r.reason)
        assertEquals(0, r.spent)
        val deep = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw StackOverflowError()
        }
        assertEquals("max_uses error (fail closed): unknown", CaveatLang.reserveMaxUses(deep, b, 10L).reason)
        val store = Authorize.MemoryStateStore()
        assertEquals(1, CaveatLang.reserveMaxUses(store, b, 10L).spent)
        val ex = CaveatLang.reserveMaxUses(store, b, 10L)
        assertEquals("max_uses 'u' is exhausted", ex.reason)
        assertEquals(0, ex.spent)
    }

    @Test fun resultsPrintTheirVerdict() {
        assertEquals("CaveatLang.DischargeVerdict(ok=false, reason=r)", CaveatLang.DischargeVerdict(false, null, null, "r").toString())
        assertEquals("CaveatLang.NarrowVerdict(ok=true, reason=null)", CaveatLang.NarrowVerdict(true, emptyList(), null).toString())
        assertEquals("CaveatLang.UsesVerdict(ok=true, spent=2, reason=null)", CaveatLang.UsesVerdict(true, 2, null).toString())
        assertEquals("CaveatLang.K1Result(ok=false, failed=[sealed])", CaveatLang.K1Result(false, listOf("sealed"), listOf("x"), emptyList(), emptyList()).toString())
        assertEquals("CaveatLang.Presented(ok=false, error=e)", CaveatLang.Presented(false, null, null, "e").toString())
        assertEquals(listOf("needs_discharge", "sealed", "max_uses", "derive", "spiffe_bound"), CaveatLang.K1_CAVEAT_TYPES)
    }

    @Test fun dischargeActionDigestMatchesTheReference() {
        // values from the TS reference dischargeActionDigest
        assertEquals("fQO_4Ep6SgvJsO10uuOEz-6HqHq87CIBrFwMXLO0DXM", CaveatLang.dischargeActionDigest(linkedMapOf<String, Any?>("v" to Json.Num("1"), "counter" to Json.Num("7"), "sig" to "x")))
        assertEquals("yq2xcYQzaCghRsKxpviO7GhPts3PxGuH6-Agy5yDZhw", CaveatLang.dischargeActionDigest(null))
    }

    @Test fun pinsAndK1InputReadOnlyWellTypedMembers() {
        val p = CaveatLang.DischargePin.fromJson(linkedMapOf<String, Any?>("label" to "l", "class" to "human", "pk" to "k", "pq_pk" to "q", "spiffe_id" to "s"))
        assertEquals(listOf("l", "human", "k", "q", "s"), listOf(p.label, p.cls, p.pk, p.pqPk, p.spiffeId))
        val n = Json.Num("5")
        val bad = CaveatLang.DischargePin.fromJson(linkedMapOf<String, Any?>("label" to n, "class" to n, "pk" to n, "pq_pk" to n, "spiffe_id" to n))
        assertEquals(listOf<Any?>("", "", "", null, null), listOf(bad.label, bad.cls, bad.pk, bad.pqPk, bad.spiffeId))
        val none = CaveatLang.DischargePin.fromJson("x")
        assertEquals(listOf<Any?>("", "", "", null, null), listOf(none.label, none.cls, none.pk, none.pqPk, none.spiffeId))

        val hist = arrayListOf<Any?>()
        val disc = arrayListOf<Any?>(n)
        val k = CaveatLang.K1Input.fromJson(linkedMapOf<String, Any?>(
            "pins" to arrayListOf<Any?>(linkedMapOf<String, Any?>("label" to "l")), "discharges" to disc, "narrow" to null,
            "action_digest" to "ad", "revoked_discharges" to arrayListOf<Any?>("a", null), "spiffe_id" to "s", "history" to hist,
        ))!!
        assertEquals(listOf("l"), k.pins.map { it.label })
        assertSame(disc, k.discharges)
        assertNull(k.narrow)
        assertEquals("ad", k.actionDigest)
        assertEquals(listOf("a", ""), k.revokedDischarges)
        assertEquals("s", k.spiffeId)
        assertSame(hist, k.history)
        val w = CaveatLang.K1Input.fromJson(linkedMapOf<String, Any?>("pins" to n, "discharges" to n, "action_digest" to n, "revoked_discharges" to n, "spiffe_id" to n, "history" to n))!!
        assertTrue(w.pins.isEmpty())
        assertNull(w.discharges)
        assertSame(CaveatLang.K1Input.ABSENT, w.narrow)
        assertNull(w.actionDigest)
        assertNull(w.revokedDischarges)
        assertNull(w.spiffeId)
        assertNull(w.history)
        val ad = w.withActionDigest("d")
        assertEquals("d", ad.actionDigest)
        assertSame(CaveatLang.K1Input.ABSENT, ad.narrow)
    }

    @Test fun presentedHeadersReportExactErrors() {
        fun p(vararg kv: Pair<String, String?>) = CaveatLang.presentedK1(linkedMapOf(*kv))
        val b64 = p("pca-discharges" to "!!!!")
        assertFalse(b64.ok)
        assertEquals("header is not strict base64url", b64.error)
        assertNull(b64.discharges)
        assertSame(CaveatLang.K1Input.ABSENT, b64.narrow)
        assertEquals("PCA-Discharges must be a JSON array", p("pca-discharges" to "eyJhIjoxfQ").error)
        val u8 = p("pca-narrow" to "WyL_Il0")
        assertFalse(u8.ok)
        assertEquals("header is not UTF-8", u8.error)
        assertSame(CaveatLang.K1Input.ABSENT, u8.narrow)
        val none = CaveatLang.presentedK1(null)
        assertTrue(none.ok)
        assertNull(none.error)
        assertNull(none.discharges)
        assertSame(CaveatLang.K1Input.ABSENT, none.narrow)
        val both = p("PCA-Discharges" to "WzFd", "Pca-Narrow" to "eyJhIjoxfQ")
        assertTrue(both.ok)
        assertEquals(1, both.discharges!!.size)
        assertTrue(IntentJs.jsonEquals(linkedMapOf<String, Any?>("a" to Json.Num("1")), both.narrow))
        val amb = p("PCA-Discharges" to "WzFd", "pca-discharges" to "WzJd")
        assertTrue(amb.ok)
        assertNull(amb.discharges) // two differing spellings: ambiguous = absent
        val same = p("PCA-Discharges" to "WzFd", "pca-discharges" to "WzFd")
        assertEquals(1, same.discharges!!.size)
    }

    @Test fun k1OfFillsOnlyWhatTheVerifierLeftUnset() {
        val h = mapOf<String, String?>("pca-discharges" to "WzFd", "pca-narrow" to "eyJhIjoxfQ")
        assertNull(CaveatLang.k1Of(h, null))
        val pins = listOf(CaveatLang.DischargePin("l", "human", "k"))
        val rev = listOf("r")
        val hist = listOf<Any?>()
        val own = CaveatLang.K1Input(pins, null, CaveatLang.K1Input.ABSENT, "ad", rev, "s", hist)
        val m = CaveatLang.k1Of(h, own)!!
        assertSame(pins, m.pins)
        assertTrue(IntentJs.jsonEquals(listOf(Json.Num("1")), m.discharges))
        assertTrue(IntentJs.jsonEquals(linkedMapOf<String, Any?>("a" to Json.Num("1")), m.narrow))
        assertEquals("ad", m.actionDigest)
        assertSame(rev, m.revokedDischarges)
        assertEquals("s", m.spiffeId)
        assertSame(hist, m.history)
        val mine = listOf<Any?>("x")
        val kept = CaveatLang.k1Of(h, CaveatLang.K1Input(discharges = mine, narrow = "n"))!!
        assertSame(mine, kept.discharges)
        assertEquals("n", kept.narrow)
        assertSame(own, CaveatLang.k1Of(mapOf("pca-discharges" to "!!!!"), own)) // unreadable headers: the verifier's own input as is
    }
}
