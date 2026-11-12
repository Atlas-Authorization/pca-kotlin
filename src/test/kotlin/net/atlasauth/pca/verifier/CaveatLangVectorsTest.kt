package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Caveat language v2 (track K1) over the shared `caveat-lang-vectors.json`: all six primitives (`discharge_verify`,
 * `k1_eval`, `caveat_shape`, `uses_key`, `uses_reserve`, `spiffe_id`), every `reason_contains` reproduced, plus exact-outcome
 * tests for hostile inputs the vectors cannot show.
 */
@Suppress("UNCHECKED_CAST")
class CaveatLangVectorsTest {
    private fun tbl(n: String) = ParityVectors.table("caveat-lang-vectors.json", "primitives", n)

    /** A fractional or unsafe clock is not a safe integer: map it to a value the library refuses. */
    private fun clock(v: Any?): Long {
        val d = IntentJs.num(v)!!
        return if (d == Math.floor(d) && Math.abs(d) <= IntentJs.MAX_SAFE) d.toLong() else Long.MAX_VALUE
    }

    @Test
    fun dischargeVerifyVectors() {
        val v = tbl("discharge_verify")
        assertTrue(v.size >= 54)
        val supported = Pq.supportedSuites().toSet()
        for (x in v) {
            val i = x["input"] as Map<String, Any?>
            val b = i["binding"] as Map<String, Any?>
            val bind = CaveatLang.DischargeBinding(
                capHash = b["cap_hash"] as String,
                actionDigest = b["action_digest"] as? String,
                pins = (b["pins"] as List<*>).map { CaveatLang.DischargePin.fromJson(it) },
                now = clock(b["now"]),
                revoked = (b["revoked"] as? List<*>)?.map { it as String },
            )
            val r = CaveatLang.verifyDischarge(i["discharge"], i["caveat"], bind)
            val e = x["expect"] as Map<String, Any?>
            val need = x["requires_suite"] as? String
            if (need != null && need !in supported) {
                // an unimplemented suite fails closed with the distinct reason (never skipped, never accepted)
                assertFalse("${x["name"]}: ${r.reason}", r.ok)
                assertTrue("${x["name"]}: '${r.reason}'", r.reason!!.contains("unsupported_suite"))
                continue
            }
            assertEquals("${x["name"]}: ${r.reason}", e["ok"], r.ok)
            if (r.ok) {
                assertEquals(x["name"].toString(), e["digest"], r.digest)
                assertTrue("${x["name"]}: claims", IntentJs.jsonEquals(e["claims"], r.claims))
            } else assertTrue("${x["name"]}: '${r.reason}' lacks '${e["reason_contains"]}'", r.reason!!.contains(e["reason_contains"] as String))
        }
    }

    @Test
    fun k1EvalVectors() {
        val v = tbl("k1_eval")
        assertTrue(v.size >= 102)
        val supported = Pq.supportedSuites().toSet()
        var ran = 0
        for (x in v) {
            val need = x["requires_suite"] as? String
            if (need != null && need !in supported) continue // k1_eval carries no suite-gated entry today; a gated one needs the suite
            val i = x["input"] as Map<String, Any?>
            val r = CaveatLang.evaluateCaveatsK1(i["grant"], i["chain"], CaveatLang.K1Input.fromJson(i["k1"]), i["context"])
            val e = x["expect"] as Map<String, Any?>
            assertEquals(x["name"].toString(), e["allow"], r.ok)
            assertEquals(x["name"].toString(), (e["failed"] as List<*>).toList(), r.failed)
            ran++
        }
        assertTrue(ran >= 102)
    }

    @Test
    fun k1UnconfiguredVectors() {
        val v = tbl("k1_unconfigured")
        assertTrue(v.size >= 9)
        var ran = 0
        for (x in v) {
            val i = x["input"] as Map<String, Any?>
            val r = CaveatLang.evaluateCaveatsK1(i["grant"], i["chain"], null, i["context"])
            val e = x["expect"] as Map<String, Any?>
            assertEquals(x["name"].toString(), e["allow"], r.ok)
            assertEquals(x["name"].toString(), (e["failed"] as List<*>).toList(), r.failed)
            ran++
        }
        assertTrue(ran >= 9)
    }

    @Test
    fun absentK1RefusesEveryK1TypeButAnEmptyObjectIsConfigured() {
        val i = tbl("k1_unconfigured").first { it["name"] == "un-sealed" }["input"] as Map<String, Any?>
        val off = CaveatLang.evaluateK1(i["grant"], i["chain"], null, 1800000000000L)
        assertFalse(off.ok)
        assertEquals(listOf("sealed"), off.failed)
        assertEquals(listOf("the caveat language is not configured (no k1 input)"), off.reasons)
        assertNull(CaveatLang.K1Input.fromJson(null))
        assertNull(CaveatLang.K1Input.fromJson("x"))
        assertNull(CaveatLang.K1Input.fromJson(ArrayList<Any?>()))
        assertNotNull(CaveatLang.K1Input.fromJson(LinkedHashMap<String, Any?>()))
        assertTrue(CaveatLang.evaluateK1(i["grant"], i["chain"], CaveatLang.K1Input.fromJson(LinkedHashMap<String, Any?>()), 1800000000000L).ok)
    }

    private fun runTtl(store: Authorize.StateStore, steps: List<*>): List<String> = steps.map {
        val m = it as Map<String, Any?>
        try {
            if (store.consumeOnce(m["key"] as String, IntentJs.lng(m["retain_until"]), IntentJs.lng(m["now"]))) "true" else "false"
        } catch (e: IllegalArgumentException) {
            "error"
        }
    }

    @Test
    fun consumeOnceTtlVectorsOnEveryStore() {
        val v = tbl("consume_once_ttl")
        assertTrue(v.size >= 9)
        var ran = 0
        for (x in v) {
            val steps = (x["input"] as Map<String, Any?>)["steps"] as List<*>
            val want = ((x["expect"] as Map<String, Any?>)["results"] as List<*>).map { it as String }
            assertEquals("memory ${x["name"]}", want, runTtl(Authorize.MemoryStateStore(), steps))
            assertEquals("jdbc ${x["name"]}", want, runTtl(AuthorizeTestKit.jdbcStore(), steps))
            ran += 2
        }
        assertTrue(ran >= 18)
    }

    @Test
    fun theDefaultConsumeOnceFallsBackToClaimAndRefusesBadInput() {
        val calls = ArrayList<String>()
        val st = object : Authorize.StateStore {
            val seen = HashSet<String>()
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? { calls.add(key); return Authorize.ClaimResult(seen.add(key)) }
        }
        assertTrue(st.consumeOnce("k", 10L, 5L))
        assertFalse(st.consumeOnce("k", 10L, 5L))
        assertTrue(runCatching { st.consumeOnce("", 10L, 5L) }.isFailure)
        assertTrue(runCatching { st.consumeOnce("z", 4L, 5L) }.isFailure)
        assertEquals(listOf("k", "k"), calls)
    }

    @Test
    fun k1HeadersVectors() {
        val v = tbl("k1_headers")
        assertTrue(v.size >= 15)
        var ran = 0
        for (x in v) {
            val h = ((x["input"] as Map<String, Any?>)["headers"] as Map<String, Any?>).mapValues { it.value as String? }
            val r = CaveatLang.presentedK1(h)
            val e = x["expect"] as Map<String, Any?>
            assertEquals("${x["name"]}: ${r.error}", e["ok"], r.ok)
            if (r.ok) {
                val want = e["value"] as Map<String, Any?>
                if (want.containsKey("discharges")) assertTrue(x["name"].toString(), IntentJs.jsonEquals(want["discharges"], r.discharges)) else assertNull(x["name"].toString(), r.discharges)
                if (want.containsKey("narrow")) assertTrue(x["name"].toString(), IntentJs.jsonEquals(want["narrow"], r.narrow)) else assertTrue(x["name"].toString(), r.narrow === CaveatLang.K1Input.ABSENT)
            }
            ran++
        }
        assertTrue(ran >= 15)
    }

    @Test
    fun k1OfMergesPresentedHeadersUnderTheVerifiersOwnInput() {
        val d = tbl("k1_headers").first { it["name"] == "kh-discharges" }
        val h = ((d["input"] as Map<String, Any?>)["headers"] as Map<String, Any?>).mapValues { it.value as String? }
        assertNull(CaveatLang.k1Of(h, null)) // headers alone never switch K1 on
        val merged = CaveatLang.k1Of(h, CaveatLang.K1Input())!!
        assertEquals(1, merged.discharges!!.size)
        val own = listOf<Any?>()
        assertEquals(0, CaveatLang.k1Of(h, CaveatLang.K1Input(discharges = own))!!.discharges!!.size) // own wins
        val bad = CaveatLang.k1Of(mapOf("PCA-Discharges" to "!!!!"), CaveatLang.K1Input())!!
        assertNull(bad.discharges) // unreadable = no discharges
    }

    @Test
    fun caveatShapeVectors() {
        val v = tbl("caveat_shape")
        assertTrue(v.size >= 50)
        for (x in v) {
            val c = (x["input"] as Map<String, Any?>)["caveat"]
            val err = when ((c as Map<String, Any?>)["type"]) {
                CaveatLang.NEEDS_DISCHARGE -> CaveatLang.needsDischargeError(c)
                CaveatLang.MAX_USES -> CaveatLang.maxUsesError(c)
                CaveatLang.DERIVE -> CaveatLang.deriveError(c)
                CaveatLang.SPIFFE_BOUND -> CaveatLang.spiffeBoundError(c)
                else -> "unexpected type in the vector file"
            }
            assertEquals("${x["name"]}: $err", (x["expect"] as Map<String, Any?>)["valid"], err == null)
        }
    }

    @Test
    fun usesKeyVectors() {
        val v = tbl("uses_key")
        assertTrue(v.size >= 5)
        for (x in v) {
            val i = x["input"] as Map<String, Any?>
            assertEquals(x["name"].toString(), (x["expect"] as Map<String, Any?>)["key"], CaveatLang.maxUsesSlotKey(i["cap_hash"] as String, i["id"] as String, IntentJs.lng(i["i"]).toInt()))
        }
    }

    @Test
    fun usesReserveVectors() {
        val v = tbl("uses_reserve")
        assertTrue(v.size >= 12)
        for (x in v) {
            val i = x["input"] as Map<String, Any?>
            val bound = (i["bound"] as List<*>).map {
                val m = it as Map<String, Any?>
                CaveatLang.BoundCaveat(m["caveat"], 0, m["cap_hash"] as String)
            }
            val store = Authorize.MemoryStateStore()
            val calls = i["calls"] as List<*>
            val want = (x["expect"] as Map<String, Any?>)["results"] as List<*>
            assertEquals(x["name"].toString(), want.size, calls.size)
            for (k in calls.indices) {
                val r = CaveatLang.reserveMaxUses(store, bound, clock((calls[k] as Map<String, Any?>)["now"]))
                val e = want[k] as Map<String, Any?>
                assertEquals("${x["name"]}[$k]: ${r.reason}", e["ok"], r.ok)
                if (r.ok) assertEquals("${x["name"]}[$k]", IntentJs.lng(e["spent"]).toInt(), r.spent)
                else assertTrue("${x["name"]}[$k]: '${r.reason}' lacks '${e["reason_contains"]}'", r.reason!!.contains(e["reason_contains"] as String))
            }
        }
    }

    @Test
    fun spiffeIdVectors() {
        val v = tbl("spiffe_id")
        assertTrue(v.size >= 24)
        for (x in v) {
            val id = (x["input"] as Map<String, Any?>)["id"]
            assertEquals("${x["name"]}: ${CaveatLang.spiffeIdError(id)}", (x["expect"] as Map<String, Any?>)["valid"], CaveatLang.spiffeIdError(id) == null)
        }
    }

    // ---- exact outcomes the vectors cannot show ----

    private fun o(t: String) = ParityVectors.obj(t)

    @Test
    fun hostileInputsAreRefusedNeverThrown() {
        val hostile = listOf<Any?>(null, 5, "x", true, ArrayList<Any?>(), LinkedHashMap<String, Any?>(), o("""{"type":null}"""), o("""{"type":["needs_discharge"]}"""))
        val bind = CaveatLang.DischargeBinding("c", null, emptyList(), 1000L)
        for (h in hostile) {
            assertNotNull(CaveatLang.needsDischargeError(h))
            assertNotNull(CaveatLang.maxUsesError(h))
            assertNotNull(CaveatLang.deriveError(h))
            assertNotNull(CaveatLang.spiffeBoundError(h))
            assertNotNull(CaveatLang.dischargeShapeError(h))
            assertNotNull(CaveatLang.narrowShapeError(h))
            assertFalse(CaveatLang.verifyDischarge(h, h, bind).ok)
            assertFalse(CaveatLang.verifyNarrow(h, h, h, 1000L).ok)
            val r = CaveatLang.evaluateK1(h, h, CaveatLang.K1Input.fromJson(h), 1000L, h)
            assertFalse(r.ok)
            assertEquals(listOf("<malformed>"), r.failed)
            val c = CaveatLang.evaluateCaveatsK1(h, h, CaveatLang.K1Input(), h)
            assertFalse(c.ok)
            assertNull(CaveatLang.boundCaveats(h, h))
        }
    }

    @Test
    fun spiffeIdMeasuresBytesAndRefusesTheDotSegments() {
        assertEquals("SPIFFE ID must be a non-empty string", CaveatLang.spiffeIdError(""))
        assertEquals("SPIFFE ID must be a non-empty string", CaveatLang.spiffeIdError(null))
        assertEquals("SPIFFE ID must begin with spiffe://", CaveatLang.spiffeIdError("https://a.test"))
        assertEquals("invalid trust domain", CaveatLang.spiffeIdError("spiffe://"))
        assertEquals("invalid trust domain", CaveatLang.spiffeIdError("spiffe://A.test"))
        assertEquals("path must not end with a slash", CaveatLang.spiffeIdError("spiffe://a.test/x/"))
        assertEquals("invalid path segment", CaveatLang.spiffeIdError("spiffe://a.test/./x"))
        assertEquals("invalid path segment", CaveatLang.spiffeIdError("spiffe://a.test//x"))
        assertEquals("invalid path segment", CaveatLang.spiffeIdError("spiffe://a.test/x\n"))
        assertNull(CaveatLang.spiffeIdError("spiffe://a.test/ns/prod/wl-1_x.y"))
        assertEquals("SPIFFE ID is too long", CaveatLang.spiffeIdError("spiffe://a.test/" + "a".repeat(2033)))
    }

    @Test
    fun anIdWithATrailingNewlineIsMalformed() {
        val c = o("""{"type":"max_uses","id":"u","n":1,"until":5}""")
        assertNull(CaveatLang.maxUsesError(c))
        assertEquals("id is malformed", CaveatLang.maxUsesError(o("{\"type\":\"max_uses\",\"id\":\"u\\n\",\"n\":1,\"until\":5}")))
        assertEquals("n must be 1..256", CaveatLang.maxUsesError(o("""{"type":"max_uses","id":"u","n":1.5,"until":5}""")))
        assertEquals("n must be 1..256", CaveatLang.maxUsesError(o("""{"type":"max_uses","id":"u","n":1e300,"until":5}""")))
        assertEquals("until must be a non-negative safe integer", CaveatLang.maxUsesError(o("""{"type":"max_uses","id":"u","n":1,"until":-0}""")))
    }

    @Test
    fun deriveLimitsAreExact() {
        fun d(defs: String, check: String) = o("""{"type":"derive","id":"x","defs":$defs,"check":$check}""")
        assertNull(CaveatLang.deriveError(d("[]", """{"const":true}""")))
        assertEquals("def 'a' is defined twice", CaveatLang.deriveError(d("""[{"name":"a","kind":"action","field":"verb"},{"name":"a","kind":"action","field":"verb"}]""", """{"const":true}""")))
        assertEquals("ref names no earlier def", CaveatLang.deriveError(d("[]", """{"ref":"a"}""")))
        assertEquals("expression nests deeper than 4", CaveatLang.deriveError(d("[]", """{"op":"not","arg":{"op":"not","arg":{"op":"not","arg":{"op":"not","arg":{"const":true}}}}}""")))
        assertNull(CaveatLang.deriveError(d("[]", """{"op":"not","arg":{"op":"not","arg":{"op":"not","arg":{"const":true}}}}""")))
        assertEquals("def 'a': param path is malformed", CaveatLang.deriveError(d("""[{"name":"a","kind":"param","path":"a.b.c.d.e"}]""", """{"const":true}""")))
        assertEquals("def 'a': param path is malformed", CaveatLang.deriveError(d("""[{"name":"a","kind":"param","path":"a.__proto__"}]""", """{"const":true}""")))
        assertEquals("def 'a': window_ms out of range", CaveatLang.deriveError(d("""[{"name":"a","kind":"count","window_ms":2592000001}]""", """{"const":true}""")))
        assertNull(CaveatLang.deriveError(d("""[{"name":"a","kind":"count","window_ms":2592000000}]""", """{"const":true}""")))
        val nine = (0..8).joinToString(",") { """{"name":"d$it","kind":"action","field":"verb"}""" }
        assertEquals("defs must be an array of at most 8", CaveatLang.deriveError(d("[$nine]", """{"const":true}""")))
        // nodes are counted over the whole caveat: one `and` over `and`s of comparisons (3 nodes each)
        val four = (0..3).joinToString(",") { """{"op":"eq","a":{"const":1},"b":{"const":1}}""" }
        val grp = """{"op":"and","args":[$four]}""" // 13 nodes
        assertNull(CaveatLang.deriveError(d("[]", """{"op":"and","args":[$grp,$grp]}"""))) // 27 nodes
        assertEquals("more than 32 expression nodes", CaveatLang.deriveError(d("[]", """{"op":"and","args":[$grp,$grp,$grp]}"""))) // 40 nodes
    }

    @Test
    fun deriveIsThreeValued() {
        fun run(check: String, action: String = """{"verb":"v","resource":"r","params":{}}"""): Boolean? {
            val c = o("""{"type":"derive","id":"x","defs":[],"check":$check}""")
            assertNull(CaveatLang.deriveError(c))
            return CaveatLang.evaluateDerive(c, 1000L, ParityVectors.parse(action), null, emptyMap())
        }
        val t = """{"const":true}"""
        val f = """{"const":false}"""
        val u = """{"op":"lt","a":{"const":"a"},"b":{"const":1}}""" // ordering a string is unknown
        assertEquals(true, run(t))
        assertEquals(false, run(f))
        assertNull(run(u))
        assertEquals(false, run("""{"op":"and","args":[$u,$f]}"""))
        assertNull(run("""{"op":"and","args":[$u,$t]}"""))
        assertEquals(true, run("""{"op":"or","args":[$u,$t]}"""))
        assertNull(run("""{"op":"or","args":[$u,$f]}"""))
        assertNull(run("""{"op":"not","arg":$u}"""))
        assertEquals(false, run("""{"op":"eq","a":{"const":1},"b":{"const":true}}"""))
        assertEquals(true, run("""{"op":"neq","a":{"const":1},"b":{"const":"1"}}"""))
    }

    @Test
    fun exhaustedAndExpiredReasonsAreExact() {
        val store = Authorize.MemoryStateStore()
        val cap = Pca.b64(ByteArray(32) { 1 })
        val b = listOf(CaveatLang.BoundCaveat(o("""{"type":"max_uses","id":"u","n":1,"until":100}"""), 0, cap))
        assertEquals(1, CaveatLang.reserveMaxUses(store, b, 10L).spent)
        assertEquals("max_uses 'u' is exhausted", CaveatLang.reserveMaxUses(store, b, 10L).reason)
        assertEquals("max_uses 'u' has expired", CaveatLang.reserveMaxUses(store, b, 100L).reason)
        assertEquals("the verifier clock is not a safe integer (fail closed)", CaveatLang.reserveMaxUses(store, b, Long.MAX_VALUE).reason)
        val dup = b + b
        assertEquals("duplicate max_uses id 'u'", CaveatLang.reserveMaxUses(Authorize.MemoryStateStore(), dup, 10L).reason)
        // a store that throws is a refusal, not an exception
        val boom = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw IllegalStateException("down")
        }
        assertEquals("max_uses error (fail closed): down", CaveatLang.reserveMaxUses(boom, b, 10L).reason)
    }
}
