package net.atlasauth.pca.verifier

import java.security.SecureRandom
import java.util.Collections
import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.Kill05ReadReadSideTest.Companion.args
import net.atlasauth.pca.verifier.Kill05ReadReadSideTest.Companion.diff
import net.atlasauth.pca.verifier.Kill05ReadReadSideTest.Companion.of
import net.atlasauth.pca.verifier.Kill05ReadReadSideTest.Companion.readIn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 0.5 mutation kills for ReadVault.kt: the tokenisation vault, aggregate grants and the integer-exact discrete Laplace sampler,
 * differential against packages/pca/src/read-vault.ts over the shared k05 read-side oracle, plus the Kotlin-only edges: the result
 * getters, stores that fail, a hostile grant, the entry expiry, every aggregate refusal and bound on grants signed at runtime, the
 * sampler over scripted streams (the rejection limit, the step bounds and every give-up path) and the CSPRNG seed width.
 */
@Suppress("UNCHECKED_CAST")
class Kill05ReadReadVaultTest {
    // ---- the differential ----

    @Test fun validAggregateGrantBody() = diff("validAggregateGrantBody") { ReadVault.validAggregateGrantBody(it[0]) }

    @Test
    fun aggregateRead() = diff("aggregateRead") {
        ReadVault.aggregateRead(ReadVault.AggregateInput(it[0], it[1], it[2], it[3], it[4], it[5], it[6], it[7], it[8], it[9], it[10])).toMap()
    }

    /** redactReadWithVault into a fresh vault, then detokenize the minted (or the given) token. */
    @Test
    fun vault() = diff("vault") {
        val ra = it[1] as List<Any?>
        val da = it[3] as List<Any?>
        val store = ReadVault.memoryVault()
        val red = ReadVault.redactReadWithVault(readIn(it[0], ra), store)
        val token = it[4] ?: red.view[it[5] as String]
        val det = ReadVault.detokenize(ReadVault.DetokenizeInput(it[2], da[0], da[1], da[2], token, store))
        linkedMapOf("redact" to red.toMap(), "detok" to det.toMap())
    }

    @Test
    fun sampler() {
        diff("uniform") {
            val d = ReadVault.seededDraws(it[0] as String)
            (it[1] as List<Any?>).map { n -> d.uniform(Json.asLong(n)) }
        }
        diff("laplace") {
            val d = ReadVault.seededDraws(it[0] as String)
            val s = Json.asLong(it[1])
            val t = Json.asLong(it[2])
            (0 until Json.asLong(it[3]).toInt()).map { _ -> ReadVault.discreteLaplace(d, s, t) }
        }
    }

    // ---- the vault ----

    private val label = "k05-vault-principal"
    private val p = IntentTestKit.pub(label)
    private val salt = "0123456789abcdef"

    private fun body(vararg over: Any?): LinkedHashMap<String, Any?> {
        val b = jm(
            "v", 1L, "id", "rg-vault", "principal", p, "issued_at", 1000L, "expires_at", 2000L,
            "reads", jl(jm("verb", "customers.get", "resource_prefix", "customers/", "purposes", jl("support"), "modes", jm("ref", "token", "ssn", "token", "tax", "token"), "default_mode", "drop")),
            "caps", jm(), "sinks", jm("payments", jm("allow", jl("ref"), "escalate", jl("ssn")), "email", jm("allow", jl(), "escalate", jl())),
        )
        for (i in over.indices step 2) b[over[i] as String] = over[i + 1]
        return b
    }

    private fun grant(b: Map<String, Any?> = body(), signer: String = label) =
        jm("body", b, "sig", IntentTestKit.sign(signer, IntentJs.message(ReadSide.READ_GRANT_DOMAIN, b)))

    private val schema = jm("fields", jm("cust", "ref", "id", "ssn", "tax", "tax"), "required", jl())

    private fun vaultRead(g: Any?) = ReadSide.ReadInput(g, p, 1500L, "customers.get", "customers/1", "support", schema, jm("cust", "c_77", "id", "123-45", "tax", 9L), jm(), salt, jm())

    /** A vault holding the three tokens of one read; returns the store and the view. */
    private fun minted(g: Map<String, Any?> = grant()): Pair<ReadVault.VaultStore, Map<String, Any?>> {
        val store = ReadVault.memoryVault()
        val r = ReadVault.redactReadWithVault(vaultRead(g), store)
        assertEquals("allow", r.decision)
        return Pair(store, r.view)
    }

    private fun det(token: Any?, store: ReadVault.VaultStore?, sink: Any? = "payments", g: Any? = grant(), now: Any? = 1500L, principal: Any? = p) =
        ReadVault.detokenize(ReadVault.DetokenizeInput(g, principal, now, sink, token, store))

    private fun show(r: ReadVault.DetokenizeResult) = Json.canonicalize(r.toMap())
    private fun res(d: String, c: String?, v: Any?) = Json.canonicalize(linkedMapOf("decision" to d, "code" to c, "value" to v))

    @Test
    fun detokenizeEveryOutcome() {
        val (store, view) = minted()
        val cust = view["cust"]
        assertEquals(res("allow", null, "c_77"), show(det(cust, store)))
        // a token minted under one grant is unknown under another; under its own grant it detokenizes
        val taxGrant = grant(body("sinks", jm("payments", jm("allow", jl("tax"), "escalate", jl()))))
        assertEquals(res("deny", "unknown_token", null), show(det(view["tax"], store, g = taxGrant)))
        val (store2, view2) = minted(taxGrant)
        assertEquals(res("allow", null, 9L), show(det(view2["tax"], store2, g = taxGrant)))
        assertEquals(res("escalate", "label_escalate", null), show(det(view["id"], store)))
        assertEquals(res("deny", "label_flow", null), show(det(view["tax"], store)))
        assertEquals(res("deny", "label_flow", null), show(det(cust, store, sink = "email")))
        assertEquals(res("deny", "unknown_sink", null), show(det(cust, store, sink = "fax")))
        assertEquals(res("deny", "unknown_token", null), show(det("tok_nope", store)))
        // the request itself
        assertEquals(res("deny", "bad_request", null), show(det(cust, null)))
        assertEquals(res("deny", "bad_request", null), show(det(cust, null, g = null)))
        assertEquals(res("deny", "bad_request", null), show(det(cust, store, principal = "x")))
        assertEquals(res("deny", "bad_request", null), show(det(cust, store, now = -1L)))
        assertEquals(res("deny", "bad_request", null), show(det(Json.Num("5"), store)))
        assertEquals(res("deny", "bad_request", null), show(det(Json.Num("5"), store, g = null)))
        assertEquals(res("deny", "bad_request", null), show(det(cust, store, sink = Json.Num("5"))))
        assertEquals(res("deny", "bad_request", null), show(det(cust, store, sink = Json.Num("5"), g = null)))
        // the grant
        assertEquals(res("deny", "bad_grant", null), show(det(cust, store, g = null)))
        assertEquals(res("deny", "bad_grant", null), show(det(cust, store, g = jm("body", body(), "sig", "x", "x", 1L))))
        assertEquals(res("deny", "bad_grant", null), show(det(cust, store, g = grant(body("reads", jl())))))
        assertEquals(res("deny", "bad_signature", null), show(det(cust, store, g = grant(body(), "k05-vault-other"))))
        assertEquals(res("deny", "bad_signature", null), show(det(cust, store, g = grant(body("principal", IntentTestKit.pub("k05-vault-other")), "k05-vault-other"))))
        assertEquals(res("deny", "not_yet", null), show(det(cust, store, now = 999L)))
        assertEquals(res("allow", null, "c_77"), show(det(cust, store, now = 1000L)))
        assertEquals(res("allow", null, "c_77"), show(det(cust, store, now = 1999L)))
        assertEquals(res("deny", "expired", null), show(det(cust, store, now = 2000L)))
    }

    /** A store may hold an entry that expires before its grant: the entry's own expiry gates. */
    @Test
    fun theEntryExpiry() {
        val digest = ReadSide.readGrantDigest(body())
        for (exp in listOf(1499L, 1500L, 1501L)) {
            val s = ReadVault.memoryVault()
            s.put("tok_x", ReadVault.VaultEntry("ref", "c_77", digest, exp))
            val got = det("tok_x", s)
            assertEquals("exp $exp", if (exp > 1500L) res("allow", null, "c_77") else res("deny", "expired", null), show(got))
        }
    }

    @Test
    fun resultGettersAndTheMemoryVault() {
        val (store, view) = minted()
        val ok = det(view["cust"], store)
        assertEquals("allow", ok.decision)
        assertNull(ok.code)
        assertEquals("c_77", ok.value)
        val esc = det(view["id"], store)
        assertEquals("escalate", esc.decision)
        assertEquals("label_escalate", esc.code)
        assertNull(esc.value)
        val e = ReadVault.VaultEntry("ref", "v", "g", 5L)
        val s = ReadVault.memoryVault()
        s.put("t", e)
        assertSame(e, s.get("t"))
        assertNull(s.get("u"))
        val minted = store.get(view["cust"] as String)!!
        assertEquals("ref", minted.cls)
        assertEquals("c_77", minted.value)
        assertEquals(ReadSide.readGrantDigest(body()), minted.grant)
        assertEquals(2000L, minted.exp)
        // a masked hash or a dropped field is never stored
        val st = ReadVault.memoryVault()
        val g = grant(body("reads", jl(jm("verb", "customers.get", "resource_prefix", "customers/", "purposes", jl("support"), "modes", jm("ref", "hash", "ssn", "token"), "default_mode", "drop"))))
        val r = ReadVault.redactReadWithVault(vaultRead(g), st)
        assertEquals("allow", r.decision)
        assertNull(st.get(r.view["cust"] as String))
        assertEquals("123-45", st.get(r.view["id"] as String)!!.value)
        // a denied read stores nothing and is returned as is
        val st2 = ReadVault.memoryVault()
        val denied = ReadVault.redactReadWithVault(ReadSide.ReadInput(grant(), p, 2500L, "customers.get", "customers/1", "support", schema, jm("cust", "c_77"), jm(), salt, jm()), st2)
        assertEquals("expired", denied.code)
    }

    private val broken = object : ReadVault.VaultStore {
        override fun put(token: String, e: ReadVault.VaultEntry) = throw IllegalStateException("disk")
        override fun get(token: String): ReadVault.VaultEntry? = throw IllegalStateException("disk")
    }

    @Test
    fun failingStoresAndAHostileGrantFailClosed() {
        val r = ReadVault.redactReadWithVault(vaultRead(grant()), broken)
        assertEquals("deny", r.decision)
        assertEquals("bad_request", r.code)
        assertTrue(r.view.isEmpty() && r.fields.isEmpty() && r.labels.isEmpty() && r.counts.isEmpty())
        val (_, view) = minted()
        val d = det(view["cust"], broken)
        assertEquals("deny", d.decision)
        assertEquals("bad_request", d.code)
        assertNull(d.value)
        val h = det("tok_x", ReadVault.memoryVault(), g = Kill05ReadReadSideTest.Boom())
        assertEquals(res("deny", "bad_request", null), show(h))
    }

    // ---- aggregates ----

    private fun rule(vararg over: Any?): LinkedHashMap<String, Any?> {
        val r = jm("verb", "orders.stats", "resource_prefix", "orders/", "purposes", jl("analytics"), "fns", jl("count", "sum"), "min_group", 2L, "clamp", 10L, "epsilon_micro", 500_000L, "dp", false)
        for (i in over.indices step 2) r[over[i] as String] = over[i + 1]
        return r
    }

    private fun agBody(vararg over: Any?): LinkedHashMap<String, Any?> {
        val b = jm("v", 1L, "id", "ag-1", "principal", p, "issued_at", 1000L, "expires_at", 2000L, "rules", jl(rule()), "epsilon_budget_micro", 1_000_000L, "max_queries", 3L)
        for (i in over.indices step 2) b[over[i] as String] = over[i + 1]
        return b
    }

    private fun agGrant(b: Map<String, Any?> = agBody(), signer: String = label) =
        jm("body", b, "sig", IntentTestKit.sign(signer, IntentJs.message(ReadVault.AGGREGATE_DOMAIN, b)))

    private fun state(spent: Any? = 0L, queries: Any? = 0L, answered: Any? = jm()) = jm("spent_micro", spent, "queries", queries, "answered", answered)

    private fun ag(
        values: Any? = jl(1L, 20L, -30L), fn: Any? = "sum", st: Any? = state(), g: Any? = agGrant(), now: Any? = 1500L, principal: Any? = p,
        verb: Any? = "orders.stats", resource: Any? = "orders/eu", purpose: Any? = "analytics", salt: Any? = this.salt, noise: Any? = "seeded",
    ) = ReadVault.aggregateRead(ReadVault.AggregateInput(g, principal, now, verb, resource, purpose, fn, values, salt, noise, st))

    private fun code(r: ReadVault.AggregateResult) = "${r.decision}/${r.code}"
    private val empty = Json.canonicalize(ReadVault.emptyAggregateState())

    @Test
    fun theEmptyState() {
        assertEquals("{\"answered\":{},\"queries\":0,\"spent_micro\":0}", empty)
        val a = ReadVault.emptyAggregateState()
        assertEquals(listOf("spent_micro", "queries", "answered"), a.keys.toList())
        assertEquals(0L, a["spent_micro"])
        assertEquals(0L, a["queries"])
        assertTrue((a["answered"] as MutableMap<String, Any?>).isEmpty())
        assertFalse(a["answered"] === ReadVault.emptyAggregateState()["answered"])
    }

    @Test
    fun exactAnswersAndTheState() {
        val sum = ag()
        assertEquals("allow/null", code(sum))
        assertEquals(1L, sum.value) // 1 + clamp(20) + clamp(-30) = 1 + 10 - 10
        assertEquals(0L, sum.chargedMicro)
        val st = sum.state as Map<String, Any?>
        assertEquals(0L, st["spent_micro"])
        assertEquals(1L, st["queries"])
        assertEquals(1, (st["answered"] as Map<String, Any?>).size)
        assertEquals(3L, ag(fn = "count").value)
        // the same query is answered from the state, free, and the state is returned unchanged
        val again = ag(st = st)
        assertEquals("allow/null", code(again))
        assertEquals(1L, again.value)
        assertEquals(0L, again.chargedMicro)
        assertSame(st, again.state)
        // a recorded answer is returned as recorded
        val qd = (st["answered"] as Map<String, Any?>).keys.first()
        assertEquals(42L, ag(st = state(0L, 1L, jm(qd, 42L))).value)
        // the group must reach min_group
        assertEquals("allow/null", code(ag(values = jl(1L, 2L))))
        assertEquals("deny/group_too_small", code(ag(values = jl(1L))))
        assertEquals("deny/group_too_small", code(ag(values = jl())))
        assertEquals("deny/group_too_small", code(ag(values = jl(), fn = "count")))
        // the query cap and the epsilon budget
        val capped = ag(st = state(0L, 2L))
        assertEquals("allow/null", code(capped))
        assertEquals(3L, (capped.state as Map<String, Any?>)["queries"])
        val atCap = state(0L, 3L)
        val refused = ag(st = atCap)
        assertEquals("deny/query_cap", code(refused))
        assertSame(atCap, refused.state)
        assertNull(refused.value)
        assertEquals(0L, refused.chargedMicro)
        val dp = agGrant(agBody("rules", jl(rule("dp", true))))
        val charged = ag(g = dp, st = state(500_000L, 0L))
        assertEquals("allow/null", code(charged))
        assertEquals(500_000L, charged.chargedMicro)
        assertEquals(1_000_000L, (charged.state as Map<String, Any?>)["spent_micro"])
        assertEquals("deny/epsilon_exhausted", code(ag(g = dp, st = state(500_001L, 0L))))
        // without dp nothing is charged, but a budget already overspent still refuses
        assertEquals("allow/null", code(ag(st = state(1_000_000L, 0L))))
        assertEquals("deny/epsilon_exhausted", code(ag(st = state(1_000_001L, 0L))))
        // a million values is the bound
        assertEquals(1_000_000L, ag(values = Collections.nCopies(1_000_000, 0L), fn = "count").value)
        assertEquals("deny/bad_request", code(ag(values = Collections.nCopies(1_000_001, 0L), fn = "count")))
    }

    @Test
    fun everyRefusal() {
        val bad = "deny/bad_request"
        // a bad state answers with the EMPTY state
        for (s in listOf<Any?>(null, "x", state(-1L), state(0L, "1"), state(0L, 0L, "x"), state(0L, 0L, jm("q", "1")), state(0L, 0L, jm("q", Json.Num("1.5"))))) {
            val r = ag(st = s)
            assertEquals("$s", bad, code(r))
            assertEquals(empty, Json.canonicalize(r.state))
            assertEquals(0L, r.chargedMicro)
            assertNull(r.value)
        }
        assertEquals("allow/null", code(ag(st = state(0L, 0L, jm("q", -5L)))))
        // everything else keeps the caller's state
        val st = state(7L, 1L)
        fun kept(r: ReadVault.AggregateResult): String {
            assertSame(st, r.state)
            assertEquals(0L, r.chargedMicro)
            assertNull(r.value)
            return code(r)
        }
        assertEquals(bad, kept(ag(st = st, principal = "x")))
        assertEquals(bad, kept(ag(st = st, now = -1L)))
        assertEquals("deny/bad_grant", kept(ag(st = st, g = null)))
        assertEquals("deny/bad_grant", kept(ag(st = st, g = jm("body", agBody(), "sig", "x", "x", 1L))))
        assertEquals("deny/bad_grant", kept(ag(st = st, g = agGrant(agBody("rules", jl())))))
        assertEquals("deny/bad_signature", kept(ag(st = st, g = agGrant(agBody(), "k05-vault-other"))))
        assertEquals("deny/not_yet", kept(ag(st = st, now = 999L)))
        assertEquals("allow/null", code(ag(st = st, now = 1000L)))
        assertEquals("deny/expired", kept(ag(st = st, now = 2000L)))
        assertEquals(bad, kept(ag(st = st, verb = "v".repeat(129))))
        assertEquals(bad, kept(ag(st = st, resource = "orders/" + "r".repeat(506))))
        assertEquals("allow/null", code(ag(st = st, resource = "orders/" + "r".repeat(505))))
        assertEquals(bad, kept(ag(st = st, purpose = "bad purpose")))
        assertEquals(bad, kept(ag(st = st, purpose = Json.Num("5"))))
        assertEquals(bad, kept(ag(st = st, fn = "avg")))
        assertEquals(bad, kept(ag(st = st, noise = "loud")))
        assertEquals(bad, kept(ag(st = st, salt = "s".repeat(15))))
        assertEquals("allow/null", code(ag(st = st, salt = "s".repeat(16))))
        assertEquals(bad, kept(ag(st = st, salt = Json.Num("1234567890123456"))))
        assertEquals(bad, kept(ag(st = st, values = "x")))
        assertEquals(bad, kept(ag(st = st, values = jl(1L, Json.Num("1.5")))))
        assertEquals(bad, kept(ag(st = st, values = jl(1L, "2"))))
        assertEquals("deny/no_read_scope", kept(ag(st = st, verb = "orders.list")))
        assertEquals("deny/no_read_scope", kept(ag(st = st, resource = "users/1")))
        assertEquals("deny/no_read_scope", kept(ag(st = st, purpose = "billing")))
        assertEquals("deny/no_read_scope", kept(ag(st = st, g = agGrant(agBody("rules", jl(rule("fns", jl("count"))))))))
        assertEquals("allow/null", code(ag(st = st, g = agGrant(agBody("rules", jl(rule("verb", "x.y"), rule()))))))
        // secure noise still answers (and a repeat comes from the state)
        val sec = ag(g = agGrant(agBody("rules", jl(rule("dp", true)))), noise = "secure")
        assertEquals("allow/null", code(sec))
        assertEquals(500_000L, sec.chargedMicro)
    }

    @Test
    fun aHostileGrantAnswersWithTheEmptyState() {
        val r = ag(g = Kill05ReadReadSideTest.Boom(), st = state(5L, 1L))
        assertEquals("deny", r.decision)
        assertEquals("bad_request", r.code)
        assertNull(r.value)
        assertEquals(empty, Json.canonicalize(r.state))
        assertEquals(0L, r.chargedMicro)
    }

    @Test
    fun aggregateGrantShape() {
        fun ok(vararg over: Any?) = ReadVault.validAggregateGrantBody(agBody("rules", jl(rule(*over))))
        assertTrue(ok())
        assertTrue(ok("clamp", 1_000_000L))
        assertFalse(ok("clamp", 1_000_001L))
        assertTrue(ok("clamp", 0L))
        assertFalse(ok("clamp", -1L))
        assertTrue(ok("epsilon_micro", 1_073_741_824L))
        assertFalse(ok("epsilon_micro", 1_073_741_825L))
        assertTrue(ok("min_group", 1L))
        assertFalse(ok("min_group", 0L))
        assertFalse(ok("min_group", "2"))
        assertTrue(ok("dp", false, "epsilon_micro", 0L))
        assertFalse(ok("dp", true, "epsilon_micro", 0L))
        assertTrue(ok("dp", true, "epsilon_micro", 1L))
        assertFalse(ok("dp", "true"))
        assertFalse(ok("dp", null))
        assertFalse(ok("fns", jl()))
        assertFalse(ok("fns", jl("avg")))
        assertFalse(ok("fns", jl("sum", "count")))
        assertTrue(ok("fns", jl("sum")))
        assertFalse(ok("purposes", jl()))
        assertFalse(ok("verb", ""))
        assertFalse(ok("verb", "v".repeat(129)))
        assertTrue(ok("verb", "v".repeat(128)))
        assertFalse(ok("resource_prefix", "r".repeat(513)))
        assertTrue(ok("resource_prefix", "r".repeat(512)))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("rules", jl(rule().also { it["x"] = 1L }))))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("rules", jl(rule(), "x"))))
        assertTrue(ReadVault.validAggregateGrantBody(agBody("rules", ArrayList<Any?>(List(16) { rule() }))))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("rules", ArrayList<Any?>(List(17) { rule() }))))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("rules", jl())))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("rules", "x")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("v", 2L)))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("v", "1")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("id", Json.Num("5"))))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("id", "bad id")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("principal", "x")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("issued_at", -1L)))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("expires_at", "1")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("epsilon_budget_micro", -1L)))
        assertFalse(ReadVault.validAggregateGrantBody(agBody("max_queries", "3")))
        assertFalse(ReadVault.validAggregateGrantBody(agBody().also { it["x"] = 1L }))
        assertFalse(ReadVault.validAggregateGrantBody("x"))
    }

    // ---- the sampler over scripted streams ----

    /** The given values in order, then the last one forever; counts reads. */
    private class Script(vararg val vs: Long) {
        var reads = 0
        fun next(): Long = vs[minOf(reads++, vs.size - 1)]
    }

    private fun uniform(n: Long, s: Script) = ReadVault.uniformOf(n) { s.next() }

    private fun iae(f: () -> Any?): String? = try {
        f()
        fail("no IllegalArgumentException")
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun uniformRejectsAtTheLimit() {
        val top = (1L shl 48) - 1 // 2^48 = 1 (mod 3): the limit for n = 3 is 2^48 - 1, so 2^48 - 1 is rejected
        val s = Script(top, top - 1)
        assertEquals((top - 1) % 3, uniform(3, s))
        assertEquals(2, s.reads)
        val p = Script(top)
        assertEquals((1L shl 47) - 1, uniform(1L shl 47, p)) // 2^47 divides 2^48: nothing is rejected
        assertEquals(1, p.reads)
        val one = Script(top, 5)
        assertEquals(0L, uniform(1, one))
        assertEquals(1, one.reads)
        val lim = Script(top - 1)
        assertEquals((top - 1) % 7, uniform(7, lim)) // 2^48 = 1 (mod 7): limit 2^48 - 1
        assertEquals(1, lim.reads)
        val rej = Script(top - 3, top - 4) // 2^48 = 4 (mod 6): limit 2^48 - 4 = top - 3, which is rejected
        assertEquals((top - 4) % 6, uniform(6, rej))
        assertEquals(2, rej.reads)
    }

    @Test
    fun uniformGivesUpAfterTheStepBound() {
        val s = Script((1L shl 48) - 1)
        assertEquals("uniform: no draw", iae { uniform(3, s) })
        assertEquals(100_000, s.reads)
        for (bad in listOf(0L, -1L, (1L shl 47) + 1)) {
            val t = Script(0)
            assertEquals("uniform: bad bound", iae { uniform(bad, t) })
            assertEquals(0, t.reads)
            assertEquals("uniform: bad bound", iae { ReadVault.seededDraws("seed-a").uniform(bad) })
        }
    }

    /** Draws answering f(n) for a bound n, counting calls (values outside [0, n) are allowed: the sampler must not assume them). */
    private class Fixed(val f: (Long) -> Long) : ReadVault.Draws {
        var calls = 0L
        override fun uniform(n: Long): Long {
            calls++
            return f(n)
        }
    }

    @Test
    fun laplaceGiveUpPaths() {
        // every Bernoulli succeeds: the inner exp(-1) trial never stops
        val zero = Fixed { 0L }
        assertEquals("bernoulli: no termination", iae { ReadVault.discreteLaplace(zero, 1, 1) })
        assertEquals(100_002L, zero.calls)
        // every exp(-1) trial succeeds at once: the geometric count never stops
        val high = Fixed { it }
        assertEquals("laplace: no termination", iae { ReadVault.discreteLaplace(high, 1, 3) })
        assertEquals(100_003L, high.calls)
        // every sample is a negative zero, which is rejected and redrawn
        val negZero = Fixed { if (it == 2L) 1L else 0L }
        assertEquals("laplace: no sample", iae { ReadVault.discreteLaplace(negZero, 1, 3) })
        assertEquals(500_000L, negZero.calls)
    }

    private class Seq(vararg val vs: Long) : ReadVault.Draws {
        var at = 0
        override fun uniform(n: Long): Long = vs[at++]
    }

    @Test
    fun laplaceComposesItsDraws() {
        // u = 2 of t = 5; exp(-2/5) accepted (its first trial fails); v = 1 (one exp(-1) success, then a failure at k = 2); sign negative
        val d = Seq(2, 9, 9, 0, 1, 1)
        assertEquals(-((2L + 5L) / 3L), ReadVault.discreteLaplace(d, 3, 5))
        assertEquals(6, d.at)
        val d2 = Seq(4, 9, 0, 9, 0)
        assertEquals(4L / 2L, ReadVault.discreteLaplace(d2, 2, 5))
        assertEquals(5, d2.at)
        // exp(-u/t) rejected (first trial succeeds, second fails: k = 2 is even), then a fresh outer draw
        val d3 = Seq(1, 0, 9, 3, 9, 0, 9, 0)
        assertEquals(3L, ReadVault.discreteLaplace(d3, 1, 5))
        assertEquals(8, d3.at)
    }

    @Test
    fun secureDrawsSeedWithThirtyTwoFreshBytes() {
        val fixed = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                for (i in bytes.indices) bytes[i] = (i + 1).toByte()
            }
        }
        val want = ByteArray(32) { (it + 1).toByte() }
        val a = ReadVault.secureDraws(fixed)
        val b = ReadVault.seededDraws(Pca.b64(want))
        for (i in 0 until 12) assertEquals(b.uniform(1L shl 47), a.uniform(1L shl 47))
    }

    /** The oracle's base aggregate is a real query: 'secure' noise differs from its seeded answer (each matches with p ~ 1/400). */
    @Test
    fun secureNoiseIsNotTheSeededNoise() {
        val base = of("aggregateRead").first { it["name"] == "aggregateRead/base" }
        val a = args(base)
        val seeded = Json.canonicalize((base["out"] as Map<String, Any?>)["value"])
        var differs = false
        for (i in 0 until 16) {
            if (differs) break
            val r = ReadVault.aggregateRead(ReadVault.AggregateInput(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], "secure", a[10]))
            assertEquals("allow", r.decision)
            differs = seeded != Json.canonicalize(r.value)
        }
        assertTrue("16 'secure' answers all equal the seeded one", differs)
    }
}
