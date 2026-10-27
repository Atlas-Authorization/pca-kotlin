package net.atlasauth.pca.verifier

import java.io.File
import java.sql.SQLException
import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import net.atlasauth.pca.verifier.AuthorizeTestKit.run
import net.atlasauth.pca.verifier.AuthorizeTestKit.settle
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `Authorize.authorize` (0.5): the shared TypeScript-signed fixtures (exact outcome and parity with the TypeScript
 * `authorize()`), the reasons, the fail-closed table, the agent caveat evaluator and the `tool_schema` rules.
 */
@Suppress("UNCHECKED_CAST")
class AuthorizeTest {
    private fun deny(allow: Boolean = false, status: Int, vararg failed: String) =
        linkedMapOf("allow" to allow, "status" to status, "failed" to failed.toList())

    // ---- the shared fixtures ----

    @Test
    fun fixtureShape() {
        assertEquals("pca-authorize-fixtures/1", AuthorizeTestKit.fix["format"])
        assertTrue(AuthorizeTestKit.cases.size >= 31)
        for (c in AuthorizeTestKit.cases) for (s in AuthorizeTestKit.steps(c)) assertTrue(c["name"].toString(), s.containsKey("ts"))
        assertEquals(35, AuthorizeTestKit.cases.sumOf { AuthorizeTestKit.steps(it).size })
    }

    @Test
    fun fixtureCopyIsByteIdentical() {
        val py = AuthorizeTestKit.findUp("sdks/python-pca/testdata/authorize-fixtures.json") ?: return // standalone checkout
        assertArrayEquals(py.readBytes(), File(AuthorizeTestKit.FIXTURES).readBytes())
    }

    private fun assertFixtures(store: () -> Authorize.StateStore, withTs: Boolean) {
        var steps = 0
        for (c in AuthorizeTestKit.cases) {
            val got = AuthorizeTestKit.runCase(c, store())
            val ss = AuthorizeTestKit.steps(c)
            assertEquals(c["name"].toString(), ss.map { AuthorizeTestKit.expectOf(it) }, got)
            if (withTs) assertEquals(c["name"].toString(), ss.map { AuthorizeTestKit.tsOf(it) }, got.map { linkedMapOf("allow" to it["allow"], "status" to it["status"]) })
            steps += ss.size
        }
        assertEquals(35, steps)
    }

    @Test
    fun fixturesMemoryStore() = assertFixtures({ Authorize.MemoryStateStore() }, true)

    @Test
    fun fixturesJdbcSqliteStore() = assertFixtures({ AuthorizeTestKit.jdbcStore() }, true)

    // ---- the reasons ----

    @Test
    fun over400Under100RefusedWithReason() {
        val r = run(case("envelope-max-spend-400-refused"))
        assertEquals(deny(status = 403, failed = arrayOf("policy")), settle(r))
        assertEquals("policy: caveat(s) not satisfied: max_spend", r.reason)
        assertEquals("policy: root caveat(s) not satisfied: max_spend", run(case("root-max-spend-400-refused")).reason)
        assertEquals("delegated_caveats: delegation caveat(s) not satisfied: max_spend", run(case("delegated-max-spend-400-refused")).reason)
        assertEquals("policy: amount <= 100 not satisfied for payments.send on payments/acme", run(case("envelope-predicate-400-refused")).reason)
        assertEquals("policy: grant carries no valid envelope", run(case("no-envelope")).reason)
        assertEquals("delegated_caveats: delegation caveat(s) not satisfied: tool_schema", run(case("delegated-tool-schema-400")).reason)
    }

    @Test
    fun signed50Executed400ReportsTheBindingFirst() {
        assertEquals(
            "operation: the proof's params_digest does not match the params of this payments.send operation",
            run(case("envelope-max-spend-signed-50-executes-400")).reason,
        )
    }

    @Test
    fun operationXForYReason() {
        assertEquals(
            "operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme",
            run(case("operation-other-verb")).reason,
        )
    }

    @Test
    fun attestationAndAudience() {
        val a = run(case("attestation-bound"))
        assertTrue(a.reason!!.startsWith("attestation: the grant binds the agent (agent_binding)"))
        val w = run(case("wrong-audience"))
        assertEquals(401, w.status)
        assertEquals("audience: aud does not match this resource server / instance", w.reason)
    }

    @Test
    fun allowBindsTheOperation() {
        val c = case("envelope-max-spend-within")
        val r = run(c)
        assertTrue(r.allow)
        assertEquals(200, r.status)
        assertNull(r.reason)
        assertEquals("payments.send", r.operation!!.verb)
        assertEquals("payments/acme", r.operation!!.resource)
        assertEquals((pcactn(c)["action"] as Map<String, Any?>)["params_digest"], r.operation!!.paramsDigest)
        assertEquals(Pca.hashCanonical(pcactn(c)), r.operation!!.id)
        assertTrue(r.checks.values.none { it == "fail" })
        assertTrue(Authorize.isAuthorizedFor(r, op(c)))
        assertFalse(Authorize.isAuthorizedFor(r, op(c).copy(params = mapOf("amount" to 400, "currency" to "usd"))))
        assertFalse(Authorize.isAuthorizedFor(r, op(c).copy(verb = "payments.refund")))
        assertFalse(Authorize.isAuthorizedFor(r, op(c).copy(resource = "payments/other")))
        assertFalse(Authorize.isAuthorizedFor(r, null))
        assertFalse(Authorize.isAuthorizedFor(null, op(c)))
        // Kotlin numbers digest like their JSON form
        assertTrue(Authorize.isAuthorizedFor(r, op(c).copy(params = mapOf("amount" to 50, "currency" to "usd"))))
        val denied = case("envelope-max-spend-400-refused")
        assertFalse(Authorize.isAuthorizedFor(run(denied), op(denied)))
    }

    @Test
    fun operationParamsAreCopiedBeforeVerification() {
        val c = case("envelope-max-spend-within")
        val params = LinkedHashMap(op(c).params)
        var calls = 0
        val r = Authorize.authorize(
            pcactn(c),
            input(c, operation = op(c).copy(params = params), isRevoked = { _, _ -> calls++; params["amount"] = Json.Num("400"); false }),
        )
        assertEquals(1, calls)
        assertTrue(r.allow)
    }

    @Test
    fun jsonTextAndBytesAccepted() {
        val c = case("envelope-max-spend-within")
        val text = Json.canonicalizeStrict(pcactn(c))
        assertTrue(Authorize.authorize(text, input(c)).allow)
        assertTrue(Authorize.authorize(text.toByteArray(Charsets.UTF_8), input(c)).allow)
    }

    // ---- fail closed: configuration, operation, callbacks, store ----

    @Test
    fun missingComponentRefusedBeforeVerification() {
        val c = case("envelope-max-spend-within")
        val cases = listOf<Pair<String, (MutableList<String>) -> Authorize.Input>>(
            "audience" to { seen -> input(c, audience = "", resolveGrant = { seen.add(it); grant(c) }) },
            "audience" to { seen -> input(c, audience = null, resolveGrant = { seen.add(it); grant(c) }) },
            "resolveGrant" to { _ -> input(c, resolveGrant = null) },
            "stateStore" to { seen -> input(c, stateStore = null, resolveGrant = { seen.add(it); grant(c) }) },
            "isRevoked" to { seen -> input(c, isRevoked = null, resolveGrant = { seen.add(it); grant(c) }) },
        )
        for ((name, mk) in cases) {
            val seen = ArrayList<String>()
            val r = Authorize.authorize(pcactn(c), mk(seen))
            assertEquals(name, deny(status = 403, failed = arrayOf("authorize_config")), settle(r))
            assertEquals(listOf(name), r.missing)
            assertEquals("authorize_config: missing required component(s): $name (fail closed)", r.reason)
            assertTrue("resolver never called", seen.isEmpty())
        }
    }

    @Test
    fun allMissingListed() {
        val r = Authorize.authorize(emptyMap<String, Any?>(), Authorize.Input(null, null, null, null, null))
        assertEquals(listOf("audience", "resolveGrant", "stateStore", "isRevoked"), r.missing)
        assertEquals(listOf("audience", "resolveGrant", "stateStore", "isRevoked"), Authorize.missingAuthorizeComponents(null, null, null, null))
    }

    @Test
    fun unknownPlanModeRefused() {
        val r = run(case("envelope-max-spend-within"), input = input(case("envelope-max-spend-within"), plan = "multi"))
        assertEquals(listOf("plan (only 'single-step' or null)"), r.missing)
    }

    @Test
    fun operationRequired() {
        val c = case("envelope-max-spend-within")
        val ops = listOf(
            null,
            Authorize.Operation.fromJson(null),
            Authorize.Operation.fromJson(emptyMap<String, Any?>()),
            Authorize.Operation.fromJson(mapOf("verb" to "payments.send", "resource" to "payments/acme")),
            Authorize.Operation.fromJson(mapOf("verb" to "payments.send", "resource" to "payments/acme", "params" to listOf(1))),
            Authorize.Operation("", "payments/acme", emptyMap()),
            Authorize.Operation("payments.send", "", emptyMap()),
        )
        for (o in ops) {
            val r = Authorize.authorize(pcactn(c), input(c, operation = o))
            assertEquals(deny(status = 403, failed = arrayOf("operation")), settle(r))
            assertEquals("operation: authorize needs the operation to execute (verb, resource, params) (fail closed)", r.reason)
        }
    }

    @Test
    fun noPlanSourceDenies() {
        val c = case("envelope-max-spend-within")
        val r = Authorize.authorize(pcactn(c), input(c, plan = null))
        assertEquals(deny(status = 403, failed = arrayOf("plan_root_authorized")), settle(r))
        assertTrue(r.reason!!.startsWith("plan_root_authorized: required check is not-enforced"))
    }

    @Test
    fun contextPlanMustBeAuthorized() {
        val c = case("envelope-max-spend-within")
        val node = linkedMapOf<String, Any?>(
            "id" to "n1", "verb" to "payments.send", "resource" to "payments/acme",
            "params_digest" to (pcactn(c)["action"] as Map<String, Any?>)["params_digest"], "reversibility_class" to "irreversible",
        )
        assertTrue(Authorize.authorize(pcactn(c), input(c, plan = null, context = { mapOf("plan" to listOf(node), "plan_authorized" to true) })).allow)
        val no = Authorize.authorize(pcactn(c), input(c, plan = null, context = { mapOf("plan" to listOf(node)) }))
        assertEquals(listOf("plan_root_authorized"), settle(no)["failed"])
        assertEquals("plan_root_authorized: the plan root has not been authorized by the principal", no.reason)
        val other = Authorize.authorize(pcactn(c), input(c, plan = null, context = { mapOf("plan" to listOf(LinkedHashMap(node).also { it["verb"] = "x" }), "plan_authorized" to true) }))
        assertEquals("plan_root_authorized: known plan does not match plan.root", other.reason)
        val garbage = Authorize.authorize(pcactn(c), input(c, plan = null, context = { mapOf("plan" to "x", "plan_authorized" to true) }))
        assertEquals("plan_root_authorized: known plan does not match plan.root", garbage.reason)
    }

    @Test
    fun revocationMustBeExactlyFalse() {
        val c = case("envelope-max-spend-within")
        for (ret in listOf<Any?>(null, 0, "no", emptyList<Any?>(), "false", true)) {
            val r = Authorize.authorize(pcactn(c), input(c, isRevoked = { _, _ -> ret }))
            assertEquals(ret.toString(), deny(status = 403, failed = arrayOf("revocation")), settle(r))
        }
        val t = Authorize.authorize(pcactn(c), input(c, isRevoked = { _, _ -> throw IllegalStateException("down") }))
        assertEquals(deny(status = 403, failed = arrayOf("revocation")), settle(t))
        assertEquals("revocation: the revocation check failed (fail closed)", t.reason)
        assertEquals("revocation: the grant is revoked", Authorize.authorize(pcactn(c), input(c, isRevoked = { _, _ -> true })).reason)
    }

    @Test
    fun storeFailureDenies() {
        val c = case("envelope-max-spend-within")
        val broken = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw SQLException("locked")
        }
        val garbage = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = null
        }
        val refused = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = Authorize.ClaimResult(false)
        }
        for (st in listOf(broken, garbage)) {
            val r = Authorize.authorize(pcactn(c), input(c, stateStore = st))
            assertEquals(deny(status = 403, failed = arrayOf("replay")), settle(r))
            assertEquals("replay: the replay store failed (fail closed)", r.reason)
        }
        assertEquals("replay: 1 was already claimed (replay)", Authorize.authorize(pcactn(c), input(c, stateStore = refused)).reason)
    }

    @Test
    fun storeKeyAndCounter() {
        val seen = ArrayList<Pair<String, Long>>()
        val rec = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult { seen.add(key to counter); return Authorize.ClaimResult(true) }
        }
        val c = case("envelope-max-spend-within")
        assertTrue(Authorize.authorize(pcactn(c), input(c, stateStore = rec)).allow)
        val leaf = (pcactn(c)["cap_chain"] as List<Any?>).last() as Map<String, Any?>
        assertEquals(listOf(Authorize.stateKey(grant(c)["id"] as String, leaf["holder"] as String) to 1L), seen)
        assertEquals("${grant(c)["id"]}:${leaf["holder"]}", seen[0].first)
    }

    @Test
    fun deniedRequestNeverReachesTheStore() {
        val seen = ArrayList<String>()
        val rec = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult { seen.add(key); return Authorize.ClaimResult(true) }
        }
        for (name in listOf("envelope-max-spend-400-refused", "operation-other-verb", "revoked", "no-envelope", "attestation-bound", "wrong-audience")) {
            val c = case(name)
            assertFalse(name, Authorize.authorize(pcactn(c), input(c, stateStore = rec, isRevoked = { _, _ -> name == "revoked" })).allow)
        }
        assertTrue(seen.isEmpty())
    }

    @Test
    fun replayReason() {
        val c = case("envelope-max-spend-within")
        val st = Authorize.MemoryStateStore()
        assertTrue(Authorize.authorize(pcactn(c), input(c, stateStore = st)).allow)
        val again = Authorize.authorize(pcactn(c), input(c, stateStore = st))
        assertEquals(deny(status = 403, failed = arrayOf("replay")), settle(again))
        assertEquals("replay: 1 is not greater than last seen 1 (replay)", again.reason)
    }

    @Test
    fun callbacksFailClosed() {
        val c = case("envelope-max-spend-within")
        val boom: (String) -> Map<String, Any?>? = { throw IllegalStateException("x") }
        assertEquals(listOf("resolve_grant"), settle(Authorize.authorize(pcactn(c), input(c, resolveGrant = boom)))["failed"])
        assertEquals(listOf("context"), settle(Authorize.authorize(pcactn(c), input(c, context = { throw IllegalStateException("x") })))["failed"])
        val listCtx = { _: Map<String, Any?> -> listOf(1) } as (Map<String, Any?>) -> Map<String, Any?>?
        assertEquals(listOf("context"), settle(Authorize.authorize(pcactn(c), input(c, context = listCtx)))["failed"])
        assertEquals(listOf("intent_v2"), settle(Authorize.authorize(pcactn(c), input(c, intentV2 = { throw IllegalStateException("x") })))["failed"])
        assertEquals(deny(status = 401, failed = arrayOf("grant_ref")), settle(Authorize.authorize(pcactn(c), input(c, resolveGrant = { null }))))
        val noRef = LinkedHashMap(pcactn(c)).also { it.remove("grant_ref") }
        assertEquals(deny(status = 401, failed = arrayOf("malformed")), settle(Authorize.authorize(noRef, input(c))))
        // a context returning null is an empty context
        assertTrue(Authorize.authorize(pcactn(c), input(c, context = { null })).allow)
    }

    @Test
    fun undecodableAndAbsentProofs() {
        val c = case("envelope-max-spend-within")
        assertEquals(deny(status = 401, failed = arrayOf("wire")), settle(Authorize.authorize(null, input(c))))
        assertEquals("wire: no PCActn presented", Authorize.authorize(null, input(c)).reason)
        for (bad in listOf<Any>("{not json", 12, "[1]", byteArrayOf(0xff.toByte(), 0x7b), "x".repeat(Pca.MAX_ARTIFACT_BYTES + 1))) {
            val r = Authorize.authorize(bad, input(c))
            assertEquals(deny(status = 401, failed = arrayOf("wire")), settle(r))
            assertEquals("wire: PCActn could not be decoded", r.reason)
        }
        // a structurally malformed proof is a terminal wire failure (401)
        val noSig = LinkedHashMap(pcactn(c)).also { it.remove("sig") }
        assertEquals(deny(status = 401, failed = arrayOf("malformed", "wire")), settle(Authorize.authorize(noSig, input(c))))
    }

    @Test
    fun zkComplianceFailsClosed() {
        val c = case("envelope-max-spend-within")
        val p = LinkedHashMap(pcactn(c)).also { it["zk_compliance"] = mapOf("x" to 1) }
        val r = Authorize.authorize(p, input(c))
        assertFalse(r.allow)
        assertEquals("fail", r.checks["zk_compliance"])
    }

    @Test
    fun requireAddsChecks() {
        val c = case("envelope-max-spend-within")
        val r = Authorize.authorize(pcactn(c), input(c, require = listOf("freshness")))
        assertEquals(deny(status = 403, failed = arrayOf("freshness")), settle(r))
        assertEquals("freshness: required check is absent (default-deny: not enforced by this resource server)", r.reason)
    }

    @Test
    fun reversibilityAuthoritativeClass() {
        val c = case("envelope-max-spend-within") // the agent declared "irreversible"
        assertEquals("pass", Authorize.authorize(pcactn(c), input(c, context = { mapOf("reversibility_class" to "reversible") })).checks["reversibility"])
        assertEquals("pass", Authorize.authorize(pcactn(c), input(c, context = { mapOf("reversibility_class" to "nuclear") })).checks["reversibility"])
        // a declared class less restrictive than the server's fails
        val p = LinkedHashMap(pcactn(c))
        p["action"] = LinkedHashMap(p["action"] as Map<String, Any?>).also { it["reversibility_class"] = "reversible" }
        val r = Authorize.authorize(p, input(c, context = { mapOf("reversibility_class" to "irreversible") }))
        assertEquals("fail", r.checks["reversibility"])
        assertTrue(r.reasons.contains("reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'"))
    }

    @Test
    fun internalErrorDenies() {
        // a params value outside the JSON model (a Double) cannot be canonicalized: an internal error, never an exception
        val c = case("envelope-max-spend-within")
        val r = Authorize.authorize(pcactn(c), input(c, operation = op(c).copy(params = mapOf("amount" to 1.5))))
        assertEquals(deny(status = 403, failed = arrayOf("authorize")), settle(r))
        assertEquals("authorize: error (fail closed): IllegalArgumentException", r.reason)
    }

    @Test
    fun readEnvelopeAndRootCaveats() {
        val g = grant(case("envelope-max-spend-within"))
        val env = Authorize.readEnvelope(g)!!
        assertFalse(env.containsKey("type"))
        assertTrue(env["predicates"] is List<*>)
        assertNull(Authorize.readEnvelope(grant(case("no-envelope"))))
        assertNull(Authorize.readEnvelope(mapOf("caveats" to listOf(mapOf("type" to "envelope", "goal_commit" to "x", "predicates" to emptyList<Any?>(), "caveats" to emptyList<Any?>(), "agent_binding" to emptyMap<String, Any?>())))))
        assertNull(Authorize.readEnvelope("x"))
        val root = Authorize.rootCaveats(grant(case("root-max-spend-within"))) as List<Map<String, Any?>>
        assertEquals(listOf("max_spend"), root.map { it["type"] })
    }

    // ---- caveat semantics: conformance parity and the agent-native types ----

    @Test
    fun caveatEvalVectorsThroughTheAgentEvaluator() {
        var n = 0
        for (v in AuthorizeTestKit.caveatEval) {
            val ctx = v["context"] as Map<String, Any?>
            val r = Authorize.evaluateAgentCaveats(Caveats.policyCaveats(v["grant"], v["chain"]), ctx, mapOf("action" to ctx["action"]))
            val exp = v["expect"] as Map<String, Any?>
            assertEquals(v["name"].toString(), exp["allow"], r.ok)
            assertEquals(v["name"].toString(), exp["failed"], r.failed)
            val stock = Caveats.evaluateCaveats(Caveats.policyCaveats(v["grant"], v["chain"]), ctx)
            assertEquals(v["name"].toString(), stock, r)
            n++
        }
        assertTrue("caveat_eval vectors present ($n)", n >= 40)
    }

    @Test
    fun agentCaveatsPredicatesAndUnknown() {
        val action = mapOf("verb" to "pay", "resource" to "inv:1", "params" to mapOf("amount" to 5))
        val ctx = mapOf("now" to 1, "action" to action)
        val actx = mapOf("action" to action)
        val allow = mapOf("type" to "predicates", "allow" to listOf(mapOf("verb" to "pay", "resource" to "inv:*")))
        val denyP = mapOf("type" to "predicates", "allow" to listOf(mapOf("verb" to "pay", "resource" to "inv:2")))
        assertEquals(Caveats.Result(true, emptyList()), Authorize.evaluateAgentCaveats(listOf(allow), ctx, actx))
        assertEquals(Caveats.Result(false, listOf("predicates")), Authorize.evaluateAgentCaveats(listOf(denyP), ctx, actx))
        assertEquals(Caveats.Result(false, listOf("predicates")), Authorize.evaluateAgentCaveats(listOf(mapOf("type" to "predicates", "allow" to "x")), ctx, actx))
        assertEquals(Caveats.Result(false, listOf("predicates")), Authorize.evaluateAgentCaveats(listOf(allow), ctx, null))
        assertEquals(Caveats.Result(false, listOf("geo", "<malformed>")), Authorize.evaluateAgentCaveats(listOf(mapOf("type" to "geo"), 5), ctx, actx))
        assertEquals(Caveats.Result(false, listOf("<malformed caveats>")), Authorize.evaluateAgentCaveats("x", ctx, actx))
        assertEquals(Caveats.Result(true, emptyList()), Authorize.evaluateAgentCaveats(emptyList<Any?>(), ctx, actx))
        val spend = mapOf("type" to "max_spend", "usd" to 10)
        assertEquals(Caveats.Result(true, emptyList()), Authorize.evaluateAgentCaveats(listOf(spend), ctx, actx))
        assertEquals(Caveats.Result(false, listOf("max_spend")), Authorize.evaluateAgentCaveats(listOf(mapOf("type" to "max_spend", "usd" to 4)), ctx, actx))
    }

    private fun toolCaveat(schema: Any?, tool: String = "pay", sig: String = "sigdigest"): Map<String, Any?> = linkedMapOf(
        "type" to "tool_schema", "tool" to tool, "signature_digest" to sig, "schema" to schema,
        "schema_digest" to Pca.hashCanonical(schema),
        "binding_digest" to Pca.hashCanonical(linkedMapOf("tool" to tool, "signature_digest" to sig, "schema" to schema)),
    )

    private fun n(s: String) = Json.Num(s)
    private fun ok() = Authorize.ToolSchemaResult(true, null)
    private fun no(reason: String) = Authorize.ToolSchemaResult(false, reason)

    @Test
    fun toolSchemaRules() {
        val cv = toolCaveat(
            Json.parse(
                """{"props":{"n":{"type":"integer","min":0,"max":10},"flag":{"type":"boolean","const":true},""" +
                    """"s":{"type":"string","prefix":"ab","maxLength":3},"e":{"type":"number","enum":[1,2.5]},""" +
                    """"o":{"type":"object","props":{"x":{"type":"string"}},"required":["x"]},""" +
                    """"a":{"type":"array","items":{"type":"integer"},"maxItems":2}},"required":["n"]}""",
            ),
        )
        fun ev(args: Map<String, Any?>, tool: String = "pay", sigDigest: String? = null): Authorize.ToolSchemaResult {
            val call = linkedMapOf<String, Any?>("tool" to tool, "args" to args)
            if (sigDigest != null) call["tool_signature_digest"] = sigDigest
            return Authorize.evaluateToolSchema(cv, call)
        }
        assertEquals(ok(), ev(mapOf("n" to n("3"))))
        assertEquals(ok(), ev(mapOf("n" to n("3.0")))) // JS: 3.0 is an integer
        assertEquals(ok(), ev(mapOf("n" to 3)))
        assertEquals(no("args.n: wrong type (expected integer)"), ev(mapOf("n" to n("3.5"))))
        assertEquals(no("args.n: wrong type (expected integer)"), ev(mapOf("n" to true))) // a bool is never a number
        assertEquals(no("args.n: above max"), ev(mapOf("n" to n("11"))))
        assertEquals(no("args.n: below min"), ev(mapOf("n" to n("-1"))))
        assertEquals(no("args: missing required argument 'n'"), ev(emptyMap()))
        assertEquals(no("args: unexpected argument \"zz\""), ev(mapOf("n" to 1, "zz" to 1)))
        assertEquals(no("args.flag: wrong type (expected boolean)"), ev(mapOf("n" to 1, "flag" to 1)))
        assertEquals(no("args.flag: violates const"), ev(mapOf("n" to 1, "flag" to false)))
        assertEquals(ok(), ev(mapOf("n" to 1, "s" to "abc")))
        assertEquals(no("args.s: violates prefix"), ev(mapOf("n" to 1, "s" to "a😀")))
        assertEquals(no("args.s: exceeds maxLength"), ev(mapOf("n" to 1, "s" to "ab😀"))) // UTF-16 length 4
        assertEquals(no("args.s: wrong type (expected string)"), ev(mapOf("n" to 1, "s" to 5)))
        assertEquals(ok(), ev(mapOf("n" to 1, "e" to n("2.5"))))
        assertEquals(ok(), ev(mapOf("n" to 1, "e" to n("1"))))
        assertEquals(no("args.e: violates enum"), ev(mapOf("n" to 1, "e" to n("3"))))
        assertEquals(no("args.o: missing required argument 'x'"), ev(mapOf("n" to 1, "o" to emptyMap<String, Any?>())))
        assertEquals(no("args.o: expected object"), ev(mapOf("n" to 1, "o" to listOf(1))))
        assertEquals(no("args.a: exceeds maxItems"), ev(mapOf("n" to 1, "a" to listOf(1, 2, 3))))
        assertEquals(no("args.a[1]: wrong type (expected integer)"), ev(mapOf("n" to 1, "a" to listOf(1, "2"))))
        assertEquals(no("args.a: expected array"), ev(mapOf("n" to 1, "a" to "x")))
        assertEquals(no("tool \"refund\" not authorized"), ev(mapOf("n" to 1), tool = "refund"))
        assertEquals(no("signed tool_binding differs from the authorized tool signature"), ev(mapOf("n" to 1), sigDigest = "other"))
        assertEquals(ok(), ev(mapOf("n" to 1), sigDigest = "sigdigest"))
        // the unexpected-argument name is cut to 48 UTF-16 code units and printed as JSON.stringify would
        val long = "k".repeat(60)
        assertEquals(no("args: unexpected argument \"${"k".repeat(48)}…\""), ev(mapOf("n" to 1, long to 1)))
        assertEquals(no("args: unexpected argument \"a\\\"b\\n\""), ev(mapOf("n" to 1, "a\"b\n" to 1)))
    }

    @Test
    fun toolSchemaCaveatIntegrity() {
        val schema = Json.parse("""{"props":{"n":{"type":"number"}}}""")
        val good = toolCaveat(schema)
        val call = mapOf("tool" to "pay", "args" to mapOf("n" to 1))
        assertTrue(Authorize.evaluateToolSchema(good, call).ok)
        assertEquals(no("schema digest mismatch"), Authorize.evaluateToolSchema(LinkedHashMap(good).also { it["schema_digest"] = "x" }, call))
        assertEquals(no("binding digest mismatch"), Authorize.evaluateToolSchema(LinkedHashMap(good).also { it["binding_digest"] = "x" }, call))
        assertEquals(no("malformed tool_schema caveat"), Authorize.evaluateToolSchema(LinkedHashMap(good).also { it["tool"] = "" }, call))
        assertEquals(no("malformed tool_schema caveat"), Authorize.evaluateToolSchema(LinkedHashMap(good).also { it["type"] = "x" }, call))
        assertEquals(no("malformed tool_schema caveat"), Authorize.evaluateToolSchema("x", call))
        val bad = toolCaveat(Json.parse("""{"props":{"n":{"type":"number","pattern":"x"}}}"""))
        assertEquals(no("malformed tool_schema caveat: n: unknown spec key"), Authorize.evaluateToolSchema(bad, call))
        assertEquals(no("malformed call"), Authorize.evaluateToolSchema(good, mapOf("tool" to "pay", "args" to listOf(1))))
        assertEquals(no("malformed call"), Authorize.evaluateToolSchema(good, null))
        // no signature_digest: the binding is over the string "undefined" (JavaScript String(undefined))
        val unsigned = LinkedHashMap(good).also {
            it.remove("signature_digest")
            it["binding_digest"] = Pca.hashCanonical(linkedMapOf("tool" to "pay", "signature_digest" to "undefined", "schema" to schema))
        }
        assertTrue(Authorize.evaluateToolSchema(unsigned, call).ok)
    }

    @Test
    fun validateArgSchemaLimits() {
        fun v(s: String) = Authorize.validateArgSchema(Json.parse(s))
        assertEquals("schema must be an object", Authorize.validateArgSchema(listOf(1)))
        assertEquals("unknown schema key", v("""{"props":{},"x":1}"""))
        assertEquals("props must be an object", v("""{"props":[]}"""))
        assertEquals("invalid property name 'a-b'", v("""{"props":{"a-b":{"type":"string"}}}"""))
        assertEquals("a: unknown type", Authorize.validateArgSchema(mapOf("props" to mapOf("a" to mapOf("type" to "date")))))
        assertEquals("required must be a short array", v("""{"props":{},"required":"a"}"""))
        assertEquals("required names an undeclared property", v("""{"props":{},"required":["a"]}"""))
        assertEquals("a: bad minItems", v("""{"props":{"a":{"type":"array","items":{"type":"string"},"minItems":-1}}}"""))
        assertEquals("a: bad maxItems", v("""{"props":{"a":{"type":"array","items":{"type":"string"},"maxItems":4097}}}"""))
        assertEquals("a: minItems > maxItems", v("""{"props":{"a":{"type":"array","items":{"type":"string"},"minItems":3,"maxItems":2}}}"""))
        assertEquals("a: bad const", v("""{"props":{"a":{"type":"integer","const":1.5}}}"""))
        assertEquals("a: bad enum", v("""{"props":{"a":{"type":"string","enum":[]}}}"""))
        assertEquals("a: bad enum", v("""{"props":{"a":{"type":"boolean","enum":[1]}}}"""))
        assertEquals("a: bad minLength", v("""{"props":{"a":{"type":"string","minLength":1.5}}}"""))
        assertEquals("a: bad maxLength", v("""{"props":{"a":{"type":"string","maxLength":1048577}}}"""))
        assertEquals("a: minLength > maxLength", v("""{"props":{"a":{"type":"string","minLength":3,"maxLength":2}}}"""))
        assertEquals("a: bad prefix", v("""{"props":{"a":{"type":"string","prefix":1}}}"""))
        assertEquals("a: bad min", v("""{"props":{"a":{"type":"number","min":"0"}}}"""))
        assertEquals("a: bad max", v("""{"props":{"a":{"type":"number","max":true}}}"""))
        assertEquals("a: min > max", v("""{"props":{"a":{"type":"number","min":2,"max":1}}}"""))
        // depth 8: an object nested 7 times is the deepest allowed
        fun nest(k: Int): String = if (k == 0) """{"type":"string"}""" else """{"type":"object","props":{"x":${nest(k - 1)}}}"""
        assertNull(v("""{"props":{"x":${nest(6)}}}"""))
        assertTrue(v("""{"props":{"x":${nest(7)}}}""")!!.endsWith("schema too deep"))
        // 64 props max, 256 nodes max
        val p64 = (0 until 64).joinToString(",") { "\"p$it\":{\"type\":\"string\"}" }
        assertNull(v("""{"props":{$p64}}"""))
        assertEquals("too many props", v("""{"props":{$p64,"p64":{"type":"string"}}}"""))
        val wide = (0 until 60).joinToString(",") { o -> "\"o$o\":{\"type\":\"object\",\"props\":{" + (0 until 4).joinToString(",") { "\"q$it\":{\"type\":\"string\"}" } + "}}" }
        assertEquals("schema too large", v("""{"props":{$wide}}""")?.substringAfterLast(": "))
    }
}
