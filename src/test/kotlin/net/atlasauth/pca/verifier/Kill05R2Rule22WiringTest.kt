package net.atlasauth.pca.verifier

import java.io.File
import java.security.MessageDigest
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rule 22 and the grant action pin in the v2 decision, against the reference intent-v2.ts:83-87, :321-325, :614-634 and the
 * shared rule 22 vectors (expected values from packages/pca-conformance/vectors/actions, signed here because the vector docs are
 * unsigned).
 */
class Kill05R2Rule22WiringTest {
    private fun seed(label: String) = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray())
    private fun pub(label: String): String { val pk = ByteArray(32); Ed25519.generatePublicKey(seed(label), 0, pk, 0); return Pca.b64(pk) }
    private fun sign(label: String, msg: ByteArray): String { val s = ByteArray(64); Ed25519.sign(seed(label), 0, msg, 0, msg.size, s, 0); return Pca.b64(s) }

    private val root = "Q".repeat(43)
    private val packPin = linkedMapOf<String, Any?>("ns" to "stripe", "root" to root)
    private val params = mapOf(
        "stripe.refund" to ParityVectors.obj("""{"amount":100,"charge":"ch_1","idempotency_key":"k1"}"""),
        "gmail.send" to ParityVectors.obj("""{"to":"a@b.example","subject":"s","body":"b","idempotency_key":"k1"}"""),
    )
    private val escalates = "escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)"
    private val exceeds = "the action floors exceed what the grant authorizes (rule 22)"
    private val allCaveats = listOf("amount_cap", "count_cap", "window")
    private val allContext = listOf("fresh_revocation", "idempotency")

    private fun vector(name: String) = ParityVectors.obj(File(ParityVectors.actionsDir(), "$name.json").readText())
    @Suppress("UNCHECKED_CAST") private fun input(v: Map<String, Any?>) = v["input"] as Map<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun vectorDoc(name: String) = input(vector(name))["doc"] as Map<String, Any?>

    private fun signed(doc: Map<String, Any?>, pack: Boolean = true): Map<String, Any?> {
        val u = LinkedHashMap(doc)
        u.remove("sig")
        if (pack) u["pack"] = linkedMapOf("ns" to "stripe", "version" to "1", "root" to root)
        val value = sign("site", IntentJs.message(ActionSchema.ACTION_SCHEMA_DOMAIN, IntentJs.obj(IntentJs.normalize(u))))
        u["sig"] = linkedMapOf("alg" to "ed25519", "kid" to "site-1", "value" to value)
        return u
    }

    private fun ctx(doc: Map<String, Any?>?, verb: String, closed: Boolean = true, reviewers: Any? = null, context: List<String>? = null, actions: Any? = null): IntentV2.Context {
        val c = LinkedHashMap<String, Any?>()
        if (closed) c["policy"] = linkedMapOf("schema" to linkedMapOf("closed_world" to true))
        if (doc != null) c["schema"] = linkedMapOf("docs" to listOf(doc), "keys" to listOf(linkedMapOf("kid" to "site-1", "alg" to "ed25519", "pk" to pub("site"))))
        c["params"] = params[verb] ?: ParityVectors.obj("""{"pax":1,"from":"SFO","date":"2026-01-01"}""")
        if (reviewers != null) c["reviewers"] = reviewers
        if (context != null) c["call_context"] = context
        if (actions != null) c["actions"] = actions
        return IntentV2.Context.fromJson(c)
    }

    private fun action(verb: String) = linkedMapOf<String, Any?>(
        "aud" to "pay",
        "action" to linkedMapOf(
            "verb" to verb, "resource" to "r",
            "params_digest" to Pca.paramsDigest(IntentJs.normalize(params[verb] ?: ParityVectors.obj("""{"pax":1,"from":"SFO","date":"2026-01-01"}"""))),
        ),
    )

    private val issuerKey = "issuer"
    private fun grant(vararg members: Pair<String, Any?>): Map<String, Any?> {
        val env = LinkedHashMap(
            ParityVectors.obj(
                """{"type":"envelope","goal_commit":"g","caveats":[],"agent_binding":{},
                "risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0},
                "predicates":[{"verb":"*"}]}""",
            ),
        )
        env.putAll(members)
        return IntentJs.obj(IntentJs.normalize(linkedMapOf("id" to "grant-1", "issuer" to pub(issuerKey), "caveats" to listOf(env))))
    }

    private fun pin(vararg extra: Pair<String, Any?>) = linkedMapOf<String, Any?>("pack" to packPin, "on_new_action" to "deny").also { it.putAll(extra) }

    private fun check(d: IntentV2.Decision, name: String) = d.checks.first { it.name == name }
    private fun names(d: IntentV2.Decision) = d.checks.map { it.name }

    // ---- the shared vectors, end to end ----

    @Test
    fun everyRule22VectorThroughTheDecision() {
        var run = 0
        for (f in ParityVectors.actionsDir().listFiles()!!.sortedBy { it.name }) {
            if (!f.name.startsWith("rule22-")) continue
            val v = ParityVectors.obj(f.readText())
            if (v["kind"] != "rule22") continue
            val i = input(v)
            val verb = i["verb"] as String
            if (verb !in params) continue
            val g = i["grant"] as Map<*, *>
            val thePin = pin("max_esc" to g["max_esc"], "preauth_esc" to g["preauth_esc"], "caveats" to g["caveats"])
            if (ActionsRegistry.actionPinError(thePin) != null) continue
            run++
            @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
            val d = IntentV2.decide(action(verb), grant("actions" to thePin), ctx(doc, verb, reviewers = i["pins"], context = (i["context"] as List<*>).map { it as String }), 0L)
            val want = v["expect"] as Map<*, *>
            val id = v["id"].toString()
            if (want["integrity"] != "ok") {
                assertEquals(id, listOf("schema", "pin"), names(d))
                val why = check(d, "schema").reason!!
                assertTrue("$id: $why", why.startsWith("schema_floor_forged: ") && why.contains(want["integrity"] as String))
                assertEquals(id, why, check(d, "pin").reason)
                continue
            }
            assertEquals(id, listOf("schema", "pin", "traits"), names(d))
            assertTrue(id, check(d, "schema").ok && check(d, "pin").ok)
            when (want["decision"]) {
                "allow" -> assertTrue(id, check(d, "traits").ok)
                "escalate" -> assertEquals(id, escalates, check(d, "traits").reason)
                else -> assertEquals(id, exceeds, check(d, "traits").reason)
            }
        }
        assertTrue("only $run vectors ran", run >= 15)
    }

    @Test
    fun aForgedFloorIsNamedAndNoPinIsNeeded() {
        val doc = signed(vectorDoc("rule22-forged-floors-denied"))
        val reviewers = input(vector("rule22-forged-floors-denied"))["pins"]
        val d = IntentV2.decide(action("stripe.refund"), grant(), ctx(doc, "stripe.refund", reviewers = reviewers), 0L)
        assertEquals(listOf("schema"), names(d))
        assertTrue(check(d, "schema").reason!!.startsWith("schema_floor_forged: "))
    }

    @Test
    fun theIntegrityCheckFollowsTheAudCheckAndPrecedesTheParams() {
        val doc = signed(vectorDoc("rule22-forged-floors-denied"))
        val other = action("stripe.refund").also { it["aud"] = "other" }
        assertEquals("schema aud does not match the PCActn aud", IntentV2.decide(other, grant(), ctx(doc, "stripe.refund"), 0L).checks[0].reason)
        val badParams = action("stripe.refund").also { it["action"] = linkedMapOf("verb" to "stripe.refund", "resource" to "r", "params_digest" to "x") }
        assertTrue(IntentV2.decide(badParams, grant(), ctx(doc, "stripe.refund"), 0L).checks[0].reason!!.startsWith("schema_floor_forged: "))
    }

    // ---- what the trait decision reads ----

    private val honest = "rule22-allow"
    private fun traits(verb: String, g: Map<String, Any?>, context: List<String>?, docName: String = honest): IntentV2.Check {
        val i = input(vector(docName))
        @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
        return check(IntentV2.decide(action(verb), g, ctx(doc, verb, reviewers = i["pins"], context = context), 0L), "traits")
    }

    private fun types(vararg t: Any?) = t.map { linkedMapOf("type" to it) }

    @Test
    fun envelopeAndPinCaveatsBothCount() {
        val full = pin("preauth_esc" to 2L, "caveats" to listOf("window"))
        assertTrue(traits("stripe.refund", grant("actions" to full, "caveats" to types("amount_cap", "count_cap")), allContext).ok)
        // each source alone falls short; a member that is no caveat object counts for nothing
        assertEquals(escalates, traits("stripe.refund", grant("actions" to pin("preauth_esc" to 2L), "caveats" to types("amount_cap", "count_cap")), allContext).reason)
        assertEquals(escalates, traits("stripe.refund", grant("actions" to full, "caveats" to types("amount_cap")), allContext).reason)
        assertEquals(escalates, traits("stripe.refund", grant("actions" to pin("preauth_esc" to 2L, "caveats" to allCaveats), "caveats" to listOf(5L)), emptyList()).reason)
        assertTrue(traits("stripe.refund", grant("actions" to pin("preauth_esc" to 2L, "caveats" to allCaveats), "caveats" to listOf(5L)), allContext).ok)
    }

    @Test
    fun thePinTiersAndTheirDefaults() {
        // esc 2 over max_esc 1: denied; over preauth 1: a step-up
        assertEquals(exceeds, traits("stripe.refund", grant("actions" to pin("max_esc" to 1L, "caveats" to allCaveats)), allContext).reason)
        assertEquals(escalates, traits("stripe.refund", grant("actions" to pin("preauth_esc" to 1L, "caveats" to allCaveats)), allContext).reason)
        // preauth_esc defaults to 0 (gmail.send is esc 1), max_esc to 3 (the top tier stays a step-up, not a denial)
        val gmail = listOf("rate_cap", "recipient_scope", "resource_scope")
        assertEquals(escalates, traits("gmail.send", grant("actions" to pin("caveats" to gmail)), listOf("fresh_revocation")).reason)
        assertTrue(traits("gmail.send", grant("actions" to pin("preauth_esc" to 1L, "caveats" to gmail)), listOf("fresh_revocation")).ok)
        val top = input(vector("rule22-unconf-with-top-grant-allows"))
        @Suppress("UNCHECKED_CAST") val topCaveats = (top["grant"] as Map<String, Any?>)["caveats"] as List<*>
        @Suppress("UNCHECKED_CAST") val topContext = (top["context"] as List<*>).map { it as String }
        assertEquals(escalates, traits("stripe.refund", grant("actions" to pin("caveats" to topCaveats)), topContext, "rule22-unconf-with-top-grant-allows").reason)
        assertEquals(escalates, traits("stripe.refund", grant(), topContext, "rule22-unconf-with-top-grant-allows").reason)
        // no call_context: nothing is presented
        assertEquals(escalates, traits("gmail.send", grant("actions" to pin("preauth_esc" to 1L, "caveats" to gmail)), null).reason)
    }

    @Test
    fun aMalformedPinFailsThePinCheckAndItsTiersAndCaveatsAreNotRead() {
        val bad = pin("max_esc" to 1L, "preauth_esc" to 2L, "caveats" to allCaveats) // preauth above max
        val i = input(vector(honest))
        @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
        val d = IntentV2.decide(action("stripe.refund"), grant("actions" to bad), ctx(doc, "stripe.refund", reviewers = i["pins"], context = allContext), 0L)
        assertEquals("bad_pin: actions.preauth_esc exceeds actions.max_esc", check(d, "pin").reason)
        assertEquals(escalates, check(d, "traits").reason) // esc 2 under the default tiers, no caveats
    }

    @Test
    fun aNoGrantContextStillDecidesFloors() {
        val i = input(vector(honest))
        @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
        val d = IntentV2.decide(action("stripe.refund"), null, ctx(doc, "stripe.refund", reviewers = i["pins"]), 0L)
        assertEquals(listOf("schema", "traits"), names(d))
        assertEquals(escalates, check(d, "traits").reason)
    }

    // ---- the pin decision ----

    private fun pinCheck(p: Map<String, Any?>, actions: Any? = null, closed: Boolean = true): IntentV2.Decision {
        val i = input(vector(honest))
        @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
        return IntentV2.decide(action("stripe.refund"), grant("actions" to p), ctx(doc, "stripe.refund", closed = closed, reviewers = i["pins"], actions = actions), 0L)
    }

    @Test
    fun aVerbTheGrantDoesNotNameFollowsOnNewAction() {
        val defs = linkedMapOf("gmail.send" to "Xo7ApENRzJyi5iakmamfXyLK2S7-jBcDWk2dwARzONE")
        assertEquals("new_action: the grant does not name 'stripe.refund' (on_new_action: deny)", check(pinCheck(pin("defs" to defs)), "pin").reason)
        assertEquals(
            "escalate: new_action: the grant does not name 'stripe.refund' (on_new_action: escalate)",
            check(pinCheck(pin("defs" to defs, "on_new_action" to "escalate")), "pin").reason,
        )
    }

    @Test
    fun anotherPackIsRefusedAndThePinRunsWithoutTheClosedWorldStep() {
        assertEquals(
            "pack_mismatch: the schema does not come from the pinned pack 'other'",
            check(pinCheck(pin("pack" to linkedMapOf("ns" to "other", "root" to root))), "pin").reason,
        )
        assertEquals(
            "pack_mismatch: the pack root differs from the pinned root (the grant pins the pack as a whole)",
            check(pinCheck(pin("pack" to linkedMapOf("ns" to "stripe", "root" to "A".repeat(43)))), "pin").reason,
        )
        val open = pinCheck(pin(), closed = false)
        assertEquals(listOf("pin", "traits"), names(open))
        assertTrue(check(open, "pin").ok)
    }

    @Test
    fun aWidenedDefNeedsItsReapproval() {
        val from = "A".repeat(43) // not the vector's digest: an equal pin is an exact match, with no chain to approve
        val to = vectorDoc(honest)["verbs"].let { vs -> (vs as List<*>).map { it as Map<*, *> }.first { it["verb"] == "stripe.refund" }["def"] as String }
        val body = linkedMapOf<String, Any?>("v" to 1L, "kind" to "pca-evolution-record", "ns" to "stripe", "verb" to "stripe.refund", "from" to from, "to" to to, "class" to "widen", "reasons" to emptyList<Any?>())
        val record = LinkedHashMap(body).also { it["sig"] = linkedMapOf("alg" to "ed25519", "kid" to "reg-1", "value" to sign("registry", IntentJs.message("atlas-pca/action-evolution/v1\u0000", body))) }
        val keys = listOf(linkedMapOf("kid" to "reg-1", "alg" to "ed25519", "pk" to pub("registry")))
        val thePin = pin("defs" to linkedMapOf("stripe.refund" to from))
        val diff = ActionsRegistry.evolutionDiffDigest(IntentJs.obj(IntentJs.normalize(record)))
        val direct = ActionsRegistry.decidePin(
            IntentJs.obj(IntentJs.normalize(linkedMapOf("pin" to thePin, "doc" to linkedMapOf("pack" to packPin, "verbs" to listOf(linkedMapOf("verb" to "stripe.refund", "def" to to))), "verb" to "stripe.refund", "records" to listOf(record), "keys" to keys, "grant" to linkedMapOf("id" to "grant-1", "issuer" to pub(issuerKey))))),
        )
        assertEquals(diff, direct["needs_reapproval"])
        val blocked = check(pinCheck(thePin, linkedMapOf("records" to listOf(record), "keys" to keys)), "pin")
        assertEquals("def_changed: ${direct["reason"]} (re-approve diff $diff)", blocked.reason)

        // no record: no diff to re-approve, so no suffix
        assertFalse(check(pinCheck(thePin), "pin").reason!!.contains("re-approve"))

        fun reapproval(grantId: String, signer: String): Map<String, Any?> {
            val r = linkedMapOf<String, Any?>("v" to 1L, "kind" to "pca-reapproval", "grant" to grantId, "verb" to "stripe.refund", "diff" to diff)
            return LinkedHashMap(r).also { it["sig"] = linkedMapOf("alg" to "ed25519", "value" to sign(signer, IntentJs.message("atlas-pca/action-reapproval/v1\u0000", r))) }
        }
        assertTrue(check(pinCheck(thePin, linkedMapOf("records" to listOf(record), "keys" to keys, "reapprovals" to listOf(reapproval("grant-1", issuerKey)))), "pin").ok)
        // the grant id and the issuer key both come from the grant
        assertFalse(check(pinCheck(thePin, linkedMapOf("records" to listOf(record), "keys" to keys, "reapprovals" to listOf(reapproval("grant-2", issuerKey)))), "pin").ok)
        assertFalse(check(pinCheck(thePin, linkedMapOf("records" to listOf(record), "keys" to keys, "reapprovals" to listOf(reapproval("grant-1", "stranger")))), "pin").ok)
    }

    // ---- the context ----

    private fun contextReason(json: String) = IntentV2.decide(action("stripe.refund"), grant(), IntentV2.Context.fromJsonText(json), 0L).checks.firstOrNull()?.reason

    @Test
    fun malformedContextMembers() {
        val m = "malformed v2 context: "
        for (t in listOf("""[]""", """{}""", """"k"""", """null""", """{"keys":{}}""")) assertEquals(t, m + "reviewers must be {keys: [...]}", contextReason("""{"reviewers":$t}"""))
        for (t in listOf(""""fresh_revocation"""", """[1]""", """["a",null]""", """null""", """{}""")) assertEquals(t, m + "call_context must be an array of strings", contextReason("""{"call_context":$t}"""))
        for (t in listOf("""[]""", """null""", """"x"""")) assertEquals(t, m + "actions must be an object", contextReason("""{"actions":$t}"""))
        for (k in listOf("records", "keys", "reapprovals")) assertEquals(m + "actions.$k must be an array", contextReason("""{"actions":{"$k":"x"}}"""))
        assertEquals(null, contextReason("""{"reviewers":{"keys":[]},"call_context":["a"],"actions":{"records":[],"keys":[],"reapprovals":[]}}"""))
        assertEquals(null, contextReason("""{"call_context":[],"actions":{}}"""))
    }

    // ---- v1 schemas ----

    private val v1 = ParityVectors.obj(
        """{"v":1,"kind":"pca-action-schema","site":"https://pay.example","aud":"pay","version":"1","verbs":[{"verb":"air.search","kind":"read","params":{
        "action.params.from":{"type":"string","values":["SFO","JFK"],"semantic":"place.airport","sensitivity":"material"},
        "action.params.date":{"type":"date","semantic":"schedule.date","sensitivity":"material"},
        "action.params.pax":{"type":"integer","min":1,"max":9,"semantic":"quantity","sensitivity":"material"}},"reversibility":"reversible"}]}""",
    )

    @Test
    fun aV1SchemaHasNoTraitsCheck() {
        val doc = signed(v1, pack = false)
        assertEquals(listOf("schema"), names(IntentV2.decide(action("air.search"), grant(), ctx(doc, "air.search"), 0L)))
        val d = IntentV2.decide(action("air.search"), grant("actions" to pin()), ctx(doc, "air.search"), 0L)
        assertEquals(listOf("schema", "pin"), names(d))
        assertEquals("pack_mismatch: the schema does not come from the pinned pack 'stripe'", check(d, "pin").reason)
    }

    // ---- order and the thrown step ----

    @Test
    fun checksRunPinTraitsUnitsTighten() {
        val i = input(vector(honest))
        @Suppress("UNCHECKED_CAST") val doc = signed(i["doc"] as Map<String, Any?>)
        val d = IntentV2.decide(action("stripe.refund"), grant("actions" to pin(), "units" to emptyList<Any?>(), "tighten" to emptyList<Any?>()), ctx(doc, "stripe.refund", reviewers = i["pins"]), 0L)
        assertEquals(listOf("schema", "pin", "traits", "units", "tighten"), names(d))
    }

    @Test
    fun noSchemaConfiguredFailsThePinAndTheStepIsOneResult() {
        val d = IntentV2.decide(action("stripe.refund"), grant("actions" to pin()), ctx(null, "stripe.refund", closed = false), 0L)
        assertEquals(listOf("pin"), names(d))
        assertEquals("this verifier has no action schema configured", check(d, "pin").reason)
    }

    @Test
    fun aSchemaStepThatThrowsFailsThePinAndAddsNoTraits() {
        var deep: Any? = 1L
        repeat(1000) { deep = linkedMapOf("a" to deep) }
        val c = IntentV2.Context.fromJson(
            linkedMapOf(
                "schema" to linkedMapOf("docs" to listOf(signed(vectorDoc(honest))), "keys" to listOf(linkedMapOf("kid" to "site-1", "alg" to "ed25519", "pk" to pub("site")))),
                "params" to deep,
                "reviewers" to input(vector(honest))["pins"],
            ),
        )
        val d = IntentV2.decide(action("stripe.refund"), grant("actions" to pin()), c, 0L)
        assertEquals(listOf("pin"), names(d))
        assertNotNull(check(d, "pin").reason)
        assertTrue(check(d, "pin").reason!!, check(d, "pin").reason!!.startsWith("pin error (fail closed): "))
    }

    @Test
    fun orFalseIsTotal() {
        assertTrue(IntentV2.orFalse { true })
        assertFalse(IntentV2.orFalse { throw IllegalStateException() })
        assertFalse(IntentV2.orFalse { throw StackOverflowError() })
    }
}
