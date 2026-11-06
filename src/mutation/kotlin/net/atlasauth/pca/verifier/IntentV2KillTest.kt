package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets
import net.atlasauth.pca.verifier.IntentTestKit.b64seed
import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.mm
import net.atlasauth.pca.verifier.IntentTestKit.norm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Intent Layer v2 W-A mutation kills: the `intent_session` wire (rule 13), the session root, delta chain and revocation
 * (rule 13), the closed-world schema check (rule 14), accumulators / monitors / receipts / sequencer key sets (rule 15), the
 * `layers` slot, the committed map (rule 19) and the pipeline's reporting and order, signed end to end (the scenario mirrors
 * packages/pca/scripts/gen-conformance-intent-v2.mjs).
 */
class IntentV2KillTest {
    companion object {
        const val NOW = 1_800_000_000_000L
        const val AUD = "skyair.example"
        const val PRINCIPAL = "v2/principal"
        const val AGENT = "v2/agent"
        const val SITE = "v2/site"
        const val SEQ_ROOT = "v2/sequencer-root"
        const val SEQ_KEY = "v2/sequencer"
        const val STRANGER = "v2/stranger"
        const val REV = "v2/revocation-authority"
        val REF = b64seed("v2/ref")
        val MAP0 = b64seed("v2/map0")
        val MAP1 = b64seed("v2/map1")
        val SESSION = b64seed("v2/session")

        fun unsignedSchema(): LinkedHashMap<String, Any?> {
            val book = jm("verb", "air.book", "kind", "write", "params", jm(
                "action.params.offer_id", jm("type", "string", "semantic", "product.ref", "sensitivity", "material"),
                "action.params.total", jm("type", "integer", "unit", "usd_cents", "min", 0L, "max", 5_000_000L, "semantic", "money.amount", "sensitivity", "critical",
                    "accumulates_into", jl("spend.usd_cents")),
                "action.params.add_ons", jm("type", "set", "values", jl("none", "tripshield", "seat_plus"), "default", jl("none"), "principal_neutral_default", true,
                    "semantic", "product.addon", "sensitivity", "material"),
                "action.params.refundable", jm("type", "boolean", "semantic", "flag", "sensitivity", "material"),
                "action.params.passengers", jm("type", "array", "max_items", 9L, "max_len", 64L, "semantic", "person.identity", "sensitivity", "critical", "required", false),
                "action.params.note", jm("type", "string", "semantic", "text.note", "sensitivity", "free", "required", false, "max_len", 16L)),
                "reversibility_by", jm("param", "action.params.refundable", "map", jm("true", "reversible", "false", "irreversible")))
            val search = jm("verb", "air.search", "kind", "read", "params", jm(
                "action.params.from", jm("type", "string", "values", jl("SFO", "JFK"), "semantic", "place.airport", "sensitivity", "material"),
                "action.params.date", jm("type", "date", "semantic", "schedule.date", "sensitivity", "material"),
                "action.params.pax", jm("type", "integer", "min", 1L, "max", 9L, "semantic", "quantity", "sensitivity", "material")),
                "reversibility", "reversible")
            return jm("v", 1L, "kind", "pca-action-schema", "site", "https://skyair.example", "aud", AUD, "version", "2026-10-01",
                "units", jm("usd_cents", jm("kind", "money", "currency", "USD", "exponent", 2L)), "verbs", jl(book, search))
        }
        fun signSchema(unsigned: Map<String, Any?>, kid: String, key: String): LinkedHashMap<String, Any?> {
            val sig = sign(key, IntentJs.message(ActionSchema.ACTION_SCHEMA_DOMAIN, unsigned))
            return LinkedHashMap(unsigned).also { it["sig"] = jm("alg", "ed25519", "kid", kid, "value", sig) }
        }
        val SCHEMA = signSchema(unsignedSchema(), "skyair-2026", SITE)
        val KEYS = jl(jm("kid", "skyair-2026", "alg", "ed25519", "pk", pub(SITE)))
        val SD = ActionSchema.digest(SCHEMA)

        fun trip() = jm("id", "trip_spend", "agg", "sum", "unit", "usd_cents", "sel", jm("accumulates_into", "spend.usd_cents"), "win", jm("kind", "task"), "key", null,
            "domain_max", 500_000L, "holder", jm("kind", "site_local"))
        fun questions() = jm("id", "questions", "agg", "count", "sel", jm("event", "intent_required"), "win", jm("kind", "task"), "key", null, "cap", 6L, "holder", jm("kind", "wallet"))
        fun rootBody() = jm("v", 1L, "kind", "pca-intent-session", "session", SESSION, "principals", jl(jm("key", pub(PRINCIPAL))), "intent_ref", REF,
            "schema", jm("aud", AUD, "digest", SD), "layers", jm("task", jm("map_digest", MAP0)), "accumulators", jl(trip(), questions()), "monitors", jl(),
            "question_uri", "https://atlas.example/q", "expires_at", NOW + 86_400_000L)
        fun signRoot(body: Map<String, Any?>, key: String): LinkedHashMap<String, Any?> {
            val s = LinkedHashMap(body)
            s["signer"] = pub(key)
            s["sig"] = sign(key, IntentJs.message(IntentSession.INTENT_SESSION_SIG_DOMAIN, s))
            return s
        }
        val S = signRoot(rootBody(), PRINCIPAL)
        val R = IntentSession.rootDigest(S)

        fun mint(seq: Long, prev: String?, mapDigest: String, salt: String, signer: String, root: String, mapForm: String? = null): LinkedHashMap<String, Any?> {
            val goal = if (mapForm == "commit") Pca.intentGoalCommitV2c(SESSION, mapDigest, salt) else Pca.intentGoalCommitV2(SESSION, mapDigest, salt)
            val env = jm("type", "envelope", "goal_commit", goal, "predicates", jl(jm("verb", "air.book")), "caveats", jl(), "agent_binding", jm())
            val sc = jm("type", "intent_session", "session", SESSION, "seq", seq, "root", root)
            if (prev != null) sc["prev"] = prev
            val body = jm("issuer", pub(signer), "holder", pub(AGENT), "caveats", jl(env, sc), "parent", null)
            val digest = Pca.hashCanonical(body)
            val msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!)
            return jm("id", digest, "issuer", pub(signer), "holder", pub(AGENT), "caveats", body["caveats"], "body_digest", digest, "sig", sign(signer, msg))
        }
        val G0 = mint(0, null, MAP0, "salt0", PRINCIPAL, R)
        val D1 = mint(1, G0["id"] as String, MAP1, "salt1", PRINCIPAL, R)

        fun params() = jm("offer_id", "OF-1", "total", 38_900L, "add_ons", jl("none"), "refundable", false)

        fun build(grant: Map<String, Any?>, salt: String, mapDigest: String, isn: Map<String, Any?>?, params: Map<String, Any?>, ref: String): LinkedHashMap<String, Any?> {
            val action = jm("verb", "air.book", "resource", "skyair.example/bookings", "params_digest", Pca.paramsDigest(params), "reversibility_class", "irreversible")
            val cond: String = KUtil.priv(Pca, "conditionsDigest", null, null)
            val leaf: Any? = KUtil.priv(Pca, "planLeaf", "book", action, cond)
            val p = jm("ver", 2L, "action", action, "grant_ref", grant["id"], "cap_chain", jl(grant),
                "plan", jm("root", Pca.merkleRoot(jl(leaf)), "inclusion_proof", jm("index", 0L, "size", 1L, "path", jl()), "node_id", "book"),
                "attestation", jm("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested"),
                "provenance", jm("causal_hash", "", "taint_level", 0L, "trusted_refs", jl()),
                "freshness", jm("beacon_ref", "", "epoch", 0L, "accumulator_witness", ""), "counter", 1L, "risk_claim", jm("r", 0L, "inputs", jm()),
                "aud", AUD, "iat", NOW, "exp", NOW + 600_000L,
                "intent", jm("ref", ref, "map_digest", mapDigest, "goal_salt", salt, "fidelity_ppm", 1_000_000L, "residual_risk_ppm", 0L))
            if (isn != null) p["intent_session"] = isn
            return resign(p)
        }
        fun resign(p: LinkedHashMap<String, Any?>): LinkedHashMap<String, Any?> {
            p.remove("sig")
            p["sig"] = sign(AGENT, Pca.thresholdMessage(p))
            return p
        }
        fun is0(vararg over: Any?): LinkedHashMap<String, Any?> =
            jm("session", SESSION, "root", R, "seq", 0L, "schema", SD, "acc", jl(jm("id", "trip_spend", "post", 38_900L))).also { it.putAll(jm(*over)) }
        fun ctx(vararg over: Any?): LinkedHashMap<String, Any?> = jm("params", params(), "schema", jm("docs", jl(SCHEMA), "keys", KEYS), "session", jm("root", S, "grants", jl()),
            "acc", jm("state", jm("trip_spend", jm("sum", 0L)), "monitors", jm())).also { it.putAll(jm(*over)) }
        fun verify(grant: Map<String, Any?>, p: Map<String, Any?>, ctx: Any?): Pca.Verdict =
            Pca.verifyPcactn(p, grant, NOW, Pca.Audience.Of(AUD), null, null, IntentV2.Context.fromJson(ctx))
        val CORE = listOf("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "intent")
        fun keys(vararg extra: String): List<String> = CORE + extra
        fun failed(v: Pca.Verdict): List<String> = v.checks.filter { !it.value }.keys.toList()
    }

    // ------------------------------------------------------------------ pipeline
    @Test fun acceptsG0AndD1() {
        val v = verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx())
        assertTrue(v.reason, v.allow)
        assertEquals(keys("schema", "intent_session", "accumulators"), v.checks.keys.toList())
        val p1 = build(D1, "salt1", MAP1, is0("seq", 1L, "acc", jl(jm("id", "trip_spend", "post", 77_800L))), params(), REF)
        val d1 = verify(D1, p1, ctx("session", jm("root", S, "grants", jl(G0)), "acc", jm("state", jm("trip_spend", jm("sum", 38_900L)), "monitors", jm())))
        assertTrue(d1.reason, d1.allow)
        assertEquals(listOf("intent_session"), failed(verify(D1, p1, ctx("acc", jm("state", jm("trip_spend", jm("sum", 38_900L)), "monitors", jm())))))
    }

    @Test fun backCompatAndPolicies() {
        val plain = build(G0, "salt0", MAP0, null, params(), REF)
        val v = verify(G0, plain, ctx())
        assertEquals(CORE, v.checks.keys.toList())
        assertEquals(listOf("intent"), failed(v))
        assertEquals(CORE, Pca.verifyPcactn(plain, G0, NOW, Pca.Audience.Of(AUD), null, null, null).checks.keys.toList())
        val req = verify(G0, plain, ctx("policy", jm("session", jm("require", true))))
        assertEquals(keys("intent_session"), req.checks.keys.toList())
        assertEquals(listOf("intent", "intent_session"), failed(req))
        assertEquals(CORE, verify(G0, plain, ctx("policy", jm("session", jm("require", false)))).checks.keys.toList())
        for (notBool in listOf<Any?>("true", 1L, null)) {
            val m = verify(G0, plain, ctx("policy", jm("session", jm("require", notBool))))
            assertEquals(notBool.toString(), keys("schema", "intent_session"), m.checks.keys.toList())
            assertEquals(notBool.toString(), listOf("intent", "schema", "intent_session"), failed(m))
        }
        assertEquals(listOf("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", jm("extra", true)))))
        assertEquals(listOf("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", jm("session", jm("reqiure", true))))))
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("params", null))))
        assertEquals(listOf("intent", "schema", "intent_session"), failed(Pca.verifyPcactn(plain, G0, NOW, Pca.Audience.Of(AUD), null, null, IntentV2.Context.fromJson(null))))
        val cw = verify(G0, plain, ctx("policy", jm("schema", jm("closed_world", true))))
        assertEquals(keys("schema"), cw.checks.keys.toList())
        assertEquals(listOf("intent"), failed(cw))
        assertEquals(listOf("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", jm("schema", jm("closed_world", "true"))))))
    }

    @Test fun rule12V2Goal() {
        assertEquals(true, verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx()).checks["intent"])
        assertEquals(false, verify(G0, build(G0, "salt0", MAP0, is0("session", b64seed("v2/other-session")), params(), REF), ctx()).checks["intent"])
        assertNotEquals(Pca.intentGoalCommitV2(SESSION, MAP0, "s"), Pca.intentGoalCommit(SESSION, MAP0, "s"))
        assertNotEquals(Pca.intentGoalCommitV2(SESSION, MAP0, "s"), Pca.intentGoalCommitV2c(SESSION, MAP0, "s"))
        assertEquals("pca-intent:v2:$SESSION:$MAP0", IntentSession.intentGoalV2(SESSION, MAP0))
        assertEquals("pca-intent:v2c:$SESSION:$MAP0", IntentSession.intentGoalV2c(SESSION, MAP0))
    }

    @Test fun checksOneToFourAreIndependent() {
        val v = verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("session", jm("grants", jl())))
        assertEquals(listOf("intent_session", "accumulators"), failed(v))
        assertEquals(true, v.checks["schema"])
        val bad = params().also { it["total"] = 1L }
        assertEquals(listOf("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("params", bad))))
        val p = build(G0, "salt0", MAP0, is0(), params(), REF)
        p["intent_session"] = is0("acc", jl(jm("id", "trip_spend", "post", 1L)))
        assertEquals(listOf("leaf_signature", "accumulators"), failed(verify(G0, p, ctx())))
    }

    // ------------------------------------------------------------------ rule 13
    @Test fun rule13Failures() {
        val forged = mint(1, G0["id"] as String, MAP1, "salt1", AGENT, R)
        val d1ctx = ctx("session", jm("root", S, "grants", jl(G0)), "acc", jm("state", jm("trip_spend", jm("sum", 38_900L)), "monitors", jm()))
        val is1 = is0("seq", 1L, "acc", jl(jm("id", "trip_spend", "post", 77_800L)))
        assertEquals(listOf("intent_session"), failed(verify(forged, build(forged, "salt1", MAP1, is1, params(), REF), d1ctx)))
        val loose = mint(1, b64seed("v2/nope"), MAP1, "salt1", PRINCIPAL, R)
        assertEquals(listOf("intent_session"), failed(verify(loose, build(loose, "salt1", MAP1, is1, params(), REF), d1ctx)))
        assertEquals(listOf("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0("seq", 1L), params(), REF), ctx("session", jm("root", S, "grants", jl(G0))))))
        assertEquals(listOf("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), b64seed("v2/x")), ctx())))
        val eS = signRoot(rootBody().also { it["expires_at"] = NOW }, PRINCIPAL)
        val eR = IntentSession.rootDigest(eS)
        val ge = mint(0, null, MAP0, "salt0", PRINCIPAL, eR)
        assertEquals(listOf("intent_session", "accumulators"), failed(verify(ge, build(ge, "salt0", MAP0, is0("root", eR), params(), REF), ctx("session", jm("root", eS, "grants", jl())))))
        val lS = signRoot(rootBody().also { it["expires_at"] = NOW + 1 }, PRINCIPAL)
        val lR = IntentSession.rootDigest(lS)
        val gl = mint(0, null, MAP0, "salt0", PRINCIPAL, lR)
        assertTrue(verify(gl, build(gl, "salt0", MAP0, is0("root", lR), params(), REF), ctx("session", jm("root", lS, "grants", jl()))).allow)
        val gm = mint(0, null, MAP1, "salt0", PRINCIPAL, R)
        assertEquals(listOf("intent_session"), failed(verify(gm, build(gm, "salt0", MAP1, is0(), params(), REF), ctx())))
        val wrong = LinkedHashMap(S).also { it["sig"] = sign(STRANGER, IntentJs.message(IntentSession.INTENT_SESSION_SIG_DOMAIN, rootBody())) }
        assertNotNull(IntentSession.verifyRoot(wrong))
        assertNull(IntentSession.verifyRoot(S))
    }

    @Test fun sessionWireBoundaries() {
        val seqReason = "'intent_session.seq' must be a safe integer in [0, 2147483647]"
        assertNull(IntentSession.validateWire(is0()))
        assertNull(IntentSession.validateWire(is0("seq", 2_147_483_647L)))
        assertEquals(seqReason, IntentSession.validateWire(is0("seq", 2_147_483_648L)))
        assertEquals(seqReason, IntentSession.validateWire(is0("seq", -1L)))
        assertEquals(seqReason, IntentSession.validateWire(is0("seq", Json.Num("1.5"))))
        assertEquals(seqReason, IntentSession.validateWire(is0("seq", Json.Num("-0"))))
        assertEquals("'intent_session' must be an object", IntentSession.validateWire(jl(is0())))
        assertEquals("unknown field 'intent_session.note'", IntentSession.validateWire(is0("note", "x")))
        assertEquals("missing field 'intent_session.schema'", IntentSession.validateWire(is0().also { it.remove("schema") }))
        assertEquals("unknown field 'intent_session.zz'", IntentSession.validateWire(is0("zz", 1L).also { it.remove("root") }))
        assertEquals("'intent_session.root' is not canonical base64url (32 bytes)", IntentSession.validateWire(is0("root", Pca.b64(ByteArray(31)))))
        val sixteen = (0 until 16).map { jm("id", "a$it", "post", 0L) }
        val seventeen = (0 until 17).map { jm("id", "a$it", "post", 0L) }
        assertNull(IntentSession.validateWire(is0("acc", ArrayList(sixteen))))
        assertNotNull(IntentSession.validateWire(is0("acc", ArrayList(seventeen))))
        assertEquals("'intent_session.acc' ids must be distinct", IntentSession.validateWire(is0("acc", jl(jm("id", "a", "post", 1L), jm("id", "a", "post", 2L)))))
        assertNotNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a-b", "post", 1L)))))
        assertNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a".repeat(64), "post", 1L)))))
        assertNotNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a".repeat(65), "post", 1L)))))
        assertNotNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a", "post", Json.Num("1.5"))))))
        assertNotNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a", "post", 0L, "receipt", "x")))))
        assertNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a", "post", 0L, "receipt", REF)))))
        assertNotNull(IntentSession.validateWire(is0("acc", jl(jm("id", "a", "post", 0L, "other", 1L)))))
        for ((name, max) in listOf("facts" to 16, "classes" to 8, "labels" to 16)) {
            val ok = ArrayList<Any?>((0 until max).map { b64seed("v2/d$it") })
            val over = ArrayList<Any?>((0..max).map { b64seed("v2/d$it") })
            assertNull(name, IntentSession.validateWire(is0(name, ok)))
            assertNotNull(name, IntentSession.validateWire(is0(name, over)))
            assertEquals("'intent_session.$name' entries must be distinct", IntentSession.validateWire(is0(name, jl(REF, REF))))
        }
        assertNotNull(IntentSession.validateWire(is0("offer_set", "x")))
        assertNull(IntentSession.validateWire(is0("prov", jm("action.params.total", jl("r".repeat(256))))))
        assertNotNull(IntentSession.validateWire(is0("prov", jm("action.params.total", jl("r".repeat(257))))))
        assertNotNull(IntentSession.validateWire(is0("prov", jm("action.params.total", jl("é".repeat(128) + "a")))))
        assertNotNull(IntentSession.validateWire(is0("prov", jm("env.x", jl("r")))))
        assertNotNull(IntentSession.validateWire(is0("prov", jm("action.params.total", jl()))))
        assertNull(IntentSession.validateWire(is0("prov", jm("action.params.total", ArrayList<Any?>((0 until 8).map { "r$it" })))))
        assertNotNull(IntentSession.validateWire(is0("prov", jm("action.params.total", ArrayList<Any?>((0 until 9).map { "r$it" })))))
        val p32 = LinkedHashMap<String, Any?>().also { m -> (0 until 32).forEach { m["action.params.p$it"] = jl("r") } }
        val p33 = LinkedHashMap<String, Any?>().also { m -> (0 until 33).forEach { m["action.params.p$it"] = jl("r") } }
        assertNull(IntentSession.validateWire(is0("prov", p32)))
        assertNotNull(IntentSession.validateWire(is0("prov", p33)))
        // map_form: only "commit"
        assertNull(IntentSession.validateWire(is0("map_form", "commit")))
        for (bad in listOf<Any?>("plain", null, true)) assertEquals("'intent_session.map_form' must be \"commit\" when present", IntentSession.validateWire(is0("map_form", bad)))
        assertEquals(listOf("wire"), verify(G0, build(G0, "salt0", MAP0, is0("seq", -1L), params(), REF), ctx()).checks.keys.toList())
    }

    @Test fun sessionCaveat() {
        val c = jm("type", "intent_session", "session", SESSION, "seq", 0L, "root", R)
        assertNull(IntentSession.caveatError(c))
        c["prev"] = REF
        assertEquals("intent_session caveat: prev is present exactly when seq > 0", IntentSession.caveatError(c))
        c["seq"] = 1L
        assertNull(IntentSession.caveatError(c))
        c.remove("prev")
        assertEquals("intent_session caveat: prev is present exactly when seq > 0", IntentSession.caveatError(c))
        assertEquals("not an intent_session caveat", IntentSession.caveatError(jm("type", "envelope")))
        assertNotNull(IntentSession.caveatError(jm("type", "intent_session", "session", SESSION, "seq", 0L, "root", R, "x", 1L)))
        assertNotNull(IntentSession.caveatError(jm("type", "intent_session", "session", SESSION, "seq", 2_147_483_648L, "root", R, "prev", REF)))
        assertTrue(Caveats.satisfied(jm("type", "intent_session", "session", SESSION, "seq", 0L, "root", R), jm("now", NOW)))
        assertFalse(Caveats.satisfied(jm("type", "intent_session", "session", SESSION, "seq", 1L, "root", R), jm("now", NOW)))
        assertFalse(Caveats.satisfied(jm("type", "intent_session", "session", SESSION, "seq", 0L, "root", R), jm()))
    }

    // ------------------------------------------------------------------ rule 13 step 7: revocation
    private val idSession = IntentRevocation.sessionRevocationId(SESSION)
    private fun sorted(xs: List<String>): List<String> = xs.sortedWith { a, b -> Json.compareUtf8(a, b) }
    private fun epoch(revoked: List<String>, issued: Long, signer: String, scope: String): LinkedHashMap<String, Any?> {
        val s = sorted(revoked)
        val body = jm("instance_id", "ana", "grant_ref", scope, "epoch", s.size.toLong(), "set_size", s.size.toLong(), "root", IntentRevocation.revsetRoot(s),
            "issued_at", issued, "not_after", issued + 300_000L)
        val ep = LinkedHashMap(body)
        ep["guardian"] = pub(signer)
        ep["sig"] = sign(signer, Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.toByteArray(StandardCharsets.UTF_8), IntentJs.canonBytes(body)))
        return ep
    }
    private fun evidence(revoked: List<String>, issued: Long, signer: String) =
        jm("epoch", epoch(revoked, issued, signer, IntentRevocation.sessionRevocationScope(SESSION)), "revoked", ArrayList<Any?>(sorted(revoked)))
    private fun rev(ev: Map<String, Any?>?, ids: List<String>, maxAge: Double, last: Map<String, Any?>? = null): String? =
        IntentRevocation.checkSessionRevocation(IntentJs.normalize(ev), SESSION, pub(REV), ids, NOW.toDouble(), maxAge, null, null, last != null, last?.let { IntentJs.normalize(it) })

    @Test fun revocationStepOrder() {
        val ids = listOf(idSession)
        val high = listOf("pca-intent:zzz")
        assertNull(rev(evidence(high, NOW - 10_000, REV), ids, 60_000.0))
        assertNull(rev(evidence(listOf(), NOW - 10_000, REV), ids, 60_000.0))
        assertNull(rev(evidence(high, NOW - 60_000, REV), ids, 60_000.0))
        assertNotNull(rev(evidence(high, NOW - 60_001, REV), ids, 60_000.0))
        assertNull(rev(evidence(high, NOW + 60_000, REV), ids, 60_000.0))
        assertEquals("revocation epoch issued in the future", rev(evidence(high, NOW + 60_001, REV), ids, 60_000.0))
        assertEquals("'$idSession' is revoked", rev(evidence(listOf(idSession), NOW - 1_000, REV), ids, 60_000.0))
        assertEquals("the epoch must be numbered by its set size and list exactly set_size ids", rev(evidence(listOf("a", "b"), NOW - 1_000, REV).also { it["revoked"] = jl("a") }, ids, 60_000.0))
        assertEquals("the revoked list is not the signed set (root mismatch)", rev(evidence(listOf("a", "b"), NOW - 1_000, REV).also { it["revoked"] = jl("a", "c") }, ids, 60_000.0))
        assertEquals("revoked must be sorted by UTF-8 bytes and distinct", rev(evidence(listOf("a", "b"), NOW - 1_000, REV).also { it["revoked"] = jl("b", "a") }, ids, 60_000.0))
        assertEquals("revoked must be an array of ids", rev(evidence(listOf("a"), NOW - 1_000, REV).also { it["revoked"] = jm("0", "a") }, ids, 60_000.0))
        assertEquals("the revocation epoch is not signed by the session revocation authority", rev(evidence(high, NOW - 1_000, PRINCIPAL), ids, 60_000.0))
        assertEquals("revocation max age misconfigured (fail closed)", rev(null, ids, -1.0))
        assertEquals("revocation max age misconfigured (fail closed)", rev(null, ids, 0.5))
        assertEquals("no session revocation epoch supplied", rev(null, ids, 0.0))
        assertEquals("the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})",
            rev(evidence(high, NOW - 1_000, REV).also { it["proofs"] = jm() }, ids, 60_000.0))
        val other = jm("epoch", epoch(high, NOW - 1_000, REV, IntentRevocation.sessionRevocationScope(REF)), "revoked", jl("pca-intent:zzz"))
        assertEquals("revocation epoch is for a different grant", rev(other, ids, 60_000.0))
        val t = evidence(high, NOW - 1_000, REV)
        mm(t["epoch"])["instance_id"] = "bob"
        assertEquals("revocation epoch signature invalid", rev(t, ids, 60_000.0))
        val last = evidence(listOf("a"), NOW - 30_000, REV)
        assertNull(rev(evidence(listOf("a", "b"), NOW - 1_000, REV), ids, 60_000.0, last))
        assertNull(rev(evidence(listOf("a"), NOW - 1_000, REV), ids, 60_000.0, last))
        assertEquals("revocation epoch rollback (older than the last accepted)", rev(evidence(listOf(), NOW - 1_000, REV), ids, 60_000.0, last))
        assertEquals("the epoch drops 'a', revoked in the last accepted epoch (not append-only)", rev(evidence(listOf("b"), NOW - 1_000, REV), ids, 60_000.0, last))
        assertEquals("the tracked last epoch is malformed (fail closed)",
            rev(evidence(listOf("a"), NOW - 1_000, REV), ids, 60_000.0, evidence(listOf("a"), NOW - 30_000, REV).also { it["revoked"] = jl() }))
        val inp = jm("epoch", evidence(high, NOW - 1_000, REV)["epoch"], "revoked", jl("pca-intent:zzz"), "session", SESSION, "authority", pub(REV),
            "ids", jl(idSession), "now", NOW, "max_age_ms", 60_000L)
        assertTrue(IntentRevocation.checkPrimitive(inp))
        inp["proofs"] = jm()
        assertFalse(IntentRevocation.checkPrimitive(inp))
        assertNotEquals(IntentRevocation.revsetRoot(listOf("a", "b")), IntentRevocation.revsetRoot(listOf("a", "c")))
    }

    @Test fun revocationThroughTheSession() {
        val s4 = signRoot(rootBody().also { it["revocation"] = jm("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", pub(REV)) }, PRINCIPAL)
        val r4 = IntentSession.rootDigest(s4)
        val g = mint(0, null, MAP0, "salt0", PRINCIPAL, r4)
        val p = build(g, "salt0", MAP0, is0("root", r4), params(), REF)
        val ids = listOf(idSession, IntentRevocation.mapRevocationId(MAP0), IntentRevocation.deltaRevocationId(g["id"] as String))
        val high = listOf("pca-intent:zzz")
        fun run(ev: Map<String, Any?>?, policy: Map<String, Any?>?, last: Map<String, Any?>? = null): Pca.Verdict {
            val sess = jm("root", s4, "grants", jl())
            if (ev != null) sess["revocation"] = ev
            if (last != null) sess["revocation_last"] = last
            val c = ctx("session", sess)
            if (policy != null) c["policy"] = policy
            return verify(g, p, c)
        }
        assertTrue(run(evidence(high, NOW - 30_000, REV), null).allow)
        assertEquals(listOf("intent_session"), failed(run(null, null)))
        assertEquals(listOf("intent_session"), failed(run(evidence(high, NOW - 61_000, REV), null)))
        for (revoked in ids) assertEquals(revoked, listOf("intent_session"), failed(run(evidence(listOf(revoked), NOW - 1_000, REV), null)))
        assertEquals(listOf("intent_session"), failed(run(evidence(high, NOW - 1_000, PRINCIPAL), null)))
        assertEquals(listOf("intent_session"), failed(run(evidence(high, NOW - 20_000, REV), jm("session", jm("max_revocation_age_s", 10L)))))
        assertTrue(run(evidence(high, NOW - 10_000, REV), jm("session", jm("max_revocation_age_s", 10L))).allow)
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(run(evidence(high, NOW - 1_000, REV), jm("session", jm("max_revocation_age_s", -1L)))))
        assertEquals(listOf("intent_session"), failed(run(evidence(high, NOW - 1_000, REV), null, evidence(listOf("pca-intent:yyy"), NOW - 20_000, REV))))
        assertEquals(listOf("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("policy", jm("session", jm("max_revocation_age_s", 60L))))))
        assertNotNull(IntentSession.rootShapeError(signRoot(rootBody().also { it["revocation"] = jm("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L) }, PRINCIPAL)))
        assertEquals("revocation.key must not be a session principal (a dedicated revocation authority)",
            IntentSession.rootShapeError(signRoot(rootBody().also { it["revocation"] = jm("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", pub(PRINCIPAL)) }, PRINCIPAL)))
    }

    // ------------------------------------------------------------------ rule 14
    private fun conform(verb: String, params: Any?) = ActionSchema.conform(IntentJs.normalize(SCHEMA), verb, IntentJs.normalize(params))
    private fun code(code: String, path: String?, c: ActionSchema.Conform) {
        assertFalse(c.ok)
        assertEquals(code, c.code)
        assertEquals(path, c.path)
    }

    @Test fun rule14ThroughTheVerifier() {
        val extra = params().also { it["reseller"] = "x" }
        assertEquals(listOf("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), extra, REF), ctx("params", extra))))
        val at16 = params().also { it["note"] = "é".repeat(8) }
        assertTrue(verify(G0, build(G0, "salt0", MAP0, is0(), at16, REF), ctx("params", at16)).allow)
        val at17 = params().also { it["note"] = "é".repeat(8) + "a" }
        assertEquals(listOf("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), at17, REF), ctx("params", at17))))
        val v2 = LinkedHashMap(unsignedSchema()).also { it["version"] = "v2" }
        assertEquals(listOf("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("schema", jm("docs", jl(signSchema(v2, "skyair-2026", SITE)), "keys", KEYS)))))
        assertEquals(listOf("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF),
            ctx("schema", jm("docs", jl(SCHEMA), "keys", jl(jm("kid", "skyair-2026", "alg", "ed25519", "pk", pub(STRANGER))))))))
        assertEquals(listOf("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("schema", jm("docs", jl(), "keys", KEYS)))))
        assertEquals(listOf("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx().also { it.remove("params") })))
    }

    @Test fun conformanceOrderAndDomains() {
        assertTrue(conform("air.book", params()).ok)
        code("unknown_verb", null, conform("air.cancel", params()))
        code("params_not_object", null, conform("air.cancel", jl()))
        code("undeclared_param", "action.params.aa", conform("air.book", params().also { it["zz"] = 1L; it["aa"] = 1L }))
        code("missing_param", "action.params.add_ons", conform("air.book", jm()))
        for ((raw, want) in listOf("38900" to null, "1.5" to "bad_type", "-0" to "bad_type", "-1" to "out_of_domain", "0" to null, "5000000" to null, "5000001" to "out_of_domain")) {
            val c = conform("air.book", params().also { it["total"] = Json.Num(raw) })
            if (want == null) assertTrue(raw, c.ok) else code(want, "action.params.total", c)
        }
        code("bad_type", "action.params.total", conform("air.book", params().also { it["total"] = "38900" }))
        code("out_of_domain", "action.params.add_ons", conform("air.book", params().also { it["add_ons"] = jl("none", "none") }))
        assertTrue(conform("air.book", params().also { it["add_ons"] = jl("none", "tripshield", "seat_plus") }).ok)
        assertTrue(conform("air.book", params().also { it["passengers"] = ArrayList<Any?>((0 until 9).map { "p$it" }) }).ok)
        code("out_of_domain", "action.params.passengers", conform("air.book", params().also { it["passengers"] = ArrayList<Any?>((0 until 10).map { "p$it" }) }))
        code("bad_type", "action.params.passengers", conform("air.book", params().also { it["passengers"] = jl("x".repeat(65)) }))
        for ((d, ok) in listOf("2028-02-29" to true, "2026-02-29" to false, "1900-02-29" to false, "2000-02-29" to true, "0000-01-01" to false, "9999-12-31" to true, "2026-04-31" to false)) {
            val c = conform("air.search", jm("from", "SFO", "date", d, "pax", 2L))
            if (ok) assertTrue(d, c.ok) else code("out_of_domain", "action.params.date", c)
        }
        code("out_of_domain", "action.params.pax", conform("air.search", jm("from", "SFO", "date", "2026-01-01", "pax", 10L)))
    }

    @Test fun schemaSignatureAndShape() {
        val n = norm(SCHEMA)
        assertNull(ActionSchema.verify(n, IntentJs.normalize(KEYS)))
        assertEquals("sig.alg does not match the pinned key suite", ActionSchema.verify(n, jl(jm("kid", "skyair-2026", "alg", "ml-dsa-65", "pk", pub(SITE)))))
        assertEquals("schema signature invalid", ActionSchema.verify(LinkedHashMap(n).also { it["version"] = "x" }, KEYS))
        assertEquals("unknown member 'extra'", ActionSchema.verify(LinkedHashMap(n).also { it["extra"] = 1L }, KEYS))
        assertEquals(SD, ActionSchema.digest(n))
        val c = ActionSchema.canonProjection(n, "air.book", norm(params().also { it["add_ons"] = jl("tripshield", "none"); it["passengers"] = jl("b", "a") }))
        assertEquals("[\"none\",\"tripshield\"]", c["add_ons"])
        assertEquals("[\"b\",\"a\"]", c["passengers"])
        assertEquals("false", c["refundable"])
        assertFalse(c.containsKey("total"))
    }

    // ------------------------------------------------------------------ rule 15
    @Test fun rule15SiteLocal() {
        fun run(isn: Map<String, Any?>, c: Map<String, Any?>) = failed(verify(G0, build(G0, "salt0", MAP0, isn, params(), REF), c))
        assertEquals(listOf("accumulators"), run(is0("acc", jl(jm("id", "trip_spend", "post", 38_899L))), ctx()))
        assertEquals(listOf("accumulators"), run(is0("acc", jl()), ctx()))
        assertEquals(listOf("accumulators"), run(is0("acc", jl(jm("id", "trip_spend", "post", 38_900L), jm("id", "questions", "post", 1L))), ctx()))
        assertEquals(listOf("accumulators"), run(is0(), ctx("acc", jm("state", jm(), "monitors", jm()))))
        assertEquals(listOf("accumulators"), run(is0("acc", jl(jm("id", "trip_spend", "post", 500_100L))), ctx("acc", jm("state", jm("trip_spend", jm("sum", 461_200L)), "monitors", jm()))))
        assertEquals(listOf<String>(), run(is0("acc", jl(jm("id", "trip_spend", "post", 500_000L))), ctx("acc", jm("state", jm("trip_spend", jm("sum", 461_100L)), "monitors", jm()))))
        assertEquals(listOf("accumulators"), run(is0("acc", jl(jm("id", "trip_spend", "post", 38_900L, "receipt", REF))), ctx()))
        assertEquals(listOf("idle", "pending:1", "pending:2", "missed"), IntentAcc.monitorStates(jm("kind", "responds_within", "within", 2L)))
        assertEquals(java.lang.Long.valueOf(9007199254740991L), IntentAcc.combineAcc("sum", jm("sum", 9007199254740990L), IntentAcc.AccValue(null, 1, null)))
        assertNull(IntentAcc.combineAcc("sum", jm("sum", 9007199254740991L), IntentAcc.AccValue(null, 1, null)))
        assertEquals("accumulator 'trip_spend': key must be null or action.params.<name>", IntentAcc.accumulatorDeclError(trip().also { it.remove("key") }))
        assertEquals("accumulator 'trip_spend': holder sequenced has unknown member 'key'",
            IntentAcc.accumulatorDeclError(trip().also { it["holder"] = jm("kind", "sequenced", "uri", "https://s", "key", pub(SEQ_ROOT)) }))
    }

    private fun keySet(keys: List<Any?>, rootKey: String, version: Long = 1L, issued: Long = NOW - 100_000L): LinkedHashMap<String, Any?> {
        val body = jm("v", 1L, "kind", "pca-sequencer-keys", "sequencer", pub(rootKey), "version", version, "issued_at", issued, "keys", keys)
        return LinkedHashMap(body).also { it["sig"] = sign(rootKey, IntentJs.message(IntentAcc.SEQUENCER_KEYS_DOMAIN, body)) }
    }
    private fun receipt(draft: Map<String, Any?>, signer: String, kid: String, vararg over: Any?): LinkedHashMap<String, Any?> {
        val r = jm("v", 1L, "kind", "pca-acc-receipt", "session", SESSION, "acc", "trip_spend", "seq", 3L, "pre", 10_000L, "delta", 38_900L, "post", 48_900L,
            "pcactn_digest", IntentAcc.pcactnReservationDigest(draft), "aud", AUD, "issued_at", NOW - 1_000L, "expires_at", NOW + 60_000L, "kid", kid,
            "ledger", jm("index", 7L, "head", b64seed("v2/head")))
        r.putAll(jm(*over))
        r["signer"] = pub(signer)
        r["sig"] = sign(signer, IntentJs.message(IntentAcc.ACC_RECEIPT_DOMAIN, r))
        return r
    }

    @Test fun rule15Sequenced() {
        val seqAcc = trip().also { it["holder"] = jm("kind", "sequenced", "uri", "https://atlas.example/seq", "root", pub(SEQ_ROOT)) }
        val rs = signRoot(rootBody().also { it["accumulators"] = jl(seqAcc) }, PRINCIPAL)
        val rsR = IntentSession.rootDigest(rs)
        val gs = mint(0, null, MAP0, "salt0", PRINCIPAL, rsR)
        val draft = build(gs, "salt0", MAP0, null, params(), REF)
        val ks = keySet(jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L)), SEQ_ROOT)
        fun go(rc: Map<String, Any?>, post: Long, receipts: List<Any?>, keySets: List<Any?>, last: Long? = null, tracked: Any? = null): Pca.Verdict {
            val p = build(gs, "salt0", MAP0, is0("root", rsR, "acc", jl(jm("id", "trip_spend", "post", post, "receipt", IntentAcc.receiptDigest(rc)))), params(), REF)
            val acc = jm("receipts", receipts, "monitors", jm(), "sequencer_keys", keySets)
            if (last != null) acc["last_seq"] = jm("trip_spend", last)
            if (tracked != null) acc["keyset_versions"] = jm(pub(SEQ_ROOT), tracked)
            return verify(gs, p, ctx("session", jm("root", rs, "grants", jl()), "acc", acc))
        }
        val rc = receipt(draft, SEQ_KEY, "k1")
        assertTrue(go(rc, 48_900L, jl(rc), jl(ks)).reason, go(rc, 48_900L, jl(rc), jl(ks)).allow)
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(), jl(ks))))
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(rc), jl())))
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(rc), jl(ks), 3L)))
        assertTrue(go(rc, 48_900L, jl(rc), jl(ks), 2L).allow)
        val foreignSet = keySet(jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L)), STRANGER)
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(rc), jl(foreignSet))))
        assertTrue(go(rc, 48_900L, jl(rc), jl(foreignSet, ks)).allow)
        val forged = receipt(draft, STRANGER, "k1")
        assertEquals(listOf("accumulators"), failed(go(forged, 48_900L, jl(forged), jl(ks))))
        val bent = receipt(draft, SEQ_KEY, "k1", "post", 48_901L)
        assertEquals(listOf("accumulators"), failed(go(bent, 48_901L, jl(bent), jl(ks))))
        val late = receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1L)
        assertEquals(listOf("accumulators"), failed(go(late, 48_900L, jl(late), jl(ks))))
        val edge = receipt(draft, SEQ_KEY, "k1", "expires_at", NOW)
        assertTrue(go(edge, 48_900L, jl(edge), jl(ks)).allow)
        // tracked {version, digest}: the same set passes, an equivocating set under the version fails, a bare number is malformed
        val t1 = jm("version", 1L, "digest", IntentAcc.keySetDigest(norm(ks)))
        assertTrue(go(rc, 48_900L, jl(rc), jl(ks), tracked = t1).allow)
        val other = keySet(jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 9_000L)), SEQ_ROOT)
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(rc), jl(other), tracked = t1)))
        assertEquals(listOf("accumulators"), failed(go(rc, 48_900L, jl(rc), jl(ks), tracked = 1L)))
        assertTrue(IntentAcc.receiptArithmeticOk("sum", jm("pre", 10L, "delta", 5L, "post", 15L), 5))
        assertFalse(IntentAcc.receiptArithmeticOk("max", jm("pre", 10L, "delta", 5L, "post", 15L), 5))
    }

    @Test fun rule15Freshness() {
        val holder = norm(jm("kind", "sequenced", "uri", "https://atlas.example/seq", "root", pub(SEQ_ROOT)))
        val draft = build(G0, "salt0", MAP0, null, params(), REF)
        val k1 = jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L))
        val ks = keySet(k1, SEQ_ROOT)
        val rDef = IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble()
        val kDef = IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble()
        fun ok(rc: Map<String, Any?>, sets: List<Any?>, r: Double, k: Double, tracked: Any?) =
            IntentAcc.verifyReceiptAgainstHolder(norm(rc), holder, IntentJs.normalize(sets), NOW.toDouble(), r, k, tracked?.let { IntentJs.normalize(it) })
        val rc = receipt(draft, SEQ_KEY, "k1")
        assertTrue(ok(rc, jl(ks), rDef, kDef, null))
        assertNull(IntentAcc.receiptShapeError(norm(receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_000L))))
        assertNotNull(IntentAcc.receiptShapeError(norm(receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_001L))))
        assertTrue(ok(rc, jl(ks), 1_000.0, kDef, null))
        assertFalse(ok(rc, jl(ks), 999.0, kDef, null))
        assertTrue(ok(rc, jl(ks), rDef, 100_000.0, null))
        assertFalse(ok(rc, jl(ks), rDef, 99_999.0, null))
        assertFalse(ok(rc, jl(keySet(k1, SEQ_ROOT, 1L, NOW + 60_001L)), rDef, kDef, null))
        val v3 = keySet(k1, SEQ_ROOT, 3L)
        val t3 = jm("version", 3L, "digest", IntentAcc.keySetDigest(norm(v3)))
        assertTrue(ok(rc, jl(v3), rDef, kDef, t3))
        assertTrue(ok(rc, jl(keySet(k1, SEQ_ROOT, 4L)), rDef, kDef, t3))
        assertFalse(ok(rc, jl(keySet(k1, SEQ_ROOT, 2L)), rDef, kDef, t3))
        assertFalse(ok(rc, jl(keySet(k1, SEQ_ROOT, 3L, NOW - 99_000L)), rDef, kDef, t3))
        for (bad in listOf<Any?>(3L, jm("version", 3L), jm("version", 0L, "digest", t3["digest"]), jm("version", 3L, "digest", t3["digest"], "x", 1L)))
            assertFalse(bad.toString(), ok(rc, jl(v3), rDef, kDef, bad))
        assertNotNull(IntentAcc.keySetShapeError(norm(keySet(k1, SEQ_ROOT, 0L))))
        val old = receipt(draft, SEQ_KEY, "k1", "issued_at", NOW - 70_000L, "expires_at", NOW + 1_000L)
        assertTrue(ok(old, jl(keySet(jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_000L)), SEQ_ROOT)), rDef, kDef, null))
        assertFalse(ok(old, jl(keySet(jl(jm("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_001L)), SEQ_ROOT)), rDef, kDef, null))
        val p = build(G0, "salt0", MAP0, is0(), params(), REF)
        assertTrue(verify(G0, p, ctx("policy", jm("acc", jm("max_receipt_age_s", 60L, "max_keyset_age_s", 60L)))).allow)
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", jm("acc", jm("max_receipt_age_s", "60"))))))
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", jm("acc", jm("other", 1L))))))
        val badVersions = ctx().also { mm(it["acc"])["keyset_versions"] = jm(pub(SEQ_ROOT), 1L) }
        assertEquals(listOf("accumulators"), failed(verify(G0, p, badVersions)))
    }

    // ------------------------------------------------------------------ layers, W-B
    @Test fun layers() {
        val p = build(G0, "salt0", MAP0, is0(), params(), REF)
        val site = jm("site", jm("predicates", jl(jm("verb", "air.book", "where", jl(jm("field", "env.canon.add_ons", "op", "eq", "value", "[\"none\"]"))))))
        val ok = verify(G0, p, ctx("layers", site))
        assertTrue(ok.reason, ok.allow)
        assertEquals(keys("schema", "intent_session", "layers", "accumulators"), ok.checks.keys.toList())
        val org = jm("org", jm("predicates", jl(jm("verb", "air.book", "where", jl(jm("field", "action.params.total", "op", "lte", "value", 10_000L))))))
        assertEquals(listOf("layers"), failed(verify(G0, p, ctx("layers", org))))
        assertTrue(verify(G0, p, ctx("layers", jm())).allow)
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("layers", jm("std", jm())))))
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("layers", jm("org", null)))))
        assertEquals(listOf("layers"), failed(verify(G0, p, ctx("layers", jm("site", jm("predicates", jl(jm("verb", "*")), "note", "x"))))))
        assertEquals(listOf("layers"), failed(verify(G0, p, ctx("layers", jm("org", jm("predicates", jl()))))))
        val bad = params().also { it["total"] = 1L }
        assertEquals(listOf("schema", "layers", "accumulators"), failed(verify(G0, p, ctx("params", bad, "layers", site))))
        assertEquals(CORE, verify(G0, build(G0, "salt0", MAP0, null, params(), REF), ctx("layers", org)).checks.keys.toList())
    }

    @Test fun wbThroughThePipeline() {
        val p = build(G0, "salt0", MAP0, is0(), params(), REF)
        val v = verify(G0, p, ctx("wb", jm("policy", jm("provenance", jm("params", jm())))))
        assertEquals(keys("schema", "intent_session", "accumulators", "provenance"), v.checks.keys.toList())
        assertTrue(v.reason, v.allow)
        val q = verify(G0, p, ctx("wb", jm("policy", jm("provenance", jm("params", jm("action.params.offer_id", "material"))))))
        assertEquals(listOf("provenance"), failed(q))
        assertTrue(q.reason, q.reason.startsWith("provenance: intent_required: "))
        val f = verify(G0, p, ctx("wb", jm("policy", jm("world", jm("worlds", jl(jm())), "provenance", jm("params", jm())))))
        assertEquals(keys("schema", "intent_session", "accumulators", "facts"), f.checks.keys.toList())
        assertEquals(CORE, verify(G0, build(G0, "salt0", MAP0, null, params(), REF), ctx("wb", jm("policy", jm("provenance", jm("params", jm()))))).checks.keys.toList())
    }

    // ------------------------------------------------------------------ rule 19 through the pipeline
    @Test fun mapReporting() {
        // policy.map.require without a committed map: map is reported and fails; the policy is closed and typed
        val p = build(G0, "salt0", MAP0, is0(), params(), REF)
        val req = verify(G0, p, ctx("policy", jm("map", jm("require", true))))
        assertEquals(keys("schema", "intent_session", "accumulators", "map"), req.checks.keys.toList())
        assertEquals(listOf("map"), failed(req))
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", jm("map", jm("require", "yes"))))))
        assertEquals(listOf("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("map", jm("other", 1L)))))
        // a committed PCActn under the v2 grant: the v2c goal does not open it, and map fails without a disclosure
        val committed = build(G0, "salt0", MAP0, is0("map_form", "commit"), params(), REF)
        val c = verify(G0, committed, ctx())
        assertEquals(keys("schema", "intent_session", "accumulators", "map"), c.checks.keys.toList())
        assertEquals(false, c.checks["intent"])
        assertEquals(false, c.checks["map"])
        // a malformed context fails map too for a committed PCActn
        assertEquals(listOf("intent", "schema", "intent_session", "accumulators", "map"), failed(verify(G0, committed, ctx("params", null))))
        // no intent_session, policy requires the map: schema-less report of map alone
        val plain = build(G0, "salt0", MAP0, null, params(), REF)
        assertEquals(keys("map"), verify(G0, plain, ctx("policy", jm("map", jm("require", true)))).checks.keys.toList())
    }
}
