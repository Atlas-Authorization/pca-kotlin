package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The agent-side signers: every refusal text, every branch, and the exact bytes signed (recomputed here from the documented layout). */
@Suppress("UNCHECKED_CAST")
class Kill15SignersMoreTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }
    private val ops by lazy { ProducerOps(m(doc["keys"]), null) }

    private val agent = Keys.edFromSeed(ByteArray(32) { 1 })
    private val agentS = Keys.ed25519(agent)
    private val pq by lazy { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 }) }
    private val hybrid by lazy { Keys.suite("hybrid-ed25519-ml-dsa-65", agent, pq) }
    private val purePq by lazy { Keys.suite("ml-dsa-65", null, pq) }

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun canon(o: Any?) = Json.canonicalize(o)
    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)
    private fun d32(n: Int) = Pca.b64(ByteArray(32) { n.toByte() })
    private fun copyOf(o: Any?): Any? = ParityVectors.parse(Json.canonicalize(o))

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private fun argMap(op: String, key: String): MutableMap<String, Any?> = LinkedHashMap(m(caseArgs(op)[key]))

    private fun caseArgs(op: String, name: String? = null): MutableMap<String, Any?> {
        val c = l(doc["cases"]).map { m(it) }.first { it["op"] == op && (name == null || it["name"] == name) }
        return LinkedHashMap(m(copyOf(c["args"])))
    }

    // ---- an Ed25519 identity is needed where the wire names one ------------------------------------------------------------

    @Test fun aPurePostQuantumSignerIsRefusedWhereAnEd25519IdentityIsNamed() {
        assertEquals("signPreparedShare: the signer needs an Ed25519 identity", refusal { SignersMore.signPreparedShare("agent", purePq, ByteArray(1)) })
        assertEquals("signRevocationEpoch: the signer needs an Ed25519 identity", refusal { SignersMore.signRevocationEpoch(purePq, Issue.obj()) })
        assertEquals("signSessionRoot: the signer needs an Ed25519 identity", refusal { SignersMore.signSessionRoot(Issue.obj(), purePq) })
        assertEquals("actionSchemaKeyOf: the signer needs an Ed25519 identity", refusal { SignersMore.actionSchemaKeyOf("k", purePq) })
    }

    // ---- threshold shares --------------------------------------------------------------------------------------------------

    @Test fun aPreparedShareIsTheRoleTheKeyAndTheSignature() {
        val prepared = ByteArray(40) { it.toByte() }
        val s = SignersMore.signPreparedShare("guardian", agentS, prepared)
        assertEquals(listOf("role", "publicKey", "sig"), s.keys.toList())
        assertEquals("guardian", s["role"])
        assertEquals(agent.id(), s["publicKey"])
        assertEquals(Pca.b64(agent.sign(prepared)), s["sig"])
        val h = SignersMore.signPreparedShare("agent", hybrid, prepared)
        assertEquals(listOf("role", "publicKey", "sig", "alg", "pq_sig"), h.keys.toList())
        assertEquals("hybrid-ed25519-ml-dsa-65", h["alg"])
        assertEquals(hybrid.sign(prepared).first, h["sig"])
        assertEquals(hybrid.sign(prepared).second, h["pq_sig"])
    }

    @Test fun aThresholdShareBindsTheSignerSetAndTheThreshold() {
        val set = l(caseArgs("sign_threshold_share")["signer_set"])
        val msg = ByteArray(32) { 5 }
        assertEquals("signShare: a 'agent' share must bind {signerSet, t}", refusal { SignersMore.signThresholdShare("agent", agentS, msg, null, 1) })
        assertEquals("signShare: a 'guardian' share must bind {signerSet, t}", refusal { SignersMore.signThresholdShare("guardian", agentS, msg, null, 0) })
        for (t in listOf(0, 4, -1)) assertEquals("t=$t", "shareMessage: t must be 1, 2 or 3", refusal { SignersMore.signThresholdShare("agent", agentS, msg, set, t) })
        val sigs = HashSet<Any?>()
        for (t in 1..3) {
            val s = SignersMore.signThresholdShare("agent", agentS, msg, set, t)
            assertEquals(SignersMore.signPreparedShare("agent", agentS, Threshold.shareMessage("agent", msg, set, t, "ed25519", true)), s)
            sigs.add(s["sig"])
        }
        assertEquals(3, sigs.size)
        val h = SignersMore.signThresholdShare("agent", hybrid, msg, set, 2)
        assertEquals(SignersMore.signPreparedShare("agent", hybrid, Threshold.shareMessage("agent", msg, set, 2, "hybrid-ed25519-ml-dsa-65", true)), h)
    }

    // ---- PQ key binding ----------------------------------------------------------------------------------------------------

    @Test fun aPqBindingNeedsAPositiveSafeEpochAndAnAudience() {
        val epochText = "signPqBinding: epoch must be a positive safe integer"
        val audText = "signPqBinding: aud (the instance/audience id) is required"
        for (e in listOf(0L, -1L, 9007199254740992L)) assertEquals("epoch $e", epochText, refusal { SignersMore.signPqBinding(agent, "pk", e, "aud") })
        assertEquals(audText, refusal { SignersMore.signPqBinding(agent, "pk", 1L, null) })
        assertEquals(audText, refusal { SignersMore.signPqBinding(agent, "pk", 1L, "") })
        assertEquals(epochText, refusal { SignersMore.signPqBinding(agent, "pk", 0L, null) })
        for (e in listOf(1L, 2L, 9007199254740991L)) {
            val b = SignersMore.signPqBinding(agent, "pqpk", e, "inst")
            assertEquals(listOf("ed", "pq", "epoch", "aud", "sig"), b.keys.toList())
            assertEquals(agent.id(), b["ed"])
            assertEquals("pqpk", b["pq"])
            assertEquals(e, b["epoch"])
            assertEquals("inst", b["aud"])
            assertEquals(Pca.b64(agent.sign(SignersMore.pqBindingMessage(agent.id(), "pqpk", e, "inst"))), b["sig"])
        }
        assertEquals("atlas-pca/pq-binding/v2\u0000ed\u0000pk\u00007\u0000aud", String(SignersMore.pqBindingMessage("ed", "pk", 7L, "aud"), Charsets.UTF_8))
    }

    // ---- caution -----------------------------------------------------------------------------------------------------------

    private fun cautionBody(): MutableMap<String, Any?> = Issue.obj("action_digest" to "digest", "holder" to "holder", "caution" to Json.Num("0.5"))

    @Test fun theCautionBodyCheckSaysWhatIsWrong() {
        assertNull(SignersMore.cautionBodyError(cautionBody()))
        for (b in listOf<Any?>(null, "x", listOf(1L), 5L)) assertEquals("not an object", SignersMore.cautionBodyError(b))
        for (v in listOf<Any?>(null, "", 5L, listOf("a"))) {
            val b = cautionBody()
            b["action_digest"] = v
            assertEquals("action_digest required", SignersMore.cautionBodyError(b))
            val h = cautionBody()
            h["holder"] = v
            assertEquals("holder required", SignersMore.cautionBodyError(h))
        }
        val both = cautionBody()
        both.remove("action_digest")
        both.remove("holder")
        assertEquals("action_digest required", SignersMore.cautionBodyError(both))
        val absent = cautionBody()
        absent.remove("action_digest")
        assertEquals("action_digest required", SignersMore.cautionBodyError(absent))
        val noHolder = cautionBody()
        noHolder.remove("holder")
        assertEquals("holder required", SignersMore.cautionBodyError(noHolder))
        val range = "caution must be a finite number in [0,1]"
        for (c in listOf<Any?>(null, "0.5", Double.NaN, Double.POSITIVE_INFINITY, -1L, 2L, Json.Num("-0.1"), Json.Num("1.0000001"), Double.NEGATIVE_INFINITY)) {
            val b = cautionBody()
            b["caution"] = c
            assertEquals("caution $c", range, SignersMore.cautionBodyError(b))
        }
        val noCaution = cautionBody()
        noCaution.remove("caution")
        assertEquals(range, SignersMore.cautionBodyError(noCaution))
        for (c in listOf<Any?>(0L, 1L, 0.0, 1.0, Json.Num("0.25"), Json.Num("1"), Json.Num("0"))) {
            val b = cautionBody()
            b["caution"] = c
            assertNull("caution $c", SignersMore.cautionBodyError(b))
        }
    }

    @Test fun theCautionReasonIsASmallToken() {
        for (r in listOf("ambiguous_instruction", "a", "A-z_.:-09", "x".repeat(64))) {
            val b = cautionBody()
            b["reason"] = r
            assertNull(r, SignersMore.cautionBodyError(b))
        }
        for (r in listOf<Any?>("", "a b", "x".repeat(65), 5L, null, "caf\u00E9", "a/b")) {
            val b = cautionBody()
            b["reason"] = r
            assertEquals("reason $r", "invalid reason", SignersMore.cautionBodyError(b))
        }
    }

    @Test fun aCautionClaimIsTheThreeMembersTheReasonAndTheSignature() {
        val b = cautionBody()
        b["zzz"] = 1L
        val c = SignersMore.signCaution(b, agent)
        assertEquals(listOf("action_digest", "caution", "holder", "sig"), c.keys.toList())
        val clean = Issue.obj("action_digest" to "digest", "caution" to Json.Num("0.5"), "holder" to "holder")
        assertEquals(Pca.b64(agent.sign(Pca.canonBytes(Issue.obj("d" to "atlas-pca/caution/v1", "b" to clean)))), c["sig"])
        assertFalse(b.containsKey("sig"))
        b["reason"] = "why_not"
        val r = SignersMore.signCaution(b, agent)
        assertEquals(listOf("action_digest", "caution", "holder", "reason", "sig"), r.keys.toList())
        clean["reason"] = "why_not"
        assertEquals(Pca.b64(agent.sign(Pca.canonBytes(Issue.obj("d" to "atlas-pca/caution/v1", "b" to clean)))), r["sig"])
        assertEquals("signCaution: invalid reason", refusal { SignersMore.signCaution(Issue.obj("action_digest" to "d", "holder" to "h", "caution" to 1L, "reason" to "a b"), agent) })
        assertEquals("signCaution: caution must be a finite number in [0,1]",
            refusal { SignersMore.signCaution(Issue.obj("action_digest" to "d", "holder" to "h", "caution" to 1.5), agent) })
    }

    // ---- lease heartbeat ---------------------------------------------------------------------------------------------------

    @Test fun aHeartbeatNeedsEveryMemberAndSignsOnlyThose() {
        val full = Issue.obj("cap_id" to "cap", "seq" to 3L, "at" to 1000L, "holder" to "h", "lease_issued_at" to 900L)
        for (k in full.keys) {
            val b = LinkedHashMap(full)
            b.remove(k)
            assertEquals("signHeartbeat: $k required", refusal { SignersMore.signHeartbeat(b, agent) })
        }
        val two = LinkedHashMap(full)
        two.remove("seq")
        two.remove("holder")
        assertEquals("signHeartbeat: seq required", refusal { SignersMore.signHeartbeat(two, agent) })
        val withExtra = LinkedHashMap(full)
        withExtra["zzz"] = 1L
        val hb = SignersMore.signHeartbeat(withExtra, agent)
        assertEquals(listOf("cap_id", "seq", "at", "holder", "lease_issued_at", "sig"), hb.keys.toList())
        assertEquals(Pca.b64(agent.sign(Pca.canonBytes(Issue.obj("d" to "atlas-pca/lease-hb/v2", "b" to full)))), hb["sig"])
    }

    // ---- read receipt ------------------------------------------------------------------------------------------------------

    @Test fun aReadReceiptCountsFromThePreviousOne() {
        val a = caseArgs("sign_read_receipt", "read-receipt-chained")
        val rs = ops.ed("rs")
        val prev = LinkedHashMap(m(copyOf(a["prev"])))
        prev["seq"] = 5L
        val r = SignersMore.signReadReceipt(rs, m(a["grant"]), "read", "customers/7", "support", m(a["fields"]), l(a["labels"]), Json.asLong(a["issued_at"]), prev)
        assertEquals(6L, Json.asLong(r["seq"]))
        assertEquals(ReadSide.readReceiptRef(prev), r["prev"])
        val first = SignersMore.signReadReceipt(rs, m(a["grant"]), "read", "customers/7", "support", m(a["fields"]), l(a["labels"]), Json.asLong(a["issued_at"]), null)
        assertEquals(0L, Json.asLong(first["seq"]))
        assertTrue(first.containsKey("prev"))
        assertNull(first["prev"])
        assertEquals(ReadSide.readGrantDigest(m(a["grant"])), first["grant"])
        // the receipt is a copy: changing the caller's members afterwards does not reach it
        val fields = LinkedHashMap(m(copyOf(a["fields"])))
        val sealed = SignersMore.signReadReceipt(rs, m(a["grant"]), "read", "customers/7", "support", fields, l(a["labels"]), Json.asLong(a["issued_at"]), null)
        val before = canon(sealed["fields"])
        fields["zzz"] = 1L
        assertEquals(before, canon(sealed["fields"]))
        assertTrue(sealed["seq"] is Json.Num)
    }

    // ---- session root ------------------------------------------------------------------------------------------------------

    private val rootMembers = setOf("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "expires_at", "signer", "sig")

    @Test fun aSessionRootCarriesItsMembersTheSignerAndTheSignature() {
        val p = ops.ed("principal")
        val body = argMap("sign_session_root", "body")
        val r = SignersMore.signSessionRoot(body, Keys.ed25519(p))
        assertEquals(rootMembers, r.keys)
        assertEquals(p.id(), r["signer"])
        assertEquals(null, IntentSession.rootShapeError(r))

        val extra = LinkedHashMap(body)
        extra["flows"] = Issue.obj()
        extra["revocation"] = Issue.obj("epoch_uri" to "https://r.example/e", "max_age_s" to 60L, "key" to d32(9))
        val r2 = SignersMore.signSessionRoot(extra, Keys.ed25519(p))
        assertEquals(rootMembers + setOf("flows", "revocation"), r2.keys)
        assertEquals(canon(extra["revocation"]), canon(r2["revocation"]))
        assertEquals(null, IntentSession.rootShapeError(r2))
    }

    @Test fun aSessionRootIgnoresSignatureMembersTheCallerLeftOnTheBody() {
        val p = ops.ed("principal")
        val body = argMap("sign_session_root", "body")
        body["sig"] = "old"
        body["alg"] = "junk"
        body["pq_pk"] = "AA"
        body["pq_sig"] = "AA"
        val r = SignersMore.signSessionRoot(body, Keys.ed25519(p))
        assertNotEquals("old", r["sig"])
        for (k in listOf("alg", "pq_pk", "pq_sig")) assertFalse(k, r.containsKey(k))
        assertEquals(null, IntentSession.rootShapeError(r))
    }

    @Test fun aSessionRootRefusesWhatTheReferenceRefuses() {
        val p = ops.ed("principal")
        val body = argMap("sign_session_root", "body")
        assertEquals("signSessionRoot: the signer is not one of the session principals",
            refusal { SignersMore.signSessionRoot(body, Keys.ed25519(ops.ed("agent"))) })
        val noUri = LinkedHashMap(body)
        noUri["question_uri"] = ""
        assertEquals("signSessionRoot: question_uri must be a non-empty string", refusal { SignersMore.signSessionRoot(noUri, Keys.ed25519(p)) })
        val unknown = LinkedHashMap(body)
        unknown["zzz"] = 1L
        assertEquals("signSessionRoot: session root: unknown member 'zzz'", refusal { SignersMore.signSessionRoot(unknown, Keys.ed25519(p)) })
    }

    // ---- session grant -----------------------------------------------------------------------------------------------------

    private val session = d32(3)
    private val root = d32(4)
    private val mapDigest = d32(5)
    private val preds = listOf<Any?>(Issue.obj("verb" to "read", "resource" to "x/*"))

    private fun grant(seq: Long = 0L, prev: String? = null, form: String? = null, caveats: List<Any?>? = null, salt: String? = "fixed-salt", holderPq: String? = null,
                      binding: Map<String, Any?>? = null, risk: Map<String, Any?>? = null) =
        SignersMore.mintSessionGrant(agentS, agent.id(), session, seq, root, prev, mapDigest, form, preds, caveats, binding, risk, salt, holderPq)

    @Test fun aSessionGrantCommitsTheGoalOfItsMap() {
        val g = grant()
        assertEquals("fixed-salt", g.goalSalt)
        val cav = l(g.grant["caveats"])
        assertEquals(2, cav.size)
        val env = m(cav[0])
        assertEquals(setOf("type", "goal_commit", "predicates", "caveats", "agent_binding", "risk_policy"), env.keys)
        assertEquals(Issue.ENVELOPE_CAVEAT, env["type"])
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2(session, mapDigest), "fixed-salt"), env["goal_commit"])
        assertEquals(canon(preds), canon(env["predicates"]))
        assertEquals("[]", canon(env["caveats"]))
        assertEquals("{}", canon(env["agent_binding"]))
        assertEquals(canon(Issue.defaultRiskPolicy()), canon(env["risk_policy"]))
        assertEquals(canon(Issue.obj("type" to "intent_session", "session" to session, "seq" to 0L, "root" to root)), canon(cav[1]))
        assertFalse(g.grant.containsKey("holder_pq"))
        assertEquals(agent.id(), g.grant["holder"])
    }

    @Test fun aCommittedMapChangesTheGoalAndOnlyThatForm() {
        val plain = m(l(grant().grant["caveats"])[0])["goal_commit"]
        val committed = m(l(grant(form = IntentMap.MAP_FORM_COMMIT).grant["caveats"])[0])["goal_commit"]
        val other = m(l(grant(form = "other").grant["caveats"])[0])["goal_commit"]
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2c(session, mapDigest), "fixed-salt"), committed)
        assertNotEquals(plain, committed)
        assertEquals(plain, other)
    }

    @Test fun aSessionGrantKeepsWhatTheCallerGave() {
        val cav = listOf<Any?>(Issue.obj("type" to "budget_alloc", "limit" to 3L))
        val binding = Issue.obj("operator" to "acme")
        val risk = Issue.obj("custom" to 1L)
        val g = grant(seq = 1L, prev = d32(6), caveats = cav, holderPq = pq.pkB64u(), binding = binding, risk = risk)
        val env = m(l(g.grant["caveats"])[0])
        assertEquals(canon(cav), canon(env["caveats"]))
        assertEquals(canon(binding), canon(env["agent_binding"]))
        assertEquals(canon(risk), canon(env["risk_policy"]))
        assertEquals(canon(Issue.obj("type" to "intent_session", "session" to session, "seq" to 1L, "root" to root, "prev" to d32(6))), canon(l(g.grant["caveats"])[1]))
        assertEquals(Pca.holderPqCommitment(pq.pkB64u()), g.grant["holder_pq"])
    }

    @Test fun aSessionGrantWithoutASaltDrawsAFreshOne() {
        val a = grant(salt = null)
        val b = grant(salt = null)
        assertEquals(22, a.goalSalt.length)
        assertNotEquals(a.goalSalt, b.goalSalt)
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2(session, mapDigest), a.goalSalt), m(l(a.grant["caveats"])[0])["goal_commit"])
    }

    @Test fun aSessionGrantRefusesAMalformedLinkOrDigest() {
        val prevText = "mintSessionGrant: intent_session caveat: prev is present exactly when seq > 0"
        assertEquals(prevText, refusal { grant(seq = 0L, prev = d32(6)) })
        assertEquals(prevText, refusal { grant(seq = 1L, prev = null) })
        assertEquals("mintSessionGrant: intent_session caveat: prev must be canonical base64url (32 bytes)", refusal { grant(seq = 1L, prev = "x") })
        val seqText = "mintSessionGrant: intent_session caveat: seq must be a safe integer in [0, 2147483647]"
        assertEquals(seqText, refusal { grant(seq = -1L, prev = d32(6)) })
        assertEquals(seqText, refusal { grant(seq = 2147483648L, prev = d32(6)) })
        grant(seq = 2147483647L, prev = d32(6))
        assertEquals("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)",
            refusal { SignersMore.mintSessionGrant(agentS, agent.id(), session, 0L, root, null, "x", null, preds) })
        assertEquals("mintSessionGrant: intent_session caveat: session and root must be canonical base64url (32 bytes)",
            refusal { SignersMore.mintSessionGrant(agentS, agent.id(), "x", 0L, root, null, "x", null, preds) })
    }

    // ---- action schema and its discovery key -------------------------------------------------------------------------------

    @Test fun anActionSchemaCarriesTheSitesSignatureOverItsBody() {
        val schema = argMap("sign_action_schema", "doc")
        val site = Keys.ed25519(ops.ed("site"))
        val s = SignersMore.signActionSchema(schema, "site-k1", site)
        val sig = m(s["sig"])
        assertEquals(listOf("alg", "kid", "value"), sig.keys.toList())
        assertEquals("ed25519", sig["alg"])
        assertEquals("site-k1", sig["kid"])
        assertEquals(site.sign(Pca.concat(utf8(ActionSchema.ACTION_SCHEMA_DOMAIN), Pca.canonBytes(schema))).first, sig["value"])
        assertFalse("the caller's document is not changed", schema.containsKey("sig"))
        assertEquals(null, ActionSchema.shapeError(s, true))

        val h = SignersMore.signActionSchema(schema, "site-k1", hybrid)
        val hs = m(h["sig"])
        assertEquals(listOf("alg", "kid", "value", "pq_value"), hs.keys.toList())
        assertEquals("hybrid-ed25519-ml-dsa-65", hs["alg"])
        val want = hybrid.sign(Pca.concat(utf8(ActionSchema.ACTION_SCHEMA_DOMAIN), Pca.canonBytes(schema)))
        assertEquals(want.first, hs["value"])
        assertEquals(want.second, hs["pq_value"])
    }

    @Test fun anActionSchemaIsCheckedBeforeItIsSigned() {
        val site = Keys.ed25519(ops.ed("site"))
        assertEquals("signActionSchema: " + ActionSchema.shapeError(Issue.obj(), false), refusal { SignersMore.signActionSchema(Issue.obj(), "k", site) })
        val signed = argMap("sign_action_schema", "doc")
        signed["sig"] = Issue.obj()
        assertEquals("signActionSchema: an unsigned schema must not carry sig", refusal { SignersMore.signActionSchema(signed, "k", site) })
    }

    @Test fun theDiscoveryKeyEntryNamesTheSuiteAndThePins() {
        val k = SignersMore.actionSchemaKeyOf("site-k1", agentS)
        assertEquals(listOf("kid", "alg", "pk"), k.keys.toList())
        assertEquals("site-k1", k["kid"])
        assertEquals("ed25519", k["alg"])
        assertEquals(agent.id(), k["pk"])
        val h = SignersMore.actionSchemaKeyOf("site-k2", hybrid)
        assertEquals(listOf("kid", "alg", "pk", "pq_pk"), h.keys.toList())
        assertEquals("hybrid-ed25519-ml-dsa-65", h["alg"])
        assertEquals(pq.pkB64u(), h["pq_pk"])
    }

    // ---- intent required ---------------------------------------------------------------------------------------------------

    private fun cellCoords(): MutableMap<String, Any?> = Issue.obj("a" to listOf(0L, 5L), "b" to listOf("x", "y"))

    @Test fun cellCoordinatesAreOneToSixtyFourDimensions() {
        val text = "coords must be an object of 1..64 dimensions"
        for (c in listOf<Any?>(null, "x", listOf("a"), 5L, Issue.obj())) assertEquals(text, SignersMore.cellCoordsError(c))
        assertNull(SignersMore.cellCoordsError(cellCoords()))
        val many = LinkedHashMap<String, Any?>()
        for (i in 0 until 64) many["k$i"] = listOf("a")
        assertNull(SignersMore.cellCoordsError(many))
        many["k64"] = listOf("a")
        assertEquals(text, SignersMore.cellCoordsError(many))
    }

    @Test fun aCoordinatePathIsOneToTwoHundredFiftySixCharacters() {
        val text = "a coordinate path must be 1..256 characters"
        assertEquals(text, SignersMore.cellCoordsError(Issue.obj("" to listOf("a"))))
        assertEquals(text, SignersMore.cellCoordsError(Issue.obj("k".repeat(257) to listOf("a"))))
        assertNull(SignersMore.cellCoordsError(Issue.obj("k".repeat(256) to listOf("a"))))
        assertNull(SignersMore.cellCoordsError(Issue.obj("k" to listOf("a"))))
    }

    @Test fun anIndexRangeIsTwoNonNegativeOrderedIntegers() {
        val text = "coords 'r': need 0 <= lo <= hi"
        for (r in listOf(listOf(5L, 4L), listOf(-1L, 3L), listOf(1L, 0L), listOf(-2L, -1L))) assertEquals("$r", text, SignersMore.cellCoordsError(Issue.obj("r" to r)))
        for (r in listOf(listOf(0L, 0L), listOf(5L, 5L), listOf(0L, 9007199254740991L), listOf(3L, 4L))) assertNull("$r", SignersMore.cellCoordsError(Issue.obj("r" to r)))
        // minus zero is not an integer of the profile, so it is read as a (malformed) value set
        assertEquals("coords 'r': an index range [lo, hi] or a value set", SignersMore.cellCoordsError(Issue.obj("r" to listOf(-0.0, 1L))))
        assertEquals("coords 'r': an index range [lo, hi] or a value set", SignersMore.cellCoordsError(Issue.obj("r" to listOf(Json.Num("0.5"), 1L))))
        assertEquals("coords 'r': an index range [lo, hi] or a value set", SignersMore.cellCoordsError(Issue.obj("r" to listOf(0L, Json.Num("1.5")))))
    }

    @Test fun aValueSetIsOneToTwoHundredFiftySixDistinctStrings() {
        val text = "coords 's': an index range [lo, hi] or a value set"
        for (v in listOf<Any?>(null, "x", 5L, emptyList<Any?>(), listOf("a", 1L), listOf(1L, 2L, 3L), listOf(1L, "a"), (0..256).map { "v$it" }))
            assertEquals("$v", text, SignersMore.cellCoordsError(Issue.obj("s" to v)))
        assertEquals("coords 's': values must be distinct", SignersMore.cellCoordsError(Issue.obj("s" to listOf("a", "a"))))
        assertEquals("coords 's': values must be distinct", SignersMore.cellCoordsError(Issue.obj("s" to listOf("a", "b", "a"))))
        assertNull(SignersMore.cellCoordsError(Issue.obj("s" to (0 until 256).map { "v$it" })))
        assertNull(SignersMore.cellCoordsError(Issue.obj("s" to listOf("a"))))
        assertNull(SignersMore.cellCoordsError(Issue.obj("s" to listOf("a", "b"))))
    }

    @Test fun everyDimensionIsCheckedNotOnlyTheFirst() {
        assertEquals("coords 'bad': need 0 <= lo <= hi", SignersMore.cellCoordsError(Issue.obj("ok" to listOf(0L, 1L), "bad" to listOf(2L, 1L))))
        assertEquals("coords 'bad': values must be distinct", SignersMore.cellCoordsError(Issue.obj("ok" to listOf("a"), "bad" to listOf("z", "z"))))
        assertEquals("a coordinate path must be 1..256 characters", SignersMore.cellCoordsError(Issue.obj("ok" to listOf("a"), "" to listOf("z"))))
    }

    private fun irBody(): MutableMap<String, Any?> = argMap("sign_intent_required", "body")

    @Test fun anIntentRequiredBodyIsWellFormedOrSaysWhy() {
        assertNull(SignersMore.intentRequiredShapeError(irBody()))
        for (b in listOf<Any?>(null, "x", listOf(1L), 5L)) assertEquals("not an object", SignersMore.intentRequiredShapeError(b))
        val extra = irBody().also { it["extra"] = 1L }
        assertEquals("unknown member 'extra'", SignersMore.intentRequiredShapeError(extra))
        val v1 = "not a pca-intent-required v1"
        for (v in listOf<Any?>(2L, 0L, "1", null, Json.Num("1.5"), Json.Num("9007199254740993"))) {
            val b = irBody()
            b["v"] = v
            assertEquals("v=$v", v1, SignersMore.intentRequiredShapeError(b))
        }
        val noV = irBody().also { it.remove("v") }
        assertEquals(v1, SignersMore.intentRequiredShapeError(noV))
        val kind = irBody().also { it["kind"] = "pca-intent-requiredx" }
        assertEquals(v1, SignersMore.intentRequiredShapeError(kind))
        val noKind = irBody().also { it.remove("kind") }
        assertEquals(v1, SignersMore.intentRequiredShapeError(noKind))
    }

    @Test fun theFiveDigestsAreCanonicalThirtyTwoByteValuesCheckedInOrder() {
        for (k in listOf("session", "map_digest", "schema", "pcactn_digest", "action_digest")) {
            for (bad in listOf<Any?>("x", Pca.b64(ByteArray(31)), Pca.b64(ByteArray(33)), null, 5L)) {
                val b = irBody()
                b[k] = bad
                assertEquals("$k=$bad", "$k must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(b))
            }
        }
        val two = irBody().also { it["session"] = "x"; it["map_digest"] = "x" }
        assertEquals("session must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(two))
        val later = irBody().also { it["map_digest"] = "x"; it["action_digest"] = "x" }
        assertEquals("map_digest must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(later))
    }

    @Test fun theCellIsExactlyAVerbAndCoordinates() {
        val text = "cell must be {verb, coords}"
        val coords = cellCoords()
        for (c in listOf<Any?>("x", null, Issue.obj("verb" to "v", "coords" to coords, "more" to 1L), Issue.obj("coords" to coords), Issue.obj("verb" to "v"),
            Issue.obj("verb" to "", "coords" to coords), Issue.obj("verb" to 5L, "coords" to coords), Issue.obj("verb" to "v", "other" to coords),
            Issue.obj("coords" to coords, "other" to "v"), Issue.obj("verb" to null, "coords" to coords))) {
            val b = irBody()
            b["cell"] = c
            assertEquals("cell=$c", text, SignersMore.intentRequiredShapeError(b))
        }
        val bad = irBody().also { it["cell"] = Issue.obj("verb" to "refund", "coords" to Issue.obj()) }
        assertEquals("coords must be an object of 1..64 dimensions", SignersMore.intentRequiredShapeError(bad))
        val ok = irBody().also { it["cell"] = Issue.obj("verb" to "refund", "coords" to coords) }
        assertNull(SignersMore.intentRequiredShapeError(ok))
    }

    @Test fun theReasonQuestionFrictionAndDeliveryAreChecked() {
        val reason = irBody().also { it["reason"] = "certain" }
        assertEquals("reason must be 'uncertain'", SignersMore.intentRequiredShapeError(reason))
        assertEquals("reason must be 'uncertain'", SignersMore.intentRequiredShapeError(irBody().also { it.remove("reason") }))
        val qText = "question_id must match [A-Za-z0-9_-]{1,64}"
        for (q in listOf<Any?>("", "a".repeat(65), "a b", 5L, null, "a.b")) {
            val b = irBody()
            b["question_id"] = q
            assertEquals("q=$q", qText, SignersMore.intentRequiredShapeError(b))
        }
        for (q in listOf("a", "a".repeat(64), "a-b_9")) assertNull(q, SignersMore.intentRequiredShapeError(irBody().also { it["question_id"] = q }))
        assertEquals(qText, SignersMore.intentRequiredShapeError(irBody().also { it.remove("question_id") }))
        for (f in listOf("tap", "hold", "typed", "device")) assertNull(f, SignersMore.intentRequiredShapeError(irBody().also { it["friction"] = f }))
        for (f in listOf<Any?>("nope", "TAP", null, "", 1L)) assertEquals("f=$f", "unknown friction tier", SignersMore.intentRequiredShapeError(irBody().also { it["friction"] = f }))
        assertEquals("unknown friction tier", SignersMore.intentRequiredShapeError(irBody().also { it.remove("friction") }))
        for (t in listOf("wallet", "agent")) assertNull(t, SignersMore.intentRequiredShapeError(irBody().also { it["delivered_to"] = t }))
        for (t in listOf<Any?>("x", "Wallet", null, 1L)) assertEquals("t=$t", "delivered_to must be 'wallet' or 'agent'", SignersMore.intentRequiredShapeError(irBody().also { it["delivered_to"] = t }))
        assertEquals("delivered_to must be 'wallet' or 'agent'", SignersMore.intentRequiredShapeError(irBody().also { it.remove("delivered_to") }))
    }

    @Test fun theExpiryIsANonNegativeSafeIntegerAndTheBodyIsUnsigned() {
        val text = "expires_at must be a non-negative safe integer"
        for (e in listOf<Any?>(-1L, "5", null, Json.Num("9007199254740992"), Json.Num("1.5"), -0.0)) {
            assertEquals("e=$e", text, SignersMore.intentRequiredShapeError(irBody().also { it["expires_at"] = e }))
        }
        assertEquals(text, SignersMore.intentRequiredShapeError(irBody().also { it.remove("expires_at") }))
        for (e in listOf<Any?>(0L, 1L, 9007199254740991L)) assertNull("e=$e", SignersMore.intentRequiredShapeError(irBody().also { it["expires_at"] = e }))
        assertEquals("an unsigned body must not carry sig", SignersMore.intentRequiredShapeError(irBody().also { it["sig"] = Issue.obj() }))
    }

    @Test fun anIntentRequiredBodyIsSignedByTheSite() {
        val body = irBody()
        val site = Keys.ed25519(ops.ed("site"))
        val s = SignersMore.signIntentRequired(body, "site-k1", site)
        val sig = m(s["sig"])
        assertEquals(listOf("alg", "kid", "value"), sig.keys.toList())
        assertEquals("ed25519", sig["alg"])
        assertEquals("site-k1", sig["kid"])
        val msg = Pca.concat(utf8(SignersMore.INTENT_REQUIRED_DOMAIN), Pca.canonBytes(body))
        assertEquals(site.sign(msg).first, sig["value"])
        assertFalse("the caller's body is not changed", body.containsKey("sig"))
        for (k in body.keys) assertEquals(canon(body[k]), canon(s[k]))
        val h = m(SignersMore.signIntentRequired(body, "site-k1", hybrid)["sig"])
        assertEquals(listOf("alg", "kid", "value", "pq_value"), h.keys.toList())
        assertEquals("hybrid-ed25519-ml-dsa-65", h["alg"])
        assertEquals(hybrid.sign(msg).first, h["value"])
        assertEquals(hybrid.sign(msg).second, h["pq_value"])
        assertEquals("signIntentRequired: unknown member 'extra'", refusal { SignersMore.signIntentRequired(irBody().also { it["extra"] = 1L }, "k", site) })
    }

    // ---- templates ---------------------------------------------------------------------------------------------------------

    @Test fun aTemplateIsSignedByThePrincipalOverItsDigest() {
        val def = caseArgs("sign_template")["def"] as Map<String, Any?>
        val p = ops.ed("principal")
        val t = SignersMore.signTemplate(def, p)
        assertEquals(listOf("def", "signer", "sig"), t.keys.toList())
        assertEquals(p.id(), t["signer"])
        val msg = Pca.concat(utf8("atlas-pca/policy-template/v1\u0000"), Pca.sha(utf8(PolicyAuthoring.templateDigest(def))))
        assertEquals(Pca.b64(p.sign(msg)), t["sig"])
        assertEquals(null, PolicyAuthoring.verifyTemplate(t, listOf(p.id())))
        assertEquals("signTemplate: " + PolicyAuthoring.templateDefError(Issue.obj()), refusal { SignersMore.signTemplate(Issue.obj(), p) })
    }

    @Test fun aTightenOverlayIsSignedByThePrincipalOverItsHash() {
        val overlay = caseArgs("sign_tighten")["overlay"] as Map<String, Any?>
        val p = ops.ed("principal")
        val t = SignersMore.signTighten(overlay, p)
        assertEquals(listOf("overlay", "signer", "sig"), t.keys.toList())
        assertEquals(p.id(), t["signer"])
        val msg = Pca.concat(utf8("atlas-pca/template-tighten/v1\u0000"), Pca.sha(utf8(Pca.hashCanonical(overlay))))
        assertEquals(Pca.b64(p.sign(msg)), t["sig"])
        assertEquals("signTighten: " + PolicyAuthoring.tightenOverlayError(Issue.obj()), refusal { SignersMore.signTighten(Issue.obj(), p) })
    }

    // ---- revocation epoch --------------------------------------------------------------------------------------------------

    private fun epochBody(): MutableMap<String, Any?> = argMap("sign_revocation_epoch", "body")

    @Test fun aRevocationEpochNeedsEveryField() {
        for (k in listOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")) {
            val b = epochBody()
            b.remove(k)
            assertEquals("signRevocationEpoch: $k required", refusal { SignersMore.signRevocationEpoch(agentS, b) })
        }
        val two = epochBody().also { it.remove("epoch"); it.remove("root") }
        assertEquals("signRevocationEpoch: epoch required", refusal { SignersMore.signRevocationEpoch(agentS, two) })
    }

    @Test fun aRevocationEpochIsSignedByTheGuardianOverItsFieldsAndTheSuite() {
        val body = epochBody()
        body["zzz"] = 1L
        val e = SignersMore.signRevocationEpoch(agentS, body)
        assertEquals(setOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after", "guardian", "sig"), e.keys)
        assertEquals(agent.id(), e["guardian"])
        // numbers come back as the canonical Json.Num whatever type the caller used
        val ints = epochBody().also { it["epoch"] = 3; it["set_size"] = 2 }
        val ie = SignersMore.signRevocationEpoch(agentS, ints)
        assertTrue(ie["epoch"] is Json.Num)
        assertEquals(canon(e["sig"]), canon(SignersMore.signRevocationEpoch(agentS, epochBody().also { it["epoch"] = 3L; it["set_size"] = 2L })["sig"]))
        val fields = epochBody()
        assertEquals(Pca.b64(agent.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(fields)))), e["sig"])

        val h = SignersMore.signRevocationEpoch(hybrid, body)
        assertEquals(setOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after", "guardian", "sig", "alg", "pq_pk", "pq_sig"), h.keys)
        assertEquals("hybrid-ed25519-ml-dsa-65", h["alg"])
        assertEquals(pq.pkB64u(), h["pq_pk"])
        val bound = epochBody()
        bound["alg"] = "hybrid-ed25519-ml-dsa-65"
        bound["pq_pk"] = pq.pkB64u()
        val sg = hybrid.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(bound)))
        assertEquals(sg.first, h["sig"])
        assertEquals(sg.second, h["pq_sig"])
    }

    // ---- constitution ------------------------------------------------------------------------------------------------------

    @Test fun aConstitutionIsSignedOverItsIdOrRefusedWithEveryProblem() {
        val c = caseArgs("sign_constitution")["constitution"] as Map<String, Any?>
        val p = ops.ed("principal")
        val s = SignersMore.signConstitution(c, p)
        val id = Prohibitions.constitutionId(c)
        assertEquals(id, s["id"])
        assertEquals(Pca.b64(p.sign(Prohibitions.domainMessage(Prohibitions.CONSTITUTION_SIG_DOMAIN, id))), s["sig"])
        assertEquals(null, Prohibitions.verifyConstitution(s, p.id()))
        val problems = Prohibitions.validateConstitution(Issue.obj())
        assertTrue("an empty constitution has several problems", problems.size >= 2)
        assertEquals("signConstitution: " + problems.joinToString("; "), refusal { SignersMore.signConstitution(Issue.obj(), p) })
        assertTrue(problems.joinToString("; ").contains("; "))
    }
}
