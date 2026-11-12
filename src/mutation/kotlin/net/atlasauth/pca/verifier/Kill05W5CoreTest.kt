package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.NOW
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TreeMap

/**
 * Core-group kills from full run 42070352941: the infinite allocation limit, the zk_compliance reason slot, a revocation `ids` hook that
 * answers null, the `actions` envelope member, AuthorizeOptions.allowUnsupported, a TBS without an AlgorithmIdentifier, one-sided absent
 * JSON members, the settlement shape, a null pin key, a non-list flow rule and a declaration map that refuses null lookups.
 */
@Suppress("UNCHECKED_CAST")
class Kill05W5CoreTest {
    // ---- Pca: capability.ts allocationsMonotone (Number.isFinite)

    private fun monotone(limit: Any?): String =
        KUtil.priv(Pca, "allocationsMonotone", KUtil.l(KUtil.m("type" to "budget_alloc", "limit" to limit)))

    @Test fun anInfiniteAllocationIsRefusedThoughNothingWidens() {
        val want = "budget_alloc caveat 0: limit must be a finite number >= 0"
        assertEquals(want, monotone(Double.POSITIVE_INFINITY))
        assertEquals(want, monotone(KUtil.n("1e999")))
        assertEquals("", monotone(KUtil.n("10")))
    }

    // ---- Pca: the zk_compliance failure (pcactn.ts:835-841) takes the reason slot only when nothing failed before it

    @Test fun zkComplianceIsTheReasonOnlyWhenNothingFailedBefore() {
        val aud = "ins_w5_core"
        val t0 = 1_800_000_000_000L
        val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 21 }))
        val holder = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 22 }))
        val env = Issue.obj(
            "predicates" to listOf(Issue.obj("verb" to "email.send", "resource" to "mail")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy(),
        )
        val g = Issue.mintGrant(principal, holder.id()!!, null, env, "send the Q3 report").grant
        val signed = Agent(holder, aud, g, clock = { t0 }).act("email.send", "mail", linkedMapOf("to" to "bob@acme.example"))
        val gn = Issue.norm(g)
        assertTrue(Pca.verifyPcactn(Issue.norm(signed), gn, t0, Pca.Audience.Of(aud), insecureSkipPlanRootCheck = true).allow)

        // zk_compliance is a signed member: re-sign so that it is the only failure
        val p = LinkedHashMap(Issue.norm(signed))
        p["zk_compliance"] = "proof"
        p["sig"] = holder.sign(Pca.thresholdMessage(p)).first

        val zk = "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof"
        val alone = Pca.verifyPcactn(p, gn, t0, Pca.Audience.Of(aud), insecureSkipPlanRootCheck = true)
        assertFalse(alone.allow)
        assertEquals(zk, alone.reason)
        assertEquals(listOf(zk), alone.reasons)
        assertEquals(false, alone.checks["zk_compliance"])
        val first = "audience: aud does not match this resource server / instance"
        val both = Pca.verifyPcactn(p, gn, t0, Pca.Audience.Of("another-resource"), insecureSkipPlanRootCheck = true)
        assertEquals(first, both.reason)
        assertEquals(listOf(first, zk), both.reasons)
    }

    // ---- Authorize

    @Test fun anIdsHookThatAnswersNullFallsBackToTheHopIds() {
        val c = case("envelope-predicate-within")
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        val stale = ParityVectors.load("staleness-vectors.json")
        val guard = stale["guardian_public"] as String
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to p["grant_ref"], "epoch" to 0L, "set_size" to 0L, "root" to IntentRevocation.revsetRoot(emptyList()),
            "issued_at" to NOW - 1_000, "not_after" to NOW - 1_000 + 600_000L,
        )
        // the seed behind the vectors' guardian_public (as Kill05AuthorizePipelineTest.signedEpoch)
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + ByteArray(32) { 11 }
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val signer = java.security.Signature.getInstance("Ed25519")
        signer.initSign(key)
        signer.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        val epoch = LinkedHashMap(body).also { it["guardian"] = guard; it["sig"] = Pca.b64(signer.sign()) }
        val state = mapOf("kind" to "epoch", "epoch" to epoch)

        // the declared type says non-null; a host written in Java (or this cast) can still answer null
        val nullIds = ({ _: Map<String, Any?> -> null } as (Map<String, Any?>) -> List<String>)
        val seen = ArrayList<String>()
        val pol = Revocation.StalenessPolicy(guardianPublic = guard, ids = nullIds, proofFor = { _, id -> seen.add(id); linkedMapOf("size" to 0L) })
        val operation = op(c)
        val r = Authorize.authorize(
            p,
            Authorize.Input(
                operation = operation, audience = AUD, resolveGrant = { grant(c) }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = NOW,
                plan = Authorize.SINGLE_STEP, context = { mapOf("revocation_state" to state, "reversibility_class" to "reversible") }, revocationStaleness = pol,
                insecureUnboundApproval = true, provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(operation), risk = AuthorizeTestKit.calmRisk,
            ),
        )
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals((p["cap_chain"] as List<Map<String, Any?>>).map { it["id"] as String }, seen)
    }

    @Test fun theActionsMemberAloneNeedsTheModelRules() {
        val e = KUtil.m(
            "type" to "envelope", "goal_commit" to "g", "predicates" to KUtil.l(KUtil.m("verb" to "*")), "caveats" to KUtil.l(),
            "agent_binding" to KUtil.m(), "risk_policy" to Issue.defaultRiskPolicy(), "actions" to KUtil.l(),
        )
        assertTrue(KUtil.priv<Boolean>(Authorize, "needsModelRules", KUtil.m("caveats" to KUtil.l(e))))
    }

    @Test fun authorizeOptionsKeepAllowUnsupported() {
        val o = Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), null, allowUnsupported = listOf("bond"), plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk)
        assertEquals(listOf("bond"), o.allowUnsupported)
    }

    // ---- Sigstore

    @Test fun aTbsWithoutAnAlgorithmIdentifierIsNotIssued() {
        val der = Kill05SigKit.leafDer()
        val c = Kill05SigKit.x509(der)
        val pc = Sigstore.parseCert(der)
        assertTrue(Sigstore.leafIssuedBy(c, pc, Kill05SigKit.ca))
        val noAlg = Sigstore.ParsedCert(pc.der, pc.top, pc.tbs, emptyList(), pc.extsWrapper, pc.exts)
        assertFalse(Sigstore.leafIssuedBy(c, noAlg, Kill05SigKit.ca))
    }

    // ---- Optimistic

    private fun memberEq(a: Map<String, Any?>, b: Map<String, Any?>): Boolean = KUtil.priv(Optimistic, "memberEq", a, b, "k")

    @Test fun anAbsentMemberIsNotAJsonNull() {
        // JavaScript: undefined === null is false, and undefined === undefined is true
        assertFalse(memberEq(KUtil.m(), KUtil.m("k" to null)))
        assertFalse(memberEq(KUtil.m("k" to null), KUtil.m()))
        assertTrue(memberEq(KUtil.m(), KUtil.m()))
        assertTrue(memberEq(KUtil.m("k" to null), KUtil.m("k" to null)))
    }

    private fun settlement(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val r = KUtil.m("claimId" to "c", "action" to "open", "amount" to KUtil.n("10"), "from" to "f", "to" to "t", "at" to KUtil.n("1"), "evidenceDigest" to "", "sig" to "s")
        for ((k, v) in kv) r[k] = v
        return r
    }

    @Test fun everySettlementMemberIsPartOfTheShape() {
        assertEquals("signature", Optimistic.settlementWireCheck(settlement(), "g"))
        for (k in listOf("claimId", "action", "amount", "from", "to", "at", "evidenceDigest", "sig")) {
            val r = settlement()
            r.remove(k)
            assertEquals(k, "shape", Optimistic.settlementWireCheck(r, "g"))
        }
        for (k in listOf("claimId", "from", "to")) assertEquals(k, "shape", Optimistic.settlementWireCheck(settlement(k to ""), "g"))
        // a slash passes the shape only with non-empty evidence: without it the split is never looked at
        val slash = settlement("action" to "slash", "evidenceDigest" to "e", "split" to KUtil.m())
        assertEquals("split", Optimistic.settlementWireCheck(slash, "g"))
        val noEvidence = LinkedHashMap(slash)
        noEvidence.remove("evidenceDigest")
        assertEquals("shape", Optimistic.settlementWireCheck(noEvidence, "g"))
        assertEquals("shape", Optimistic.settlementWireCheck(settlement("action" to "slash", "split" to KUtil.m()), "g"))
    }

    // ---- Pq

    @Test fun aNullIdentityNeverReadsAPin() {
        val pins = LinkedHashMap<String?, Any?>().also { it[null] = "pk" } as Map<String, Any?>
        assertNull(PinnedPq.resolve(null, "pk", null, pins, null))
    }

    // ---- ParamProvenance

    @Test fun aFlowRuleThatIsNotAListAllowsNothing() {
        assertFalse(ParamProvenance.flowAllowed(linkedMapOf<String, Any?>("c" to "a"), "c", "o", "a"))
        assertTrue(ParamProvenance.flowAllowed(linkedMapOf<String, Any?>("c" to listOf("a")), "c", "o", "a"))
    }

    // ---- ActionSchema

    @Test fun onlyMinAndMaxAreLookedUp() {
        // a TreeMap throws on a null key: the loop over ("min", "max") must not read a third, empty slot
        val d = TreeMap<String, Any?>()
        d["type"] = "integer"
        d["semantic"] = "s"
        d["sensitivity"] = "free"
        assertNull(KUtil.priv<String?>(ActionSchema, "paramDeclError", "action.params.x", d, null, false))
    }

    /** hash.ts compareUtf8: shared bytes, then the shorter sorts first. A code-unit fallback would answer the other way here. */
    @Test
    fun compareUtf8OrdersByByteLengthBeforeCodeUnits() {
        assertEquals(-1, Json.compareUtf8("\uFFFD", "\uD800A"))
        assertEquals(1, Json.compareUtf8("\uD800A", "\uFFFD"))
    }
}
