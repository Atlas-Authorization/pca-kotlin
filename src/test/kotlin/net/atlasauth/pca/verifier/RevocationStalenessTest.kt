package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Revocation staleness (T9): replays `staleness-vectors.json` (`max_age`, `effective_reversibility`, `age`, `epoch`, `gate`;
 * a missing file FAILS) and checks the `authorize` wiring (the `freshness` check).
 */
@Suppress("UNCHECKED_CAST")
class RevocationStalenessTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("staleness-vectors.json") }
    private val guard: String get() = doc["guardian_public"] as String
    private fun rows(k: String) = doc[k] as List<Map<String, Any?>>

    /** A vector number: the "NaN" string stands for a NaN, null stays null, anything else is the JSON number. */
    private fun num(v: Any?): Any? = if (v == "NaN") Double.NaN else v
    private fun dbl(v: Any?): Double = IntentJs.num(num(v))!!

    private fun policy(p: Any?, allowUnsigned: Boolean = false): Revocation.StalenessPolicy? {
        if (p !is Map<*, *>) return null
        val st = p["staleness"] as? Map<*, *>
        return Revocation.StalenessPolicy(
            maxRevocationAgeMs = p["maxRevocationAgeMs"]?.let { dbl(it) },
            irreversibleMs = st?.get("irreversible")?.let { dbl(it) },
            costlyMs = st?.get("costly")?.let { dbl(it) },
            allowUnsignedRootForIrreversible = allowUnsigned,
            guardianPublic = guard,
        )
    }

    private fun same(name: String, want: Map<String, Any?>, got: Revocation.Check, okOnly: Boolean) {
        assertEquals("$name ok (${got.reason})", want["ok"], got.ok)
        if (!okOnly) assertEquals("$name reason", want["reason"], got.reason)
    }

    @Test
    fun corpusIsComplete() {
        assertEquals(listOf(15, 14, 13, 25, 28, 27, 10), listOf("max_age", "effective_reversibility", "age", "epoch", "gate", "membership", "gate_ids").map { rows(it).size })
        val c = doc["constants"] as Map<String, Any?>
        assertEquals(Revocation.REFRESH_MS, dbl(c["refresh_ms"]), 0.0)
        assertEquals(Revocation.VALIDITY_MS, dbl(c["validity_ms"]), 0.0)
        assertEquals(Revocation.IRREVERSIBLE_MAX_AGE_MS, dbl(c["irreversible_max_age_ms"]), 0.0)
    }

    @Test
    fun maxAgeVectors() {
        for (v in rows("max_age")) {
            val p = policy(v["policy"])!!
            assertEquals("${v["policy"]} ${v["class"]}", dbl(v["max_age_ms"]), Revocation.maxAgeMs(p, v["class"] as String), 0.0)
        }
    }

    @Test
    fun effectiveReversibilityVectors() {
        for (v in rows("effective_reversibility"))
            assertEquals("${v["server_class"]}/${v["signed_class"]}", v["effective"], Revocation.effectiveReversibility(v["server_class"], v["signed_class"]))
    }

    @Test
    fun ageVectors() {
        for ((i, v) in rows("age").withIndex()) {
            val got = Revocation.checkAge(num(v["issued_at"]), dbl(v["now"]), dbl(v["max_age_ms"]), (v["what"] as String?) ?: "revocation state")
            same("age#$i", v["result"] as Map<String, Any?>, got, v["ok_only"] == true)
        }
    }

    @Test
    fun epochVectors() {
        for (v in rows("epoch")) {
            val got = Revocation.checkEpoch(
                v["epoch"], v["guardian_public"] as String, dbl(v["now"]),
                grantRef = v["grant_ref"] as String?,
                lastAcceptedEpoch = if (v.containsKey("last_accepted_epoch")) Json.asLong(v["last_accepted_epoch"]) else null,
                pcactnEpoch = v["pcactn_epoch"],
                maxAgeMs = if (v.containsKey("max_age_ms")) dbl(v["max_age_ms"]) else null,
            )
            same(v["name"].toString(), v["result"] as Map<String, Any?>, got, v["ok_only"] == true)
        }
    }

    @Test
    fun gateVectors() {
        for (v in rows("gate")) {
            val pol = policy(v["policy"], v["allow_unsigned_root_for_irreversible"] == true)
            val state: Revocation.State? = when (v["mode"]) {
                "epoch" -> Revocation.State.Epoch(v["epoch"], v["bare_root"])
                "root" -> Revocation.State.Root(doc["revocation_root"], v["root_issued_at"])
                else -> null
            }
            val got = Revocation.checkState(
                pol, state, dbl(v["now"]), grantRef = "g1", signedClass = v["signed_class"], serverClass = v["server_class"],
                pcactnEpoch = 0L, guardianPublic = guard,
            )
            same(v["name"].toString(), v["result"] as Map<String, Any?>, got, false)
        }
    }

    @Test
    fun membershipVectors() {
        val set = doc["revocation_set"] as Map<String, Any?>
        for (v in rows("membership"))
            assertEquals(v["name"].toString(), v["ok"], Revocation.verifyNonMembership(v["root"] as? String ?: "", v["proof"], v["id"] as String))
        // the named sets are the roots the cases use
        assertTrue(rows("membership").any { it["set"] == "main" && it["root"] == set["root"] })
        assertTrue(rows("membership").any { it["set"] == "empty" && it["root"] == set["empty_root"] })
        assertTrue(rows("membership").any { it["set"] == "one" && it["root"] == (set["single"] as Map<String, Any?>)["root"] })
    }

    /** The vectors' guardian signs with 32 bytes of 0x0b. */
    private fun signedMainEpoch(root: Any?, size: Any?, issuedAt: Long, grantRef: String = "g1"): Map<String, Any?> {
        val body = linkedMapOf<String, Any?>(
            "instance_id" to "i", "grant_ref" to grantRef, "epoch" to 0L, "set_size" to Json.asLong(size), "root" to root,
            "issued_at" to issuedAt, "not_after" to issuedAt + 600_000L,
        )
        val seed = ByteArray(32) { 11 }
        val pkcs8 = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + seed
        val key = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(Pca.concat(IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN), IntentJs.canonBytes(body)))
        return LinkedHashMap(body).also { it["guardian"] = guard; it["sig"] = Pca.b64(sig.sign()) }
    }

    @Test
    fun gateIdsVectors() {
        val set = doc["revocation_set"] as Map<String, Any?>
        val pol = Revocation.StalenessPolicy(maxRevocationAgeMs = Revocation.VALIDITY_MS, guardianPublic = guard)
        for (v in rows("gate_ids")) {
            val ids = (v["ids"] as List<Any?>).map { it as String }
            val ep = signedMainEpoch(set["root"], set["size"], Json.asLong(v["epoch_issued_at"]))
            val proofs = v["proofs"] as Map<String, Any?>
            val got = Revocation.checkState(
                pol, Revocation.State.Epoch(ep), dbl(v["now"]), grantRef = "g1", signedClass = "costly", pcactnEpoch = 0L,
                guardianPublic = guard, ids = ids, proofFor = { proofs[it] },
            )
            same(v["name"].toString(), v["result"] as Map<String, Any?>, got, false)
        }
    }

    @Test
    fun everyChainCapabilityNeedsANonMembershipProof() {
        // default ids = the PCActn's cap_chain: with no proof source the request is denied, fail closed
        val gref = pcactn(c)["grant_ref"] as String
        val state = linkedMapOf("kind" to "epoch", "epoch" to signedMainEpoch(IntentRevocation.revsetRoot(emptyList()), 0L, AuthorizeTestKit.NOW - 1_000, gref))
        val deny = run(state, Revocation.StalenessPolicy(guardianPublic = guard), serverClass = "reversible")
        assertFalse(deny.allow)
        assertEquals("fail", deny.checks["freshness"])
        assertTrue(deny.reason!!, deny.reason!!.startsWith("freshness: no non-membership proof for "))
        val ok = run(state, Revocation.StalenessPolicy(guardianPublic = guard, proofFor = { _, _ -> linkedMapOf("size" to 0L) }), serverClass = "reversible")
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["freshness"])
    }

    @Test
    fun aMalformedPolicyIsAConstructionError() {
        for (bad in listOf(-5.0, 0.0, Double.NaN, Double.POSITIVE_INFINITY)) {
            for (build in listOf<() -> Any>(
                { Revocation.StalenessPolicy(maxRevocationAgeMs = bad) }, { Revocation.StalenessPolicy(irreversibleMs = bad) },
                { Revocation.StalenessPolicy(costlyMs = bad) },
            )) {
                try { build(); fail("policy with $bad must be refused") } catch (e: IllegalArgumentException) { assertTrue(e.message!!.contains("positive")) }
            }
        }
    }

    // ---- authorize(): the freshness step ----

    private val c = case("envelope-max-spend-within")

    private fun run(state: Any?, pol: Revocation.StalenessPolicy?, serverClass: String? = null): Authorize.Result {
        val ctx = LinkedHashMap<String, Any?>()
        if (serverClass != null) ctx["reversibility_class"] = serverClass
        if (state != null) ctx["revocation_state"] = state
        return Authorize.authorize(
            pcactn(c),
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW,
                plan = Authorize.SINGLE_STEP, context = { ctx }, revocationStaleness = pol,
            ),
        )
    }

    private fun root(issuedAt: Any?) = linkedMapOf("kind" to "root", "root" to "r", "issued_at" to issuedAt)

    @Test
    fun withoutThePolicyTheStateIsIgnored() {
        val r = run(root(0L), null)
        assertTrue(r.allow)
        assertFalse(r.checks.containsKey("freshness"))
    }

    @Test
    fun aStaleRootIsDeniedAndAFreshOneAdmitted() {
        // every signed fixture action is irreversible: an unsigned root counts only when allowed, within the window
        val pol = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true, irreversibleMs = 10_000.0, ids = { emptyList() })
        val now = AuthorizeTestKit.NOW
        val fresh = run(root(now - 10_000), pol)
        assertTrue(fresh.reasons.toString(), fresh.allow)
        assertEquals("pass", fresh.checks["freshness"])
        val stale = run(root(now - 10_001), pol)
        assertFalse(stale.allow)
        assertEquals("fail", stale.checks["freshness"])
        assertEquals("freshness: revocation root is 10001 ms old, over the verifier's maximum of 10000 ms (stale revocation state)", stale.reason)
        val unknown = run(root(null), pol)
        assertFalse(unknown.allow)
        assertEquals("freshness: revocation root age is unknown (unverifiable revocation state)", unknown.reason)
        assertTrue(run(null, pol).allow) // no state at all is accepted when allowed (the boolean hook decided)
        assertEquals("not-enforced", run(null, pol).checks["freshness"])
    }

    @Test
    fun anIrreversibleActionNeedsSignedState() {
        val pol = Revocation.StalenessPolicy()
        val none = run(null, pol)
        assertFalse(none.allow)
        assertEquals("fail", none.checks["freshness"])
        assertEquals("freshness: no verifiable (guardian-signed) revocation state for an irreversible action", none.reason)
        val unsigned = run(root(AuthorizeTestKit.NOW), pol)
        assertFalse(unsigned.allow)
        assertTrue(unsigned.reason!!, unsigned.reason!!.contains("unsigned revocation root refused"))
        assertTrue(run(null, Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true)).allow)
    }

    @Test
    fun aSignedEpochForAnotherGrantIsRefused() {
        val ep = rows("gate").first { it["name"] == "epoch-reversible-fresh" }["epoch"]
        val pol = Revocation.StalenessPolicy(guardianPublic = guard)
        val r = run(linkedMapOf("kind" to "epoch", "epoch" to ep), pol, serverClass = "irreversible")
        assertFalse(r.allow)
        assertEquals("freshness: revocation epoch is for a different grant", r.reason)
    }

    @Test
    fun aMalformedStateShapeIsNeverVerifiableState() {
        val r = run(linkedMapOf("kind" to "bogus"), Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true))
        assertFalse(r.allow)
        assertEquals("freshness: no signed revocation epoch", r.reason)
    }

    @Test
    fun onEpochAcceptedNeverRunsWithoutAnEpoch() {
        val seen = ArrayList<Map<String, Any?>>()
        val pol = Revocation.StalenessPolicy(allowUnsignedRootForIrreversible = true, onEpochAccepted = { e, _ -> seen.add(e) })
        assertTrue(run(null, pol).allow)
        assertTrue(seen.isEmpty())
        assertNull(Revocation.State.fromJson("nope"))
    }
}
