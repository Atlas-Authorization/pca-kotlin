package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The shared hardening corpora: `plan-root-vectors.json` (the core `plan_root_authorized` check), `pq-pin-vectors.json`
 * (`pq_pin` at the server verifier) and `budget-alloc-vectors.json` (budget_alloc monotonicity). A missing file FAILS.
 */
@Suppress("UNCHECKED_CAST")
class HardeningVectorsTest {
    private fun coreVector(name: String): Map<String, Any?> =
        (ParityVectors.load("vectors.json")["vectors"] as List<Map<String, Any?>>).first { it["name"] == name }

    private fun audienceOf(ctx: Map<String, Any?>): Pca.Audience = (ctx["aud"] as? String)?.let { Pca.Audience.Of(it) } ?: Pca.Audience.Unset

    @Test fun planRootAuthorized() {
        val rows = ParityVectors.load("plan-root-vectors.json")["plan_root_authorized"] as List<Map<String, Any?>>
        assertEquals(9, rows.size)
        for (row in rows) {
            val v = coreVector(row["vector"] as String)
            val ctx = v["context"] as Map<String, Any?>
            val pcactn = v["pcactn"] as Map<String, Any?>
            val root = (pcactn["plan"] as Map<String, Any?>)["root"]
            val o = row["options"] as Map<String, Any?>
            val roots = (o["authorizedPlanRoots"] as? List<*>)?.map { if (it == "\$plan_root") root as String else it as String }
            val got = Pca.verifyPcactn(
                pcactn, v["grant"] as Map<String, Any?>, Json.asLong(ctx["now"]), audienceOf(ctx),
                authorizedPlanRoots = roots, insecureSkipPlanRootCheck = o["insecureSkipPlanRootCheck"] == true,
            )
            val want = row["expect"] as Map<String, Any?>
            val status = when {
                got.checks["plan_root_authorized"] == true -> "pass"
                got.checks["plan_root_authorized"] == false -> "fail"
                "plan_root_authorized" in got.notEnforced -> "not-enforced"
                else -> "absent"
            }
            assertEquals("${row["name"]} check", want["check"], status)
            assertEquals("${row["name"]} allow (${got.reason})", want["allow"], got.allow)
            if (want.containsKey("reason")) assertEquals("${row["name"]} reason", want["reason"], got.reason)
        }
    }

    @Test fun pqPin() {
        val rows = ParityVectors.load("pq-pin-vectors.json")["pq_pin"] as List<Map<String, Any?>>
        assertTrue(rows.size >= 9)
        for (row in rows) {
            val v = coreVector(row["vector"] as String)
            val ctx = v["context"] as Map<String, Any?>
            val grant = v["grant"] as Map<String, Any?>
            val pcactn = v["pcactn"] as Map<String, Any?>
            fun sub(x: Any?): Any? = when {
                x == "\$grant.issuer" -> grant["issuer"]
                x == "\$grant.pq_pk" -> grant["pq_pk"]
                x is String && x.startsWith("\$grant.pq_pk[0:") -> (grant["pq_pk"] as String).substring(0, x.removePrefix("\$grant.pq_pk[0:").removeSuffix("]").toInt())
                else -> x
            }
            val pins: Map<String, Any?>? = (row["pq_pins"] as? Map<String, Any?>)?.let { m -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in m) out[sub(k) as String] = sub(x) } }
            val input = Authorize.Input(
                operation = (pcactn["action"] as Map<String, Any?>).let { Authorize.Operation(it["verb"] as String, it["resource"] as String, emptyMap()) }, audience = ctx["aud"] as? String, resolveGrant = { grant },
                stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = Json.asLong(ctx["now"]), pqPins = pins, risk = AuthorizeTestKit.calmRisk,
            )
            val r = Authorize.authorize(pcactn, input)
            val want = row["expect"] as Map<String, Any?>
            assertEquals("${row["name"]} check", if (want["check"] == "absent") null else want["check"], r.checks["pq_pin"])
            if (want.containsKey("reason")) assertTrue("${row["name"]}: ${r.reasons}", r.reasons.contains(want["reason"]))
        }
    }

    @Test fun budgetAlloc() {
        val rows = ParityVectors.load("budget-alloc-vectors.json")["budget_alloc"] as List<Map<String, Any?>>
        assertEquals(24, rows.size)
        for (row in rows) {
            val why = Pca.allocationsMonotone(row["caveats"])
            val want = row["expect"] as Map<String, Any?>
            assertEquals("${row["name"]} ok", want["ok"], why.isEmpty())
            if (want["ok"] == false) assertEquals("${row["name"]} reason", want["reason"], why)
        }
    }

    // ---- stateful-vectors.json: replay, counters, revocation, trust-budget depletion, expiry and per-holder streams, one store per sequence

    private val reference = setOf("replay", "threshold", "revocation", "leaf_signature", "plan_inclusion", "validity")

    private fun leafHolder(pc: Map<String, Any?>): String = ((pc["cap_chain"] as List<Map<String, Any?>>).last())["holder"] as String

    @Test fun statefulSequences() {
        val seqs = ParityVectors.load("stateful-vectors.json")["stateful"] as List<Map<String, Any?>>
        assertTrue(seqs.size >= 20)
        for (seq in seqs) {
            val setup = seq["setup"] as Map<String, Any?>
            val grants = (setup["grants"] as List<Map<String, Any?>>).associateBy { it["id"] as String }
            val revoked = ArrayList<String>((setup["revoked"] as? List<String>) ?: emptyList())
            val store = Authorize.MemoryStateStore()
            val steps = seq["steps"] as List<Map<String, Any?>>
            val initial = setup["initial_budget"] as? Map<String, Any?>
            if (initial != null) for (st in steps) if (st["op"] == "present") {
                val pc = st["pcactn"] as Map<String, Any?>
                val key = Authorize.stateKey(pc["grant_ref"] as String, leafHolder(pc))
                if (store.budget(key) == null) store.budgetCas(key, null, Risk.Budget(IntentJs.num(initial["B"])!!, IntentJs.num(initial["tau"])!!, null))
            }
            for ((i, st) in steps.withIndex()) {
                if (st["op"] == "revoke") { revoked.add(st["id"] as String); continue }
                val pc = st["pcactn"] as Map<String, Any?>
                val action = pc["action"] as Map<String, Any?>
                val op = Authorize.Operation(action["verb"] as String, action["resource"] as String, st["params"] as Map<String, Any?>)
                val input = Authorize.Input(
                    operation = op, audience = setup["audience"] as String, resolveGrant = { ref -> grants[ref] }, stateStore = store,
                    isRevoked = { p, _ -> ((p["cap_chain"] as? List<Map<String, Any?>>) ?: emptyList()).any { it["id"] in revoked } },
                    now = Json.asLong(st["now"]),
                    context = { _ -> mapOf("plan" to setup["plan_nodes"], "plan_authorized" to true, "risk" to setup["risk"]) },
                    seedBudget = { _, _ -> null }, provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(op),
                )
                val r = Authorize.authorize(pc, input)
                val failed = r.checks.filterValues { it == "fail" }.keys.map { if (it == "chain") "cap_chain" else it }.filter { it in reference }.sorted()
                val want = st["expect"] as Map<String, Any?>
                assertEquals("${seq["name"]} step $i allow (${r.reasons})", want["allow"], r.allow)
                assertEquals("${seq["name"]} step $i failed", (want["failed"] as List<String>).sorted(), failed)
            }
        }
    }

    /** `authorize-pq-pin-fixtures.json`: server-side PQ pins end to end through authorize (a classical grant from a pinned issuer is refused). */
    @Test fun authorizePqPinFixtures() {
        val doc = ParityVectors.load("authorize-pq-pin-fixtures.json")
        val cases = doc["cases"] as List<Map<String, Any?>>
        assertTrue(cases.size >= 9)
        val op = Authorize.Operation.fromJson(doc["operation"])!!
        for (c in cases) {
            val grant = c["grant"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val pins = c["pq_pins"] as Map<String, Any?>?
            val r = Authorize.authorize(
                c["pcactn"],
                Authorize.Input(
                    operation = op, audience = doc["audience"] as String, resolveGrant = { id -> if (id == grant["id"]) grant else null },
                    stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = Json.asLong(doc["now"]),
                    plan = Authorize.SINGLE_STEP, pqPins = pins, risk = AuthorizeTestKit.calmRisk,
                ),
            )
            val want = c["expect"] as Map<String, Any?>
            val name = c["name"] as String
            assertEquals("$name allow (${r.reasons})", want["allow"], r.allow)
            assertEquals("$name decision", want["decision"], r.decision)
            assertEquals("$name status", Json.asLong(want["status"]).toInt(), r.status)
            for (f in want["failed_includes"] as List<*>) assertEquals("$name failed $f", "fail", r.checks[f])
            val wantPin = (want["checks"] as Map<String, Any?>)["pq_pin"]
            assertEquals("$name pq_pin", if (wantPin == "absent") null else wantPin, r.checks["pq_pin"])
            if (want.containsKey("reason")) assertTrue("$name: ${r.reasons}", r.reasons.contains(want["reason"] as String))
        }
    }

    /** The core verifier with pins: a classical root whose issuer is pinned is refused; an unrelated pin or empty pins change nothing. */
    @Test fun coreRefusesAClassicalRootFromAPinnedIssuer() {
        val v = coreVector("valid-in-plan-action")
        val ctx = v["context"] as Map<String, Any?>
        val grant = v["grant"] as Map<String, Any?>
        val issuer = grant["issuer"] as String
        fun run(pins: Map<String, Any?>?) = Pca.verifyPcactn(
            v["pcactn"] as Map<String, Any?>, grant, Json.asLong(ctx["now"]), audienceOf(ctx), insecureSkipPlanRootCheck = true, pqPins = pins,
        )
        for (pin in listOf<Any?>("any-pq-key", "", 7L, null)) {
            val r = run(mapOf(issuer to pin))
            assertFalse(r.allow)
            assertEquals(false, r.checks["pq_pin"])
            assertTrue(r.reasons.toString(), r.reasons.contains("pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused"))
        }
        for (pins in listOf<Map<String, Any?>?>(mapOf("other" to "k"), emptyMap(), null)) {
            val r = run(pins)
            assertTrue(r.reasons.toString(), r.allow)
            assertFalse(r.checks.containsKey("pq_pin"))
        }
    }
}
