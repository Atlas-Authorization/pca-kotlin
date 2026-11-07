package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills, round 2 (full run 41911466407, shards 15/16): the Operations @JvmOverloads bridges, the outcome shape
 * of a status that only shares a hashCode, a recheck that answers null (refused, as the reference's `rc?.ok !== true`), the
 * PlanRegistry context bridge and message-less planRoot failure, the read-side BMP bound and receipt `prev` shape, the vault's
 * grant expiry ahead of a later entry expiry, the forbid-wins rank of an unsigned row, and Assurance's report / degraded reason.
 */
@Suppress("UNCHECKED_CAST")
class Kill05R2OpsTest {
    private val T0 = 1_800_000_000_000L
    private val PD = Pca.paramsDigest(null)

    // ---- Operations ----

    // the @JvmOverloads bridges are what a Java caller links against (Kotlin callers use the $default methods)
    @Test fun operationsOverloadBridges() {
        val c = Operations::class.java
        val st = Operations.MemoryStore()
        for (id in listOf("a", "b", "c", "d")) assertNull(st.create(linkedMapOf("id" to id, "state" to "pending", "startedAt" to 0L)))
        // the 5-minute default and the wall clock: a claim started at epoch 0 is long stale
        val ra = c.getMethod("recoverOperation", Operations.Store::class.java, String::class.java).invoke(Operations, st, "a") as Map<String, Any?>
        assertEquals("aborted", ra["state"])
        val rb = c.getMethod("recoverOperation", Operations.Store::class.java, String::class.java, Double::class.javaPrimitiveType)
            .invoke(Operations, st, "b", 1.0) as Map<String, Any?>
        assertEquals("aborted", rb["state"])
        val one = c.getMethod("recoverOperations", Operations.Store::class.java).invoke(Operations, st) as List<Map<String, Any?>>
        assertEquals(listOf("aborted", "aborted"), one.map { it["state"] })
        assertNull(st.create(linkedMapOf("id" to "e", "state" to "pending", "startedAt" to 0L)))
        val two = c.getMethod("recoverOperations", Operations.Store::class.java, Double::class.javaPrimitiveType).invoke(Operations, st, 1.0) as List<Map<String, Any?>>
        assertEquals(listOf("e"), two.map { it["id"] })

        for (id in listOf("u1", "u2")) assertNull(st.create(linkedMapOf("id" to id, "state" to "uncertain")))
        val r3 = c.getMethod("resolveOperation", Operations.Store::class.java, String::class.java, Boolean::class.javaPrimitiveType)
        assertEquals(true, r3.invoke(Operations, st, "u1", true))
        assertEquals("committed", st.get("u1")!!["state"])
        assertEquals(false, r3.invoke(Operations, st, "u1", true))
        val r4 = c.getMethod("resolveOperation", Operations.Store::class.java, String::class.java, Boolean::class.javaPrimitiveType, Any::class.java)
        assertEquals(true, r4.invoke(Operations, st, "u2", false, "gone"))
        assertEquals("gone", st.get("u2")!!["error"])
        assertEquals(false, r4.invoke(Operations, st, "u2", false, "gone"))
    }

    // `when (status)` compares the hashCode first: a status sharing one with a known status still gets the generic shape
    @Test fun outcomeShapeOfACollidingStatus() {
        for ((s, c) in listOf("committed" to "committfE", "failed" to "failfE", "aborted" to "abortfE", "uncertain" to "uncertajO", "pending" to "pendioH")) {
            assertEquals(s.hashCode(), c.hashCode())
            val o = Operations.ExecuteOutcome(c, "id", result = 1L, error = "e", reason = "r")
            assertEquals(linkedMapOf<String, Any?>("status" to c, "reason" to "r"), o.toMap())
        }
    }

    private val nullRecheck = { _: Operations.ExecutionHandle -> null } as (Operations.ExecutionHandle) -> Operations.Recheck

    @Test fun aRecheckThatAnswersNullIsRefused() {
        val p = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("reversibility_class" to "irreversible"))
        val a = Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = Authorize.AuthorizedOperation("v", "/r", PD, "op1"), pcactn = p)
        var ran = false
        val o = Operations.executeAuthorized(a, Operations.MemoryStore(), null, nullRecheck, "irreversible", null, 1000.0, { T0 }) { ran = true; null }
        assertFalse(ran)
        assertEquals(linkedMapOf<String, Any?>("status" to "aborted", "operationId" to "op1", "reason" to "recheck: refused", "replayed" to false), o.toMap())

        // the executor passes the extra recheck's null answer on (executeAuthorized refuses it)
        val grant = linkedMapOf<String, Any?>("g" to "rant")
        val ex = Operations.Executor(
            Operations.MemoryStore(), Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }), "aud",
            { ref -> if (ref == "g1") grant else null }, nullRecheck, now = { T0 },
        )
        val h = Operations.ExecutionHandle("id", Authorize.AuthorizedOperation("v", "/r", PD, "id"), linkedMapOf("grant_ref" to "g1"))
        assertNull(ex.recheckAll(h))
    }

    // ---- PlanLifecycle ----

    private val planNodes = listOf<Map<String, Any?>>(linkedMapOf("id" to "n1", "verb" to "v", "resource" to "/r"))

    @Test fun planContextBridgeAndAMessagelessRootFailure() {
        val reg = PlanLifecycle.PlanRegistry(now = { T0 })
        val root = reg.draft("g1", planNodes).record!!["root"] as String
        val m = PlanLifecycle.PlanRegistry::class.java.getMethod("context", String::class.java, String::class.java)
        assertNotNull(m.invoke(reg, "g1", root))
        assertNull(m.invoke(reg, "g1", "unknown-root"))

        class Boom : LinkedHashMap<String, Any?>() {
            override fun get(key: String): Any? = throw IllegalStateException()
        }
        val t = reg.draft("g1", listOf(Boom()))
        assertFalse(t.ok)
        assertEquals("the plan cannot be committed: unknown", t.reason)
    }

    // ---- ReadSide / ReadVault ----

    private val rLabel = "k05-r2-read-principal"
    private val rp = IntentTestKit.pub(rLabel)
    private val vd = Pca.b64(ByteArray(32))

    private fun readGrant(): Map<String, Any?> {
        val b = jm(
            "v", 1L, "id", "rg-1", "principal", rp, "issued_at", 1000L, "expires_at", 2000L,
            "reads", jl(jm(
                "verb", "customers.get", "resource_prefix", "customers/", "purposes", jl("support"),
                "modes", jm("fin", "bucket:100", "gone", "drop", "pii", "last4", "pub", "show", "ref", "token", "sec", "hash"), "default_mode", "drop",
            )),
            "caps", jm(), "sinks", jm("payments", jm("allow", jl("pub", "ref"), "escalate", jl("pii")), "email", jm("allow", jl(), "escalate", jl())),
        )
        return jm("body", b, "sig", IntentTestKit.sign(rLabel, IntentJs.message(ReadSide.READ_GRANT_DOMAIN, b)))
    }

    @Test fun last4KeepsToTheBmp() {
        val g = readGrant()
        fun last4(v: Any?) = ReadSide.redactRead(ReadSide.ReadInput(
            g, rp, 1500L, "customers.get", "customers/1", "support", jm("fields", jm("b_pii", "pii"), "required", jl()), jm("b_pii", v), jm(), "0123456789abcdef", jm(),
        )).view["b_pii"]
        assertEquals("****abcd", last4("￿abcd"))
        assertNull(last4("𐀀abcd")) // U+10000, the first code point past the BMP
    }

    @Test fun aLaterReceiptNeedsAWellFormedPrev() {
        val ok = jm(
            "v", 1L, "grant", vd, "verb", "customers.get", "resource", "customers/1", "purpose", "support", "seq", 1L, "prev", vd,
            "fields", jm("f0", jm("class", "pub", "action", "shown", "kind", null, "vd", vd)), "labels", jl("pub"), "issued_at", 1500L, "signer", vd, "sig", "x",
        )
        fun valid(r: Any?): Boolean = KUtil.priv(ReadSide, "validReadReceipt", r)
        assertTrue(valid(ok))
        assertFalse(valid(LinkedHashMap(ok).also { it["prev"] = "x" }))
        assertFalse(valid(LinkedHashMap(ok).also { it["prev"] = Json.Num("5") }))
    }

    @Test fun theGrantExpiresBeforeALaterEntry() {
        val label = "k05-r2-vault-principal"
        val p = IntentTestKit.pub(label)
        val b = jm(
            "v", 1L, "id", "rg-vault", "principal", p, "issued_at", 1000L, "expires_at", 2000L,
            "reads", jl(jm("verb", "customers.get", "resource_prefix", "customers/", "purposes", jl("support"), "modes", jm("ref", "token", "ssn", "token", "tax", "token"), "default_mode", "drop")),
            "caps", jm(), "sinks", jm("payments", jm("allow", jl("ref"), "escalate", jl("ssn")), "email", jm("allow", jl(), "escalate", jl())),
        )
        val g = jm("body", b, "sig", IntentTestKit.sign(label, IntentJs.message(ReadSide.READ_GRANT_DOMAIN, b)))
        val s = ReadVault.memoryVault()
        s.put("tok_x", ReadVault.VaultEntry("ref", "c_77", ReadSide.readGrantDigest(b), 5000L))
        fun det(now: Long) = ReadVault.detokenize(ReadVault.DetokenizeInput(g, p, now, "payments", "tok_x", s)).toMap()
        assertEquals(linkedMapOf<String, Any?>("decision" to "allow", "code" to null, "value" to "c_77"), det(1999L))
        assertEquals(linkedMapOf<String, Any?>("decision" to "deny", "code" to "expired", "value" to null), det(2000L))
        assertEquals(linkedMapOf<String, Any?>("decision" to "deny", "code" to "expired", "value" to null), det(4000L))
    }

    // ---- PolicyAuthoring ----

    // a Java caller's precedence may hold a null: an unsigned row still ranks last (the reference: `signer === undefined ? -1`)
    @Test fun anUnsignedRowRanksLastEvenWithANullInThePrecedence() {
        val rows = "[{\"id\":\"b\",\"kind\":\"forbid\",\"value\":\"true\"},{\"id\":\"a\",\"kind\":\"forbid\",\"value\":\"true\",\"signer\":\"z\"}]"
        fun cert(win: String, shadowed: String) =
            Json.parseLenient("{\"v\":1,\"kind\":\"forbid-wins\",\"clauses\":$rows,\"decision\":\"deny\",\"winner\":{\"kind\":\"forbid\",\"id\":\"$win\"},\"shadowed\":$shadowed}")
        val prec = listOf<String?>(null) as List<String>
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert("a", "[\"b\"]"), prec))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("b", "[\"a\"]"), prec))
    }

    // ---- Assurance ----

    @Test fun reportHooksAreReadByTheExactCheckName() {
        val h = Assurance.setLabel(Any(), "hardware")
        val hooks = mapOf<String, Any?>("attestation" to h, "zk" to h, "threshold" to h, "revocation" to h)
        for ((n, c) in listOf("attestation" to "attestatipO", "zk_compliance" to "zk_compliandF", "threshold" to "threshomE", "revocation" to "revocatipO")) {
            assertEquals(n.hashCode(), c.hashCode())
            assertEquals(linkedMapOf<String, Any?>("outcome" to "pass"), Assurance.report(emptyMap(), mapOf(c to "pass"), hooks = hooks)[c])
        }
        assertEquals("hardware", Assurance.report(emptyMap(), mapOf("attestation" to "pass"), hooks = hooks)["attestation"]!!["level"])
        val bare = Assurance.report(emptyMap(), mapOf("attestation" to "pass"), hooks = emptyMap())["attestation"]!!
        assertEquals(linkedMapOf<String, Any?>("outcome" to "pass", "level" to "unknown"), bare)
    }

    @Test fun aDegradedReasonIsShownOnlyWhenANonEmptyString() {
        fun deg(vararg reason: Any?): Map<String, Map<String, Any?>> {
            val e = linkedMapOf<String, Any?>("outcome" to "pass", "degraded" to true)
            if (reason.isNotEmpty()) e["reason"] = reason[0]
            return linkedMapOf("tighten" to e)
        }
        fun why(w: String) = "assurance: tighten rests on a degraded compatibility mode ($w); a high-assurance policy never accepts it"
        assertEquals(why("degraded"), Assurance.unmetAssurance(deg(), emptyMap()))
        assertEquals(why("degraded"), Assurance.unmetAssurance(deg(null), emptyMap()))
        assertEquals(why("degraded"), Assurance.unmetAssurance(deg(Json.Num("5")), emptyMap()))
        assertEquals(why("degraded"), Assurance.unmetAssurance(deg(""), emptyMap()))
        assertEquals(why("legacy"), Assurance.unmetAssurance(deg("legacy"), emptyMap()))
    }
}
