package net.atlasauth.pca.verifier

import java.io.File
import java.security.SecureRandom
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * The traits gate and the shared schema step of intent-v2.ts:614-634 (`schemaMemo ??= ...`: one step per decision), and a hybrid
 * revocation epoch through IntentRevocation.checkRevocationEpoch.
 */
class Kill05W5IntentRestTest {
    private val clockReason = "the verifier clock is not a safe integer (fail closed)"
    private val verb = "stripe.refund"
    private val params = ParityVectors.obj("""{"amount":100,"charge":"ch_1","idempotency_key":"k1"}""")

    @Suppress("UNCHECKED_CAST")
    private val allow: Map<String, Any?> by lazy {
        ParityVectors.obj(File(ParityVectors.actionsDir(), "rule22-allow.json").readText())["input"] as Map<String, Any?>
    }

    /** The v2 vector schema under the site key, with no closed-world policy: only a grant pin can start the schema step. */
    @Suppress("UNCHECKED_CAST")
    private fun openCtx(): IntentV2.Context {
        val root = "Q".repeat(43)
        val u = LinkedHashMap(allow["doc"] as Map<String, Any?>)
        u.remove("sig")
        u["pack"] = linkedMapOf("ns" to "stripe", "version" to "1", "root" to root)
        val value = IntentTestKit.sign("site", IntentJs.message(ActionSchema.ACTION_SCHEMA_DOMAIN, IntentJs.obj(IntentJs.normalize(u))))
        u["sig"] = linkedMapOf("alg" to "ed25519", "kid" to "site-1", "value" to value)
        val c = LinkedHashMap<String, Any?>()
        c["schema"] = linkedMapOf("docs" to listOf(u), "keys" to listOf(linkedMapOf("kid" to "site-1", "alg" to "ed25519", "pk" to IntentTestKit.pub("site"))))
        c["params"] = params
        if (allow["pins"] != null) c["reviewers"] = allow["pins"]
        return IntentV2.Context.fromJson(c)
    }

    private fun action() = linkedMapOf<String, Any?>(
        "aud" to "pay",
        "action" to linkedMapOf("verb" to verb, "resource" to "r", "params_digest" to Pca.paramsDigest(IntentJs.normalize(params))),
    )

    private fun grant(vararg members: Pair<String, Any?>): Map<String, Any?> {
        val env = LinkedHashMap(
            ParityVectors.obj(
                """{"type":"envelope","goal_commit":"g","caveats":[],"agent_binding":{},
                "risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0},
                "predicates":[{"verb":"*"}]}""",
            ),
        )
        env.putAll(members)
        return IntentJs.obj(IntentJs.normalize(linkedMapOf("id" to "grant-1", "issuer" to IntentTestKit.pub("issuer"), "caveats" to listOf(env))))
    }

    private fun pin() = linkedMapOf<String, Any?>("pack" to linkedMapOf("ns" to "stripe", "root" to "Q".repeat(43)), "on_new_action" to "deny")

    @Test fun withoutAPinOrAMatchedSchemaNoV2CheckRuns() {
        // intent-v2.ts:623: `out.schema?.v === 2 || (env?.actions !== undefined && ...)`: no pin never starts the schema step
        assertEquals(emptyList<String>(), IntentV2.decide(action(), grant(), openCtx(), 0L).checks.map { it.name })
    }

    @Test fun anUnsafeClockStillResolvesTheSchemaForTheTraitsGate() {
        // `run` skips the pin body on an unsafe clock, so the gate itself must run the step to see the v2 schema
        val d = IntentV2.decide(action(), grant("actions" to pin()), openCtx(), 9007199254740992L)
        assertEquals(listOf("pin", "traits"), d.checks.map { it.name })
        assertEquals(listOf(clockReason, clockReason), d.checks.map { it.reason })
    }

    // ---- SchemaMemo: the step runs at most once, and never for a schema already matched ----

    private fun newMemo(ctx: IntentV2.Context, doc: Any?): Any {
        val c = Class.forName("net.atlasauth.pca.verifier.IntentV2\$SchemaMemo").declaredConstructors.single()
        c.isAccessible = true
        return c.newInstance(emptyMap<String, Any?>(), ctx, doc)
    }

    /** A context around a `docs` list counting `isEmpty()`: schemaStep calls it exactly once per run. */
    private class Spy {
        var runs = 0
        private val docs = object : ArrayList<Any?>() {
            override fun isEmpty(): Boolean { runs++; return super.isEmpty() }
        }
        val ctx: IntentV2.Context = run {
            val raw = linkedMapOf<String, Any?>("schema" to linkedMapOf("docs" to docs, "keys" to listOf<Any?>()))
            val c = IntentV2.Context::class.java.declaredConstructors.first { it.parameterCount == 2 }
            c.isAccessible = true
            c.newInstance(raw, true) as IntentV2.Context
        }
    }

    @Test fun aMemoRunsItsStepOnce() {
        val spy = Spy()
        val memo = newMemo(spy.ctx, null)
        val none = "this verifier has no action schema configured"
        assertEquals(none, KUtil.priv<String?>(memo, "step"))
        assertEquals(none, KUtil.priv<String?>(memo, "step"))
        assertEquals(1, spy.runs)
        assertNull(KUtil.priv<Any?>(memo, "getDoc"))
    }

    @Test fun aMemoOverAMatchedSchemaNeverRunsTheStep() {
        val spy = Spy()
        val doc = linkedMapOf<String, Any?>("v" to 2L)
        val memo = newMemo(spy.ctx, doc)
        assertSame(doc, KUtil.priv<Any?>(memo, "getDoc"))
        assertNull(KUtil.priv<String?>(memo, "step"))
        assertEquals(0, spy.runs)
        assertSame(doc, KUtil.priv<Any?>(memo, "getDoc"))
    }

    // ---- a hybrid epoch verifies under the pin with its own pq_pk and pq_sig ----

    @Test fun aHybridRevocationEpochVerifiesUnderThePin() {
        val now = 1_800_000_000_000L
        val guard = IntentTestKit.pub("w5/rev")
        val g = MLDSAKeyPairGenerator()
        g.init(MLDSAKeyGenerationParameters(SecureRandom(), MLDSAParameters.ml_dsa_65))
        val kp = g.generateKeyPair()
        val pqPk = Pca.b64((kp.public as MLDSAPublicKeyParameters).encoded)
        val signed = linkedMapOf<String, Any?>(
            "instance_id" to "ana", "grant_ref" to "g1", "epoch" to IntentJs.ofLong(0), "set_size" to IntentJs.ofLong(0),
            "root" to IntentRevocation.revsetRoot(listOf()), "issued_at" to IntentJs.ofLong(now - 1000), "not_after" to IntentJs.ofLong(now + 1000),
            "alg" to "hybrid-ed25519-ml-dsa-65", "pq_pk" to pqPk,
        )
        val msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.toByteArray(Charsets.UTF_8), IntentJs.canonBytes(signed))
        val s = MLDSASigner()
        s.init(true, kp.private)
        s.update(msg, 0, msg.size)
        val ep = LinkedHashMap(signed)
        ep["guardian"] = guard
        ep["sig"] = IntentTestKit.sign("w5/rev", msg)
        ep["pq_sig"] = Pca.b64(s.generateSignature())
        val pins = mapOf<String, Any?>(guard to pqPk)
        fun chk(e: Map<String, Any?>, p: Map<String, Any?>?) = IntentRevocation.checkRevocationEpoch(e, guard, now.toDouble(), "g1", p)
        assertNull(chk(ep, pins))
        val invalid = "revocation epoch signature invalid"
        assertEquals(invalid, chk(ep, null))
        assertEquals(invalid, chk(LinkedHashMap(ep).also { it.remove("pq_sig") }, pins))
    }
}
