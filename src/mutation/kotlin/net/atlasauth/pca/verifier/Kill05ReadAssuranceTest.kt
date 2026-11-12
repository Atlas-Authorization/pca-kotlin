package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for Assurance.kt, pinned to packages/pca/src/assurance.ts: labels and their lookup, the multi-root level
 * (quorum fill, required roots, the weakest root, unlabelled and unranked roots), signature levels and the weakest suite of a
 * chain, whole reports for every check kind (hooks, suites, threshold t, unbound PQ, degraded, bond, and the hooks == null
 * unsupported conversions of this SDK), the @JvmOverloads entry points, and every reason unmetAssurance gives.
 */
@Suppress("UNCHECKED_CAST")
class Kill05ReadAssuranceTest {
    private fun hook(level: String, vendor: String? = null, awaitingAudit: Boolean? = null, ceremony: String? = null): Any =
        Assurance.setLabel(Any(), level, vendor, awaitingAudit, ceremony)

    private fun canon(v: Any?) = Json.canonicalize(v)

    private fun rep(
        p: Map<String, Any?>?, checks: Map<String, String>, degraded: Map<String, String>? = null, hooks: Map<String, Any?>? = null,
        attestationHook: Any? = null, thresholdT: Any? = null, allowUnboundPq: Boolean = false,
    ) = canon(Assurance.report(p, checks, degraded, hooks, attestationHook, thresholdT, allowUnboundPq))

    private fun checks(vararg kv: String): LinkedHashMap<String, String> {
        val m = LinkedHashMap<String, String>()
        var i = 0
        while (i < kv.size) { m[kv[i]] = kv[i + 1]; i += 2 }
        return m
    }

    // ---- labels ----

    @Test
    fun labels() {
        val t = Any()
        assertSame(t, Assurance.setLabel(t, "hardware", "v", true, "c"))
        val l = Assurance.labelOf(t)!!
        assertEquals(listOf<Any?>("hardware", "v", true, "c"), listOf(l.level, l.vendor, l.awaitingAudit, l.ceremony))
        val plain = Assurance.labelOf(Assurance.setLabel(Any(), "software"))!!
        assertEquals(listOf<Any?>("software", null, null, null), listOf(plain.level, plain.vendor, plain.awaitingAudit, plain.ceremony))
        assertNull(Assurance.labelOf(null))
        assertNull(Assurance.labelOf(Any()))
        val own = Assurance.Label("multi_root", "x")
        val labelled = object : Assurance.Labeled {
            override val assuranceLabel: Assurance.Label? = own
        }
        assertSame(own, Assurance.labelOf(labelled))
        val none = object : Assurance.Labeled {
            override val assuranceLabel: Assurance.Label? = null
        }
        assertNull(Assurance.labelOf(none))
        for (s in listOf("frost", "frost_dkg", "mpc")) assertTrue(s, Assurance.isAwaitingAuditScheme(s))
        for (s in listOf("multisig", "unknown", "")) assertFalse(s, Assurance.isAwaitingAuditScheme(s))
        assertFalse(Assurance.isAwaitingAuditScheme(null))
    }

    // ---- the multi-root level ----

    @Test
    fun multiRootLevels() {
        val hw = hook("hardware")
        val sw = hook("software")
        val mr = hook("multi_root")
        val none = hook("unknown")
        val bogus = hook("bogus")
        val unlabelled = Any()
        fun lv(t: Double, vararg r: Assurance.Root) = Assurance.multiRootLevel(r.toList(), t)
        fun opt(v: Any) = Assurance.Root(v)
        fun req(v: Any) = Assurance.Root(v, true)
        // optional roots fill the quorum weakest first, whatever their order
        assertEquals("software", lv(1.0, opt(hw), opt(sw)))
        assertEquals("software", lv(1.0, opt(sw), opt(hw)))
        assertEquals("hardware", lv(2.0, opt(hw), opt(sw)))
        assertEquals("multi_root", lv(2.0, opt(hw), opt(mr)))
        assertEquals("hardware", lv(5.0, opt(hw), opt(sw)))
        // more required roots than the threshold: no optional root is added (and no error)
        assertEquals("multi_root", lv(1.0, req(hw), req(hw), opt(sw)))
        assertEquals("hardware", lv(1.0, req(hw), req(sw)))
        // a required root is never counted again among the optional ones
        assertEquals("hardware", lv(2.0, req(sw), opt(hw)))
        // with no hardware root the level is the weakest chosen root: unknown, unlabelled and unranked roots rank 0
        assertEquals("unknown", lv(2.0, req(none), req(sw)))
        assertEquals("unknown", lv(2.0, req(sw), req(none)))
        assertEquals("unknown", lv(2.0, req(sw), req(sw), req(none)))
        assertEquals("unknown", lv(1.0, req(none)))
        assertEquals("software", lv(1.0, req(sw)))
        assertEquals("unknown", lv(1.0, opt(bogus)))
        assertEquals("unknown", lv(1.0, opt(unlabelled)))
        assertEquals("unknown", lv(2.0, opt(none), opt(bogus)))
        // a fractional remainder rounds down: no optional root, no roots at all
        assertEquals("software", lv(0.5, opt(sw), opt(none)))
        assertEquals("software", lv(1.0))
    }

    @Test
    fun signatureLevels() {
        assertEquals("ed25519", Assurance.signatureLevel(null))
        assertEquals("ed25519", Assurance.signatureLevel("ed25519"))
        assertEquals("unknown", Assurance.signatureLevel(Json.Num("1")))
        assertEquals("unknown", Assurance.signatureLevel("foo"))
        assertEquals("pq", Assurance.signatureLevel("ml-dsa-65"))
        assertEquals("pq", Assurance.signatureLevel("fn-dsa-512"))
        assertEquals("hybrid", Assurance.signatureLevel("hybrid-ed25519-ml-dsa-65"))
    }

    // ---- the report ----

    @Test
    fun hookLevels() {
        val hooks = jm(
            "attestation", hook("software"), "zk", hook("groth16", "z", null, "multi-party"), "threshold", hook("frost"),
            "revocation", hook("hardware", "r", true),
        )
        assertEquals(
            canon(
                jm(
                    "attestation", jm("outcome", "pass", "level", "hardware", "vendor", "amd"),
                    "zk_compliance", jm("outcome", "pass", "level", "groth16", "vendor", "z", "ceremony", "multi-party"),
                    "threshold", jm("outcome", "pass", "level", "frost", "awaiting_audit", true),
                    "revocation", jm("outcome", "pass", "level", "hardware", "vendor", "r", "awaiting_audit", true),
                    "other", jm("outcome", "pass"), "failing", jm("outcome", "fail"),
                    "missing", jm("outcome", "unsupported", "reason", "missing is not implemented by this verifier"),
                ),
            ),
            rep(
                null, checks("attestation", "pass", "zk_compliance", "pass", "threshold", "pass", "revocation", "pass", "other", "pass", "failing", "fail", "missing", "unsupported"),
                hooks = hooks, attestationHook = hook("hardware", "amd", null, "ignored"),
            ),
        )
        // no hook: attestation and zk are unknown, threshold and the rest carry no level; an unlabelled hook is unknown
        assertEquals(
            canon(jm("attestation", jm("outcome", "pass", "level", "software"), "zk_compliance", jm("outcome", "pass", "level", "unknown"), "threshold", jm("outcome", "pass"), "revocation", jm("outcome", "pass"))),
            rep(null, checks("attestation", "pass", "zk_compliance", "pass", "threshold", "pass", "revocation", "pass"), hooks = jm("attestation", hook("software"), "revocation", Any())),
        )
        assertEquals(
            canon(jm("threshold", jm("outcome", "pass", "level", "unknown"), "attestation", jm("outcome", "fail"), "zk_compliance", jm("outcome", "pass", "level", "unknown"))),
            rep(null, checks("threshold", "pass", "attestation", "fail", "zk_compliance", "pass"), hooks = jm("threshold", Any(), "zk", Any()), attestationHook = hook("hardware")),
        )
        assertEquals(
            canon(jm("attestation", jm("outcome", "pass", "level", "software", "awaiting_audit", true), "threshold", jm("outcome", "pass", "level", "multisig"), "revocation", jm("outcome", "pass", "level", "hardware"))),
            rep(null, checks("attestation", "pass", "threshold", "pass", "revocation", "pass"), hooks = jm("threshold", hook("multisig"), "revocation", hook("hardware", null, false)), attestationHook = hook("software", null, true)),
        )
        // the zk ceremony is reported for zk only; awaiting_audit false is not reported
        assertEquals(
            canon(jm("zk_compliance", jm("outcome", "pass", "level", "stark"), "attestation", jm("outcome", "pass", "level", "hardware"))),
            rep(null, checks("zk_compliance", "pass", "attestation", "pass"), hooks = jm("zk", hook("stark", null, false), "attestation", hook("hardware", null, null, "c"))),
        )
    }

    @Test
    fun thresholdT() {
        fun t(v: Any?) = (Assurance.report(null, checks("threshold", "pass"), null, jm("threshold", hook("multisig")), null, v)["threshold"] as Map<String, Any?>)
        assertEquals(Json.Num("3"), t(Json.Num("3"))["t"])
        assertEquals(2.5, t(2.5)["t"])
        assertEquals(3L, t(3L)["t"])
        assertFalse(t("3").containsKey("t"))
        assertFalse(t(true).containsKey("t"))
        assertFalse(t(null).containsKey("t"))
        // no threshold hook: no level and no t
        assertEquals(canon(jm("threshold", jm("outcome", "pass"))), rep(null, checks("threshold", "pass"), hooks = jm(), thresholdT = 2L))
    }

    @Test
    fun signatureSuites() {
        assertEquals(canon(jm("leaf_signature", jm("outcome", "pass"), "cap_chain", jm("outcome", "pass"))), rep(null, checks("leaf_signature", "pass", "cap_chain", "pass")))
        val suites = jl("bogus", "ed25519", "ed25519", "hybrid-ed25519-ml-dsa-65")
        assertEquals(
            canon(
                jm(
                    "leaf_signature", jm("outcome", "pass", "suites", jl("ed25519"), "level", "ed25519"),
                    "cap_chain", jm("outcome", "pass", "suites", suites, "level", "unknown"),
                    "chain", jm("outcome", "pass", "suites", suites, "level", "unknown"),
                    "other", jm("outcome", "fail"), "replay", jm("outcome", "pass"),
                ),
            ),
            rep(
                jm("cap_chain", jl(jm("alg", "bogus"), jm(), "x", jm("alg", "hybrid-ed25519-ml-dsa-65"))),
                checks("leaf_signature", "pass", "cap_chain", "pass", "chain", "pass", "other", "fail", "replay", "pass"),
            ),
        )
        fun chainLevel(c: List<Any?>) = (Assurance.report(jm("alg", "ml-dsa-65", "cap_chain", c), checks("cap_chain", "pass"))["cap_chain"] as Map<String, Any?>)["level"]
        assertEquals("hybrid", chainLevel(jl(jm("alg", "ml-dsa-65"), jm("alg", "hybrid-ed25519-ml-dsa-65"))))
        assertEquals("pq", chainLevel(jl(jm("alg", "ml-dsa-65"), jm("alg", "slh-dsa-sha2-128f"))))
        assertEquals("ed25519", chainLevel(jl(jm("alg", "hybrid-ed25519-ml-dsa-65"), jm())))
        assertEquals("unknown", chainLevel(jl()))
        assertEquals("unknown", chainLevel(jl(jm("alg", "bogus"), jm("alg", "ml-dsa-65"))))
        assertEquals("unknown", chainLevel(jl(jm("alg", "bogus"), jm())))
        assertEquals("unknown", chainLevel(jl(jm("alg", "hybrid-ed25519-ml-dsa-65"), jm("alg", "bogus"))))
        // a chain that is not a list carries no suites; a non-string alg is printed as JavaScript prints it
        assertEquals(
            canon(jm("cap_chain", jm("outcome", "pass"), "leaf_signature", jm("outcome", "pass", "suites", jl("5"), "level", "unknown"))),
            rep(jm("cap_chain", "x", "alg", Json.Num("5")), checks("cap_chain", "pass", "leaf_signature", "pass")),
        )
        assertEquals(
            canon(jm("leaf_signature", jm("outcome", "pass", "suites", jl("2.5"), "level", "unknown"))),
            rep(jm("alg", Json.Num("2.50")), checks("leaf_signature", "pass")),
        )
        // the unbound-PQ compatibility mode: only a non-Ed25519 suite is reported as unbound
        assertEquals(
            canon(jm("leaf_signature", jm("outcome", "pass", "suites", jl("ed25519"), "level", "ed25519"), "cap_chain", jm("outcome", "pass", "suites", jl("ed25519", "ed25519"), "level", "ed25519"))),
            rep(jm("alg", "ed25519", "cap_chain", jl(jm(), jm("alg", "ed25519"))), checks("leaf_signature", "pass", "cap_chain", "pass"), allowUnboundPq = true),
        )
        assertEquals(
            canon(jm("leaf_signature", jm("outcome", "pass", "suites", jl("ml-dsa-65"), "level", "unbound_pq"), "cap_chain", jm("outcome", "pass", "suites", jl("ed25519", "ml-dsa-65"), "level", "unbound_pq"))),
            rep(jm("alg", "ml-dsa-65", "cap_chain", jl(jm(), jm("alg", "ml-dsa-65"))), checks("leaf_signature", "pass", "cap_chain", "pass"), allowUnboundPq = true),
        )
        assertEquals(
            canon(jm("leaf_signature", jm("outcome", "pass", "suites", jl("ed25519"), "level", "ed25519"), "cap_chain", jm("outcome", "pass", "suites", jl(), "level", "unknown"))),
            rep(jm("cap_chain", jl()), checks("leaf_signature", "pass", "cap_chain", "pass"), allowUnboundPq = true),
        )
    }

    /** With no hooks (the authorize path) this SDK reports what it does not verify as unsupported. */
    @Test
    fun theHooklessUnsupportedConversions() {
        val noBackend = "fn-dsa-512" // registered, never implemented here
        assertEquals(
            canon(jm("leaf_signature", jm("outcome", "unsupported", "reason", "signature suite 'fn-dsa-512' has no backend in this runtime"))),
            rep(jm("alg", noBackend), checks("leaf_signature", "fail")),
        )
        for (alg in listOf<Any?>("ml-dsa-65", "bogus", Json.Num("5"))) {
            assertEquals("$alg", canon(jm("leaf_signature", jm("outcome", "fail"))), rep(jm("alg", alg), checks("leaf_signature", "fail")))
        }
        assertEquals(canon(jm("leaf_signature", jm("outcome", "fail"))), rep(jm(), checks("leaf_signature", "fail")))
        // only when the check failed, and only without hooks
        assertEquals(canon(jm("leaf_signature", jm("outcome", "not-enforced"))), rep(jm("alg", noBackend), checks("leaf_signature", "not-enforced")))
        assertEquals(canon(jm("leaf_signature", jm("outcome", "fail"))), rep(jm("alg", noBackend), checks("leaf_signature", "fail"), hooks = jm()))
        val chainGone = canon(jm("chain", jm("outcome", "unsupported", "reason", "a capability suite has no backend in this runtime")))
        assertEquals(chainGone, rep(jm("cap_chain", jl(jm(), jm("alg", noBackend))), checks("chain", "fail")))
        assertEquals(canon(jm("chain", jm("outcome", "fail"))), rep(jm("cap_chain", jl(jm(), jm("alg", "ml-dsa-65"))), checks("chain", "fail")))
        assertEquals(canon(jm("chain", jm("outcome", "fail"))), rep(jm("cap_chain", jl()), checks("chain", "fail")))
        assertEquals(canon(jm("cap_chain", jm("outcome", "fail"))), rep(jm("cap_chain", jl(jm("alg", noBackend))), checks("cap_chain", "fail")))
        assertEquals(canon(jm("chain", jm("outcome", "fail"))), rep(jm("cap_chain", jl(jm("alg", noBackend))), checks("chain", "fail"), hooks = jm()))
        // carried zk / threshold evidence and a failed attestation
        assertEquals(
            canon(
                jm(
                    "attestation", jm("outcome", "unsupported", "reason", "attestation verification is not implemented by this SDK"),
                    "zk_compliance", jm("outcome", "unsupported", "reason", "zk compliance verification is not implemented by this SDK"),
                    "threshold", jm("outcome", "unsupported", "reason", "threshold co-signatures are not verified by this SDK"),
                ),
            ),
            rep(jm("zk_compliance", null, "threshold", null), checks("attestation", "fail")),
        )
        assertEquals(canon(jm("attestation", jm("outcome", "pass", "level", "unknown"))), rep(jm(), checks("attestation", "pass")))
        assertEquals(canon(jm("attestation", jm("outcome", "fail"))), rep(jm("zk_compliance", null, "threshold", null), checks("attestation", "fail"), hooks = jm()))
        assertEquals(canon(jm("x", jm("outcome", "pass"))), rep(null, checks("x", "pass")))
    }

    @Test
    fun degradedAndBond() {
        val bond = jm("outcome", "unsupported", "reason", "bond verification is not implemented by this verifier")
        assertEquals(
            canon(jm("a", jm("outcome", "pass", "degraded", true, "reason", "why"), "b", jm("outcome", "fail"), "bond", bond)),
            rep(jm("bond_ref", null), checks("a", "pass", "b", "fail"), degraded = mapOf("a" to "why", "b" to "no", "c" to "absent")),
        )
        assertEquals(canon(jm("bond", bond)), rep(jm("bond_ref", "x"), checks(), hooks = jm()))
        assertEquals(canon(jm("a", jm("outcome", "pass"))), rep(jm(), checks("a", "pass"), degraded = mapOf()))
        assertEquals(canon(jm("a", jm("outcome", "pass"))), rep(null, checks("a", "pass")))
    }

    /** The Java-facing @JvmOverloads entry points each answer the full report. */
    @Test
    fun jvmOverloads() {
        val m = Map::class.java
        val o = Any::class.java
        val shapes = listOf(arrayOf(m, m), arrayOf(m, m, m), arrayOf(m, m, m, m), arrayOf(m, m, m, m, o), arrayOf(m, m, m, m, o, o))
        for (s in shapes) {
            val method = Assurance::class.java.getMethod("report", *s)
            val args = arrayOfNulls<Any?>(s.size)
            args[1] = checks("x", "pass", "attestation", "pass")
            val got = method.invoke(Assurance, *args)
            assertEquals("${s.size}", canon(jm("x", jm("outcome", "pass"), "attestation", jm("outcome", "pass", "level", "unknown"))), canon(got))
        }
    }

    // ---- unmetAssurance ----

    private fun pass(level: Any? = null): Map<String, Any?> = if (level == null) jm("outcome", "pass") else jm("outcome", "pass", "level", level)

    private fun unmet(report: Map<String, Any?>, require: Map<String, Any?>) = Assurance.unmetAssurance(report as Map<String, Map<String, Any?>>, require)

    private val notBound = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence"

    @Test
    fun unmetPrecedenceAndRequirementErrors() {
        assertEquals("assurance: unsupported: x (why); a high-assurance policy never accepts it", unmet(jm("n", pass(), "x", jm("outcome", "unsupported", "reason", "why")), jm()))
        assertEquals("assurance: unsupported: x (not implemented); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "unsupported")), jm()))
        assertEquals("assurance: unsupported: x (not implemented); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "unsupported", "reason", "")), jm()))
        assertEquals("assurance: unsupported: x (not implemented); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "unsupported", "reason", Json.Num("5"))), jm()))
        assertEquals("assurance: unsupported: x (w); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "unsupported", "reason", "w")), jm()))
        // unsupported wins over degraded wherever it sits
        assertEquals(
            "assurance: unsupported: u (a); a high-assurance policy never accepts it",
            unmet(jm("d", jm("outcome", "pass", "degraded", true, "reason", "b"), "u", jm("outcome", "unsupported", "reason", "a")), jm()),
        )
        assertEquals(
            "assurance: x rests on a degraded compatibility mode (why); a high-assurance policy never accepts it",
            unmet(jm("n", pass(), "f", jm("outcome", "fail", "degraded", true), "x", jm("outcome", "pass", "degraded", true, "reason", "why")), jm()),
        )
        assertEquals("assurance: x rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "pass", "degraded", true)), jm()))
        assertEquals("assurance: x rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "pass", "degraded", true, "reason", "")), jm()))
        assertEquals("assurance: x rests on a degraded compatibility mode (d); a high-assurance policy never accepts it", unmet(jm("x", jm("outcome", "pass", "degraded", true, "reason", "d")), jm()))
        assertNull(unmet(jm("x", jm("outcome", "pass", "degraded", "true")), jm()))
        assertNull(unmet(jm(), jm()))
        assertEquals("assurance: unknown assurance requirement(s): a, b (fail closed)", unmet(jm(), jm("b", 1L, "zk", "proof", "a", 2L)))
        assertEquals("assurance: unknown assurance requirement(s): z (fail closed)", unmet(jm(), jm("z", null)))
        assertEquals("assurance: unknown attestation requirement 'bogus' (fail closed)", unmet(jm(), jm("attestation", "bogus")))
        assertEquals("assurance: unknown attestation requirement 5 (fail closed)", unmet(jm(), jm("attestation", Json.Num("5"))))
        assertEquals("assurance: unknown zk requirement 'bogus' (fail closed)", unmet(jm(), jm("zk", "bogus")))
        assertEquals("assurance: unknown zk requirement true (fail closed)", unmet(jm(), jm("zk", true)))
        assertEquals("assurance: unknown signature requirement 'classic' (fail closed)", unmet(jm(), jm("signature", "classic")))
        assertEquals("assurance: unknown signature requirement 1 (fail closed)", unmet(jm(), jm("signature", Json.Num("1"))))
        assertEquals("assurance: unknown threshold requirement 'x' (fail closed)", unmet(jm(), jm("threshold", "x")))
        assertEquals("assurance: unknown threshold requirement 5 (fail closed)", unmet(jm(), jm("threshold", Json.Num("5"))))
        assertEquals("assurance: unknown threshold requirement a,1 (fail closed)", unmet(jm(), jm("threshold", jl("a", Json.Num("1")))))
        // an empty scheme list is a valid (unsatisfiable) requirement
        assertEquals("assurance: threshold () required but there is no threshold evidence", unmet(jm(), jm("threshold", jl())))
        // the evidence-free requirement keys alone are met
        assertNull(unmet(jm(), jm("allowAwaitingAudit", true, "allow_awaiting_audit", false, "allowPreview", false, "allow_preview", false)))
    }

    @Test
    fun unmetAttestation() {
        fun att(l: String) = jm("attestation", l)
        assertEquals("assurance: software attestation required but there is no attestation evidence", unmet(jm(), att("software")))
        assertEquals("assurance: hardware attestation required but the attestation check is fail", unmet(jm("attestation", jm("outcome", "fail")), att("hardware")))
        assertEquals("assurance: hardware attestation required but the evidence is unknown", unmet(jm("attestation", pass(Json.Num("2"))), att("hardware")))
        assertEquals("assurance: hardware attestation required but the evidence is unknown", unmet(jm("attestation", pass()), att("hardware")))
        assertEquals("assurance: software attestation required but the evidence is bogus", unmet(jm("attestation", pass("bogus")), att("software")))
        assertEquals("assurance: hardware attestation required but the evidence is software", unmet(jm("attestation", pass("software")), att("hardware")))
        assertEquals("assurance: multi_root attestation required but the evidence is hardware", unmet(jm("attestation", pass("hardware")), att("multi_root")))
        assertNull(unmet(jm("attestation", pass("multi_root")), att("multi_root")))
        assertNull(unmet(jm("attestation", pass("hardware")), att("hardware")))
        assertNull(unmet(jm("attestation", pass("software")), att("software")))
        assertNull(unmet(jm("attestation", pass("multi_root")), att("software")))
    }

    @Test
    fun unmetZk() {
        fun zk(l: String) = jm("zk", l)
        fun ev(l: Any?) = jm("zk_compliance", pass(l))
        assertEquals(notBound, unmet(ev("attested_vm"), zk("attested_vm_hardware")))
        assertEquals(notBound, unmet(ev(null), zk("attested_vm_hardware")))
        assertEquals(notBound, unmet(ev("unknown"), zk("attested_vm_hardware")))
        assertNull(unmet(ev("attested_vm_hw"), zk("attested_vm_hardware")))
        assertNull(unmet(ev("stark"), zk("attested_vm_hardware")))
        assertEquals("assurance: zk compliance (attested_vm_hardware) required but the evidence is bogus", unmet(ev("bogus"), zk("attested_vm_hardware")))
        assertNull(unmet(ev("attested_vm"), zk("attested_vm")))
        assertEquals("assurance: zk compliance (attested_vm) required but the evidence is unknown", unmet(ev(null), zk("attested_vm")))
        assertEquals("assurance: zk compliance (attested_vm) required but the evidence is bogus", unmet(ev("bogus"), zk("attested_vm")))
        assertNull(unmet(ev("zkvm"), zk("proof")))
        assertNull(unmet(ev("stark"), zk("proof")))
        assertEquals("assurance: zk compliance (proof) required but the evidence is attested_vm_hw", unmet(ev("attested_vm_hw"), zk("proof")))
        assertEquals("assurance: zk compliance (snark) required but the evidence is stark", unmet(ev("stark"), zk("snark")))
        assertNull(unmet(ev("groth16"), zk("snark")))
        assertNull(unmet(ev("policyvm_snark"), zk("snark")))
        assertEquals("assurance: zk compliance (snark) required but there is no zk_compliance evidence", unmet(jm(), zk("snark")))
        assertEquals("assurance: zk compliance (proof) required but the zk_compliance check is not-enforced", unmet(jm("zk_compliance", jm("outcome", "not-enforced")), zk("proof")))
    }

    @Test
    fun unmetSignature() {
        val pq = jm("signature", "pq")
        assertNull(unmet(jm("leaf_signature", pass("pq"), "chain", pass("hybrid")), pq))
        assertNull(unmet(jm("leaf_signature", pass("hybrid"), "cap_chain", pass("pq"), "chain", pass("ed25519")), pq))
        assertEquals("assurance: post-quantum signatures required but there is no cap_chain evidence", unmet(jm("leaf_signature", pass("pq")), pq))
        assertEquals("assurance: post-quantum signatures required but there is no leaf_signature evidence", unmet(jm("cap_chain", pass("pq")), pq))
        assertEquals("assurance: post-quantum signatures required but leaf_signature is ed25519", unmet(jm("leaf_signature", pass("ed25519"), "cap_chain", pass("pq")), pq))
        assertEquals("assurance: post-quantum signatures required but leaf_signature is unknown", unmet(jm("leaf_signature", pass(), "cap_chain", pass("pq")), pq))
        assertEquals("assurance: post-quantum signatures required but chain is unbound_pq", unmet(jm("leaf_signature", pass("pq"), "chain", pass("unbound_pq")), pq))
        assertEquals("assurance: post-quantum signatures required but the cap_chain check is fail", unmet(jm("leaf_signature", pass("pq"), "cap_chain", jm("outcome", "fail")), pq))
    }

    @Test
    fun unmetThresholdAndAwaitingAudit() {
        val frost = jm("threshold", jl("frost", "mpc"))
        assertEquals("assurance: threshold (frost | mpc) required but there is no threshold evidence", unmet(jm(), frost))
        assertEquals("assurance: threshold (frost | mpc) required but the threshold check is fail", unmet(jm("threshold", jm("outcome", "fail")), frost))
        assertEquals("assurance: threshold (frost | mpc) required but no threshold verifier enforced it", unmet(jm("threshold", pass()), frost))
        assertEquals("assurance: threshold (frost | mpc) required but no threshold verifier enforced it", unmet(jm("threshold", pass(Json.Num("5"))), frost))
        assertEquals("assurance: threshold (frost | mpc) required but the scheme is multisig", unmet(jm("threshold", pass("multisig")), frost))
        assertNull(unmet(jm("threshold", pass("mpc")), frost))
        // a listed scheme awaiting audit is accepted; the same level on another check is still reported
        val thr = jm("outcome", "pass", "level", "frost", "awaiting_audit", true)
        assertNull(unmet(jm("threshold", thr), frost))
        assertEquals(
            "assurance: zk_compliance rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            unmet(jm("threshold", thr, "zk_compliance", jm("outcome", "pass", "level", "frost", "awaiting_audit", true)), frost),
        )
        val awaiting = "assurance: threshold rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it"
        assertEquals(awaiting, unmet(jm("threshold", thr), jm()))
        for (k in listOf("allowAwaitingAudit", "allow_awaiting_audit", "allowPreview", "allow_preview")) {
            assertNull(k, unmet(jm("threshold", thr), jm(k, true)))
            assertEquals(k, awaiting, unmet(jm("threshold", thr), jm(k, "true")))
            assertEquals(k, awaiting, unmet(jm("threshold", thr), jm(k, false)))
        }
        // the camelCase key, when present, decides over the snake_case one
        assertEquals(awaiting, unmet(jm("threshold", thr), jm("allowAwaitingAudit", false, "allow_awaiting_audit", true)))
        assertNull(unmet(jm("threshold", thr), jm("allowAwaitingAudit", true, "allow_awaiting_audit", false)))
        // the preview flag counts; a failed check and a string flag do not
        assertEquals(
            "assurance: p rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it",
            unmet(jm("n", pass(), "f", jm("outcome", "fail", "awaiting_audit", true), "s", jm("outcome", "pass", "awaiting_audit", "true"), "p", jm("outcome", "pass", "preview", true)), jm()),
        )
        // the list exempts only the threshold check, never another check awaiting audit
        val listed = jm("threshold", jm("outcome", "pass", "level", "frost", "awaiting_audit", true), "x", jm("outcome", "pass", "level", "mpc", "preview", true))
        assertEquals("assurance: x rests on crypto awaiting audit (mpc); set allowAwaitingAudit or list the scheme to accept it", unmet(listed, jm("threshold", jl("frost"))))
    }
}
