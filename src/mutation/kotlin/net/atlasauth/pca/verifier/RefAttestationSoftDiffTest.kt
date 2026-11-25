package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The software attestation layer against the reference (ref-attestation-soft, 512 cases): the binding hash, the dev attestor and its documents
 * (signature bytes compare under Ed25519, ML-DSA-65 and the hybrid suites), the document registry, the bounded nonce store and the entropy gate,
 * the agent-binding match, verification and its hook, the multi-root verifier and evidence anchoring. A hardware verifier is a constant
 * ({result} or {throws}). A reason that starts with the fail-closed prefix carries the reference's own exception text: compared by prefix.
 * The two cases the reference accepts only through its legacy `allowUnboundPq` option are asserted refused (the option is not offered).
 */
@Suppress("UNCHECKED_CAST")
class RefAttestationSoftDiffTest {
    private val mod = "ref-attestation-soft"
    private val prefix = "attestation verification error (fail closed):"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun signer(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun hw(h: Any?): Attestation.HardwareVerifier? = if (h == null) null else Attestation.HardwareVerifier {
        val m = map(h)
        if (m["throws"] != null) throw RuntimeException(m["throws"] as String)
        m["result"]
    }

    private fun pre(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = if (k == "reason" && x is String && x.startsWith(prefix)) prefix else pre(x) }
        is List<*> -> v.map { pre(it) }
        else -> v
    }

    private fun clockOf(x: Any?): Double = IntentJs.num(x) ?: Double.NaN

    private fun nonceStore(a: List<Any?>): Any? {
        var t = 0.0
        val opts = arg(a, 1) as Map<String, Any?>?
        val st = Attestation.memoryNonceStore(a[0], opts?.get("retentionMs"), { t })
        return (a[2] as List<Any?>).map { op ->
            val x = op as List<Any?>
            if (x[0] == "clock") { t = clockOf(x[1]); null } else st.consume(x[1])
        }
    }

    private fun hook(a: List<Any?>): Any? {
        val op = map(a[0])
        val o = Attestation.VerifierOptions()
        val now = clockOf(op["now"])
        o.trustedAttestorKeys = op["trustedAttestorKeys"]
        o.minNonceBytes = op["minNonceBytes"]
        o.maxNonceAgeMs = op["maxNonceAgeMs"]
        o.clockSkewMs = op["clockSkewMs"]
        o.pqPins = op["pqPins"] as Map<String, Any?>?
        o.insecureSelfDeclaredNonce = op["insecure_selfDeclaredNonce"] == true
        o.now = { now }
        o.hardwareVerifier = hw(op["hardware"])
        o.resolveDocument = Attestation.attestationRegistry(op["docs"] ?: emptyList<Any?>())
        val store = op["store"] as Map<String, Any?>?
        if (store != null) { val t = now; o.nonceStore = Attestation.memoryNonceStore(store["max"], store["retentionMs"], { t }) }
        if (op.containsKey("storeConsume")) { val c = op["storeConsume"] == true; o.nonceStore = Attestation.NonceStore { c } }
        val binding = op["binding"]
        if (binding == "throws") o.expectedBinding = { throw RuntimeException("boom") }
        else if (binding != null) o.expectedBinding = { ctx ->
            val q = ((((ctx as? Map<*, *>)?.get("pcactn") as? Map<*, *>)?.get("attestation")) as? Map<*, *>)?.let { if (it.containsKey("quote_digest")) it["quote_digest"] else ZkJs.UNDEF } ?: ZkJs.UNDEF
            (map(map(binding)["byNonce"]))[ZkJs.string(q)]
        }
        val h = Attestation.createAttestationVerifier(o)
        return (a[1] as List<Any?>).map { h(it) }
    }

    private fun multiRoot(a: List<Any?>): Any? {
        val pol = map(a[0])
        val rawRoots = pol["roots"] as? List<Any?> ?: emptyList()
        val roots = rawRoots.map { r ->
            val m = r as? Map<String, Any?>
            val id = m?.get("id")
            Attestation.Root(if (id is String) id else "", hw(m?.get("hw")) ?: Attestation.HardwareVerifier { null }, m?.get("required") == true, m?.get("suite") as String?)
        }
        val v = Attestation.createMultiRootVerifier(roots, IntentJs.num(pol["threshold"]) ?: Double.NaN)
        val inp = arg(a, 1) ?: return linkedMapOf("built" to true)
        return v.verify(map(inp))
    }

    private fun anchor(a: List<Any?>): Any? {
        val op = map(a[1])
        val o = Attestation.AnchorOptions()
        if (op["ledger"] == "ok") o.ledger = MerkleLog().also { l -> for (i in 0 until (IntentJs.num(op["preload"])?.toInt() ?: 0)) l.appendCommitment("c$i") }
        o.principal = op["principal"] as String? ?: ""
        if (op["guardianSeed"] != null) o.guardian = Keys.ed25519(Keys.edFromSeed(seed(op["guardianSeed"])))
        o.instanceId = op["instanceId"] as String?
        if (op.containsKey("now")) { val n = clockOf(op["now"]); o.now = { n } }
        o.required = op["required"] == true
        return Attestation.anchorAttestationEvidence(a[0], o)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "ATTEST_BIND_DOMAIN" to Attestation.ATTEST_BIND_DOMAIN, "MAX_ATTESTATION_AGE_MS" to Attestation.MAX_ATTESTATION_AGE_MS,
            "DEFAULT_NONCE_RETENTION_MS" to Attestation.DEFAULT_NONCE_RETENTION_MS, "MIN_ATTESTATION_NONCE_BYTES" to Attestation.MIN_ATTESTATION_NONCE_BYTES,
            "ATTEST_ANCHOR_DOMAIN" to Attestation.ATTEST_ANCHOR_DOMAIN,
        )
        "attestationBinding" -> Attestation.attestationBinding(a[0])
        "attestationBindingB64u" -> Attestation.attestationBindingB64u(a[0])
        "attest" -> Attestation.createDevAttestor(signer(a[0], arg(a, 1))).attest(map(a[2]))
        "attestorPublicKey" -> Attestation.createDevAttestor(signer(a[0], arg(a, 1))).publicKey
        "attestationDigest" -> Attestation.attestationDigest(a[0])
        "registry" -> {
            val r = Attestation.attestationRegistry(a[0])
            (a[1] as List<Any?>).map { q -> r(linkedMapOf("pcactn" to linkedMapOf("attestation" to linkedMapOf("quote_digest" to q)))) }
        }
        "nonceStore" -> nonceStore(a)
        "nonceEntropyOk" -> Attestation.nonceEntropyOk(a[0], arg(a, 1))
        "requiresAttestation" -> Attestation.requiresAttestation(arg(a, 0))
        "nonceBinds" -> Attestation.nonceBinds(a[0], a[1])
        "matchAgentBinding" -> Attestation.matchAgentBinding(a[0], arg(a, 1))
        "verifyAttestation" -> {
            val inp = LinkedHashMap(map(a[0]))
            inp.remove("hardware")
            inp.remove("allowUnboundPq")
            pre(Attestation.verifyAttestation(inp, hw(map(a[0])["hardware"])))
        }
        "attestationHook" -> pre(hook(a))
        "multiRoot" -> multiRoot(a)
        "attestationEvidenceDigest" -> Attestation.attestationEvidenceDigest(a[0])
        "anchorEvidence" -> anchor(a)
        else -> throw AssertionError("unhandled fn $fn")
    }

    /** The cases the reference accepts only through `allowUnboundPq`: a post-quantum key the document carries is never trusted by itself. */
    private val unboundOnly = setOf("verifyAttestation/pq-unbound#384", "verifyAttestation/hybrid-unbound#386")

    @Test fun everyFunction() {
        val fns = setOf(
            "attestationBinding", "attestationBindingB64u", "attest", "attestorPublicKey", "attestationDigest", "registry", "nonceStore", "nonceEntropyOk",
            "requiresAttestation", "nonceBinds", "matchAgentBinding", "verifyAttestation", "attestationHook", "multiRoot", "attestationEvidenceDigest",
            "anchorEvidence", "constants",
        )
        var total = 0
        var refused = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val args = OracleCases.decNum(c["args"]) as List<Any?>
                if (c["name"] in unboundOnly) {
                    val r = map(call(fn, args))
                    assertEquals(c["name"].toString(), false, r["ok"])
                    assertEquals("attestation signature does not verify", r["reason"])
                    refused++
                    continue
                }
                val case = LinkedHashMap(c)
                case["args"] = args
                OracleCases.diff(case, pre(c["out"])) { x -> call(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(2, refused)
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(512, total)
    }
}
