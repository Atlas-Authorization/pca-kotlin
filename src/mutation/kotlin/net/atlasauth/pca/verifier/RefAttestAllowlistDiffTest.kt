package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The measurement-allowlist manifests and their transparency anchor against the reference (ref-attest-allowlist, 959 cases): verification over every suite,
 * option, shape, body and value rule (744 cases, hostile mutations included), the durable high-water mark, create / sign (signature bytes) / revoke, the
 * projection and policy fields, and the anchor: commit, operator log, evidence and the verifier over the committed anchor conformance vectors. A refusal compares
 * by `code` (the reason text is the reference's wording); an operator-log error compares by presence.
 */
@Suppress("UNCHECKED_CAST")
class RefAttestAllowlistDiffTest {
    private val mod = "ref-attest-allowlist"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict(if (o is Map<*, *>) o["\$bytes"] else o, 32) ?: throw IllegalArgumentException("not a key seed")

    /** A refusal's reason text and an error's message are the reference's wording: compare the code / the presence of the error. */
    private fun strip(v: Any?): Any? = when (v) {
        is Map<*, *> -> {
            val m = LinkedHashMap<String, Any?>()
            for ((k, x) in v) m[k as String] = strip(x)
            if (m["ok"] == false && m.containsKey("code")) m.remove("reason")
            if (m.containsKey("\$throws")) m["\$throws"] = true
            m
        }
        is List<*> -> v.map { strip(it) }
        else -> v
    }

    private fun keysOf(spec: Map<String, Any?>): Pair<Keys.EdKey?, Keys.PqKey?> {
        val alg = spec["alg"] as String
        val prim = Pq.resolveSigAlg(alg, true)?.pq
        val pq = if (spec["seed"] != null && prim != null) Keys.pqFromSeed(prim, seed(spec["seed"])) else null
        val ed = spec["edSecret"]?.let { Keys.edFromSeed(seed(it)) }
        return Pair(ed, pq)
    }

    private fun sign(a: List<Any?>): Any? {
        val o = map(a[1])
        val (ed, pq) = keysOf(map(o["keySpec"]))
        return AttestAllowlist.signAllowlistManifest(a[0], o["issuer"] as String, o["alg"], ed, pq)
    }

    private fun durable(a: List<Any?>): Any? {
        val sc = map(a[0])
        val kv = MemoryAtomicKv()
        for ((k, v) in (sc["initial"] as Map<String, Any?>? ?: emptyMap())) kv.set(k, v)
        val results = (sc["steps"] as List<Any?>).map { AttestAllowlist.verifyAllowlistDurable(it, map(sc["opts"]), kv) }
        val state = LinkedHashMap<String, Any?>()
        for (k in kv.keys()) state[k] = kv.get(k)
        return linkedMapOf("results" to results, "kv" to state)
    }

    private fun anchorOps(a: List<Any?>): Any? {
        val sc = map(a[0])
        val log = AttestAllowlistAnchor.createAllowlistAnchorLog(sc["instanceId"] as String, sc["principal"] as String)
        val guardian = Keys.suite("ed25519", Keys.edFromSeed(seed(sc["secret"])), null)
        return (sc["ops"] as List<Any?>).map { opo ->
            val op = map(opo)
            try {
                when {
                    op.containsKey("anchor") -> AttestAllowlistAnchor.anchorAllowlistHead(log, op["anchor"], guardian, op["nowMs"])
                    op.containsKey("refresh") -> AttestAllowlistAnchor.refreshAnchorHead(log, guardian, op["refresh"])
                    op.containsKey("evidenceFor") ->
                        AttestAllowlistAnchor.evidenceFor(log, IntentJs.lng(op["evidenceFor"]), (op["cached"] as Map<String, Any?>?)?.let { IntentJs.lng(it["size"]) })
                    op.containsKey("latest") -> log.latest()
                    else -> log.entries()
                }
            } catch (e: RuntimeException) {
                linkedMapOf("\$throws" to (e.message ?: "error"))
            }
        }
    }

    private fun verifyAnchored(a: List<Any?>): Any? {
        val sc = map(a[0])
        return AttestAllowlistAnchor.verifyAllowlistAnchored(map(sc["verified"]), sc["evidence"], map(sc["opts"]))
    }

    private fun policyFields(a: List<Any?>): Any? {
        val p = map(a[1])
        return when (a[0]) {
            "azureMaaPolicyFields" -> AttestAllowlist.azureMaaPolicyFields(p)
            "intelDcapPolicyFields" -> AttestAllowlist.intelDcapPolicyFields(p)
            "sevSnpPolicyFields" -> AttestAllowlist.sevSnpPolicyFields(p)
            "gcpCsPolicyFields" -> AttestAllowlist.gcpCsPolicyFields(p)
            "nvidiaCcPolicyFields" -> AttestAllowlist.nvidiaCcPolicyFields(p)
            else -> throw AssertionError("policy fields ${a[0]}")
        }
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf("ALLOWLIST_KINDS" to AttestAllowlist.ALLOWLIST_KINDS, "DOMAIN" to AttestAllowlist.DOMAIN)
        "verifyAllowlistManifest" -> AttestAllowlist.verifyAllowlistManifest(a[0], a[1] as Map<String, Any?>?)
        "verifyAllowlistDurable" -> durable(a)
        "createAllowlistManifest" -> AttestAllowlist.createAllowlistManifest(a[0])
        "signAllowlistManifest" -> sign(a)
        "revokeAllowlistEntry" -> AttestAllowlist.revokeAllowlistEntry(map(a[0]), map(a[1]), map(a[2]))
        "driverVersionSlotHex" -> AttestAllowlist.driverVersionSlotHex(a[0] as String)
        "projectAllowlist" -> AttestAllowlist.projectAllowlist(map(a[0]), IntentJs.num(map(a[1])["nowMs"])!!)
        "policyFields" -> policyFields(a)
        "anchorCommit" -> AttestAllowlistAnchor.allowlistAnchorCommit(map(a[0]))
        "anchorEntryOf" -> AttestAllowlistAnchor.anchorEntryOf(map(a[0]))
        "anchorOps" -> anchorOps(a)
        "verifyAnchored" -> verifyAnchored(a)
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf(
            "constants", "verifyAllowlistManifest", "verifyAllowlistDurable", "createAllowlistManifest", "signAllowlistManifest", "revokeAllowlistEntry", "driverVersionSlotHex",
            "projectAllowlist", "policyFields", "anchorCommit", "anchorEntryOf", "anchorOps", "verifyAnchored",
        )
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val case = LinkedHashMap(c)
                case["args"] = OracleCases.decNum(c["args"])
                OracleCases.diff(case, strip(c["out"])) { x -> strip(call(fn, x)) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(959, total)
    }
}
