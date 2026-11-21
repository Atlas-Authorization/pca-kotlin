package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference oracle of the mesh issuing side and the federation primitives (787 cases, every fn dispatched): the worked
 * example and the fork demonstration, the size and latency models, domain / witness lifecycle scripts, cross-domain capability
 * translation, the federated budget tree and cross-reference commitments. A secret is a seed label (a script's domain label X is the
 * seed "mesh-issue/d/X", a witness label "mesh-issue/w/X"). In a script a refused op is `{"$err"}` on both sides; its text is not compared.
 */
@Suppress("UNCHECKED_CAST")
class MeshIssueDiffTest {
    private val mod = "ref-mesh-issue"

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null
    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")
    private fun dbl(o: Any?): Double = IntentJs.num(o) ?: throw IllegalArgumentException("not a number")
    private fun lng(o: Any?): Long = dbl(o).toLong()

    /** The loader has replaced each {"$seed": label} by the base64url seed; anything else is not a key and the reference refuses it. */
    private fun key(o: Any?): Keys.EdKey = Keys.edFromSeed(Pca.decodeB64uStrict(o, 32) ?: throw IllegalArgumentException("not a signing key"))
    private fun labelKey(label: Any?): Keys.EdKey = Keys.edFromSeed(OracleCases.seed("mesh-issue/" + label as String))

    /** A number the corpus spells out of band: Infinity is {"$num": "Infinity"}. */
    private fun num(d: Double): Any? = if (d.isInfinite()) linkedMapOf<String, Any?>("\$num" to (if (d > 0) "Infinity" else "-Infinity")) else d

    private fun cap(label: Any?): Map<String, Any?> = linkedMapOf(
        "id" to label, "issuer" to "iss-$label", "holder" to "h",
        "caveats" to arrayListOf<Any?>(linkedMapOf<String, Any?>("type" to "scope", "actions" to arrayListOf<Any?>(label))),
    )

    private class FailingStore(private val failAfter: Long) : MeshWitnessStore {
        private val inner = MemoryMeshWitnessStore()
        private var saves = 0L
        override fun load(): Map<String, Any?>? = inner.load()
        override fun save(state: Map<String, Any?>) {
            if (saves++ >= failAfter) throw IllegalStateException("disk")
            inner.save(state)
        }
    }

    private fun script(ops: List<Any?>): List<Any?> {
        val doms = LinkedHashMap<String, MeshDomain>()
        val ws = HashMap<String, MeshWitness>()
        val heads = HashMap<String, Map<String, Any?>>()
        val binds = HashMap<String, Map<String, Any?>>()
        val stores = HashMap<String, MeshWitnessStore>()
        fun <T> get(m: Map<String, T>, k: Any?): T = m[k as String] ?: throw IllegalStateException("unknown name $k")
        fun one(op: List<Any?>): Any? = when (op[0] as String) {
            "domain" -> MeshDomain(op[1] as String, labelKey("d/" + op[2])).also { doms[op[1] as String] = it }.id
            "witness" -> MeshWitness(labelKey("w/" + op[2])).also { ws[op[1] as String] = it }.id
            "witnessOpts" -> {
                val x = op[3] as? Map<String, Any?> ?: emptyMap()
                val o = MeshWitness.Options()
                if (x["store"] is String) o.store = get(stores, x["store"])
                x["clock"]?.let { c -> val now = dbl(c); o.clock = { now } }
                x["skew"]?.let { o.maxClockSkewMs = dbl(it) }
                MeshWitness(labelKey("w/" + op[2]), o).also { ws[op[1] as String] = it }.id
            }
            "store" -> { stores[op[1] as String] = MemoryMeshWitnessStore(); true }
            "failStore" -> { stores[op[1] as String] = FailingStore(lng(op[2])); true }
            "storeLoad" -> get(stores, op[1]).load()
            "record" -> get(doms, op[1]).record(cap(op[2]))
            "revoke" -> { get(doms, op[1]).revoke(op[2] as String); null }
            "publish" -> {
                val d = get(doms, op[1])
                d.publishHead((op[4] as List<Any?>).map { get(ws, it) }, dbl(op[3]), op[5]?.let { lng(it).toInt() }).also { heads[op[2] as String] = it }
            }
            "fork" -> { heads[op[1] as String] = LinkedHashMap(get(heads, op[2])).also { it[op[3] as String] = op[4] }; null }
            "forkHead" -> {
                val h = get(heads, op[2])
                val inner = LinkedHashMap(map(h["head"])).also { it[op[3] as String] = op[4] }
                heads[op[1] as String] = LinkedHashMap(h).also { it["head"] = inner }
                null
            }
            "cosign" -> {
                val w = get(ws, op[1])
                val h = get(heads, op[2])
                val hd = h["head"] as? Map<String, Any?>
                val d = doms.values.firstOrNull { it.id == hd?.get("domain") } ?: throw IllegalStateException("no such domain")
                val consistency = if (op[3] == "domain") {
                    w.lastSeen(d.id)?.let { prev -> d.consistencyProof(lng(prev["size"]), lng(hd!!["size"])) }
                } else op[3]
                val req = linkedMapOf<String, Any?>("head" to h)
                if (consistency != null) req["consistency"] = consistency
                req["rev_ids"] = if (op[4] == "domain") ArrayList<Any?>(d.revocationSetCopy().list()) else op[4]
                w.cosign(req)
            }
            "lastSeen" -> get(ws, op[1]).lastSeen(doms[op[2] as String]?.id ?: op[2] as String)
            "export" -> get(ws, op[1]).exportState()
            "import" -> {
                val w = get(ws, op[1])
                val st = op[2] as Map<String, Any?>?
                w.importState(if (st != null && st.containsKey("\$export")) get(ws, st["\$export"]).exportState() else st)
                null
            }
            "restart" -> {
                val o = MeshWitness.Options()
                o.store = get(stores, op[2])
                MeshWitness(labelKey("w/" + op[3]), o).also { ws[op[1] as String] = it }.exportState()
            }
            "consistency" -> if (op[3] == null) get(doms, op[1]).consistencyProof(lng(op[2])) else get(doms, op[1]).consistencyProof(lng(op[2]), lng(op[3]))
            "enroll" -> get(doms, op[1]).enroll(op[3] as String, op[4] as String).also { binds[op[2] as String] = it }
            "evidence" -> get(doms, op[1]).evidence(cap(op[2]), get(heads, op[3]), op[4]?.let { get(binds, it) })
            else -> throw IllegalStateException("op")
        }
        return ops.map { op ->
            try {
                one(op as List<Any?>)
            } catch (e: RuntimeException) { // a refused op is part of the script's result
                linkedMapOf<String, Any?>("\$err" to true)
            }
        }
    }

    /** A script result with every refusal text removed: both sides must refuse the same ops. */
    private fun errs(v: Any?): Any? =
        (v as? List<Any?>)?.map { x -> if (x is Map<*, *> && x.keys == setOf("\$err")) linkedMapOf<String, Any?>("\$err" to true) else x } ?: v

    private fun example(ex: MeshIssue.Example): Map<String, Any?> = linkedMapOf(
        "trust" to ex.trust, "proof" to ex.proof, "evidence" to ex.evidence, "chain" to ex.chain, "heads" to ex.heads, "bindings" to ex.bindings,
        "domains" to ex.domains.mapValues { it.value.id }, "witnesses" to ex.witnesses.map { it.id },
    )

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "DEFAULT_MAX_HEAD_AGE_MS" to Mesh.DEFAULT_MAX_HEAD_AGE_MS, "DEFAULT_MAX_CLOCK_SKEW_MS" to Mesh.DEFAULT_MAX_CLOCK_SKEW_MS,
            "DEFAULT_MAX_CHAIN_LENGTH" to Mesh.DEFAULT_MAX_CHAIN_LENGTH,
        )
        "keyRevocationId" -> MeshIssue.keyRevocationId(arg(a, 0))
        "effectiveAuthority" -> Mesh.effectiveAuthority(arg(a, 0))
        "buildMeshExample" -> example(if (arg(a, 0) == null) MeshIssue.buildMeshExample() else MeshIssue.buildMeshExample(lng(a[0])))
        "demonstrateForkRejection" -> MeshIssue.demonstrateForkRejection()
        "meshProofSize" -> MeshIssue.meshProofSize(arg(a, 0))
        "revocationLatencyBound" -> MeshIssue.revocationLatencyBound(arg(a, 0)).let {
            linkedMapOf("published_ms" to num(it.publishedMs), "unpinned_ms" to num(it.unpinnedMs), "pinned_ms" to num(it.pinnedMs), "honest_provers_viable" to it.honestProversViable)
        }
        "meshIssue" -> script(arg(a, 0) as List<Any?>)
        "translateCapability" -> {
            val args = map(arg(a, 1))
            MeshIssue.translateCapabilityRef(arg(a, 0), args, key(args["bridgeSecret"]))
        }
        "verifyTranslatedCapability" -> MeshIssue.verifyTranslatedCapabilityRef(arg(a, 0), arg(a, 1), a.size > 1)
        "translatedEffectiveAuthority" -> MeshIssue.translatedEffectiveAuthority(arg(a, 0))
        "createFederatedBudget" -> MeshIssue.createFederatedBudget(arg(a, 0))
        "allocateSub" -> MeshIssue.allocateSub(arg(a, 0), arg(a, 1))
        "spendFederated" -> MeshIssue.spendFederated(arg(a, 0), arg(a, 1), arg(a, 2))
        "federatedSafetyBound" -> num(MeshIssue.federatedSafetyBound(arg(a, 0)))
        "meshActionDigest" -> MeshIssue.meshActionDigest(arg(a, 0))
        "crossReferenceCommit" -> MeshIssue.crossReferenceCommit(arg(a, 0))
        "anchorCrossReference" -> MeshIssue.anchorCrossReference(key(arg(a, 0)), arg(a, 1), arg(a, 2))
        "verifyCrossReference" -> MeshIssue.verifyCrossReference(arg(a, 0), arg(a, 1))
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val handled = setOf(
        "constants", "keyRevocationId", "effectiveAuthority", "buildMeshExample", "demonstrateForkRejection", "meshProofSize", "revocationLatencyBound",
        "meshIssue", "translateCapability", "verifyTranslatedCapability", "translatedEffectiveAuthority", "createFederatedBudget", "allocateSub",
        "spendFederated", "federatedSafetyBound", "meshActionDigest", "crossReferenceCommit", "anchorCrossReference", "verifyCrossReference",
    )

    @Test fun replayAllCases() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        var total = 0
        val bad = ArrayList<String>()
        for (fn in handled) for (c in OracleCases.of(mod, fn)) {
            total++
            OracleCases.diff(c, errs(c["out"])) { a -> errs(call(fn, a)) }?.let { bad.add(it) }
        }
        assertEquals(787, total)
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun theWorkedExampleVerifiesAndATamperedOneDoesNot() {
        val ex = MeshIssue.buildMeshExample()
        assertTrue(Mesh.verifyMeshProof(ex.proof, ex.trust).ok)
        val other = LinkedHashMap(ex.trust).also { it["humanPrincipal"] = ex.keys["leaf"]!!.id() }
        assertFalse(Mesh.verifyMeshProof(ex.proof, other).ok)
    }

    @Test fun theTypedTranslationRoundTrips() {
        val ex = MeshIssue.buildMeshExample()
        val bridge = Keys.edFromSeed(OracleCases.seed("mesh-issue/cap/bridge"))
        val narrow = listOf<Any?>(linkedMapOf<String, Any?>("type" to "max_amount", "max" to IntentJs.ofLong(10)))
        val tc = MeshIssue.translateCapability(ex.chain, ex.domains["A"]!!.id, ex.domains["B"]!!.id, bridge, 1_800_000_000_000L, narrow)
        val v = MeshIssue.verifyTranslatedCapability(tc, linkedMapOf<String, Any?>("bridge" to bridge.id()))
        assertEquals(true, v["ok"])
        assertEquals(false, MeshIssue.verifyTranslatedCapability(tc, linkedMapOf<String, Any?>("bridge" to ex.keys["leaf"]!!.id()))["ok"])
        assertEquals(false, MeshIssue.verifyTranslatedCapability(LinkedHashMap(tc).also { it["toGuardian"] = it["fromGuardian"] })["ok"])
    }

    /** Text given as a caveat list is read character by character (no character has a type); text given as `now` is read as a numeric literal. */
    @Test fun textInPlaceOfAListOrANumberIsReadAsTheReferenceReadsIt() {
        assertEquals(mapOf<String, Any?>("prefixes" to emptyList<Any?>()), Mesh.effectiveAuthority(""))
        assertEquals(mapOf<String, Any?>("error" to "unknown caveat type \"undefined\" (fail closed)"), Mesh.effectiveAuthority("scope"))
        val c = OracleCases.of(mod, "verifyTranslatedCapability").first { it["name"] == "verifyTranslatedCapability/now string" }
        val tc = (c["args"] as List<Any?>)[0] // its translated authority expires at 1800003600000
        fun at(now: Any?): Any? = MeshIssue.verifyTranslatedCapability(tc, linkedMapOf<String, Any?>("now" to now))["ok"]
        for (live in listOf<Any?>("5", " 0x10 ", "", "1.8000036e12", listOf<Any?>("7"))) assertEquals("$live", true, at(live))
        for (late in listOf<Any?>("1800003600001", "1.8000036001e12", "Infinity", "+Infinity", "-Infinity", "1e400", "12abc", "1f", linkedMapOf<String, Any?>(), " 0x1A318933E81 ", listOf<Any?>("1800003600001"))) assertEquals("$late", false, at(late))
    }
}
