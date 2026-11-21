package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.HarmModel
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The layered intent lattice (org ceiling, site policy, standing profile, task grant: deny anywhere wins, a ceiling is never a
 * question) and the quorum of principal-signed approvals that a shared layer needs to widen. The learner-bound views
 * (the lattice view of a task learner and its outcome decision) live in [IntentLattice].
 */
object IntentLayers {
    /** The ceilings in evaluation order. */
    @JvmField val LAYER_CEILINGS: List<String> = listOf("org", "site", "std")
    const val LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\u0000"

    /** Compiled ceilings; an absent ceiling is null. */
    data class CeilingAdmitters(val org: IntentPolicy.Admitter?, val site: IntentPolicy.Admitter?, val std: IntentPolicy.Admitter?) {
        internal fun of(k: String): IntentPolicy.Admitter? = if (k == "org") org else if (k == "site") site else std
    }

    /** Absent = no ceiling; a ceiling PRESENT with null (or not an object) is malformed: throws. */
    fun ceilingAdmitters(layers: Map<String, Any?>): CeilingAdmitters {
        val out = arrayOfNulls<IntentPolicy.Admitter>(3)
        for (i in 0..2) {
            val k = LAYER_CEILINGS[i]
            if (!layers.containsKey(k)) continue
            val l = layers[k]
            require(l is Map<*, *>) { "ceilingAdmitters: the $k ceiling is malformed (null or not an object)" }
            out[i] = IntentPolicy.admitter(l)
        }
        return CeilingAdmitters(out[0], out[1], out[2])
    }

    /** The first ceiling that excludes the outcome, or null when every ceiling admits it. */
    fun ceilingOf(c: CeilingAdmitters, vs: VerbSpace, o: Outcome): String? {
        for (k in LAYER_CEILINGS) {
            val a = c.of(k)
            if (a != null && !a.admits(vs, o)) return k
        }
        return null
    }

    private fun key(verb: String?, cell: List<*>): String = verb + "|" + cell.joinToString(",") { AttestUtil.jsNumString(IntentOmega.dbl(it)) }

    /** A question may only be about a cell of the uncertain set (inside every ceiling). Throws otherwise. */
    fun assertAskable(view: Map<String, Any?>, c: Map<String, Any?>) {
        val k = key(c["verb"] as String?, IntentOmega.arr(c["cell"]))
        for (u in IntentOmega.arr(view["uncertain"])) {
            val um = IntentOmega.obj(u)
            if (key(um["verb"] as String?, IntentOmega.arr(um["cell"])) == k) return
        }
        throw IllegalArgumentException("layers: cell $k is not an uncertain cell inside every ceiling (never a question)")
    }

    private fun idxOf(cl: List<Any?>): IntArray = IntArray(cl.size) { IntentOmega.dbl(cl[it]).toInt() }

    /** Layer owner's own risk of a set of cells ({verb, cell}): sum of mass * (1 - a) * E[h | cell]. */
    fun ownerRisk(omega: Omega, cells: List<Map<String, Any?>>, acceptability: IntentMetrics.Acceptability, harm: HarmModel): Double {
        var r = 0.0
        for (c in cells) {
            val vs = IntentOmega.verbSpace(omega, c["verb"] as String?) ?: continue
            val idx = idxOf(IntentOmega.arr(c["cell"]))
            val st = IntentOmega.cellStats(vs, idx, harm)
            r += st.mass * (1 - acceptability.of(vs, IntentOmega.cellRep(vs, idx))) * st.harm
        }
        return r
    }

    private fun cellKey(verb: String, cell: IntArray): MutableMap<String, Any?> = linkedMapOf("verb" to verb, "cell" to cell.toMutableList())

    /** Every cell of the space an admitter admits (the layer as a cell set). */
    fun layerCells(omega: Omega, a: IntentPolicy.Admitter): List<MutableMap<String, Any?>> {
        val out = ArrayList<MutableMap<String, Any?>>()
        for (vs in omega.verbs) {
            val n = IntentOmega.verbCellCount(vs)
            var f = 0.0
            while (f < n) {
                val cell = IntentOmega.decodeCell(vs, f)
                if (a.admits(vs, IntentOmega.cellRep(vs, cell))) out.add(cellKey(vs.verb, cell))
                f++
            }
        }
        return out
    }

    /** Flat key of a cell ({verb, cell}). */
    fun cellKeyOf(omega: Omega, c: Map<String, Any?>): String {
        val verb = c["verb"] as String?
        val vs = IntentOmega.verbSpace(omega, verb)
        val cl = IntentOmega.arr(c["cell"])
        if (vs == null) return key(verb, cl)
        return verb + "|" + AttestUtil.jsNumString(IntentOmega.encodeCell(vs, idxOf(cl)))
    }

    // ---- quorum-signed layer approvals ----

    private val STATEMENT_KEYS = listOf("v", "kind", "layer", "session", "seq", "map_digest", "prev")

    private fun statementOf(a: Map<String, Any?>): MutableMap<String, Any?> {
        val st = LinkedHashMap<String, Any?>()
        st["v"] = Json.Num("1")
        st["kind"] = "pca-intent-layer-approval"
        for (k in listOf("layer", "session", "seq", "map_digest", "prev")) if (a.containsKey(k)) st[k] = a[k]
        return st
    }

    private fun approvalMessage(st: Map<String, Any?>): ByteArray = IntentKit.message(LAYER_APPROVAL_DOMAIN, st)

    /** Sign an approval of a shared-layer widening ({layer, session, seq, map_digest, prev}). */
    fun signLayerApproval(s: Map<String, Any?>, secretSeed: ByteArray): MutableMap<String, Any?> {
        val key = Keys.edFromSeed(secretSeed)
        val st = statementOf(s)
        val out = LinkedHashMap(st)
        out["signer"] = key.id()
        out["sig"] = Keys.b64u(key.sign(approvalMessage(st)))
        return out
    }

    private fun strictEq(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a === b
        val x = IntentKit.num(a)
        val y = IntentKit.num(b)
        if (x != null || y != null) return x != null && y != null && x == y
        if (a is String || a is Boolean) return a == b
        return a === b
    }

    private fun quorumResult(ok: Boolean, signers: List<String>, ignored: List<Map<String, Any?>>): MutableMap<String, Any?> =
        linkedMapOf("ok" to ok, "signers" to ArrayList<Any?>(signers), "ignored" to ArrayList<Any?>(ignored))

    private fun ign(index: Int, reason: String?): MutableMap<String, Any?> = linkedMapOf("index" to index, "reason" to reason)

    /**
     * Verify approvals against the layer's members and rule. An approval counts iff its signer is a member, it is the FIRST from
     * that member, its statement equals [expected] field by field and its signature verifies; the rule is the multi-principal
     * one over member keys. Returns {ok, signers, ignored[{index, reason}]}.
     */
    fun verifyQuorumApprovals(approvals: Any?, members: Any?, rule: Map<String, Any?>, expected: Any?): MutableMap<String, Any?> {
        if (approvals !is List<*> || members !is List<*> || (expected !is Map<*, *> && expected !is List<*>))
            return quorumResult(false, ArrayList(), listOf(ign(-1, "approvals and members must be arrays and expected an object")))
        val bad = HashSet<Any?>(members).size != members.size || members.any { it !is String || Pca.decodeB64uStrict(it, 32) == null }
        if (bad) return quorumResult(false, ArrayList(), listOf(ign(-1, "members must be distinct 32-byte keys")))
        val mem = members.map { it as String }
        val n = try {
            IntentMulti.normalizeRule(rule, mem)
        } catch (e: RuntimeException) {
            return quorumResult(false, ArrayList(), listOf(ign(-1, e.message)))
        }
        val want = statementOf(if (expected is Map<*, *>) IntentOmega.obj(expected) else LinkedHashMap<String, Any?>()) // an array has none of the statement members
        val counted = HashSet<String>()
        val ignored = ArrayList<Map<String, Any?>>()
        for (i in approvals.indices) {
            val ao = approvals[i]
            if (ao !is Map<*, *> && ao !is List<*>) {
                ignored.add(ign(i, "not an object"))
                continue
            }
            if (ao is List<*>) {
                ignored.add(ign(i, "signer is not a member"))
                continue
            }
            val a = IntentOmega.obj(ao)
            val signer = a["signer"]
            if (!mem.contains(signer)) {
                ignored.add(ign(i, "signer is not a member"))
                continue
            }
            if (counted.contains(signer)) {
                ignored.add(ign(i, "second approval from the same member"))
                continue
            }
            val st = statementOf(a)
            var same = true
            for (k in STATEMENT_KEYS) {
                val xd = st.containsKey(k)
                val yd = want.containsKey(k)
                if (xd != yd || (xd && !strictEq(st[k], want[k]))) same = false
            }
            same = same && strictEq(a["v"], Json.Num("1")) && "pca-intent-layer-approval" == a["kind"]
            if (!same) {
                ignored.add(ign(i, "approval is for another (layer, session, seq, map_digest, prev)"))
                continue
            }
            val ok = try {
                IntentKit.verifyEd(signer, approvalMessage(st), a["sig"])
            } catch (e: RuntimeException) {
                false
            }
            if (!ok) {
                ignored.add(ign(i, "bad signature"))
                continue
            }
            counted.add(signer as String)
        }
        val signers = ArrayList<String>()
        val ins = BooleanArray(mem.size)
        for (i in mem.indices) {
            ins[i] = counted.contains(mem[i])
            if (ins[i]) signers.add(mem[i])
        }
        return quorumResult(IntentMulti.ruleAdmits(n, ins), signers, ignored)
    }
}
