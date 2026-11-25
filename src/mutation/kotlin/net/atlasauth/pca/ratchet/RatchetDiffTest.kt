package net.atlasauth.pca.ratchet

import java.math.BigInteger
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference vectors of the capability ratchet and risk accumulator through the native port. */
@Suppress("UNCHECKED_CAST")
class RatchetDiffTest {
    private val module = "ref-ratchet"

    private fun m(o: Any?) = o as Map<String, Any?>

    private fun l(o: Any?) = o as List<Any?>

    private fun bytes(o: Any?): ByteArray? {
        if (o is Map<*, *> && o.size == 1 && o["\$bytes"] is String) return Keys.unb64u(o["\$bytes"] as String)
        return null
    }

    private fun isBig(o: Any?): Boolean = o is Map<*, *> && o.size == 1 && o["\$bigint"] is String

    /** {"$bigint": "n"} to BigInteger; anything else is left as it is. */
    private fun rev(o: Any?): Any? = if (isBig(o)) BigInteger((o as Map<*, *>)["\$bigint"] as String) else o

    private fun big(o: Any?): BigInteger {
        if (!isBig(o)) throw IllegalArgumentException("not a bigint")
        return rev(o) as BigInteger
    }

    private fun jb(b: BigInteger): Any? = linkedMapOf<String, Any?>("\$bigint" to b.toString())

    private fun num(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDouble()
        is Number -> o.toDouble()
        else -> Double.NaN
    }

    private fun err(code: Any?): Any? = linkedMapOf<String, Any?>("\$err" to code)

    @Test fun leafNullifier() = OracleCases.each(module, "leafNullifier") { a -> Ratchet.leafNullifier(a[0] as String, a[1]) }
    @Test fun counterToLeafIndex() = OracleCases.each(module, "counterToLeafIndex") { a -> Adapters.counterToLeafIndex(a[0], a[1]) }
    @Test fun leafIndexToCounter() = OracleCases.each(module, "leafIndexToCounter") { a -> Adapters.leafIndexToCounter(a[0]) }
    @Test fun leafIndexForAction() = OracleCases.each(module, "leafIndexForAction") { a -> Adapters.leafIndexForAction(m(a[0]), a[1]) }
    @Test fun riskToUnits() = OracleCases.each(module, "riskToUnits") { a -> jb(Adapters.riskToUnits(a[0])) }
    @Test fun budgetCeilingUnits() = OracleCases.each(module, "budgetCeilingUnits") { a -> jb(Adapters.budgetCeilingUnits(m(a[0]))) }

    @Test fun quantizer() = OracleCases.each(module, "quantizer") { a ->
        val q = Adapters.RiskQuantizer()
        val out = ArrayList<Any?>()
        for (r in l(a[0])) {
            try {
                out.add(jb(q.next(r)))
            } catch (e: RuntimeException) {
                out.add(err(true))
            }
        }
        out.add(jb(q.totalUnits()))
        out
    }

    // ---- ratchet scenarios ----

    private fun deepCopy(o: Any?): Any? = when (o) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, v) in o) out[k as String] = deepCopy(v) }
        is List<*> -> ArrayList<Any?>().also { out -> for (x in o) out.add(deepCopy(x)) }
        else -> o
    }

    private fun step(container: Any?, key: Any?): Any? = when (container) {
        is Map<*, *> -> container[key.toString()]
        is List<*> -> { val i = num(key).toInt(); if (i >= 0 && i < container.size) container[i] else null }
        else -> null
    }

    /** The reference's clonePath: a copy of [v] with the member at [path] replaced (or removed for "__DEL__"); an empty path writes the member "undefined". */
    private fun clonePath(v: Any?, path: List<*>, value: Any?): Any? {
        val c = deepCopy(v)
        var t = c
        for (i in 0 until path.size - 1) t = step(t, path[i])
        if (t == null) return c
        val lastKey: Any? = if (path.isEmpty()) "undefined" else path[path.size - 1]
        val del = "__DEL__" == value
        if (t is MutableMap<*, *>) {
            val mm = t as MutableMap<String, Any?>
            if (del) mm.remove(lastKey.toString()) else mm[lastKey.toString()] = value
        } else if (t is MutableList<*>) {
            val ml = t as MutableList<Any?>
            val i = num(lastKey).toInt()
            if (i >= 0 && i < ml.size) ml[i] = if (del) null else value
        }
        return c
    }

    @Test fun ratchetScenarios() = OracleCases.each(module, "ratchet") { a ->
        val spec = m(a[0])
        val store: Binding.SpentLeafStore = if ("throws" == spec["store"]) Binding.SpentLeafStore { _, _ -> throw IllegalStateException("boom") } else Binding.memorySpentLeafStore()
        var state: Ratchet.RatchetState? = null
        var root: String? = null
        val sigs = ArrayList<Any?>()
        val out = ArrayList<Any?>()
        for (so in l(spec["ops"])) {
            val s = m(so)
            try {
                when (s["op"] as String) {
                    "derive" -> {
                        val d = Ratchet.deriveRatchetRoot(bytes(s["seed"]), s["depth"])
                        state = d.state
                        root = d.rootCommitment
                        out.add(linkedMapOf<String, Any?>("root" to d.rootCommitment, "leafPubKeys" to ArrayList<Any?>(d.state.leafPubKeys), "available" to ArrayList<Any?>(Ratchet.availableLeaves(d.state))))
                    }
                    "sign" -> {
                        val r = Ratchet.signAtLeaf(state!!, s["leaf"], bytes(s["msg"])!!)
                        state = r.newState
                        sigs.add(r.signature)
                        out.add(linkedMapOf<String, Any?>("signature" to r.signature))
                    }
                    "avail" -> out.add(ArrayList<Any?>(Ratchet.availableLeaves(state!!)))
                    "isAvail" -> out.add(Ratchet.isLeafAvailable(state!!, s["leaf"]))
                    "verify", "once" -> {
                        val ri = num(s["sigRef"]).toInt()
                        var sig: Any? = if (ri >= 0 && ri < sigs.size) sigs[ri] else null
                        val set = s["set"]
                        if (set != null) for (e in l(set)) sig = clonePath(sig, l(l(e)[0]), l(e)[1])
                        val rc = if ("other" == s["root"]) "other-root" else root!!
                        out.add(
                            if ("verify" == s["op"]) Ratchet.verifyLeafSignature(rc, s["leaf"], bytes(s["msg"])!!, sig)
                            else Binding.verifyLeafSignatureOnce(rc, s["leaf"], bytes(s["msg"])!!, sig, store),
                        )
                    }
                    else -> throw IllegalStateException("bad op")
                }
            } catch (e: RatchetError) {
                out.add(err(e.code))
            } catch (e: RuntimeException) {
                out.add(err(true))
            }
        }
        out
    }

    // ---- accumulator ----

    @Test fun commitRisk() = OracleCases.each(module, "commitRisk") { a ->
        val c = Accumulator.commitRisk(rev(a[0]), big(a[1]))
        linkedMapOf<String, Any?>("commitment" to c.commitment, "blinding" to jb(c.blinding))
    }

    @Test fun addCommitments() = OracleCases.each(module, "addCommitments") { a -> Accumulator.addCommitments(l(a[0])) }

    @Test fun openCommitment() = OracleCases.each(module, "openCommitment") { a -> Accumulator.openCommitment(a[0], rev(a[1]), if (isBig(a[2])) big(a[2]) else null) }

    @Test fun verifyRiskRange() = OracleCases.each(module, "verifyRiskRange") { a -> Accumulator.verifyRiskRange(a[0], a[1]) }
    @Test fun verifyBudget() = OracleCases.each(module, "verifyBudget") { a -> Accumulator.verifyBudget(a[0], rev(a[1]), a[2]) }
    @Test fun verifyBoundedBudget() = OracleCases.each(module, "verifyBoundedBudget") { a -> Accumulator.verifyBoundedBudget(a[0], a[1], rev(a[2]), a[3]) }

    @Test fun proveBudgetRefusals() = OracleCases.each(module, "proveBudget") { a ->
        Accumulator.proveBudget(l(a[0]).map { rev(it) }, l(a[1]).map { big(it) }, rev(a[2]))
    }

    @Test fun proveRiskRangeRefusals() = OracleCases.each(module, "proveRiskRange") { a -> Accumulator.proveRiskRange(rev(a[0]), big(a[1])) }

    private fun authoritySecret(): ByteArray = OracleCases.seed("ratchet-authority")

    @Test fun issueRiskCommitmentRefusals() {
        val auth = authoritySecret()
        OracleCases.each(module, "issueRiskCommitment") { a -> Binding.issueRiskCommitment(rev(a[0]), a[1] as String, if (a.size > 2 && "short" == a[2]) ByteArray(3) else auth) }
    }

    @Test fun verifyRiskAttestation() = OracleCases.each(module, "verifyRiskAttestation") { a -> Binding.verifyRiskAttestation(a[0], a[1], a[2]) }
    @Test fun verifyAttestedBudget() = OracleCases.each(module, "verifyAttestedBudget") { a -> Binding.verifyAttestedBudget(a[0], a[1], a[2], rev(a[3]), a[4]) }

    // ---- round trips the oracle cannot compare (the provers are randomized) ----

    private fun n(v: Long) = Json.Num(v.toString())

    @Test fun rangeProofRoundTrip() {
        val b = BigInteger.valueOf(12345)
        val c = Accumulator.commitRisk(n(7), b).commitment
        val proof = Accumulator.proveRiskRange(n(7), b)
        assertTrue(Accumulator.verifyRiskRange(c, proof))
        assertFalse(Accumulator.verifyRiskRange(Accumulator.commitRisk(n(8), b).commitment, proof))
        // a value outside [0, 2^32) yields a well-formed proof the verifier rejects
        val big = BigInteger.ONE.shiftLeft(32)
        assertFalse(Accumulator.verifyRiskRange(Accumulator.commitRisk(big, b).commitment, Accumulator.proveRiskRange(big, b)))
    }

    @Test fun boundedBudgetRoundTrip() {
        val b1 = BigInteger.valueOf(5)
        val b2 = BigInteger.valueOf(6)
        val commitments = listOf<Any?>(Accumulator.commitRisk(n(3), b1).commitment, Accumulator.commitRisk(n(4), b2).commitment)
        val ranges = listOf<Any?>(Accumulator.proveRiskRange(n(3), b1), Accumulator.proveRiskRange(n(4), b2))
        val risks = listOf<Any?>(n(3), n(4))
        val ok = Accumulator.proveBudget(risks, listOf(b1, b2), n(10))
        assertTrue(Accumulator.verifyBoundedBudget(commitments, ranges, n(10), ok))
        assertTrue(Accumulator.verifyBudget(Accumulator.addCommitments(commitments), n(7), Accumulator.proveBudget(risks, listOf(b1, b2), n(7))))
        // over budget: well-formed proof, rejected
        assertFalse(Accumulator.verifyBudget(Accumulator.addCommitments(commitments), n(6), Accumulator.proveBudget(risks, listOf(b1, b2), n(6))))
        assertFalse(Accumulator.verifyBoundedBudget(commitments, ranges, n(9), ok))
        try {
            Accumulator.proveBudget(risks, listOf(b1), n(10))
            fail("length mismatch accepted")
        } catch (e: AccumulatorError) {
            assertEquals("length_mismatch", e.code)
        }
    }

    @Test fun attestedBudgetRoundTrip() {
        val auth = authoritySecret()
        val pk = Keys.edFromSeed(auth).id()
        val i1 = Binding.issueRiskCommitment(n(3), "digest-1", auth)
        val i2 = Binding.issueRiskCommitment(n(4), "digest-2", auth)
        val proof = Accumulator.proveBudget(listOf<Any?>(n(3), n(4)), listOf(i1.blinding, i2.blinding), n(10))
        val items = listOf(i1, i2).map { linkedMapOf<String, Any?>("commitment" to it.commitment, "rangeProof" to it.rangeProof, "attestation" to it.attestation) }
        assertTrue(Binding.verifyRiskAttestation(i1.commitment, i1.attestation, pk))
        assertFalse(Binding.verifyRiskAttestation(i2.commitment, i1.attestation, pk))
        assertTrue(Binding.verifyAttestedBudget(items, listOf("digest-1", "digest-2"), pk, n(10), proof))
        assertFalse(Binding.verifyAttestedBudget(items, listOf("digest-2", "digest-1"), pk, n(10), proof))
    }

    @Test fun ratchetPuncturesAndDetectsReuse() {
        val seed = ByteArray(32)
        seed[0] = 5
        val d = Ratchet.deriveRatchetRoot(seed, n(3))
        val msg = "m".toByteArray(Charsets.UTF_8)
        val s = Ratchet.signAtLeaf(d.state, n(2), msg)
        assertTrue(Ratchet.verifyLeafSignature(d.rootCommitment, n(2), msg, s.signature))
        assertFalse(Ratchet.isLeafAvailable(s.newState, n(2)))
        assertEquals(7, Ratchet.availableLeaves(s.newState).size)
        try {
            Ratchet.signAtLeaf(s.newState, n(2), msg)
            fail("a punctured leaf signed")
        } catch (e: RatchetError) {
            assertEquals("leaf_punctured", e.code)
        }
        val store = Binding.memorySpentLeafStore()
        assertEquals(true, Binding.verifyLeafSignatureOnce(d.rootCommitment, n(2), msg, s.signature, store)["ok"])
        assertEquals("replay", Binding.verifyLeafSignatureOnce(d.rootCommitment, n(2), msg, s.signature, store)["reason"])
    }
}
