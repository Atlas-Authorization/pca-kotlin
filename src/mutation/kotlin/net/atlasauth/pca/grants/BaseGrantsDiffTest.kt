package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.BreakGlass
import net.atlasauth.pca.verifier.Lease
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/** Replays the reference oracle of the verification halves of leases and break-glass grants (record shapes, separation of duties, registry walks). */
@Suppress("UNCHECKED_CAST")
class BaseGrantsDiffTest {
    private val module = "base-grants"

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for ((k, v) in kv) r[k] = v; return r }
    private fun n(o: Any?): Long = o.toString().toLong()

    private fun policy(po: Any?): Lease.Policy {
        val p = m(po)
        return Lease.Policy(
            if (p["authorities"] == null) emptyList() else strs(p["authorities"]),
            minApprovals = if (p["minApprovals"] != null) n(p["minApprovals"]) else 1L,
            eligibleApprovers = if (p["eligibleApprovers"] != null) strs(p["eligibleApprovers"]) else null,
            freshJustification = if (p["freshJustification"] != null) p["freshJustification"] as Boolean else true,
            maxTtlCeiling = if (p["maxTtlCeiling"] != null) n(p["maxTtlCeiling"]) else null,
        )
    }

    private fun accept(a: Lease.Accept): Map<String, Any?> =
        if (a.code == null) obj("ok" to true, "replaced" to a.replaced, "seq" to a.seq) else obj("ok" to false, "code" to a.code)

    private fun revoke(r: Lease.Revoke): Map<String, Any?> =
        if (r.code == null) obj("ok" to true, "revoked" to r.revoked.toLong()) else obj("ok" to false, "code" to r.code)

    private fun decision(d: Lease.Decision): Map<String, Any?> {
        val out = obj("decision" to d.decision)
        if (d.code != null) out["code"] = d.code
        if (d.leaseId != null) out["lease_id"] = d.leaseId
        if (d.expiresAt != null) out["expires_at"] = d.expiresAt
        return out
    }

    private fun bgResult(r: BreakGlass.Result): Map<String, Any?> =
        if (r.ok) obj("ok" to true, "replaced" to r.replaced) else obj("ok" to false, "code" to r.code)

    private fun bgDecision(d: BreakGlass.Decision): Map<String, Any?> {
        val out = obj("decision" to d.decision)
        if (d.decision == "allow") {
            out["id"] = d.id
            out["use"] = d.use
            out["remaining"] = d.remaining
            out["review_due"] = d.reviewDue
        } else {
            out["code"] = d.code
            if (d.id != null) out["id"] = d.id
        }
        return out
    }

    @Test fun verifyLease() = OracleCases.each(module, "verifyLease") { a -> Lease.verifyLease(a[0]) }
    @Test fun verifyLeaseRevocation() = OracleCases.each(module, "verifyLeaseRevocation") { a -> Lease.verifyLeaseRevocation(a[0]) }
    @Test fun verifyBreakGlass() = OracleCases.each(module, "verifyBreakGlass") { a -> BreakGlass.verifyBreakGlass(a[0]) }
    @Test fun verifyBreakGlassReview() = OracleCases.each(module, "verifyBreakGlassReview") { a -> BreakGlass.verifyBreakGlassReview(a[0]) }

    @Test fun sodError() = OracleCases.each(module, "sodError") { a ->
        val lease = m(a[0])
        val p = policy(a[1])
        Lease.sodError(lease["requester"] as String, lease["holder"] as String, strs(lease["approvers"]), p.minApprovals, p.eligibleApprovers, strs(a[2]))
    }

    @Test fun leaseWalk() = OracleCases.each(module, "leaseWalk") { a ->
        val reg = Lease.Registry(policy(a[0]), MemoryAtomicKv())
        val out = ArrayList<Any?>()
        for (sx in l(a[1])) {
            val s = m(sx)
            when (s["op"]) {
                "accept" -> out.add(accept(reg.accept(s["rec"], if (s["chain"] == null) emptyList() else strs(s["chain"]))))
                "revoke" -> out.add(revoke(reg.revoke(s["rec"])))
                else -> out.add(decision(Lease.checkLease(s["rec"], reg, s["now"])))
            }
        }
        out
    }

    @Test fun bgWalk() = OracleCases.each(module, "bgWalk") { a ->
        val p = m(a[0])
        val reg = BreakGlass.Registry(BreakGlass.Policy(strs(p["authorities"]), strs(p["reviewers"])), MemoryAtomicKv())
        val out = ArrayList<Any?>()
        for (sx in l(a[1])) {
            val s = m(sx)
            when (s["op"]) {
                "accept" -> out.add(bgResult(reg.accept(s["rec"], s["now"])))
                "use" -> out.add(bgDecision(reg.use(s["id"], s["holder"], s["action_digest"], s["now"], s["notified"])))
                "review" -> out.add(bgResult(reg.review(s["rec"], s["holder"], s["now"])))
                else -> out.add(reg.frozen(s["holder"], s["now"]))
            }
        }
        out
    }

    private fun arg0(fn: String, name: String): Any? =
        l(OracleCases.of(module, fn).first { it["name"] == "$fn/$name" }["args"])[0]

    // a registry's TTL ceiling: a longer max_ttl is refused, the ceiling itself must be a positive safe integer
    @Test fun maxTtlCeiling() {
        val lease = m(arg0("verifyLease", "base"))
        val ttl = n(lease["max_ttl"])
        val auth = listOf(lease["authority"] as String)
        fun code(ceiling: Long?) = Lease.Registry(Lease.Policy(auth, maxTtlCeiling = ceiling), MemoryAtomicKv()).accept(LinkedHashMap(lease), emptyList()).code
        assertEquals("ceiling below", "ttl_ceiling", code(ttl - 1))
        assertNull("ceiling equal", code(ttl))
        assertNull("ceiling above", code(ttl + 1))
        assertNull("no ceiling", code(null))
        assertEquals("the smallest ceiling is legal", "ttl_ceiling", code(1L))
        assertNull("the largest ceiling is legal", code(9007199254740991L))
        for (bad in listOf(0L, -1L, 9007199254740992L)) {
            try {
                Lease.Registry(Lease.Policy(auth, maxTtlCeiling = bad), MemoryAtomicKv())
                fail("ceiling $bad accepted")
            } catch (e: IllegalArgumentException) {
                assertEquals("LeaseRegistry: maxTtlCeiling must be a positive integer", e.message)
            }
        }
    }
}
