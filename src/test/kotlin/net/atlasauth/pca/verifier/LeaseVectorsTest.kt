package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The lease corpus (`lease-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class LeaseVectorsTest {
    private val doc = ParityVectors.load("lease-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test
    fun scenarios() {
        val records = l(doc["records"])
        val revocations = l(doc["revocations"])
        val authority = doc["authority"] as String
        assertTrue(l(doc["scenarios"]).size >= 20)
        for (x in l(doc["scenarios"])) {
            val s = m(x)
            val name = s["name"] as String
            val p = s["policy"]?.let { m(it) } ?: emptyMap()
            val policy = Lease.Policy(
                listOf(authority),
                p["minApprovals"]?.let { IntentJs.lng(it) } ?: 1L,
                p["eligibleApprovers"]?.let { strs(it) },
                (p["freshJustification"] as Boolean?) ?: true,
            )
            val reg = Lease.Registry(policy)
            for ((i, y) in l(s["steps"]).withIndex()) {
                val st = m(y)
                val e = m(st["expect"])
                val at = "$name step $i"
                when (st["op"]) {
                    "accept" -> {
                        val got = reg.accept(records[IntentJs.lng(st["record"]).toInt()], st["chain"]?.let { strs(it) } ?: emptyList())
                        assertEquals("$at: ok", e["ok"], got.ok)
                        if (got.ok) {
                            assertEquals("$at: replaced", e["replaced"], got.replaced)
                            assertEquals("$at: seq", IntentJs.lng(e["seq"]), got.seq)
                        } else assertEquals("$at: code", e["code"], got.code)
                    }
                    "revoke" -> {
                        val got = reg.revoke(revocations[IntentJs.lng(st["revocation"]).toInt()])
                        assertEquals("$at: ok", e["ok"], got.ok)
                        if (got.ok) assertEquals("$at: revoked", IntentJs.lng(e["revoked"]), got.revoked.toLong()) else assertEquals("$at: code", e["code"], got.code)
                    }
                    "check" -> {
                        val got = Lease.checkLease(records[IntentJs.lng(st["record"]).toInt()], reg, st["now"])
                        assertEquals("$at: decision", e["decision"], got.decision)
                        assertEquals("$at: code", e["code"], got.code)
                        assertEquals("$at: lease_id", e["lease_id"], got.leaseId)
                        assertEquals("$at: expires_at", e["expires_at"]?.let { IntentJs.lng(it) }, got.expiresAt)
                    }
                    else -> throw AssertionError("$at: unknown op ${st["op"]}")
                }
            }
        }
    }

    @Test
    fun pathUnderAndSod() {
        assertTrue(Lease.pathUnder("db/prod/ro", "db/prod"))
        assertTrue(Lease.pathUnder("db/prod", "db/prod"))
        assertTrue(!Lease.pathUnder("db/production", "db/prod"))
        assertEquals(null, Lease.sodError("alice", "agent", listOf("bob")))
        assertEquals("the requester may not approve their own request", Lease.sodError("alice", "agent", listOf("alice")))
    }
}
