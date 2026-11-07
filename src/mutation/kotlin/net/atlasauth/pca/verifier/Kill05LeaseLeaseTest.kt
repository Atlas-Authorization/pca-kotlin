package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for [Lease] (packages/pca-grants/src/lease.ts): every well-formedness bound on both sides, every registry and
 * check code with its reason, the history ledger, revocation coverage and the separation-of-duties reasons. Every malformed record is
 * correctly SIGNED, so a mutant that drops a shape check is caught by the signature then verifying.
 */
class Kill05LeaseLeaseTest {
    private val K = "k05-lease/authority"
    private val K2 = "k05-lease/authority-2"
    private val AUTH = pub(K)
    private val AUTH2 = pub(K2)
    private val BODY = listOf(
        "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at",
        "renewed_at", "expires_at", "max_ttl", "authority",
    )
    private val REV = listOf("v", "target", "value", "revoked_at", "authority")

    private fun base(): LinkedHashMap<String, Any?> = jm(
        "v", 1L, "lease_id", "L1", "path", "db/prod", "grant_ref", "g1", "holder", "H", "requester", "R", "approvers", jl("A1"),
        "justification_digest", "j1", "seq", 1L, "issued_at", 1000L, "renewed_at", 1000L, "expires_at", 2000L, "max_ttl", 5000L,
        "authority", AUTH,
    )

    private fun signedLease(m: Map<String, Any?>, key: String): LinkedHashMap<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY) body[k] = m[k]
        return LinkedHashMap(m).also { it["sig"] = sign(key, IntentJs.message(Lease.DOMAIN, body)) }
    }

    /** The base lease with [kv] overrides, signed by [K] (or by [K2] when the authority is [AUTH2]). */
    private fun rec(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = base()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return signedLease(m, if (m["authority"] == AUTH2) K2 else K)
    }

    private fun rev(target: Any?, value: Any?, revokedAt: Any?, v: Any? = 1L, key: String = K): LinkedHashMap<String, Any?> {
        val m = jm("v", v, "target", target, "value", value, "revoked_at", revokedAt, "authority", pub(key))
        val body = LinkedHashMap<String, Any?>()
        for (k in REV) body[k] = m[k]
        return LinkedHashMap(m).also { it["sig"] = sign(key, IntentJs.message(Lease.REVOKE_DOMAIN, body)) }
    }

    private fun reg(minApprovals: Long = 1, eligible: List<String>? = null, fresh: Boolean = true) =
        Lease.Registry(Lease.Policy(listOf(AUTH, AUTH2), minApprovals, eligible, fresh))

    private fun refused(a: Lease.Accept, code: String, reason: String? = null) {
        assertFalse(code, a.ok)
        assertEquals(code, a.code)
        assertEquals(code, reason, a.reason)
    }

    private fun taken(a: Lease.Accept, seq: Long, replaced: Boolean = true) {
        assertTrue("${a.code} ${a.reason}", a.ok)
        assertNull(a.code)
        assertEquals(replaced, a.replaced)
        assertEquals(seq, a.seq)
        assertNull(a.reason)
    }

    private fun s(n: Int) = "x".repeat(n)

    @Test fun wellFormedBoundsBothSides() {
        assertTrue(Lease.verifyLease(rec()))
        // not an object
        assertFalse(Lease.verifyLease(null))
        assertFalse(Lease.verifyLease("lease"))
        assertFalse(Lease.verifyLease(jl(rec())))
        // v
        assertFalse(Lease.verifyLease(rec("v", 2L)))
        assertFalse(Lease.verifyLease(rec("v", 0L)))
        assertFalse(Lease.verifyLease(rec("v", "1")))
        assertFalse(Lease.verifyLease(rec("v", Json.Num("1.5"))))
        assertTrue(Lease.verifyLease(rec("v", Json.Num("1"))))
        // bounded strings: the bound itself is accepted, one more and the empty string are not
        for ((k, max) in listOf("lease_id" to 128, "grant_ref" to 256, "holder" to 128, "requester" to 128, "justification_digest" to 128)) {
            assertTrue(k, Lease.verifyLease(rec(k, s(max))))
            assertFalse(k, Lease.verifyLease(rec(k, s(max + 1))))
            assertFalse(k, Lease.verifyLease(rec(k, "")))
            assertFalse(k, Lease.verifyLease(rec(k, 7L)))
            assertFalse(k, Lease.verifyLease(rec(k, null)))
        }
        // the authority is the signing key: anything else fails the signature
        assertFalse(Lease.verifyLease(rec("authority", s(129))))
        assertFalse(Lease.verifyLease(rec("authority", "")))
        // path
        assertTrue(Lease.verifyLease(rec("path", "a")))
        assertTrue(Lease.verifyLease(rec("path", "a/b/c/d/e/f/g/h")))
        assertFalse(Lease.verifyLease(rec("path", "a/b/c/d/e/f/g/h/i")))
        assertFalse(Lease.verifyLease(rec("path", "DB/prod")))
        assertFalse(Lease.verifyLease(rec("path", "db//prod")))
        assertFalse(Lease.verifyLease(rec("path", "")))
        assertFalse(Lease.verifyLease(rec("path", 5L)))
        assertTrue(Lease.verifyLease(rec("path", s(64))))
        assertFalse(Lease.verifyLease(rec("path", s(65))))
        // each integer member: a string, a negative, a fraction
        for (k in listOf("seq", "issued_at", "renewed_at", "expires_at", "max_ttl")) {
            assertFalse(k, Lease.verifyLease(rec(k, "5")))
            assertFalse(k, Lease.verifyLease(rec(k, -1L)))
            assertFalse(k, Lease.verifyLease(rec(k, null)))
        }
        assertFalse(Lease.verifyLease(rec("max_ttl", Json.Num("1.5"))))
        assertFalse(Lease.verifyLease(rec("seq", Json.Num("1.5"))))
        // seq and max_ttl start at 1
        assertFalse(Lease.verifyLease(rec("seq", 0L)))
        assertFalse(Lease.verifyLease(rec("max_ttl", 0L)))
        assertTrue(Lease.verifyLease(rec("max_ttl", 1L)))
        // the window: a renewal may renew at its issue time, an issue must; expiry strictly after renewal
        assertTrue(Lease.verifyLease(rec("seq", 2L, "renewed_at", 1000L)))
        assertTrue(Lease.verifyLease(rec("seq", 2L, "renewed_at", 1001L)))
        assertFalse(Lease.verifyLease(rec("seq", 2L, "renewed_at", 999L)))
        assertFalse(Lease.verifyLease(rec("renewed_at", 1001L)))
        assertFalse(Lease.verifyLease(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 1500L)))
        assertTrue(Lease.verifyLease(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 1501L)))
        assertFalse(Lease.verifyLease(rec("expires_at", 1000L)))
        assertFalse(Lease.verifyLease(rec("expires_at", 999L)))
        assertTrue(Lease.verifyLease(rec("expires_at", 1001L)))
        // approvers
        assertTrue(Lease.verifyLease(rec("approvers", jl())))
        assertTrue(Lease.verifyLease(rec("approvers", ArrayList<Any?>((1..16).map { "a$it" }))))
        assertFalse(Lease.verifyLease(rec("approvers", ArrayList<Any?>((1..17).map { "a$it" }))))
        assertTrue(Lease.verifyLease(rec("approvers", jl("A1", s(128)))))
        assertFalse(Lease.verifyLease(rec("approvers", jl("A1", s(129)))))
        assertFalse(Lease.verifyLease(rec("approvers", jl(s(129), "A1"))))
        assertFalse(Lease.verifyLease(rec("approvers", jl("A1", ""))))
        assertFalse(Lease.verifyLease(rec("approvers", jl("A1", 3L))))
        assertFalse(Lease.verifyLease(rec("approvers", "A1")))
        assertFalse(Lease.verifyLease(rec("approvers", jm("a", "A1"))))
        assertFalse(Lease.verifyLease(rec("approvers", null)))
        // the signature covers exactly the body
        assertFalse(Lease.verifyLease(LinkedHashMap(rec()).also { it["holder"] = "H2" }))
        assertFalse(Lease.verifyLease(LinkedHashMap(rec()).also { it["sig"] = rec("holder", "H2")["sig"] }))
        assertFalse(Lease.verifyLease(LinkedHashMap(rec()).also { it.remove("sig") }))
        assertTrue(Lease.verifyLease(LinkedHashMap(rec()).also { it["extra"] = "ignored" }))
    }

    @Test fun revocationShape() {
        assertTrue(Lease.verifyLeaseRevocation(rev("lease", "L1", 5L)))
        assertTrue(Lease.verifyLeaseRevocation(rev("grant", "g1", 0L)))
        assertTrue(Lease.verifyLeaseRevocation(rev("prefix", "db/prod", 5L)))
        assertTrue(Lease.verifyLeaseRevocation(rev("lease", s(256), 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", s(257), 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "", 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", 3L, 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", 5L, v = 2L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", 5L, v = "1")))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", 5L, v = Json.Num("1.5"))))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", -1L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", "5")))
        assertFalse(Lease.verifyLeaseRevocation(rev("lease", "L1", Json.Num("1.5"))))
        assertFalse(Lease.verifyLeaseRevocation(rev("leases", "L1", 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev(null, "L1", 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("prefix", "DB/Prod", 5L)))
        assertFalse(Lease.verifyLeaseRevocation(rev("prefix", "db/", 5L)))
        assertTrue(Lease.verifyLeaseRevocation(rev("grant", "DB/Prod", 5L)))
        assertFalse(Lease.verifyLeaseRevocation(null))
        assertFalse(Lease.verifyLeaseRevocation(jl()))
        assertFalse(Lease.verifyLeaseRevocation(LinkedHashMap(rev("lease", "L1", 5L)).also { it["value"] = "L2" }))
    }

    @Test fun sodReasons() {
        assertNull(Lease.sodError("R", "H", listOf("A")))
        assertNull(Lease.sodError("R", "H", listOf("A"), 1))
        assertEquals("minApprovals must be a positive integer", Lease.sodError("R", "H", emptyList(), 0))
        assertEquals("minApprovals must be a positive integer", Lease.sodError("R", "H", listOf("A"), -1))
        assertEquals("an approver is listed twice", Lease.sodError("R", "H", listOf("A", "A")))
        assertEquals("the requester may not approve their own request", Lease.sodError("R", "H", listOf("A", "R")))
        assertEquals("the holder may not approve its own lease", Lease.sodError("R", "H", listOf("A", "H")))
        assertEquals("an approver appears in the holder's delegation chain", Lease.sodError("R", "H", listOf("A", "C"), 1, null, listOf("X", "C")))
        assertNull(Lease.sodError("R", "H", listOf("A"), 1, null, listOf("X", "C")))
        assertEquals("an approver is not eligible", Lease.sodError("R", "H", listOf("A", "B"), 1, listOf("A")))
        assertNull(Lease.sodError("R", "H", listOf("A", "B"), 2, listOf("A", "B")))
        assertNull(Lease.sodError("R", "H", listOf("A", "B"), 2))
        assertEquals("1 approver(s), need 2", Lease.sodError("R", "H", listOf("A"), 2))
        assertEquals("0 approver(s), need 1", Lease.sodError("R", "H", emptyList()))
        assertEquals("2 approver(s), need 3", Lease.sodError("R", "H", listOf("A", "B"), 3, listOf("A", "B"), listOf("Z")))
        assertTrue(Lease.pathUnder("db/prod/ro", "db/prod"))
        assertTrue(Lease.pathUnder("db/prod", "db/prod"))
        assertFalse(Lease.pathUnder("db/production", "db/prod"))
        assertFalse(Lease.pathUnder("db", "db/prod"))
    }

    @Test fun acceptCodesInOrder() {
        val r = reg()
        refused(r.accept(null), "bad_record")
        refused(r.accept(rec("v", 2L)), "bad_record")
        val stranger = signedLease(LinkedHashMap(base()).also { it["authority"] = pub("k05-lease/stranger") }, "k05-lease/stranger")
        assertTrue(Lease.verifyLease(stranger))
        refused(r.accept(stranger), "unknown_authority")
        refused(r.accept(rec("approvers", jl("R"))), "sod", "the requester may not approve their own request")
        refused(r.accept(rec("approvers", jl("A1")), listOf("A1")), "sod", "an approver appears in the holder's delegation chain")
        refused(reg(minApprovals = 2).accept(rec()), "sod", "1 approver(s), need 2")
        refused(reg(eligible = listOf("B")).accept(rec()), "sod", "an approver is not eligible")
        // cap = issued_at + max_ttl: equal is fine, one past is not
        refused(r.accept(rec("max_ttl", 999L)), "over_max_ttl")
        taken(r.accept(rec("lease_id", "cap", "max_ttl", 1000L)), 1)
        refused(r.accept(rec("lease_id", "L9", "seq", 2L, "renewed_at", 1500L)), "bad_seq", "a new lease starts at seq 1")
        assertNull(r.get("L9"))
        assertTrue(r.history("L9").isEmpty())
        // the default chain is empty
        taken(r.accept(rec()), 1)
        assertEquals(rec()["sig"], r.get("L1")!!["sig"])
    }

    /** lease.ts:219 (the constructor) and :245 (right after over_max_ttl). */
    @Test fun maxTtlCeiling() {
        fun ceiling(c: Long?) = Lease.Registry(Lease.Policy(listOf(AUTH), maxTtlCeiling = c))
        for (bad in listOf(0L, -1L, 9007199254740992L, Long.MAX_VALUE)) {
            val e = assertThrows(IllegalArgumentException::class.java) { ceiling(bad) }
            assertEquals("LeaseRegistry: maxTtlCeiling must be a positive integer", e.message)
        }
        ceiling(1L)
        ceiling(9007199254740991L)
        // base max_ttl is 5000
        refused(ceiling(4999L).accept(rec()), "ttl_ceiling")
        taken(ceiling(5000L).accept(rec()), 1)
        taken(ceiling(5001L).accept(rec()), 1)
        taken(ceiling(null).accept(rec()), 1)
        // over_max_ttl (cap = issued_at + max_ttl) is reported first
        refused(ceiling(1L).accept(rec("max_ttl", 999L)), "over_max_ttl")
    }

    @Test fun renewalsAndHistory() {
        val r = reg()
        val issue = rec()
        taken(r.accept(issue, emptyList()), 1)
        assertSame(issue, r.get("L1"))
        // the same record again: ok, nothing replaced
        taken(r.accept(rec(), emptyList()), 1, replaced = false)
        refused(r.accept(rec("justification_digest", "other")), "lease_fork")
        refused(r.accept(rec("seq", 3L, "renewed_at", 1500L, "expires_at", 2500L, "justification_digest", "j3")), "bad_seq", "renewals advance seq by exactly 1")
        // renewal mismatch on every pinned member
        for ((k, v) in listOf("authority" to AUTH2, "path" to "db/other", "grant_ref" to "g2", "holder" to "H2", "requester" to "R2", "max_ttl" to 6000L, "issued_at" to 900L)) {
            val renew = rec("seq", 2L, "renewed_at", 1500L, "expires_at", 2500L, "justification_digest", "j2", k, v)
            assertTrue(k, Lease.verifyLease(renew))
            refused(r.accept(renew), "renewal_mismatch")
        }
        // renewing at or after the current expiry is too late
        refused(r.accept(rec("seq", 2L, "renewed_at", 2000L, "expires_at", 3000L, "justification_digest", "j2")), "expired_lease", "an expired lease cannot be renewed")
        // must extend: the same expiry is not an extension
        refused(r.accept(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 2000L, "justification_digest", "j2")), "not_extending")
        refused(r.accept(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 2500L)), "stale_justification")
        val second = rec("seq", 2L, "renewed_at", 1999L, "expires_at", 2001L, "justification_digest", "j2")
        taken(r.accept(second), 2)
        assertSame(second, r.get("L1"))
        val snapshot = r.history("L1")
        assertEquals(2, snapshot.size)
        // an earlier renewal time than the current record's does not extend
        refused(r.accept(rec("seq", 3L, "renewed_at", 1998L, "expires_at", 3000L, "justification_digest", "j3")), "not_extending")
        refused(r.accept(rec(), emptyList()), "stale_seq")
        val third = rec("seq", 3L, "renewed_at", 1999L, "expires_at", 3000L, "justification_digest", "j3")
        taken(r.accept(third), 3)
        val h = r.history("L1")
        assertEquals(3, h.size)
        assertEquals(2, snapshot.size) // a copy, not the live ledger
        assertEquals(listOf(1L, 2L, 3L), h.map { it.seq })
        assertEquals(listOf(1000L, 1999L, 1999L), h.map { it.renewedAt })
        assertEquals(listOf(2000L, 2001L, 3000L), h.map { it.expiresAt })
        assertEquals(listOf("j1", "j2", "j3"), h.map { it.justificationDigest })
        assertTrue(r.history("nope").isEmpty())
        assertNull(r.get("nope"))
        // freshJustification off: the same justification may renew
        val lax = reg(fresh = false)
        taken(lax.accept(rec()), 1)
        taken(lax.accept(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 2500L)), 2)
        assertEquals(listOf("j1", "j1"), lax.history("L1").map { it.justificationDigest })
    }

    @Test fun revocationsCoverAndCount() {
        val r = reg()
        val bad = r.revoke(rev("lease", "L1", 5L, v = 2L))
        assertFalse(bad.ok); assertEquals("bad_record", bad.code); assertEquals(0, bad.revoked)
        val strange = r.revoke(rev("lease", "L1", 5L, key = "k05-lease/stranger"))
        assertFalse(strange.ok); assertEquals("unknown_authority", strange.code); assertEquals(0, strange.revoked)
        taken(r.accept(rec()), 1)
        taken(r.accept(rec("lease_id", "L2", "path", "db/prod/ro", "grant_ref", "g2")), 1)
        taken(r.accept(rec("lease_id", "L3", "path", "db/production", "grant_ref", "g1", "issued_at", 1500L, "renewed_at", 1500L, "expires_at", 2500L)), 1)
        // revoked_at before every issue time covers nothing
        var x = r.revoke(rev("prefix", "db", 999L))
        assertTrue(x.ok); assertNull(x.code); assertEquals(0, x.revoked)
        // revoked_at equal to an issue time covers it (issued_at <= revoked_at)
        x = r.revoke(rev("grant", "g1", 1000L))
        assertTrue(x.ok); assertEquals(1, x.revoked)
        x = r.revoke(rev("grant", "g1", 1500L))
        assertEquals(2, x.revoked)
        x = r.revoke(rev("prefix", "db/prod", 9999L))
        assertEquals(2, x.revoked)
        x = r.revoke(rev("lease", "L2", 9999L))
        assertEquals(1, x.revoked)
        x = r.revoke(rev("lease", "L9", 9999L))
        assertEquals(0, x.revoked)
        val before = r.revocations.size
        assertEquals(6, before)
        // idempotent: the same signed revocation is stored once
        x = r.revoke(rev("lease", "L2", 9999L))
        assertTrue(x.ok); assertEquals(1, x.revoked)
        assertEquals(before, r.revocations.size)
        // a revoked lease cannot be (re)issued or renewed
        refused(r.accept(rec("lease_id", "L2", "path", "db/prod/ro", "grant_ref", "g2")), "revoked")
        val r2 = reg()
        r2.revoke(rev("lease", "L1", 999L))
        taken(r2.accept(rec()), 1)
        r2.revoke(rev("lease", "L1", 1000L))
        refused(r2.accept(rec("seq", 2L, "renewed_at", 1500L, "expires_at", 2500L, "justification_digest", "j2")), "revoked")
    }

    @Test fun checkLeaseDecisions() {
        val r = reg()
        val issue = rec("max_ttl", 1500L)
        fun d(p: Any?, now: Any?, decision: String, code: String?, id: String?, exp: Long? = null) {
            val got = Lease.checkLease(p, r, now)
            assertEquals("$code", decision, got.decision)
            assertEquals(code, got.code)
            assertEquals(code, id, got.leaseId)
            assertEquals(code, exp, got.expiresAt)
        }
        d(issue, "1500", "deny", "bad_input", null)
        d(issue, -1L, "deny", "bad_input", null)
        d(issue, Json.Num("1500.5"), "deny", "bad_input", null)
        d(rec("v", 2L), 1500L, "deny", "bad_record", null)
        d(issue, 1500L, "deny", "unknown_lease", "L1")
        taken(r.accept(issue), 1)
        d(issue, 999L, "deny", "not_yet_valid", "L1")
        d(issue, 1000L, "allow", null, "L1", 2000L)
        d(issue, 1999L, "allow", null, "L1", 2000L)
        d(issue, 2000L, "deny", "expired", "L1")
        val renewed = rec("max_ttl", 1500L, "seq", 2L, "renewed_at", 1800L, "expires_at", 2500L, "justification_digest", "j2")
        taken(r.accept(renewed), 2)
        d(issue, 1900L, "deny", "superseded", "L1")
        d(renewed, 1799L, "deny", "not_yet_valid", "L1")
        d(renewed, 1800L, "allow", null, "L1", 2500L)
        d(renewed, 2499L, "allow", null, "L1", 2500L)
        d(renewed, 2500L, "deny", "past_max_ttl", "L1")
        val r3 = reg()
        val wide = rec("lease_id", "W", "max_ttl", 5000L)
        taken(r3.accept(wide), 1)
        assertEquals("allow", Lease.checkLease(wide, r3, 1999L).decision)
        assertEquals("expired", Lease.checkLease(wide, r3, 2000L).code)
        assertEquals("past_max_ttl", Lease.checkLease(wide, r3, 6000L).code)
        assertEquals("allow", Lease.checkLease(wide, r3, 1000L).decision)
        r3.revoke(rev("lease", "W", 1000L))
        val got = Lease.checkLease(wide, r3, 1500L)
        assertEquals("deny", got.decision); assertEquals("revoked", got.code); assertEquals("W", got.leaseId); assertNull(got.expiresAt)
    }
}
