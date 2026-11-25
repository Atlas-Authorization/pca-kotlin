package net.atlasauth.pca.ciba

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import net.atlasauth.pca.verifier.Agent
import net.atlasauth.pca.verifier.Approvals
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * Conformance cases for an [CibaApproval.ApprovalStore], plus broker-level cases run over it. Run them against your store:
 * `for (c in CibaStoreConformance.approvalStoreCases({ MyStore() }, ::reopen)) c.run()`.
 *
 * Each case throws an [AssertionError] when the store breaks the contract: absent means version 0, `cas` writes only at the expected
 * version and bumps it by one, exactly one of many concurrent `cas` calls wins, returned values are snapshots, and (with `reopen`)
 * written records survive a restart. The broker cases check what the contract is for: exactly one concurrent decision wins and an
 * approval redeems once.
 */
object CibaStoreConformance {
    /** One case: a [name] and a [run] that throws on a contract violation. */
    class Case(val name: String, val run: () -> Unit)

    private fun same(a: Any?, b: Any?): Boolean = Json.canonicalize(a) == Json.canonicalize(b)

    private fun expect(ok: Boolean, what: String) {
        if (!ok) throw AssertionError(what)
    }

    private fun expectVersioned(got: CibaApproval.Versioned?, version: Long, value: Any?, what: String) {
        expect(got != null && got.version == version && same(got.value, value), "$what: expected version $version with value ${Json.canonicalize(value)}, got " + (if (got == null) "absent" else "${got.version} ${Json.canonicalize(got.value)}"))
    }

    private fun <T> parallel(n: Int, job: (Int) -> T): List<T> {
        val pool = Executors.newFixedThreadPool(n)
        try {
            return pool.invokeAll((0 until n).map { i -> Callable { job(i) } }).map { it.get() }
        } finally {
            pool.shutdown()
        }
    }

    /**
     * @param make a store over a fresh, empty backing location each call.
     * @param reopen for a persistent store: a NEW store object over the same backing location as the previous one, as after a restart.
     *   Omit to skip the durability case.
     */
    @JvmStatic
    @JvmOverloads
    fun approvalStoreCases(make: () -> CibaApproval.ApprovalStore, reopen: ((CibaApproval.ApprovalStore) -> CibaApproval.ApprovalStore)? = null): List<Case> {
        val cases = arrayListOf(
            Case("an absent key reads null") { expect(make().get("nope") == null, "an absent key must read null") },
            Case("cas at version 0 creates the key at version 1 with the whole value") {
                val s = make()
                val v = Issue.obj("a" to 1L, "nested" to Issue.obj("b" to listOf<Any?>("x", 2L, null)))
                expect(s.cas("k", 0, v), "cas at version 0 must create an absent key")
                expectVersioned(s.get("k"), 1, v, "after the create")
            },
            Case("cas at version 0 on an existing key is refused and changes nothing") {
                val s = make()
                s.cas("k", 0, "first")
                expect(!s.cas("k", 0, "second"), "cas at version 0 on an existing key must be refused")
                expectVersioned(s.get("k"), 1, "first", "after the refused create")
            },
            Case("cas succeeds only at the current version and bumps it by exactly one") {
                val s = make()
                s.cas("k", 0, 1L)
                expect(s.cas("k", 1, 2L), "cas at the current version must succeed")
                expect(!s.cas("k", 1, 3L), "a stale cas must be refused")
                expect(!s.cas("k", 5, 4L), "a cas from the future must be refused")
                expect(s.cas("k", 2, 5L), "cas at the new current version must succeed")
                expectVersioned(s.get("k"), 3, 5L, "after three writes")
            },
            Case("cas on a key that does not exist at a non-zero version is refused and creates nothing") {
                val s = make()
                expect(!s.cas("k", 1, "x"), "cas at a non-zero version on an absent key must be refused")
                expect(s.get("k") == null, "a refused cas must create nothing")
            },
            Case("keys are independent") {
                val s = make()
                s.cas("a", 0, "A")
                s.cas("b", 0, "B")
                s.cas("a", 1, "A2")
                expectVersioned(s.get("a"), 2, "A2", "key a")
                expectVersioned(s.get("b"), 1, "B", "key b")
            },
            Case("a read is a snapshot: changing the returned value does not change the store") {
                val s = make()
                s.cas("k", 0, Issue.obj("list" to arrayListOf<Any?>(1L)))
                val got = s.get("k")
                try { ((got?.value as? Map<*, *>)?.get("list") as? MutableList<Any?>)?.add(2L) } catch (e: UnsupportedOperationException) { /* an immutable copy is as good */ }
                expectVersioned(s.get("k"), 1, Issue.obj("list" to listOf<Any?>(1L)), "after mutating a read")
            },
            Case("a written value is a snapshot: changing it after cas does not change the store") {
                val s = make()
                val list = arrayListOf<Any?>(1L)
                s.cas("k", 0, Issue.obj("list" to list))
                list.add(2L)
                expectVersioned(s.get("k"), 1, Issue.obj("list" to listOf<Any?>(1L)), "after mutating the written value")
            },
            Case("exactly one of many concurrent creates wins") {
                val s = make()
                val results = parallel(32) { i -> s.cas("k", 0, i.toLong()) }
                expect(results.count { it } == 1, "exactly one concurrent create must win, got ${results.count { it }}")
                val stored = s.get("k")
                expectVersioned(stored, 1, results.indexOf(true).toLong(), "after the concurrent creates")
            },
            Case("exactly one of many concurrent updates at the same version wins") {
                val s = make()
                s.cas("k", 0, "base")
                val results = parallel(32) { i -> s.cas("k", 1, i.toLong()) }
                expect(results.count { it } == 1, "exactly one concurrent update must win, got ${results.count { it }}")
                expectVersioned(s.get("k"), 2, results.indexOf(true).toLong(), "after the concurrent updates")
            },
            Case("a retry loop over concurrent writers loses no increment") {
                val s = make()
                s.cas("n", 0, 0L)
                parallel(24) {
                    while (true) {
                        val cur = s.get("n")
                        if (cur != null && s.cas("n", cur.version, (cur.value as Number).toLong() + 1)) break
                    }
                }
                expectVersioned(s.get("n"), 25, 24L, "after 24 increments")
            },
        )
        if (reopen != null) {
            cases.add(
                Case("records and their versions survive reopening the store") {
                    val s = make()
                    s.cas("k", 0, Issue.obj("v" to 1L))
                    s.cas("k", 1, Issue.obj("v" to 2L))
                    val again = reopen(s)
                    expectVersioned(again.get("k"), 2, Issue.obj("v" to 2L), "after reopening")
                    expect(!again.cas("k", 1, Issue.obj("v" to "stale")), "a stale cas after reopening must be refused")
                    expect(again.cas("k", 2, Issue.obj("v" to 3L)), "a current cas after reopening must succeed")
                },
            )
        }
        return cases
    }

    private fun stepUp(): Map<String, Any?> {
        val principal = Keys.ed25519(Keys.edGenerate())
        val a = Agent.fromPrincipal(
            Facade.AgentOptions(
                principal = principal, goal = "pay suppliers", permissions = Issue.obj("stripe" to listOf("payout")), limits = Issue.obj("payout" to "\$100"),
                aud = "ins_conformance", riskPolicy = Issue.obj("theta1" to Json.Num("0.3"), "theta2" to Json.Num("0.6")), now = 0L,
            ),
        )
        val r = Approvals.reviewAction(
            a, "stripe.payout", "acct:1", Issue.obj("amount" to 80L, "currency" to "USD", "payee" to "bob"),
            Approvals.ReviewOptions(now = 1L, goal = "pay suppliers", insecureUnboundApproval = true),
        )
        if (r["kind"] != "step_up") throw IllegalStateException("conformance fixture did not produce a step-up")
        @Suppress("UNCHECKED_CAST")
        return r["request"] as Map<String, Any?>
    }

    private fun brokers(make: () -> CibaApproval.ApprovalStore, n: Int): List<CibaApproval.ApprovalBroker> {
        val store = make()
        return (0 until n).map { CibaApproval.createDurableCibaBroker(CibaApproval.DurableBrokerOptions().also { it.store = store }) }
    }

    /** Broker-level cases over a store: what the compare-and-set contract is for. */
    @JvmStatic
    fun approvalBrokerCases(make: () -> CibaApproval.ApprovalStore): List<Case> = listOf(
        Case("concurrent resolves through separate brokers: exactly one wins and its decision stands") {
            val bs = brokers(make, 8)
            val req = bs[0].start(stepUp(), null)
            val id = req["auth_req_id"] as String
            val won = parallel(bs.size) { i ->
                try { bs[i].resolve(id, if (i % 2 == 0) "approve" else "deny", "user-$i"); i } catch (e: RuntimeException) { -1 }
            }.filter { it >= 0 }
            expect(won.size == 1, "exactly one concurrent resolve must win, got ${won.size}")
            val final = bs[0].get(id)
            expect(final?.get("decidedBy") == "user-${won[0]}", "the winner's decision must stand")
            expect(final?.get("status") == (if (won[0] % 2 == 0) "approved" else "denied"), "the stored status must be the winner's decision")
        },
        Case("an approval redeems once even when many brokers redeem at the same time") {
            val bs = brokers(make, 8)
            val req = bs[0].start(stepUp(), null)
            val id = req["auth_req_id"] as String
            bs[0].resolve(id, "approve", "owner")
            val outs = parallel(bs.size) { i -> bs[i].token(id) }
            expect(outs.count { it["ok"] == true } == 1, "an approval must redeem exactly once, got ${outs.count { it["ok"] == true }}")
        },
        Case("a second broker over the same store sees the decision of the first") {
            val bs = brokers(make, 2)
            val req = bs[0].start(stepUp(), null)
            val id = req["auth_req_id"] as String
            expect(bs[1].poll(id)["status"] == "pending", "a fresh request must be pending for the second broker")
            bs[0].resolve(id, "approve", "owner")
            expect(bs[1].poll(id)["status"] == "approved", "the second broker must see the first one's decision")
            var late = false
            try { bs[1].resolve(id, "deny", "late") } catch (e: RuntimeException) { late = true }
            expect(late, "a late resolve must be refused")
        },
    )
}
