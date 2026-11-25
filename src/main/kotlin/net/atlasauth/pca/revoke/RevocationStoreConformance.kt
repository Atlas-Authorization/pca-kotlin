package net.atlasauth.pca.revoke

import java.util.concurrent.Callable
import java.util.concurrent.Executors

/**
 * Conformance cases for a [RevocationStore]. Run them against your own store:
 * `RevocationStoreConformance.cases({ MyStore() }).forEach { it.run() }`.
 *
 * Each case throws an [AssertionError] when the store breaks the contract. A store that passes keeps (kind, value) keys apart,
 * replaces rather than duplicates, hands out snapshots, and loses nothing under concurrent writes. Durability across a restart is
 * checked with `reopen`.
 */
object RevocationStoreConformance {
    /** A named check. */
    class Case(val name: String, val run: () -> Unit)

    private fun entry(kind: String, value: String, reason: String? = null, notBefore: Double? = null) = RevocationEntry(
        kind, value, if (kind == "prefix") value.split(",") else null, reason ?: "r-$kind-$value", 1000.0, notBefore,
    )

    private fun check(ok: Boolean, what: String) { if (!ok) throw AssertionError(what) }

    private fun sortedValues(xs: List<RevocationEntry>): List<String> =
        xs.sortedBy { it.kind + it.value }.map { "${it.kind}/${it.value}/${it.reason}/${it.notBefore}" }

    /**
     * @param make a fresh, empty store each call
     * @param reopen for stores that persist: opens the same backing location again (null skips the durability case)
     */
    @JvmStatic
    @JvmOverloads
    fun cases(make: () -> RevocationStore, reopen: ((RevocationStore) -> RevocationStore)? = null): List<Case> {
        val cs = mutableListOf(
            Case("starts empty") {
                check(make().all().isEmpty(), "a new store is not empty")
                check(make().get("cap", "x") == null, "a new store returns an entry")
            },
            Case("add then get returns the whole entry, including notBefore") {
                val s = make()
                val e = entry("cap", "c1", notBefore = 5000.0)
                s.add(e)
                val g = s.get("cap", "c1")
                check(g != null && sortedValues(listOf(g)) == sortedValues(listOf(e)), "get differs from add")
            },
            Case("the same value under different kinds is kept apart") {
                val s = make()
                s.add(entry("cap", "k"))
                s.add(entry("holder", "k"))
                s.add(entry("issuer", "k"))
                check(s.all().size == 3, "kinds collapsed")
                check(s.remove("holder", "k"), "remove said nothing was removed")
                check(s.get("cap", "k")?.kind == "cap", "cap lost")
                check(s.get("issuer", "k")?.kind == "issuer", "issuer lost")
                check(s.get("holder", "k") == null, "holder kept")
            },
            Case("add at an existing key replaces, it does not duplicate") {
                val s = make()
                s.add(entry("cap", "c", "first"))
                s.add(entry("cap", "c", "second"))
                check(s.all().size == 1, "duplicated")
                check(s.get("cap", "c")?.reason == "second", "not replaced")
            },
            Case("remove reports whether something was removed, and only once") {
                val s = make()
                s.add(entry("cap", "c"))
                check(s.remove("cap", "c"), "first remove")
                check(!s.remove("cap", "c"), "second remove")
                check(!s.remove("cap", "never-added"), "remove of a missing key")
            },
            Case("prefix paths that differ stay distinct") {
                val s = make()
                s.add(entry("prefix", "a,b"))
                s.add(entry("prefix", "a"))
                s.add(entry("prefix", "b,a"))
                check(s.all().size == 3, "paths collapsed")
                check(s.remove("prefix", "a"), "remove a")
                val left = s.all().map { it.value }.sorted()
                check(left == listOf("a,b", "b,a"), "wrong entries left: $left")
            },
            Case("all() is a snapshot: changing it does not change the store") {
                val s = make()
                s.add(entry("cap", "c"))
                val snap = s.all()
                try {
                    (snap as MutableList<RevocationEntry>).removeAt(snap.size - 1)
                    snap.add(entry("cap", "forged"))
                } catch (ignored: UnsupportedOperationException) { // a read-only snapshot is fine
                } catch (ignored: ClassCastException) {
                }
                check(s.all().size == 1, "snapshot edit reached the store")
                check(s.get("cap", "forged") == null, "forged entry reached the store")
            },
            Case("clear drops everything") {
                val s = make()
                s.add(entry("cap", "c"))
                s.add(entry("prefix", "a,b"))
                s.clear()
                check(s.all().isEmpty(), "not empty after clear")
                check(s.get("cap", "c") == null, "entry after clear")
            },
            Case("interleaved adds and removes from many threads lose nothing") {
                val s = make()
                val n = 200
                // Each odd task removes the even entry it added itself first, so the expected set does not depend on scheduling.
                val ex = Executors.newFixedThreadPool(8)
                try {
                    (0 until n step 2).map { k ->
                        ex.submit(Callable {
                            s.add(entry("cap", "c$k"))
                            s.add(entry("cap", "c${k + 1}"))
                            s.remove("cap", "c$k")
                        })
                    }.forEach { it.get() }
                } finally {
                    ex.shutdown()
                }
                val left = s.all().map { it.value }.toSet()
                check(left.size == n / 2, "expected ${n / 2} entries, found ${left.size}")
                for (i in 0 until n) check(("c$i" in left) == (i % 2 == 1), "wrong membership for c$i")
            },
        )
        if (reopen != null) {
            cs.add(Case("entries survive reopening the store") {
                val s = make()
                val a = entry("cap", "durable", notBefore = 9000.0)
                val b = entry("prefix", "r,m")
                s.add(a)
                s.add(b)
                s.add(entry("holder", "gone"))
                s.remove("holder", "gone")
                check(sortedValues(reopen(s).all()) == sortedValues(listOf(a, b)), "reopened store differs")
            })
        }
        return cs
    }
}
