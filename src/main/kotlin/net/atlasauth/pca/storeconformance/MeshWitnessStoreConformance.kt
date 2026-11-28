package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.storeconformance.Suite.Check
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.MemoryMeshWitnessStore
import net.atlasauth.pca.verifier.MeshDomain
import net.atlasauth.pca.verifier.MeshWitness
import net.atlasauth.pca.verifier.MeshWitnessStore
import net.atlasauth.pca.verifier.StoreJs

/**
 * Conformance cases for a [MeshWitnessStore]: the durable memory of a mesh log witness. A witness cosigns a head only if it extends
 * the last head THIS witness cosigned. A store that forgets across a restart, or that loses a save and still lets the cosignature
 * out, lets a domain walk the witness back and show two verifiers different histories. The cases check the store by itself (round
 * trip, replace, copy semantics, atomicity, reopen) and through a real [MeshWitness] (every cosignature is persisted first; a
 * restarted witness refuses rollback and forks; a failed save refuses the cosignature and changes nothing; damaged storage is not
 * read as empty).
 */
@Suppress("UNCHECKED_CAST")
object MeshWitnessStoreConformance {
    /** The adapter a store author implements. */
    interface Adapter {
        fun name(): String

        /** A fresh, empty store. */
        fun make(): MeshWitnessStore

        /** True when [reopen] is implemented (a store that can persist). */
        fun canReopen(): Boolean = false

        /** A new store object over the same backing storage as `previous` (a restart). */
        fun reopen(previous: MeshWitnessStore): MeshWitnessStore = throw UnsupportedOperationException("reopen")

        /** True when [damage] is implemented (a store that can detect damage). */
        fun canDamage(): Boolean = false

        /** Damage the backing storage of `store` so that `load` must fail. */
        fun damage(store: MeshWitnessStore): Unit = throw UnsupportedOperationException("damage")
    }

    /** The environment of one case. */
    class Env(val adapter: Adapter) : Suite.Handle

    private fun seed(label: String): ByteArray = ByteArray(32) { i -> ((label[i % label.length].code + i) and 0xff).toByte() }

    private fun key(label: String): Keys.EdKey = Keys.edFromSeed(seed(label))

    private fun cap(label: String): Map<String, Any?> {
        val cav = linkedMapOf<String, Any?>("type" to "scope", "actions" to arrayListOf<Any?>(label))
        return linkedMapOf("id" to label, "caveats" to arrayListOf<Any?>(cav))
    }

    /** Same domain key, different history: the second is a fork of the first from entry 0 on. */
    private fun twoLogs(): Pair<MeshDomain, MeshDomain> {
        val honest = MeshDomain("d", key("domain"))
        val fork = MeshDomain("d", key("domain"))
        honest.record(cap("a"))
        fork.record(cap("x"))
        return Pair(honest, fork)
    }

    private fun state(n: Long): MutableMap<String, Any?> {
        val head = linkedMapOf<String, Any?>(
            "domain" to "d$n", "size" to StoreJs.num(0L), "root" to "", "rev_root" to "r", "rev_size" to StoreJs.num(0L), "timestamp" to StoreJs.num(n),
        )
        val seen = linkedMapOf<String, Any?>("head" to head, "rev_ids" to ArrayList<Any?>())
        return linkedMapOf("seen" to arrayListOf<Any?>(seen))
    }

    private fun cosigs(ch: Map<String, Any?>): Int = (ch["cosigs"] as List<*>).size

    private fun thrown(r: () -> Unit): String = try {
        r()
        ""
    } catch (e: RuntimeException) {
        e.message.toString()
    }

    /** A store whose saves can be made to fail. */
    private class Flaky(val inner: MeshWitnessStore) : MeshWitnessStore {
        @Volatile var failing = false

        override fun load(): Map<String, Any?>? = inner.load()

        override fun save(state: Map<String, Any?>) {
            if (failing) throw IllegalStateException("disk full")
            inner.save(state)
        }
    }

    private fun witnessOver(store: MeshWitnessStore): MeshWitness {
        val o = MeshWitness.Options()
        o.store = store
        return MeshWitness(key("w"), o)
    }

    /** The cases that apply to `a` (reopen and damage cases only when the adapter implements them). */
    fun cases(a: Adapter): List<Check<Env>> {
        val cases = ArrayList<Check<Env>>()
        cases.add(Check<Env>("a fresh store loads nothing", "a store that was never written loads null") { Suite.ok(a.make().load() == null, "a fresh store must load null") })
        cases.add(Check<Env>("save then load returns the same state", "what was saved is what loads") {
            val s = a.make()
            s.save(state(1))
            Suite.eq(state(1), s.load())
        })
        cases.add(Check<Env>("a later save replaces the earlier one", "the last save wins") {
            val s = a.make()
            s.save(state(1))
            s.save(state(2))
            Suite.eq(state(2), s.load())
        })
        cases.add(Check<Env>("load returns a copy: changing it does not change the store", "mutating a loaded state leaves the store alone") {
            val s = a.make()
            s.save(state(1))
            val got = s.load()!!
            (got["seen"] as MutableList<Any?>).clear()
            Suite.eq(state(1), s.load())
        })
        cases.add(Check<Env>("save keeps its own copy: changing the argument afterwards does not change the store", "mutating a saved state leaves the store alone") {
            val s = a.make()
            val st = state(1)
            s.save(st)
            (st["seen"] as MutableList<Any?>).clear()
            Suite.eq(state(1), s.load())
        })
        cases.add(Check<Env>("a witness persists every cosignature before returning it", "the stored state is the witness's state after each cosignature") {
            val s = a.make()
            val w = witnessOver(s)
            val honest = twoLogs().first
            val ch = honest.publishHead(listOf(w), 1_000.0, null)
            Suite.eq(w.exportState(), s.load())
            val heads = (s.load()!!["seen"] as List<*>).map { StoreJs.map(it)!!["head"] }
            Suite.eq(listOf(ch["head"]), heads)
        })
        cases.add(Check<Env>("a failed save refuses the cosignature and leaves the witness unchanged", "the cosignature is released only after the state is saved") {
            val flaky = Flaky(a.make())
            val w = witnessOver(flaky)
            val honest = twoLogs().first
            honest.publishHead(listOf(w), 1_000.0, null)
            val before = Json.canonicalize(w.exportState())
            honest.record(cap("b"))
            flaky.failing = true
            val threw = thrown { honest.publishHead(listOf(w), 2_000.0, null) }
            Suite.eq("witness: could not persist state; refusing to cosign", threw)
            Suite.eq(before, Json.canonicalize(w.exportState()))
            Suite.eq(Json.parseLenient(before), flaky.inner.load())
            flaky.failing = false
            Suite.ok(cosigs(honest.publishHead(listOf(w), 2_000.0, null)) == 1, "the same head is cosigned once the disk recovers")
        })
        if (a.canReopen()) {
            cases.add(Check<Env>("state survives reopening the store", "a new store object over the same storage loads the saved state") {
                val s = a.make()
                s.save(state(3))
                Suite.eq(state(3), a.reopen(s).load())
            })
            cases.add(Check<Env>("a restarted witness remembers what it cosigned: it refuses a fork and a rollback", "restart safety: a witness never cosigns a fork of what it saw") {
                val s = a.make()
                val w1 = witnessOver(s)
                val (honest, fork) = twoLogs()
                honest.publishHead(listOf(w1), 1_000.0, null)
                honest.record(cap("b"))
                honest.publishHead(listOf(w1), 2_000.0, null)
                val w2 = witnessOver(a.reopen(s))
                Suite.eq(2, w2.lastSeen(honest.id)!!["size"])
                fork.record(cap("y"))
                fork.record(cap("z"))
                Suite.ok(thrown { fork.publishHead(listOf(w2), 3_000.0, null) }.isNotEmpty(), "a fork that grew past the remembered size must be refused")
                val rollback = MeshDomain("d", key("domain"))
                rollback.record(cap("a"))
                Suite.ok(thrown { rollback.publishHead(listOf(w2), 3_000.0, null) }.isNotEmpty(), "a rollback to the first head must be refused")
                Suite.ok(cosigs(honest.publishHead(listOf(w2), 3_000.0, null)) == 1, "the honest log is still cosigned")
            })
        }
        if (a.canDamage()) {
            cases.add(Check<Env>("damaged storage makes load throw, so a witness never starts empty over it", "damaged storage is refused, never read as empty") {
                val s = a.make()
                // a state a witness accepts, so that only the damage can make construction fail
                val w0 = MeshWitness(key("w"))
                val d0 = MeshDomain("d", key("domain"))
                d0.record(cap("a"))
                d0.publishHead(listOf(w0), 1_000.0, null)
                s.save(w0.exportState())
                a.damage(s)
                Suite.ok(thrown { s.load() }.isNotEmpty(), "load must throw on damaged storage")
                Suite.ok(thrown { witnessOver(s) }.isNotEmpty(), "constructing a witness over damaged storage must throw")
            })
        }
        return cases
    }

    /** Run the cases that apply to [adapter]. */
    fun run(adapter: Adapter): Suite.Report = Suite.run("mesh witness store", adapter.name(), true, { Env(adapter) }, cases(adapter), null)

    /** GOOD, in process: the memory store (no reopen, no damage). */
    fun memoryAdapter(): Adapter = object : Adapter {
        override fun name() = "MemoryMeshWitnessStore"

        override fun make(): MeshWitnessStore = MemoryMeshWitnessStore()
    }

    /** BAD: a store that forgets everything (load nothing, save nothing). The suite MUST flag it. */
    fun forgetfulAdapter(): Adapter {
        val forget = object : MeshWitnessStore {
            override fun load(): Map<String, Any?>? = null

            override fun save(state: Map<String, Any?>) { /* forgets */ }
        }
        return object : Adapter {
            override fun name() = "BAD forgetful (loads nothing, saves nothing)"

            override fun make(): MeshWitnessStore = forget

            override fun canReopen() = true

            override fun reopen(previous: MeshWitnessStore): MeshWitnessStore = forget
        }
    }

    /** BAD: a store that accepts a save but returns a stale copy (a lost update); flagged by the round-trip and persistence cases. */
    fun staleAdapter(): Adapter = object : Adapter {
        override fun name() = "BAD stale (keeps the first state it was given)"

        override fun make(): MeshWitnessStore = object : MeshWitnessStore {
            private var first: Map<String, Any?>? = null

            @Synchronized
            override fun load(): Map<String, Any?>? = first?.let { StoreJs.map(StoreJs.deepCopy(it)) }

            @Synchronized
            override fun save(state: Map<String, Any?>) { if (first == null) first = StoreJs.map(StoreJs.deepCopy(state)) }
        }
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    fun referenceAdapters(): Map<String, () -> Adapter> = linkedMapOf(
        "mesh-witness-memory" to { memoryAdapter() },
        "bad-mesh-witness-forgetful" to { forgetfulAdapter() },
        "bad-mesh-witness-stale" to { staleAdapter() },
    )
}
