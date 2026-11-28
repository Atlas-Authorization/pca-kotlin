package net.atlasauth.pca.storeconformance

import java.util.concurrent.ConcurrentHashMap
import net.atlasauth.pca.verifier.Authorize

/**
 * Reference adapters. The GOOD one must pass the kit; the BAD ones are positive controls the kit MUST flag (a checker that passes
 * everything is worthless). Each bad adapter reproduces one real mistake from the replay-store verification work.
 */
object Reference {
    /** GOOD for ONE process: the library's in-memory state store. Not durable (declared), not shared between processes. */
    fun inMemoryAdapter(): StoreAdapter {
        val store = Authorize.MemoryStateStore()
        return object : StoreAdapter {
            override fun name(): String = "in-memory (MemoryStateStore)"
            override fun capabilities(): StoreAdapter.Capabilities = StoreAdapter.Capabilities().withDurable(false)
            override fun open(): StoreClient = object : StoreClient {
                override fun hasConsumeOnce(): Boolean = true
                override fun hasAdvance(): Boolean = true
                override fun consumeOnce(key: String, retainUntilMs: Double, nowMs: Double): Boolean {
                    // a non-finite clock or horizon must be refused, not saturated into a Long
                    require(nowMs.isFinite() && retainUntilMs.isFinite()) { "consumeOnce: retainUntilMs is before nowMs" }
                    return store.consumeOnce(key, retainUntilMs.toLong(), nowMs.toLong())
                }
                override fun advance(streamKey: String, counter: Double): Boolean = store.claim(streamKey, counter.toLong())?.ok == true
            }
        }
    }

    private fun yieldTurn() {
        Thread.yield()
        try { Thread.sleep(1) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
    }

    /** BAD: read, then write after a pause (no transaction / no compare-and-set). Two clients both read "absent". */
    fun readThenWriteAdapter(): StoreAdapter {
        val seen = ConcurrentHashMap<String, Double>()
        val counters = ConcurrentHashMap<String, Double>()
        return object : StoreAdapter {
            override fun name(): String = "BAD read-then-write (pause between check and set)"
            override fun capabilities(): StoreAdapter.Capabilities = StoreAdapter.Capabilities().withDurable(false)
            override fun open(): StoreClient = object : StoreClient {
                override fun hasConsumeOnce(): Boolean = true
                override fun hasAdvance(): Boolean = true
                override fun consumeOnce(key: String, retainUntilMs: Double, nowMs: Double): Boolean {
                    val until = seen[key]
                    yieldTurn()
                    if (until != null && !(nowMs.isFinite() && until < nowMs)) return false
                    seen[key] = retainUntilMs
                    return true
                }

                override fun advance(streamKey: String, counter: Double): Boolean {
                    val last = counters[streamKey]
                    yieldTurn()
                    if (last != null && !(counter > last)) return false
                    counters[streamKey] = counter
                    return true
                }
            }
        }
    }

    /** BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter. */
    fun volatileAdapter(): StoreAdapter {
        var store = Authorize.MemoryStateStore()
        return object : StoreAdapter {
            override fun name(): String = "BAD volatile (state lost on restart)"
            override fun capabilities(): StoreAdapter.Capabilities = StoreAdapter.Capabilities().withDurable(true)
            override fun hasRestart(): Boolean = true
            override fun restart() { store = Authorize.MemoryStateStore() }
            override fun open(): StoreClient = object : StoreClient {
                override fun hasConsumeOnce(): Boolean = true
                override fun hasAdvance(): Boolean = true
                override fun consumeOnce(key: String, retainUntilMs: Double, nowMs: Double): Boolean = store.consumeOnce(key, retainUntilMs.toLong(), nowMs.toLong())
                override fun advance(streamKey: String, counter: Double): Boolean = store.claim(streamKey, counter.toLong())?.ok == true
            }
        }
    }

    /** BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune). */
    fun evictingAdapter(capacity: Int): StoreAdapter {
        val seen = LinkedHashMap<String, Double>()
        val counters = LinkedHashMap<String, Double>()
        fun evict(m: MutableMap<String, Double>) {
            while (m.size > capacity) {
                val it = m.keys.iterator()
                it.next()
                it.remove()
            }
        }
        return object : StoreAdapter {
            override fun name(): String = "BAD evicting cache (capacity $capacity, evicts live records)"
            override fun capabilities(): StoreAdapter.Capabilities = StoreAdapter.Capabilities().withDurable(false)
            override fun open(): StoreClient = object : StoreClient {
                override fun hasConsumeOnce(): Boolean = true
                override fun hasAdvance(): Boolean = true
                override fun consumeOnce(key: String, retainUntilMs: Double, nowMs: Double): Boolean = synchronized(seen) {
                    val until = seen[key]
                    if (until != null && !(nowMs.isFinite() && until < nowMs)) return@synchronized false
                    seen[key] = retainUntilMs
                    evict(seen)
                    true
                }

                override fun advance(streamKey: String, counter: Double): Boolean = synchronized(counters) {
                    val last = counters[streamKey]
                    if (last != null && !(counter > last)) return@synchronized false
                    counters[streamKey] = counter
                    evict(counters)
                    true
                }
            }
        }
    }

    /** BAD: a counter that accepts a value EQUAL to the last one (`>=` instead of `>`), so one counter is accepted twice. */
    fun nonStrictCounterAdapter(): StoreAdapter {
        val counters = HashMap<String, Double>()
        return object : StoreAdapter {
            override fun name(): String = "BAD non-strict counter (accepts an equal value)"
            override fun capabilities(): StoreAdapter.Capabilities = StoreAdapter.Capabilities().withDurable(false).withConsumeOnce(false)
            override fun open(): StoreClient = object : StoreClient {
                override fun hasAdvance(): Boolean = true
                override fun advance(streamKey: String, counter: Double): Boolean = synchronized(counters) {
                    val last = counters[streamKey]
                    if (last != null && counter < last) return@synchronized false
                    counters[streamKey] = counter
                    true
                }
            }
        }
    }

    /**
     * Built-in adapters by name (`--adapter builtin:<name>`); each takes the `--option k=v` pairs. Known limit: the reference's
     * `durable-file` adapter (a crash-safe multi-process file store) is not here.
     */
    val REFERENCE_ADAPTERS: Map<String, (Map<String, String>) -> StoreAdapter> = linkedMapOf(
        "in-memory" to { _: Map<String, String> -> inMemoryAdapter() },
        "bad-read-then-write" to { _: Map<String, String> -> readThenWriteAdapter() },
        "bad-volatile" to { _: Map<String, String> -> volatileAdapter() },
        "bad-evicting" to { o: Map<String, String> -> evictingAdapter(o["capacity"]?.toDouble()?.toInt() ?: 64) },
        "bad-non-strict-counter" to { _: Map<String, String> -> nonStrictCounterAdapter() },
    )

    /**
     * Load a store adapter from a built-in name (`builtin:<name>`) or a class name: a [StoreAdapter] with a public no-argument
     * constructor, or a `java.util.function.Function<Map<String,String>, StoreAdapter>` factory.
     */
    @Suppress("UNCHECKED_CAST")
    fun loadAdapter(spec: String, options: Map<String, String>): StoreAdapter {
        val made: Any?
        if (spec.startsWith("builtin:")) {
            val name = spec.substring("builtin:".length)
            val f = REFERENCE_ADAPTERS[name]
                ?: throw IllegalArgumentException("unknown built-in adapter '$name' (known: " + REFERENCE_ADAPTERS.keys.joinToString(", ") + ")")
            made = f(options)
        } else {
            val inst = Class.forName(spec).getDeclaredConstructor().newInstance()
            made = if (inst is java.util.function.Function<*, *>) (inst as java.util.function.Function<Map<String, String>, Any?>).apply(options) else inst
        }
        if (made !is StoreAdapter) {
            throw IllegalArgumentException("$spec: does not name a store adapter (a StoreAdapter with a name and an open() method, or a factory returning one)")
        }
        return made
    }
}
