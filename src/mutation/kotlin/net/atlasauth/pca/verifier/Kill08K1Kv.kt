package net.atlasauth.pca.verifier

/** AtomicKv doubles for the Kill08K1 tests: a store that always throws, one whose update never runs the function, one that counts calls. */
internal class Kill08K1ThrowingKv(private val t: () -> Throwable) : AtomicKv {
    override fun get(key: String): Any? { throw t() }
    override fun set(key: String, value: Any?) { throw t() }
    override fun update(key: String, fn: (Any?) -> Any?): Any? { throw t() }
}

internal object Kill08K1NoopKv : AtomicKv {
    override fun get(key: String): Any? = null
    override fun set(key: String, value: Any?) {}
    override fun update(key: String, fn: (Any?) -> Any?): Any? = null
}

internal class Kill08K1CountingKv(val inner: AtomicKv = MemoryAtomicKv()) : AtomicKv {
    val updates = ArrayList<String>()
    override fun get(key: String): Any? = inner.get(key)
    override fun set(key: String, value: Any?) = inner.set(key, value)
    override fun update(key: String, fn: (Any?) -> Any?): Any? {
        updates.add(key)
        return inner.update(key, fn)
    }
}
