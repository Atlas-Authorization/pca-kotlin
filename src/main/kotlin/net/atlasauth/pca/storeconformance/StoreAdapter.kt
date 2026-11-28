package net.atlasauth.pca.storeconformance

/**
 * The adapter a store author implements to run the conformance kit against THEIR store: [open] returns one client per simulated
 * verifier instance, all on the same shared backend.
 */
interface StoreAdapter {
    /** Shown in reports. */
    fun name(): String

    /** What the adapter declares; a null member is detected from the first client (or, for `durable`, assumed true). */
    fun capabilities(): Capabilities? = null

    /** Open one client against the shared backend. Called once per simulated verifier instance. */
    fun open(): StoreClient

    /** Optional: whether [restart] is implemented. */
    fun hasRestart(): Boolean = false

    /** Restart the BACKEND after every client was closed. Without it the durability test only closes and re-opens clients. */
    fun restart() {}

    /** Optional: whether [crash] is implemented. */
    fun hasCrash(): Boolean = false

    /** Crash the backend abruptly (kill -9 equivalent). Followed by [restart]. Used by the crash test. */
    fun crash() {}

    /** Release everything the adapter holds (pools, temp dirs). Never drop shared data here. */
    fun teardown() {}

    class Capabilities {
        var consumeOnce: Boolean? = null
        var advance: Boolean? = null

        /**
         * The store claims durability: consumed keys and counters survive closing every client and `restart()`. Declare false ONLY
         * for a single-process in-memory store whose lifetime covers the action lifetime; the durability test is then skipped.
         */
        var durable: Boolean? = null

        fun withDurable(d: Boolean): Capabilities { durable = d; return this }
        fun withConsumeOnce(d: Boolean): Capabilities { consumeOnce = d; return this }
        fun withAdvance(d: Boolean): Capabilities { advance = d; return this }
    }
}

/**
 * One connection / verifier instance talking to the shared backend. Implement whichever of the two operations you ship (and
 * override the matching `has...` method). Both are atomic across every client of the same backend, durable, and FAIL CLOSED
 * (throw when they cannot decide).
 */
interface StoreClient {
    fun hasConsumeOnce(): Boolean = false
    fun hasAdvance(): Boolean = false

    /** True iff there is no live record for [key] (live = its stored horizon is >= [nowMs]); then records [retainUntilMs]. */
    fun consumeOnce(key: String, retainUntilMs: Double, nowMs: Double): Boolean = throw UnsupportedOperationException("consumeOnce")

    /** True iff [counter] is strictly greater than the stored value; then stores it. */
    fun advance(streamKey: String, counter: Double): Boolean = throw UnsupportedOperationException("advance")

    /** Release the connection. The backend's state must survive it. */
    fun close() {}
}
