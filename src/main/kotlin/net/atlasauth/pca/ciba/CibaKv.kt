package net.atlasauth.pca.ciba

import java.io.File
import net.atlasauth.pca.ciba.CibaApproval.ApprovalStore
import net.atlasauth.pca.ciba.CibaApproval.Versioned
import net.atlasauth.pca.durable.OwnerOnly
import net.atlasauth.pca.gnap.GnapJs as Js
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json

/**
 * Shared-store reference for the durable broker: a versioned [ApprovalStore] built on a tiny durable key-value interface that needs ONE
 * primitive, a compare-and-swap on a string (Redis, DynamoDB conditional put, SQL `UPDATE ... WHERE value = ?`, etcd).
 */
object CibaKv {
    /**
     * A durable string key-value store with compare-and-swap. `putIfEquals(key, expected, next)` writes `next` only if the stored value is
     * exactly `expected` (null means "the key must be absent") and reports whether it wrote. It MUST be atomic across every process sharing
     * the store, and a write MUST be durable before it returns. Any failure must throw.
     */
    interface DurableKv {
        /** The stored string, or null when absent. */
        fun get(key: String): String?
        fun putIfEquals(key: String, expected: String?, next: String): Boolean
    }

    /** Thrown by the KV reference implementations; the broker treats any throw from the store as "no approval". `code`: corrupt_record, lock_timeout or bad_key. */
    class ApprovalStoreError(val code: String, message: String) : RuntimeException(message)

    private fun decode(raw: String): Versioned {
        val parsed = try {
            Json.parseLenient(raw)
        } catch (e: RuntimeException) {
            throw ApprovalStoreError("corrupt_record", "ciba: stored approval record is not valid JSON")
        } catch (e: StackOverflowError) {
            throw ApprovalStoreError("corrupt_record", "ciba: stored approval record is not valid JSON")
        }
        val v = Js.num(Js.member(parsed, "version"))
        if (parsed !is Map<*, *> || v == null || v != Math.rint(v) || v.isInfinite() || v < 1 || !parsed.containsKey("value"))
            throw ApprovalStoreError("corrupt_record", "ciba: stored approval record has no valid version")
        return Versioned(v.toLong(), parsed["value"])
    }

    /**
     * An [ApprovalStore] over a [DurableKv]. Each key holds `{version, value}` as JSON; `cas` re-reads the raw string, checks the version,
     * and swaps only if the raw string is still the one it read, so two processes racing on the same expected version cannot both win. A
     * stored value that is not a valid versioned record throws (`corrupt_record`).
     */
    fun createKvApprovalStore(kv: DurableKv?): ApprovalStore {
        if (kv == null) throw IllegalArgumentException("createKvApprovalStore: `kv` with get and putIfEquals is required")
        return object : ApprovalStore {
            override fun get(key: String): Versioned? = kv.get(key)?.let { decode(it) }

            override fun cas(key: String, expectedVersion: Long, value: Any?): Boolean {
                val raw = kv.get(key)
                val current = if (raw == null) 0L else decode(raw).version
                if (current != expectedVersion) return false
                return kv.putIfEquals(key, raw, Js.stringify(Issue.obj("version" to expectedVersion + 1, "value" to value)))
            }
        }
    }

    /** Single-process [DurableKv] for tests of code that takes a KV. Not durable. */
    fun createMemoryKv(): DurableKv = object : DurableKv {
        private val m = HashMap<String, String>()

        @Synchronized override fun get(key: String): String? = m[key]

        @Synchronized override fun putIfEquals(key: String, expected: String?, next: String): Boolean {
            if (m[key] != expected) return false
            m[key] = next
            return true
        }
    }

    /**
     * A [DurableKv] on a directory, safe for several processes on ONE host (and one filesystem with atomic exclusive-create and rename).
     * One file per key; each swap takes a per-key lock file (exclusive create), compares, writes a temp file and renames it over the key. A
     * process that dies while holding the lock leaves it behind: every later swap on that key then throws `lock_timeout` (fail closed)
     * until an operator removes the `.lock` file.
     */
    @JvmOverloads
    fun createDirectoryKv(dir: File, lockTimeoutMs: Long = 5000): DurableKv {
        if (lockTimeoutMs <= 0) throw IllegalArgumentException("createDirectoryKv: lockTimeoutMs must be a positive number")
        // created owner-only (POSIX mode or Windows ACL at creation); a directory the caller handed in is restricted in place
        try {
            if (dir.isDirectory) OwnerOnly.restrictExisting(dir.toPath()) else OwnerOnly.createDirectories(dir.toPath())
        } catch (e: java.io.IOException) {
            throw IllegalStateException("createDirectoryKv: cannot create or restrict $dir", e)
        }
        return object : DurableKv {
            // The key is hashed into the file name, so no key can escape the directory.
            private fun fileOf(key: String): File {
                if (key.isEmpty()) throw ApprovalStoreError("bad_key", "ciba: store key must be a non-empty string")
                val h = Js.sha256(Json.utf8(key))
                return File(dir, h.joinToString("") { String.format("%02x", it.toInt() and 0xff) })
            }

            override fun get(key: String): String? {
                val f = fileOf(key)
                return if (f.exists()) String(f.readBytes(), Charsets.UTF_8) else null
            }

            private fun tryLock(lock: File): Boolean =
                try {
                    OwnerOnly.createFile(lock.toPath())
                    true
                } catch (e: java.nio.file.FileAlreadyExistsException) {
                    false
                }

            override fun putIfEquals(key: String, expected: String?, next: String): Boolean {
                val f = fileOf(key)
                val lock = File(f.path + ".lock")
                val deadline = System.currentTimeMillis() + lockTimeoutMs
                while (!tryLock(lock)) { // atomic exclusive create, owner-only at creation
                    if (System.currentTimeMillis() >= deadline) throw ApprovalStoreError("lock_timeout", "ciba: could not take the store lock in time")
                    try {
                        Thread.sleep(2)
                    } catch (ie: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw IllegalStateException(ie)
                    }
                }
                try {
                    val current = if (f.exists()) String(f.readBytes(), Charsets.UTF_8) else null
                    if (current != expected) return false
                    CibaApproval.atomicWrite(f, Json.utf8(next))
                    return true
                } finally {
                    lock.delete() // a lock that stays makes later swaps fail closed with lock_timeout
                }
            }
        }
    }
}
