package net.atlasauth.pca.revoke

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json

/**
 * A durable [RevocationStore] backed by one JSON file. Every change is written to a temporary file, synced to disk, then renamed over
 * the real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two processes must not
 * share one file.
 *
 * Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes the constructor throw
 * [IllegalStateException]. Silently starting empty would un-revoke everything.
 */
class FileRevocationStore(private val file: File) : RevocationStore {
    private val mem = LinkedHashMap<String, RevocationEntry>()

    init {
        if (file.exists()) {
            val parsed = try {
                Json.parseLenient(String(file.readBytes(), Charsets.UTF_8))
            } catch (e: Exception) {
                throw IllegalStateException("FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty")
            }
            val list = (parsed as? Map<*, *>)?.get("entries") as? List<*> ?: throw invalid()
            val out = list.map { valid(it) ?: throw invalid() }
            for (e in out) mem[InMemoryRevocationStore.key(e.kind, e.value)] = e
        }
    }

    private fun invalid() = IllegalStateException("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty")

    private fun valid(e: Any?): RevocationEntry? {
        val o = e as? Map<*, *> ?: return null
        val kind = o["kind"] as? String ?: return null
        val value = o["value"]
        val reason = o["reason"] as? String ?: return null
        if (kind !in KINDS || !Js.nonEmptyString(value) || !Js.isFinite(o["revokedAt"])) return null
        var nb: Double? = null
        if (o.containsKey("notBefore")) {
            if (!Js.isFinite(o["notBefore"])) return null
            nb = Js.num(o["notBefore"])
        }
        var prefix: List<String>? = null
        if (kind == "prefix") {
            val p = o["prefix"] as? List<*> ?: return null
            if (p.isEmpty() || !p.all { Js.nonEmptyString(it) }) return null
            prefix = p.map { it as String }
            if (prefix.joinToString(",") != value) return null
        }
        return RevocationEntry(kind, value as String, prefix, reason, Js.num(o["revokedAt"])!!, nb)
    }

    private fun flush() {
        val tmp = File(file.path + ".tmp")
        val doc = linkedMapOf<String, Any?>("v" to Json.Num("1"), "entries" to mem.values.map { it.toMap() })
        val bytes = Json.canonicalize(doc).toByteArray(Charsets.UTF_8)
        FileOutputStream(tmp).use { out ->
            // Owner-only, best effort off POSIX.
            tmp.setReadable(false, false); tmp.setReadable(true, true)
            tmp.setWritable(false, false); tmp.setWritable(true, true)
            out.write(bytes)
            out.fd.sync()
        }
        // renameTo replaces atomically on POSIX; Windows refuses an existing target, so fall back to the atomic move that replaces (never a non-atomic replace)
        if (!tmp.renameTo(file)) {
            try {
                java.nio.file.Files.move(tmp.toPath(), file.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            } catch (e: Exception) {
                throw IOException("FileRevocationStore: could not replace the revocation file", e)
            }
        }
    }

    /** Apply the change to memory and flush; on a failed flush put memory back, so memory never claims more than disk. */
    @Synchronized
    private fun <T> write(change: () -> T): T {
        val before = LinkedHashMap(mem)
        val out = change()
        try {
            flush()
        } catch (e: Exception) {
            mem.clear()
            mem.putAll(before)
            throw e as? RuntimeException ?: IllegalStateException(e)
        }
        return out
    }

    override fun add(entry: RevocationEntry) { write { mem.put(InMemoryRevocationStore.key(entry.kind, entry.value), entry) } }
    override fun remove(kind: String, value: String): Boolean = write { mem.remove(InMemoryRevocationStore.key(kind, value)) != null }
    @Synchronized override fun get(kind: String, value: String): RevocationEntry? = mem[InMemoryRevocationStore.key(kind, value)]
    @Synchronized override fun all(): List<RevocationEntry> = ArrayList(mem.values)
    override fun clear() { write { mem.clear() } }

    private companion object {
        val KINDS = setOf("cap", "holder", "issuer", "prefix")
    }
}
