package net.atlasauth.pca.verifier

import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Where a mesh log witness keeps what it has cosigned. `save` MUST be durable and atomic: when it returns, a restarted witness loads
 * exactly this state. A witness that forgets across a restart can be walked back to cosign a fork. Synchronous on purpose: `cosign`
 * must not return a signature before the state behind it is on disk.
 *
 * The state is the JSON object `{seen: [{head, rev_ids}]}`.
 */
interface MeshWitnessStore {
    /** The last saved state (a copy), or null for a store that has never been written. Throws on corrupt data (never returns a partial state). */
    fun load(): Map<String, Any?>?

    fun save(state: Map<String, Any?>)
}

/** The stored form shared by the durable witness stores: `{v:1, state, digest}` with the digest of the state. */
internal object MeshWitnessDoc {
    fun wrap(state: Map<String, Any?>): Map<String, Any?> =
        linkedMapOf("v" to StoreJs.num(1L), "state" to StoreJs.deepCopy(state), "digest" to Pca.hashCanonical(state))

    /** The state of a stored document; throws (never an empty state) on a wrong shape or a failed digest. */
    fun state(doc: Any?, who: String): Map<String, Any?> {
        val d = StoreJs.map(doc)
        if (d == null || !IntentJs.isInt(d["v"]) || IntentJs.lng(d["v"]) != 1L || d["digest"] !is String || StoreJs.map(d["state"]) == null) {
            throw IllegalStateException("$who has an unexpected shape; refusing to start empty")
        }
        val st = StoreJs.map(StoreJs.deepCopy(d["state"]))!!
        val digest = try {
            Pca.hashCanonical(st)
        } catch (e: RuntimeException) {
            throw IllegalStateException("$who fails its digest; refusing to start empty")
        }
        if (digest != d["digest"]) throw IllegalStateException("$who fails its digest; refusing to start empty")
        return st
    }
}

/**
 * A durable [MeshWitnessStore] over an [AtomicKv] (for example [JdbcAtomicKv]): the state is one document with a digest. `save`
 * returns only after the kv acknowledged the write; `load` refuses damaged or edited content (it throws, so a witness never starts
 * empty over it).
 */
class KvMeshWitnessStore @JvmOverloads constructor(private val kv: AtomicKv, private val key: String = DOC_KEY) : MeshWitnessStore {
    override fun load(): Map<String, Any?>? {
        val doc = kv.get(key) ?: return null
        return MeshWitnessDoc.state(doc, "KvMeshWitnessStore: the stored state")
    }

    override fun save(state: Map<String, Any?>) = kv.set(key, MeshWitnessDoc.wrap(state))

    companion object {
        const val DOC_KEY = "pca-mesh-witness/v1"
    }
}

/**
 * A [MeshWitnessStore] on one file. `save` writes a temp file, fsyncs it, renames it over the state file (atomic on one filesystem)
 * and, where the platform allows, fsyncs the directory, so after it returns a restarted witness loads exactly this state and a crash
 * mid-write leaves the old or the new file, never a mix. The file carries a digest of its state: `load` refuses damaged, edited or
 * foreign content (it throws; a witness never starts empty over it).
 */
class FileMeshWitnessStore(private val path: File) : MeshWitnessStore {
    @Synchronized
    override fun load(): Map<String, Any?>? {
        if (!path.exists()) return null
        val doc = try {
            Json.parseLenient(path.readText(Charsets.UTF_8))
        } catch (e: java.io.IOException) {
            throw IllegalStateException("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty")
        } catch (e: RuntimeException) {
            throw IllegalStateException("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty")
        }
        return MeshWitnessDoc.state(doc, "FileMeshWitnessStore: the state file")
    }

    @Synchronized
    override fun save(state: Map<String, Any?>) {
        val body = Json.canonicalize(MeshWitnessDoc.wrap(state)).toByteArray(Charsets.UTF_8)
        val tmp = File(path.absoluteFile.parentFile, path.name + ".tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(body)
                out.fd.sync()
            }
            try {
                Files.move(tmp.toPath(), path.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                throw java.io.IOException("the filesystem cannot rename atomically", e) // fail closed: never a non-atomic replace
            }
            try {
                java.nio.channels.FileChannel.open(path.absoluteFile.parentFile.toPath(), StandardOpenOption.READ).use { it.force(true) }
            } catch (e: java.io.IOException) {
                // some platforms cannot fsync a directory; the rename above is already atomic
            } catch (e: UnsupportedOperationException) {
            }
        } catch (e: java.io.IOException) {
            throw IllegalStateException("FileMeshWitnessStore: could not write the state file: ${e.message}", e)
        }
    }
}
