package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.util.zip.GZIPInputStream

/**
 * The `blobs` table of a corpus (header line: long strings the cases reference as `{"$blob": id}`) and the hydration of a tree: every `{"$blob": id}` object
 * is replaced by the string stored under that id, in arguments and in expected results alike.
 */
object OracleBlobs {
    @Suppress("UNCHECKED_CAST")
    fun load(file: String): Map<String, Any?> {
        GZIPInputStream(Files.newInputStream(BaseOracle.corpusPath(file)), 1 shl 16).bufferedReader(Charsets.UTF_8).use { r ->
            val head = r.readLine()
            val doc = Json.parseLenient(head.removeSuffix("\"cases\":[") + "\"cases\":[]}") as Map<String, Any?>
            return doc["blobs"] as Map<String, Any?>
        }
    }

    fun hydrate(v: Any?, blobs: Map<String, Any?>): Any? = when (v) {
        is List<*> -> v.map { hydrate(it, blobs) }
        is Map<*, *> -> {
            val id = if (v.size == 1) v["\$blob"] as? String else null
            if (id != null) blobs[id] ?: throw IllegalStateException("unknown blob $id")
            else LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = hydrate(x, blobs) }
        }
        else -> v
    }
}
