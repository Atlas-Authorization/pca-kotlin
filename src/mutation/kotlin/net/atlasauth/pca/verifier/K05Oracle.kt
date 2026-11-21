package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream

/**
 * Streams a k05 oracle (test-data/k05-*.json.gz: one case per line) and parses only the cases of one fn. Parsing a whole oracle
 * (the action registry one is 170 MB of JSON) ran the 2 GB surefire fork and the 1.5 GB PIT minions out of heap.
 */
object K05Oracle {
    private val FN = Regex("^\\{\"fn\":\"((?:[^\"\\\\]|\\\\.)*)\"")

    private fun lines(file: String, each: (String) -> Unit) =
        GZIPInputStream(Files.newInputStream(Path.of("test-data/$file")), 1 shl 16).bufferedReader(Charsets.UTF_8).use { r -> r.lineSequence().forEach(each) }

    /** Every fn the oracle holds. */
    fun fns(file: String): Set<String> {
        val s = LinkedHashSet<String>()
        lines(file) { l -> FN.find(l)?.let { s.add(it.groupValues[1]) } }
        return s
    }

    /** The cases of [fn], parsed leniently ([normalize]: numbers spelled as JavaScript prints them). */
    @Suppress("UNCHECKED_CAST")
    fun cases(file: String, fn: String, normalize: Boolean = true): List<Map<String, Any?>> {
        val pre = "{\"fn\":" + Json.canonicalize(fn) + ","
        val out = ArrayList<Map<String, Any?>>()
        lines(file) { l ->
            if (l.startsWith(pre)) {
                val v = Json.parseLenient(l.removeSuffix(","))
                out.add((if (normalize) IntentJs.normalize(v) else v) as Map<String, Any?>)
            }
        }
        return out
    }
}
