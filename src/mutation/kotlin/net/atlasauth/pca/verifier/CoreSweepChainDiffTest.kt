package net.atlasauth.pca.verifier

import org.junit.Test

/** Replays the reference over chain compaction: the hop leaf, the hops root, the compact form, its shape check and the verifier memo. */
@Suppress("UNCHECKED_CAST")
class CoreSweepChainDiffTest {
    private val mod = "ref-core-sweep-java"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun chain(o: Any?): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("not an array")

    private fun num(o: Any?): Double = IntentJs.num(o) ?: throw IllegalArgumentException("not a number")

    @Test fun hopsRootAndCompactChain() {
        OracleCases.each(mod, "hopsRoot") { a -> ChainCompact.hopsRoot(chain(a[0])) }
        OracleCases.each(mod, "compactChain") { a -> ChainCompact.compactChain(chain(a[0])) }
        OracleCases.each(mod, "hopLeaf") { a -> ChainCompact.hopLeaf(map(a[0])) }
        OracleCases.each(mod, "compactChainShapeError") { a -> ChainCompact.compactChainShapeError(a[0]) }
    }

    @Test fun chainMemo() = OracleCases.each(mod, "chainMemo") { a ->
        var memo: ChainCompact.Memo? = null
        val out = ArrayList<Any?>()
        for (oo in a[0] as List<*>) {
            val op = oo as List<*>
            try {
                var v: Any? = null
                when (op[0] as String) {
                    "new" -> {
                        val c = if (op[1] == null) LinkedHashMap<String, Any?>() else map(op[1])
                        memo = ChainCompact.Memo(if (c.containsKey("maxEntries")) num(c["maxEntries"]).toInt() else null, if (c.containsKey("ttlMs")) IntentJs.num(c["ttlMs"]) else null)
                    }
                    "remember" -> v = memo!!.rememberVerified(chain(op[1]), op[2] as String, num(op[3]))
                    "resolve" -> {
                        val r = memo!!.resolve(op[1], IntentJs.num(op[2]) ?: Double.NaN)
                        val res = linkedMapOf<String, Any?>("ok" to r.ok)
                        if (r.ok) {
                            val view = r.view!!
                            val hashes = ArrayList<Any?>()
                            val counts = ArrayList<Any?>()
                            for (i in 0 until view.n()) { hashes.add(view.hash(i)); counts.add(view.count(i)) }
                            res["view"] = linkedMapOf<String, Any?>("n" to view.n(), "hashes" to hashes, "counts" to counts, "leaf" to view.leaf())
                        } else {
                            res["reason"] = r.reason
                        }
                        v = res
                    }
                    "prune" -> memo!!.prune(num(op[1]))
                    "forget" -> v = memo!!.forget(op[1] as String)
                    "size" -> v = memo!!.size()
                    else -> throw IllegalStateException("op")
                }
                out.add(v)
            } catch (t: Throwable) {
                out.add(linkedMapOf<String, Any?>("\$err" to "Error"))
            }
        }
        out
    }
}
