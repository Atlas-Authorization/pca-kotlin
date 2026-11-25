package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** The immune system's adaptation, signed tightening proposals and durable store against the reference. */
@Suppress("UNCHECKED_CAST")
class ImmuneDiffTest {
    private val module = "ref-immune-java"

    private fun m(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun sd(label: Any?): ByteArray = OracleCases.seed("immune/$label")

    /** The pinned guardian "@g" is the public key of the seed labelled g. */
    private fun pin(opts: Any?): Map<String, Any?>? {
        val o = m(opts) ?: return null
        if (o["guardian"] != "@g") return o
        val c = LinkedHashMap(o)
        c["guardian"] = Keys.edFromSeed(sd("g")).id()
        return c
    }

    @Test fun adapt() = OracleCases.each(module, "adapt") { a -> Immune.adapt(a[0], m(a[1])!!) }

    @Test fun noWiden() = OracleCases.each(module, "noWidenViolation") { a -> Immune.noWidenViolation(m(a[0])!!, m(a[1])!!) }

    @Test fun digests() {
        OracleCases.each(module, "policyDigest") { a -> Immune.policyDigest(m(a[0])!!) }
        OracleCases.each(module, "immuneStateDigest") { a -> Immune.immuneStateDigest(m(a[0])!!) }
    }

    @Test fun issue() = OracleCases.each(module, "issueTighteningProposal") { a ->
        Immune.issueTighteningProposal(m(a[0])!!, a[1], a[2], a[3], sd(a[4]))
    }

    @Test fun apply() = OracleCases.each(module, "applyTightening") { a -> Immune.applyTightening(m(a[0]), m(a[1]), pin(a[2])!!) }

    @Test fun store() = OracleCases.each(module, "store") { a ->
        val kv = MemoryAtomicKv()
        val subject = a[0] as String
        val st = Immune.createImmuneStore(kv, subject)
        val out = ArrayList<Any?>()
        for (o in a[1] as List<Any?>) {
            val op = o as List<Any?>
            try {
                when (op[0] as String) {
                    "seed" -> { kv.set("immune/state/$subject", op[1] ?: AtomicKv.JSON_NULL); out.add(null) }
                    "get" -> out.add(st.get())
                    "observe" -> out.add(st.observe(m(op[1])!!))
                    "lastEpoch" -> out.add(st.lastEpoch())
                    "apply" -> out.add(st.apply(m(op[1])!!, m(op[2]), pin(op[3])!!))
                    else -> throw IllegalStateException("op ${op[0]}")
                }
            } catch (e: RuntimeException) {
                out.add(linkedMapOf("\$err" to "Error"))
            }
        }
        out
    }
}
