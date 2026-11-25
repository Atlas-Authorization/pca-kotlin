package net.atlasauth.pca.aggsig

import net.atlasauth.pca.aggsig.Oracle.bytes
import net.atlasauth.pca.aggsig.Oracle.bytesList
import org.junit.Test

/** Replays the TypeScript-reference corpus (test-data/ref-aggsig.json.gz) through the native port. */
@Suppress("UNCHECKED_CAST")
class AggsigDiffTest {
    private val m = "ref-aggsig"

    private fun map(o: Any?) = o as Map<String, Any?>

    /** Register every {pk, pop}; null when any refuses (the reference reports {registerFailed: true}). */
    private fun reg(keys: Any?): List<RegisteredKey>? {
        val out = ArrayList<RegisteredKey>()
        for (k in keys as List<Any?>) {
            val r = Aggsig.registerKey(bytes(map(k)["pk"]), bytes(map(k)["pop"]))
            val key = r.key
            if (!r.ok || key == null) return null
            out.add(key)
        }
        return out
    }

    private fun registry(keys: Any?): KeyRegistry {
        val r = KeyRegistry()
        for (k in keys as List<Any?>) if (!r.register(bytes(map(k)["pk"]), bytes(map(k)["pop"])).ok) return r
        return r
    }

    private fun failed(): Any = linkedMapOf<String, Any?>("registerFailed" to true)

    @Test fun publicKeyOf() = Oracle.each(m, "publicKeyOf") { a -> Aggsig.publicKeyOf(bytes(a[0])) }
    @Test fun sign() = Oracle.each(m, "sign") { a -> Aggsig.sign(bytes(a[0]), bytes(a[1])) }
    @Test fun popProve() = Oracle.each(m, "popProve") { a -> Aggsig.popProve(bytes(a[0])) }
    @Test fun verify() = Oracle.each(m, "verify") { a -> Aggsig.verify(bytes(a[0]), bytes(a[1]), bytes(a[2])) }
    @Test fun keyValidate() = Oracle.each(m, "keyValidate") { a -> Aggsig.keyValidate(bytes(a[0])) }

    @Test fun registerKey() = Oracle.each(m, "registerKey") { a ->
        val r = Aggsig.registerKey(bytes(a[0]), bytes(a[1]))
        val o = LinkedHashMap<String, Any?>()
        o["ok"] = r.ok
        if (!r.ok) o["reason"] = r.reason
        o
    }

    @Test fun aggregate() = Oracle.each(m, "aggregate") { a -> Aggsig.aggregate(bytesList(a[0])) }

    @Test fun aggregateVerify() = Oracle.each(m, "aggregateVerify") { a ->
        val ks = reg(a[0])
        if (ks == null) failed() else Aggsig.aggregateVerify(ks, bytesList(a[1]), bytes(a[2]))
    }

    @Test fun fastAggregateVerify() = Oracle.each(m, "fastAggregateVerify") { a ->
        val ks = reg(a[0])
        if (ks == null) failed() else Aggsig.fastAggregateVerify(ks, bytes(a[1]), bytes(a[2]))
    }

    @Test fun mintBlsRoot() = Oracle.each(m, "mintBlsRoot") { a ->
        AggsigChain.mintBlsRoot(bytes(a[0]), a[1] as String?, a[2] as String?, a[3] as List<*>)
    }

    @Test fun chainDelegate() = Oracle.each(m, "chainDelegate") { a ->
        AggsigChain.blsDelegate(map(a[0]), a[1] as String?, a[2] as List<*>, bytes(a[3]))
    }

    @Test fun chainAttenuate() = Oracle.each(m, "chainAttenuate") { a ->
        AggsigChain.blsAttenuate(map(a[0]), a[1] as List<*>, bytes(a[2]))
    }

    @Test fun capHash() = Oracle.each(m, "capHash") { a -> AggsigChain.capHash(map(a[0])) }

    @Test fun aggregateChainSignatures() = Oracle.each(m, "aggregateChainSignatures") { a ->
        AggsigChain.aggregateChainSignatures(a[0] as List<Any?>)
    }

    @Test fun verifyAggregatedChain() = Oracle.each(m, "verifyAggregatedChain") { a ->
        AggsigChain.verifyAggregatedChain(a[0] as List<Any?>, bytes(a[1]), registry(a[2]), a[3] as String?)
    }

    @Test fun cosignTreeHead() = Oracle.each(m, "cosignTreeHead") { a -> AggsigWitness.cosignTreeHead(map(a[0]), bytes(a[1])) }

    @Test fun verifyWitnessCosignature() = Oracle.each(m, "verifyWitnessCosignature") { a ->
        AggsigWitness.verifyWitnessCosignature(map(a[0]), map(a[1]))
    }

    @Test fun aggregateWitnessCosignatures() = Oracle.each(m, "aggregateWitnessCosignatures") { a ->
        AggsigWitness.aggregateWitnessCosignatures((a[0] as List<Any?>).map { map(it) })
    }

    @Test fun verifyAggregatedWitnessCosignatures() = Oracle.each(m, "verifyAggregatedWitnessCosignatures") { a ->
        val ks = reg(a[1])
        if (ks == null) failed() else AggsigWitness.verifyAggregatedWitnessCosignatures(map(a[0]), ks, bytes(a[2]))
    }
}
