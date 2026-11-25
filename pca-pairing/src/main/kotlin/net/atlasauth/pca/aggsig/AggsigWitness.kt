package net.atlasauth.pca.aggsig

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * BLS aggregation of transparency-ledger witness cosignatures: a quorum cosigns the same tree-head statement
 * {size, root, prev_root, guardian_epoch}; the quorum collapses into one 96-byte aggregate verified by one FastAggregateVerify.
 */
@Suppress("UNCHECKED_CAST")
object AggsigWitness {
    private const val STH_WITNESS_BLS_DOMAIN = "atlas-pca/sth-witness-bls/v1\u0000"

    private fun witnessMessage(h: Map<String, Any?>): ByteArray {
        val b = LinkedHashMap<String, Any?>()
        b["size"] = h["size"]
        b["root"] = h["root"]
        b["prev_root"] = h["prev_root"]
        b["guardian_epoch"] = h["guardian_epoch"] ?: Json.Num("0")
        val body = Json.canonicalizeStrict(b).toByteArray(Charsets.UTF_8)
        val p = AggsigCore.utf8(STH_WITNESS_BLS_DOMAIN)
        val m = ByteArray(p.size + body.size)
        System.arraycopy(p, 0, m, 0, p.size)
        System.arraycopy(body, 0, m, p.size, body.size)
        return m
    }

    /** A trusted witness cosigns the tree-head statement with its BLS secret key: {key, sig, suite}. */
    fun cosignTreeHead(statement: Map<String, Any?>, witnessSecret: ByteArray): Map<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        c["key"] = Keys.b64u(AggsigCore.publicKeyOf(witnessSecret))
        c["sig"] = Keys.b64u(AggsigCore.sign(witnessSecret, witnessMessage(statement)))
        c["suite"] = AggsigChain.BLS_SUITE
        return c
    }

    /** Verify ONE cosignature against the exact statement. Never throws. */
    fun verifyWitnessCosignature(statement: Map<String, Any?>, cosig: Map<String, Any?>?): Boolean {
        try {
            if (cosig == null || AggsigChain.BLS_SUITE != cosig["suite"]) return false
            return AggsigCore.verify(Keys.unb64u(cosig["key"] as String), witnessMessage(statement), Keys.unb64u(cosig["sig"] as String))
        } catch (e: RuntimeException) {
            return false
        }
    }

    /** Collapse a quorum of cosignatures into one aggregate. Throws on an empty set or a sig that is not valid b64u. */
    fun aggregateWitnessCosignatures(cosigs: List<Map<String, Any?>>?): ByteArray {
        if (cosigs == null || cosigs.isEmpty()) throw IllegalArgumentException("aggregateWitnessCosignatures: empty set")
        val sigs = ArrayList<ByteArray>()
        for (c in cosigs) sigs.add(Keys.unb64u(c["sig"] as String))
        return Aggsig.aggregate(sigs)
    }

    /** One FastAggregateVerify over the statement for exactly the registered witness keys supplied; a repeated witness is refused. Never throws. */
    fun verifyAggregatedWitnessCosignatures(statement: Map<String, Any?>, witnessKeys: List<RegisteredKey?>?, aggSig: ByteArray?): Boolean {
        try {
            if (witnessKeys == null || witnessKeys.isEmpty()) return false
            val seen = HashSet<String>()
            for (k in witnessKeys) if (!seen.add(Aggsig.hex(k!!.bytes()))) return false
            return Aggsig.fastAggregateVerify(witnessKeys, witnessMessage(statement), aggSig)
        } catch (e: RuntimeException) {
            return false
        }
    }
}
