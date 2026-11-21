package net.atlasauth.pca.aggsig

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * A BLS-suite attenuable capability chain: the same structure as the core chain (hash-linked, holder-to-issuer continuity,
 * append-only caveats) but each hop is signed with the BLS12-381 PoP scheme, so an M-hop chain's signatures collapse into one
 * 96-byte aggregate checked with one pairing-product AggregateVerify. Capabilities are JSON maps (issuer, holder, caveats,
 * parent?, id, body_digest, sig, suite).
 */
@Suppress("UNCHECKED_CAST")
object AggsigChain {
    private const val CAP_BLS_DOMAIN = "atlas-pca/cap-bls/v1\u0000"
    const val BLS_SUITE = "bls12-381-pop"
    const val MAX_CHAIN_DEPTH = 16

    private fun bodyOf(c: Map<String, Any?>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["issuer"] = c["issuer"]
        b["holder"] = c["holder"]
        b["caveats"] = c["caveats"]
        b["parent"] = c["parent"]
        return b
    }

    private fun sigMessage(bodyDigest: String): ByteArray {
        val d = Keys.unb64u(bodyDigest)
        val p = AggsigCore.utf8(CAP_BLS_DOMAIN)
        val m = ByteArray(p.size + d.size)
        System.arraycopy(p, 0, m, 0, p.size)
        System.arraycopy(d, 0, m, p.size, d.size)
        return m
    }

    /** Identity of a capability: the hash of everything EXCEPT sig, so a free sig string cannot mint distinct identities for one hop. */
    fun capHash(c: Map<String, Any?>): String {
        val rest = LinkedHashMap(c)
        rest.remove("sig")
        return Pca.hashCanonical(rest)
    }

    private fun cloneCaveats(cs: List<*>): List<Any?> = Json.parse(Json.canonicalizeStrict(cs)) as List<Any?>

    private fun seal(issuer: String?, holder: String?, caveats: List<Any?>, parent: String?, signerSecret: ByteArray): Map<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        body["issuer"] = issuer
        body["holder"] = holder
        body["caveats"] = caveats
        body["parent"] = parent
        val digest = Pca.hashCanonical(body)
        val sig = Keys.b64u(AggsigCore.sign(signerSecret, sigMessage(digest)))
        val cap = LinkedHashMap<String, Any?>()
        cap["id"] = digest
        cap["issuer"] = issuer
        cap["holder"] = holder
        cap["caveats"] = caveats
        cap["body_digest"] = digest
        cap["sig"] = sig
        cap["suite"] = BLS_SUITE
        if (parent != null) cap["parent"] = parent
        return cap
    }

    /** b64u BLS G1 public key for a secret scalar: the identity a chain is rooted at / delegated to. */
    fun blsPublicKey(secretKey: ByteArray): String = Keys.b64u(AggsigCore.publicKeyOf(secretKey))

    /** Mint a root capability, signed by the principal. */
    fun mintBlsRoot(principalSecret: ByteArray, principalPublic: String?, holder: String?, caveats: List<*>): Map<String, Any?> =
        seal(principalPublic, holder, cloneCaveats(caveats), null, principalSecret)

    /** Child with the SAME holder; caveats = parent caveats then added. Signed by the parent's holder. */
    fun blsAttenuate(parent: Map<String, Any?>, added: List<*>, signerSecret: ByteArray): Map<String, Any?> =
        blsDelegate(parent, parent["holder"] as String?, added, signerSecret)

    /** Like blsAttenuate, but rebinds the holder to a new sub-agent key. */
    fun blsDelegate(parent: Map<String, Any?>, toHolder: String?, added: List<*>, signerSecret: ByteArray): Map<String, Any?> {
        val cav = ArrayList(cloneCaveats(parent["caveats"] as List<*>))
        cav.addAll(cloneCaveats(added))
        return seal(parent["holder"] as String?, toHolder, cav, capHash(parent), signerSecret)
    }

    private fun wellTyped(o: Any?): Boolean {
        if (o !is Map<*, *>) return false
        if (!(o["id"] is String && o["issuer"] is String && o["holder"] is String &&
                o["body_digest"] is String && o["sig"] is String && BLS_SUITE == o["suite"])) return false
        if (o.containsKey("parent") && o["parent"] !is String) return false
        val cavs = o["caveats"] as? List<*> ?: return false
        for (cv in cavs) {
            if (cv !is Map<*, *> || cv["type"] !is String) return false
        }
        return true
    }

    /** Collapse every per-hop signature into one 96-byte aggregate. Throws on an empty chain or a sig that is not valid b64u. */
    fun aggregateChainSignatures(chain: List<Any?>?): ByteArray {
        if (chain == null || chain.isEmpty()) throw IllegalArgumentException("aggregateChainSignatures: empty chain")
        val sigs = ArrayList<ByteArray>()
        for (c in chain) sigs.add(Keys.unb64u((c as Map<String, Any?>)["sig"] as String))
        return Aggsig.aggregate(sigs)
    }

    private fun ok(): Map<String, Any?> = linkedMapOf("ok" to true)

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /**
     * Verify an entire BLS capability chain against one aggregate signature: depth bound, well-typedness, root has no parent,
     * optional expected root principal, parent hash-links, holder-to-issuer continuity, append-only caveat prefixes, then one
     * distinct-message AggregateVerify. Every hop issuer must be in the registry. Never throws.
     */
    fun verifyAggregatedChain(chain: List<Any?>?, aggSig: ByteArray?, registry: KeyRegistry?, expectedRootPrincipal: String?): Map<String, Any?> {
        if (registry == null) return fail("a KeyRegistry of proof-of-possession-verified keys is required")
        if (chain == null || chain.isEmpty()) return fail("empty chain")
        if (chain.size > MAX_CHAIN_DEPTH) return fail("chain too long (max $MAX_CHAIN_DEPTH hops)")
        for (i in chain.indices) if (!wellTyped(chain[i])) return fail("hop $i: malformed capability")

        val pks = ArrayList<RegisteredKey?>()
        val msgs = ArrayList<ByteArray>()
        val root = chain[0] as Map<String, Any?>
        if (root.containsKey("parent")) return fail("hop 0: root must not have a parent")
        if (expectedRootPrincipal != null && expectedRootPrincipal != root["issuer"]) return fail("hop 0: root issuer is not the expected principal")

        for (i in chain.indices) {
            val c = chain[i] as Map<String, Any?>
            val digest = try {
                Pca.hashCanonical(bodyOf(c))
            } catch (e: RuntimeException) {
                return fail("hop $i: malformed body")
            }
            if (digest != c["body_digest"] || c["id"] != c["body_digest"]) return fail("hop $i: body digest mismatch")

            val pk = try {
                registry.get(Keys.unb64u(c["issuer"] as String))
            } catch (e: RuntimeException) {
                return fail("hop $i: malformed issuer key")
            }
            if (pk == null) return fail("hop $i: issuer key has no verified proof of possession (not in the registry)")

            if (i > 0) {
                val parent = chain[i - 1] as Map<String, Any?>
                if (capHash(parent) != c["parent"]) return fail("hop $i: broken parent link")
                if (c["issuer"] != parent["holder"]) return fail("hop $i: issuer is not the parent's bound holder")
                val cc = c["caveats"] as List<Any?>
                val pc = parent["caveats"] as List<Any?>
                if (cc.size < pc.size) return fail("hop $i: drops parent caveat(s)")
                for (j in pc.indices) {
                    if (Pca.hashCanonical(cc[j]) != Pca.hashCanonical(pc[j])) return fail("hop $i: caveat $j altered or reordered")
                }
            }
            pks.add(pk)
            msgs.add(sigMessage(c["body_digest"] as String))
        }

        try {
            val raws = ArrayList<ByteArray>()
            for (i in chain.indices) {
                val s = (chain[i] as Map<String, Any?>)["sig"] as String
                val raw = Keys.unb64u(s)
                if (Keys.b64u(raw) != s) return fail("hop $i: non-canonical sig encoding")
                raws.add(raw)
            }
            if (aggSig == null || !Aggsig.aggregate(raws).contentEquals(aggSig)) return fail("hop sig fields do not sum to the aggregate signature")
        } catch (e: RuntimeException) {
            return fail("malformed hop sig")
        }

        if (!Aggsig.aggregateVerify(pks, msgs, aggSig)) return fail("aggregate signature does not verify over all hops")
        return ok()
    }
}
