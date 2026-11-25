package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mesh.verifyMeshProof end to end over proofs minted here (Issue caps, Ed25519 domain / witness / holder keys, RFC 6962 logs):
 * every table bound, the PQ pin hand-off to the chain verifier, witness counting, head shapes, inclusion size, the canonicalizer
 * refusals and the totality catch. Valid proofs are the baseline each case changes one thing in.
 */
@Suppress("UNCHECKED_CAST")
class Kill05IntelMeshMeshProofTest {
    private fun m(vararg kv: Pair<String, Any?>) = KUtil.m(*kv)
    private fun l(vararg v: Any?) = KUtil.l(*v)
    private fun key(n: Int) = Keys.edFromSeed(ByteArray(32) { (n * 31 + it).toByte() })
    private val human = key(1)
    private val agents = (0 until 4).map { key(10 + it) }
    private val doms = (0 until 3).map { key(20 + it) }
    private val wits = (0 until 3).map { key(30 + it) }
    private val stranger = key(40)
    private val now = 1_800_000_000_000L
    private val rev0: String = KUtil.priv(Mesh, "bindRevRoot", 0L, KUtil.priv<String>(Mesh, "emptyRevTree"))

    private fun sign(k: Keys.EdKey, domain: String, body: Any?): String =
        Pca.b64(k.sign((domain + Json.canonicalizeStrict(body)).toByteArray(Charsets.UTF_8)))

    private fun mth(h: List<ByteArray>): ByteArray {
        if (h.size == 1) return h[0]
        var k = 1
        while (k * 2 < h.size) k *= 2
        return Pca.nodeHash(mth(h.subList(0, k)), mth(h.subList(k, h.size)))
    }

    /** RFC 6962 audit path of leaf [i], leaf to root, as the wire's {side, hash} steps. */
    private fun incPath(h: List<ByteArray>, i: Int): List<Any?> {
        if (h.size <= 1) return emptyList()
        var k = 1
        while (k * 2 < h.size) k *= 2
        return if (i < k) incPath(h.subList(0, k), i) + listOf<Any?>(m("side" to "R", "hash" to Pca.b64(mth(h.subList(k, h.size)))))
        else incPath(h.subList(k, h.size), i - k) + listOf<Any?>(m("side" to "L", "hash" to Pca.b64(mth(h.subList(0, k)))))
    }

    private class Built(val proof: MutableMap<String, Any?>, val trust: MutableMap<String, Any?>)

    /** Hop i appends [added][i] and is issued in doms[[dom][i]]; [sizeOf] maps a domain log's leaf count to its head's size. */
    private fun build(
        added: List<List<Any?>> = listOf(l(), l()),
        dom: List<Int> = listOf(0, 1),
        cosigners: List<Keys.EdKey> = listOf(wits[0], wits[1]),
        sizeOf: (Int) -> Long = { it.toLong() },
    ): Built {
        val caps = ArrayList<Map<String, Any?>>()
        for (i in added.indices) caps.add(
            if (i == 0) Issue.mintRoot(Keys.ed25519(human), agents[0].id(), null, added[0])
            else Issue.delegate(caps[i - 1], agents[i].id(), added[i], Keys.ed25519(agents[i - 1]))
        )
        val order = dom.distinct()
        fun members(d: Int) = dom.indices.filter { dom[it] == d }
        fun logLeaves(d: Int) = members(d).map { Pca.leafHash(Pca.capHash(caps[it])) }
        val heads = ArrayList<Any?>()
        for (d in order) {
            val hs = logLeaves(d)
            val head = m("domain" to doms[d].id(), "size" to sizeOf(hs.size), "root" to Pca.b64(mth(hs)), "rev_root" to rev0,
                "rev_size" to 0L, "timestamp" to now - 1000)
            val cosigs = ArrayList<Any?>()
            for (w in cosigners) cosigs.add(m("witness" to w.id(), "sig" to sign(w, Mesh.COSIG_DOMAIN, head)))
            heads.add(m("head" to head, "sig" to sign(doms[d], Mesh.HEAD_DOMAIN, head), "cosigs" to cosigs))
        }
        val hops = ArrayList<Any?>()
        for (i in caps.indices) {
            val d = doms[dom[i]]
            val hs = logLeaves(dom[i])
            val j = members(dom[i]).indexOf(i)
            val ev = m(
                "domain" to d.id(), "head" to order.indexOf(dom[i]).toLong(),
                "inclusion" to m("index" to j.toLong(), "size" to hs.size.toLong(), "path" to ArrayList<Any?>(incPath(hs, j))),
                "revocation" to m("cap" to m("size" to 0L), "issuer_key" to m("size" to 0L)),
            )
            if (i > 0) {
                val bind = m("agent" to caps[i]["issuer"], "domain" to d.id(), "role" to "agent")
                bind["sig"] = sign(d, Mesh.BINDING_DOMAIN, m("agent" to caps[i]["issuer"], "domain" to d.id(), "role" to "agent"))
                ev["binding"] = bind
            }
            hops.add(ev)
        }
        val action = m("type" to "orders.read", "resource" to "/orders/42", "service_domain" to "svc", "nonce" to "n1", "at" to now)
        val proof = m(
            "chain" to ArrayList<Any?>(caps), "heads" to heads, "rev_leaves" to l(), "hops" to hops, "action" to action,
            "action_sig" to sign(agents[caps.size - 1], Mesh.ACTION_DOMAIN, m("action" to action, "tip" to Pca.capHash(caps.last()))),
        )
        val trust = m(
            "humanPrincipal" to human.id(), "witnesses" to ArrayList<Any?>(wits.map { it.id() }), "threshold" to 2L, "now" to now,
            "allowedDomains" to ArrayList<Any?>(doms.map { it.id() }), "rootDomain" to doms[dom[0]].id(),
        )
        return Built(proof, trust)
    }

    private fun oneHop() = build(added = listOf(l()), dom = listOf(0))
    private fun v(b: Built): Mesh.Verdict = Mesh.verifyMeshProof(b.proof, b.trust)
    private fun expect(ok: Boolean, reason: String, hop: Int, got: Mesh.Verdict) {
        assertEquals(got.toString(), ok, got.ok)
        assertEquals(reason, got.reason)
        assertEquals(got.toString(), hop.toLong(), got.hop.toLong())
    }
    private fun ok(b: Built) = expect(true, "", -1, v(b))
    private fun head0(b: Built): MutableMap<String, Any?> = (b.proof["heads"] as List<*>)[0] as MutableMap<String, Any?>

    @Test fun mintedProofsVerify() {
        ok(build())
        ok(oneHop())
        ok(build(added = listOf(l(), l(), l()), dom = listOf(0, 0, 1)))
        ok(build(added = listOf(l(m("type" to "scope", "actions" to l("orders.read"))), l(), l(m("type" to "resource", "prefix" to "/orders/"))), dom = listOf(1, 2, 2)))
    }

    /** A map whose every read throws: the verifier's totality catch turns it into the generic refusal with no hop. */
    private class Boom(val t: Throwable) : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw t
    }

    @Test fun anyThrowIsMalformedProof() {
        val t = build().trust
        expect(false, "malformed proof", -1, Mesh.verifyMeshProof(Boom(IllegalStateException("boom")), t))
        expect(false, "malformed proof", -1, Mesh.verifyMeshProof(Boom(StackOverflowError()), t))
    }

    @Test fun missingTablesAreMalformedProofBeforeTheAction() {
        for (k in listOf("chain", "hops", "heads", "rev_leaves")) {
            val b = build()
            b.proof.remove(k)
            b.proof.remove("action")
            expect(false, "malformed proof", -1, v(b))
        }
    }

    @Test fun pinProofTable() {
        fun pins(k: Int): ArrayList<Any?> = ArrayList<Any?>().also { a ->
            repeat(k) { a.add(m("domain" to "elsewhere", "proof" to m("oldSize" to 0L, "newSize" to 0L, "path" to l()))) }
        }
        val b = build()
        b.proof["pin_proofs"] = pins(256)
        ok(b)
        b.proof["pin_proofs"] = pins(257)
        expect(false, "malformed pin proofs", -1, v(b))
        b.proof["pin_proofs"] = l(5L)
        expect(false, "malformed pin proofs", -1, v(b))
        b.proof["pin_proofs"] = l(m("proof" to m("oldSize" to 0L, "newSize" to 0L, "path" to l())))
        expect(false, "malformed pin proofs", -1, v(b))
        b.proof["pin_proofs"] = l(m("domain" to 5L, "proof" to m("oldSize" to 0L, "newSize" to 0L, "path" to l())))
        expect(false, "malformed pin proofs", -1, v(b))
    }

    @Test fun chainLengthBounds() {
        fun junk(k: Int): ArrayList<Any?> = ArrayList<Any?>().also { a -> repeat(k) { a.add(m()) } }
        val b = build()
        b.proof["chain"] = junk(65) // the default maxChainLength is 64
        expect(false, "chain length out of bounds", -1, v(b))
        b.proof["chain"] = junk(64)
        assertTrue(v(b).toString(), v(b).reason.startsWith("chain: "))
        b.proof["chain"] = junk(0)
        expect(false, "chain length out of bounds", -1, v(b))
        val c = build()
        c.trust["maxChainLength"] = 2L // a chain exactly at the configured maximum
        ok(c)
        c.trust["maxChainLength"] = 1L
        expect(false, "chain length out of bounds", -1, v(c))
    }

    @Test fun evidenceTableBounds() {
        val leaf = m("id" to "x", "proof" to m("index" to 0L, "size" to 1L, "path" to l()))
        val one = oneHop()
        one.proof["rev_leaves"] = l(leaf, leaf) // up to two revocation leaves per hop
        ok(one)
        one.proof["rev_leaves"] = l(leaf, leaf, leaf)
        expect(false, "evidence tables exceed chain size", -1, v(one))
        val two = oneHop()
        val h = (two.proof["heads"] as List<*>)[0]
        two.proof["heads"] = l(h, h)
        expect(false, "evidence tables exceed chain size", -1, v(two))
    }

    @Test fun pqPinsReachTheChainVerifier() {
        val b = oneHop()
        val root = LinkedHashMap((b.proof["chain"] as List<*>)[0] as Map<String, Any?>)
        root["alg"] = "ml-dsa-65"
        root["pq_pk"] = "PK"
        b.proof["chain"] = l(root)
        val needsPin = "chain: hop 0: root suite 'ml-dsa-65' needs a PQ key pinned"
        assertTrue(v(b).toString(), v(b).reason.startsWith(needsPin))
        // pinned (non-string pins are dropped): the root gets past the pin check to its own digest check
        b.trust["pqPins"] = m(human.id() to "PK", "junk" to 5L)
        expect(false, "chain: hop 0: body digest mismatch", -1, v(b))
        b.trust["pqPins"] = 5L // not an object: no pins
        assertTrue(v(b).toString(), v(b).reason.startsWith(needsPin))
        b.trust["pqPins"] = m(human.id() to 5L)
        assertTrue(v(b).toString(), v(b).reason.startsWith(needsPin))
    }

    @Test fun onlyTrustedDistinctCosignaturesCount() {
        val two = "source-domain anchor: head has 1/2 trusted witness cosignatures"
        expect(false, two, 0, v(build(cosigners = listOf(wits[0], stranger))))
        expect(false, two, 0, v(build(cosigners = listOf(wits[0], wits[0]))))
        ok(build(cosigners = listOf(wits[0], wits[0], wits[2])))
    }

    @Test fun cosignatureListBound() {
        fun padded(k: Int): Built {
            val b = oneHop()
            val cs = head0(b)["cosigs"] as MutableList<Any?>
            while (cs.size < k) cs.add(m())
            return b
        }
        ok(padded(256))
        expect(false, "source-domain anchor: malformed head", 0, v(padded(257)))
    }

    @Test fun headWithoutAStringDomain() {
        for (h in listOf<Any?>(5L, m("size" to 0L), m("domain" to 5L))) {
            val b = oneHop()
            head0(b)["head"] = h
            expect(false, "source-domain anchor: head is for a different domain", 0, v(b))
        }
        val noHead = oneHop()
        head0(noHead).remove("head")
        expect(false, "malformed proof", -1, v(noHead))
        val notMap = oneHop()
        notMap.proof["heads"] = l(5L)
        expect(false, "malformed proof", -1, v(notMap))
    }

    @Test fun inclusionSizeMustMatchTheHead() {
        // the head claims 2 leaves over a 1-leaf root: the 1-leaf inclusion proof folds to the root but its size is not the head's
        expect(false, "hop not included in the issuing domain log", 0, v(build(added = listOf(l()), dom = listOf(0), sizeOf = { it + 1L })))
    }

    @Test fun tipThatCannotBeHashedIsNotIncluded() {
        val b = build()
        val chain = b.proof["chain"] as MutableList<Any?>
        // an extra member outside the strict profile: not in the signed body (the chain verifies), but capHash refuses it
        chain[1] = LinkedHashMap(chain[1] as Map<String, Any?>).also { it["x"] = Json.Num("1.50") }
        expect(false, "hop not included in the issuing domain log", 1, v(b))
    }

    @Test fun bindingOutsideTheStrictProfileIsMalformed() {
        val b = build()
        val bind = ((b.proof["hops"] as List<*>)[1] as MutableMap<String, Any?>)["binding"] as MutableMap<String, Any?>
        bind["role"] = "\uD800" // lone surrogate: the reference's canonicalizer throws
        bind["sig"] = "x"
        expect(false, "malformed proof", -1, v(b))
    }

    @Test fun maxHopsCountsTheWholeChain() {
        expect(false, "action not admitted: chain exceeds max_hops 1", -1, v(build(added = listOf(l(m("type" to "max_hops", "n" to 1L)), l()))))
        ok(build(added = listOf(l(m("type" to "max_hops", "n" to 2L)), l())))
    }

    @Test fun trustNowMustBeAFiniteNumber() {
        for (bad in listOf<Any?>("1800000000000", null, true, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            val b = build()
            b.trust["now"] = bad
            expect(false, "invalid trust configuration: now", -1, v(b))
        }
        val b = build()
        b.trust["now"] = now.toDouble()
        ok(b)
    }

    @Test fun onlyATruthyPinnedHeadIsChecked() {
        // JavaScript truthiness: null / false / "" / 0 / NaN pins are skipped, anything else is checked as a head
        for (falsy in listOf<Any?>(null, false, "", 0L, 0.0, Double.NaN)) {
            val b = build()
            b.trust["pinnedHeads"] = m(doms[0].id() to falsy)
            ok(b)
        }
        for (truthy in listOf<Any?>(true, "x", 1L, -1L, Double.POSITIVE_INFINITY, l())) {
            val b = build()
            b.trust["pinnedHeads"] = m(doms[0].id() to truthy)
            expect(false, "source-domain anchor: malformed head (vs pinned head)", 0, v(b))
        }
    }
}
