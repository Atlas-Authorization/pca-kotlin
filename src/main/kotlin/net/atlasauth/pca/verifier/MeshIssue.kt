package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs

/**
 * The issuing side of the cross-domain mesh and the agent-to-agent federation primitives (mesh.ts): the worked example and the fork
 * demonstration, the proof-size and revocation-latency models, cross-domain capability translation, the consolidated budget tree that
 * spans domains, and the mutual-transparency cross-reference. Domains and witnesses themselves are [MeshDomain] and [MeshWitness];
 * verification of a whole proof is [Mesh.verifyMeshProof].
 *
 * Values are the JSON trees the wire carries (maps, lists, strings, booleans, [Json.Num]). Signers and translators throw on input
 * they cannot sign; verifiers never throw and always answer with `{ok: false, reason}`.
 */
@Suppress("UNCHECKED_CAST")
object MeshIssue {
    const val XCAP_VERSION = "atlas-pca/mesh-xcap/v1"
    const val XREF_VERSION = "atlas-pca/mesh-xref/v1"
    const val XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\u0000"
    const val XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\u0000"
    const val ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\u0000"

    /** The deepest budget tree a spend walks (a path of more nodes is refused). */
    const val MAX_BUDGET_DEPTH = 64

    private fun rec(x: Any?): Map<String, Any?>? = x as? Map<String, Any?>
    private fun fin(x: Any?): Boolean = IntentJs.isFinite(x)
    private fun dbl(x: Any?): Double = IntentJs.num(x)!!
    private fun nat(x: Any?): Boolean = Json.isSafeInt(x) && IntentJs.isNonNeg(x)
    private fun msg(domain: String, body: Any?): ByteArray = Pca.concat(Json.utf8(domain), Pca.canonBytes(body))
    private fun no(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /** A member the reference reads into a signed or hashed body: an absent one cannot be hashed. */
    private fun member(m: Map<String, Any?>, k: String): Any? {
        if (!m.containsKey(k)) throw IllegalArgumentException("canonicalize: member '$k' is absent")
        return m[k]
    }

    /** The id used in a domain's revocation set to revoke an agent KEY (it kills every capability that key issues). */
    fun keyRevocationId(agentPublic: Any?): String = "key:" + IntentRevocation.jsText(agentPublic, true)

    // ---- size model ---------------------------------------------------------------------------------------------------------------

    private val UNDEF = Any()

    /** `container[key]` as the reference indexes a JSON value; [UNDEF] when there is no such member. A null container throws. */
    private fun index(container: Any?, key: Any?): Any? {
        if (container == null) throw IllegalArgumentException("cannot index null")
        if (container is List<*>) {
            val d = IntentJs.num(key) ?: (key as? String)?.takeIf { Regex("0|[1-9][0-9]*").matches(it) }?.toDoubleOrNull() ?: return UNDEF
            return if (d == Math.rint(d) && d >= 0 && d < container.size) container[d.toInt()] else UNDEF
        }
        val m = rec(container) ?: return UNDEF
        val k = IntentRevocation.jsText(key, true)
        return if (m.containsKey(k)) m[k] else UNDEF
    }

    private fun truthy(v: Any?): Boolean = when (v) {
        null, false, "" -> false
        is Json.Num -> IntentJs.num(v).let { it != null && it != 0.0 && !it.isNaN() }
        else -> v !== UNDEF
    }

    private fun bytes(x: Any?): Long = Pca.canonBytes(x).size.toLong()

    /**
     * Byte sizes (strict canonical JSON) of a mesh proof's parts: `{total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes, hops_bytes,
     * uncompacted_bytes}`. `uncompacted_bytes` is the size had every hop carried its own head copy and inline revocation leaves. Throws
     * IllegalArgumentException on a value that is not a proof (a missing part, a hop naming a head that is not in the table).
     */
    fun meshProofSize(proof: Any?): Map<String, Any?> {
        val p = rec(proof) ?: throw IllegalArgumentException("meshProofSize: not a proof")
        val leaves = if (p.containsKey("rev_leaves")) p["rev_leaves"] else UNDEF
        fun expand(c: Any?): Map<String, Any?> {
            val m = rec(c) ?: throw IllegalArgumentException("meshProofSize: malformed non-membership proof")
            val o = linkedMapOf<String, Any?>("size" to member(m, "size"))
            for (side in listOf("lo", "hi")) {
                if (!m.containsKey(side)) continue
                if (leaves === UNDEF) throw IllegalArgumentException("meshProofSize: no rev_leaves")
                val leaf = index(leaves, m[side])
                if (truthy(leaf)) o[side] = leaf
            }
            return o
        }
        var uncompacted = bytes(member(p, "chain")) + bytes(member(p, "action")) + bytes(member(p, "action_sig"))
        val hops = p["hops"] as? List<Any?> ?: throw IllegalArgumentException("meshProofSize: hops is not a list")
        for (hO in hops) {
            val h = rec(hO) ?: throw IllegalArgumentException("meshProofSize: malformed hop")
            val rev = rec(h["revocation"]) ?: throw IllegalArgumentException("meshProofSize: malformed hop revocation")
            val full = LinkedHashMap(h)
            val head = if (h.containsKey("head")) index(member(p, "heads"), h["head"]) else UNDEF
            if (head === UNDEF) throw IllegalArgumentException("meshProofSize: hop names a head that is not in the table")
            full["head"] = head
            full["revocation"] = linkedMapOf("cap" to expand(rev["cap"]), "issuer_key" to expand(rev["issuer_key"]))
            uncompacted += bytes(full)
        }
        return linkedMapOf(
            "total_bytes" to bytes(p), "chain_bytes" to bytes(member(p, "chain")), "heads_bytes" to bytes(member(p, "heads")),
            "rev_leaves_bytes" to bytes(member(p, "rev_leaves")), "hops_bytes" to bytes(hops), "uncompacted_bytes" to uncompacted,
        )
    }

    // ---- freshness and revocation latency model -----------------------------------------------------------------------------------

    /** Worst-case time (ms) from "revocation made" until it is enforced, per verifier posture. Infinite and not viable for unusable inputs. */
    class LatencyBound(
        /** Until the revocation is visible in a head that new provers hold. */
        val publishedMs: Double,
        /** A verifier without pins: a head from before the revocation is rejected as stale by then. */
        val unpinnedMs: Double,
        /** A pinning verifier: the lesser of [unpinnedMs] and its pin refresh interval. */
        val pinnedMs: Double,
        /** Honest provers can always hold a fresh head only if heads are published more often than they go stale (after skew). */
        val honestProversViable: Boolean,
    )

    /**
     * The revocation-latency bound for `{maxHeadAgeMs, headIntervalMs, maxClockSkewMs?, pinRefreshMs?}` (all ms). A head from before a
     * revocation stops verifying no later than `maxHeadAgeMs + maxClockSkewMs` after it; a head that contains it is available within
     * `headIntervalMs`; a verifier whose pin advances every `pinRefreshMs` rejects the older head as soon as the pin moves. A missing,
     * non-finite or negative input yields an unusable bound.
     */
    fun revocationLatencyBound(params: Any?): LatencyBound {
        val p = rec(params) ?: emptyMap()
        fun ok(k: String): Boolean = fin(p[k]) && dbl(p[k]) >= 0
        if (!ok("maxHeadAgeMs") || !ok("headIntervalMs") || (p.containsKey("maxClockSkewMs") && !ok("maxClockSkewMs")) ||
            (p.containsKey("pinRefreshMs") && !ok("pinRefreshMs"))
        ) {
            return LatencyBound(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY, false)
        }
        val skew = if (p.containsKey("maxClockSkewMs")) dbl(p["maxClockSkewMs"]) else 0.0
        val age = dbl(p["maxHeadAgeMs"])
        val interval = dbl(p["headIntervalMs"])
        val unpinned = age + skew
        val pinned = if (p.containsKey("pinRefreshMs")) Math.min(unpinned, dbl(p["pinRefreshMs"])) else unpinned
        return LatencyBound(interval, unpinned, pinned, interval + skew < age)
    }

    // ---- worked example -----------------------------------------------------------------------------------------------------------

    /** The example's keys: the first 32 bytes of the TEXT of the digest of `{seed: "atlas-pca/mesh-example/<label>"}` (not the decoded digest). */
    private fun seedKey(label: String): Keys.EdKey =
        Keys.edFromSeed(Pca.hashCanonical(Issue.obj("seed" to "atlas-pca/mesh-example/$label")).substring(0, 32).toByteArray(Charsets.US_ASCII))

    private fun scope(vararg actions: String): Map<String, Any?> = Issue.obj("type" to "scope", "actions" to arrayListOf<Any?>(*actions))
    private fun cav(type: String, k: String, v: Any?): Map<String, Any?> = Issue.obj("type" to type, k to v)

    /** The parts of [buildMeshExample], exposed so callers can build variants (revocation, widening, forks). */
    class Example internal constructor(
        /** The verifier's trust anchors for the example. */
        val trust: Map<String, Any?>,
        val proof: Map<String, Any?>,
        /** The uncompacted evidence the proof was assembled from. */
        val evidence: List<Map<String, Any?>>,
        /** `A`, `B`, `C`. */
        val domains: Map<String, MeshDomain>,
        val witnesses: List<MeshWitness>,
        /** `human`, `orchestrator`, `tool`, `service`, `leaf`. */
        val keys: Map<String, Keys.EdKey>,
        val chain: List<Map<String, Any?>>,
        /** `A0` is A's earlier head (size 1), `A` its current one (size 2); `B`, `C`. */
        val heads: Map<String, Map<String, Any?>>,
        /** `orchestrator`, `tool`, `service`. */
        val bindings: Map<String, Map<String, Any?>>,
    )

    /**
     * The worked example: four hops across three organisations (human to orchestrator in A, to a tool agent in B, to a service agent in
     * C, to a leaf worker), the leaf then refunding 25 under /orders/42. Organisation A publishes two successive heads; every witness
     * cosigns the second only after verifying the consistency proof between them. Deterministic for a given `now` (epoch ms).
     */
    @JvmOverloads
    fun buildMeshExample(now: Long = 1_800_000_000_000L): Example {
        val keys = linkedMapOf<String, Keys.EdKey>()
        for (l in listOf("human", "orchestrator", "tool", "service", "leaf")) keys[l] = seedKey(l)
        fun k(l: String): Keys.EdKey = keys[l]!!
        val a = MeshDomain("org-A", seedKey("domain-A"))
        val b = MeshDomain("org-B", seedKey("domain-B"))
        val c = MeshDomain("org-C", seedKey("domain-C"))
        val witnesses = listOf(MeshWitness(seedKey("witness-1")), MeshWitness(seedKey("witness-2")), MeshWitness(seedKey("witness-3")))

        val root = Issue.mintRoot(
            Keys.ed25519(k("human")), k("orchestrator").id(), null,
            listOf(
                scope("payments.refund", "payments.read", "orders.read"), cav("resource", "prefix", "/orders/"), cav("max_amount", "max", StoreJs.num(500L)),
                cav("expires", "at", StoreJs.num(now + 3_600_000L)), cav("audience", "domains", arrayListOf<Any?>(c.id)),
            ),
        )
        val c1 = Issue.delegate(root, k("tool").id(), listOf(scope("payments.refund", "payments.read"), cav("max_amount", "max", StoreJs.num(100L))), Keys.ed25519(k("orchestrator")))
        val c2 = Issue.delegate(c1, k("service").id(), listOf(cav("resource", "prefix", "/orders/42"), cav("max_hops", "n", StoreJs.num(4L))), Keys.ed25519(k("tool")))
        val c3 = Issue.delegate(c2, k("leaf").id(), listOf(scope("payments.refund"), cav("max_amount", "max", StoreJs.num(50L))), Keys.ed25519(k("service")))
        val chain = listOf(root, c1, c2, c3)

        a.record(root)
        val hA0 = a.publishHead(witnesses, (now - 2_000L).toDouble())
        a.record(c1)
        val hA = a.publishHead(witnesses, (now - 1_000L).toDouble()) // size 1 -> 2: consistency-proven by every witness
        b.record(c2)
        c.record(c3)
        val hB = b.publishHead(witnesses, (now - 1_000L).toDouble())
        val hC = c.publishHead(witnesses, (now - 1_000L).toDouble())
        val bOrch = a.enroll(k("orchestrator").id(), "orchestrator")
        val bTool = b.enroll(k("tool").id(), "tool-agent")
        val bSvc = c.enroll(k("service").id(), "service-agent")

        val evidence = listOf(a.evidence(root, hA, null), a.evidence(c1, hA, bOrch), b.evidence(c2, hB, bTool), c.evidence(c3, hC, bSvc))
        val action = Issue.obj(
            "type" to "payments.refund", "resource" to "/orders/42/line/1", "amount" to StoreJs.num(25L), "service_domain" to c.id, "nonce" to "n-0001",
            "at" to StoreJs.num(now),
        )
        val proof = SignersMore.assembleMeshProof(chain, evidence, action, k("leaf"))
        val trust = Issue.obj(
            "humanPrincipal" to k("human").id(), "witnesses" to witnesses.mapTo(ArrayList<Any?>()) { it.id }, "threshold" to StoreJs.num(2L),
            "now" to StoreJs.num(now), "allowedDomains" to arrayListOf<Any?>(a.id, b.id, c.id), "rootDomain" to a.id,
        )
        return Example(
            trust, proof, evidence, linkedMapOf("A" to a, "B" to b, "C" to c), witnesses, keys, chain,
            linkedMapOf("A0" to hA0, "A" to hA, "B" to hB, "C" to hC), linkedMapOf("orchestrator" to bOrch, "tool" to bTool, "service" to bSvc),
        )
    }

    /**
     * A worked demonstration that witnesses verify real RFC 9162 consistency: a domain rewrites an early log entry and grows the forked
     * log PAST the size the witness last saw. Size-only checks pass; the consistency proof (necessarily computed over the forked log)
     * does not. Returns `{honest_extension_cosigned, fork_larger_than_prior, size_only_check_would_accept, fork_rejected, fork_reason}`.
     */
    fun demonstrateForkRejection(): Map<String, Any?> {
        val dk = seedKey("fork-domain")
        val hk = seedKey("fork-human")
        fun mk(n: Int): Map<String, Any?> = Issue.mintRoot(Keys.ed25519(hk), hk.id(), null, listOf(scope("a$n")))
        val w = MeshWitness(seedKey("fork-witness"))
        val honest = MeshDomain("X", dk)
        honest.record(mk(0))
        honest.record(mk(1))
        honest.publishHead(listOf(w), 100.0)
        honest.record(mk(2))
        val honestOk = try {
            honest.publishHead(listOf(w), 200.0)
            true
        } catch (e: RuntimeException) {
            false
        }
        val prior = Json.asLong(w.lastSeen(honest.id)!!["size"])
        val fork = MeshDomain("X", dk) // same key, rewritten history (entry 0 differs), grown past the prior size
        for (n in listOf(100, 1, 2, 3)) fork.record(mk(n))
        var reason = ""
        var rejected = false
        try {
            fork.publishHead(listOf(w), 300.0)
        } catch (e: RuntimeException) {
            rejected = true
            reason = e.message ?: ""
        }
        return linkedMapOf(
            "honest_extension_cosigned" to honestOk, "fork_larger_than_prior" to (4 > prior), "size_only_check_would_accept" to (4 >= prior),
            "fork_rejected" to rejected, "fork_reason" to reason,
        )
    }

    // ---- 1. cross-domain capability translation -----------------------------------------------------------------------------------

    /** A list whose every entry is an object with a string `type`, else null. */
    private fun caveatArray(x: Any?): List<Any?>? {
        val l = x as? List<Any?> ?: return null
        return if (l.all { rec(it)?.get("type") is String }) l else null
    }

    private fun xcapBody(from: Any?, to: Any?, sourceTip: String, caveats: List<Any?>, issuedAt: Any?): Map<String, Any?> =
        Issue.obj("v" to XCAP_VERSION, "from" to from, "to" to to, "source_tip" to sourceTip, "caveats" to caveats, "issued_at" to issuedAt)

    /**
     * Translate a capability chain rooted in guardian A's grant into a capability valid in guardian B's domain: the result's caveats are
     * the chain tip's followed by `additionalCaveats` (append-only, so the bridge can only narrow), signed by `bridge`. Returns
     * `{source, fromGuardian, toGuardian, bridge, source_tip, caveats, issued_at, sig}`. `pqPins` are the verifier-side post-quantum pins
     * a hybrid or pure post-quantum root needs. Throws IllegalArgumentException on an invalid source chain or caveats that are not caveats.
     */
    @JvmOverloads
    fun translateCapability(
        chain: List<Any?>, fromGuardian: String, toGuardian: String, bridge: Keys.EdKey, issuedAt: Long,
        additionalCaveats: List<Any?>? = null, pqPins: Map<String, Any?>? = null,
    ): Map<String, Any?> {
        val args = Issue.obj("fromGuardian" to fromGuardian, "toGuardian" to toGuardian, "issued_at" to StoreJs.num(issuedAt))
        if (additionalCaveats != null) args["additionalCaveats"] = additionalCaveats
        if (pqPins != null) args["pqPins"] = pqPins
        return translateCapabilityRef(chain, args, bridge)
    }

    /** [translateCapability] over the reference's untyped arguments `{fromGuardian, toGuardian, issued_at, additionalCaveats?, pqPins?}`: a present null is not an absent member. */
    internal fun translateCapabilityRef(chainO: Any?, args: Map<String, Any?>, bridge: Keys.EdKey): Map<String, Any?> {
        val chain = chainO as? List<Any?> ?: emptyList()
        val why = Pca.verifyChain(chain, "", false, null, rec(args["pqPins"]), null)
        if (why.isNotEmpty()) throw IllegalArgumentException("translateCapability: invalid source chain: $why")
        val added = if (args.containsKey("additionalCaveats")) {
            caveatArray(args["additionalCaveats"]) ?: throw IllegalArgumentException("translateCapability: additionalCaveats must be an array of caveats")
        } else emptyList()
        val tip = chain.last() as Map<String, Any?>
        val caveats = ArrayList<Any?>(Issue.norm(tip["caveats"] as List<Any?>))
        caveats.addAll(Issue.norm(added))
        val sourceTip = Pca.capHash(tip)
        val from = member(args, "fromGuardian")
        val to = member(args, "toGuardian")
        val at = member(args, "issued_at")
        val sig = Keys.b64u(bridge.sign(msg(XCAP_DOMAIN, xcapBody(from, to, sourceTip, caveats, at))))
        return Issue.obj(
            "source" to chain, "fromGuardian" to from, "toGuardian" to to, "bridge" to bridge.id(), "source_tip" to sourceTip, "caveats" to caveats,
            "issued_at" to at, "sig" to sig,
        )
    }

    /** The translated effective authority (the conjunction of all translated caveats), or `{error}` (fail closed) for a malformed translation or caveat. */
    fun translatedEffectiveAuthority(tc: Any?): Map<String, Any?> {
        val caveats = caveatArray(rec(tc)?.get("caveats")) ?: return linkedMapOf("error" to "malformed translated capability")
        return Mesh.effectiveAuthority(caveats)
    }

    /**
     * Verify a translated capability: `{ok: true, from, to, bridge, effective}` or `{ok: false, reason}`. Checks the source chain, the
     * optional pins in `opts` (`fromGuardian`, `toGuardian`, `bridge`, `rootIssuer`, `pqPins`), that the translation crosses a domain
     * boundary, the source tip binding, that the translated caveats extend the tip's without altering them, the bridge signature, that
     * the translated authority narrows the source's, and, with `opts.now`, expiry. Never throws.
     */
    @JvmOverloads
    fun verifyTranslatedCapability(tc: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> = verifyTranslatedCapabilityRef(tc, opts, false)

    /** [verifyTranslatedCapability] with the reference's reading of its second argument: a null that was passed is malformed, any other non-object is no options. */
    internal fun verifyTranslatedCapabilityRef(tc: Any?, opts: Any?, optsGiven: Boolean): Map<String, Any?> = try {
        verifyTranslated(tc, opts, optsGiven)
    } catch (e: RuntimeException) {
        no("malformed translated capability")
    }

    /**
     * JavaScript's number for `now` in `now > expiry`: text is read as a numeric literal (white space trimmed, "" is 0, a decimal with an
     * optional exponent, a signed Infinity, a 0x / 0o / 0b integer; anything else is NaN), a list or an object through its text.
     * shortcut: a 0x / 0o / 0b literal over 63 bits reads as NaN, use BigInteger if such text must compare.
     */
    private fun jsNumber(v: Any?): Double =
        ComplianceJs.toNumber(if (v is List<*> || v is Map<*, *>) IntentRevocation.jsText(v, true) else v)

    private fun verifyTranslated(tcO: Any?, optsO: Any?, optsGiven: Boolean): Map<String, Any?> {
        val bad = "malformed translated capability"
        val tc = rec(tcO) ?: return no(bad)
        val source = tc["source"] as? List<Any?> ?: return no(bad)
        val from = tc["fromGuardian"] as? String ?: return no(bad)
        val to = tc["toGuardian"] as? String ?: return no(bad)
        val bridge = tc["bridge"] as? String ?: return no(bad)
        val sourceTip = tc["source_tip"] as? String ?: return no(bad)
        val sig = tc["sig"] as? String ?: return no(bad)
        if (!fin(tc["issued_at"])) return no(bad)
        val caveats = caveatArray(tc["caveats"]) ?: return no(bad)
        if (optsGiven && optsO == null) return no(bad)
        val opts = rec(optsO) ?: emptyMap()

        // (1) source chain; an expected root issuer that is not a string can match no issuer
        val pinRoot = opts.containsKey("rootIssuer")
        val why = Pca.verifyChain(source, if (pinRoot) opts["rootIssuer"] as? String ?: "\u0000" else "", pinRoot, null, rec(opts["pqPins"]), null)
        if (why.isNotEmpty()) return no("source chain: $why")

        // (2) guardian / bridge pins
        if (opts.containsKey("fromGuardian") && opts["fromGuardian"] != from) return no("source guardian mismatch")
        if (opts.containsKey("toGuardian") && opts["toGuardian"] != to) return no("target guardian mismatch")
        if (opts.containsKey("bridge") && opts["bridge"] != bridge) return no("bridge key mismatch")
        if (from == to) return no("translation does not cross a domain boundary")

        // (3) source tip binding
        val tip = source.last() as Map<String, Any?>
        if (sourceTip != Pca.capHash(tip)) return no("source_tip does not match the source chain tip")

        // (4) append-only prefix over the source tip's caveats
        val tipCaveats = tip["caveats"] as List<Any?>
        if (caveats.size < tipCaveats.size) return no("translation drops a source caveat (widening)")
        for (j in tipCaveats.indices) {
            if (Pca.hashCanonical(caveats[j]) != Pca.hashCanonical(tipCaveats[j])) return no("translation altered or reordered source caveat $j (widening)")
        }

        // (5) bridge signature
        if (!Pca.verifyB64u(bridge, msg(XCAP_DOMAIN, xcapBody(from, to, sourceTip, caveats, tc["issued_at"])), sig)) {
            return no("translation not signed by the declared bridge key")
        }

        // (6) monotone narrowing of the effective authority (defence in depth; an unknown caveat fails closed)
        val (effS, errS) = Mesh.authority(tipCaveats)
        if (errS.isNotEmpty()) return no("source caveats: $errS")
        val (effT, errT) = Mesh.authority(caveats)
        if (errT.isNotEmpty()) return no(errT)
        if (!Mesh.narrows(effT, effS)) return no("translated authority widens the source authority")

        // (7) optional expiry
        // Number.isFinite does not coerce: a null or string clock is no finite number, so it is expired
        if (opts.containsKey("now") && effT.hasExp) {
            val nowV = opts["now"]
            val ok = (nowV is Json.Num || nowV is Number) && jsNumber(nowV).let { it.isFinite() && it <= effT.expiresAt }
            if (!ok) return no("translated capability expired")
        }

        return linkedMapOf("ok" to true, "from" to from, "to" to to, "bridge" to bridge, "effective" to Mesh.authorityJson(effT))
    }

    // ---- 2. consolidated cross-domain budget (the budget tree spans domains) ------------------------------------------------------

    private fun validBudgetState(sO: Any?): Map<String, Any?>? {
        val s = rec(sO) ?: return null
        val nodes = rec(s["nodes"]) ?: return null
        val root = s["root"] as? String ?: return null
        if (!fin(s["kappa"]) || !fin(s["bMax"]) || dbl(s["kappa"]) <= 0 || dbl(s["bMax"]) < 0 || !nodes.containsKey(root)) return null
        for (nO in nodes.values) {
            val n = rec(nO) ?: return null
            if (n["domain"] !is String || !fin(n["B"]) || dbl(n["B"]) < 0) return null
            if (n.containsKey("parent") && n["parent"] !is String) return null
        }
        return s
    }

    private fun nodesOf(state: Map<String, Any?>): Map<String, Any?> = state["nodes"] as Map<String, Any?>
    private fun balance(nodes: Map<String, Any?>, id: String): Double = dbl((nodes[id] as Map<String, Any?>)["B"])
    private fun withNodes(state: Map<String, Any?>, nodes: Map<String, Any?>): Map<String, Any?> =
        linkedMapOf("ok" to true, "state" to LinkedHashMap(state).also { it["nodes"] = nodes })

    /** A node debited by `c`, floored at zero. */
    private fun debited(nodes: Map<String, Any?>, id: String, c: Double): Map<String, Any?> =
        LinkedHashMap(nodes[id] as Map<String, Any?>).also { it["B"] = StoreJs.num(Math.max(0.0, balance(nodes, id) - c)) }

    /**
     * A federated budget tree `{nodes, root, kappa, bMax}` with one root node `{domain, B}`: `{ok: true, state}` or `{ok: false, reason}`
     * for `{rootId, rootDomain, B0, kappa, bMax}` (0 <= B0 <= bMax, kappa > 0, all finite). The state is a value: every operation
     * returns a new one.
     */
    fun createFederatedBudget(args: Any?): Map<String, Any?> {
        val a = rec(args)
        val rootId = a?.get("rootId") as? String
        val rootDomain = a?.get("rootDomain") as? String
        if (a == null || rootId == null || rootDomain == null) return no("malformed root")
        if (!fin(a["kappa"]) || dbl(a["kappa"]) <= 0) return no("kappa must be finite and > 0")
        if (!fin(a["bMax"]) || dbl(a["bMax"]) < 0) return no("bMax must be finite and >= 0")
        if (!fin(a["B0"]) || dbl(a["B0"]) < 0) return no("B0 must be finite and >= 0")
        if (dbl(a["B0"]) > dbl(a["bMax"])) return no("B0 exceeds bMax")
        val nodes = linkedMapOf<String, Any?>(rootId to linkedMapOf<String, Any?>("domain" to rootDomain, "B" to a["B0"]))
        return linkedMapOf("ok" to true, "state" to linkedMapOf<String, Any?>("nodes" to nodes, "root" to rootId, "kappa" to a["kappa"], "bMax" to a["bMax"]))
    }

    /**
     * Allocate a sub-budget `{id, domain, parent, alloc}` under an existing node, possibly in another domain. The allocation is a
     * ceiling (0 <= alloc <= the parent's CURRENT remaining budget) and does not reduce the parent; spends do.
     */
    fun allocateSub(state: Any?, args: Any?): Map<String, Any?> {
        val s = validBudgetState(state) ?: return no("malformed budget state")
        val a = rec(args)
        val id = a?.get("id") as? String
        val domain = a?.get("domain") as? String
        val parent = a?.get("parent") as? String
        if (a == null || id == null || domain == null || parent == null) return no("malformed allocation")
        val nodes = nodesOf(s)
        if (nodes.containsKey(id)) return no("node id already exists")
        if (!nodes.containsKey(parent)) return no("unknown parent")
        if (!fin(a["alloc"]) || dbl(a["alloc"]) < 0) return no("allocation must be finite and >= 0")
        if (!(balance(nodes, parent).isFinite() && dbl(a["alloc"]) <= balance(nodes, parent))) return no("allocation exceeds parent remaining budget")
        val next = LinkedHashMap(nodes)
        next[id] = linkedMapOf<String, Any?>("domain" to domain, "parent" to parent, "B" to a["alloc"])
        return withNodes(s, next)
    }

    /**
     * A sub-agent spends `c` from node `nodeId`. Atomic: every node from the spender up to the root must cover `c`, then every one of
     * them is debited by `c`; if any cannot, nothing changes. So the whole cross-domain delegation tree draws on one consolidated budget.
     */
    fun spendFederated(state: Any?, nodeId: Any?, c: Any?): Map<String, Any?> {
        val s = validBudgetState(state) ?: return no("malformed budget state")
        if (nodeId !is String) return no("malformed node id")
        if (!fin(c) || dbl(c) < 0) return no("spend must be finite and >= 0")
        val x = dbl(c)
        val nodes = nodesOf(s)
        val rootId = s["root"] as String

        val path = ArrayList<String>()
        var cur: String? = nodeId
        while (cur != null) {
            if (!nodes.containsKey(cur)) return no("unknown node")
            if (cur in path) return no("cycle in budget tree")
            if (path.size >= MAX_BUDGET_DEPTH) return no("budget tree too deep")
            path.add(cur)
            cur = (nodes[cur] as Map<String, Any?>)["parent"] as String?
        }
        if (path.last() != rootId) return no("node is not rooted at the budget root")

        val next = LinkedHashMap(nodes)
        if (nodeId == rootId) {
            if (!(balance(nodes, rootId).isFinite() && balance(nodes, rootId) >= x)) return no("root budget insufficient")
            next[rootId] = debited(nodes, rootId, x)
            return withNodes(s, next)
        }
        // the strict-interior ancestors (everything between the spender and the root), then the spender and the root
        val interior = path.subList(1, path.size - 1)
        for (id in interior) if (!(balance(nodes, id).isFinite() && balance(nodes, id) >= x)) return no("ancestor \"$id\" budget insufficient")
        if (!(balance(nodes, nodeId).isFinite() && balance(nodes, nodeId) >= x)) return no("sub-agent budget insufficient")
        if (!(balance(nodes, rootId).isFinite() && balance(nodes, rootId) >= x)) return no("parent budget insufficient")
        for (id in interior + listOf(nodeId, rootId)) next[id] = debited(nodes, id, x)
        return withNodes(s, next)
    }

    /** The consolidated safety bound of a federated tree `{bMax, kappa}`: the total spend over the whole tree is at most `bMax / kappa`. 0 for a malformed value. */
    fun federatedSafetyBound(p: Any?): Double {
        val m = rec(p)
        if (m == null || !fin(m["bMax"]) || !fin(m["kappa"])) return 0.0
        return if (dbl(m["kappa"]) > 0) Math.max(0.0, dbl(m["bMax"])) / dbl(m["kappa"]) else 0.0
    }

    // ---- 3. mutual transparency: the cross-reference linking commitment -----------------------------------------------------------

    /** Canonical, domain-separated digest of a mesh action (what both guardians anchor). Throws on a value the strict canonical form refuses. */
    fun meshActionDigest(action: Any?): String = Pca.hashCanonical(Issue.obj("v" to ACTION_DIGEST_DOMAIN, "action" to action))

    /**
     * The linking commitment of a cross-reference `{action_digest, fromGuardian, toGuardian, nonce, at}`, deterministic in all five
     * members. Throws IllegalArgumentException when a member is absent or cannot be hashed.
     */
    fun crossReferenceCommit(x: Any?): String {
        val m = rec(x) ?: throw IllegalArgumentException("crossReferenceCommit: not a cross-reference")
        return Pca.hashCanonical(
            Issue.obj(
                "v" to XREF_VERSION, "action_digest" to member(m, "action_digest"), "from" to member(m, "fromGuardian"), "to" to member(m, "toGuardian"),
                "nonce" to member(m, "nonce"), "at" to member(m, "at"),
            ),
        )
    }

    /** A guardian anchors a cross-reference commitment in its own log at `seq`, signing it: `{domain, commit, seq, sig}`. */
    fun anchorCrossReference(domain: Keys.EdKey, commit: Any?, seq: Any?): Map<String, Any?> = Issue.obj(
        "domain" to domain.id(), "commit" to commit, "seq" to seq,
        "sig" to Keys.b64u(domain.sign(msg(XANCHOR_DOMAIN, Issue.obj("commit" to commit, "seq" to seq)))),
    )

    private fun validAnchor(aO: Any?): Map<String, Any?>? {
        val a = rec(aO) ?: return null
        return if (a["domain"] is String && a["commit"] is String && nat(a["seq"]) && a["sig"] is String) a else null
    }

    private fun anchorSigned(a: Map<String, Any?>): Boolean =
        Pca.verifyB64u(a["domain"] as String, msg(XANCHOR_DOMAIN, Issue.obj("commit" to a["commit"], "seq" to a["seq"])), a["sig"] as String)

    /**
     * Verify a cross-reference against both guardians' anchors `{from, to}`: both commit the SAME action (the commitment recomputed
     * from `x`), each is signed by the domain it claims, and those domains are the cross-reference's two distinct guardians.
     * `{ok: true, commit}` or `{ok: false, reason}`; never throws.
     */
    fun verifyCrossReference(x: Any?, anchors: Any?): Map<String, Any?> = try {
        crossReference(x, anchors)
    } catch (e: RuntimeException) {
        no("malformed cross-reference")
    }

    private fun crossReference(xO: Any?, anchorsO: Any?): Map<String, Any?> {
        val x = rec(xO)
        if (x == null || x["action_digest"] !is String || x["fromGuardian"] !is String || x["toGuardian"] !is String || x["nonce"] !is String || !fin(x["at"])) {
            return no("malformed cross-reference")
        }
        val anchors = rec(anchorsO)
        val from = validAnchor(anchors?.get("from"))
        val to = validAnchor(anchors?.get("to"))
        if (from == null || to == null) return no("malformed anchors")
        if (x["fromGuardian"] == x["toGuardian"]) return no("cross-reference must span two distinct domains")

        val expected = crossReferenceCommit(x)
        if (from["domain"] != x["fromGuardian"]) return no("source anchor domain does not match the cross-reference")
        if (to["domain"] != x["toGuardian"]) return no("target anchor domain does not match the cross-reference")
        if (from["commit"] != expected) return no("source anchor commits a different action")
        if (to["commit"] != expected) return no("target anchor commits a different action")
        if (!anchorSigned(from)) return no("source anchor signature invalid")
        if (!anchorSigned(to)) return no("target anchor signature invalid")
        return linkedMapOf("ok" to true, "commit" to expected)
    }
}
