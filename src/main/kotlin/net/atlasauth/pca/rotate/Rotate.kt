package net.atlasauth.pca.rotate

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.revoke.RevocationRegistry
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys

/**
 * A record naming a key / capability / subtree as revoked, for a revocation registry. Only [reason] and [revokedAt] are always present;
 * the identifying fields are whatever the rotation knows (null when unknown).
 */
class RevocationRecord(
    /** The capability id being revoked (the subtree root for a subtree revocation). */
    val capId: String?,
    /** The b64u holder key whose authority is revoked. */
    val holder: String?,
    /** The b64u issuer key that signed the revoked capability. */
    val issuer: String?,
    /** The capability id at the top of a revoked subtree. */
    val subtreeRoot: String?,
    capIds: List<String>?,
    val reason: String,
    /** Epoch ms the revocation was recorded. */
    val revokedAt: Double,
) {
    /** Every capability id this record covers. */
    val capIds: List<String>? = capIds?.toList()

    /** The JSON form (the reference's record object). */
    fun toMap(): Map<String, Any?> = linkedMapOf<String, Any?>().apply {
        if (capId != null) put("capId", capId)
        if (holder != null) put("holder", holder)
        if (issuer != null) put("issuer", issuer)
        if (subtreeRoot != null) put("subtreeRoot", subtreeRoot)
        if (capIds != null) put("capIds", ArrayList<Any?>(capIds))
        put("reason", reason)
        put("revokedAt", Js.jsNum(revokedAt))
    }
}

/** The part of a revocation registry that [Rotate.applyRotation] needs; [of] adapts a [RevocationRegistry]. */
interface RevocationSink {
    /** Revoke input = {kind: 'cap', value, reason?, revokedAt?}. */
    fun revoke(input: Map<String, Any?>)

    /** Remove the cap revocation; true when one was removed. */
    fun unrevoke(key: Map<String, Any?>): Boolean

    /** The cap revocation for value, or null when there is none. */
    fun lookup(kind: String, value: String): Any?

    companion object {
        @JvmStatic
        fun of(registry: RevocationRegistry): RevocationSink = object : RevocationSink {
            override fun revoke(input: Map<String, Any?>) { registry.revoke(input) }
            override fun unrevoke(key: Map<String, Any?>): Boolean = registry.unrevoke(key)
            override fun lookup(kind: String, value: String): Any? = registry.lookup(kind, value)
        }

        /** {kind: 'cap', value: id}. */
        @JvmStatic
        fun capKey(id: String): MutableMap<String, Any?> = linkedMapOf("kind" to "cap", "value" to id)
    }
}

/**
 * Key rotation and subtree revocation for capability chains. Every re-issue goes through the core builders ([Issue.mintRoot],
 * [Issue.delegate]); nothing here re-implements signing or hashing. Attenuation is preserved by construction: each re-issued hop
 * carries exactly the caveats the hop it replaces carried, so a re-issue never widens authority. Each function returns the new chain
 * together with a [RevocationRecord] for the old key or subtree.
 *
 * A chain whose hops lack a string id / issuer / holder or a caveats list is refused (the reference passes such hops through untouched).
 */
object Rotate {
    /** The new chain plus the revocation record for the old key(s). */
    class RotationResult internal constructor(val chain: List<Map<String, Any?>>, val revocation: RevocationRecord)

    /** The result of [compromisedKeyFlow]. */
    class CompromisedFlow internal constructor(val revocations: List<RevocationRecord>, val reissued: List<Map<String, Any?>>)

    private fun pub(secret: Keys.EdKey?): String = secret?.id() ?: throw JsTypeError("expected a secret key")

    @Suppress("UNCHECKED_CAST")
    private fun chainOf(chain: Any?, ctx: String): List<Map<String, Any?>> {
        if (chain !is List<*> || chain.isEmpty()) throw IllegalArgumentException("$ctx: empty chain")
        return chain.map { hop ->
            val h = hop as? Map<String, Any?> ?: throw JsTypeError("$ctx: malformed capability")
            if (!Js.nonEmptyString(h["id"]) || h["issuer"] !is String || h["holder"] !is String) throw JsTypeError("$ctx: a capability needs a string id, issuer and holder")
            if (h["caveats"] !is List<*>) throw JsTypeError("malformed capability: caveats must be arrays")
            h
        }
    }

    private fun Map<String, Any?>.s(k: String): String = this[k] as String

    private fun appendedCaveats(parent: Map<String, Any?>, child: Map<String, Any?>): List<Any?> {
        val pc = parent["caveats"] as List<*>
        val cc = child["caveats"] as List<*>
        if (cc.size < pc.size) throw IllegalArgumentException("malformed chain: a child carries fewer caveats than its parent (not an attenuation)")
        return ArrayList(cc.subList(pc.size, cc.size))
    }

    private fun checkNow(now: Double?, ctx: String) {
        if (now != null && (now.isNaN() || now.isInfinite())) throw JsTypeError("$ctx: now must be a finite number")
    }

    private fun at(now: Double?): Double = now ?: System.currentTimeMillis().toDouble()

    private fun delegate(parent: Map<String, Any?>, toHolder: String, added: List<Any?>, signer: Keys.EdKey) =
        Issue.delegate(parent, toHolder, added, Keys.ed25519(signer), null)

    /**
     * Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf delegation, re-binding it to [newKeyPair]'s public key while
     * preserving the leaf's exact caveats. [oldHolderSecret] re-signs the leaf hop, i.e. it is the leaf's issuer (the parent's holder
     * key); the call throws when it does not match. A root-only chain has no leaf delegation to re-issue: use [rotatePrincipalKey].
     */
    @JvmStatic
    fun rotateAgentKey(chainIn: Any?, oldHolderSecret: Keys.EdKey?, newKeyPair: Keys.EdKey?, reason: String? = null, now: Double? = null): RotationResult {
        val chain = chainOf(chainIn, "rotateAgentKey")
        if (chain.size < 2) throw IllegalArgumentException("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey")
        val parent = chain[chain.size - 2]
        val leaf = chain[chain.size - 1]
        val signerPub = pub(oldHolderSecret)
        if (signerPub != leaf.s("issuer")) {
            throw IllegalArgumentException(
                "rotateAgentKey: oldHolderSecret (pub $signerPub) is not the leaf's issuer ${leaf.s("issuer")}; the leaf is re-signed by its parent holder (the leaf issuer)",
            )
        }
        if (newKeyPair == null) throw JsTypeError("rotateAgentKey: newKeyPair is required")
        val newHolder = newKeyPair.id()
        if (newHolder == leaf.s("holder")) throw IllegalArgumentException("rotateAgentKey: newKeyPair is the key being rotated out")
        checkNow(now, "rotateAgentKey")
        val newChain = chain.dropLast(1) + delegate(parent, newHolder, appendedCaveats(parent, leaf), oldHolderSecret!!)
        return RotationResult(
            newChain,
            RevocationRecord(leaf.s("id"), leaf.s("holder"), leaf.s("issuer"), null, listOf(leaf.s("id")), reason ?: "agent key rotated", at(now)),
        )
    }

    /**
     * Rotate the PRINCIPAL (root) key by re-rooting: mint a fresh root under [newPrincipalKeyPair] bound to the same agent holder and
     * root caveats, then re-issue every downstream hop onto it (holders unchanged, so each hop is re-signed by the same issuer secret it
     * had; supply them in [holderSecrets], chain order, one per non-root hop). Pass the full chain, or a null chain and [oldRoot] for a
     * root-only chain. [oldPrincipalSecret] must be the current root's issuer.
     */
    @JvmStatic
    fun rotatePrincipalKey(
        chainIn: Any?,
        oldRoot: Any?,
        oldPrincipalSecret: Keys.EdKey?,
        newPrincipalKeyPair: Keys.EdKey?,
        holderSecrets: List<Keys.EdKey?>? = null,
        reason: String? = null,
        now: Double? = null,
    ): RotationResult {
        val chain = chainOf(chainIn ?: if (Js.truthy(oldRoot)) listOf(oldRoot) else emptyList<Any?>(), "rotatePrincipalKey")
        val root = chain[0]
        if (root.containsKey("parent")) throw IllegalArgumentException("rotatePrincipalKey: chain[0] is not a root (it has a parent)")
        val oldPub = pub(oldPrincipalSecret)
        if (oldPub != root.s("issuer")) throw IllegalArgumentException("rotatePrincipalKey: oldPrincipalSecret (pub $oldPub) is not the root's issuer ${root.s("issuer")}")
        val hs = holderSecrets ?: emptyList()
        if (hs.size != chain.size - 1) {
            throw IllegalArgumentException("rotatePrincipalKey: expected ${chain.size - 1} holderSecrets (one per non-root hop), got ${hs.size}")
        }
        if (newPrincipalKeyPair == null) throw JsTypeError("rotatePrincipalKey: newPrincipalKeyPair is required")
        if (newPrincipalKeyPair.id() == root.s("issuer")) throw IllegalArgumentException("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out")
        checkNow(now, "rotatePrincipalKey")
        val newChain = arrayListOf(Issue.mintRoot(Keys.ed25519(newPrincipalKeyPair), root.s("holder"), null, Js.list(root["caveats"])))
        for (i in 1 until chain.size) {
            val oldChild = chain[i]
            val signer = hs[i - 1]
            val signerPub = pub(signer)
            if (signerPub != oldChild.s("issuer")) {
                throw IllegalArgumentException("rotatePrincipalKey: holderSecret for hop $i (pub $signerPub) is not that hop's issuer ${oldChild.s("issuer")}")
            }
            newChain.add(delegate(newChain[i - 1], oldChild.s("holder"), appendedCaveats(chain[i - 1], oldChild), signer!!))
        }
        return RotationResult(
            newChain,
            RevocationRecord(root.s("id"), root.s("holder"), root.s("issuer"), root.s("id"), chain.map { it.s("id") }, reason ?: "principal key rotated (re-root)", at(now)),
        )
    }

    private fun indexOfHolder(chain: List<Map<String, Any?>>, holder: String?): Int = chain.indexOfFirst { it.s("holder") == holder }

    /**
     * Treat [compromisedHolder] as COMPROMISED: revoke the hop it first holds and every descendant, and re-issue a fresh chain from the
     * nearest safe ancestor (the hop just above) down to a brand-new key, carrying the caveats of the subtree's deepest leaf so the
     * re-issued authority is never wider. [ancestorSecret] must be the safe ancestor's holder secret. Throws when the holder is not in
     * the chain or is the root holder (rotate the root with [rotatePrincipalKey]).
     */
    @JvmStatic
    fun revokeAndReissueSubtree(chainIn: Any?, compromisedHolder: String?, newKeyPair: Keys.EdKey?, ancestorSecret: Keys.EdKey?, reason: String? = null, now: Double? = null): RotationResult {
        val chain = chainOf(chainIn, "revokeAndReissueSubtree")
        val idx = indexOfHolder(chain, compromisedHolder)
        if (idx < 0) throw IllegalArgumentException("revokeAndReissueSubtree: holder $compromisedHolder is not in the chain")
        if (idx == 0) {
            throw IllegalArgumentException("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey")
        }
        val ancestor = chain[idx - 1]
        val subtreeRoot = chain[idx]
        val leaf = chain[chain.size - 1]
        val ancestorPub = pub(ancestorSecret)
        if (ancestorPub != ancestor.s("holder")) {
            throw IllegalArgumentException("revokeAndReissueSubtree: ancestorSecret (pub $ancestorPub) is not the safe ancestor's holder ${ancestor.s("holder")}")
        }
        if (newKeyPair == null) throw JsTypeError("revokeAndReissueSubtree: newKeyPair is required")
        val newHolder = newKeyPair.id()
        val subtree = chain.subList(idx, chain.size)
        if (subtree.any { it.s("holder") == newHolder }) throw IllegalArgumentException("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree")
        checkNow(now, "revokeAndReissueSubtree")
        val reissued = chain.subList(0, idx) + delegate(ancestor, newHolder, appendedCaveats(ancestor, leaf), ancestorSecret!!)
        return RotationResult(
            reissued,
            RevocationRecord(subtreeRoot.s("id"), compromisedHolder, subtreeRoot.s("issuer"), subtreeRoot.s("id"), subtree.map { it.s("id") },
                reason ?: "delegation subtree compromised", at(now)),
        )
    }

    /**
     * Handle a compromised key end to end: one revocation record per capability in the compromised subtree (root to leaf, so a
     * registry can revoke each id) plus the re-issued chain from the nearest safe ancestor.
     */
    @JvmStatic
    fun compromisedKeyFlow(chainIn: Any?, compromisedHolder: String?, newKeyPair: Keys.EdKey?, ancestorSecret: Keys.EdKey?, reason: String? = null, now: Double? = null): CompromisedFlow {
        val chain = chainOf(chainIn, "compromisedKeyFlow")
        val idx = indexOfHolder(chain, compromisedHolder)
        if (idx < 0) throw IllegalArgumentException("compromisedKeyFlow: holder $compromisedHolder is not in the chain")
        val reissued = revokeAndReissueSubtree(chain, compromisedHolder, newKeyPair, ancestorSecret, reason, now).chain
        val rootId = chain[idx].s("id")
        val revokedAt = at(now)
        val why = reason ?: "delegation subtree compromised"
        val revocations = chain.subList(idx, chain.size).map { c ->
            RevocationRecord(c.s("id"), c.s("holder"), c.s("issuer"), rootId, listOf(c.s("id")), why, revokedAt)
        }
        return CompromisedFlow(revocations, reissued)
    }

    /**
     * Revoke what a rotation replaced, all or nothing. Every capability id the record(s) cover is revoked in [sink]; if any revoke
     * throws, the ones this call added are removed again and the error is rethrown, so a failed rotation never leaves the old chain half
     * revoked. It revokes capability ids only (not the holder / issuer keys). It refuses, before touching the sink, a record that names
     * no capability id and a re-issued chain that shares an id with what is being revoked. [records] is one record or a list of them
     * (each a JSON object, as [RevocationRecord.toMap]); [reissued] may be null.
     */
    @JvmStatic
    fun applyRotation(sink: RevocationSink, records: Any?, reissued: Any?): List<String> {
        val list = records as? List<*> ?: listOf(records)
        val todo = LinkedHashMap<String, Any?>()
        for (r in list) {
            val capIds = Js.member(r, "capIds")
            val ids: List<*> = when {
                // `r.capIds ?? ...` then iterating: anything that is not a list cannot be iterated as ids
                capIds != null -> capIds as? List<*> ?: throw JsTypeError("applyRotation: a record names an invalid capability id")
                Js.own(r, "capId") -> listOf(Js.member(r, "capId"))
                else -> emptyList<Any?>()
            }
            for (id in ids) {
                if (id !is String || id.isEmpty()) throw JsTypeError("applyRotation: a record names an invalid capability id")
                if (id !in todo) todo[id] = r
            }
        }
        if (todo.isEmpty()) throw IllegalArgumentException("applyRotation: the record names no capability to revoke")
        val kept = HashSet<Any?>()
        if (reissued != null) {
            if (reissued !is List<*>) throw JsTypeError("applyRotation: reissued must be a list")
            for (c in reissued) kept.add(Js.member(c, "id"))
        }
        if (todo.keys.any { it in kept }) throw IllegalArgumentException("applyRotation: the re-issued chain contains a capability that is being revoked")
        val added = ArrayList<String>()
        try {
            for ((id, r) in todo) {
                if (sink.lookup("cap", id) == null) added.add(id)
                val inp = RevocationSink.capKey(id)
                if (Js.own(r, "reason")) inp["reason"] = Js.member(r, "reason")
                if (Js.own(r, "revokedAt")) inp["revokedAt"] = Js.member(r, "revokedAt")
                sink.revoke(inp)
            }
        } catch (e: RuntimeException) {
            for (id in added) {
                try { sink.unrevoke(RevocationSink.capKey(id)) } catch (ignored: RuntimeException) { /* best effort: the original failure is the one to report */ }
            }
            throw e
        }
        return ArrayList(todo.keys)
    }

    /** Typed form of [applyRotation]. */
    @JvmStatic
    fun applyRotation(sink: RevocationSink, records: List<RevocationRecord>, reissued: List<Map<String, Any?>>?): List<String> =
        applyRotation(sink, records.map { it.toMap() } as Any?, reissued as Any?)
}
