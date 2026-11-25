package net.atlasauth.pca.revoke

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError

/**
 * A stored revocation. [kind] is cap / holder / issuer / prefix; [value] is the canonical key (for prefix the comma-joined path);
 * [notBefore] (epoch ms) is the time before which the revocation does not yet bite. [revokedAt] is metadata only.
 */
class RevocationEntry(
    val kind: String,
    val value: String,
    prefix: List<String>?,
    val reason: String,
    val revokedAt: Double,
    val notBefore: Double?,
) {
    /** For kind prefix only: the ordered cap-id path. */
    val prefix: List<String>? = prefix?.toList()

    /** The JSON form (the reference's entry object). */
    fun toMap(): Map<String, Any?> = linkedMapOf<String, Any?>().apply {
        put("kind", kind)
        put("value", value)
        if (prefix != null) put("prefix", ArrayList<Any?>(prefix))
        put("reason", reason)
        put("revokedAt", Js.jsNum(revokedAt))
        if (notBefore != null) put("notBefore", Js.jsNum(notBefore))
    }
}

/**
 * The pluggable backing store for a [RevocationRegistry]. Point kinds are addressed by (kind, value); prefix entries are scanned via
 * [all]. Implementations must be thread-safe: after [add] returns, every reader sees the entry.
 */
interface RevocationStore {
    /** Insert or replace the entry at its (kind, value) key. */
    fun add(entry: RevocationEntry)

    /** Remove the entry at (kind, value); true when something was removed. */
    fun remove(kind: String, value: String): Boolean

    fun get(kind: String, value: String): RevocationEntry?

    /** Every stored entry (a snapshot copy). */
    fun all(): List<RevocationEntry>

    fun clear()
}

/** In-memory [RevocationStore] (the default). Single process; swap in a shared store for a fleet. */
class InMemoryRevocationStore : RevocationStore {
    private val entries = LinkedHashMap<String, RevocationEntry>()

    @Synchronized override fun add(entry: RevocationEntry) { entries[key(entry.kind, entry.value)] = entry }
    @Synchronized override fun remove(kind: String, value: String): Boolean = entries.remove(key(kind, value)) != null
    @Synchronized override fun get(kind: String, value: String): RevocationEntry? = entries[key(kind, value)]
    @Synchronized override fun all(): List<RevocationEntry> = ArrayList(entries.values)
    @Synchronized override fun clear() = entries.clear()

    internal companion object {
        fun key(kind: String, value: String): String = kind + "\u0000" + value
    }
}

/**
 * A live, mutable registry of revocations keyed by capability id, agent holder key, issuer key, or delegation-subtree prefix. A
 * resource server holds one and consults [Revoke.checkRevocation] / [Revoke.verifyWithRevocation] on every action.
 *
 * Inputs are JSON objects, as the reference takes them: {kind, value | prefix, reason?, revokedAt?, notBefore?}.
 */
class RevocationRegistry @JvmOverloads constructor(private val store: RevocationStore = InMemoryRevocationStore()) {
    /** Revoke a capability id, holder key, issuer key, or subtree prefix. Throws [JsTypeError] on a malformed input. */
    fun revoke(input: Map<String, Any?>?): RevocationEntry {
        val ra = Js.member(input, "revokedAt")
        val revokedAt = when {
            ra == null -> System.currentTimeMillis().toDouble()
            !Js.isFinite(ra) -> throw JsTypeError("revoke: revokedAt must be a finite number")
            else -> Js.num(ra)!!
        }
        val inp = input!!
        var notBefore: Double? = null
        if (Js.own(inp, "notBefore")) {
            val nb = inp["notBefore"]
            if (!Js.isFinite(nb)) throw JsTypeError("revoke: notBefore must be a finite number")
            notBefore = Js.num(nb)
        }
        val reason = inp["reason"] ?: ""
        if (reason !is String) throw JsTypeError("revoke: reason must be a string")
        val kind = inp["kind"]
        val entry = if (kind == "prefix") {
            val p = inp["prefix"]
            if (p !is List<*> || p.isEmpty()) throw JsTypeError("revoke: a prefix revocation requires a non-empty cap-id path")
            val path = p.map { id ->
                // The path is serialized with ',' as separator: an element holding one would alias a different path.
                if (!Js.nonEmptyString(id) || (id as String).contains(PREFIX_SEP)) throw JsTypeError("revoke: every prefix element must be a non-empty string without ','")
                id
            }
            RevocationEntry("prefix", serializePrefix(path), path, reason, revokedAt, notBefore)
        } else {
            // Stricter than the reference, which stores any kind: a kind that is not a string is refused.
            if (kind !is String) throw JsTypeError("revoke: kind must be a string")
            val v = inp["value"]
            if (!Js.nonEmptyString(v)) throw JsTypeError("revoke: a $kind revocation requires a non-empty value")
            RevocationEntry(kind, v as String, null, reason, revokedAt, notBefore)
        }
        store.add(entry)
        return entry
    }

    /**
     * Revoke an entire delegation subtree: a root cap id (String) revokes every chain through that capability; a chain prefix (List of
     * cap ids) revokes every chain whose hops begin with that path. opts: reason, revokedAt, notBefore.
     */
    fun revokeSubtree(target: Any?, opts: Map<String, Any?>?): RevocationEntry {
        val inp = LinkedHashMap<String, Any?>()
        if (target is List<*>) { inp["kind"] = "prefix"; inp["prefix"] = target } else { inp["kind"] = "cap"; inp["value"] = target }
        if (opts != null) inp.putAll(opts)
        return revoke(inp)
    }

    /** Remove a revocation. key: {kind, value} or {kind: 'prefix', prefix}. True when one was removed. */
    fun unrevoke(key: Map<String, Any?>?): Boolean {
        if (Js.member(key, "kind") == "prefix") {
            val p = key!!["prefix"]
            if (p !is List<*> || p.isEmpty()) return false
            return store.remove("prefix", serializePrefix(p))
        }
        return store.remove(strMember(key, "kind"), strMember(key, "value"))
    }

    /** Every active-or-scheduled revocation (a snapshot). */
    fun list(): List<RevocationEntry> = store.all()

    /** Point lookup of a cap / holder / issuer revocation. */
    fun lookup(kind: String, value: String): RevocationEntry? = store.get(kind, value)

    /** Every subtree-prefix revocation. */
    fun prefixes(): List<RevocationEntry> = store.all().filter { it.kind == "prefix" }

    fun clear() = store.clear()

    /** KILL-SWITCH: instantly revoke an agent by its holder key; denies every in-flight action by it. */
    fun killAgent(holder: Any?, opts: Map<String, Any?>?): RevocationEntry = kill("holder", holder, opts, "kill-switch: agent killed")

    /** KILL-SWITCH: instantly revoke an entire delegation subtree rooted at a cap id. */
    fun killSubtree(rootCapId: Any?, opts: Map<String, Any?>?): RevocationEntry = kill("cap", rootCapId, opts, "kill-switch: subtree killed")

    private fun kill(kind: String, value: Any?, opts: Map<String, Any?>?, dflt: String): RevocationEntry {
        val inp = linkedMapOf<String, Any?>("kind" to kind, "value" to value, "reason" to (opts?.get("reason") ?: dflt))
        if (opts != null && opts.containsKey("revokedAt")) inp["revokedAt"] = opts["revokedAt"]
        return revoke(inp)
    }

    private companion object {
        const val PREFIX_SEP = ","

        fun serializePrefix(prefix: List<*>): String = Js.join(prefix, PREFIX_SEP)

        /** `${o[k]}`: an absent member prints "undefined". */
        fun strMember(o: Map<String, Any?>?, k: String): String = if (Js.own(o, k)) Js.template(o!![k]) else "undefined"
    }
}

/**
 * Realtime revocation and a mid-run kill-switch, layered on the core verifier. [checkRevocation] walks every hop of a PCActn's
 * cap_chain against a [RevocationRegistry]; [verifyWithRevocation] ANDs the core outcome with that gate and fails closed;
 * [ingestCaepEvent] bridges a Shared-Signals / CAEP revocation event into registry entries.
 */
object Revoke {
    /** CAEP 1.0 section 3.4: a session for the subject was revoked. */
    const val SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    /** A single grant (by grant_ref, the root grant's cap id) is revoked. */
    const val GRANT_REVOKED = "https://atlasauth.net/caep/grant-revoked"
    /** A mid-run kill-switch that revokes every grant the named agent holds. */
    const val KILL_SWITCH = "https://atlasauth.net/caep/kill-switch"

    /** The outcome of a revocation check; [matched] and [reason] are set only when revoked. */
    class IsRevokedResult(val revoked: Boolean, val matched: RevocationEntry?, val reason: String?) {
        fun toMap(): Map<String, Any?> = linkedMapOf<String, Any?>("revoked" to revoked).apply {
            if (matched != null) put("matched", matched.toMap())
            if (reason != null) put("reason", reason)
        }
    }

    /** The combined outcome; [allow] is true only when the core verified and nothing in the chain is revoked. */
    class VerifyWithRevocationResult(val allow: Boolean, val coreAllow: Boolean, val revocation: IsRevokedResult, val reason: Any?) {
        fun toMap(): Map<String, Any?> = linkedMapOf<String, Any?>("allow" to allow, "coreAllow" to coreAllow, "revocation" to revocation.toMap()).apply {
            if (!allow) put("reason", reason)
        }
    }

    /** True when a revocation is in effect at [now] (a future notBefore has not yet been reached). Non-finite clocks bite. */
    @JvmStatic
    fun isActiveAt(entry: RevocationEntry, now: Double): Boolean {
        val nb = entry.notBefore ?: return true
        if (now.isNaN() || now.isInfinite() || nb.isNaN() || nb.isInfinite()) return true
        return now >= nb
    }

    private fun matchReason(e: RevocationEntry): String {
        val base = "${e.kind} ${e.value} is revoked"
        return if (e.reason.isNotEmpty()) "$base: ${e.reason}" else base
    }

    private fun startsWith(ids: List<String>, prefix: List<String>): Boolean =
        prefix.isNotEmpty() && ids.size >= prefix.size && prefix.indices.all { ids[it] == prefix[it] }

    private fun closed(why: String) = IsRevokedResult(true, null, "revocation check failed closed: $why")

    private val HOP_KEYS = listOf("id", "issuer", "holder")
    private val HOP_KINDS = listOf("cap", "issuer", "holder")

    private fun scan(chain: List<*>, registry: RevocationRegistry, now: Double): IsRevokedResult {
        val ids = ArrayList<String>()
        for (hop in chain) {
            val h = hop as Map<*, *>
            for (i in 0 until 3) {
                val k = h[HOP_KEYS[i]]
                if (!Js.nonEmptyString(k)) continue
                val e = registry.lookup(HOP_KINDS[i], k as String)
                if (e != null && isActiveAt(e, now)) return IsRevokedResult(true, e, matchReason(e))
            }
            (h["id"] as? String)?.let { ids.add(it) }
        }
        for (e in registry.prefixes()) {
            if (e.prefix != null && startsWith(ids, e.prefix) && isActiveAt(e, now)) return IsRevokedResult(true, e, matchReason(e))
        }
        return IsRevokedResult(false, null, null)
    }

    /**
     * Is any authority in this PCActn's cap_chain revoked at opts.now (default: the clock)? Never throws and never reports "not
     * revoked" because it could not look: a missing or malformed cap_chain, a hop whose id, issuer or holder is not a non-empty
     * string, a non-finite now, or a store that throws all yield revoked with a reason that starts "revocation check failed closed".
     */
    @JvmStatic
    fun checkRevocation(p: Any?, registry: RevocationRegistry, opts: Map<String, Any?>?): IsRevokedResult {
        val nowO = opts?.get("now")
        val now = when {
            nowO == null -> System.currentTimeMillis().toDouble()
            !Js.isFinite(nowO) -> return closed("clock is not a finite number")
            else -> Js.num(nowO)!!
        }
        val chain = Js.get(p, "cap_chain")
        if (chain !is List<*> || chain.isEmpty()) return closed("the action carries no capability chain")
        for (hop in chain) for (k in HOP_KEYS) if (!Js.nonEmptyString(Js.get(hop, k))) return closed("a chain hop has no $k")
        return try {
            scan(chain, registry, now)
        } catch (e: RuntimeException) {
            closed("the revocation store failed (" + (if (e is JsTypeError) "TypeError" else "Error") + ")")
        }
    }

    /**
     * Combine the core verify outcome with the revocation gate: allow only if the core verified and nothing in the chain is revoked;
     * a core result that did not allow denies regardless of the registry, and any match denies regardless of the core.
     */
    @JvmStatic
    fun verifyWithRevocation(p: Any?, coreVerifyResult: Any?, registry: RevocationRegistry, opts: Map<String, Any?>?): VerifyWithRevocationResult {
        val coreAllow = (coreVerifyResult as? Map<*, *>)?.get("allow") == true
        val revocation = checkRevocation(p, registry, opts)
        if (coreAllow && !revocation.revoked) return VerifyWithRevocationResult(true, true, revocation, null)
        val reason: Any? = if (!coreAllow) Js.get(coreVerifyResult, "reason") ?: "core verification failed" else revocation.reason ?: "revoked"
        return VerifyWithRevocationResult(false, coreAllow, revocation, reason)
    }

    private fun revokedAtFrom(ts: Any?): Double =
        if (Js.isFinite(ts)) Js.round(Js.num(ts)!! * 1000) else System.currentTimeMillis().toDouble()

    private fun stringField(ev: Any?, subject: Any?, key: String): String? {
        if (!Js.own(ev, "subject")) return null
        return (Js.member(subject, key) as? String)?.takeIf { it.isNotEmpty() }
    }

    private fun cap(value: Any?, reason: Any?, revokedAt: Double) =
        linkedMapOf<String, Any?>("kind" to "cap", "value" to value, "reason" to reason, "revokedAt" to Js.jsNum(revokedAt))

    private fun at(reason: Any?, revokedAt: Double) = linkedMapOf<String, Any?>("reason" to reason, "revokedAt" to Js.jsNum(revokedAt))

    /**
     * Bridge a CAEP / PCA revocation event ({type, payload}) into registry entries; returns the entries added. grant-revoked revokes
     * the grant's cap id (the whole subtree under it); kill-switch kills the agent's holder key (and the named grant_ref too); any
     * other type is read as session-revoked: when the subject carries a holder / agent / id key, that agent is killed.
     */
    @JvmStatic
    fun ingestCaepEvent(event: Any?, registry: RevocationRegistry): List<RevocationEntry> {
        val added = ArrayList<RevocationEntry>()
        val type = Js.member(event, "type")
        val ev = Js.member(event, "payload")
        when (type) {
            GRANT_REVOKED -> {
                val ref = Js.member(ev, "grant_ref")
                if (Js.nonEmptyString(ref)) {
                    added.add(registry.revoke(cap(ref, Js.get(ev, "reason") ?: "CAEP grant-revoked", revokedAtFrom(Js.get(ev, "event_timestamp")))))
                }
            }
            KILL_SWITCH -> {
                val revokedAt = revokedAtFrom(Js.member(ev, "event_timestamp"))
                val agent = Js.get(ev, "agent")
                val reason = Js.get(ev, "reason") ?: "CAEP kill-switch"
                if (Js.nonEmptyString(agent)) added.add(registry.killAgent(agent, at(reason, revokedAt)))
                val ref = Js.get(ev, "grant_ref")
                if (Js.nonEmptyString(ref)) added.add(registry.revoke(cap(ref, reason, revokedAt)))
            }
            else -> {
                val subject = Js.member(ev, "subject")
                val holder = stringField(ev, subject, "holder") ?: stringField(ev, subject, "agent") ?: stringField(ev, subject, "id")
                if (holder != null) {
                    val reason = Js.get(ev, "reason_admin") ?: Js.get(ev, "reason_user") ?: "CAEP session-revoked"
                    added.add(registry.killAgent(holder, at(reason, revokedAtFrom(Js.get(ev, "event_timestamp")))))
                }
            }
        }
        return added
    }
}
