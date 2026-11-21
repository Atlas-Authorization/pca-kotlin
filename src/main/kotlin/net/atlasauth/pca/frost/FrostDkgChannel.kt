package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/** Every channel and driver refusal. `peer` is the authenticated party the refusal is about, when known; `code` is one of the [FrostDkgChannel] codes. */
class DkgChannelError(val code: String, val peer: Long?, message: String) : RuntimeException("dkg channel ($code${if (peer == null) "" else ", peer $peer"}): $message") {
    /** The message without the `dkg channel (code, peer n): ` prefix. */
    val detail: String get() = message!!.replace(Regex("^dkg channel \\([^)]*\\): "), "")
}

/** One participant's end of the authenticated channel. Every call may block; a refusal is a [DkgChannelError]. */
interface DkgChannel {
    val self: Long

    /** Every other participant this channel is connected to, ascending. */
    val peers: List<Long>

    /** Authenticated broadcast of `body` to every peer. */
    fun broadcast(kind: String, body: Any?)

    /** Private, authenticated delivery of `body` to one peer. */
    fun send(to: Long, kind: String, body: Any?)

    /**
     * Wait for exactly one `kind` message from each of `from` and return the bodies keyed by the AUTHENTICATED sender. Throws [DkgChannelError] on timeout, a duplicate
     * or divergent second message, a malformed, oversize or wrong-session message from any of `from`, or a closed channel.
     */
    fun collect(kind: String, from: List<Long>, timeoutMs: Double): Map<Long, Any?>

    fun close()
}

/**
 * The authenticated-channel interface of the FROST DKG. [FrostDkg] produces and verifies the protocol messages but assumes an authenticated broadcast and
 * private authenticated point-to-point links; this states that assumption as an interface and enforces what the protocol can enforce on top of it. The CHANNEL
 * supplies the sender's identity (for TLS, the pinned certificate); the message never does, so every driver check compares the channel-authenticated sender with
 * the identifier inside the message. A message names one session; a second message of the same kind from the same sender is refused (identical: `duplicate`,
 * different: `equivocation`) and the refusal is sticky for that peer; every message is size-capped before it is parsed, parsed with the strict JSON profile and
 * shape-checked with exact member sets; a missing message at the timeout aborts the run; transcript equivocation is caught by the echo round, which the driver
 * always runs. What the channel must provide, and the interface cannot check: confidentiality and integrity of every message, and that `collect` reports a message
 * under the identity of the party that really sent it. [createMemoryDkgNetwork] is the in-process reference; [FrostDkgTls] has the framing of the mutual-TLS one.
 */
@Suppress("UNCHECKED_CAST")
object FrostDkgChannel {
    const val DKG_WIRE_VERSION = 1

    /** The largest wire message a channel accepts, checked before parsing. */
    const val DKG_MAX_MESSAGE_BYTES = 256 * 1024

    /** The largest participant set the driver accepts. */
    const val DKG_MAX_PARTICIPANTS = 256
    @JvmField val DKG_MESSAGE_KINDS: List<String> = listOf("round1", "share", "complaints", "rebuttals", "echo")

    // ---- JSON.stringify ----

    private fun quote(s: String): String {
        val b = StringBuilder("\"")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> b.append("\\\"")
                c == '\\' -> b.append("\\\\")
                c == '\b' -> b.append("\\b")
                c == '\u000c' -> b.append("\\f")
                c == '\n' -> b.append("\\n")
                c == '\r' -> b.append("\\r")
                c == '\t' -> b.append("\\t")
                c.code < 0x20 -> b.append("\\u").append("%04x".format(c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { b.append(c).append(s[i + 1]); i++ }
                Character.isSurrogate(c) -> b.append("\\u").append("%04x".format(c.code)) // a lone surrogate is escaped, as JSON.stringify writes it
                else -> b.append(c)
            }
            i++
        }
        return b.append('"').toString()
    }

    /** `JSON.stringify` of a decoded JSON tree: members in the order given (integer-like keys first, as an object enumerates them), numbers as JavaScript prints them. */
    @JvmStatic
    fun stringify(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is String -> quote(v)
        is List<*> -> v.joinToString(",", "[", "]") { stringify(it) }
        is Map<*, *> -> IntentJs.jsKeys(v).joinToString(",", "{", "}") { quote(it) + ":" + stringify(v[it]) }
        else -> {
            val d = IntentJs.num(v) ?: throw IllegalArgumentException("not a JSON value")
            if (d.isNaN() || d.isInfinite()) "null" else if (d == 0.0) "0" else Json.esNumber(d)
        }
    }

    // ---- wire envelope ----

    /** Encode one wire message: `JSON.stringify({v, sid, kind, body})` in that member order. `kind` is not checked here. Throws `oversize` over the cap. */
    @JvmStatic
    fun encodeDkgMessage(sessionId: ByteArray, kind: Any?, body: Any?): ByteArray {
        val bytes = Json.utf8(stringify(linkedMapOf("v" to IntentJs.ofLong(DKG_WIRE_VERSION.toLong()), "sid" to Keys.b64u(sessionId), "kind" to kind, "body" to body)))
        if (bytes.size > DKG_MAX_MESSAGE_BYTES) throw DkgChannelError("oversize", null, "message of ${bytes.size} bytes exceeds the cap")
        return bytes
    }

    private fun malformed(msg: String): DkgChannelError = DkgChannelError("malformed", null, msg)

    private fun asRecord(x: Any?, keys: List<String>, what: String): Map<String, Any?> {
        if (x !is Map<*, *>) throw malformed("$what is not an object")
        if (x.size != keys.size || !keys.all { x.containsKey(it) }) throw malformed("$what has unexpected or missing members")
        return x as Map<String, Any?>
    }

    private fun posInt(x: Any?, what: String): Any? {
        if (!IntentJs.isSafeInteger(x) || IntentJs.num(x)!! <= 0) throw malformed("$what is not a positive integer")
        return x
    }

    private fun b64Field(x: Any?, what: String, len: Int = -1): String {
        if (Pca.decodeB64uStrict(x, len) == null) throw malformed("$what is not canonical base64url")
        return x as String
    }

    /** Strictly decode one wire message for `sessionId`: `{kind, body}`. A typed [DkgChannelError] on every deviation (`malformed`, `oversize`, `wrong-session`). */
    @JvmStatic
    fun decodeDkgMessage(bytes: ByteArray, sessionId: ByteArray?): Pair<String, Any?> {
        if (bytes.size > DKG_MAX_MESSAGE_BYTES) throw DkgChannelError("oversize", null, "message of ${bytes.size} bytes exceeds the cap")
        val msg = try {
            Json.parseBytes(bytes)
        } catch (e: RuntimeException) {
            throw malformed("message is not strict JSON")
        }
        val o = asRecord(msg, listOf("v", "sid", "kind", "body"), "envelope")
        if (IntentJs.num(o["v"]) != DKG_WIRE_VERSION.toDouble()) throw malformed("unsupported wire version")
        val kind = o["kind"]
        if (kind !is String || kind !in DKG_MESSAGE_KINDS) throw malformed("unknown message kind")
        if (o["sid"] != Keys.b64u(sessionId ?: throw IllegalArgumentException("sessionId"))) throw DkgChannelError("wrong-session", null, "message names another session")
        return Pair(kind, o["body"])
    }

    // ---- message-body decoders ----

    /** Decode a round-1 package body; `t` is the threshold the package must commit to. */
    @JvmStatic
    fun decodeDkgRound1Package(x: Any?, t: Any?): Map<String, Any?> {
        val o = asRecord(x, listOf("identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"), "round-1 package")
        val pok = asRecord(o["proofOfKnowledge"], listOf("R", "mu"), "proof of knowledge")
        val cc = o["coefficientCommitments"]
        if (cc !is List<*> || IntentJs.num(t) != cc.size.toDouble()) throw malformed("round-1 package must commit to exactly t=${net.atlasauth.pca.verifier.ZkJs.string(t)} coefficients")
        return linkedMapOf(
            "identifier" to posInt(o["identifier"], "identifier"), "sessionId" to b64Field(o["sessionId"], "sessionId"),
            "coefficientCommitments" to cc.map { b64Field(it, "coefficient commitment", 32) },
            "proofOfKnowledge" to linkedMapOf("R" to b64Field(pok["R"], "PoP R", 32), "mu" to b64Field(pok["mu"], "PoP mu", 32)),
        )
    }

    /** Decode a private share body `{from, to, sessionId, share, sig}`; `share` is returned as bytes. */
    @JvmStatic
    fun decodeDkgShareMessage(x: Any?): Map<String, Any?> {
        val o = asRecord(x, listOf("from", "to", "sessionId", "share", "sig"), "share message")
        return linkedMapOf(
            "from" to posInt(o["from"], "from"), "to" to posInt(o["to"], "to"), "sessionId" to b64Field(o["sessionId"], "sessionId"),
            "share" to Pca.decodeB64uStrict(b64Field(o["share"], "share", 32), -1), "sig" to b64Field(o["sig"], "share signature", 64),
        )
    }

    private fun complaintOf(x: Any?): Map<String, Any?> {
        val o = asRecord(x, listOf("accused", "accuser", "sessionId", "revealedShare", "shareSig"), "complaint")
        return linkedMapOf(
            "accused" to posInt(o["accused"], "accused"), "accuser" to posInt(o["accuser"], "accuser"), "sessionId" to b64Field(o["sessionId"], "sessionId"),
            "revealedShare" to b64Field(o["revealedShare"], "revealed share", 32), "shareSig" to b64Field(o["shareSig"], "share signature", 64),
        )
    }

    private fun rebuttalOf(x: Any?): Map<String, Any?> {
        val o = asRecord(x, listOf("accused", "accuser", "sessionId", "presentedShare", "shareSig"), "rebuttal")
        return linkedMapOf(
            "accused" to posInt(o["accused"], "accused"), "accuser" to posInt(o["accuser"], "accuser"), "sessionId" to b64Field(o["sessionId"], "sessionId"),
            "presentedShare" to b64Field(o["presentedShare"], "presented share", 32), "shareSig" to b64Field(o["shareSig"], "share signature", 64),
        )
    }

    private fun listField(x: Any?, key: String, one: (Any?) -> Map<String, Any?>): List<Map<String, Any?>> {
        val o = asRecord(x, listOf(key), key)
        val l = o[key]
        if (l !is List<*> || l.size > DKG_MAX_PARTICIPANTS) throw malformed("$key is not a bounded list")
        return l.map(one)
    }

    /** Decode a complaints body `{complaints: [...]}`, possibly empty. */
    @JvmStatic fun decodeDkgComplaints(x: Any?): List<Map<String, Any?>> = listField(x, "complaints") { complaintOf(it) }

    /** Decode a rebuttals body `{rebuttals: [...]}`, possibly empty. */
    @JvmStatic fun decodeDkgRebuttals(x: Any?): List<Map<String, Any?>> = listField(x, "rebuttals") { rebuttalOf(it) }

    /** Decode an echo body `{identifier, sessionId, transcriptDigest}`. */
    @JvmStatic
    fun decodeDkgEcho(x: Any?): Map<String, Any?> {
        val o = asRecord(x, listOf("identifier", "sessionId", "transcriptDigest"), "echo")
        return linkedMapOf("identifier" to posInt(o["identifier"], "identifier"), "sessionId" to b64Field(o["sessionId"], "sessionId"), "transcriptDigest" to b64Field(o["transcriptDigest"], "transcript digest", 32))
    }

    // ---- the shared inbox ----

    /**
     * The receive side shared by every channel implementation: at most one message per (kind, authenticated sender), a sticky error per peer, and `collect`. A
     * channel calls [accept] with the AUTHENTICATED sender.
     */
    class DkgInbox(val sessionId: ByteArray, val peers: List<Long>) {
        private val lock = Object()
        private val seen = HashMap<String, Pair<String, Any?>>()
        private val errors = HashMap<Long, DkgChannelError>()
        private val gone = HashSet<Long>()
        private var closed = false

        /** Record a peer failure (the first one wins). */
        fun fail(peer: Long, err: DkgChannelError) {
            synchronized(lock) {
                if (!errors.containsKey(peer)) errors[peer] = DkgChannelError(err.code, peer, err.detail)
                lock.notifyAll()
            }
        }

        /** Accept one wire message from the authenticated `sender`. Never throws: a bad message becomes a sticky peer error. */
        fun accept(sender: Long, bytes: ByteArray) {
            if (sender !in peers) return // not a participant: nothing to attribute to
            try {
                val (kind, body) = decodeDkgMessage(bytes, sessionId)
                val key = "$kind\u0000$sender"
                val digest = Keys.b64u(bytes)
                synchronized(lock) {
                    val prev = seen[key]
                    if (prev != null) throw DkgChannelError(if (prev.first == digest) "duplicate" else "equivocation", sender, "second $kind message")
                    seen[key] = Pair(digest, body)
                    lock.notifyAll()
                }
            } catch (e: DkgChannelError) {
                fail(sender, e)
            } catch (e: RuntimeException) {
                fail(sender, DkgChannelError("malformed", sender, "undecodable message"))
            }
        }

        /** The link to `peer` ended. Soft: it only matters if a message that peer owed is still missing. */
        fun peerGone(peer: Long) {
            synchronized(lock) {
                gone.add(peer)
                lock.notifyAll()
            }
        }

        fun close() {
            synchronized(lock) {
                closed = true
                lock.notifyAll()
            }
        }

        /** [DkgChannel.collect] over this inbox. */
        fun collect(kind: String, from: List<Long>, timeoutMs: Double): Map<Long, Any?> {
            val want = from.sorted()
            // a timeout that is not a finite number is already past (a NaN or infinite one would wait without end)
            val deadline = System.nanoTime() + (if (timeoutMs.isFinite() && timeoutMs >= 0) (timeoutMs * 1_000_000.0).toLong() else 0L)
            synchronized(lock) {
                while (true) {
                    for (id in want) errors[id]?.let { throw it }
                    val out = LinkedHashMap<Long, Any?>()
                    for (id in want) seen["$kind\u0000$id"]?.let { out[id] = it.second }
                    if (out.size == want.size) return out
                    if (closed) throw DkgChannelError("closed", null, "channel closed before all messages arrived")
                    val g = want.firstOrNull { !out.containsKey(it) && gone.contains(it) }
                    if (g != null) throw DkgChannelError("closed", g, "link ended before its $kind message arrived")
                    val leftNs = deadline - System.nanoTime()
                    if (leftNs <= 0) {
                        val missing = want.filter { !out.containsKey(it) }
                        throw DkgChannelError("timeout", missing[0], "no $kind message from ${missing.joinToString(",")}")
                    }
                    lock.wait(leftNs / 1_000_000, (leftNs % 1_000_000).toInt())
                }
            }
            @Suppress("UNREACHABLE_CODE") throw IllegalStateException()
        }
    }

    // ---- the in-memory reference network ----

    class MemoryDkgNetwork internal constructor(val channels: Map<Long, DkgChannel>, private val inboxes: Map<Long, DkgInbox>) {
        /** Adversary hook: deliver raw `bytes` to `to` as if sent by `from` (the adversary controls `from`'s link). */
        fun deliver(from: Long, to: Long, bytes: ByteArray) {
            inboxes[to]?.accept(from, bytes)
        }
    }

    /**
     * The in-process reference network. `intercept` sees every delivery `(from, to, kind, bytes)` and returns the bytes to deliver, or null to drop it, so a test
     * models a network or a corrupted peer without any private API.
     */
    @JvmStatic @JvmOverloads
    fun createMemoryDkgNetwork(ids: List<Long>, sessionId: ByteArray, intercept: ((Long, Long, String, ByteArray) -> ByteArray?)? = null): MemoryDkgNetwork {
        val sorted = ids.sorted()
        val inboxes = LinkedHashMap<Long, DkgInbox>()
        for (id in sorted) inboxes[id] = DkgInbox(sessionId, sorted.filter { it != id })
        val net = arrayOfNulls<MemoryDkgNetwork>(1)
        val channels = LinkedHashMap<Long, DkgChannel>()
        for (selfId in sorted) {
            val peerList = sorted.filter { it != selfId }
            fun route(to: Long, kind: String, body: Any?) {
                val bytes = encodeDkgMessage(sessionId, kind, body)
                val out = if (intercept != null) intercept(selfId, to, kind, bytes) else bytes
                if (out != null) net[0]!!.deliver(selfId, to, out)
            }
            channels[selfId] = object : DkgChannel {
                override val self: Long = selfId
                override val peers: List<Long> = peerList
                override fun broadcast(kind: String, body: Any?) { for (p in peerList) route(p, kind, body) }
                override fun send(to: Long, kind: String, body: Any?) {
                    if (to !in peerList) throw DkgChannelError("identity", to, "not a connected peer")
                    route(to, kind, body)
                }
                override fun collect(kind: String, from: List<Long>, timeoutMs: Double): Map<Long, Any?> = inboxes.getValue(selfId).collect(kind, from, timeoutMs)
                override fun close() { inboxes.getValue(selfId).close() }
            }
        }
        net[0] = MemoryDkgNetwork(channels, inboxes)
        return net[0]!!
    }

    // ---- the driver ----

    /** One participant's result: its key package, the qualified set and the complaints of the run. */
    class RunDkgResult(val keyPackage: Map<String, Any?>, val qualified: List<Any?>, val complaints: List<Map<String, Any?>>)

    private fun bind(peer: Long, f: () -> Any?): Any? = try {
        f()
    } catch (e: DkgChannelError) {
        throw DkgChannelError(e.code, peer, e.detail)
    }

    /**
     * Run ONE participant's whole DKG over `ch`: round 1, the proof-of-possession checks, round 2 with signed shares, share verification, complaints, rebuttals, the
     * qualified set, the echo round and finalize. Returns this participant's key package; throws [DkgChannelError] on any channel or protocol violation (nothing
     * partial is returned). `participants` includes this one; `sessionId` is the ceremony id, identical for all and unique per run; `timeoutMs` is the per-phase
     * wait (default 30 s: a missing message after it aborts the run); `coefficients` fix the polynomial (tests); `rng` supplies the random draws.
     */
    @JvmStatic @JvmOverloads
    fun runDkgOverChannel(
        ch: DkgChannel, t: Any?, participants: List<Any?>, sessionId: ByteArray, timeoutMs: Double? = null, coefficients: List<ByteArray>? = null, rng: Random32 = FrostNet.SECURE_RANDOM32,
    ): RunDkgResult {
        val self = ch.self
        val nums = participants.map { IntentJs.num(it) }
        val sortedNums = nums.sortedBy { it ?: Double.NaN }
        val invalid = participants.size > DKG_MAX_PARTICIPANTS || sortedNums.withIndex().any { (k, d) ->
            d == null || !IntentJs.isSafeInteger(d) || d <= 0 || (k > 0 && sortedNums[k - 1] == d)
        }
        if (invalid) throw DkgChannelError("protocol", null, "participants must be distinct positive integers within the cap")
        val ids = sortedNums.map { it!!.toLong() }
        if (self !in ids) throw DkgChannelError("protocol", null, "this participant is not in the participant list")
        if (!IntentJs.isSafeInteger(t) || IntentJs.num(t)!! < 1 || IntentJs.num(t)!! > ids.size) throw DkgChannelError("protocol", null, "need 1 <= t <= n")
        val tt = IntentJs.num(t)!!.toInt()
        val others = ids.filter { it != self }
        if (ch.peers.size != others.size || !others.withIndex().all { (k, o) -> ch.peers[k] == o }) throw DkgChannelError("protocol", null, "the channel peers are not exactly the other participants")
        val sid = sessionId
        val sidB64 = Keys.b64u(sid)
        val tmo = timeoutMs ?: 30_000.0
        val n = ids.size

        // Round 1: broadcast, collect, bind each package to its authenticated sender.
        val r1 = FrostDkg.dkgRound1(IntentJs.ofLong(self), IntentJs.ofLong(tt.toLong()), IntentJs.ofLong(n.toLong()), sid, coefficients, null, rng)
        ch.broadcast("round1", r1.pkg)
        val pkgs = ArrayList<Map<String, Any?>>()
        pkgs.add(r1.pkg)
        for ((from, body) in ch.collect("round1", others, tmo)) {
            val p = bind(from) { decodeDkgRound1Package(body, tt) } as Map<String, Any?>
            if (IntentJs.num(p["identifier"]) != from.toDouble()) throw DkgChannelError("identity", from, "package claims identifier ${net.atlasauth.pca.verifier.ZkJs.string(p["identifier"])}")
            if (p["sessionId"] != sidB64) throw DkgChannelError("wrong-session", from, "package names another session")
            pkgs.add(p)
        }
        val byId = HashMap<Long, Map<String, Any?>>()
        for (p in pkgs) byId[IntentJs.num(p["identifier"])!!.toLong()] = p
        // A package whose proof of possession fails is dropped by the qualified set; it gets and gives no shares.
        val pok = pkgs.filter { FrostDkg.dkgVerifyRound1(it["identifier"], it, sid) }
        val okPeers = others.filter { o -> pok.any { IntentJs.num(it["identifier"]) == o.toDouble() } }

        // Round 2: signed shares out (private), signed shares in.
        for (s in FrostDkg.dkgRound2(r1.state, pok)) {
            ch.send(
                IntentJs.num(s["to"])!!.toLong(), "share",
                linkedMapOf("from" to s["from"], "to" to s["to"], "sessionId" to s["sessionId"], "share" to Keys.b64u(s["share"] as ByteArray), "sig" to s["sig"]),
            )
        }
        val inbox = ArrayList<Map<String, Any?>>()
        val mine = ArrayList<Map<String, Any?>>()
        for ((from, body) in ch.collect("share", okPeers, tmo)) {
            val m = bind(from) { decodeDkgShareMessage(body) } as Map<String, Any?>
            if (IntentJs.num(m["from"]) != from.toDouble()) throw DkgChannelError("identity", from, "share claims sender ${net.atlasauth.pca.verifier.ZkJs.string(m["from"])}")
            if (IntentJs.num(m["to"]) != self.toDouble()) throw DkgChannelError("identity", from, "share is addressed to ${net.atlasauth.pca.verifier.ZkJs.string(m["to"])}")
            if (m["sessionId"] != sidB64) throw DkgChannelError("wrong-session", from, "share names another session")
            val received = linkedMapOf("from" to IntentJs.ofLong(from), "sessionId" to m["sessionId"], "share" to m["share"], "sig" to m["sig"])
            val sender = byId.getValue(from)
            if (FrostDkg.dkgVerifyShare(received, sender, IntentJs.ofLong(self), sid)) {
                inbox.add(received)
                continue
            }
            val c = FrostDkg.dkgFileComplaint(IntentJs.ofLong(from), IntentJs.ofLong(self), m["share"], m["sig"], sender["coefficientCommitments"], sid)
            // Only a share the sender really signed is attributable blame; anything else aborts the run instead of accusing.
            if (FrostDkg.dkgVerifyComplaint(c, pkgs)["justified"] != true) throw DkgChannelError("protocol", from, "share failed verification and is not admissible blame")
            mine.add(c)
        }

        // Complaints (broadcast, possibly empty), then rebuttals by the accused.
        ch.broadcast("complaints", linkedMapOf("complaints" to mine))
        val complaints = ArrayList<Map<String, Any?>>(mine)
        for ((from, body) in ch.collect("complaints", others, tmo)) {
            val list = bind(from) { decodeDkgComplaints(body) } as List<Map<String, Any?>>
            val pairs = HashSet<Double?>()
            for (c in list) {
                if (IntentJs.num(c["accuser"]) != from.toDouble()) throw DkgChannelError("identity", from, "complaint filed as ${net.atlasauth.pca.verifier.ZkJs.string(c["accuser"])}")
                if (c["sessionId"] != sidB64) throw DkgChannelError("wrong-session", from, "complaint names another session")
                val accused = IntentJs.num(c["accused"])
                if (accused == from.toDouble() || ids.none { it.toDouble() == accused }) throw DkgChannelError("protocol", from, "complaint names an invalid accused")
                if (!pairs.add(accused)) throw DkgChannelError("duplicate", from, "two complaints against one accused")
                complaints.add(c)
            }
        }
        val rebuttals = complaints.filter { IntentJs.num(it["accused"]) == self.toDouble() }.map { FrostDkg.dkgRebut(IntentJs.ofLong(self), it, r1.state) }
        ch.broadcast("rebuttals", linkedMapOf("rebuttals" to rebuttals))
        val allRebuttals = ArrayList<Map<String, Any?>>(rebuttals)
        for ((from, body) in ch.collect("rebuttals", others, tmo)) {
            for (r in bind(from) { decodeDkgRebuttals(body) } as List<Map<String, Any?>>) {
                if (IntentJs.num(r["accused"]) != from.toDouble()) throw DkgChannelError("identity", from, "rebuttal made as ${net.atlasauth.pca.verifier.ZkJs.string(r["accused"])}")
                if (r["sessionId"] != sidB64) throw DkgChannelError("wrong-session", from, "rebuttal names another session")
                allRebuttals.add(r)
            }
        }

        val qualified = FrostDkg.dkgQualifiedSet(ids.map { IntentJs.ofLong(it) }, complaints, pkgs, allRebuttals)
        if (qualified.none { IntentJs.num(it) == self.toDouble() }) throw DkgChannelError("disqualified", self, "this participant was disqualified by the blame round")
        if (qualified.size < tt) throw DkgChannelError("protocol", null, "fewer than t participants remain qualified")

        // Echo round: every qualified party must have seen the identical transcript.
        val echo = FrostDkg.dkgEcho(IntentJs.ofLong(self), pkgs, complaints, qualified, sid)
        ch.broadcast("echo", echo)
        val echoes = ArrayList<Map<String, Any?>>()
        echoes.add(echo)
        val echoFrom = qualified.map { IntentJs.num(it)!!.toLong() }.filter { it != self }
        for ((from, body) in ch.collect("echo", echoFrom, tmo)) {
            val e = bind(from) { decodeDkgEcho(body) } as Map<String, Any?>
            if (IntentJs.num(e["identifier"]) != from.toDouble()) throw DkgChannelError("identity", from, "echo claims identifier ${net.atlasauth.pca.verifier.ZkJs.string(e["identifier"])}")
            echoes.add(e)
        }
        val agreement = FrostDkg.dkgCheckEchoes(qualified, echoes, sid)
        if (agreement["agreed"] != true) throw DkgChannelError("equivocation", null, agreement["reason"] as String)

        val keyPackage = FrostDkg.dkgFinalize(IntentJs.ofLong(self), r1.state, inbox, pkgs, qualified, linkedMapOf("echoes" to echoes, "complaints" to complaints), true)
        return RunDkgResult(keyPackage, qualified, complaints)
    }
}
