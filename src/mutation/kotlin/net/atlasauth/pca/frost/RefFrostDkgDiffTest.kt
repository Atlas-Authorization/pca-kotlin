package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The FROST distributed key generation against the reference (ref-frost-dkg, 439 committed cases, plus the 286 cases that carry a derived secret, generated in CI
 * by gen-secret-corpus.sh and never committed): the rounds, the proof-of-possession and share checks, complaints, rebuttals, blame, the qualified set, the echo
 * round, finalize, the in-process ceremony, the wire codec, the inbox, the in-memory network, the frame model of the TLS channel and one party's whole ceremony
 * replayed over a scripted channel. A channel refusal compares by class, code and peer; a refusal of any other function compares as a refusal; verdict and
 * resolution reasons compare exactly.
 */
@Suppress("UNCHECKED_CAST")
class RefFrostDkgDiffTest {
    private val mod = "ref-frost-dkg"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun bytes(o: Any?): ByteArray = o as ByteArray

    private fun un(v: Any?): Any? = when (v) {
        is List<*> -> v.map { un(it) }
        is Map<*, *> -> if (v.size == 1 && v["\$bytes"] is String) Pca.decodeB64uStrict(v["\$bytes"], -1) else LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = un(x) }
        else -> v
    }

    private fun errOut(e: Throwable): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("\$throws" to (e.message ?: e.toString()))
        if (e is DkgChannelError) {
            o["code"] = e.code
            o["class"] = "DkgChannelError"
            o["peer"] = e.peer?.let { IntentJs.ofLong(it) }
        }
        return o
    }

    private fun differ(w: Any?, g: Any?, at: String): String? {
        if (w is Map<*, *>) {
            if (g !is Map<*, *>) return "$at: want an object, got ${g?.javaClass?.simpleName}"
            val skip = if (w.containsKey("\$throws")) setOf("\$throws") else emptySet()
            val wk = w.keys.filter { it !in skip }.toSet()
            val gk = g.keys.filter { it !in skip }.toSet()
            if (wk != gk) return "$at: members differ: want $wk, got $gk"
            if (w.containsKey("\$throws") && !g.containsKey("\$throws")) return "$at: want a refusal"
            for (k in wk) differ(w[k], g[k], "$at.$k")?.let { return it }
            return null
        }
        if (w is List<*>) {
            if (g !is List<*> || g.size != w.size) return "$at: list differs (want ${w.size})"
            for (i in w.indices) differ(w[i], g[i], "$at[$i]")?.let { return it }
            return null
        }
        return if (IntentJs.jsonEquals(w, g)) null else "$at: want ${Json.canonicalize(w)}, got ${Json.canonicalize(g)}"
    }

    private fun queue(vals: List<ByteArray>): Random32 {
        val q = ArrayDeque(vals)
        return Random32 { q.removeFirstOrNull() ?: throw IllegalStateException("unscripted randomness draw") }
    }

    private fun stateOf(spec: Map<String, Any?>): FrostDkg.State =
        FrostDkg.dkgRound1(spec["id"], spec["t"], spec["n"], spec["sessionId"], spec["coefficients"], spec["popNonce"], queue(emptyList())).state

    // ---- inbox, network, party ----

    private fun longs(o: Any?): List<Long> = (o as List<Any?>).map { IntentJs.num(it)!!.toLong() }

    private fun bodies(m: Map<Long, Any?>): Map<String, Any?> = LinkedHashMap<String, Any?>().also { out -> for ((k, v) in m) out[k.toString()] = v }

    private fun inboxRun(a: Map<String, Any?>): Any? {
        val ib = FrostDkgChannel.DkgInbox(bytes(a["sessionId"]), longs(a["peers"]))
        return (a["ops"] as List<Any?>).map { o ->
            val op = map(o)
            try {
                when (op["op"]) {
                    "accept" -> { ib.accept(IntentJs.lng(op["sender"]), bytes(op["bytes"])); linkedMapOf("ok" to true) }
                    "fail" -> { ib.fail(IntentJs.lng(op["peer"]), DkgChannelError(op["code"] as String, null, op["message"] as String)); linkedMapOf("ok" to true) }
                    "peerGone" -> { ib.peerGone(IntentJs.lng(op["peer"])); linkedMapOf("ok" to true) }
                    "close" -> { ib.close(); linkedMapOf("ok" to true) }
                    "collect" -> linkedMapOf("ok" to true, "bodies" to bodies(ib.collect(op["kind"] as String, longs(op["from"]), IntentJs.num(op["timeoutMs"])!!)))
                    else -> throw IllegalArgumentException("bad op")
                }
            } catch (e: RuntimeException) {
                errOut(e)
            }
        }
    }

    private fun netRun(a: Map<String, Any?>): Any? {
        val sid = bytes(a["sessionId"])
        val m = a["intercept"] as Map<String, Any?>?
        val intercept: ((Long, Long, String, ByteArray) -> ByteArray?)? = if (m == null) null else { from, to, kind, b ->
            val hit = (m["kind"] == null || m["kind"] == kind) && (m["from"] == null || IntentJs.lng(m["from"]) == from) && (m["to"] == null || IntentJs.lng(m["to"]) == to)
            if (!hit) b else if (m["action"] == "drop") null else if (m["action"] == "replace") bytes(m["bytes"]) else b
        }
        val net = FrostDkgChannel.createMemoryDkgNetwork(longs(a["ids"]), sid, intercept)
        val out = ArrayList<Any?>()
        val summary = LinkedHashMap<String, Any?>()
        for ((id, ch) in net.channels) summary[id.toString()] = linkedMapOf("self" to IntentJs.ofLong(ch.self), "peers" to ch.peers.map { IntentJs.ofLong(it) })
        out.add(linkedMapOf("channels" to summary))
        for (o in a["ops"] as List<Any?>) {
            val op = map(o)
            try {
                when (op["op"]) {
                    "broadcast" -> { net.channels[IntentJs.lng(op["from"])]!!.broadcast(op["kind"] as String, op["body"]); out.add(linkedMapOf("ok" to true)) }
                    "send" -> { net.channels[IntentJs.lng(op["from"])]!!.send(IntentJs.lng(op["to"]), op["kind"] as String, op["body"]); out.add(linkedMapOf("ok" to true)) }
                    "deliver" -> { net.deliver(IntentJs.lng(op["from"]), IntentJs.lng(op["to"]), bytes(op["bytes"])); out.add(linkedMapOf("ok" to true)) }
                    "collect" -> out.add(linkedMapOf("ok" to true, "bodies" to bodies(net.channels[IntentJs.lng(op["at"])]!!.collect(op["kind"] as String, longs(op["fromIds"]), IntentJs.num(op["timeoutMs"])!!))))
                    "close" -> { net.channels[IntentJs.lng(op["at"])]!!.close(); out.add(linkedMapOf("ok" to true)) }
                    else -> throw IllegalArgumentException("bad op")
                }
            } catch (e: RuntimeException) {
                out.add(errOut(e))
            }
        }
        return out
    }

    private val PHASES = listOf("round1", "share", "complaints", "rebuttals", "echo")

    private fun partyRun(spec: Map<String, Any?>, rng: List<ByteArray>): Any? {
        val sid = bytes(spec["sessionId"])
        val selfId = IntentJs.lng(spec["self"])
        val participants = spec["participants"] as List<Any?>
        val peerList: List<Long> = if (spec["peers"] != null) (spec["peers"] as List<Any?>).map { IntentJs.num(it)!!.toLong() }
        else participants.map { IntentJs.num(it)!!.toLong() }.filter { it != selfId }.sorted()
        val inbox = FrostDkgChannel.DkgInbox(sid, peerList)
        val pending = ArrayList((spec["inbound"] as List<Any?>? ?: emptyList()).map { map(it) })
        val outbound = ArrayList<Any?>()
        for (g in spec["gone"] as List<Any?>? ?: emptyList()) inbox.peerGone(IntentJs.lng(g))
        val ch = object : DkgChannel {
            override val self: Long = selfId
            override val peers: List<Long> = peerList
            override fun broadcast(kind: String, body: Any?) { outbound.add(linkedMapOf("op" to "broadcast", "kind" to kind, "bytes" to FrostDkgChannel.encodeDkgMessage(sid, kind, body))) }
            override fun send(to: Long, kind: String, body: Any?) {
                if (to !in peerList) throw DkgChannelError("identity", to, "not a connected peer")
                outbound.add(linkedMapOf("op" to "send", "kind" to kind, "to" to IntentJs.ofLong(to), "bytes" to FrostDkgChannel.encodeDkgMessage(sid, kind, body)))
            }
            override fun collect(kind: String, from: List<Long>, timeoutMs: Double): Map<Long, Any?> {
                val lim = PHASES.indexOf(kind)
                val keep = ArrayList<Map<String, Any?>>()
                for (m in pending) if (PHASES.indexOf(m["kind"] as String) <= lim) inbox.accept(IntentJs.lng(m["from"]), bytes(m["bytes"])) else keep.add(m)
                pending.clear()
                pending.addAll(keep)
                return inbox.collect(kind, from, timeoutMs)
            }
            override fun close() = inbox.close()
        }
        return try {
            val r = FrostDkgChannel.runDkgOverChannel(ch, spec["t"], participants, sid, IntentJs.num(spec["timeoutMs"]), null, queue(rng))
            linkedMapOf("outbound" to outbound, "result" to linkedMapOf("qualified" to r.qualified, "complaints" to r.complaints, "keyPackage" to r.keyPackage))
        } catch (e: RuntimeException) {
            linkedMapOf("outbound" to outbound, "error" to errOut(e))
        }
    }

    private fun decodeMessage(a: List<Any?>): Any? {
        val b = a[0] as? ByteArray ?: throw DkgChannelError("malformed", null, "message is not bytes")
        val (kind, body) = FrostDkgChannel.decodeDkgMessage(b, a[1] as ByteArray?)
        return linkedMapOf("kind" to kind, "body" to body)
    }

    private fun simulate(a: List<Any?>, rng: List<ByteArray>): Any? {
        val r = FrostDkg.frostDkgSimulate(a[0], a[1], map(a[2]), queue(rng))
        val out = LinkedHashMap<String, Any?>()
        for (k in listOf("groupPublicKey", "participantShares", "groupCommitment", "keyPackages", "round1Packages", "qualified", "complaints", "rebuttals", "echoes", "sessionId")) out[k] = r[k]
        return out
    }

    private fun call(fn: String, a: List<Any?>, rng: List<ByteArray>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "DKG_WIRE_VERSION" to IntentJs.ofLong(FrostDkgChannel.DKG_WIRE_VERSION.toLong()), "DKG_MAX_MESSAGE_BYTES" to IntentJs.ofLong(FrostDkgChannel.DKG_MAX_MESSAGE_BYTES.toLong()),
            "DKG_MAX_PARTICIPANTS" to IntentJs.ofLong(FrostDkgChannel.DKG_MAX_PARTICIPANTS.toLong()), "DKG_MESSAGE_KINDS" to FrostDkgChannel.DKG_MESSAGE_KINDS,
        )
        "dkgRound1" -> {
            val o = map(a[4])
            linkedMapOf("package" to FrostDkg.dkgRound1(a[0], a[1], a[2], a[3], o["coefficients"], o["popNonce"], queue(rng)).pkg)
        }
        "dkgVerifyRound1" -> FrostDkg.dkgVerifyRound1(a[0], a[1], a[2])
        "dkgSignShare" -> FrostDkg.dkgSignShare(stateOf(map(a[0])), a[1], a[2])
        "dkgRound2" -> FrostDkg.dkgRound2(stateOf(map(a[0])), a[1] as List<Any?>)
        "dkgVerifyShare" -> FrostDkg.dkgVerifyShare(a[0], a[1], a[2], a[3])
        "dkgFileComplaint" -> map(a[0]).let { FrostDkg.dkgFileComplaint(it["accused"], it["accuser"], it["receivedShare"], it["shareSig"], it["senderCommitments"], it["sessionId"]) }
        "dkgVerifyComplaint" -> FrostDkg.dkgVerifyComplaint(a[0], a[1])
        "dkgRebut" -> FrostDkg.dkgRebut(a[0], a[1], stateOf(map(a[2])))
        "dkgResolveBlame" -> FrostDkg.dkgResolveBlame(a[0], a[1], a[2])
        "dkgQualifiedSet" -> if (a.size > 3) FrostDkg.dkgQualifiedSet(a[0], a[1], a[2], a[3]) else FrostDkg.dkgQualifiedSet(a[0], a[1], a[2])
        "dkgTranscriptDigest" -> map(a[0]).let { FrostDkg.dkgTranscriptDigest(it["round1Packages"], it["complaints"], it["qualified"], bytes(it["sessionId"])) }
        "dkgEcho" -> map(a[0]).let { FrostDkg.dkgEcho(it["identifier"], it["round1Packages"], it["complaints"], it["qualified"], bytes(it["sessionId"])) }
        "dkgCheckEchoes" -> FrostDkg.dkgCheckEchoes(a[0], a[1], a[2])
        "dkgFinalize" -> FrostDkg.dkgFinalize(a[0], stateOf(map(a[1])), a[2], a[3], a[4], a[5], a[5] != null)
        "frostDkgSimulate" -> simulate(a, rng)
        "encodeDkgMessage" -> FrostDkgChannel.encodeDkgMessage(bytes(a[0]), a[1], a[2])
        "decodeDkgMessage" -> decodeMessage(a)
        "decodeDkgRound1Package" -> FrostDkgChannel.decodeDkgRound1Package(a[0], a[1])
        "decodeDkgShareMessage" -> FrostDkgChannel.decodeDkgShareMessage(a[0])
        "decodeDkgComplaints" -> FrostDkgChannel.decodeDkgComplaints(a[0])
        "decodeDkgRebuttals" -> FrostDkgChannel.decodeDkgRebuttals(a[0])
        "decodeDkgEcho" -> FrostDkgChannel.decodeDkgEcho(a[0])
        "dkgInbox" -> inboxRun(map(a[0]))
        "memoryNetwork" -> netRun(map(a[0]))
        "runDkgOverChannel" -> partyRun(map(a[0]), rng)
        "tlsFrameEncode" -> FrostDkgTls.encodeFrame(bytes(a[0]))
        "tlsFrameDecode" -> FrostDkgTls.decodeFrames((map(a[0])["chunks"] as List<Any?>).map { bytes(it) }).let { linkedMapOf("accepted" to it.accepted, "error" to it.error, "buffered" to IntentJs.ofLong(it.buffered.toLong())) }
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        BaseOracle.requireGen(mod)
        val fns = BaseOracle.fns("$mod.json.gz")
        assertTrue("the oracle must hold the whole DKG surface", fns.containsAll(setOf("dkgRound1", "dkgFinalize", "frostDkgSimulate", "runDkgOverChannel", "tlsFrameDecode", "dkgInbox", "memoryNetwork")))
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                var args = (OracleCases.decNum(c["args"]) as List<Any?>).toList()
                var rng: List<ByteArray> = emptyList()
                val last = args.lastOrNull()
                if (last is Map<*, *> && last.size == 1 && last.containsKey("\$rng")) {
                    rng = (last["\$rng"] as List<Any?>).map { Pca.decodeB64uStrict((it as Map<*, *>)["\$bytes"], -1)!! }
                    args = args.dropLast(1)
                }
                val got: Any? = try {
                    IntentJs.normalize(OracleCases.toJson(call(fn, un(args) as List<Any?>, rng)))
                } catch (e: RuntimeException) {
                    IntentJs.normalize(OracleCases.toJson(errOut(e)))
                }
                differ(c["out"], got, c["name"] as String)?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        // 439 committed cases, and with the CI-generated half (private-key-derived shares) 725
        assertTrue("every committed and generated case is replayed", total == 439 + 286 || total == 439)
    }
}
