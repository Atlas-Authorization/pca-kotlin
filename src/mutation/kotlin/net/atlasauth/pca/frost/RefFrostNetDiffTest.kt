package net.atlasauth.pca.frost

import net.atlasauth.pca.pqthreshold.PqThreshold
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Networked FROST signing against the reference (ref-frost-net, 634 cases): the allow token, the signer proof-of-possession and enrollment, the equivocation
 * guard, the wire decoders, the signer service (round 1 and 2, the stale-session guard, the durable nonce store, restarts), the coordinator over scripted
 * transports (delays, unreachable signers, hostile responses, session reuse), the nonce-store contract and the FROST post-quantum co-sign. A typed error compares
 * by class and fields; a refusal marked `reasonOpen` compares by presence of a reason; the tail after `(fail closed)` of an error reason is open. The corpus
 * carries every secret as a seed label or a dealer descriptor.
 *
 * A nonce store without a method (the reference's `invalid-no-spend`) cannot be written in a typed language: the harness answers that one constructor refusal.
 */
@Suppress("UNCHECKED_CAST")
class RefFrostNetDiffTest {
    private val mod = "ref-frost-net"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun num(o: Any?): Double = IntentJs.num(o)!!

    // ---- corpus values ----

    private val shares = HashMap<String, ByteArray>()

    private fun dealerShare(d: Map<String, Any?>): ByteArray = shares.getOrPut(Json.canonicalize(d)) {
        val o = Frost.FrostKeygenOpts()
        (un(d["secret"]) as ByteArray?)?.let { o.secret = it }
        (d["coefficients"] as List<Any?>?)?.let { l -> o.coefficients = l.map { un(it) as ByteArray } }
        (d["identifiers"] as List<Any?>?)?.let { l -> o.identifiers = LongArray(l.size) { IntentJs.lng(l[it]) } }
        val kg = Frost.trustedDealerKeygen(IntentJs.lng(d["t"]).toInt(), IntentJs.lng(d["n"]).toInt(), o)
        val id = IntentJs.lng(d["id"])
        kg.participantShares.first { it.identifier == id }.share
    }

    /** `{"$bytes": b64url}` is bytes and `{"$share": {...}}` the dealer share of a participant, at any depth. */
    private fun un(v: Any?): Any? = when (v) {
        is List<*> -> v.map { un(it) }
        is Map<*, *> -> {
            if (v.size == 1 && v["\$bytes"] is String) Pca.decodeB64uStrict(v["\$bytes"], -1)
            else if (v.size == 1 && v.containsKey("\$share")) dealerShare(map(v["\$share"]))
            else LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = un(x) }
        }
        else -> v
    }

    private fun bytes(o: Any?): ByteArray = o as ByteArray

    private fun flipStr(s: String): String {
        val u = Pca.decodeB64uStrict(s, -1)!!
        u[0] = (u[0].toInt() xor 1).toByte()
        return Keys.b64u(u)
    }

    // ---- comparison ----

    private fun errOut(e: Throwable): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("\$throws" to (e.message ?: e.toString()))
        when (e) {
            is PoPError -> {
                o["class"] = "PoPError"
                e.identifier?.let { o["identifier"] = IntentJs.ofLong(it) }
            }
            is EquivocationError -> {
                o["class"] = "EquivocationError"
                o["session_id"] = e.sessionId
                o["round"] = IntentJs.ofLong(e.round)
                o["identifier"] = IntentJs.ofLong(e.identifier)
                o["previousDigest"] = e.previousDigest
                o["offendingDigest"] = e.offendingDigest
            }
            is CoordinatorError -> {
                o["class"] = if (e is CoordinatorTimeoutError) "CoordinatorTimeoutError" else "CoordinatorError"
                o["refusals"] = e.refusals.map { linkedMapOf("identifier" to IntentJs.ofLong(it.first), "reason" to it.second) }
                if (e is CoordinatorTimeoutError) o["timeoutMs"] = Json.Num(Json.esNumber(e.timeoutMs))
            }
        }
        return o
    }

    private fun failClosed(r: String): String {
        val i = r.indexOf("(fail closed)")
        return if (i >= 0) r.substring(0, i + "(fail closed)".length) else r
    }

    /** A first difference, or null. */
    private fun differ(w: Any?, g: Any?, at: String): String? {
        if (w is Map<*, *>) {
            if (g !is Map<*, *>) return "$at: want an object, got ${g?.javaClass?.simpleName}"
            val open = w["reasonOpen"] == true
            val skip = HashSet<String>().also { if (w.containsKey("\$throws")) it.add("\$throws"); if (open) { it.add("reason"); it.add("reasonOpen") } }
            val wk = w.keys.filter { it !in skip }.toSet()
            val gk = g.keys.filter { it !in skip }.toSet()
            if (wk != gk) return "$at: members differ: want $wk, got $gk"
            if (w.containsKey("\$throws") && !g.containsKey("\$throws")) return "$at: want a refusal"
            if (open && g["reason"] !is String) return "$at: want a reason"
            for (k in wk) {
                if (k == "reason" && w[k] is String && g[k] is String) {
                    if (failClosed(w[k] as String) != failClosed(g[k] as String)) return "$at.reason: want ${w[k]}, got ${g[k]}"
                    continue
                }
                differ(w[k], g[k], "$at.$k")?.let { return it }
            }
            return null
        }
        if (w is List<*>) {
            if (g !is List<*> || g.size != w.size) return "$at: list differs"
            for (i in w.indices) differ(w[i], g[i], "$at[$i]")?.let { return it }
            return null
        }
        return if (IntentJs.jsonEquals(w, g)) null else "$at: want ${Json.canonicalize(w)}, got ${Json.canonicalize(g)}"
    }

    // ---- scripted randomness ----

    private fun queue(vals: List<ByteArray>): Random32 {
        val q = ArrayDeque(vals)
        return Random32 { q.removeFirstOrNull() ?: throw IllegalStateException("unscripted randomness draw") }
    }

    // ---- nonce stores ----

    private class FailStore(val m: String) : NonceStore {
        private val inner = MemoryNonceStore()
        private fun down(what: String) { if (m == what) throw IllegalStateException("store down") }
        override fun create(sessionId: String, record: NonceRecord) { down("create"); inner.create(sessionId, record) }
        override fun load(sessionId: String): NonceRecord? { down("load"); return inner.load(sessionId) }
        override fun spend(sessionId: String) { down("spend"); inner.spend(sessionId) }
        override fun drop(sessionId: String) { down("drop"); inner.drop(sessionId) }
        override fun isSpent(sessionId: String): Boolean { down("isSpent"); return inner.isSpent(sessionId) }
    }

    private fun mkStore(kind: Any?): NonceStore? = when {
        kind == null || kind == "none" -> null
        kind == "memory" -> MemoryNonceStore()
        kind is String && kind.startsWith("fail-") -> FailStore(kind.substring(5))
        else -> throw AssertionError("store $kind")
    }

    /** A store with exactly one defect, as the reference's contract cases build it. */
    private class BrokenStore(val kind: String) : NonceStore {
        val live = HashMap<String, NonceRecord>()
        val spent = HashSet<String>()
        override fun create(sessionId: String, record: NonceRecord) {
            if (kind != "create-overwrites" && live.containsKey(sessionId)) throw IllegalStateException("exists")
            if (kind != "create-over-spent" && spent.contains(sessionId)) throw IllegalStateException("spent")
            live[sessionId] = if (kind == "create-aliases-input") record else record.copy()
        }
        override fun load(sessionId: String): NonceRecord? {
            val r = live[sessionId] ?: return null
            return if (kind == "load-aliases") r else r.copy()
        }
        override fun spend(sessionId: String) {
            if (!live.containsKey(sessionId)) {
                if (kind == "spend-unknown-ok" || (kind == "spend-twice-ok" && spent.contains(sessionId))) return
                throw IllegalStateException("not live")
            }
            live.remove(sessionId)
            spent.add(sessionId)
        }
        override fun drop(sessionId: String) {
            live.remove(sessionId)
            if (kind == "drop-marks-spent") spent.add(sessionId)
        }
        override fun isSpent(sessionId: String): Boolean = if (kind == "unknown-reports-spent") true else spent.contains(sessionId)
    }

    private fun record(m: Map<String, Any?>): NonceRecord = NonceRecord(bytes(m["hiding"]), bytes(m["binding"]), bytes(m["hidingCommitment"]), bytes(m["bindingCommitment"]), num(m["createdAt"]))

    private fun recordOut(r: NonceRecord): Map<String, Any?> =
        // a snapshot (the reference serialises before it mutates the loaded record)
        linkedMapOf("hiding" to r.hiding.clone(), "binding" to r.binding.clone(), "hidingCommitment" to r.hidingCommitment.clone(), "bindingCommitment" to r.bindingCommitment.clone(), "createdAt" to r.createdAt)

    private fun nonceStoreOps(ops: List<Any?>): Any? {
        val s = MemoryNonceStore()
        return ops.map { o ->
            val op = map(o)
            val sid = op["sid"]
            try {
                when (op["op"]) {
                    "create" -> {
                        if (sid !is String) throw IllegalArgumentException("nonce-store: session id must be a non-empty string")
                        val r = record(map(op["rec"]))
                        s.create(sid, r)
                        if (op["mutateInputAfter"] == true) {
                            r.hiding.fill(0xee.toByte())
                            r.hidingCommitment.fill(0xee.toByte())
                        }
                        linkedMapOf("ok" to true)
                    }
                    "load" -> {
                        val r = if (sid is String) s.load(sid) else null
                        val out = linkedMapOf<String, Any?>("value" to r?.let { recordOut(it) })
                        if (r != null && op["mutate"] == true) {
                            r.hiding.fill(0xee.toByte())
                            r.binding.fill(0xee.toByte())
                        }
                        out
                    }
                    "spend" -> {
                        if (sid !is String) throw IllegalStateException("nonce-store: cannot spend a session that is not live")
                        s.spend(sid)
                        linkedMapOf("ok" to true)
                    }
                    "drop" -> {
                        if (sid is String) s.drop(sid)
                        linkedMapOf("ok" to true)
                    }
                    "isSpent" -> linkedMapOf("value" to (sid is String && s.isSpent(sid)))
                    else -> throw IllegalArgumentException("bad op")
                }
            } catch (e: RuntimeException) {
                errOut(e)
            }
        }
    }

    private fun contract(a: Map<String, Any?>): Any? = try {
        val kind = a["store"] as String
        if (kind == "memory") FrostNonceStore.assertNonceStoreContract({ MemoryNonceStore() })
        else {
            val b = BrokenStore(kind.removePrefix("broken:"))
            FrostNonceStore.assertNonceStoreContract({ b }, { s ->
                if (b.kind == "spent-forgotten-on-restart") b.spent.clear()
                if (b.kind == "live-lost-on-restart") b.live.clear()
                s
            })
        }
        null
    } catch (e: RuntimeException) {
        errOut(e)
    }

    // ---- guard, decoders ----

    private fun guardRun(ops: List<Any?>): Any? {
        val g = FrostNet.EquivocationGuard()
        return ops.map { o ->
            val op = map(o)
            try {
                when (op["op"]) {
                    "observe" -> g.observe(op["session_id"], op["round"], op["identifier"], op["message"])
                    "forget" -> g.forget(op["session_id"] as String)
                    else -> throw IllegalArgumentException("bad op")
                }
                linkedMapOf("ok" to true)
            } catch (e: RuntimeException) {
                errOut(e)
            }
        }
    }

    private fun commitmentOut(c: Frost.FrostCommitment): Map<String, Any?> = linkedMapOf("identifier" to IntentJs.ofLong(c.identifier), "hiding" to c.hiding, "binding" to c.binding)

    // ---- the signer service ----

    private fun signerService(cfg: Map<String, Any?>, steps: List<Any?>, rng: List<ByteArray>): Any? {
        val out = linkedMapOf<String, Any?>("ctor" to null, "steps" to ArrayList<Any?>())
        val outSteps = out["steps"] as ArrayList<Any?>
        if (cfg["store"] == "invalid-no-spend") {
            out["ctor"] = errOut(IllegalArgumentException("GuardianSignerService: nonceStore.spend must be a function"))
            return out
        }
        val clock = doubleArrayOf(if (cfg["clock"] != null) num(cfg["clock"]) else 1_000_000.0)
        val store = mkStore(cfg["store"])
        val r32 = queue(rng)
        fun mk() = FrostNet.GuardianSignerService(
            cfg["identifier"], cfg["share"], cfg["groupPublicKey"], cfg["threshold"], cfg["policyAuthorityPublicKey"], cfg["sessionTtlMs"], { clock[0] }, store, r32,
        )
        var svc: FrostNet.GuardianSignerService
        try {
            svc = mk()
            out["ctor"] = linkedMapOf("verificationShare" to svc.verificationShare, "pop" to svc.proofOfPossession, "enrollment" to svc.enrollment())
        } catch (e: RuntimeException) {
            out["ctor"] = errOut(e)
            return out
        }
        for (so in steps) {
            val st = map(so)
            try {
                outSteps.add(
                    when (st["op"]) {
                        "round1" -> svc.round1(st["req"])
                        "round2" -> svc.round2(st["req"])
                        "clock" -> {
                            clock[0] += num(st["ms"])
                            linkedMapOf("clock" to clock[0])
                        }
                        "restart" -> {
                            svc = mk()
                            linkedMapOf("restarted" to true, "pop" to svc.proofOfPossession)
                        }
                        "storeLoad" -> linkedMapOf("live" to (store!!.load(st["sid"] as String) != null))
                        "storeIsSpent" -> linkedMapOf("spent" to store!!.isSpent(st["sid"] as String))
                        else -> throw IllegalArgumentException("bad step")
                    },
                )
            } catch (e: RuntimeException) {
                outSteps.add(errOut(e))
            }
        }
        return out
    }

    // ---- the coordinator ----

    private fun jsonCopy(v: Any?): Any? = IntentJs.normalize(OracleCases.toJson(v))

    private fun applyEdits(resp: Map<String, Any?>, edits: List<Any?>?, round: Int): Map<String, Any?> {
        val r = jsonCopy(resp) as MutableMap<String, Any?>
        for (eo in edits ?: emptyList()) {
            val e = map(eo)
            if (IntentJs.num(e["round"]) != round.toDouble()) continue
            val path = (e["path"] as List<Any?>).map { it as String }
            var parent: Any? = r
            for (k in path.dropLast(1)) parent = (parent as? Map<*, *>)?.get(k)
            if (parent !is MutableMap<*, *>) continue
            val p = parent as MutableMap<String, Any?>
            val key = path.last()
            when (e["op"]) {
                "set" -> p[key] = e["value"]
                "delete" -> p.remove(key)
                "flip" -> p[key] = flipStr(p[key] as String)
            }
        }
        return r
    }

    private fun coordinator(cfg: Map<String, Any?>): Any? {
        val out = linkedMapOf<String, Any?>("calls" to ArrayList<Any?>())
        val calls = out["calls"] as ArrayList<Any?>
        val transports = (cfg["signers"] as List<Any?>).map { so ->
            val s = map(so)
            val id = IntentJs.lng(s["identifier"])
            val counters = intArrayOf(0, 0)
            var service: FrostNet.GuardianSignerService? = null
            if (s["canned"] == null) {
                service = FrostNet.GuardianSignerService(
                    id, s["share"], s["groupPublicKey"], s["threshold"], s["policyAuthorityPublicKey"], s["sessionTtlMs"], { 1_000_000.0 }, mkStore(s["store"]),
                    queue((s["rng"] as List<Any?>).map { bytes(it) }),
                )
            }
            fun respond(round: Int, req: Map<String, Any?>): Map<String, Any?> {
                val key = if (round == 1) "r1" else "r2"
                val n = counters[round - 1]++
                val delay = (s["delay"] as Map<String, Any?>?)?.get(key)
                if (delay != null) Thread.sleep(IntentJs.lng(delay))
                if ((s["throws"] as Map<String, Any?>?)?.get(key) == true) throw IllegalStateException("unreachable")
                val resp: Map<String, Any?> = if (s["canned"] != null) {
                    val list = map(s["canned"])[if (round == 1) "round1" else "round2"] as List<Any?>
                    val c = list.getOrNull(n)
                    if (c == "throw" || c == null) throw IllegalStateException("unreachable")
                    map(c)
                } else if (round == 1) service!!.round1(req) else service!!.round2(req)
                return applyEdits(resp, s["edits"] as List<Any?>?, round)
            }
            object : SignerTransport {
                override val identifier: Long = id
                override fun round1(req: Map<String, Any?>): Map<String, Any?> = respond(1, req)
                override fun round2(req: Map<String, Any?>): Map<String, Any?> = respond(2, req)
            }
        }
        val sids = ArrayDeque((cfg["sessionIds"] as List<Any?>? ?: emptyList()).map { it as String })
        val coord = try {
            FrostNet.NetworkCoordinator(
                cfg["groupPublicKey"], cfg["threshold"], transports, (cfg["verificationShares"] as List<Any?>?)?.map { map(it) }, cfg["enroll"], cfg.containsKey("enroll"),
                { sids.removeFirstOrNull() ?: throw IllegalStateException("no more scripted session ids") }, cfg["timeoutMs"],
            )
        } catch (e: RuntimeException) {
            out["ctor"] = errOut(e)
            return out
        }
        for (co in cfg["calls"] as List<Any?>) {
            val c = map(co)
            try {
                val r = coord.sign(c["message"], c["allow"], (c["signerIds"] as List<Any?>?)?.map { IntentJs.lng(it) }, c["timeoutMs"]?.let { num(it) })
                calls.add(linkedMapOf("signature" to r.signature, "sessionId" to r.sessionId, "signers" to r.signers.map { IntentJs.ofLong(it) }))
            } catch (e: RuntimeException) {
                calls.add(errOut(e))
            }
        }
        Thread.sleep(0)
        return out
    }

    // ---- post-quantum co-sign ----

    private fun sign(a: List<Any?>): Any? {
        val o = map(a[3])
        val quorum = (a[1] as List<Any?>).map { q ->
            val m = map(q)
            Frost.FrostParticipantShare(IntentJs.lng(m["identifier"]), bytes(m["share"]), bytes(m["publicKey"]))
        }
        val seed = o["guardianMlDsaSeed"] as ByteArray?
        val guardian = seed?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, it) }
        val gpk = bytes(a[0])
        val msg = bytes(a[2])
        val r = FrostPq.signHybridFrostCosign(gpk, quorum, msg, o["groupAlg"] as String?, guardian, o["threshold"]?.let { IntentJs.lng(it).toInt() })
        val sig = Pca.decodeB64uStrict(r["sig"], -1)!!
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in r) if (k != "sig") out[k] = v
        out["sigVerifies"] = Pca.ed25519Strict(gpk, msg, sig)
        out["sigLength"] = IntentJs.ofLong(sig.size.toLong())
        return out
    }

    private fun verifyHybrid(a: List<Any?>): Any? {
        val opts = map(a[4])
        return FrostPq.verifyHybridFrostCosign(a[0], bytes(a[1]), a[2], a[3], opts["guardianPqPublicKey"], opts["expectGroupAlg"], opts.containsKey("expectGroupAlg"))
    }

    private fun cosignRep(a: List<Any?>): Any? {
        val msg = a[1] as? ByteArray ?: throw IllegalArgumentException("sha256 needs bytes")
        val alg = if (a[3] == null) "null" else a[3] as? String ?: throw IllegalArgumentException("utf8 needs a string") // TextEncoder reads null as the text "null"
        return FrostPq.frostCosignRepresentative(a[0], msg, a[2], alg)
    }

    private fun keyPair(seed: Any?): PqThreshold.MlDsaKeyPair {
        val k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, bytes(seed))
        return PqThreshold.MlDsaKeyPair(k.pk, k.sk)
    }

    // ---- dispatch ----

    private fun call(fn: String, a: List<Any?>, rng: List<ByteArray>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "ALLOW_TOKEN_TYP" to FrostNet.ALLOW_TOKEN_TYP, "SIGNER_POP_DST" to FrostNet.SIGNER_POP_DST, "MAX_FROST_SIGNING_SET" to IntentJs.ofLong(FrostNet.MAX_FROST_SIGNING_SET.toLong()),
            "DEFAULT_FROST_GROUP_ALG" to FrostPq.DEFAULT_FROST_GROUP_ALG, "PQ_QUORUM_VERSION" to IntentJs.ofLong(PqThreshold.PQ_QUORUM_VERSION.toLong()), "PQ_QUORUM_ALG" to PqThreshold.PQ_QUORUM_ALG,
            "MAX_PQ_QUORUM_ENTRIES" to IntentJs.ofLong(PqThreshold.MAX_PQ_QUORUM_ENTRIES.toLong()),
        )
        "frostActionDigest" -> FrostNet.frostActionDigest(a[0])
        "issueAllowToken" -> FrostNet.issueAllowToken(a[0], map(a[1]), queue(rng))
        "verifyAllowToken" -> FrostNet.verifyAllowToken(a[0], map(a[1]))
        "createSignerPoP" -> {
            val o = map(a[2])
            FrostNet.createSignerPoP(a[0], a[1], o["groupPublicKey"], o["nonce"] as ByteArray?, queue(rng))
        }
        "verifySignerPoP" -> FrostNet.verifySignerPoP(a[0], (a[1] as Map<String, Any?>?)?.get("groupPublicKey"))
        "enrollVerificationShares" -> FrostNet.enrollVerificationShares(a[0], (a[1] as Map<String, Any?>?)?.get("groupPublicKey"))
        "equivocationGuard" -> guardRun(a[0] as List<Any?>)
        "decodeCommitment" -> commitmentOut(FrostNet.decodeCommitment(a[0]))
        "decodeCommitments" -> FrostNet.decodeCommitments(a[0]).map { commitmentOut(it) }
        "decodeVerificationShares" -> FrostNet.decodeVerificationShares(a[0]).map { linkedMapOf("identifier" to IntentJs.ofLong(it.identifier), "publicKey" to it.publicKey) }
        "signerService" -> signerService(map(a[0]), a[1] as List<Any?>, rng.map { it })
        "coordinator" -> coordinator(map(a[0]))
        "nonceStore" -> nonceStoreOps(a[0] as List<Any?>)
        "assertNonceStoreContract" -> contract(map(a[0]))
        "resolveFrostGroupAlg" -> FrostPq.resolveFrostGroupAlg(a.getOrNull(0), a.isEmpty())
        "frostSignerSetDigest" -> FrostPq.frostSignerSetDigest(a[0])
        "frostCosignRepresentative" -> cosignRep(a)
        "verifyHybridFrostCosign" -> verifyHybrid(a)
        "signHybridFrostCosign" -> sign(a)
        "pqQuorumRepresentative" -> PqThreshold.pqQuorumRepresentative(a[0] as? ByteArray ?: throw IllegalArgumentException("sha256 needs bytes"))
        "signPqQuorum" -> PqThreshold.signPqQuorum(bytes(a[0]), (a[1] as List<Any?>).map { keyPair(it) }, a[2]?.let { IntentJs.lng(it).toInt() })
        "normalizePqQuorumPool" -> PqThreshold.normalizePqQuorumPool(a[0] as List<*>).toList()
        "verifyPqQuorum" -> PqThreshold.verifyPqQuorum(a[0], bytes(a[1]), (a[2] as List<Any?>).map { it as String }.toSet(), a[3])
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf(
            "constants", "frostActionDigest", "issueAllowToken", "verifyAllowToken", "createSignerPoP", "verifySignerPoP", "enrollVerificationShares", "equivocationGuard", "decodeCommitment",
            "decodeCommitments", "decodeVerificationShares", "signerService", "coordinator", "nonceStore", "assertNonceStoreContract", "resolveFrostGroupAlg", "frostSignerSetDigest",
            "frostCosignRepresentative", "signHybridFrostCosign", "verifyHybridFrostCosign", "pqQuorumRepresentative", "signPqQuorum", "normalizePqQuorumPool", "verifyPqQuorum",
        )
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
                    val raw = call(fn, un(args) as List<Any?>, rng)
                    IntentJs.normalize(OracleCases.toJson(raw))
                } catch (e: RuntimeException) {
                    IntentJs.normalize(OracleCases.toJson(errOut(e)))
                }
                // an argument list the harness resolved earlier than the call (a dealer share) must not make a refusal a harness failure
                differ(c["out"], got, c["name"] as String)?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(634, total)
    }
}
