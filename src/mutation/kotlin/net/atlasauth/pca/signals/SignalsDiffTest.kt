package net.atlasauth.pca.signals

import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.regex.Pattern
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the TypeScript-reference vectors of the shared-signals package (SET build/verify, revocation state, receiver, stream health, management API). */
@Suppress("UNCHECKED_CAST")
class SignalsDiffTest {
    private val m = "ref-signals"
    private val tx = Keys.edFromSeed(OracleCases.seed("ref-signals/tx"))
    private val txPub: Map<String, Any?> = jwk(false)
    private val txPriv: Map<String, Any?> = jwk(true)
    private val uuid = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    private fun jwk(priv: Boolean): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["kty"] = "OKP"
        o["crv"] = "Ed25519"
        o["x"] = tx.id()
        if (priv) o["d"] = Keys.b64u(tx.seed)
        return o
    }

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun err(e: RuntimeException): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["\$err"] = true
        if (e is SignalsError) o["code"] = e.code
        return o
    }

    private fun plainErr(): Map<String, Any?> = linkedMapOf("\$err" to true)

    private fun num(o: Any?): Double = Js.num(o)!!

    // ---- decode + normalise (a SET built with a random jti and the wall-clock iat) ----

    private fun parseSeg(seg: String): Any? = Json.parseLenient(String(Base64.getUrlDecoder().decode(seg), StandardCharsets.UTF_8))

    private fun shape(set: String): Map<String, Any?> {
        val p = set.split(".")
        val header = map(parseSeg(p[0]))
        val payload = map(parseSeg(p[1])) as MutableMap<String, Any?>
        val iat = Js.num(payload["iat"])
        if (iat != null && Math.abs(iat * 1000 - System.currentTimeMillis()) < 120_000) payload["iat"] = "<now>"
        val jti = payload["jti"]
        if (jti is String && uuid.matcher(jti).matches()) payload["jti"] = "<uuid>"
        val ok = try { Jose.compactVerify(set, txPub, listOf("EdDSA")); true } catch (e: RuntimeException) { false }
        return linkedMapOf("header" to header, "payload" to payload, "sigOk" to ok)
    }

    // ---- named function options ----

    private fun mapper(name: String): Signals.SubjectToAgent = when (name) {
        "email" -> Signals.SubjectToAgent { s -> if ("email" == s["format"] && s["email"] is String) s["email"] else null }
        "throws" -> Signals.SubjectToAgent { throw IllegalStateException("x") }
        "empty" -> Signals.SubjectToAgent { "" }
        "num" -> Signals.SubjectToAgent { Json.Num("5") }
        "id" -> Signals.SubjectToAgent { s -> if (s["id"] is String) s["id"] else null }
        "prefixed" -> Signals.SubjectToAgent { s -> if (s["id"] is String) "agent:" + s["id"] else null }
        else -> throw IllegalArgumentException(name)
    }

    private fun stdOpts(spec: Any?): Map<String, Any?>? {
        if (spec == null) return null
        val sp = map(spec)
        val out = LinkedHashMap<String, Any?>()
        val mp = sp["mapper"]
        if (mp != null && "default" != mp) out["subjectToAgent"] = mapper(mp as String)
        if (sp.containsKey("fail")) out["failOnUnmapped"] = sp["fail"]
        return out
    }

    private fun agentOf(name: Any?): ((Map<String, Any?>) -> Any?)? {
        if (name == null || "leaf" == name) return null
        val n = name as String
        if (n.startsWith("const:")) { val c = n.substring(6); return { _ -> c } }
        return when (n) {
            "throws" -> ({ _: Map<String, Any?> -> throw IllegalStateException("x") })
            "empty" -> ({ _: Map<String, Any?> -> "" })
            "num" -> ({ _: Map<String, Any?> -> Json.Num("5") })
            "grantId" -> ({ ctx: Map<String, Any?> -> Js.get(ctx["grant"], "id") })
            else -> throw IllegalArgumentException(n)
        }
    }

    // ---- tests ----

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "SET_TYP" to Signals.SET_TYP,
            "SET_ALG" to Signals.SET_ALG,
            "EVENT_TYPES" to LinkedHashMap(Signals.EVENT_TYPES),
            "RISC_EVENT_TYPES" to LinkedHashMap(Signals.RISC_EVENT_TYPES),
            "SET_INMEMORY_MAX_ENTRIES" to Signals.SET_INMEMORY_MAX_ENTRIES,
            "DELIVERY_PUSH" to SsfStream.DELIVERY_PUSH,
            "DELIVERY_POLL" to SsfStream.DELIVERY_POLL,
            "STREAM_STATUSES" to ArrayList<Any?>(SsfStream.STREAM_STATUSES),
        )
    }

    @Test fun verifySET() = OracleCases.each(m, "verifySET") { a ->
        // an explicit null options value is read as opts.issuer in the reference and throws; only an absent one means no options
        if (a.size > 2 && a[2] == null) throw IllegalArgumentException("Cannot read properties of null (reading 'issuer')")
        // the corpus was written under a frozen wall clock (the case clock T0): a call that names no currentDate is judged at that instant
        val opts = if (a.size > 2 && a[2] is Map<*, *>) LinkedHashMap(map(a[2])).also { if (!it.containsKey("currentDate")) it["currentDate"] = Json.Num(java.math.BigDecimal(net.atlasauth.pca.verifier.BaseOracle.clockMs("$m.json.gz")).toPlainString()) } else null
        Signals.verifySET(a[0], a[1], opts).toMap()
    }

    @Test fun buildSETShape() = OracleCases.each(m, "buildSETShape") { a ->
        val args = LinkedHashMap(map(a[0]))
        args["key"] = args.remove("keyJwk")
        shape(Signals.buildSET(args))
    }

    @Test fun stateScenario() = OracleCases.each(m, "stateScenario") { a ->
        val st = Signals.createRevocationState()
        val out = ArrayList<Any?>()
        for (so in map(a[0])["ops"] as List<Any?>) {
            val s = map(so)
            try {
                val target = if (s["badState"] == true) null else st
                val r: Any? = when (s["op"] as String) {
                    "apply" -> { Signals.applySET(st, s["parsed"]); st.toMap() }
                    "applyStd" -> linkedMapOf<String, Any?>(
                        "plan" to Signals.applyStandardRevocations(target, s["parsed"], stdOpts(s["std"])).toMap(),
                        "state" to st.toMap(),
                    )
                    "plan" -> Signals.planStandardRevocations(s["parsed"], stdOpts(s["std"])).toMap()
                    "isRevoked" -> Signals.isRevoked(st, s["grant"], s["agent"])
                    "isIntentRevoked" -> Signals.isIntentRevoked(st, s["id"])
                    "stream" -> Signals.streamProcessor(s["sets"] as List<Any?>, if (s["useState"] == true) st else null).toMap()
                    "snapshot" -> Signals.snapshotRevocationState(target)
                    "restore" -> {
                        val res = if (s["fresh"] == true) Signals.restoreRevocationState(s["snapshot"])
                        else if (s["nullInto"] == true) Signals.restoreRevocationState(s["snapshot"], null)
                        else Signals.restoreRevocationState(s["snapshot"], target)
                        res.toMap()
                    }
                    else -> throw IllegalArgumentException("bad op")
                }
                out.add(r)
            } catch (e: RuntimeException) {
                out.add(err(e))
            }
        }
        out.add(st.toMap())
        out
    }

    @Test fun replayScenario() = OracleCases.each(m, "replayScenario") { a ->
        val spec = map(a[0])
        val store: SetReplayStore = try {
            Signals.createInMemorySetReplayStore(if (spec["opts"] is Map<*, *>) map(spec["opts"]) else null)
        } catch (e: RuntimeException) {
            return@each arrayListOf<Any?>(err(e))
        }
        val out = ArrayList<Any?>()
        for (opO in spec["ops"] as List<Any?>) {
            val op = opO as List<Any?>
            try { out.add(store.addIfAbsent(op[0] as String, num(op[1]), num(op[2]))) } catch (e: RuntimeException) { out.add(plainErr()) }
        }
        out
    }

    @Test fun replayConformance() = OracleCases.each(m, "replayConformance") { a ->
        val spec = map(a[0])
        val mk: () -> SetReplayStore = when (spec["store"] as String) {
            "alwaysTrue" -> { { SetReplayStore { _, _, _ -> true } } }
            "alwaysFalse" -> { { SetReplayStore { _, _, _ -> false } } }
            "noExpiry" -> { { val seen = HashSet<String>(); SetReplayStore { j, _, _ -> seen.add(j) } } }
            else -> { { Signals.createInMemorySetReplayStore(if (spec["opts"] is Map<*, *>) map(spec["opts"]) else null) } }
        }
        ArrayList<Any?>(Signals.runSetReplayStoreConformance(mk))
    }

    @Test fun receiveScenario() = OracleCases.each(m, "receiveScenario") { a ->
        val spec = map(a[0])
        val st = Signals.createRevocationState()
        val store: SetReplayStore = when (spec["store"]) {
            "throws" -> SetReplayStore { _, _, _ -> throw IllegalStateException("boom") }
            "false" -> SetReplayStore { _, _, _ -> false }
            "mem1" -> Signals.createInMemorySetReplayStore(linkedMapOf<String, Any?>("maxEntries" to Json.Num("1")))
            else -> Signals.createInMemorySetReplayStore(null)
        }
        val out = ArrayList<Any?>()
        for (dO in spec["deliveries"] as List<Any?>) {
            val d = map(dO)
            val op = LinkedHashMap(map(d["opts"]))
            if (d["noStore"] != true) op["replayStore"] = store
            if (d["noState"] != true) op["state"] = st
            if (d["std"] != null) op["standardRevocations"] = stdOpts(d["std"])
            val key = if (d.containsKey("key")) d["key"] else txPub
            try {
                val r = Signals.receiveSET(d["set"], key, if (d["noOpts"] == true) null else op).toMap()
                if ("verify_failed" == r["code"] && !r["reason"].toString().startsWith("SET invalid:")) r["reason"] = "<jose>"
                out.add(r)
            } catch (e: RuntimeException) {
                out.add(plainErr())
            }
        }
        out.add(st.toMap())
        out
    }

    @Test fun adapterScenario() = OracleCases.each(m, "adapterScenario") { a ->
        val spec = map(a[0])
        val hook: Signals.Hook
        val isRev: (Any?, Any?) -> Boolean
        try {
            var st: RevocationState? = null
            if (spec["badState"] == null) {
                val snap = LinkedHashMap<String, Any?>()
                snap["v"] = Json.Num("1")
                snap["grants"] = spec["grants"] ?: ArrayList<Any?>()
                snap["agents"] = spec["agents"] ?: ArrayList<Any?>()
                snap["intents"] = ArrayList<Any?>()
                st = Signals.restoreRevocationState(snap)
            }
            hook = Signals.createRevocationHook(st, agentOf(spec["agentOf"]))
            isRev = Signals.createIsRevoked(st, agentOf(spec["agentOf"]))
        } catch (e: RuntimeException) {
            return@each arrayListOf<Any?>(err(e))
        }
        val out = ArrayList<Any?>()
        for (cO in spec["calls"] as List<Any?>) {
            val c = map(cO)
            val r = LinkedHashMap<String, Any?>()
            try {
                val ctx = LinkedHashMap<String, Any?>()
                ctx["pcactn"] = c["pcactn"]
                ctx["grant"] = c["grant"]
                r["hook"] = hook.check(ctx)
            } catch (e: RuntimeException) { r["hook"] = plainErr() }
            try { r["isRevoked"] = isRev(c["grant"], c["pcactn"]) } catch (e: RuntimeException) { r["isRevoked"] = plainErr() }
            out.add(r)
        }
        out
    }

    @Test fun validateStreamConfig() = OracleCases.each(m, "validateStreamConfig") { a -> ArrayList<Any?>(SsfStream.validateStreamConfig(a[0])) }

    private fun defaultStreamConfig(): Map<String, Any?> = linkedMapOf(
        "stream_id" to "s1", "iss" to "https://tx.example", "aud" to "rx", "min_verification_interval" to Json.Num("30"),
    )

    @Test fun healthScenario() = OracleCases.each(m, "healthScenario") { a ->
        val spec = map(a[0])
        val h = SsfStream.StreamHealth(if (spec["config"] != null) map(spec["config"]) else defaultStreamConfig(), if (spec["opts"] != null) map(spec["opts"]) else null)
        val issued = ArrayList<String>()
        val out = ArrayList<Any?>()
        for (so in spec["ops"] as List<Any?>) {
            val s = map(so)
            try {
                val r: Any? = when (s["op"] as String) {
                    "status" -> { h.setStatus(s["v"]); null }
                    "event" -> { h.recordEvent(num(s["now"])); null }
                    "request" -> {
                        val st = h.requestVerification(num(s["now"]))
                        if (st != null) { issued.add(st); "<state:" + (issued.size - 1) + ">" } else null
                    }
                    "ack" -> {
                        val state: Any? = if (s.containsKey("ref")) (if (num(s["ref"]).toInt() < issued.size) issued[num(s["ref"]).toInt()] else null) else s["state"]
                        h.ackVerification(state, num(s["now"]))
                    }
                    "report" -> h.report(num(s["now"]))
                    "fresh" -> h.revocationFreshWithin(num(s["max"]), num(s["now"]))
                    else -> throw IllegalArgumentException("bad op")
                }
                out.add(r)
            } catch (e: RuntimeException) { out.add(plainErr()) }
        }
        out
    }

    @Test fun verificationScenario() = OracleCases.each(m, "verificationScenario") { a ->
        val spec = map(a[0])
        val streams = LinkedHashMap<String, MutableMap<String, Any?>>()
        if (spec["streams"] != null) for ((k, v) in map(spec["streams"])) streams[k] = v as MutableMap<String, Any?>
        val out = ArrayList<Any?>()
        for (so in spec["ops"] as List<Any?>) {
            val s = map(so)
            try {
                val r = SsfStream.handleVerificationRequest(streams, s["req"], num(s["now"]), if (s["noKey"] == true) null else txPriv)
                val mm = LinkedHashMap<String, Any?>()
                mm["status"] = Json.Num(r.status.toString())
                if (r.status == 204) mm["set"] = shape(r.set!!) else mm["error"] = r.error
                out.add(mm)
            } catch (e: RuntimeException) { out.add(plainErr()) }
        }
        val last = LinkedHashMap<String, Any?>()
        for ((k, v) in streams) last[k] = v["lastVerification"]
        out.add(last)
        out
    }

    @Test fun pollScenario() = OracleCases.each(m, "pollScenario") { a ->
        val q = SsfStream.PollQueue()
        val out = ArrayList<Any?>()
        for (so in map(a[0])["ops"] as List<Any?>) {
            val s = map(so)
            try {
                val r: Any? = if (s["enqueue"] != null) { val e = s["enqueue"] as List<Any?>; q.enqueue(e[0] as String, e[1] as String); null }
                else if (s["depth"] != null) q.depth()
                else q.poll(s["poll"])
                out.add(r)
            } catch (e: RuntimeException) { out.add(plainErr()) }
        }
        out.add(linkedMapOf("depth" to q.depth(), "errors" to ArrayList<Any?>(q.errors)))
        out
    }

    @Test fun pushResponse() = OracleCases.each(m, "pushResponse") { a -> SsfStream.pushResponse(a[0]) }

    @Test fun caepSET() = OracleCases.each(m, "caepSET") { a ->
        val args = LinkedHashMap(map(a[0]))
        args["key"] = args.remove("keyJwk")
        val kind = args.remove("kind") as String?
        shape(if ("risk" == kind) SsfStream.riskLevelChangeSET(args) else SsfStream.assuranceLevelChangeSET(args))
    }

    @Test fun transmitterMetadata() = OracleCases.each(m, "transmitterMetadata") { a ->
        val o = map(a[0])
        val dm = (o["deliveryMethods"] as List<Any?>?)?.map { it as String }
        SsfManage.transmitterMetadata(o["issuer"] as String?, dm, a[1] as String, a[2] as String?)
    }

    @Test fun manageScenario() = OracleCases.each(m, "manageScenario") { a ->
        val spec = map(a[0])
        val store = SsfManage.MemoryStreamStore()
        val delivered = ArrayList<Any?>()
        var ids = 0
        var now = 0.0
        var rcv: Any? = null
        val o = SsfManage.Options()
        o.store = store
        o.issuer = "https://tx.example"
        o.eventsSupported = if (spec["eventsSupported"] != null) (spec["eventsSupported"] as List<Any?>).map { it as String }
        else listOf(Signals.GRANT_REVOKED, Signals.KILL_SWITCH, Signals.SESSION_REVOKED)
        o.pollEndpoint = { id -> "https://tx.example/poll/$id" }
        o.signingKey = txPriv
        o.deliver = { stream, set ->
            delivered.add(linkedMapOf("stream" to SsfManage.deepCopy(stream), "set" to shape(set)))
        }
        o.now = { now }
        o.newId = { "s" + (++ids) }
        val so = if (spec["options"] != null) map(spec["options"]) else LinkedHashMap()
        if (so["maxStreamsPerReceiver"] != null) o.maxStreamsPerReceiver = num(so["maxStreamsPerReceiver"])
        if (so["maxSubjectsPerStream"] != null) o.maxSubjectsPerStream = num(so["maxSubjectsPerStream"])
        if (so["deliveryMethods"] != null) o.deliveryMethods = (so["deliveryMethods"] as List<Any?>).map { it as String }
        val h = SsfManage.ssfManagementHandler(o, SsfManage.Authenticate { _ ->
            if ("throws" == rcv) throw IllegalStateException("auth")
            if (rcv == null) null else map(rcv)
        })
        val out = ArrayList<Any?>()
        for (stO in spec["steps"] as List<Any?>) {
            val st = map(stO)
            now = if (st["now"] != null) num(st["now"]) else 1000.0
            rcv = if (st.containsKey("rcv")) st["rcv"] else linkedMapOf("id" to "rx1", "aud" to "rx")
            out.add(h.handle(st["req"]))
        }
        val dump = LinkedHashMap<String, Any?>()
        val receivers = if (spec["receivers"] != null) spec["receivers"] as List<Any?> else listOf("rx1", "rx2")
        for (rid in receivers) {
            dump[rid as String] = store.listByReceiver(rid).map { listOf(it.first, it.second) }
        }
        out.add(linkedMapOf("delivered" to delivered, "store" to dump))
        out
    }

    // ---- what the oracle cannot pin: a SET built here verifies here, and the clock-driven paths ----

    @Test fun builtSetRoundTrips() {
        val payload = linkedMapOf<String, Any?>("grant_ref" to "g1", "event_timestamp" to Json.Num("100"))
        val ev = linkedMapOf<String, Any?>(Signals.GRANT_REVOKED to payload)
        val args = linkedMapOf<String, Any?>("events" to ev, "issuer" to "https://tx.example", "audience" to "rx", "subject" to "subj", "key" to txPriv)
        val set = Signals.buildSET(args)
        val p = Signals.verifySET(set, txPub, null)
        assertEquals("https://tx.example", p.iss)
        assertEquals("subj", p.sub)
        assertNotNull(p.jti)
        val st = Signals.createRevocationState()
        val opts = linkedMapOf<String, Any?>(
            "issuer" to "https://tx.example", "audience" to "rx", "replayStore" to Signals.createInMemorySetReplayStore(null),
            "state" to st, "maxAgeSec" to Json.Num("300"),
        )
        val r = Signals.receiveSET(set, txPub, opts)
        assertTrue(r.reason, r.ok)
        assertTrue(Signals.isRevoked(st, "g1", null))
        assertFalse(Signals.receiveSET(set, txPub, opts).ok)
    }
}
