package net.atlasauth.pca.mpc.net

import java.io.File
import java.io.IOException
import java.math.BigInteger
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz.DealerFault
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr
import net.atlasauth.pca.mpc.net.Protocol.Behavior
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig
import net.atlasauth.pca.mpc.net.Protocol.PartyResult
import net.atlasauth.pca.verifier.Json

/**
 * One MPC node (a party, the dealer, or one end of a base-OT demo) as its OWN OS process, talking to the others only over the
 * mutual-TLS mesh. Usage: `PartyMain <config.json>` or `PartyMain keygen <dir> <cn>`. Prints exactly one JSON line
 * (the result or the attributable abort) on stdout; exit code 3 on an abort. Test hooks need both `unsafeTestHooks` in the
 * config and the environment variable `PCA_MPC_UNSAFE_TEST_HOOKS=1`, else the node refuses to start.
 */
object PartyMain {
    @Suppress("UNCHECKED_CAST")
    private fun obj(o: Any?): Map<String, Any?> {
        require(o is Map<*, *>) { "config: object expected" }
        return o as Map<String, Any?>
    }

    private fun num(o: Any?, what: String): Int {
        require(o is Json.Num) { "config: $what must be a number" }
        val d = o.toString().toDouble()
        require(!(d != Math.rint(d) || Math.abs(d) > 1e9)) { "config: $what must be an integer" }
        return d.toInt()
    }

    private fun str(o: Any?, what: String): String {
        require(o is String) { "config: $what must be a string" }
        return o
    }

    private fun out(m: Map<String, Any?>) {
        println(NetWire.stringify(m))
    }

    private fun resultJson(r: PartyResult): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["id"] = r.id
        m["n"] = r.n
        m["Q"] = r.Q
        val c = LinkedHashMap<String, Any?>()
        c["allow"] = r.composed.allow
        c["t"] = r.composed.t
        c["rQuant"] = r.composed.rQuant
        m["composed"] = c
        m["transcriptDigest"] = r.transcriptDigest
        m["rounds"] = r.rounds.map { x ->
            val o = LinkedHashMap<String, Any?>()
            o["rd"] = x.rd
            o["ms"] = x.ms
            o["bytesOut"] = x.bytesOut
            o["bytesIn"] = x.bytesIn
            o
        }
        m["wallMs"] = r.wallMs
        m["multiplications"] = r.multiplications
        m["opens"] = r.opens
        m["offlineMode"] = r.offlineMode
        m["macKeys"] = r.macKeys
        m["sacrificedTriples"] = r.sacrificedTriples
        m["sacrificePartners"] = r.sacrificePartners
        m["identifiableAbort"] = r.identifiableAbort
        return m
    }

    private fun links(mesh: Mesh): List<Any?> = mesh.stats().map { s ->
        val m = LinkedHashMap<String, Any?>()
        m["peer"] = s.peer
        m["appBytesOut"] = s.appBytesOut
        m["appBytesIn"] = s.appBytesIn
        m["framesOut"] = s.framesOut
        m["framesIn"] = s.framesIn
        m
    }

    private fun abortJson(role: String, id: Int, e: NetAbort): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = false
        m["role"] = role
        m["id"] = id
        val er = LinkedHashMap<String, Any?>()
        er["kind"] = e.kind
        er["blamed"] = e.blamed
        er["reporter"] = e.reporter
        er["claimedKind"] = e.claimedKind
        er["claimedBlame"] = e.claimedBlame
        er["reason"] = e.reason
        if (e.evidence != null) er["evidence"] = e.evidence
        er["deadlineMs"] = e.deadlineMs
        er["message"] = e.message
        m["error"] = er
        return m
    }

    @JvmStatic
    fun main(argv: Array<String>) {
        System.exit(run(argv))
    }

    /** Runs the node and returns the process exit code (0 ok, 3 abort or refusal). */
    @JvmStatic
    @Throws(IOException::class)
    fun run(argv: Array<String>): Int {
        if (argv.size >= 3 && argv[0] == "keygen") {
            val ident = Certs.generate(argv[2])
            val dir = File(argv[1])
            dir.mkdirs()
            val keyFile = File(dir, "key.pem")
            val certFile = File(dir, "cert.pem")
            keyFile.writeText(ident.keyPem, Charsets.UTF_8)
            certFile.writeText(ident.certPem, Charsets.UTF_8)
            val m = LinkedHashMap<String, Any?>()
            m["keyPath"] = keyFile.path
            m["certPath"] = certFile.path
            out(m)
            return 0
        }
        require(argv.size == 1) { "usage: PartyMain <config.json> | keygen <dir> <cn>" }
        val cfg = obj(Json.parseLenient(File(argv[0]).readText(Charsets.UTF_8)))
        val role = str(cfg["role"], "role")
        val id = num(cfg["id"], "id")
        val hooksRequested = cfg.containsKey("behavior") || cfg.containsKey("frameFault") || cfg.containsKey("dealerFault")
        if (hooksRequested && !(cfg["unsafeTestHooks"] == true && System.getenv("PCA_MPC_UNSAFE_TEST_HOOKS") == "1")) {
            out(abortJson(role, id, NetAbort("local", null, id, "refusing to start: test hooks are not enabled in this environment")))
            return 3
        }
        var frameFault: FrameFault? = null
        if (cfg.containsKey("frameFault")) {
            try {
                val ff = obj(cfg["frameFault"])
                val kindName = str(ff["kind"], "frameFault.kind")
                val kind = FrameFaultKind.values().firstOrNull { it.name.lowercase().replace('_', '-') == kindName }
                    ?: throw IllegalArgumentException("config: unknown frameFault kind $kindName")
                frameFault = FrameFault(
                    kind, str(ff["round"], "frameFault.round"),
                    if (ff["to"] == null) null else num(ff["to"], "frameFault.to"),
                    if (ff["accuse"] == null) null else num(ff["accuse"], "frameFault.accuse"),
                )
            } catch (e: IllegalArgumentException) {
                out(abortJson(role, id, NetAbort("local", null, id, "refusing to start: " + e.message)))
                return 3
            }
        }
        val n = num(cfg["n"], "n")
        val nodes = ArrayList<NodeAddr>()
        val rawNodes = cfg["nodes"]
        require(rawNodes is List<*>) { "config: nodes must be an array" }
        for (o in rawNodes) {
            val x = obj(o)
            nodes.add(
                NodeAddr(
                    num(x["id"], "node id"), str(x["host"], "host"), num(x["port"], "port"),
                    File(str(x["certPath"], "certPath")).readText(Charsets.UTF_8),
                ),
            )
        }
        val mc = Mesh.Config()
        mc.selfId = id
        mc.nodes = nodes
        if (role == "dealer") mc.linkTo = nodes.filter { it.id < n }.map { it.id }
        mc.keyPem = File(str(cfg["keyPath"], "keyPath")).readText(Charsets.UTF_8)
        mc.certPem = File(str(cfg["certPath"], "certPath")).readText(Charsets.UTF_8)
        mc.sessionId = str(cfg["sessionId"], "sessionId")
        if (cfg["listenHost"] != null) mc.listenHost = str(cfg["listenHost"], "listenHost")
        if (cfg["recvTimeoutMs"] != null) mc.recvTimeoutMs = num(cfg["recvTimeoutMs"], "recvTimeoutMs").toLong()
        if (cfg["connectTimeoutMs"] != null) mc.connectTimeoutMs = num(cfg["connectTimeoutMs"], "connectTimeoutMs").toLong()
        if (hooksRequested) mc.unsafeTestHooks = true
        if (frameFault != null) mc.tamper = Faults.tamperFor(frameFault)
        val mesh = Mesh(mc)
        val startMs = System.currentTimeMillis()
        val q: Int? = if (cfg["Q"] == null) null else num(cfg["Q"], "Q")
        try {
            mesh.connect()
            val res = LinkedHashMap<String, Any?>()
            res["ok"] = true
            res["role"] = role
            res["id"] = id
            res["connectMs"] = System.currentTimeMillis() - startMs
            if (role == "dealer") {
                val d = DealerConfig()
                d.n = n
                d.Q = q
                d.mesh = mesh
                d.insecureTrustedDealer = cfg["insecureTrustedDealer"] == true
                if (cfg["dealerSeed"] != null) d.seed = BigInteger(str(cfg["dealerSeed"], "dealerSeed"))
                if (cfg["dealerFault"] != null) {
                    val df = obj(cfg["dealerFault"])
                    val keep = if (df["keepCDelta"] == null) null else BigInteger(str(df["keepCDelta"], "keepCDelta"))
                    var partners: List<BigInteger?>? = null
                    if (df["partnerCDelta"] != null) {
                        val raw = df["partnerCDelta"]
                        require(raw is List<*>) { "config: partnerCDelta must be an array" }
                        partners = raw.map { x -> if (x == null) null else BigInteger(str(x, "partnerCDelta")) }
                    }
                    d.fault = DealerFault(keep, partners)
                    if (df["macFaultAtInput"] != null) d.macFaultAtInput = num(df["macFaultAtInput"], "macFaultAtInput")
                }
                Protocol.runDealer(d)
            } else if (role == "ot-sender" || role == "ot-receiver") {
                val kind = if (cfg["ot"] == null) "ec" else str(obj(cfg["ot"])["kind"], "ot.kind")
                // the endemic-LWE variant lives in the Java lwe-ot adapter (a different Mesh class); never run it as ec
                if (kind != "ec") throw NetAbort("local", null, id, "ot kind '$kind' is not available in this build (only 'ec')")
                val count = if (cfg["ot"] == null) 128 else num(obj(cfg["ot"])["count"], "ot.count")
                val otStart = System.nanoTime()
                val r = if (role == "ot-sender") OtNet.runOtSender(mesh, 1, count) else OtNet.runOtReceiver(mesh, 0, count)
                val rm = LinkedHashMap<String, Any?>()
                rm["kind"] = kind
                rm["role"] = r.role
                rm["count"] = r.count
                rm["matched"] = r.matched
                rm["padDigest"] = r.padDigest
                rm["ms"] = (System.nanoTime() - otStart) / 1e6
                res["result"] = rm
            } else {
                val input = obj(cfg["input"])
                val c = PartyConfig()
                c.id = id
                c.n = n
                c.Q = q
                c.input = DecisionVector(num(input["allow"], "allow"), num(input["t"], "t"), num(input["rQuant"], "rQuant"))
                c.mesh = mesh
                if (cfg["offline"] != null) c.offline = str(cfg["offline"], "offline")
                c.insecureTrustedDealer = cfg["insecureTrustedDealer"] == true
                if (cfg["behavior"] != null) {
                    val b = obj(cfg["behavior"])
                    c.behavior = Behavior(str(b["kind"], "behavior.kind"), if (b["round"] == null) null else str(b["round"], "behavior.round"))
                    c.unsafeTestHooks = true
                }
                c.sessionId = mc.sessionId
                res["result"] = resultJson(Protocol.runParty(c))
            }
            res["links"] = links(mesh)
            res["events"] = ArrayList<Any?>(mesh.events())
            out(res)
            return 0
        } catch (e: Protocol.CrashParty) {
            // the test-only crash behaviour: exit abruptly with no output (hooks are gated above)
            Runtime.getRuntime().halt(7)
            return 7
        } catch (e: RuntimeException) {
            val f = mesh.failed()
            val ne = if (e is NetAbort) e else (f ?: NetAbort("local", null, id, e.message.toString()))
            val m = abortJson(role, id, ne)
            m["links"] = links(mesh)
            m["events"] = ArrayList<Any?>(mesh.events())
            out(m)
            return 3
        } finally {
            // give sockets a moment to flush abort frames
            try {
                Thread.sleep(300)
            } catch (ie: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            mesh.kill()
        }
    }
}
