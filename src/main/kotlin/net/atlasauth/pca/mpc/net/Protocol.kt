package net.atlasauth.pca.mpc.net

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.TreeMap
import net.atlasauth.pca.mpc.Compose.ComposedDecision
import net.atlasauth.pca.mpc.Field
import net.atlasauth.pca.mpc.Field.FieldRng
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fsub
import net.atlasauth.pca.mpc.FieldSource
import net.atlasauth.pca.mpc.NetCodec
import net.atlasauth.pca.mpc.NetForensics
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure
import net.atlasauth.pca.mpc.NetPa
import net.atlasauth.pca.mpc.NetPa.AW
import net.atlasauth.pca.mpc.NetPa.PA
import net.atlasauth.pca.mpc.NetPa.PaEnv
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.NetWire.hx
import net.atlasauth.pca.mpc.NetWire.unhxArray
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.mpc.Spdz.DealerFault
import net.atlasauth.pca.mpc.Thermometer
import net.atlasauth.pca.verifier.Json

/**
 * The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol: same circuit and semantics as the in-process runner
 * (allow = AND, t = MAX, r = MAX via thermometers, authenticated Beaver multiplication, batched MAC-check before any output),
 * but each party is its own node holding only its own shares and every opening is a message over the TLS [Mesh].
 * Rounds: prep, coin1-*, sac-rho, sac-tau, inputs (or in-check), mul0.., out, the pairwise tag rounds (dealer mode), coin-c/o,
 * sig-c/o, digest, and on a failed MAC-check a blame round. No output is decoded until the MAC-check and the transcript echo pass.
 *
 * Offline modes: `trusted-dealer` (a separate node that knows every share and key; a dealer that gives a wrong triple is
 * detected by the sacrifice, one that deals inconsistent MACs is named by the blame round) and `no-dealer`
 * (the parties derive everything from OT). In both modes shares are pairwise-authenticated so an online lie is attributable.
 * There is no security proof; the echo is a hash exchange, not Byzantine agreement; the dealer is trusted for privacy.
 */
object Protocol {
    const val T_M = 3
    internal const val DEFAULT_Q = 100
    private const val PREP_CHUNK = 30_000
    private val HEX64 = Regex("^[0-9a-f]{64}$")

    @JvmStatic fun chainCount(q: Int): Int = 1 + T_M + q

    /** Thrown by the test-only `silent` behaviour; the host then idles with its sockets open. */
    class SilentParty : RuntimeException("silent")

    /** Thrown by the test-only `crash` behaviour; the host closes the node abruptly. */
    class CrashParty : RuntimeException("crash")

    /** Test-only protocol-level misbehaviour (kind: open-lie, mac-lie, bad-tag, sigma-lie, offline-lie, ot-u-lie, ot-proof-lie, equivocate, bad-coin-open, bad-sigma-open, short-array, noncanonical, crash, silent). */
    class Behavior(val kind: String, val round: String?)

    class RoundStat(val rd: String, val ms: Double, val bytesOut: Long, val bytesIn: Long)

    class PartyResult(
        val id: Int, val n: Int, val Q: Int, val composed: ComposedDecision, val rounds: List<RoundStat>, val transcriptDigest: String, val wallMs: Double,
        val multiplications: Int, val opens: Int, val offlineMode: String, val macKeys: Int, val sacrificedTriples: Int, val sacrificePartners: Int,
        val identifiableAbort: Boolean,
    )

    /** What an offline-phase implementation receives from the online driver. */
    class OfflineCtx(
        val mesh: Mesh, val id: Int, val n: Int, val C: Int, val keys: Int, val partners: Int, val sessionId: String, val input: DecisionVector, val Q: Int,
        val behavior: Behavior?, val io: Exchanger, val crashIf: (String) -> Unit,
    )

    /** The no-dealer offline phase: produces this party's [Prep]. */
    fun interface OfflineRunner { fun run(ctx: OfflineCtx): Prep }

    class DealerConfig {
        /** Required true: the dealer sees every share and MAC key. */
        @JvmField var insecureTrustedDealer: Boolean = false
        @JvmField var n: Int = 0
        @JvmField var Q: Int? = null
        @JvmField var mesh: Mesh? = null
        /** Deterministic stream for reproducible tests; null means the CSPRNG. */
        @JvmField var seed: BigInteger? = null
        /** TEST ONLY: a LYING dealer that authenticates a wrong product. */
        @JvmField var fault: DealerFault? = null
        /** TEST ONLY: a dealer that gives party 0 a wrong MAC share for this input mask number. */
        @JvmField var macFaultAtInput: Int? = null
    }

    class PartyConfig {
        @JvmField var id: Int = 0
        @JvmField var n: Int = 0
        @JvmField var Q: Int? = null
        @JvmField var input: DecisionVector? = null
        @JvmField var mesh: Mesh? = null
        /** Node id of the dealer (default n). */
        @JvmField var dealerId: Int? = null
        /** "no-dealer" (default) or "trusted-dealer" (which also needs insecureTrustedDealer). */
        @JvmField var offline: String? = "no-dealer"
        @JvmField var insecureTrustedDealer: Boolean = false
        @JvmField var behavior: Behavior? = null
        @JvmField var unsafeTestHooks: Boolean = false
        @JvmField var sessionId: String? = null
        @JvmField var forensicDeadlineMs: Int? = null
        /** The no-dealer offline phase; null selects the default implementation. */
        @JvmField var offlineRunner: OfflineRunner? = null
    }

    private fun intOf(o: Any?): Int {
        if (o !is Json.Num) return Int.MIN_VALUE
        val d = o.toString().toDoubleOrNull() ?: return Int.MIN_VALUE
        return if (d == Math.rint(d) && Math.abs(d) < 1e9) d.toInt() else Int.MIN_VALUE
    }

    private fun prepLayout(n: Int, c: Int, keys: Int, partners: Int, tagged: Boolean): IntArray {
        val aw = NetPa.awWidth(n, keys, tagged)
        val triples = (n - 1) * c
        val inputs = n * c
        val nums = (if (tagged) 1 else 0) + keys * NetPa.paWidth(n, tagged) + triples * NetCodec.sharingsPerTriple(partners) * aw + inputs * aw + c
        return intArrayOf(nums, triples, inputs)
    }

    // ---------------------------------------------------------------------------------------------- dealer

    private fun dealPA(x: Array<BigInteger>, deltas: Array<BigInteger>, rng: FieldSource): Array<PA> {
        val n = x.size
        val k = Array(n) { i -> Array(n) { j -> if (i == j) BigInteger.ZERO else rng.next() } }
        return Array(n) { p ->
            val tag = Array(n) { j -> if (j == p) BigInteger.ZERO else fadd(k[p][j], fmul(deltas[j], x[p])) }
            val key = Array(n) { j -> if (j == p) BigInteger.ZERO else k[j][p] }
            PA(x[p], tag, key)
        }
    }

    private fun dealAW(sv: AuthSV, deltas: Array<BigInteger>, rng: FieldSource): Array<AW> {
        val n = sv.value.size
        val comps = ArrayList<Array<BigInteger>>()
        comps.add(sv.value)
        comps.add(sv.mac)
        comps.addAll(sv.extraMac)
        val dealt = ArrayList<Array<PA>>()
        for (c in comps) dealt.add(dealPA(c, deltas, rng))
        return Array(n) { p -> AW(dealt[0][p], Array(dealt.size - 1) { l -> dealt[l + 1][p] }) }
    }

    /**
     * The TRUSTED DEALER role: samples the MAC keys, verification keys, sacrifice-certified authenticated triples and input
     * masks, and ships each party only its own slice. It never sees an input bit, but it knows every key and share.
     */
    @JvmStatic fun runDealer(cfg: DealerConfig) {
        val n = cfg.n
        val mesh = cfg.mesh ?: throw IllegalArgumentException("runDealer requires a mesh")
        require(cfg.insecureTrustedDealer) { "runDealer requires insecureTrustedDealer (a dealer sees every share and MAC key; the default offline phase has no dealer)" }
        val q = cfg.Q ?: DEFAULT_Q
        val seed = cfg.seed
        val rng: FieldSource = if (seed != null) FieldRng(seed) else Field.SecureFieldRng()
        val c = chainCount(q)
        val ctx = Spdz.setupMac(n, rng, Spdz.MAC_KEYS)
        val keys = Spdz.macKeys(ctx)
        val deltas = Array<BigInteger>(n) { BigInteger.ZERO }
        for (i in 0 until n) {
            var d = rng.next()
            while (d.signum() == 0) d = rng.next()
            deltas[i] = d
        }
        val perParty = ArrayList<ArrayList<BigInteger>>()
        for (p in 0 until n) {
            perParty.add(ArrayList())
            perParty[p].add(deltas[p])
        }
        val alphaPA = ArrayList<Array<PA>>()
        for (k in keys) alphaPA.add(dealPA(k.alphaShares, deltas, rng))
        for (p in 0 until n) for (a in alphaPA) perParty[p].addAll(NetPa.paFlat(a[p], p, n, true))

        val nTriples = (n - 1) * c
        for (t in 0 until nTriples) {
            val tr = Spdz.genTripleWithPartners(ctx, rng, Spdz.SACRIFICE_PARTNERS, cfg.fault)
            val sharings = ArrayList<AuthSV>()
            sharings.add(tr.keep.a)
            sharings.add(tr.keep.b)
            sharings.add(tr.keep.c)
            for (qt in tr.partners) {
                sharings.add(qt.a)
                sharings.add(qt.c)
            }
            for (sv in sharings) {
                val aws = dealAW(sv, deltas, rng)
                for (p in 0 until n) perParty[p].addAll(NetPa.awFlat(aws[p], p, n, true))
            }
        }
        val masksByOwner = ArrayList<ArrayList<BigInteger>>()
        for (p in 0 until n) masksByOwner.add(ArrayList())
        for (qi in 0 until n * c) {
            val owner = qi / c
            val r = rng.next()
            masksByOwner[owner].add(r)
            val sv = Spdz.authShare(r, ctx, rng)
            if (cfg.macFaultAtInput == qi) sv.mac[0] = fadd(sv.mac[0], BigInteger.ONE)
            val aws = dealAW(sv, deltas, rng)
            for (p in 0 until n) perParty[p].addAll(NetPa.awFlat(aws[p], p, n, true))
        }
        for (p in 0 until n) perParty[p].addAll(masksByOwner[p])

        for (p in 0 until n) {
            val nums = ArrayList<String>()
            for (b in perParty[p]) nums.add(hx(b))
            val chunks = Math.max(1, (nums.size + PREP_CHUNK - 1) / PREP_CHUNK)
            val first = LinkedHashMap<String, Any?>()
            first["total"] = nums.size
            first["chunks"] = chunks
            first["nums"] = ArrayList<Any?>(nums.subList(0, Math.min(PREP_CHUNK, nums.size)))
            mesh.send(p, "prep", first)
            for (ci in 1 until chunks) mesh.send(p, "prep.$ci", ArrayList<Any?>(nums.subList(ci * PREP_CHUNK, Math.min((ci + 1) * PREP_CHUNK, nums.size))))
        }
        mesh.finish()
    }

    // ---------------------------------------------------------------------------------------------- party

    private fun sha(vararg parts: Any): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (p in parts) {
            h.update(if (p is ByteArray) p else Json.utf8((p as String)))
            h.update(0.toByte())
        }
        return h.digest()
    }

    private fun hex(b: ByteArray): String = NetHex.enc(b)

    /** Uniform non-zero field element [j] of the public challenge stream [label] derived from [seed]. */
    @JvmStatic internal fun challenge(seed: ByteArray, label: String, j: Int): BigInteger {
        var ctr = 0
        while (true) {
            val h = sha("chal", seed, "$label:$j:$ctr")
            val x = ByteBuffer.wrap(h).getLong(0) and ((1L shl 61) - 1)
            if (x != 0L && x != (1L shl 61) - 1) return BigInteger.valueOf(x)
            ctr++
        }
    }

    private class Opened(val value: BigInteger, val mac: Array<PA>)

    private class Blame(val g: Array<BigInteger>, val gt: Array<BigInteger>, val a: Array<BigInteger>, val at: Array<BigInteger>)

    @JvmStatic fun runParty(cfg: PartyConfig): PartyResult = PartyRun(cfg).run()

    private class PartyRun(val cfg: PartyConfig) : Exchanger {
        val id: Int = cfg.id
        val n: Int = cfg.n
        val q: Int = cfg.Q ?: DEFAULT_Q
        val dealerId: Int = cfg.dealerId ?: cfg.n
        val c: Int = chainCount(q)
        val kKeys: Int = Spdz.MAC_KEYS
        val partners: Int = Spdz.SACRIFICE_PARTNERS
        val mesh: Mesh = cfg.mesh ?: throw NetAbort("local", null, cfg.id, "no mesh configured")
        val sessionId: String = cfg.sessionId ?: throw NetAbort("local", null, cfg.id, "no session id configured")
        val offlineMode: String = cfg.offline ?: "no-dealer"
        val beh: Behavior? = cfg.behavior
        val t0: Long = System.nanoTime()
        val rounds = ArrayList<RoundStat>()
        val transcript = ByteArrayOutputStream()
        val others = ArrayList<Int>()
        val opened = ArrayList<Opened>()
        lateinit var prep: Prep
        lateinit var env: PaEnv

        init {
            for (i in 0 until n) if (i != id) others.add(i)
        }

        fun totals(): LongArray {
            var o = 0L
            var i = 0L
            for (s in mesh.stats()) {
                o += s.appBytesOut
                i += s.appBytesIn
            }
            return longArrayOf(o, i)
        }

        fun crashIf(rd: String) {
            val b = beh
            if (b != null && rd == b.round) {
                if (b.kind == "crash") throw CrashParty()
                if (b.kind == "silent") throw SilentParty()
            }
        }

        fun at(kind: String, rd: String): Boolean {
            val b = beh
            return b != null && kind == b.kind && rd == b.round
        }

        override fun bad(p: Int, what: String): NetAbort = NetAbort("malformed", p, id, what)

        fun abort(e: NetAbort): NetAbort {
            mesh.fail(e, null)
            return e
        }

        fun arr(p: Int, raw: Any?, len: Int): Array<BigInteger> = unhxArray(raw, len) ?: throw bad(p, "expected $len canonical field elements")

        override fun <T> exchange(rd: String, mine: (Int) -> Any?, parse: (Int, Any?) -> T, timeoutMs: Long?): Map<Int, T> =
            round(rd, mine, parse, null, false, timeoutMs)

        /** One all-to-all round; `hashed = false` keeps a round (peer-specific tags, forensics) out of the echoed transcript. */
        fun <T> round(rd: String, mine: (Int) -> Any?, parse: (Int, Any?) -> T, common: Any?, hashed: Boolean, timeoutMs: Long?): Map<Int, T> {
            crashIf(rd)
            val a = totals()
            val s = System.nanoTime()
            for (p in others) mesh.send(p, rd, mine(p))
            val raw: Map<Int, Any?> = mesh.collect(rd, others, timeoutMs)
            val parsed = TreeMap<Int, T>()
            for (p in others) {
                try {
                    parsed[p] = parse(p, raw[p])
                } catch (e: NetAbort) {
                    mesh.fail(e, null)
                    throw e
                } catch (e: RuntimeException) {
                    val ne = NetAbort("malformed", p, id, "round '$rd': ${e.message}")
                    mesh.fail(ne, null)
                    throw ne
                }
            }
            if (hashed) {
                // transcript: party order, canonical JSON of what each party broadcast in this round
                val rb = Json.utf8(rd)
                transcript.write(rb, 0, rb.size)
                for (p in 0 until n) {
                    val pb = Json.utf8(("|" + p + ":" + NetWire.stringify(if (p == id) common else raw[p])))
                    transcript.write(pb, 0, pb.size)
                }
            }
            val b = totals()
            rounds.add(RoundStat(rd, (System.nanoTime() - s) / 1e6, b[0] - a[0], b[1] - a[1]))
            return parsed
        }

        // ---- trusted-dealer prep ----
        fun receiveDealerPrep(): Prep {
            val lay = prepLayout(n, c, kKeys, partners, true)
            val firstRaw = mesh.recv(dealerId, "prep")
            val nums = ArrayList<BigInteger>()
            try {
                val first = firstRaw as? Map<*, *>
                if (first == null || intOf(first["total"]) != lay[0]) throw bad(dealerId, "bad prep size")
                val chunks = intOf(first["chunks"])
                if (chunks != Math.max(1, (lay[0] + PREP_CHUNK - 1) / PREP_CHUNK)) throw bad(dealerId, "bad prep chunk count")
                nums.addAll(take(first["nums"], Math.min(PREP_CHUNK, lay[0])))
                for (ci in 1 until chunks) {
                    val part = mesh.recv(dealerId, "prep.$ci")
                    nums.addAll(take(part, Math.min(PREP_CHUNK, lay[0] - ci * PREP_CHUNK)))
                }
            } catch (e: NetAbort) {
                throw abort(e)
            } catch (e: RuntimeException) {
                throw abort(NetAbort("malformed", dealerId, id, e.message.toString()))
            }
            var o = 0
            val delta = nums[o++]
            if (delta.signum() == 0) throw abort(NetAbort("dealer", dealerId, id, "the dealer gave me a zero verification key"))
            val w = NetPa.paWidth(n, true)
            val alpha = Array(kKeys) { _ ->
                val a = NetPa.paParse(nums, o, id, n, true)
                o += w
                a
            }
            val aw = NetPa.awWidth(n, kKeys, true)
            val spt = NetCodec.sharingsPerTriple(partners)
            val triples = Array(lay[1]) { _ ->
                Array(spt) { _ ->
                    val x = NetPa.awParse(nums, o, id, n, kKeys, true)
                    o += aw
                    x
                }
            }
            val inputs = Array(lay[2]) { _ ->
                val x = NetPa.awParse(nums, o, id, n, kKeys, true)
                o += aw
                x
            }
            val myPlain = nums.subList(o, o + c).toTypedArray()
            return Prep("trusted-dealer", true, delta, alpha, triples, inputs, myPlain, null, null)
        }

        fun take(raw: Any?, len: Int): List<BigInteger> = (unhxArray(raw, len) ?: throw bad(dealerId, "bad prep numbers")).asList()

        fun addPub(x: AW, k: BigInteger): AW = NetPa.wAddPublic(env, x, k, prep.alpha)

        fun not(x: AW): AW = addPub(NetPa.wNeg(x), BigInteger.ONE)

        /** Open authenticated values: broadcast value shares, verify pairwise tags (dealer mode), record for the MAC-check. */
        fun openMany(rd: String, ws: Array<AW>): Array<BigInteger> {
            val sendVals = Array(ws.size) { ws[it].v.x }
            val macs = Array(ws.size) { ws[it].m }
            val b = beh
            if (b != null && rd == b.round) {
                if (b.kind == "open-lie") sendVals[0] = fadd(sendVals[0], BigInteger.ONE)
                if (b.kind == "mac-lie") {
                    val m0 = macs[0].clone()
                    m0[0] = PA(fadd(m0[0].x, BigInteger.ONE), m0[0].tag, m0[0].key)
                    macs[0] = m0
                }
            }
            val common = ArrayList<Any?>()
            for (v in sendVals) common.add(hx(v))
            val mineFn: (Int) -> Any? = { peer ->
                if (at("equivocate", rd) && peer == others[0]) {
                    val cm = ArrayList<Any?>(common)
                    cm[0] = hx(fadd(BigInteger(common[0] as String, 16), BigInteger.ONE))
                    cm
                } else if (at("short-array", rd)) {
                    ArrayList<Any?>(common.subList(1, common.size))
                } else if (at("noncanonical", rd)) {
                    val cm = ArrayList<Any?>(common)
                    cm[0] = hx(Field.PRIME)
                    cm
                } else {
                    common
                }
            }
            val got: Map<Int, Array<BigInteger>> = round(rd, mineFn, { p, raw -> arr(p, raw, ws.size) }, common, true, null)
            if (prep.tagged) {
                // pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
                val tagMsg: (Int) -> Any? = { peer ->
                    val t = ArrayList<Any?>()
                    for (i in ws.indices) {
                        val tag = ws[i].v.tag[peer]
                        t.add(hx(if (at("bad-tag", rd) && i == 0) fadd(tag, BigInteger.ONE) else tag))
                    }
                    t
                }
                val tags: Map<Int, Array<BigInteger>> = round(rd + ".t", tagMsg, { p, raw -> arr(p, raw, ws.size) }, null, false, null)
                for (p in others) {
                    for (i in ws.indices) {
                        if (!NetPa.paVerify(env, ws[i].v, p, got[p]!![i], tags[p]!![i])) {
                            throw abort(NetAbort("mac-check", p, id,
                                "pairwise MAC on party $p's opened share failed in round '$rd' (index $i): the share or its tag is not what the dealer issued"))
                        }
                    }
                }
            }
            val out = Array<BigInteger>(ws.size) { BigInteger.ZERO }
            for (i in ws.indices) {
                var sum = sendVals[i]
                for (p in others) sum = fadd(sum, got[p]!![i])
                out[i] = sum
                opened.add(Opened(sum, macs[i]))
            }
            return out
        }

        /** Commit / open of a random seed, giving a joint public seed. */
        fun coin(label: String, tamperOpen: Boolean): ByteArray {
            val mySeed = ByteArray(32)
            SecureRandom().nextBytes(mySeed)
            val seedCommit = hex(sha("seed", sessionId, label, id.toString(), mySeed))
            val seedCommits: Map<Int, String> = round(label + "-c", { _ -> seedCommit }, { p, raw ->
                if (raw is String && HEX64.matches(raw)) raw else throw bad(p, "bad commitment")
            }, seedCommit, true, null)
            val openMsg: (Int) -> Any? = { _ ->
                if (tamperOpen && beh != null && beh.kind == "bad-coin-open") {
                    val r = ByteArray(32)
                    SecureRandom().nextBytes(r)
                    hex(r)
                } else {
                    hex(mySeed)
                }
            }
            val seeds: Map<Int, ByteArray> = round(label + "-o", openMsg, { p, raw ->
                if (raw !is String || !HEX64.matches(raw)) throw bad(p, "bad seed")
                val sd = NetHex.dec(raw)
                if (hex(sha("seed", sessionId, label, p.toString(), sd)) != seedCommits[p]) {
                    throw NetAbort("commitment", p, id, "party $p opened a coin seed that does not match its commitment")
                }
                sd
            }, hex(mySeed), true, null)
            val parts = ArrayList<Any>()
            parts.add("joint")
            parts.add(sessionId)
            parts.add(label)
            for (p in 0 until n) parts.add(if (p == id) mySeed else seeds[p]!!)
            return sha(*parts.toTypedArray())
        }

        fun sigCommit(p: Int, s: Array<BigInteger>, nonce: ByteArray): String =
            hex(sha("sigma", sessionId, p.toString(), s.joinToString(",") { hx(it) }, nonce))

        fun bitOf(x: BigInteger): BigInteger = if (x == BigInteger.ONE) BigInteger.ONE else BigInteger.ZERO

        // inputs state
        var masked: Array<BigInteger> = emptyArray()
        var gotMasked: Map<Int, Array<BigInteger>> = emptyMap()

        fun bitShare(owner: Int, k: Int): AW {
            if (prep.mode == "trusted-dealer") {
                val pub = if (owner == id) masked[k] else gotMasked[owner]!![k]
                return addPub(prep.inputs[owner * c + k], pub)
            }
            return prep.inputs[owner * c + k]
        }

        fun hexList(xs: Array<BigInteger>): List<Any?> {
            val out = ArrayList<Any?>()
            for (x in xs) out.add(hx(x))
            return out
        }

        fun run(): PartyResult {
            if (offlineMode == "trusted-dealer" && !cfg.insecureTrustedDealer) {
                throw NetAbort("local", null, id, "offline 'trusted-dealer' requires insecureTrustedDealer (the dealer sees every share and key); the default is 'no-dealer'")
            }
            if (beh != null && !cfg.unsafeTestHooks) throw NetAbort("local", null, id, "the behavior test hook requires unsafeTestHooks (test-only)")
            if (n < 1) throw NetAbort("local", null, id, "n must be >= 1")
            val v = cfg.input
            if (v == null || (v.allow != 0 && v.allow != 1) || v.t < 1 || v.t > 3 || v.rQuant < 0 || v.rQuant > q) {
                throw NetAbort("local", null, id, "invalid decision vector")
            }

            // ---- offline phase ----
            crashIf("prep")
            val prepStart = System.nanoTime()
            val before = totals()
            if (offlineMode == "trusted-dealer") {
                prep = receiveDealerPrep()
            } else {
                val runner = cfg.offlineRunner ?: OfflineRunner { ctx -> OfflineNet.run(ctx) }
                prep = runner.run(OfflineCtx(mesh, id, n, c, kKeys, partners, sessionId, v, q, beh, this) { rd -> crashIf(rd) })
            }
            val afterPrep = totals()
            rounds.add(RoundStat("prep", (System.nanoTime() - prepStart) / 1e6, afterPrep[0] - before[0], afterPrep[1] - before[1]))
            env = PaEnv(id, n, prep.delta, prep.tagged)

            // ---- sacrifice: certify every triple against its partners before it is used ----
            val nT = prep.triples.size
            if (nT > 0) sacrifice(nT)

            // ---- inputs ----
            val therm = Thermometer.thermometerEncode(v.t.toDouble(), T_M)
            val rtherm = Thermometer.thermometerEncode(v.rQuant.toDouble(), q)
            val myBits = Array<BigInteger>(c) { BigInteger.ZERO }
            myBits[0] = BigInteger.valueOf(v.allow.toLong())
            for (i in 0 until T_M) myBits[1 + i] = BigInteger.valueOf(therm[i].toLong())
            for (i in 0 until q) myBits[1 + T_M + i] = BigInteger.valueOf(rtherm[i].toLong())
            if (prep.mode == "trusted-dealer") {
                val m = Array<BigInteger>(c) { BigInteger.ZERO }
                val maskedMsg = ArrayList<Any?>()
                for (k in 0 until c) {
                    m[k] = fsub(myBits[k], prep.myPlain[k])
                    maskedMsg.add(hx(m[k]))
                }
                masked = m
                gotMasked = round("inputs", { _ -> maskedMsg }, { p, raw -> arr(p, raw, c) }, maskedMsg, true, null)
            } else {
                // No-dealer: inputs are already authenticated sharings; MASCOT input-consistency check (joins the batched MAC-check).
                val jointIn = coin("coin-in", false)
                var w = prep.checkMask ?: throw NetAbort("local", null, id, "the offline phase gave no input-check mask")
                for (qi in 0 until n * c) w = NetPa.wAdd(w, NetPa.wScale(prep.inputs[qi], challenge(jointIn, "in", qi)))
                openMany("in-check", arrayOf(w))
            }

            // ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
            var acc = Array(c) { ci ->
                val b0 = bitShare(0, ci)
                if (ci != 0) not(b0) else b0
            }
            var mults = 0
            for (s in 1 until n) {
                val trs = Array(c) { ci -> prep.triples[(s - 1) * c + ci] }
                val ds = ArrayList<AW>()
                val es = ArrayList<AW>()
                for (ci in 0 until c) {
                    val b = bitShare(s, ci)
                    val y = if (ci != 0) not(b) else b
                    ds.add(NetPa.wSub(acc[ci], trs[ci][0]))
                    es.add(NetPa.wSub(y, trs[ci][1]))
                }
                val both = (ds + es).toTypedArray()
                val pub = openMany("mul" + (s - 1), both)
                acc = Array(c) { ci ->
                    val d = pub[ci]
                    val e = pub[c + ci]
                    val z = NetPa.wAdd(trs[ci][2], NetPa.wAdd(NetPa.wScale(trs[ci][1], d), NetPa.wScale(trs[ci][0], e)))
                    addPub(z, fmul(d, e))
                }
                mults += c
            }

            // ---- outputs: allow as-is; or-chains are NOT of the product ----
            val outShares = Array(c) { ci -> if (ci != 0) not(acc[ci]) else acc[ci] }
            val outVals = openMany("out", outShares)

            // ---- MAC-check ----
            val joint = coin("coin", true)
            val aPub = Array<BigInteger>(kKeys) { BigInteger.ZERO }
            val gamma = Array<BigInteger>(kKeys) { BigInteger.ZERO }
            val sigma = Array<BigInteger>(kKeys) { BigInteger.ZERO }
            for (l in 0 until kKeys) {
                var a = BigInteger.ZERO
                var g = BigInteger.ZERO
                for (j in opened.indices) {
                    val ch = challenge(joint, "mac$l", j)
                    a = fadd(a, fmul(ch, opened[j].value))
                    g = fadd(g, fmul(ch, opened[j].mac[l].x))
                }
                aPub[l] = a
                gamma[l] = g
                sigma[l] = fsub(g, fmul(prep.alpha[l].x, a))
            }
            val sigNonce = ByteArray(32)
            SecureRandom().nextBytes(sigNonce)
            val sigmaSent = sigma.clone()
            if (beh != null && beh.kind == "sigma-lie") sigmaSent[0] = fadd(sigmaSent[0], BigInteger.ONE)
            val mySigCommit = sigCommit(id, sigmaSent, sigNonce)
            val sigCommits: Map<Int, String> = round("sig-c", { _ -> mySigCommit }, { p, raw ->
                if (raw is String && HEX64.matches(raw)) raw else throw bad(p, "bad commitment")
            }, mySigCommit, true, null)
            val mySigOpen = LinkedHashMap<String, Any?>()
            mySigOpen["s"] = hexList(sigmaSent)
            mySigOpen["nonce"] = hex(sigNonce)
            val sigOpens: Map<Int, Array<BigInteger>> = round("sig-o", { _ ->
                if (beh != null && beh.kind == "bad-sigma-open") {
                    val s2 = sigmaSent.clone()
                    s2[0] = fadd(s2[0], BigInteger.ONE)
                    linkedMapOf<String, Any?>("s" to hexList(s2), "nonce" to mySigOpen["nonce"])
                } else {
                    mySigOpen
                }
            }, { p, raw ->
                val o = raw as? Map<*, *> ?: throw bad(p, "bad sigma opening")
                val sv = unhxArray(o["s"], kKeys)
                val nonce = o["nonce"]
                if (sv == null || nonce !is String || !HEX64.matches(nonce)) throw bad(p, "bad sigma opening")
                if (sigCommit(p, sv, NetHex.dec(nonce)) != sigCommits[p]) {
                    throw NetAbort("commitment", p, id, "party $p opened a MAC residual that does not match its commitment")
                }
                sv
            }, mySigOpen, true, null)
            var macFailed = false
            for (l in 0 until kKeys) {
                var r = sigmaSent[l]
                for (p in others) r = fadd(r, sigOpens[p]!![l])
                if (r.signum() != 0) macFailed = true
            }

            // ---- transcript echo: everyone must have seen the same broadcasts ----
            val digest = hex(MessageDigest.getInstance("SHA-256").digest(transcript.toByteArray()))
            val digests: Map<Int, String> = round("digest", { _ -> digest }, { p, raw ->
                if (raw is String && HEX64.matches(raw)) raw else throw bad(p, "bad digest")
            }, digest, true, null)
            for (p in others) {
                if (digest != digests[p]) throw abort(NetAbort("equivocation", p, id, "transcript digest of party $p differs from mine (a broadcast was inconsistent)"))
            }

            if (macFailed) blame(aPub, gamma, sigOpens, joint)

            // ---- only now decode ----
            val tBits = IntArray(T_M) { bitOf(outVals[1 + it]).toInt() }
            val rBits = IntArray(q) { bitOf(outVals[1 + T_M + it]).toInt() }
            val allow = bitOf(outVals[0]).toInt()
            val composed = ComposedDecision(allow, Math.min(3, Math.max(1, Thermometer.thermometerDecode(tBits))), Thermometer.thermometerDecode(rBits))
            mesh.finish()
            return PartyResult(id, n, q, composed, rounds, digest, (System.nanoTime() - t0) / 1e6, mults, opened.size, prep.mode, kKeys, nT, partners, prep.tagged)
        }

        fun sacrifice(nT: Int) {
            val p = partners
            val joint1 = coin("coin1", false)
            val rhoW = Array(nT * p) { idx ->
                val t = idx / p
                val r = idx % p
                val tr = prep.triples[t]
                val e = challenge(joint1, "sac", idx)
                NetPa.wSub(NetPa.wScale(tr[0], e), tr[3 + 2 * r])
            }
            val rho = openMany("sac-rho", rhoW)
            val tauW = Array(nT * p) { idx ->
                val t = idx / p
                val r = idx % p
                val tr = prep.triples[t]
                val e = challenge(joint1, "sac", idx)
                NetPa.wSub(NetPa.wSub(NetPa.wScale(tr[2], e), tr[3 + 2 * r + 1]), NetPa.wScale(tr[1], rho[idx]))
            }
            val tau = openMany("sac-tau", tauW)
            var badAt = -1
            for (i in tau.indices) if (tau[i].signum() != 0) { badAt = i; break }
            if (badAt < 0) return
            // Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a wrong operand.
            var attributed: Int? = null
            var note = ""
            val fx = if (prep.mode == "no-dealer") prep.forensics else null
            if (fx != null) {
                val bt = badAt / p
                val mine = fx.disclose(bt)
                // commit first, open only once every commitment is in hand; a late or absent party times out at the shared deadline
                val deadline = (cfg.forensicDeadlineMs ?: NetForensics.DEFAULT_FORENSIC_DEADLINE_MS).toLong()
                val got = Forensic.exchangeDisclosures(sessionId, id, n, bt, mine, fx.slots, fx.rows, deadline, this)
                val all = TreeMap<Int, List<SlotDisclosure>>(got)
                all[id] = mine
                val res = NetForensics.auditDisclosures(all, fx.gadget)
                attributed = NetForensics.blameFrom(id, res)
                note = if (attributed == null) {
                    " (OT transcript audit: ${res.pairBad.size} inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)"
                } else {
                    " (OT transcript audit names party $attributed)"
                }
            }
            val dealer = prep.mode == "trusted-dealer"
            val blamed: Int? = if (dealer) dealerId else (attributed ?: (if (n == 2) 1 - id else null))
            throw abort(NetAbort(
                if (dealer) "dealer" else "mac-check", blamed, id,
                "triple sacrifice FAILED at triple ${badAt / p} (partner ${badAt % p}): c != a*b in the offline material; aborting with no output$note",
                null, null,
                "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted as evidence)",
                null, null,
            ))
        }

        fun blame(aPub: Array<BigInteger>, gamma: Array<BigInteger>, sigOpens: Map<Int, Array<BigInteger>>, joint: ByteArray) {
            val msg = "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output"
            if (!prep.tagged) {
                throw abort(NetAbort("mac-check", if (n == 2) 1 - id else null, id, msg, null, null,
                    "this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)", null, null))
            }
            // every party opens its combined MAC shares with their pairwise tags; each verifier checks them
            val blameMsg: (Int) -> Any? = { peer ->
                val gt = ArrayList<Any?>()
                val a = ArrayList<Any?>()
                val at = ArrayList<Any?>()
                for (l in 0 until kKeys) {
                    var g = BigInteger.ZERO
                    for (j in opened.indices) g = fadd(g, fmul(challenge(joint, "mac$l", j), opened[j].mac[l].tag[peer]))
                    gt.add(hx(g))
                    a.add(hx(prep.alpha[l].x))
                    at.add(hx(prep.alpha[l].tag[peer]))
                }
                linkedMapOf<String, Any?>("g" to hexList(gamma), "gt" to gt, "a" to a, "at" to at)
            }
            // Abort claims arriving during this round are read in link order (see Mesh.setDeferAborts).
            mesh.setDeferAborts(true)
            val blames: Map<Int, Blame> = try {
                round("blame", blameMsg, { p, raw ->
                    val o: Map<*, *> = raw as? Map<*, *> ?: emptyMap<Any?, Any?>()
                    Blame(arr(p, o["g"], kKeys), arr(p, o["gt"], kKeys), arr(p, o["a"], kKeys), arr(p, o["at"], kKeys))
                }, null, false, null)
            } finally {
                mesh.setDeferAborts(false)
            }
            for (p in others) {
                val b = blames[p]!!
                for (l in 0 until kKeys) {
                    var keyCombo = BigInteger.ZERO
                    for (j in opened.indices) keyCombo = fadd(keyCombo, fmul(challenge(joint, "mac$l", j), opened[j].mac[l].key[p]))
                    if (fadd(keyCombo, fmul(env.delta, b.g[l])) != b.gt[l]) {
                        throw abort(NetAbort("mac-check", p, id, "$msg - party $p's MAC share (key $l) does not match its pairwise tag"))
                    }
                    if (fadd(prep.alpha[l].key[p], fmul(env.delta, b.a[l])) != b.at[l]) {
                        throw abort(NetAbort("mac-check", p, id, "$msg - party $p's key share (key $l) does not match its pairwise tag"))
                    }
                    if (fsub(b.g[l], fmul(b.a[l], aPub[l])) != sigOpens[p]!![l]) {
                        throw abort(NetAbort("mac-check", p, id, "$msg - party $p's opened MAC residual (key $l) is not what its authenticated shares give"))
                    }
                }
            }
            // Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
            if (prep.mode == "trusted-dealer") {
                throw abort(NetAbort("dealer", dealerId, id, "$msg - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"))
            }
            throw abort(NetAbort("mac-check", if (n == 2) 1 - id else null, id,
                "$msg - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable", null, null,
                "every party's shares verify under its pairwise tags, so the fault lies in the offline material, which names no party", null, null))
        }
    }
}
