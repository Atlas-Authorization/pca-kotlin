package net.atlasauth.pca.mpc.net

import net.atlasauth.pca.verifier.Json

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.Frame

/**
 * TEST-ONLY fault injection for the networked MPC. Two layers, deliberately separate:
 *  - [tamperFor]: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate, reorder, skipped
 *    sequence, garbage, truncation, wrong round/session, oversize length, drop, silence). The bytes still travel inside valid TLS,
 *    so the receiver's framing checks decide.
 *  - [FaultProxy]: a NETWORK adversary on the wire (TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at the
 *    byte level. TLS 1.3 record authentication rejects tampering, so the expected outcome is an attributable-to-the-link
 *    `disconnect`, never a silently corrupted value.
 */
enum class FrameFaultKind { DUPLICATE, REORDER, SKIP_SEQ, GARBAGE, TRUNCATE, BITFLIP, WRONG_ROUND, WRONG_SESSION, OVERSIZE, DROP, SILENT_FROM, EXTRA_FIELD, FALSE_ACCUSE }

/**
 * [round] is the protocol round to attack (e.g. "mul0"); [to] restricts to one recipient (default: all); [accuse] is, for
 * FALSE_ACCUSE, the (honest) party the malicious sender names in its forged abort frame.
 */
data class FrameFault(val kind: FrameFaultKind, val round: String, val to: Int? = null, val accuse: Int? = null)

object Faults {
    private fun lengthPrefixed(body: ByteArray): ByteArray {
        val o = ByteArray(4 + body.size)
        o[0] = (body.size ushr 24).toByte(); o[1] = (body.size ushr 16).toByte(); o[2] = (body.size ushr 8).toByte(); o[3] = body.size.toByte()
        System.arraycopy(body, 0, o, 4, body.size)
        return o
    }

    private fun seqPlusOne(f: Frame): Any? = (f.seq as? Number)?.let { it.toLong() + 1 } ?: f.seq

    /** The hook to install as [Mesh.Config.tamper] (with unsafeTestHooks) for one malicious sender. */
    @JvmStatic fun tamperFor(spec: FrameFault): (Mesh.TamperEvent) -> List<ByteArray> {
        val stash = ConcurrentHashMap<Int, ByteArray>()
        val silent = AtomicBoolean(false)
        return fun(ev: Mesh.TamperEvent): List<ByteArray> {
            if (silent.get()) return emptyList()
            val hit = ev.frame.rd == spec.round && (spec.to == null || spec.to == ev.to)
            if (spec.kind == FrameFaultKind.REORDER) {
                val held = stash.remove(ev.to)
                if (held != null) return listOf(ev.raw, held) // later frame first, then the held-back one
                if (hit) { stash[ev.to] = ev.raw; return emptyList() }
                return listOf(ev.raw)
            }
            if (!hit) return listOf(ev.raw)
            val fr = ev.frame
            return when (spec.kind) {
                FrameFaultKind.DUPLICATE -> listOf(ev.raw, ev.raw)
                FrameFaultKind.SKIP_SEQ -> listOf(NetWire.encodeFrame(Frame(fr.v, fr.ty, fr.sid, seqPlusOne(fr), fr.rd, fr.d)))
                FrameFaultKind.GARBAGE -> {
                    val g = ByteArray(ev.raw.size) { 0x5a }
                    val n = ev.raw.size - 4
                    g[0] = (n ushr 24).toByte(); g[1] = (n ushr 16).toByte(); g[2] = (n ushr 8).toByte(); g[3] = n.toByte()
                    listOf(g)
                }
                FrameFaultKind.TRUNCATE -> listOf(ev.raw.copyOfRange(0, maxOf(5, ev.raw.size / 2)))
                FrameFaultKind.BITFLIP -> {
                    val b = ev.raw.copyOf()
                    val i = (b.size * 0.6).toInt()
                    b[i] = (b[i].toInt() xor 0x04).toByte()
                    listOf(b)
                }
                FrameFaultKind.WRONG_ROUND -> listOf(NetWire.encodeFrame(Frame(fr.v, fr.ty, fr.sid, fr.seq, "zzz-" + fr.rd, fr.d)))
                FrameFaultKind.WRONG_SESSION -> listOf(NetWire.encodeFrame(Frame(fr.v, fr.ty, "not-this-session", fr.seq, fr.rd, fr.d)))
                FrameFaultKind.OVERSIZE -> listOf(byteArrayOf(0x7f, 0xff.toByte(), 0xff.toByte(), 0xff.toByte()))
                FrameFaultKind.DROP -> emptyList()
                FrameFaultKind.SILENT_FROM -> { silent.set(true); emptyList() }
                FrameFaultKind.FALSE_ACCUSE -> {
                    val d = LinkedHashMap<String, Any?>()
                    d["kind"] = "timeout"; d["blamed"] = spec.accuse ?: 0; d["detail"] = "forged accusation"
                    listOf(NetWire.encodeFrame(Frame(fr.v, "abort", fr.sid, fr.seq, "abort", d)))
                }
                FrameFaultKind.EXTRA_FIELD -> {
                    val m = LinkedHashMap<String, Any?>()
                    m["v"] = fr.v; m["ty"] = fr.ty; m["sid"] = fr.sid; m["seq"] = fr.seq; m["rd"] = fr.rd; m["d"] = fr.d; m["x"] = 1
                    listOf(lengthPrefixed(Json.utf8(NetWire.stringify(m))))
                }
                FrameFaultKind.REORDER -> listOf(ev.raw) // handled above
            }
        }
    }
}

enum class WireFaultKind { NONE, DROP, DELAY, TRUNCATE, BITFLIP, DUPLICATE, REORDER }

/** [dir] is "c2s" (client to server) or "s2c"; the fault starts after [afterBytes] bytes passed in that direction (skips the TLS handshake). */
data class WireFault(val kind: WireFaultKind, val dir: String, val afterBytes: Long, val ms: Long = 1000)

/** A transparent TCP proxy that misbehaves once, after `afterBytes` bytes, in one direction. */
class FaultProxy(private val listenPort: Int, private val target: Pair<String, Int>, private val fault: WireFault) {
    @JvmField val log: MutableList<String> = CopyOnWriteArrayList()
    private var server: ServerSocket? = null

    /** The port the proxy listens on (useful when [listenPort] was 0). */
    fun port(): Int = server?.localPort ?: -1

    fun listen() {
        val s = ServerSocket(listenPort, 50, InetAddress.getByName("127.0.0.1"))
        server = s
        Thread({
            while (!s.isClosed) {
                val c: Socket = try { s.accept() } catch (e: IOException) { break }
                Thread({ onClient(c) }, "fault-proxy-conn").also { it.isDaemon = true }.start()
            }
        }, "fault-proxy-accept").also { it.isDaemon = true }.start()
    }

    fun close() {
        try { server?.close() } catch (e: IOException) { /* already closed */ }
    }

    private fun onClient(c: Socket) {
        val up: Socket
        try { up = Socket(target.first, target.second) } catch (e: IOException) { closeQuietly(c); return }
        val a = Thread({ pipe(c, up, "c2s") }, "fault-proxy-c2s").also { it.isDaemon = true }
        val b = Thread({ pipe(up, c, "s2c") }, "fault-proxy-s2c").also { it.isDaemon = true }
        a.start(); b.start()
        Thread({
            try { a.join(); b.join() } catch (e: InterruptedException) { /* closing anyway */ }
            closeQuietly(c); closeQuietly(up)
        }, "fault-proxy-reap").also { it.isDaemon = true }.start()
    }

    private fun closeQuietly(s: Socket) {
        try { s.close() } catch (e: IOException) { /* gone */ }
    }

    private fun pipe(from: Socket, to: Socket, dir: String) {
        val f = fault
        val active = f.kind != WireFaultKind.NONE && f.dir == dir
        var seen = 0L
        var fired = false
        var done = false
        var held: ByteArray? = null
        val buf = ByteArray(64 * 1024)
        try {
            val input = from.getInputStream()
            val out = to.getOutputStream()
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                val chunk = buf.copyOf(n)
                val arrived = System.nanoTime() / 1_000_000L
                val before = seen
                seen += n
                if (!active || done || before + n <= f.afterBytes) {
                    if (active && f.kind == WireFaultKind.DROP && fired) continue // black hole stays black
                    out.write(chunk); out.flush()
                    continue
                }
                if (!fired) {
                    fired = true
                    log.add("fault ${f.kind.name.lowercase()} $dir after ${f.afterBytes}B")
                }
                when (f.kind) {
                    WireFaultKind.DROP -> {}
                    WireFaultKind.DELAY -> {
                        val wait = arrived + f.ms - System.nanoTime() / 1_000_000L
                        if (wait > 0) Thread.sleep(wait)
                        out.write(chunk); out.flush()
                    }
                    WireFaultKind.TRUNCATE -> {
                        done = true
                        out.write(chunk, 0, n / 2); out.flush()
                        to.shutdownOutput()
                    }
                    WireFaultKind.BITFLIP -> {
                        done = true
                        val b = chunk.copyOf()
                        b[b.size / 2] = (b[b.size / 2].toInt() xor 0x01).toByte()
                        out.write(b); out.flush()
                    }
                    WireFaultKind.DUPLICATE -> {
                        done = true
                        out.write(chunk); out.write(chunk); out.flush()
                    }
                    WireFaultKind.REORDER -> {
                        val h = held
                        if (h == null) {
                            held = chunk
                        } else {
                            done = true
                            out.write(chunk); out.write(h); out.flush()
                            held = null
                        }
                    }
                    WireFaultKind.NONE -> { out.write(chunk); out.flush() }
                }
            }
            val h = held
            if (h != null) { out.write(h); out.flush() }
            to.shutdownOutput()
        } catch (e: IOException) {
            closeQuietly(from); closeQuietly(to)
        } catch (e: InterruptedException) {
            closeQuietly(from); closeQuietly(to)
        }
    }
}
