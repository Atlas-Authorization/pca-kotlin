@file:JvmName("DurableStates")

package net.atlasauth.pca.durable

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.Json
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileAttribute
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Crash-safe, tamper-evident, multi-process-safe persistent key/value state (a faithful port of the reference `durable-state`; the
 * on-disk format is byte-compatible with the other lanes: a directory written by one lane opens in another).
 *
 * LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line), `state.head` (seq + hash of
 * the last record, written AFTER the journal), `state.lock.<g>` (the lock: immutable numbered generation files created atomically with
 * link(2) = [Files.createLink]), `state.fence*` (operator-recovery fences).
 *
 * GUARANTEES: every mutation is write-temp, fsync ([FileChannel.force]), rename, fsync(directory): a crash leaves the old or the new
 * journal, never a torn one, and the head trails by at most one record (repaired by the next writer). No lost updates across processes:
 * every mutation runs under the exclusive generation lock; a lock is taken over only from a PROVABLY dead holder on this host and PID
 * namespace, never by age; the generation is re-checked right before every rename. A holder that is only PAUSED across
 * [recoverDurableState] is fenced: every record and head carries the writer's generation, and the fence recovery wrote makes load refuse
 * a late record from a released generation. Records are hash-chained (and HMAC-tagged with `hmacKey`); a corrupt, truncated or
 * rolled-back state makes every operation throw [DurableStateError], never silently starting empty; the ONLY way past is
 * `recoverFromCorruption = true`, which quarantines the files (kept for forensics) and starts from genesis with `recovered` true.
 *
 * NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or in another namespace is never judged dead:
 * waiters time out, fail closed); a LOCAL filesystem with working hard links (probed at open: `link-unsupported`); a stalled live holder
 * blocks until it dies (`lock-timeout`); the journal is rewritten whole per mutation (small state) and compacted every `compactEvery`
 * records. A stored JSON `null` reads back as an absent key (the [AtomicKv] contract uses null for "absent").
 *
 * Platform: a JVM feature (java.nio.file); on Android it needs API 26+. Process liveness uses `java.lang.ProcessHandle` when the runtime
 * has it, else `/proc`; where neither can judge, a holder is treated as alive (never robbed).
 */
class DurableStateError(val code: String, detail: String) : RuntimeException("$code: $detail")

/** The holder an operator attests is gone: copied EXACTLY from a complete holder record of a lock file (or the lock-timeout error). */
class ExpectedLockHolder(val host: String, val pid: Long, val nonce: String)

/** A chain position: the sequence number and record hash of the last record. */
data class DurablePosition(val seq: Long, val hash: String)

class DurableStateOptions @JvmOverloads constructor(
    val dir: String,
    /** Optional >= 32-byte HMAC key: records and head are tagged; forging or re-chaining then needs the key. */
    val hmacKey: ByteArray? = null,
    /** Explicit recovery: quarantine corrupt/rolled-back files and start from genesis. Default false (fail closed). */
    val recoverFromCorruption: Boolean = false,
    /** Give up acquiring the lock after this long (default 10 s). */
    val lockTimeoutMs: Long = 10_000,
    /** Compact the journal into a checkpoint every N records (default 256, at least 2). */
    val compactEvery: Int = 256,
    /** Max serialised value size in UTF-16 units (default 1 MiB). */
    val maxValueBytes: Int = 1_048_576,
    /** Clock for record timestamps (default System.currentTimeMillis). */
    val now: (() -> Long)? = null,
    /** TEST ONLY: halt this process at the named point of a commit ("after-temp-write" | "after-journal-rename"). */
    val testCrashAt: String? = null,
)

class RecoverDurableStateOptions @JvmOverloads constructor(
    val dir: String,
    /** Must be literally true: this is an out-of-band operator action, never automatic. */
    val force: Boolean,
    /** An [ExpectedLockHolder] copied from a complete holder record, or the string "unreadable" for an unreadable/incomplete record. */
    val expectedHolder: Any?,
    /** Release the LEGACY single-file `state.lock` of an older version (moved aside, never deleted). */
    val legacyLock: Boolean = false,
)

class RecoverDurableStateResult(val released: Boolean, val reason: String, val lockFile: String? = null)

/** In-memory store with the same semantics and no durability (tests / one process). Values are kept as JSON text. */
class MemoryDurableKv : AtomicKv {
    private val m = HashMap<String, String>()

    private fun dec(s: String?): Any? = if (s == null) null else Json.parseLenient(s)

    private fun enc(v: Any?): String = try {
        Js.stringify(v)
    } catch (e: RuntimeException) {
        throw DurableStateError("invalid", "value is not JSON-serialisable")
    }

    @Synchronized override fun get(key: String): Any? = dec(m[key])

    @Synchronized override fun set(key: String, value: Any?) {
        m[key] = enc(value)
    }

    @Synchronized override fun update(key: String, fn: (Any?) -> Any?): Any? {
        val next = fn(dec(m[key]))
        if (next != null) m[key] = enc(next)
        return dec(m[key])
    }

    @Synchronized override fun keys(): List<String> = m.keys.sorted()

    /** Every stored value, parsed. */
    @Synchronized fun snapshot(): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for (k in m.keys.sorted()) out[k] = dec(m[k])
        return out
    }
}

fun createMemoryDurableKv(): MemoryDurableKv = MemoryDurableKv()

/** Open (creating if needed) a durable state directory. Throws [DurableStateError] on corrupt / rolled-back state unless recovering. */
fun openDurableState(opts: DurableStateOptions): DurableState = DurableState(opts)

/** Operator recovery for a lock whose holder cannot be judged dead automatically (see [DurableState.recover]). */
fun recoverDurableState(opts: RecoverDurableStateOptions): RecoverDurableStateResult = DurableState.recover(opts)

/** A durable state directory handle. Build with [openDurableState]. A handle is safe to share between threads (calls are serialised). */
class DurableState internal constructor(private val opts: DurableStateOptions) : AtomicKv {
    private class Rec(val seq: Long, val prev: String, val op: String, val payload: String, val ts: Long, val gen: Long?, val h: String, val mac: String?)

    private class Head(val seq: Long, val h: String, val gen: Long?, val mac: String?)

    private class Loaded(val recs: List<Rec>, val state: LinkedHashMap<String, String>, val head: Head?)

    private val dir: String = opts.dir
    private val key: ByteArray? = opts.hmacKey
    private val lockTimeout: Long = opts.lockTimeoutMs
    private val compactEvery: Int = maxOf(2, opts.compactEvery)
    private val maxValue: Int = opts.maxValueBytes
    private val clock: () -> Long = opts.now ?: { System.currentTimeMillis() }
    private val journalPath = File(dir, "state.journal").path
    private val headPath = File(dir, "state.head").path
    private val legacyLockPath = File(dir, "state.lock").path
    private val mutex = Any()
    private var seen = DurablePosition(0, GENESIS)
    private var heldNonce: String? = null
    private var myGen: Long = -1
    private val myNs: String? = ownNamespace()
    private val myStart: String? = procStartOf(selfPid)

    /** True when this open quarantined corrupt state (see `recoverFromCorruption`). */
    @Volatile var recovered: Boolean = false
        private set

    init {
        if (opts.dir.isEmpty()) throw DurableStateError("invalid", "dir is required")
        if (key != null && key.size < 32) throw DurableStateError("invalid", "hmacKey must be at least 32 bytes")
        val d = File(dir)
        try {
            Files.createDirectories(d.toPath(), *dirAttrs())
        } catch (e: IOException) {
            if (!d.isDirectory) throw e
        }
        try {
            setMode(d)
        } catch (e: Exception) {
            // not ours to chmod (e.g. a shared parent): keep going
        }
        probeLinks()
        withLock {
            val l = loadOrRecover()
            observe(l)
            val last = l.recs.lastOrNull()
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written")
        }
    }

    /** Highest chain position this handle has observed. */
    fun position(): DurablePosition = seen

    /** Verify the chain from disk now; throws [DurableStateError] on any problem. */
    fun verify(): DurablePosition = withLock {
        observe(load())
        seen
    }

    override fun get(key: String): Any? {
        checkKey(key)
        return withLock {
            val l = load()
            observe(l)
            val v = l.state[key]
            if (v == null) null else Json.parseLenient(v)
        }
    }

    override fun keys(): List<String> = withLock {
        val l = load()
        observe(l)
        l.state.keys.sorted()
    }

    /** Unconditional write (still serialised and hash-chained). Prefer [update] for monotone state. */
    override fun set(key: String, value: Any?) {
        checkKey(key)
        val vj = encode(value)
        withLock {
            val l = load()
            val last = l.recs.lastOrNull()
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written")
            commit(l, key, vj)
        }
    }

    /**
     * Atomic read-modify-write: [fn] gets the current value (null when absent) and returns the next value, or null to leave the key
     * unchanged. Runs under the cross-process lock and must be quick. Returns the value now stored.
     */
    override fun update(key: String, fn: (Any?) -> Any?): Any? {
        checkKey(key)
        return withLock {
            val l = load()
            val last = l.recs.lastOrNull()
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written")
            val cur = l.state[key]
            val next = fn(if (cur == null) null else Json.parseLenient(cur))
            if (next == null) {
                if (cur == null) null else Json.parseLenient(cur)
            } else {
                val vj = encode(next)
                if (vj != cur) commit(l, key, vj)
                Json.parseLenient(vj)
            }
        }
    }

    // ---- encoding, keys, hashing ----

    private fun encode(value: Any?): String {
        val s = try {
            Js.stringify(value)
        } catch (e: RuntimeException) {
            throw DurableStateError("invalid", "value is not JSON-serialisable")
        }
        if (s.length > maxValue) throw DurableStateError("too-large", "value exceeds maxValueBytes=$maxValue")
        return s
    }

    private fun checkKey(k: String) {
        if (k.isEmpty() || k.length > MAX_KEY || k.indexOf('\n') >= 0) throw DurableStateError("invalid", "key must be 1..256 chars without newlines")
    }

    private fun macOf(msg: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key!!, "HmacSHA256"))
        return hex(mac.doFinal(Json.utf8(msg)))
    }

    private fun macEq(a: String, b: String): Boolean = a.length == b.length && MessageDigest.isEqual(Json.utf8(a), Json.utf8(b))

    private fun recHash(seq: Long, prev: String, op: String, payload: String, ts: Long, gen: Long?): String {
        val arr = ArrayList<Any?>()
        arr.add(seq); arr.add(prev); arr.add(op); arr.add(payload); arr.add(ts)
        if (gen != null) arr.add(gen)
        return sha(DOMAIN + Js.stringify(arr))
    }

    private fun headMsg(seq: Long, h: String, gen: Long?): String = if (gen == null) "head\n$seq\n$h" else "head\n$seq\n$h\n$gen"

    private fun recJson(r: Rec): String {
        val m = LinkedHashMap<String, Any?>()
        m["seq"] = r.seq; m["prev"] = r.prev; m["op"] = r.op; m["payload"] = r.payload; m["ts"] = r.ts
        if (r.gen != null) m["gen"] = r.gen
        m["h"] = r.h
        if (r.mac != null) m["mac"] = r.mac
        return Js.stringify(m)
    }

    // ---- loading and verifying ----

    private fun readHead(): Head? {
        val f = File(headPath)
        if (!f.exists()) return null
        val o = try {
            Json.parseLenient(readText(headPath))
        } catch (e: IllegalArgumentException) {
            throw DurableStateError("corrupt", "state.head is not valid JSON")
        }
        val m = o as? Map<*, *>
        val ok = m != null && safeInt(m["seq"]) && lng(m["seq"]) >= 0 && !Js.isNegZero(m["seq"]) && isHex64(m["h"]) && (!m.containsKey("gen") || isGen(m["gen"]))
        if (!ok) throw DurableStateError("corrupt", "state.head has an invalid shape")
        m!!
        val head = Head(lng(m["seq"]), m["h"] as String, if (m.containsKey("gen")) lng(m["gen"]) else null, m["mac"] as? String)
        if (key != null && (head.mac == null || !macEq(head.mac, macOf(headMsg(head.seq, head.h, head.gen))))) {
            throw DurableStateError("key-mismatch", "state.head MAC does not verify (wrong key or forged head)")
        }
        return head
    }

    private fun parseLine(line: String, i: Int): Rec {
        val o = try {
            Json.parseLenient(line)
        } catch (e: IllegalArgumentException) {
            throw DurableStateError("corrupt", "journal line ${i + 1} is not valid JSON")
        }
        val m = o as? Map<*, *>
        val ok = m != null && safeInt(m["seq"]) && isHex64(m["prev"]) && (m["op"] == "set" || m["op"] == "checkpoint") && m["payload"] is String &&
            safeInt(m["ts"]) && !Js.isNegZero(m["ts"]) && isHex64(m["h"]) && (!m.containsKey("gen") || isGen(m["gen"]))
        if (!ok) throw DurableStateError("corrupt", "journal line ${i + 1} has an invalid shape")
        m!!
        return Rec(lng(m["seq"]), m["prev"] as String, m["op"] as String, m["payload"] as String, lng(m["ts"]), if (m.containsKey("gen")) lng(m["gen"]) else null, m["h"] as String, m["mac"] as? String)
    }

    private fun load(): Loaded {
        val head = readHead()
        val fences = readFences(dir)
        if (!File(journalPath).exists()) {
            if (head != null && head.seq > 0) throw DurableStateError("rollback", "state.journal is missing but state.head records seq ${head.seq}")
            val cut = fences.firstOrNull { it.seq > 0 }
            if (cut != null) throw DurableStateError("rollback", "state.journal is missing but operator recovery cut it at seq ${cut.seq}")
            if (seen.seq > 0) throw DurableStateError("rollback", "state was deleted while open")
            return Loaded(emptyList(), LinkedHashMap(), head)
        }
        val lines = ArrayList(readText(journalPath).split("\n"))
        if (lines[lines.size - 1] != "") throw DurableStateError("corrupt", "journal does not end with a newline (torn or truncated)")
        lines.removeAt(lines.size - 1)
        val recs = ArrayList<Rec>()
        val state = LinkedHashMap<String, String>()
        var prevHash = GENESIS
        var prevSeq = 0L
        var prevGen = 0L
        for ((i, line) in lines.withIndex()) {
            val rec = parseLine(line, i)
            if (i == 0) {
                if (rec.op == "set" && (rec.seq != 1L || rec.prev != GENESIS)) throw DurableStateError("corrupt", "journal does not start at genesis")
                if (rec.op == "checkpoint" && rec.seq < 1) throw DurableStateError("corrupt", "bad checkpoint seq")
            } else {
                if (rec.seq != prevSeq + 1) throw DurableStateError("corrupt", "journal line ${i + 1}: sequence gap")
                if (rec.prev != prevHash) throw DurableStateError("corrupt", "journal line ${i + 1}: hash chain broken")
            }
            if (recHash(rec.seq, rec.prev, rec.op, rec.payload, rec.ts, rec.gen) != rec.h) throw DurableStateError("corrupt", "journal line ${i + 1}: record hash mismatch (edited)")
            if (key != null) {
                if (rec.mac == null || !macEq(rec.mac, macOf(rec.h))) throw DurableStateError("key-mismatch", "journal line ${i + 1}: MAC does not verify (wrong key or forged record)")
            } else if (rec.mac != null) {
                throw DurableStateError("key-mismatch", "journal is MAC-tagged but no hmacKey was supplied")
            }
            val rg = rec.gen ?: 0L
            if (rg < prevGen) {
                throw DurableStateError("corrupt", "journal line ${i + 1} (seq ${rec.seq}) was written by lock generation $rg, older than generation $prevGen of an earlier record: a stale writer's record (refused)")
            }
            for (f in fences) {
                if (rec.seq > f.seq && rg < f.gen) {
                    throw DurableStateError("corrupt", "journal line ${i + 1} (seq ${rec.seq}) was written by lock generation $rg, but operator recovery fenced generations below ${f.gen} after seq ${f.seq}: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)")
                }
            }
            prevGen = rg
            if (rec.op == "checkpoint") {
                val entries = try {
                    Json.parseLenient(rec.payload)
                } catch (e: IllegalArgumentException) {
                    throw DurableStateError("corrupt", "checkpoint payload is not JSON")
                }
                if (entries !is List<*>) throw DurableStateError("corrupt", "checkpoint payload is not an array")
                state.clear()
                for (e in entries) {
                    if (e !is List<*> || e.size != 2 || e[0] !is String || e[1] !is String) throw DurableStateError("corrupt", "checkpoint entry is malformed")
                    state[e[0] as String] = e[1] as String
                }
            } else {
                val nl = rec.payload.indexOf('\n')
                if (nl < 1) throw DurableStateError("corrupt", "journal line ${i + 1}: malformed payload")
                state[rec.payload.substring(0, nl)] = rec.payload.substring(nl + 1)
            }
            recs.add(rec)
            prevHash = rec.h
            prevSeq = rec.seq
        }
        val last = recs.lastOrNull()
        val lastSeq = last?.seq ?: 0L
        for (f in fences) {
            if (lastSeq < f.seq) throw DurableStateError("rollback", "journal is at seq $lastSeq but operator recovery cut it at seq ${f.seq} (truncation, or a stale writer replaced it)")
            val atCut = recs.firstOrNull { it.seq == f.seq }
            if (f.seq > 0 && atCut != null && atCut.h != f.h) {
                throw DurableStateError("corrupt", "journal record at seq ${f.seq} is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)")
            }
        }
        if (head != null) {
            val hg = head.gen ?: 0L
            if (lastSeq < head.seq) throw DurableStateError("rollback", "journal is at seq $lastSeq but state.head recorded seq ${head.seq} (truncation or older copy)")
            if (last != null && (last.gen ?: 0L) < hg && (lastSeq == head.seq + 1 || (lastSeq == head.seq && last.h != head.h))) {
                throw DurableStateError("corrupt", "journal tail (seq $lastSeq) was written by lock generation ${last.gen ?: 0L}, older than generation $hg that wrote state.head: a stale writer replaced the journal (refused)")
            }
            val staleHead = lastSeq > head.seq + 1 && fences.any { hg < it.gen && head.seq <= it.seq && lastSeq > it.seq } && recs.any { it.seq == head.seq && it.h == head.h }
            if (lastSeq > head.seq + 1 && !staleHead) throw DurableStateError("corrupt", "journal (seq $lastSeq) is more than one record ahead of state.head (seq ${head.seq})")
            if (last != null) {
                if (lastSeq == head.seq && last.h != head.h) throw DurableStateError("corrupt", "journal tail does not match state.head")
                if (lastSeq == head.seq + 1 && last.prev != head.h) throw DurableStateError("corrupt", "journal tail is not chained from state.head")
            }
        } else if (lastSeq > 1) {
            throw DurableStateError("rollback", "state.head is missing but the journal is at seq $lastSeq")
        }
        if (last != null) {
            if (last.seq < seen.seq) throw DurableStateError("rollback", "state moved backwards from seq ${seen.seq} to ${last.seq} while open")
            if (last.seq == seen.seq && last.h != seen.hash) throw DurableStateError("rollback", "state forked at seq ${last.seq} while open")
        } else if (seen.seq > 0) {
            throw DurableStateError("rollback", "state was emptied while open")
        }
        return Loaded(recs, state, head)
    }

    private fun quarantine() {
        val tag = "${clock()}-${randomHex(3)}"
        assertLockHeld("nothing was written") // a writer that lost the lock must not move a newer holder's files aside
        val fencePath = File(dir, FENCE_FILE).path
        val oldEntries = fenceEntryFiles(dir)
        if (File(fencePath).exists() || oldEntries.isNotEmpty()) {
            if (File(fencePath).exists()) Files.createLink(Paths.get("$fencePath.quarantine-$tag"), Paths.get(fencePath))
            val gf = linkedMapOf<String, Any?>("gen" to myGen, "seq" to 0L, "h" to GENESIS, "from" to myGen - 1, "t" to clock())
            atomicWrite(fencePath, Js.stringify(linkedMapOf<String, Any?>("v" to 1, "fences" to listOf(gf))) + "\n", null, false)
            for (e in oldEntries) move(File(dir, e.name).path, File(dir, e.name + ".quarantine-" + tag).path)
        }
        for (p in listOf(journalPath, headPath)) if (File(p).exists()) move(p, "$p.quarantine-$tag")
        fsyncDir(dir)
        seen = DurablePosition(0, GENESIS)
        recovered = true
    }

    private fun loadOrRecover(): Loaded = try {
        load()
    } catch (e: DurableStateError) {
        if (!opts.recoverFromCorruption) throw e
        quarantine()
        load()
    }

    private fun observe(l: Loaded) {
        val last = l.recs.lastOrNull()
        if (last != null && last.seq >= seen.seq) seen = DurablePosition(last.seq, last.h)
    }

    // ---- the lock: immutable numbered generation files ----

    private fun lockFile(g: Long) = File(dir, "state.lock.$g").path

    /** Highest numbered generation: (g, body); g = 0 when there is none; a null body means unreadable. */
    private fun topLock(): Pair<Long, Map<String, Any?>?> {
        val g = lockGenerations(dir).maxOrNull() ?: -1L
        return if (g >= 1) Pair(g, readBody(lockFile(g))) else Pair(0L, null)
    }

    private fun holderDead(b: Map<String, Any?>?, legacyAgeMs: Long): Boolean {
        if (b == null) return legacyAgeMs > 1000 // an unreadable legacy file (torn by an old version) older than 1 s
        val pid = b["pid"] as? Long
        if (b["host"] != hostname || pid == null) return false // another host: cannot judge, never break
        val ns = b["ns"]
        if (ns != null && ns != myNs) return false // another PID namespace: cannot judge, never break
        if (!pidAlive(pid)) return true
        val start = b["start"] as? String
        if (start != null) {
            val cur = procStartOf(pid)
            if (cur != null && cur != start) return true // the pid was reused by a different process
        }
        return false
    }

    /** Create generation [g] atomically with its body. false = somebody else created it first. */
    private fun createGen(g: Long, body: Map<String, Any?>): Boolean {
        val tmp = File(dir, "state.lock.tmp-$selfPid-${randomHex(6)}").path
        val full = LinkedHashMap<String, Any?>(body)
        full["t"] = System.currentTimeMillis()
        writeNew(tmp, Js.stringify(full))
        try {
            Files.createLink(Paths.get(lockFile(g)), Paths.get(tmp))
            return true
        } catch (e: FileAlreadyExistsException) {
            return false
        } catch (e: IOException) {
            throw DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: ${e.javaClass.simpleName})")
        } catch (e: UnsupportedOperationException) {
            throw DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: ${e.javaClass.simpleName})")
        } finally {
            quietDelete(tmp)
        }
    }

    private fun gcLocks(keepFrom: Long) {
        try {
            for (f in File(dir).list() ?: emptyArray()) {
                val m = LOCK_GEN.matchEntire(f)
                if (m != null) {
                    if ((m.groupValues[1].toLongOrNull() ?: Long.MAX_VALUE) < keepFrom) quietDelete(File(dir, f).path)
                } else if (f.startsWith("state.lock.tmp-")) {
                    val pid = LOCK_TMP.find(f)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
                    if (pid > 0 && !pidAlive(pid)) quietDelete(File(dir, f).path)
                }
            }
        } catch (e: Exception) {
            // best effort
        }
    }

    /** Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics. */
    private fun probeLinks() {
        val a = File(dir, "state.probe-$selfPid-${randomHex(6)}").path
        val b = "$a.lnk"
        try {
            writeNew(a, "probe")
            Files.createLink(Paths.get(b), Paths.get(a))
            val second = try {
                Files.createLink(Paths.get(b), Paths.get(a))
                false
            } catch (e: FileAlreadyExistsException) {
                true
            } catch (e: Exception) {
                false
            }
            if (!second) throw IllegalStateException("link(2) is not atomic/exclusive here")
            val nlink = try {
                (Files.getAttribute(Paths.get(a), "unix:nlink") as Number).toInt()
            } catch (e: Exception) {
                2 // no unix view on this runtime: the exclusive-create probe above is the evidence
            }
            if (nlink != 2) throw IllegalStateException("link(2) is not atomic/exclusive here")
        } catch (e: Exception) {
            val what = if (e is IllegalStateException) e.message else e.javaClass.simpleName
            throw DurableStateError("link-unsupported", "the state directory's filesystem does not provide working hard links with exclusive-create semantics ($what); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE")
        } finally {
            quietDelete(a)
            quietDelete(b)
        }
    }

    private fun <T> withLock(f: () -> T): T = synchronized(mutex) { withLockLocked(f) }

    private fun <T> withLockLocked(f: () -> T): T {
        val nonce = randomHex(12)
        var mustFence = false
        val deadline = System.currentTimeMillis() + lockTimeout
        while (true) {
            val (topG, topBody) = topLock()
            var legacyBlocks = false
            if (File(legacyLockPath).exists()) {
                val age = try {
                    System.currentTimeMillis() - File(legacyLockPath).lastModified()
                } catch (e: Exception) {
                    0L
                }
                legacyBlocks = !holderDead(readBody(legacyLockPath), age)
            }
            val free = topG == 0L || topBody?.get("st") == "free"
            if (!legacyBlocks && (free || holderDead(topBody, 0))) {
                val recovering = if (free) null else topBody?.get("recovering")
                val body = LinkedHashMap<String, Any?>()
                body["st"] = "held"; body["pid"] = selfPid; body["host"] = hostname; body["nonce"] = nonce; body["boot"] = BOOT_ID
                if (myNs != null) body["ns"] = myNs
                if (myStart != null) body["start"] = myStart
                if (recovering != null) body["recovering"] = recovering
                if (createGen(topG + 1, body)) {
                    if (topLock().first != topG + 1) continue // a stale creator's re-created generation is buried below the real top: not a lock
                    myGen = topG + 1
                    mustFence = recovering != null
                    break
                }
                continue // lost the race for that generation: look again immediately
            }
            if (System.currentTimeMillis() > deadline) {
                val desc = { b: Map<String, Any?>? ->
                    if (b == null) {
                        "an unreadable holder record"
                    } else if (b["pid"] == null || b["host"] == null || ((b["nonce"] as? String) ?: "").isEmpty()) {
                        "an incomplete holder record (pid=${b["pid"] ?: "?"} host=${b["host"] ?: "?"} nonce=${(b["nonce"] as? String)?.takeIf { it.isNotEmpty() } ?: "?"}); release it with expectedHolder: 'unreadable'"
                    } else {
                        "holder pid=${b["pid"]} host=${b["host"]} nonce=${b["nonce"]}${if (b["ns"] != null && b["ns"] != myNs) " (another PID namespace)" else ""}"
                    }
                }
                if (legacyBlocks && (free || holderDead(topBody, 0))) {
                    throw DurableStateError("lock-timeout", "could not acquire the state lock in $dir within $lockTimeout ms; blocked by $legacyLockPath (legacy single-file lock of an older version; ${desc(readBody(legacyLockPath))}). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs")
                }
                throw DurableStateError("lock-timeout", "could not acquire the state lock in $dir within $lockTimeout ms; blocked by ${lockFile(topG)} (${desc(topBody)}). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs")
            }
            try {
                Thread.sleep(5L + RANDOM.nextInt(15))
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw DurableStateError("lock-timeout", "interrupted while waiting for the state lock in $dir")
            }
        }
        heldNonce = nonce
        gcLocks(myGen - 16)
        try {
            if (mustFence) {
                // the recovery we took over may have died before (or after) writing its fence: cut and fence now, under OUR generation, before loading
                testCrashPoint("takeover-after-lock")
                writeFence(dir, myGen - 1) { testCrashPoint("takeover-after-fence-temp") }
            }
            return f()
        } finally {
            heldNonce = null
            try {
                createGen(myGen + 1, linkedMapOf<String, Any?>("st" to "free")) // release; a live holder is never superseded, so this cannot lose a race
                gcLocks(myGen - 15)
            } catch (e: Exception) {
                // the lock stays "held" by a process about to be judged dead or alive by its pid: still safe
            }
        }
    }

    /** Immediately before EVERY rename this writer makes: this handle's generation must still be the highest and must still name us. */
    private fun assertLockHeld(outcome: String) {
        val (g, body) = topLock()
        if (heldNonce == null || g != myGen || body == null || body["st"] != "held" || body["nonce"] != heldNonce) {
            throw DurableStateError("lock-lost", "the state lock is no longer held by this writer (generation $myGen, highest $g ${if (body != null) body["st"] else "unreadable"}); $outcome")
        }
    }

    private fun commit(l: Loaded, keyName: String, valueJson: String) {
        val last = l.recs.lastOrNull()
        val seq = (last?.seq ?: 0L) + 1
        val prev = last?.h ?: GENESIS
        val payload = "$keyName\n$valueJson"
        val ts = clock()
        val h = recHash(seq, prev, "set", payload, ts, myGen)
        val rec = Rec(seq, prev, "set", payload, ts, myGen, h, if (key != null) macOf(h) else null)
        var all: List<Rec> = l.recs + rec
        if (all.size > compactEvery) {
            // compact: ONE checkpoint at the same seq the new record would have, chained from the current tail, carrying the full state
            val next = LinkedHashMap(l.state)
            next[keyName] = valueJson
            val entries = next.entries.sortedWith(Comparator { x, y -> x.key.compareTo(y.key) }).map { listOf(it.key, it.value) }
            val cpPayload = Js.stringify(entries)
            val cts = clock()
            val ch = recHash(seq, prev, "checkpoint", cpPayload, cts, myGen)
            all = listOf(Rec(seq, prev, "checkpoint", cpPayload, cts, myGen, ch, if (key != null) macOf(ch) else null))
        }
        val tail = all[all.size - 1]
        // journal first (atomic), head second (atomic): a crash between leaves the head one record behind (repaired by the next writer)
        atomicWrite(journalPath, all.joinToString("\n") { recJson(it) } + "\n", { assertLockHeld("nothing was written") }, opts.testCrashAt == "after-temp-write")
        if (opts.testCrashAt == "after-journal-rename") Runtime.getRuntime().halt(137)
        writeHead(tail, "the journal record (seq ${tail.seq}) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)")
        seen = DurablePosition(tail.seq, tail.h)
    }

    /** Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal. */
    private fun writeHead(tail: Rec, outcome: String) {
        val m = LinkedHashMap<String, Any?>()
        m["seq"] = tail.seq; m["h"] = tail.h; m["gen"] = myGen
        if (key != null) m["mac"] = macOf(headMsg(tail.seq, tail.h, myGen))
        atomicWrite(headPath, Js.stringify(m) + "\n", { assertLockHeld(outcome) }, false)
    }

    companion object {
        const val DOMAIN = "pca-durable-state/v1\n"
        const val GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"
        const val MAX_KEY = 256
        const val FENCE_FILE = "state.fence"
        const val RECOVER_CRASH_ENV = "PCA_DURABLE_TEST_RECOVER_CRASH_AT"
        private val HEX64 = Regex("[0-9a-f]{64}")
        private val FENCE_ENTRY = Regex("state\\.fence\\.(\\d+)-([0-9a-f]+)")
        private val LOCK_GEN = Regex("state\\.lock\\.(\\d+)")
        private val LOCK_TMP = Regex("state\\.lock\\.tmp-(\\d+)-")
        private val RANDOM = SecureRandom()
        private val BOOT_ID: String by lazy { randomHex(12) }

        internal class FenceFile(val name: String, val gen: Long)

        internal class Fence(val gen: Long, val seq: Long, val h: String)

        // ---- small helpers ----

        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        internal fun hex(b: ByteArray): String {
            val c = CharArray(b.size * 2)
            for (i in b.indices) {
                val v = b[i].toInt() and 0xff
                c[i * 2] = HEX_DIGITS[v ushr 4]
                c[i * 2 + 1] = HEX_DIGITS[v and 15]
            }
            return String(c)
        }

        internal fun randomHex(nBytes: Int): String {
            val b = ByteArray(nBytes)
            RANDOM.nextBytes(b)
            return hex(b)
        }

        private fun sha(s: String): String = hex(MessageDigest.getInstance("SHA-256").digest(Json.utf8(s)))

        private fun isHex64(o: Any?): Boolean = o is String && HEX64.matches(o)

        private fun safeInt(o: Any?): Boolean {
            val d = Js.num(o) ?: return false
            return !d.isNaN() && !d.isInfinite() && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0
        }

        private fun isGen(o: Any?): Boolean = safeInt(o) && lng(o) >= 1

        private fun lng(o: Any?): Long = Js.num(o)!!.toLong()

        private fun readText(path: String): String = String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8)

        private fun quietDelete(path: String) {
            try {
                Files.deleteIfExists(Paths.get(path))
            } catch (e: Exception) {
                // best effort: an orphan temp is harmless
            }
        }

        private fun move(from: String, to: String) {
            Files.move(Paths.get(from), Paths.get(to), StandardCopyOption.ATOMIC_MOVE)
        }

        private fun fileAttrs(): Array<FileAttribute<*>> = OwnerOnly.attrs(false)

        private fun dirAttrs(): Array<FileAttribute<*>> = OwnerOnly.attrs(true)

        private fun setMode(f: File) = OwnerOnly.restrictExisting(f.toPath())

        /** Create [path] exclusively (owner-only at creation), write [data], fsync. */
        private fun writeNew(path: String, data: String) {
            val opts = setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            FileChannel.open(Paths.get(path), opts, *fileAttrs()).use { ch ->
                val buf = ByteBuffer.wrap(Json.utf8(data))
                while (buf.hasRemaining()) ch.write(buf)
                ch.force(true)
            }
        }

        internal fun fsyncDir(dir: String) {
            try {
                FileChannel.open(Paths.get(dir), StandardOpenOption.READ).use { it.force(true) }
            } catch (e: IOException) {
                // a directory cannot be opened for fsync on Windows; everywhere else this is a real failure
                if (!System.getProperty("os.name", "").lowercase().contains("win")) throw e
            }
        }

        /** write-temp, fsync, [beforeRename] check, rename, fsync(dir). A failed check removes the temp and rethrows. */
        private fun atomicWrite(path: String, data: String, beforeRename: (() -> Unit)?, crashAfterTemp: Boolean) {
            val tmp = "$path.tmp-$selfPid-${randomHex(6)}"
            writeNew(tmp, data)
            if (crashAfterTemp) Runtime.getRuntime().halt(137)
            if (beforeRename != null) {
                try {
                    beforeRename()
                } catch (e: RuntimeException) {
                    quietDelete(tmp)
                    throw e
                }
            }
            move(tmp, path)
            fsyncDir(File(path).parent ?: ".")
        }

        // ---- the host: pid, hostname, namespace, process start time ----

        private fun processHandleClass(): Class<*>? = try {
            Class.forName("java.lang.ProcessHandle")
        } catch (e: ClassNotFoundException) {
            null
        }

        internal val selfPid: Long by lazy {
            try {
                val c = processHandleClass()
                if (c != null) (c.getMethod("pid").invoke(c.getMethod("current").invoke(null)) as Number).toLong()
                else File("/proc/self").canonicalFile.name.toLong()
            } catch (e: Exception) {
                throw DurableStateError("invalid", "cannot determine the process id of this runtime")
            }
        }

        /** kill(pid, 0) semantics: a process this user cannot signal still counts as alive. Where nothing can judge, alive. */
        internal fun pidAlive(pid: Long): Boolean {
            val c = processHandleClass()
            if (c != null) {
                return try {
                    val opt = c.getMethod("of", java.lang.Long.TYPE).invoke(null, pid) as java.util.Optional<*>
                    opt.isPresent && (c.getMethod("isAlive").invoke(opt.get()) as Boolean)
                } catch (e: Exception) {
                    true
                }
            }
            return if (File("/proc/self").exists()) pid == selfPid || File("/proc/$pid").exists() else true
        }

        /** Process start time (field 22 of /proc/<pid>/stat); null off Linux or when gone. */
        internal fun procStartOf(pid: Long): String? = try {
            val st = readText("/proc/$pid/stat")
            st.substring(st.lastIndexOf(')') + 2).split(' ')[19]
        } catch (e: Exception) {
            null
        }

        internal fun ownNamespace(): String? = try {
            Files.readSymbolicLink(Paths.get("/proc/self/ns/pid")).toString()
        } catch (e: Exception) {
            null
        }

        /** The machine's hostname as the OS reports it (gethostname), not a DNS-resolved name. */
        val hostname: String by lazy {
            fun clean(s: String?): String? = s?.trim()?.takeIf { it.isNotEmpty() }
            clean(try { readText("/proc/sys/kernel/hostname") } catch (e: Exception) { null })
                ?: clean(try {
                    val p = ProcessBuilder("hostname").redirectErrorStream(true).start()
                    val out = String(p.inputStream.readBytes(), StandardCharsets.UTF_8)
                    p.waitFor()
                    out
                } catch (e: Exception) { null })
                ?: clean(System.getenv("HOSTNAME")) ?: clean(System.getenv("COMPUTERNAME"))
                ?: java.net.InetAddress.getLocalHost().hostName
        }

        /** Test-only: halt this process at a named step of operator recovery (PCA_DURABLE_TEST=1 and the env var both set). */
        private fun testCrashPoint(point: String) {
            if (System.getenv("PCA_DURABLE_TEST") == "1" && System.getenv(RECOVER_CRASH_ENV) == point) Runtime.getRuntime().halt(137)
        }

        // ---- lock and fence files ----

        private fun lockGenerations(dir: String): List<Long> =
            (File(dir).list() ?: throw IOException("cannot list $dir")).mapNotNull { f -> LOCK_GEN.matchEntire(f)?.groupValues?.get(1)?.toLongOrNull() }

        /** A lock body, normalised; null when the file is unreadable or not an object. */
        private fun readBody(path: String): Map<String, Any?>? {
            val o = try {
                Json.parseLenient(readText(path))
            } catch (e: Exception) {
                return null
            }
            if (o is List<*>) return linkedMapOf("st" to "held") // a JSON array is an object in the reference: no holder fields
            if (o !is Map<*, *>) return null
            val b = LinkedHashMap<String, Any?>()
            b["st"] = if (o["st"] == "free") "free" else "held"
            val pid = o["pid"]
            if (Js.num(pid) != null) b["pid"] = Js.num(pid)!!.toLong()
            for (k in listOf("host", "nonce", "start", "ns", "boot")) if (o[k] is String) b[k] = o[k]
            if (safeInt(o["recovering"])) b["recovering"] = lng(o["recovering"])
            return b
        }

        private fun fenceEntryFiles(dir: String): List<FenceFile> =
            (File(dir).list() ?: throw IOException("cannot list $dir")).mapNotNull { n ->
                val m = FENCE_ENTRY.matchEntire(n)
                if (m == null) null else FenceFile(n, m.groupValues[1].toLongOrNull() ?: Long.MAX_VALUE)
            }

        private fun parseFence(f: Any?, where: String): Fence {
            val ok = f is Map<*, *> && isGen(f["gen"]) && safeInt(f["seq"]) && lng(f["seq"]) >= 0 && !Js.isNegZero(f["seq"]) && isHex64(f["h"])
            if (!ok) throw DurableStateError("corrupt", "$where has an invalid entry")
            f as Map<*, *>
            return Fence(lng(f["gen"]), lng(f["seq"]), f["h"] as String)
        }

        private fun readJson(path: String, name: String): Any? = try {
            Json.parseLenient(readText(path))
        } catch (e: IllegalArgumentException) {
            throw DurableStateError("corrupt", "$name is not valid JSON")
        }

        private fun isOne(o: Any?): Boolean = Js.num(o) == 1.0

        /** Every fence: the list in `state.fence` (absent = none) then each `state.fence.<gen>-<rand>` by generation. Malformed = corrupt. */
        private fun readFences(dir: String): List<Fence> {
            val out = ArrayList<Fence>()
            val p = File(dir, FENCE_FILE).path
            if (File(p).exists()) {
                val o = readJson(p, "state.fence")
                if (o !is Map<*, *> || !isOne(o["v"]) || o["fences"] !is List<*>) throw DurableStateError("corrupt", "state.fence has an invalid shape")
                for (f in o["fences"] as List<*>) out.add(parseFence(f, "state.fence"))
            }
            val entries = fenceEntryFiles(dir).sortedWith(Comparator { a, b -> if (a.gen != b.gen) a.gen.compareTo(b.gen) else a.name.compareTo(b.name) })
            for (e in entries) {
                val o = readJson(File(dir, e.name).path, e.name)
                if (o !is Map<*, *> || !isOne(o["v"])) throw DurableStateError("corrupt", "${e.name} has an invalid shape")
                val f = parseFence(o["fence"], e.name)
                if (f.gen != e.gen) throw DurableStateError("corrupt", "${e.name} names generation ${e.gen} but holds ${f.gen}")
                out.add(f)
            }
            return out
        }

        /** (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros). */
        private fun journalTail(dir: String): Pair<Long, String> {
            val none = Pair(0L, GENESIS)
            return try {
                val lines = readText(File(dir, "state.journal").path).split("\n").filter { it.isNotEmpty() }
                val o = Json.parseLenient(lines.lastOrNull() ?: "null")
                if (o is Map<*, *> && safeInt(o["seq"]) && lng(o["seq"]) >= 1 && isHex64(o["h"])) Pair(lng(o["seq"]), o["h"] as String) else none
            } catch (e: Exception) {
                none
            }
        }

        /** The operator's CUT: every journal record after the tail seen NOW must come from a generation above [g]. Its own immutable file. */
        private fun writeFence(dir: String, g: Long, beforeRename: (() -> Unit)? = null) {
            readFences(dir) // an unreadable fence set fails closed here too
            val (seq, h) = journalTail(dir)
            val fence = LinkedHashMap<String, Any?>()
            fence["gen"] = g + 1; fence["seq"] = seq; fence["h"] = h; fence["from"] = g; fence["t"] = System.currentTimeMillis()
            val doc = Js.stringify(linkedMapOf<String, Any?>("v" to 1, "fence" to fence)) + "\n"
            atomicWrite(File(dir, "$FENCE_FILE.${g + 1}-${randomHex(6)}").path, doc, beforeRename, false)
        }

        internal class Classified(val kind: String, val body: Map<String, Any?>? = null, val raw: Any? = null)

        /** A holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce. */
        private fun classifyLockFile(path: String): Classified {
            val o = try {
                Json.parseLenient(readText(path))
            } catch (e: Exception) {
                return Classified("unreadable")
            }
            if (o == null || (o !is Map<*, *> && o !is List<*>)) return Classified("unreadable")
            if (o is List<*>) return Classified("incomplete", raw = o)
            @Suppress("UNCHECKED_CAST")
            val r = o as Map<String, Any?>
            if (r["st"] == "free") return Classified("free")
            if (Js.num(r["pid"]) != null && r["host"] is String && r["nonce"] is String && r["nonce"] != "") return Classified("complete", body = r, raw = r)
            return Classified("incomplete", raw = r)
        }

        private fun jsMember(raw: Any?, k: String): String = if (raw is Map<*, *> && raw.containsKey(k)) Js.template(raw[k]) else "undefined"

        /** Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname. */
        private fun holderAliveHere(raw: Any?): Boolean {
            val b = raw as? Map<*, *> ?: return false
            val pidNum = Js.num(b["pid"]) ?: return false
            val nsNow = ownNamespace()
            val ns = b["ns"]
            val judgeable = if (ns is String) nsNow != null && ns == nsNow else b["host"] == hostname
            if (!judgeable || !pidAlive(pidNum.toLong())) return false
            val start = b["start"]
            if (start is String) {
                val cur = procStartOf(pidNum.toLong())
                if (cur != null && cur != start) return false // the pid was reused by a different process
            }
            return true
        }

        private fun invalid(msg: String) = DurableStateError("invalid", msg)

        private fun confirmHolder(c: Classified, exp: Any?, path: String) {
            val unreadable = exp == "unreadable"
            when (c.kind) {
                "unreadable" -> if (!unreadable) throw invalid("$path is unreadable; pass expectedHolder: 'unreadable' to release it")
                "incomplete" -> {
                    if (!unreadable) {
                        throw invalid("$path has an incomplete holder record (${Js.stringify(c.raw).take(160)}); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it")
                    }
                    if (holderAliveHere(c.raw)) throw invalid("the holder of $path (pid ${jsMember(c.raw, "pid")}) is alive in this PID namespace; refusing to release a live holder")
                }
                "complete" -> {
                    val b = c.body!!
                    val pidT = Js.template(b["pid"])
                    if (unreadable) throw invalid("$path is readable (holder pid=$pidT host=${b["host"]}); expectedHolder 'unreadable' does not match")
                    val e = exp as ExpectedLockHolder
                    if (b["host"] != e.host || Js.num(b["pid"]) != e.pid.toDouble() || b["nonce"] != e.nonce) {
                        throw invalid("expectedHolder does not match the holder recorded in $path (recorded pid=$pidT host=${b["host"]} nonce=${b["nonce"]}); nothing was changed")
                    }
                    if (holderAliveHere(b)) throw invalid("the holder of $path (pid $pidT) is alive in this PID namespace; refusing to release a live holder")
                }
            }
        }

        /**
         * Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an
         * unreadable or incomplete top lock file, or a legacy single-file `state.lock`). Out of band: it takes the lock itself
         * (generation g+1, marked `recovering`), cuts and FENCES the released generation, then appends a "free" generation g+2. The
         * caller passes the recorded holder EXACTLY (or "unreadable"); any difference, or a holder alive in this PID namespace, is
         * refused with code `invalid` and nothing is changed.
         */
        fun recover(opts: RecoverDurableStateOptions): RecoverDurableStateResult {
            if (!opts.force) throw invalid("recoverDurableState requires force: true")
            val exp = opts.expectedHolder
            if (!(exp == "unreadable" || (exp is ExpectedLockHolder && exp.nonce.isNotEmpty()))) {
                throw invalid("expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'")
            }
            val dir = opts.dir
            val g = lockGenerations(dir).maxOrNull() ?: 0L
            val path = File(dir, "state.lock.$g").path
            val top = if (g == 0L) null else classifyLockFile(path)
            val legacyPath = File(dir, "state.lock").path
            if (opts.legacyLock) {
                if (top != null && top.kind != "free") throw invalid("legacyLock: true, but the blocking lock is the generation lock $path; call recoverDurableState without legacyLock")
                if (!File(legacyPath).exists()) return RecoverDurableStateResult(false, "not-held")
                val legacy = classifyLockFile(legacyPath)
                if (legacy.kind == "free") return RecoverDurableStateResult(false, "not-held", legacyPath)
                confirmHolder(legacy, exp, legacyPath)
                // a legacy (older-version) writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1
                writeFence(dir, g)
                move(legacyPath, File(dir, "state.lock.legacy-recovered-${System.currentTimeMillis()}-${randomHex(3)}").path)
                fsyncDir(dir)
                return RecoverDurableStateResult(true, "released", legacyPath)
            }
            if (top == null || top.kind == "free") {
                if (File(legacyPath).exists()) {
                    val lb = classifyLockFile(legacyPath)
                    val who = if (lb.kind == "complete") "holder pid=${Js.template(lb.body!!["pid"])} host=${lb.body["host"]} nonce=${lb.body["nonce"]}" else "${lb.kind} holder record"
                    throw invalid("the blocking lock is the legacy single-file $legacyPath ($who); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')")
                }
                return if (top == null) RecoverDurableStateResult(false, "not-held") else RecoverDurableStateResult(false, "not-held", path)
            }
            confirmHolder(top, exp, path)
            // in this order (the model DurableFence): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free
            fun linkBody(gen: Long, body: Map<String, Any?>, crashPoint: String) {
                val tmp = File(dir, "state.lock.tmp-$selfPid-${randomHex(6)}").path
                writeNew(tmp, Js.stringify(body))
                testCrashPoint(crashPoint)
                try {
                    Files.createLink(Paths.get(File(dir, "state.lock.$gen").path), Paths.get(tmp))
                } catch (e: FileAlreadyExistsException) {
                    throw invalid("$path was superseded while recovering; re-read the lock state and retry")
                } finally {
                    quietDelete(tmp)
                }
            }
            val ns = ownNamespace()
            testCrashPoint("before-lock")
            val start = procStartOf(selfPid)
            val body = LinkedHashMap<String, Any?>()
            body["st"] = "held"; body["pid"] = selfPid; body["host"] = hostname; body["nonce"] = randomHex(12); body["boot"] = BOOT_ID
            if (ns != null) body["ns"] = ns
            if (start != null) body["start"] = start
            body["recovering"] = g
            body["t"] = System.currentTimeMillis()
            linkBody(g + 1, body, "after-lock-temp")
            testCrashPoint("after-lock")
            writeFence(dir, g) { testCrashPoint("after-fence-temp") }
            testCrashPoint("after-fence")
            val free = linkedMapOf<String, Any?>("st" to "free", "t" to System.currentTimeMillis(), "recoveredFrom" to g)
            linkBody(g + 2, free, "after-release-temp")
            testCrashPoint("after-release")
            return RecoverDurableStateResult(true, "released", path)
        }
    }
}
