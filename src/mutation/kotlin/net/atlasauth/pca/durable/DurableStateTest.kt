package net.atlasauth.pca.durable

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong

/**
 * The durable state store: the shared scenario corpus (every lane replays the same directory scenarios), plus what a corpus cannot
 * carry: file modes, racing writers and the in-memory store.
 */
@Suppress("UNCHECKED_CAST")
class DurableStateTest {
    private val dead = 999_999_999L
    private val pid: Long = ProcessHandle.current().pid()
    private val host: String = DurableState.hostname

    private fun tmp(): File = Files.createTempDirectory("pca-ds-kt-").toFile()

    private fun subst(s: String) = s.replace("\$HOST", host).replace("\$PID", pid.toString()).replace("\$DEAD", dead.toString())

    private fun so(v: Any?): Any? = when {
        v == "\$HOST" -> host
        v == "\$PID" -> Json.Num(pid.toString())
        v is List<*> -> v.map { so(it) }
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = so(x) }
        else -> v
    }

    private fun normName(f: String): String = f
        .replace(Regex("^(state\\.fence\\.\\d+)-[0-9a-f]+"), "\$1-*")
        .replace(Regex("\\.quarantine-.*$"), ".quarantine-*")
        .replace(Regex("^state\\.lock\\.legacy-recovered-.*$"), "state.lock.legacy-recovered-*")
        .replace(Regex("^state\\.lock\\.tmp-.*$"), "state.lock.tmp-*")

    private fun readOpt(dir: File, f: String): String? = File(dir, f).let { if (it.exists()) String(it.readBytes(), Charsets.UTF_8) else null }

    private fun parseFile(dir: File, f: String): Any? {
        val txt = readOpt(dir, f) ?: return null
        return try { Json.parseLenient(txt) } catch (e: Exception) { null }
    }

    private fun strip(x: Any?): Any? = if (x is Map<*, *>) LinkedHashMap<String, Any?>().also { m -> for ((k, v) in x) if (k != "t") m[k as String] = v } else x

    private fun snapshot(dir: File): Map<String, Any?> {
        val names = (dir.list() ?: emptyArray()).sorted()
        val fences = ArrayList<Any?>()
        if (names.contains("state.fence")) {
            val o = parseFile(dir, "state.fence")
            val l = (o as? Map<*, *>)?.get("fences") as? List<*>
            if (l != null) l.forEach { fences.add(strip(it)) } else fences.add(linkedMapOf("unreadable" to normName("state.fence")))
        }
        val entry = Regex("state\\.fence\\.(\\d+)-[0-9a-f]+")
        val ents = names.filter { entry.matches(it) }.sortedWith(Comparator { a, b ->
            val ga = entry.matchEntire(a)!!.groupValues[1].toDouble()
            val gb = entry.matchEntire(b)!!.groupValues[1].toDouble()
            if (ga != gb) ga.compareTo(gb) else a.compareTo(b)
        })
        for (n in ents) {
            val f = (parseFile(dir, n) as? Map<*, *>)?.get("fence")
            if (f != null) fences.add(strip(f)) else fences.add(linkedMapOf("unreadable" to normName(n)))
        }
        val gens = names.mapNotNull { Regex("state\\.lock\\.(\\d+)").matchEntire(it)?.groupValues?.get(1)?.toLong() }
        val g = gens.maxOrNull() ?: 0L
        var top: Any? = null
        if (g > 0) {
            val pb = parseFile(dir, "state.lock.$g")
            val b = if (pb is List<*>) emptyMap<Any?, Any?>() else pb as? Map<*, *> // an array is an object without members in the reference
            top = if (b == null) linkedMapOf<String, Any?>("g" to g, "st" to "unreadable") else LinkedHashMap<String, Any?>().also { m ->
                m["g"] = g
                for (k in listOf("st", "recovering", "recoveredFrom")) if (b.containsKey(k)) m[k] = b[k]
            }
        }
        val files = names.filter { !it.startsWith("state.lock.tmp-") && !it.startsWith("state.probe-") && !Regex("\\.tmp-").containsMatchIn(it) }.map { normName(it) }
        return linkedMapOf("t" to "dir", "files" to files, "journal" to readOpt(dir, "state.journal"), "head" to readOpt(dir, "state.head"), "fences" to fences, "top" to top)
    }

    private fun runScenario(sc: Map<String, Any?>): List<Any?> {
        val dir = tmp()
        try {
            fun norm(s: String) = s.replace(dir.path, "\$DIR").replace("\$DIR" + java.io.File.separator, "\$DIR/").replace(host, "\$HOST").replace("pid=$pid", "pid=\$PID").replace("pid $pid", "pid \$PID")
            fun err(e: DurableStateError) = linkedMapOf<String, Any?>("err" to linkedMapOf("code" to e.code, "msg" to norm(e.message ?: "")))
            val out = ArrayList<Any?>()
            ((sc["files"] as? Map<String, Any?>) ?: emptyMap()).forEach { (f, t) -> File(dir, f).writeText(subst(t as String)) }
            for (st in sc["steps"] as List<Map<String, Any?>>) {
                when (st["t"]) {
                    "write" -> {
                        val text = st["text"] as? String
                        if (text == null) File(dir, st["file"] as String).delete() else File(dir, st["file"] as String).writeText(subst(text))
                        out.add(null)
                    }
                    "dir" -> out.add(snapshot(dir))
                    "recover" -> {
                        val o = (so(st["opts"]) as? Map<String, Any?>) ?: emptyMap()
                        val eh = o["expectedHolder"]
                        val exp: Any? = if (eh is Map<*, *> && eh["host"] is String && IntentJs.num(eh["pid"]) != null && eh["nonce"] is String) {
                            ExpectedLockHolder(eh["host"] as String, IntentJs.num(eh["pid"])!!.toLong(), eh["nonce"] as String)
                        } else eh
                        out.add(try {
                            val r = recoverDurableState(RecoverDurableStateOptions(dir.path, o["force"] != false, exp, o["legacyLock"] == true))
                            val m = linkedMapOf<String, Any?>("released" to r.released, "reason" to r.reason)
                            if (r.lockFile != null) m["lockFile"] = norm(r.lockFile)
                            linkedMapOf<String, Any?>("ok" to m)
                        } catch (e: DurableStateError) {
                            err(e)
                        })
                    }
                    "open" -> {
                        val op = (st["opts"] as? Map<String, Any?>) ?: emptyMap()
                        val c = AtomicLong(1000)
                        val key: ByteArray? = (op["hmacKey"] as? String)?.let { MessageDigest.getInstance("SHA-256").digest(it.toByteArray(Charsets.UTF_8)) }
                            ?: op["hmacKeyBytes"]?.let { ByteArray(IntentJs.lng(it).toInt()) }
                        val opts = DurableStateOptions(
                            dir = if (op["dir"] == "") "" else dir.path,
                            hmacKey = key,
                            recoverFromCorruption = op["recoverFromCorruption"] == true,
                            lockTimeoutMs = op["lockTimeoutMs"]?.let { IntentJs.lng(it) } ?: 10_000,
                            compactEvery = op["compactEvery"]?.let { IntentJs.lng(it).toInt() } ?: 256,
                            maxValueBytes = op["maxValueBytes"]?.let { IntentJs.lng(it).toInt() } ?: 1_048_576,
                            now = { c.getAndIncrement() },
                        )
                        val h = try {
                            openDurableState(opts)
                        } catch (e: DurableStateError) {
                            out.add(err(e))
                            continue
                        }
                        val res = ArrayList<Any?>()
                        val saved = HashMap<String, Pair<String?, String?>>()
                        for (x in (st["ops"] as? List<Map<String, Any?>>) ?: emptyList()) {
                            val k = (x["key"] as? String) ?: ""
                            res.add(try {
                                val v: Any? = when (x["op"]) {
                                    "set" -> { h.set(k, x["value"]); null }
                                    "get" -> h.get(k) ?: linkedMapOf("\$undef" to true)
                                    "keys" -> h.keys()
                                    "verify" -> h.verify().let { linkedMapOf("seq" to it.seq, "hash" to it.hash) }
                                    "position" -> h.position().let { linkedMapOf("seq" to it.seq, "hash" to it.hash) }
                                    "update" -> {
                                        val arg = x["arg"]
                                        val kind = x["kind"] as String
                                        h.update(k) { p ->
                                            when (kind) {
                                                "append" -> ArrayList<Any?>((p as? List<Any?>) ?: emptyList()).also { it.add(arg) }
                                                "max" -> if (p == null || IntentJs.num(arg)!! > IntentJs.num(p)!!) arg else null
                                                "noop" -> null
                                                "same" -> p
                                                "set" -> arg
                                                else -> throw IllegalStateException("unknown update kind $kind")
                                            }
                                        } ?: linkedMapOf("\$undef" to true)
                                    }
                                    "fs" -> {
                                        val text = x["text"] as? String
                                        if (text == null) File(dir, x["file"] as String).delete() else File(dir, x["file"] as String).writeText(subst(text))
                                        null
                                    }
                                    "save" -> { saved[x["name"] as String] = Pair(readOpt(dir, "state.journal"), readOpt(dir, "state.head")); null }
                                    "restore" -> {
                                        val (j, hd) = saved[x["name"] as String]!!
                                        for ((f, t) in listOf("state.journal" to j, "state.head" to hd)) if (t == null) File(dir, f).delete() else File(dir, f).writeText(t)
                                        null
                                    }
                                    else -> throw IllegalStateException("unknown op ${x["op"]}")
                                }
                                linkedMapOf<String, Any?>("ok" to v)
                            } catch (e: DurableStateError) {
                                err(e)
                            })
                        }
                        out.add(linkedMapOf("ok" to linkedMapOf("recovered" to h.recovered, "ops" to res)))
                    }
                    else -> throw IllegalStateException("unknown step ${st["t"]}")
                }
            }
            out.add(snapshot(dir))
            return out
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun everyScenarioOfTheReferenceCorpusReplaysIdentically() {
        OracleCases.each("ref-durable-state", "scenario") { a -> runScenario(a[0] as Map<String, Any?>) }
    }

    @Test fun theDirectoryIs0700AndTheFiles0600() {
        org.junit.Assume.assumeTrue("POSIX file permissions", java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))
        val d = File(tmp(), "state")
        val s = openDurableState(DurableStateOptions(d.path))
        s.set("a", Json.Num("1"))
        fun mode(f: File) = java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath()))
        assertEquals("rwx------", mode(d))
        assertEquals("rw-------", mode(File(d, "state.journal")))
        assertEquals("rw-------", mode(File(d, "state.head")))
    }

    @Test fun racingWritersLoseNoUpdateAndTheChainStaysIntact() {
        val d = tmp()
        val threads = 4
        val each = 12
        val ts = (0 until threads).map {
            Thread {
                val s = openDurableState(DurableStateOptions(d.path, lockTimeoutMs = 60_000))
                repeat(each) { s.update("n") { p -> Json.Num(((if (p == null) 0L else IntentJs.lng(p)) + 1).toString()) } }
            }.also { it.start() }
        }
        ts.forEach { it.join() }
        val s = openDurableState(DurableStateOptions(d.path))
        assertEquals((threads * each).toLong(), IntentJs.lng(s.get("n")))
        assertTrue(s.verify().seq >= threads * each)
    }

    @Test fun aLiveHolderIsNeverRobbedTheWaiterTimesOut() {
        val d = tmp()
        val s = openDurableState(DurableStateOptions(d.path))
        s.set("a", Json.Num("1"))
        val top = (d.list() ?: emptyArray()).mapNotNull { it.removePrefix("state.lock.").toLongOrNull() }.maxOrNull()!!
        File(d, "state.lock.${top + 1}").writeText("{\"st\":\"held\",\"pid\":$pid,\"host\":\"$host\",\"nonce\":\"n\"}")
        val e = try {
            openDurableState(DurableStateOptions(d.path, lockTimeoutMs = 150)); null
        } catch (e: DurableStateError) {
            e
        }
        assertEquals("lock-timeout", e!!.code)
    }

    @Test fun theInMemoryStoreHasTheSameUpdateSemantics() {
        val m = createMemoryDurableKv()
        assertEquals(5L, IntentJs.lng(m.update("hw") { p -> if (p == null) Json.Num("5") else null }))
        assertEquals(5L, IntentJs.lng(m.update("hw") { p -> if (p == null) Json.Num("9") else null }))
        m.set("b", linkedMapOf("x" to listOf(Json.Num("1"), null)))
        assertEquals(listOf("b", "hw"), m.keys())
        assertNull(m.update("nope") { null })
    }
}
