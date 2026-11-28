package net.atlasauth.pca.durable

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

/**
 * The durable state store: the shared scenario corpus (every lane replays the same directory scenarios), plus what a corpus cannot
 * carry: file modes, racing writers and the in-memory store.
 * Hang guard: every test (and every corpus scenario) runs under a deadline far above its normal time and below PIT's per-test time
 * limit (3 x normal + 15 s), so a mutant that never returns (e.g. a lock wait that can no longer time out) fails a test, not the run.
 */
@Suppress("UNCHECKED_CAST")
class DurableStateTest {
    companion object {
        private const val SCENARIO_LIMIT_S = 10L
        private const val TEST_LIMIT_MS = 10_000L
    }

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

    /** Runs [f] on a daemon thread and fails when it has not returned within [SCENARIO_LIMIT_S] seconds (the thread is interrupted and left behind). */
    private fun <T> withinLimit(f: () -> T): T {
        val task = FutureTask<T> { f() }
        val t = Thread(task, "durable-state-scenario")
        t.isDaemon = true
        t.start()
        try {
            return task.get(SCENARIO_LIMIT_S, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            t.interrupt()
            throw AssertionError("did not finish within $SCENARIO_LIMIT_S s")
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    }

    @Test fun everyScenarioOfTheReferenceCorpusReplaysIdentically() {
        // each scenario has its own deadline; after the first that does not finish, the rest are not started, so a hanging mutant costs
        // one deadline, not one per scenario
        var hung = false
        OracleCases.each("ref-durable-state", "scenario") { a ->
            if (hung) throw IllegalStateException("not run: an earlier scenario did not finish within $SCENARIO_LIMIT_S s")
            try {
                withinLimit { runScenario(a[0] as Map<String, Any?>) }
            } catch (e: AssertionError) {
                hung = true
                throw e
            }
        }
        assertFalse("a scenario did not finish within $SCENARIO_LIMIT_S s", hung)
    }

    @Test(timeout = TEST_LIMIT_MS) fun theDirectoryIs0700AndTheFiles0600() {
        org.junit.Assume.assumeTrue("POSIX file permissions", java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))
        val d = File(tmp(), "state")
        val s = openDurableState(DurableStateOptions(d.path))
        s.set("a", Json.Num("1"))
        fun mode(f: File) = java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath()))
        assertEquals("rwx------", mode(d))
        assertEquals("rw-------", mode(File(d, "state.journal")))
        assertEquals("rw-------", mode(File(d, "state.head")))
    }

    @Test(timeout = 3 * TEST_LIMIT_MS) fun racingWritersLoseNoUpdateAndTheChainStaysIntact() {
        val d = tmp()
        val threads = 4
        val each = 12
        val ts = (0 until threads).map {
            Thread {
                val s = openDurableState(DurableStateOptions(d.path, lockTimeoutMs = 60_000))
                repeat(each) { s.update("n") { p -> Json.Num(((if (p == null) 0L else IntentJs.lng(p)) + 1).toString()) } }
            }.also { it.isDaemon = true; it.start() } // a writer a mutant left spinning must not keep the JVM alive after the guard fails the test
        }
        ts.forEach { it.join() }
        val s = openDurableState(DurableStateOptions(d.path))
        assertEquals((threads * each).toLong(), IntentJs.lng(s.get("n")))
        assertTrue(s.verify().seq >= threads * each)
    }

    @Test(timeout = TEST_LIMIT_MS) fun aLiveHolderIsNeverRobbedTheWaiterTimesOut() {
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

    /** Arms a commit hook in this (non-child) process with the halt replaced by a recorder; returns the points the halter was called at. */
    private fun fireHook(point: String, asChild: Boolean): List<String> {
        val halted = ArrayList<String>()
        val prev = DurableState.crashHalter
        val prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY)
        val halter: () -> Unit = { halted.add(point); throw IllegalStateException("halted") }
        DurableState.crashHalter = halter
        // the hook below halts the JVM when the recorder is not in place: check it is, before arming it
        assertTrue("the test halter was not installed", DurableState.crashHalter === halter)
        try {
            if (asChild) System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1")
            val s = openDurableState(DurableStateOptions(tmp().path, testCrashAt = point))
            val e: Throwable? = try { s.set("a", Json.Num("1")); null } catch (x: Throwable) { x }
            if (asChild) {
                assertTrue("expected the halter, got $e", e is IllegalStateException && e.message == "halted")
            } else {
                assertTrue("expected an AssertionError, got $e", e is AssertionError)
                assertEquals("crash hook fired outside a crash child ($point)", e!!.message)
            }
        } finally {
            DurableState.crashHalter = prev
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY) else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp)
        }
        return halted
    }

    @Test(timeout = TEST_LIMIT_MS) fun aCrashHookOutsideACrashChildThrowsInsteadOfHalting() {
        for (point in listOf("after-temp-write", "after-journal-rename")) assertEquals(emptyList<String>(), fireHook(point, false))
    }

    @Test(timeout = TEST_LIMIT_MS) fun aCrashHookInACrashChildHalts() {
        for (point in listOf("after-temp-write", "after-journal-rename")) assertEquals(listOf(point), fireHook(point, true))
    }

    /** A crash child: one durable write, which the after-temp-write hook ends through the DEFAULT halter (nothing replaced). */
    object CrashChild {
        @JvmStatic fun main(args: Array<String>) {
            val s = openDurableState(DurableStateOptions(args[0], testCrashAt = "after-temp-write"))
            println("opened")
            System.out.flush()
            s.set("a", Json.Num("2"))
            println("after the halt")
            System.out.flush()
            System.exit(0)
        }
    }

    // The default halter can only be observed from outside: a child JVM (the unmutated class) dies at the hook with exactly 137, runs
    // nothing after it, leaves the journal temp written and the journal and head untouched, and a fresh open carries on from them.
    @Test(timeout = 2 * TEST_LIMIT_MS) fun theDefaultHalterEndsACrashChildWithExit137AtItsHook() {
        val d = tmp()
        openDurableState(DurableStateOptions(d.path)).set("a", Json.Num("1"))
        val journal = readOpt(d, "state.journal")!!
        val head = readOpt(d, "state.head")
        val javaBin = java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java").toString()
        val p = ProcessBuilder(javaBin, "-cp", System.getProperty("java.class.path"), "-D${DurableState.CRASH_CHILD_PROPERTY}=1", CrashChild::class.java.name, d.path)
            .redirectErrorStream(true).start()
        val out = String(p.inputStream.readBytes(), Charsets.UTF_8)
        assertTrue("the crash child did not exit: $out", p.waitFor(15, TimeUnit.SECONDS))
        assertEquals(out, 137, p.exitValue())
        assertTrue(out, out.contains("opened"))
        assertFalse(out, out.contains("after the halt"))
        assertEquals(journal, readOpt(d, "state.journal"))
        assertEquals(head, readOpt(d, "state.head"))
        val tmpName = (d.list() ?: emptyArray()).firstOrNull { it.startsWith("state.journal.tmp-${p.pid()}-") }
        assertTrue("no journal temp of the child in ${d.list()?.toList()}", tmpName != null)
        val temp = readOpt(d, tmpName!!)!!
        assertTrue(temp, temp.startsWith(journal) && temp.length > journal.length)
        val fresh = openDurableState(DurableStateOptions(d.path))
        assertEquals(1L, IntentJs.lng(fresh.get("a")))
        fresh.set("a", Json.Num("3"))
        assertEquals(3L, IntentJs.lng(openDurableState(DurableStateOptions(d.path)).get("a")))
    }

    @Test(timeout = TEST_LIMIT_MS) fun theInMemoryStoreHasTheSameUpdateSemantics() {
        val m = createMemoryDurableKv()
        assertEquals(5L, IntentJs.lng(m.update("hw") { p -> if (p == null) Json.Num("5") else null }))
        assertEquals(5L, IntentJs.lng(m.update("hw") { p -> if (p == null) Json.Num("9") else null }))
        m.set("b", linkedMapOf("x" to listOf(Json.Num("1"), null)))
        assertEquals(listOf("b", "hw"), m.keys())
        assertNull(m.update("nope") { null })
    }
}
