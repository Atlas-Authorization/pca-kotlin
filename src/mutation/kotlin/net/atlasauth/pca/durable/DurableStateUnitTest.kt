package net.atlasauth.pca.durable

import net.atlasauth.pca.durable.DurableState.Companion.Linker
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout
import java.io.File
import java.io.IOException
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The durable state store, behaviour by behaviour: what the shared scenario corpus cannot pin (exact lock / fence / head bodies this
 * process writes, garbage collection of old generations and temp files, lock-timeout and lock-lost wording, recovery bodies, the
 * host probes). Every test runs on Linux and Windows unless it says otherwise.
 */
@Suppress("UNCHECKED_CAST")
class DurableStateUnitTest {
    @get:Rule val hangGuard: Timeout = Timeout.builder().withTimeout(10, TimeUnit.SECONDS).build()

    private val pid: Long = ProcessHandle.current().pid()
    private val host: String = DurableState.hostname
    private val dead = 999_999_999L
    private val g0 = DurableState.GENESIS
    private val isWindows = System.getProperty("os.name", "").lowercase().contains("win")
    private val dirs = ArrayList<File>()

    @After fun cleanUp() {
        for (d in dirs) d.deleteRecursively()
    }

    // ---- helpers ----

    private fun tmp(): File = Files.createTempDirectory("pca-dsu-kt-").toFile().also { dirs.add(it) }

    private fun open(d: File, lockTimeoutMs: Long = 300, now: (() -> Long)? = null, recover: Boolean = false, testCrashAt: String? = null): DurableState =
        openDurableState(DurableStateOptions(d.path, recoverFromCorruption = recover, lockTimeoutMs = lockTimeoutMs, now = now, testCrashAt = testCrashAt))

    private fun num(n: Long): Json.Num = Json.Num(n.toString())

    private fun n(o: Any?): Long = Js.num(o)!!.toLong()

    private fun dse(f: () -> Any?): DurableStateError {
        try {
            f()
        } catch (e: DurableStateError) {
            return e
        }
        throw AssertionError("expected a DurableStateError")
    }

    private fun obj(f: File): Map<String, Any?> = Json.parseLenient(f.readText()) as Map<String, Any?>

    private fun names(d: File): List<String> = (d.list() ?: emptyArray()).sorted()

    private fun gens(d: File): List<Long> = names(d).mapNotNull { Regex("state\\.lock\\.(\\d+)").matchEntire(it)?.groupValues?.get(1)?.toLongOrNull() }.sorted()

    private fun top(d: File): Long = gens(d).last()

    private fun journal(d: File): List<Map<String, Any?>> =
        File(d, "state.journal").readText().split("\n").filter { it.isNotEmpty() }.map { Json.parseLenient(it) as Map<String, Any?> }

    private fun json(vararg kv: Pair<String, Any?>): String = Js.stringify(linkedMapOf(*kv))

    private fun held(p: Long, h: String, nonce: String, vararg more: Pair<String, Any?>): String = json("st" to "held", "pid" to p, "host" to h, "nonce" to nonce, *more)

    private fun recHash(seq: Long, prev: String, op: String, payload: String, ts: Long, gen: Long?): String {
        val arr = arrayListOf<Any?>(seq, prev, op, payload, ts)
        if (gen != null) arr.add(gen)
        return DurableState.hex(MessageDigest.getInstance("SHA-256").digest(Json.utf8(DurableState.DOMAIN + Js.stringify(arr))))
    }

    /** One journal line with a correct record hash; returns (line, hash). */
    private fun rec(seq: Long, prev: String, payload: String, op: String = "set", gen: Long? = null, ts: Long = 1000): Pair<String, String> {
        val h = recHash(seq, prev, op, payload, ts, gen)
        val m = linkedMapOf<String, Any?>("seq" to seq, "prev" to prev, "op" to op, "payload" to payload, "ts" to ts)
        if (gen != null) m["gen"] = gen
        m["h"] = h
        return Pair(Js.stringify(m), h)
    }

    private fun writeJournal(d: File, vararg lines: String) = File(d, "state.journal").writeText(lines.joinToString("") { it + "\n" })

    private fun writeHead(d: File, seq: Long, h: String, gen: Long? = null) =
        File(d, "state.head").writeText(if (gen == null) json("seq" to seq, "h" to h) else json("seq" to seq, "h" to h, "gen" to gen))

    /** Runs [body] as a crash child whose halter is [halter] (the property and the halter are restored afterwards). */
    private fun <T> asCrashChild(halter: () -> Unit, body: () -> T): T {
        val prev = DurableState.crashHalter
        val prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY)
        DurableState.crashHalter = halter
        System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1")
        try {
            return body()
        } finally {
            DurableState.crashHalter = prev
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY) else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp)
        }
    }

    /** Field 22 of /proc/self/stat read here, independently of the library; null off Linux. */
    private fun expectedStart(): String? = try {
        val st = String(Files.readAllBytes(Paths.get("/proc/self/stat")), Charsets.UTF_8)
        st.substring(st.lastIndexOf(')') + 2).split(' ')[19]
    } catch (e: Exception) {
        null
    }

    private fun expectedNs(): String? = try {
        Files.readSymbolicLink(Paths.get("/proc/self/ns/pid")).toString()
    } catch (e: Exception) {
        null
    }

    private fun genTimeout(d: File, g: Long, desc: String, ms: Long) =
        "lock-timeout: could not acquire the state lock in ${d.path} within $ms ms; blocked by ${File(d.path, "state.lock.$g").path} ($desc). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs"

    private fun legacyTimeout(d: File, desc: String, ms: Long) =
        "lock-timeout: could not acquire the state lock in ${d.path} within $ms ms; blocked by ${File(d.path, "state.lock").path} (legacy single-file lock of an older version; $desc). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs"

    /** The holder record this process writes into a generation it takes: exactly these members. */
    private fun assertOwnHolder(b: Map<String, Any?>, before: Long, after: Long, vararg extra: String) {
        val want = HashSet(listOf("st", "pid", "host", "nonce", "boot", "t") + extra)
        if (expectedNs() != null) want.add("ns")
        if (expectedStart() != null) want.add("start")
        assertEquals(want, b.keys.toSet())
        assertEquals("held", b["st"])
        assertEquals(pid, n(b["pid"]))
        assertEquals(host, b["host"])
        assertTrue("nonce ${b["nonce"]}", Regex("[0-9a-f]{24}").matches(b["nonce"] as String))
        assertTrue("boot ${b["boot"]}", Regex("[0-9a-f]{24}").matches(b["boot"] as String))
        if (expectedNs() != null) assertEquals(expectedNs(), b["ns"])
        if (expectedStart() != null) assertEquals(expectedStart(), b["start"])
        val t = n(b["t"])
        assertTrue("t=$t not in [$before, $after]", t in before..after)
    }

    // ---- opening ----

    @Test fun recordsAreStampedWithTheWallClockByDefault() {
        val d = tmp()
        val before = System.currentTimeMillis()
        open(d).set("a", num(1))
        val after = System.currentTimeMillis()
        val ts = n(journal(d)[0]["ts"])
        assertTrue("ts=$ts", ts in before..after)
    }

    @Test fun aDirThatIsARegularFileFailsWithTheFilesystemError() {
        val f = File(tmp(), "plain")
        f.writeText("x")
        val e: Throwable? = try {
            open(f); null
        } catch (x: Throwable) {
            x
        }
        assertTrue("expected FileAlreadyExistsException, got $e", e is FileAlreadyExistsException)
    }

    @Test fun missingParentsAreCreatedOwnerOnly() {
        assumeTrue("POSIX file permissions", java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))
        val base = tmp()
        val d = File(base, "a/b/state")
        open(d).set("k", num(1))
        for (p in listOf(File(base, "a"), File(base, "a/b"), d)) {
            assertEquals(p.path, "rwx------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(p.toPath())))
        }
    }

    @Test fun aPathTooLongForTheProbeFailsAsLinkUnsupportedNamingTheError() {
        assumeFalse("Linux path limits", isWindows)
        assumeTrue("Linux", File("/proc/self").exists())
        val sb = StringBuilder(tmp().path)
        while (true) {
            val rem = 4080 - sb.length - 1
            if (rem <= 0) break
            sb.append(File.separator).append("d".repeat(minOf(200, rem)))
        }
        val e = dse { open(File(sb.toString())) }
        assertEquals("link-unsupported", e.code)
        assertEquals(
            "link-unsupported: the state directory's filesystem does not provide working hard links with exclusive-create semantics (FileSystemException); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE",
            e.message,
        )
    }

    @Test fun keysAreOneTo256CharsWithoutNewlines() {
        val h = open(tmp())
        val msg = "invalid: key must be 1..256 chars without newlines"
        for (k in listOf("", "x".repeat(257), "\na", "a\nb", "a\n")) assertEquals(k, msg, dse { h.set(k, num(1)) }.message)
        h.set("y".repeat(256), num(2))
        assertEquals(2L, n(h.get("y".repeat(256))))
    }

    // ---- the head and the journal ----

    private fun headlessThenWrite(write: (DurableState) -> Unit) {
        val d = tmp()
        val h = open(d)
        h.set("a", num(1))
        File(d, "state.head").delete() // one record and no head: still a valid state
        write(h)
        assertEquals(2L, n(obj(File(d, "state.head"))["seq"]))
        assertEquals(listOf("a", "b"), open(d).keys())
    }

    @Test fun setRepairsAMissingHeadBeforeCommitting() = headlessThenWrite { it.set("b", num(2)) }

    @Test fun updateRepairsAMissingHeadBeforeCommitting() = headlessThenWrite { it.update("b") { num(2) } }

    private fun lagThenCrash(write: (DurableState) -> Unit) {
        val d = tmp()
        val late = open(d, testCrashAt = "after-journal-rename")
        val w = open(d)
        w.set("a", num(1))
        val head1 = File(d, "state.head").readText()
        w.set("b", num(2))
        File(d, "state.head").writeText(head1)
        val e = asCrashChild({ throw IllegalStateException("halted") }) {
            try {
                write(late); null
            } catch (x: IllegalStateException) {
                x
            }
        }
        assertEquals("halted", e?.message)
        assertEquals(3, journal(d).size)
        // the lagging head was brought up to the journal tail BEFORE the new journal was renamed in
        assertEquals(2L, n(obj(File(d, "state.head"))["seq"]))
    }

    @Test fun setBringsALaggingHeadUpToDateBeforeReplacingTheJournal() = lagThenCrash { it.set("c", num(3)) }

    @Test fun updateBringsALaggingHeadUpToDateBeforeReplacingTheJournal() = lagThenCrash { it.update("c") { num(3) } }

    @Test fun aHeadWithANegativeSeqIsCorrupt() {
        val d = tmp()
        writeHead(d, -1, g0)
        assertEquals("corrupt: state.head has an invalid shape", dse { open(d) }.message)
    }

    @Test fun aMissingJournalIsARollbackWhenTheHeadOrAFenceNamesAnyRecord() {
        val d1 = tmp()
        writeHead(d1, 1, g0)
        assertEquals("rollback: state.journal is missing but state.head records seq 1", dse { open(d1) }.message)
        val d2 = tmp()
        File(d2, "state.fence").writeText(json("v" to 1, "fences" to listOf(linkedMapOf("gen" to 1, "seq" to 1, "h" to g0))))
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 1", dse { open(d2) }.message)
        val d3 = tmp()
        val x = "ab".repeat(32)
        File(d3, "state.fence").writeText(json("v" to 1, "fences" to listOf(linkedMapOf("gen" to 1, "seq" to 0, "h" to g0), linkedMapOf("gen" to 2, "seq" to 3, "h" to x))))
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 3", dse { open(d3) }.message)
    }

    @Test fun everyCheckpointEntryMustBeAKeyValuePairOfStrings() {
        for (payload in listOf("[\"x\"]", "[[\"a\"]]", "[[1,\"1\"]]", "[[\"a\",1]]", "[[\"a\",\"1\",\"2\"]]")) {
            val d = tmp()
            writeJournal(d, rec(1, g0, payload, op = "checkpoint").first)
            assertEquals(payload, "corrupt: checkpoint entry is malformed", dse { open(d) }.message)
        }
        val d = tmp()
        writeJournal(d, rec(1, g0, "[[\"a\",\"1\"],[\"b\",\"[2]\"]]", op = "checkpoint").first)
        val s = open(d)
        assertEquals(1L, n(s.get("a")))
        assertEquals(listOf("a", "b"), s.keys())
    }

    @Test fun aGenerationLessJournalOneAheadOfAGenerationLessHeadOpens() {
        val d = tmp()
        val (l1, h1) = rec(1, g0, "a\n1")
        val (l2, _) = rec(2, h1, "b\n2")
        writeJournal(d, l1, l2)
        writeHead(d, 1, h1)
        assertEquals(2L, n(open(d).get("b")))
    }

    @Test fun aTailOlderThanTheHeadsGenerationNamesTheTailsGeneration() {
        val d1 = tmp()
        val (a1, ah1) = rec(1, g0, "a\n1")
        val (a2, _) = rec(2, ah1, "b\n2")
        writeJournal(d1, a1, a2)
        writeHead(d1, 1, ah1, 5)
        assertEquals(
            "corrupt: journal tail (seq 2) was written by lock generation 0, older than generation 5 that wrote state.head: a stale writer replaced the journal (refused)",
            dse { open(d1) }.message,
        )
        val d2 = tmp()
        val (b1, bh1) = rec(1, g0, "a\n1", gen = 2)
        val (b2, _) = rec(2, bh1, "b\n2", gen = 2)
        writeJournal(d2, b1, b2)
        writeHead(d2, 1, bh1, 5)
        assertEquals(
            "corrupt: journal tail (seq 2) was written by lock generation 2, older than generation 5 that wrote state.head: a stale writer replaced the journal (refused)",
            dse { open(d2) }.message,
        )
    }

    @Test fun anEmptyJournalOpensWithOrWithoutAGenesisHead() {
        val d1 = tmp()
        File(d1, "state.journal").writeText("")
        writeHead(d1, 0, g0)
        assertEquals(emptyList<String>(), open(d1).keys())
        val d2 = tmp()
        File(d2, "state.journal").writeText("")
        assertEquals(emptyList<String>(), open(d2).keys())
        assertFalse(File(d2, "state.head").exists())
    }

    @Test fun aMissingHeadBehindTwoRecordsIsARollback() {
        val d = tmp()
        val h = open(d)
        h.set("a", num(1))
        h.set("b", num(2))
        File(d, "state.head").delete()
        assertEquals("rollback: state.head is missing but the journal is at seq 2", dse { open(d) }.message)
    }

    @Test fun aStateEmptiedWhileOpenIsARollback() {
        val d = tmp()
        val h = open(d)
        h.set("a", num(1))
        File(d, "state.journal").writeText("")
        File(d, "state.head").delete()
        assertEquals("rollback: state was emptied while open", dse { h.get("a") }.message)
    }

    /** Four records by one handle with the head put back to seq 2; returns the records. */
    private fun headTwoBehind(d: File): List<Map<String, Any?>> {
        val h = open(d)
        h.set("a", num(1))
        h.set("b", num(2))
        val head2 = File(d, "state.head").readText()
        h.set("c", num(3))
        h.set("d", num(4))
        File(d, "state.head").writeText(head2)
        return journal(d)
    }

    @Test fun aHeadLeftBehindByAFencedStaleWriterIsAccepted() {
        val d = tmp()
        val r = headTwoBehind(d)
        File(d, "state.fence.${n(r[2]["gen"])}-ab").writeText(json("v" to 1, "fence" to linkedMapOf("gen" to n(r[2]["gen"]), "seq" to 2, "h" to r[1]["h"])))
        assertEquals(4L, n(open(d).get("d")))
        assertEquals(4L, n(obj(File(d, "state.head"))["seq"]))
    }

    @Test fun aHeadMoreThanOneRecordBehindIsCorruptUnlessAFenceExplainsIt() {
        val ahead = "corrupt: journal (seq 4) is more than one record ahead of state.head (seq 2)"
        val d1 = tmp()
        headTwoBehind(d1)
        assertEquals(ahead, dse { open(d1) }.message)
        // a fence that does not lift the head's generation explains nothing
        val d2 = tmp()
        val r2 = headTwoBehind(d2)
        val g2 = n(r2[1]["gen"])
        File(d2, "state.fence.$g2-ab").writeText(json("v" to 1, "fence" to linkedMapOf("gen" to g2, "seq" to 2, "h" to r2[1]["h"])))
        assertEquals(ahead, dse { open(d2) }.message)
        // a head naming no record of the journal is not a stale head
        val d3 = tmp()
        val r3 = headTwoBehind(d3)
        val g3 = n(r3[2]["gen"])
        File(d3, "state.fence.$g3-ab").writeText(json("v" to 1, "fence" to linkedMapOf("gen" to g3, "seq" to 2, "h" to r3[1]["h"])))
        writeHead(d3, 2, r3[0]["h"] as String, n(r3[1]["gen"]))
        assertEquals(ahead, dse { open(d3) }.message)
    }

    @Test fun recordTimestampsMustBeSafeIntegers() {
        val shape = "corrupt: journal line 1 has an invalid shape"
        val ok = tmp()
        writeJournal(ok, rec(1, g0, "a\n1", ts = 9007199254740991L).first)
        assertEquals(1L, n(open(ok).get("a")))
        for (ts in listOf(9007199254740992L, -9007199254740993L)) {
            val d = tmp()
            writeJournal(d, rec(1, g0, "a\n1", ts = ts).first)
            assertEquals("ts=$ts", shape, dse { open(d) }.message)
        }
        val d = tmp()
        writeJournal(d, "{\"seq\":1,\"prev\":\"$g0\",\"op\":\"set\",\"payload\":\"a\\n1\",\"ts\":1.5,\"h\":\"${"ab".repeat(32)}\"}")
        assertEquals(shape, dse { open(d) }.message)
    }

    // ---- fences ----

    @Test fun fenceFilesMustHaveTheirExactShape() {
        fun fenceList(text: String): String? {
            val d = tmp()
            File(d, "state.fence").writeText(text)
            return try {
                open(d); null
            } catch (e: DurableStateError) {
                e.message
            }
        }
        val shape = "corrupt: state.fence has an invalid shape"
        assertEquals(shape, fenceList("[]"))
        assertEquals(shape, fenceList("{\"v\":2,\"fences\":[]}"))
        assertEquals(shape, fenceList("{\"v\":1,\"fences\":{}}"))
        assertNull(fenceList("{\"v\":1,\"fences\":[]}"))
        assertEquals("corrupt: state.fence has an invalid entry", fenceList(json("v" to 1, "fences" to listOf(linkedMapOf("gen" to 1, "seq" to -1, "h" to g0)))))

        fun entry(name: String, text: String): String? {
            val d = tmp()
            File(d, name).writeText(text)
            return try {
                open(d); null
            } catch (e: DurableStateError) {
                e.message
            }
        }
        val e = "state.fence.1-ab"
        assertEquals("corrupt: $e has an invalid shape", entry(e, "[]"))
        assertEquals("corrupt: $e has an invalid shape", entry(e, json("v" to 2, "fence" to linkedMapOf("gen" to 1, "seq" to 0, "h" to g0))))
        assertEquals("corrupt: $e has an invalid entry", entry(e, json("v" to 1, "fence" to linkedMapOf("gen" to 0, "seq" to 0, "h" to g0))))
        assertNull(entry(e, json("v" to 1, "fence" to linkedMapOf("gen" to 1, "seq" to 0, "h" to g0))))
        val big = "state.fence.99999999999999999999-ab"
        assertEquals(
            "corrupt: $big names generation 9223372036854775807 but holds 1",
            entry(big, json("v" to 1, "fence" to linkedMapOf("gen" to 1, "seq" to 0, "h" to g0))),
        )
    }

    @Test fun aLoneFenceEntryFileIsRead() {
        // on a filesystem that lists names in order this entry is the first name in the directory
        val d = tmp()
        File(d, "state.fence.3-ab").writeText(json("v" to 1, "fence" to linkedMapOf("gen" to 3, "seq" to 2, "h" to "ab".repeat(32))))
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 2", dse { open(d) }.message)
    }

    @Test fun quarantineMovesEverythingAsideUnderOneTagAndRestartsTheFenceList() {
        val d = tmp()
        File(d, "state.journal").writeText("garbage\n")
        File(d, "state.fence").writeText(json("v" to 1, "fences" to listOf(linkedMapOf("gen" to 1, "seq" to 0, "h" to g0))))
        File(d, "state.fence.1-ab").writeText(json("v" to 1, "fence" to linkedMapOf("gen" to 1, "seq" to 0, "h" to g0)))
        val s = open(d, now = { 1234L }, recover = true)
        assertTrue(s.recovered)
        val nm = names(d)
        val tag = Regex("state\\.journal\\.quarantine-(1234-[0-9a-f]{6})").let { re -> nm.mapNotNull { re.matchEntire(it)?.groupValues?.get(1) } }
        assertEquals(nm.toString(), 1, tag.size)
        assertTrue(nm.toString(), nm.contains("state.fence.quarantine-${tag[0]}"))
        assertTrue(nm.toString(), nm.contains("state.fence.1-ab.quarantine-${tag[0]}"))
        assertFalse(nm.contains("state.fence.1-ab"))
        assertFalse(nm.contains("state.journal"))
        assertEquals(json("v" to 1, "fences" to listOf(linkedMapOf("gen" to 1L, "seq" to 0L, "h" to g0, "from" to 0L, "t" to 1234L))) + "\n", File(d, "state.fence").readText())
    }

    // ---- the lock: what this process writes ----

    @Test fun aTakenGenerationRecordsExactlyThisProcess() {
        val d = tmp()
        val h = open(d)
        val raw = AtomicReference<String>()
        val before = System.currentTimeMillis()
        h.update("a") { raw.set(File(d, "state.lock.${top(d)}").readText()); num(1) }
        val after = System.currentTimeMillis()
        assertOwnHolder(Json.parseLenient(raw.get()) as Map<String, Any?>, before, after)
    }

    @Test fun takingOverADeadRecoveringHolderFencesItsGeneration() {
        val d = tmp()
        File(d, "state.lock.1").writeText(held(dead, host, "n", "recovering" to 7))
        val before = System.currentTimeMillis()
        open(d)
        val after = System.currentTimeMillis()
        assertOwnHolder(obj(File(d, "state.lock.2")), before, after, "recovering")
        assertEquals(7L, n(obj(File(d, "state.lock.2"))["recovering"]))
        val fences = names(d).filter { Regex("state\\.fence\\.2-[0-9a-f]{12}").matches(it) }
        assertEquals(names(d).toString(), 1, fences.size)
        val doc = obj(File(d, fences[0]))
        assertEquals(setOf("v", "fence"), doc.keys)
        val f = doc["fence"] as Map<String, Any?>
        assertEquals(listOf("gen", "seq", "h", "from", "t"), f.keys.toList())
        assertEquals(listOf(2L, 0L, g0, 1L), listOf(n(f["gen"]), n(f["seq"]), f["h"], n(f["from"])))
        assertTrue(n(f["t"]) in before..after)
    }

    @Test fun aHolderRecordWithANonStringNamespaceIsJudgedByItsPid() {
        val d = tmp()
        File(d, "state.lock.1").writeText(held(dead, host, "n", "ns" to 5))
        open(d).set("a", num(1))
        assertEquals(1L, n(open(d).get("a")))
    }

    @Test fun aLivePidWhoseStartTimeChangedIsAReusedPid() {
        assumeTrue("process start times (Linux)", expectedStart() != null)
        val d = tmp()
        File(d, "state.lock.1").writeText(held(pid, host, "n", "start" to "1"))
        open(d).set("a", num(1))
        assertEquals(1L, n(open(d).get("a")))
    }

    // ---- the lock: garbage collection ----

    @Test fun onlyTheLast16GenerationsAreKept() {
        val d = tmp()
        for (g in 1..30) File(d, "state.lock.$g").writeText("{\"st\":\"free\"}")
        val h = open(d) // takes 31, releases as 32
        assertEquals((16L..32L).toList(), gens(d))
        val inside = AtomicReference<List<Long>>()
        h.update("a") { inside.set(gens(d)); num(1) } // takes 33
        assertEquals((17L..33L).toList(), inside.get())
        assertEquals((18L..34L).toList(), gens(d))
    }

    @Test fun onlyTempLockFilesOfDeadProcessesAreCollected() {
        val d = tmp()
        val planted = listOf("state.lock.tmp-$dead-ab", "state.lock.tmp-$pid-ab", "state.lock.tmp-abc", "state.lock.tmp-0-ab", "state.lock.tmp-1-ab")
        for (f in planted) File(d, f).writeText("x")
        open(d).set("a", num(1))
        val pid1Alive: Boolean = ProcessHandle.of(1L).map { it.isAlive }.orElse(false)
        val want = listOf("state.lock.tmp-$pid-ab", "state.lock.tmp-abc", "state.lock.tmp-0-ab") + (if (pid1Alive) listOf("state.lock.tmp-1-ab") else emptyList())
        val nm = names(d)
        assertEquals(want.sorted(), nm.filter { it.startsWith("state.lock.tmp-") })
        assertTrue(nm.toString(), nm.none { it.startsWith("state.probe-") || it.contains(".tmp-") && !it.startsWith("state.lock.tmp-") })
    }

    @Test fun theHighestGenerationIsFoundWhereverItIsListed() {
        // "state.lock.10" lists before "state.lock.9" on a filesystem that keeps names sorted
        val d = tmp()
        File(d, "state.lock.10").writeText("{\"st\":\"free\"}")
        File(d, "state.lock.9").writeText("garbage")
        open(d).set("a", num(1))
        assertEquals(listOf(9L, 10L, 11L, 12L, 13L, 14L), gens(d))
    }

    @Test fun aGenerationCreatedBelowTheRealTopIsNeverTakenAsTheLock() {
        // generation Long.MAX_VALUE + 1 wraps to a name no lock scan counts: the creator must keep looking, never proceed
        val d = tmp()
        File(d, "state.lock.${Long.MAX_VALUE}").writeText("{\"st\":\"free\"}")
        val done = CountDownLatch(1)
        val t = Thread {
            try {
                open(d, lockTimeoutMs = 200)
            } catch (e: Throwable) {
                // the directory is pulled away below to stop the scan
            } finally {
                done.countDown()
            }
        }
        t.isDaemon = true
        t.start()
        val finished = done.await(600, TimeUnit.MILLISECONDS)
        val stop = System.currentTimeMillis() + 5000
        while (t.isAlive && System.currentTimeMillis() < stop) {
            d.deleteRecursively()
            t.join(20)
        }
        assertFalse("the open went ahead on a generation below the top", finished)
    }

    // ---- the lock: waiting and timing out ----

    @Test fun aLockTimeoutDescribesTheHolderRecord() {
        val ms = 50L
        fun timeout(body: String): Pair<File, DurableStateError> {
            val d = tmp()
            File(d, "state.lock.1").writeText(body)
            return d to dse { open(d, lockTimeoutMs = ms) }
        }
        val inc = "; release it with expectedHolder: 'unreadable'"
        val cases = listOf(
            "garbage" to "an unreadable holder record",
            "{\"st\":\"held\"}" to "an incomplete holder record (pid=? host=? nonce=?)$inc",
            "[]" to "an incomplete holder record (pid=? host=? nonce=?)$inc",
            json("st" to "held", "pid" to 5, "host" to "elsewhere", "nonce" to "") to "an incomplete holder record (pid=5 host=elsewhere nonce=?)$inc",
            json("st" to "held", "pid" to 5, "host" to "elsewhere", "nonce" to 7) to "an incomplete holder record (pid=5 host=elsewhere nonce=?)$inc",
            json("st" to "held", "host" to "elsewhere", "nonce" to "abc") to "an incomplete holder record (pid=? host=elsewhere nonce=abc)$inc",
            json("st" to "held", "pid" to 5, "nonce" to "abc") to "an incomplete holder record (pid=5 host=? nonce=abc)$inc",
            json("st" to "held", "pid" to 5, "host" to "elsewhere", "nonce" to "abc") to "holder pid=5 host=elsewhere nonce=abc",
            json("st" to "held", "pid" to 5, "host" to "elsewhere", "nonce" to "abc", "ns" to "pid:[1]") to "holder pid=5 host=elsewhere nonce=abc (another PID namespace)",
        )
        for ((body, desc) in cases) {
            val (d, e) = timeout(body)
            assertEquals(body, genTimeout(d, 1, desc, ms), e.message)
        }
    }

    @Test fun aLiveHolderMakesTheWaiterWaitTheFullTimeout() {
        val d = tmp()
        File(d, "state.lock.1").writeText(held(pid, host, "n"))
        val t0 = System.currentTimeMillis()
        val e = dse { open(d, lockTimeoutMs = 300) }
        assertTrue("timed out early", System.currentTimeMillis() - t0 >= 300)
        assertEquals(genTimeout(d, 1, "holder pid=$pid host=$host nonce=n", 300), e.message)
    }

    @Test fun aLegacyLockBlocksUntilItsHolderIsGone() {
        // an unreadable legacy file older than a second is a torn file of a dead writer: ignored
        val old = tmp()
        File(old, "state.lock").writeText("torn")
        File(old, "state.lock").setLastModified(System.currentTimeMillis() - 10_000)
        open(old).set("a", num(1))
        // a recent unreadable one blocks
        val fresh = tmp()
        File(fresh, "state.lock").writeText("torn")
        File(fresh, "state.lock").setLastModified(System.currentTimeMillis() + 60_000)
        assertEquals(legacyTimeout(fresh, "an unreadable holder record", 100), dse { open(fresh, lockTimeoutMs = 100) }.message)
        // a live legacy holder blocks, named as such
        val live = tmp()
        File(live, "state.lock").writeText(held(pid, host, "n"))
        assertEquals(legacyTimeout(live, "holder pid=$pid host=$host nonce=n", 100), dse { open(live, lockTimeoutMs = 100) }.message)
        // when a live generation holder blocks too, the generation lock is named
        val both = tmp()
        File(both, "state.lock").writeText(held(pid, host, "n"))
        File(both, "state.lock.1").writeText(held(pid, host, "m"))
        assertEquals(genTimeout(both, 1, "holder pid=$pid host=$host nonce=m", 100), dse { open(both, lockTimeoutMs = 100) }.message)
    }

    @Test fun anInterruptedWaiterGivesUpAndKeepsItsInterrupt() {
        val d = tmp()
        val h = open(d, lockTimeoutMs = 5000)
        File(d, "state.lock.${top(d) + 1}").writeText(held(pid, host, "n"))
        val got = AtomicReference<Throwable?>()
        val flag = AtomicReference<Boolean>()
        val t = Thread {
            Thread.currentThread().interrupt()
            try {
                h.get("a")
            } catch (e: Throwable) {
                got.set(e)
            }
            flag.set(Thread.interrupted())
        }
        t.start()
        t.join(5000)
        val e = got.get()
        assertTrue("got $e", e is DurableStateError)
        assertEquals("lock-timeout: interrupted while waiting for the state lock in ${d.path}", e!!.message)
        assertEquals(true, flag.get())
    }

    // ---- the lock: lost under a writer ----

    private fun lockLost(prep: (File, Long) -> Unit): Triple<File, Long, DurableStateError> {
        val d = tmp()
        val h = open(d)
        var g = -1L
        val e = dse {
            h.update("k") {
                g = top(d)
                prep(d, g)
                num(1)
            }
        }
        assertFalse(File(d, "state.journal").exists())
        assertTrue(names(d).toString(), names(d).none { it.contains(".tmp-") })
        return Triple(d, g, e)
    }

    @Test fun aWriterThatLostTheLockWritesNothingAndSaysWhatItSaw() {
        fun msg(g: Long, top: Long, st: String) = "lock-lost: the state lock is no longer held by this writer (generation $g, highest $top $st); nothing was written"
        lockLost { d, g -> File(d, "state.lock.${g + 1}").writeText(held(pid, host, "x")) }.let { (_, g, e) -> assertEquals(msg(g, g + 1, "held"), e.message) }
        lockLost { d, g -> File(d, "state.lock.$g").writeText("{\"st\":\"free\"}") }.let { (_, g, e) -> assertEquals(msg(g, g, "free"), e.message) }
        lockLost { d, g -> File(d, "state.lock.$g").writeText(held(pid, host, "someone-else")) }.let { (_, g, e) -> assertEquals(msg(g, g, "held"), e.message) }
        lockLost { d, g -> File(d, "state.lock.$g").writeText("garbage") }.let { (_, g, e) -> assertEquals(msg(g, g, "unreadable"), e.message) }
        lockLost { d, g -> File(d, "state.lock.$g").writeText("[]") }.let { (_, g, e) -> assertEquals(msg(g, g, "held"), e.message) }
    }

    @Test fun aLockLostBetweenJournalAndHeadIsReportedAsSuch() {
        val d = tmp()
        val h = open(d, testCrashAt = "after-journal-rename")
        var g = -1L
        val e = asCrashChild({
            g = top(d)
            File(d, "state.lock.${g + 1}").writeText(held(pid, host, "x"))
        }) { dse { h.set("a", num(1)) } }
        assertEquals(
            "lock-lost: the state lock is no longer held by this writer (generation $g, highest ${g + 1} held); the journal record (seq 1) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)",
            e.message,
        )
        assertEquals(1, journal(d).size)
        assertFalse(File(d, "state.head").exists())
    }

    // ---- operator recovery ----

    @Test fun recoveryTakesFencesAndReleasesWithExactBodies() {
        val d = tmp()
        val h = open(d)
        h.set("a", num(1))
        h.set("b", num(2))
        val tail = journal(d)[1]["h"] as String
        val g = top(d) + 1
        File(d, "state.lock.$g").writeText("garbage")
        val before = System.currentTimeMillis()
        val r = recoverDurableState(RecoverDurableStateOptions(d.path, true, "unreadable"))
        val after = System.currentTimeMillis()
        assertTrue(r.released)
        assertEquals("released", r.reason)
        assertEquals(File(d.path, "state.lock.$g").path, r.lockFile)
        val taken = obj(File(d, "state.lock.${g + 1}"))
        assertOwnHolder(taken, before, after, "recovering")
        assertEquals(g, n(taken["recovering"]))
        val free = obj(File(d, "state.lock.${g + 2}"))
        assertEquals(listOf("st", "t", "recoveredFrom"), free.keys.toList())
        assertEquals("free", free["st"])
        assertEquals(g, n(free["recoveredFrom"]))
        assertTrue(n(free["t"]) in before..after)
        val fences = names(d).filter { Regex("state\\.fence\\.${g + 1}-[0-9a-f]{12}").matches(it) }
        assertEquals(names(d).toString(), 1, fences.size)
        val f = obj(File(d, fences[0]))["fence"] as Map<String, Any?>
        assertEquals(listOf("gen", "seq", "h", "from", "t"), f.keys.toList())
        assertEquals(listOf(g + 1, 2L, tail, g), listOf(n(f["gen"]), n(f["seq"]), f["h"], n(f["from"])))
        assertTrue(n(f["t"]) in before..after)
        assertTrue(names(d).toString(), names(d).none { it.contains(".tmp-") })
        assertEquals(2L, n(open(d).get("b")))
    }

    @Test fun recoveryRefusesWhenItsGenerationWasTakenMeanwhile() {
        val d = tmp()
        val topName = "state.lock.${Long.MAX_VALUE}"
        File(d, topName).writeText("garbage")
        File(d, "state.lock.${Long.MIN_VALUE}").writeText("x") // where generation Long.MAX_VALUE + 1 lands
        val e = dse { recoverDurableState(RecoverDurableStateOptions(d.path, true, "unreadable")) }
        assertEquals("invalid: ${File(d.path, topName).path} was superseded while recovering; re-read the lock state and retry", e.message)
        assertTrue(names(d).toString(), names(d).none { it.startsWith("state.lock.tmp-") })
        assertTrue(names(d).none { it.startsWith("state.fence") })
    }

    @Test fun recoveryConfirmsTheHolderExactly() {
        fun refuse(body: String, exp: Any): String {
            val d = tmp()
            File(d, "state.lock.1").writeText(body)
            val e = dse { recoverDurableState(RecoverDurableStateOptions(d.path, true, exp)) }
            assertEquals(listOf("state.lock.1"), names(d)) // nothing was changed
            return e.message!!.replace(File(d.path, "state.lock.1").path, "\$P")
        }
        val other = ExpectedLockHolder("elsewhere", 5, "zzz")
        for (u in listOf("garbage", "5", "\"s\"", "null", "")) {
            assertEquals(u, "invalid: \$P is unreadable; pass expectedHolder: 'unreadable' to release it", refuse(u, other))
        }
        for (inc in listOf("{\"st\":\"held\",\"pid\":5}", "[1]", json("st" to "held", "host" to "x".repeat(300)))) {
            val raw = Js.stringify(Json.parseLenient(inc)).take(160)
            assertEquals(
                "invalid: \$P has an incomplete holder record ($raw); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it",
                refuse(inc, other),
            )
        }
        val complete = json("st" to "held", "pid" to 5, "host" to "elsewhere", "nonce" to "abc")
        assertEquals("invalid: \$P is readable (holder pid=5 host=elsewhere); expectedHolder 'unreadable' does not match", refuse(complete, "unreadable"))
        assertEquals(
            "invalid: expectedHolder does not match the holder recorded in \$P (recorded pid=5 host=elsewhere nonce=abc); nothing was changed",
            refuse(complete, other),
        )
        val alive = "invalid: the holder of \$P (pid $pid) is alive in this PID namespace; refusing to release a live holder"
        assertEquals(alive, refuse(held(pid, host, "abc"), ExpectedLockHolder(host, pid, "abc")))
        assertEquals(alive, refuse(json("st" to "held", "pid" to pid, "host" to host), "unreadable"))
    }

    @Test fun anIncompleteArrayRecordIsReleasedAsUnreadable() {
        val d = tmp()
        File(d, "state.lock.1").writeText("[]")
        val r = recoverDurableState(RecoverDurableStateOptions(d.path, true, "unreadable"))
        assertTrue(r.released)
        assertEquals(listOf(1L, 2L, 3L), gens(d))
    }

    // ---- host probes ----

    @Test fun theProcessProbesReportThisProcess() {
        assertEquals(pid, DurableState.selfPid)
        assertTrue(DurableState.pidAlive(pid))
        assertFalse(DurableState.pidAlive(dead))
        assertEquals(expectedStart(), DurableState.procStartOf(pid))
        assertNull(DurableState.procStartOf(dead))
        assertEquals(expectedNs(), DurableState.ownNamespace())
        assertEquals("000f10ff", DurableState.hex(byteArrayOf(0, 0x0f, 0x10, -1)))
        assertTrue(Regex("[0-9a-f]{10}").matches(DurableState.randomHex(5)))
    }

    @Test fun aDirectoryFsyncFailsOnlyWhereDirectoriesCanBeOpened() {
        val d = tmp()
        DurableState.fsyncDir(d.path)
        val missing = File(d, "missing").path
        val e: Throwable? = try {
            DurableState.fsyncDir(missing); null
        } catch (x: Throwable) {
            x
        }
        if (isWindows) assertNull(e) else assertTrue("got $e", e is IOException)
    }

    /** A compiler-generated static (or companion) method of DurableState: a lazy initializer or a local function in one. */
    private fun synthetic(match: (Method) -> Boolean): (Array<Any?>) -> Any? {
        val all = DurableState::class.java.declaredMethods.toList() + DurableState.Companion::class.java.declaredMethods.toList()
        val ms = all.filter(match)
        assertEquals(ms.map { it.name }.toString(), 1, ms.size)
        val m = ms[0]
        m.isAccessible = true
        return { args ->
            try {
                if (Modifier.isStatic(m.modifiers)) m.invoke(null, *args) else m.invoke(DurableState.Companion, *args)
            } catch (e: java.lang.reflect.InvocationTargetException) {
                throw e.targetException
            }
        }
    }

    private fun lazyInit(prop: String) = synthetic { it.name.startsWith("${prop}_delegate\$lambda\$") && !it.name.removePrefix("${prop}_delegate\$lambda\$").contains('$') && it.parameterCount == 0 }

    @Test fun theBootIdIs12RandomBytes() {
        assertTrue(Regex("[0-9a-f]{24}").matches(lazyInit("BOOT_ID")(arrayOf<Any?>()) as String))
    }

    private fun rawHostnameCommand(): String {
        val p = ProcessBuilder("hostname").redirectErrorStream(true).start()
        val out = String(p.inputStream.readBytes(), Charsets.UTF_8)
        p.waitFor()
        return out
    }

    @Test fun eachHostnameSourceAnswersFromItsOwnPlace() {
        val src = DurableState.HOSTNAME_SOURCES
        assertEquals(4, src.size)
        val proc = Paths.get("/proc/sys/kernel/hostname")
        if (Files.exists(proc)) assertEquals(String(Files.readAllBytes(proc), Charsets.UTF_8), src[0]()) else assertTrue(runCatching { src[0]() }.isFailure)
        assertEquals(rawHostnameCommand(), src[1]())
        val prev = DurableState.crashEnv
        DurableState.crashEnv = { k -> mapOf("HOSTNAME" to " env-host ", "COMPUTERNAME" to "env-computer")[k] }
        try {
            assertEquals(" env-host ", src[2]())
            assertEquals("env-computer", src[3]())
        } finally {
            DurableState.crashEnv = prev
        }
    }

    @Test fun theHostnameIsTheFirstNonBlankTrimmedSourceElseTheResolver() {
        val none: () -> String? = { null }
        val blank: () -> String? = { " \t\n " }
        val boom: () -> String? = { throw IOException("no") }
        assertEquals("b", DurableState.firstClean(listOf(none, blank, boom, { " b " }, { "c" })))
        assertNull(DurableState.firstClean(listOf(none, blank, boom, { "" })))
        assertNull(DurableState.firstClean(emptyList()))
        assertEquals("c", DurableState.firstClean(listOf<() -> String?>({ "c" }, { "d" })))
        assertEquals("x", DurableState.firstClean(listOf<() -> String?>({ "x" })))
        assertEquals("a b", DurableState.firstClean(listOf<() -> String?>({ "  a b \r\n" })))
        assertEquals("pca-test-host-7", DurableState.hostnameFrom(listOf(none, { " pca-test-host-7\n" })))
        val local = runCatching { java.net.InetAddress.getLocalHost().hostName }
        val got = runCatching { DurableState.hostnameFrom(listOf(none, blank)) }
        assertEquals(local.getOrNull(), got.getOrNull())
        assertEquals(local.exceptionOrNull()?.javaClass, got.exceptionOrNull()?.javaClass)
        // the lazy property computes exactly that from the real sources
        val expected = DurableState.hostnameFrom(DurableState.HOSTNAME_SOURCES)
        assertEquals(expected, lazyInit("hostname")(arrayOf<Any?>()))
        assertEquals(expected, DurableState.hostname)
        val independent = try {
            String(Files.readAllBytes(Paths.get("/proc/sys/kernel/hostname")), Charsets.UTF_8).trim()
        } catch (e: Exception) {
            rawHostnameCommand().trim()
        }
        if (independent.isNotEmpty()) assertEquals(independent, expected)
    }

    // ---- hard links (through the overridable linker) ----

    private val realLinker: Linker = DurableState.linker
    private val linkHead = "link-unsupported: the state directory's filesystem does not provide working hard links with exclusive-create semantics ("
    private val linkTail = "); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE"

    private fun <T> withLinker(l: Linker, body: () -> T): T {
        val prev = DurableState.linker
        DurableState.linker = l
        try {
            return body()
        } finally {
            DurableState.linker = prev
        }
    }

    private fun probeFails(l: Linker): String {
        val d = tmp()
        val e = withLinker(l) { dse { open(d) } }
        assertTrue(names(d).toString(), names(d).none { it.startsWith("state.probe-") })
        return e.message!!
    }

    @Test fun theProbeAndTheLockLinkFreshTempsOfTheirOwn() {
        val d = tmp()
        val calls = ArrayList<Pair<java.nio.file.Path, java.nio.file.Path>>()
        withLinker(Linker { n, x -> calls.add(n to x); realLinker.link(n, x) }) { open(d) }
        assertEquals(4, calls.size) // the probe twice, then generation 1 (taken) and 2 (released)
        val a = calls[0].second.fileName.toString()
        assertTrue(a, Regex("state\\.probe-$pid-[0-9a-f]{12}").matches(a))
        for (i in 0..1) {
            assertEquals(a + ".lnk", calls[i].first.fileName.toString())
            assertEquals(a, calls[i].second.fileName.toString())
        }
        for (i in 2..3) {
            assertEquals("state.lock.${i - 1}", calls[i].first.fileName.toString())
            assertTrue(calls[i].second.toString(), Regex("state\\.lock\\.tmp-$pid-[0-9a-f]{12}").matches(calls[i].second.fileName.toString()))
        }
        for (c in calls) {
            assertEquals(d.toPath().toAbsolutePath().normalize(), c.first.toAbsolutePath().parent.normalize())
            assertEquals(d.toPath().toAbsolutePath().normalize(), c.second.toAbsolutePath().parent.normalize())
        }
        assertTrue(names(d).toString(), names(d).none { it.startsWith("state.probe-") || it.startsWith("state.lock.tmp-") })
    }

    @Test fun aFilesystemWhoseLinksAreNotExclusiveIsRefusedAtOpen() {
        val notAtomic = linkHead + "link(2) is not atomic/exclusive here" + linkTail
        var n1 = 0
        assertEquals(notAtomic, probeFails(Linker { n, x -> if (n1++ == 0) realLinker.link(n, x) })) // the second link also "succeeds"
        var n2 = 0
        assertEquals(notAtomic, probeFails(Linker { n, x -> if (n2++ == 0) realLinker.link(n, x) else throw IOException("not here") }))
        assertEquals(linkHead + "IOException" + linkTail, probeFails(Linker { _, _ -> throw IOException("boom") }))
        assertEquals(linkHead + "UnsupportedOperationException" + linkTail, probeFails(Linker { _, _ -> throw UnsupportedOperationException("no") }))
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("unix")) {
            var n3 = 0 // "exclusive", yet no link was ever made: the link count stays 1
            assertEquals(notAtomic, probeFails(Linker { n, _ -> if (n3++ > 0) throw FileAlreadyExistsException(n.toString()) }))
        }
    }

    @Test fun aLockLinkThatFailsIsAnUnfitFilesystemAndLeavesNoTemp() {
        val d = tmp()
        val s = open(d)
        val before = gens(d)
        assertEquals(
            "invalid: the state directory's filesystem cannot create the lock atomically (link: IOException)",
            withLinker(Linker { _, _ -> throw IOException("no") }) { dse { s.set("a", num(1)) } }.message,
        )
        assertEquals(
            "invalid: the state directory's filesystem cannot create the lock atomically (link: UnsupportedOperationException)",
            withLinker(Linker { _, _ -> throw UnsupportedOperationException("no") }) { dse { s.set("a", num(1)) } }.message,
        )
        assertEquals(before, gens(d))
        assertTrue(names(d).toString(), names(d).none { it.startsWith("state.lock.tmp-") })
        s.set("a", num(1))
        assertEquals(1L, n(s.get("a")))
    }

    // ---- the crash hooks, armed in-process (the halter records the directory and returns) ----

    private fun hooked(point: String, flag: String, d: File, run: () -> Unit): List<List<String>> {
        val hits = ArrayList<List<String>>()
        val prevEnv = DurableState.crashEnv
        DurableState.crashEnv = { k -> if (k == "PCA_DURABLE_TEST") flag else if (k == DurableState.RECOVER_CRASH_ENV) point else null }
        try {
            asCrashChild({ hits.add(names(d)) }) { run() }
        } finally {
            DurableState.crashEnv = prevEnv
        }
        return hits
    }

    @Test fun everyRecoveryCrashPointFiresOnceAtItsStep() {
        val tmpLock = Regex("state\\.lock\\.tmp-$pid-[0-9a-f]{12}")
        val fence = Regex("state\\.fence\\.2-[0-9a-f]{12}")
        val fenceTmp = Regex("state\\.fence\\.2-[0-9a-f]{12}\\.tmp-$pid-[0-9a-f]{12}")
        fun at(point: String, flag: String = "1"): List<List<String>> {
            val d = tmp()
            File(d, "state.lock.1").writeText("garbage")
            val hits = hooked(point, flag, d) { assertTrue(recoverDurableState(RecoverDurableStateOptions(d.path, true, "unreadable")).released) }
            assertEquals(listOf(1L, 2L, 3L), gens(d))
            return hits
        }
        fun one(point: String): List<String> {
            val h = at(point)
            assertEquals(point, 1, h.size)
            return h[0]
        }
        fun List<String>.has(r: Regex) = any { r.matches(it) }
        one("before-lock").let { assertFalse(it.toString(), it.contains("state.lock.2") || it.has(tmpLock)) }
        one("after-lock-temp").let { assertTrue(it.toString(), it.has(tmpLock) && !it.contains("state.lock.2")) }
        one("after-lock").let { assertTrue(it.toString(), it.contains("state.lock.2") && !it.has(tmpLock) && !it.has(fence) && !it.has(fenceTmp)) }
        one("after-fence-temp").let { assertTrue(it.toString(), it.has(fenceTmp) && !it.has(fence)) }
        one("after-fence").let { assertTrue(it.toString(), it.has(fence) && !it.has(fenceTmp) && !it.contains("state.lock.3")) }
        one("after-release-temp").let { assertTrue(it.toString(), it.has(tmpLock) && !it.contains("state.lock.3")) }
        one("after-release").let { assertTrue(it.toString(), it.contains("state.lock.3") && !it.has(tmpLock)) }
        assertEquals(emptyList<List<String>>(), at("after-lock", flag = "0"))
        assertEquals(emptyList<List<String>>(), at("no-such-point"))
    }

    @Test fun theTakeoverCrashPointsFireBeforeAndInsideTheFence() {
        val fence = Regex("state\\.fence\\.2-[0-9a-f]{12}")
        val fenceTmp = Regex("state\\.fence\\.2-[0-9a-f]{12}\\.tmp-$pid-[0-9a-f]{12}")
        fun at(point: String): List<String> {
            val d = tmp()
            File(d, "state.lock.1").writeText(held(dead, host, "n", "recovering" to 0))
            val hits = hooked(point, "1", d) { open(d) }
            assertEquals(point, 1, hits.size)
            assertTrue(names(d).toString(), names(d).any { fence.matches(it) })
            return hits[0]
        }
        at("takeover-after-lock").let { assertTrue(it.toString(), it.contains("state.lock.2") && it.none { n -> n.startsWith("state.fence") }) }
        at("takeover-after-fence-temp").let { assertTrue(it.toString(), it.any { n -> fenceTmp.matches(n) } && it.none { n -> fence.matches(n) }) }
    }
}
