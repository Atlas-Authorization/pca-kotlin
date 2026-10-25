package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Differential kill test for SafeRegex.kt: every pattern of a TS-generated corpus (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs
 * over packages/pca/src/safe-regex.ts + predicates.ts) must compile to the EXACT same NFA program (op, x, y, set ranges, negation,
 * instruction for instruction) or be refused alike, get the same isSafeSource verdict, and full-match every recorded subject
 * with the same true / false / null.
 */
class K042SafeRegexOracleTest {
    private fun dump(c: SafeRegex.Compiled): String {
        val prog = c.program
        assertEquals("Compiled.size()", prog.size, c.size())
        val sb = StringBuilder()
        for ((k, ins) in prog.withIndex()) {
            if (k > 0) sb.append(';')
            sb.append(ins.op).append(',').append(ins.x).append(',').append(ins.y).append(',')
            val cs = ins.set
            if (cs == null) { sb.append("-,-"); continue }
            sb.append(if (cs.negated) 1 else 0).append(',')
            if (cs.ranges.isEmpty()) sb.append('E')
            for (r in cs.ranges.indices) {
                if (r > 0) sb.append(':')
                assertEquals(2, cs.ranges[r].size)
                sb.append(cs.ranges[r][0]).append('-').append(cs.ranges[r][1])
            }
        }
        var s = sb.toString()
        if (s.length > 1000) s = "H" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)))
        return s
    }

    private fun unhex(h: String): String {
        if (h == "-") return ""
        val sb = StringBuilder()
        var k = 0
        while (k < h.length) { sb.append(h.substring(k, k + 4).toInt(16).toChar()); k += 4 }
        return sb.toString()
    }

    private fun show(s: String): String {
        val sb = StringBuilder()
        for (ch in s) sb.append(if (ch.code in 0x20 until 0x7f) ch.toString() else String.format("\\u%04x", ch.code))
        return if (sb.length > 80) sb.substring(0, 80) + "...(${s.length})" else sb.toString()
    }
    private fun abbrev(s: String) = if (s.length > 160) s.substring(0, 160) + "..." else s

    @Test fun corpusMatchesTheTsReference() {
        val fails = ArrayList<String>()
        var patterns = 0; var compiled = 0; var safe = 0; var matches = 0
        GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-saferegex.txt.gz"))).bufferedReader(Charsets.UTF_8).use { r ->
            var pat = ""; var cur: SafeRegex.Compiled? = null; var firstSubject = false
            while (true) {
                val line = r.readLine() ?: break
                val f = line.split(" ")
                if (f[0] == "P") {
                    patterns++
                    pat = unhex(f[1])
                    val wantSafe = f[2] == "1"; val wantProg = f[3]
                    cur = SafeRegex.compile(pat)
                    val got = if (cur == null) "N" else dump(cur)
                    if (cur != null) compiled++
                    if (got != wantProg) fails.add("compile /${show(pat)}/: want ${abbrev(wantProg)} got ${abbrev(got)}")
                    val gotSafe = SafeRegex.isSafeSource(pat)
                    if (gotSafe) safe++
                    if (gotSafe != wantSafe) fails.add("isSafeSource /${show(pat)}/: want $wantSafe got $gotSafe")
                    if (cur == null && SafeRegex.fullMatch(pat, "a") != null) fails.add("fullMatch on refused /${show(pat)}/ not null")
                    firstSubject = true
                } else {
                    matches++
                    val subj = unhex(f[1])
                    val want: Boolean? = if (f[2] == "N") null else f[2] == "T"
                    if (cur == null) { fails.add("subject for a refused pattern /${show(pat)}/"); continue }
                    val got = SafeRegex.run(cur, subj)
                    if (want != got) fails.add("run /${show(pat)}/ on \"${show(subj)}\": want $want got $got")
                    if (firstSubject) {
                        val fm = SafeRegex.fullMatch(pat, subj)
                        if (want != fm) fails.add("fullMatch /${show(pat)}/ on \"${show(subj)}\": want $want got $fm")
                        firstSubject = false
                    }
                }
                if (fails.size >= 3) break
            }
        }
        if (fails.isNotEmpty()) fail("${fails.size} differences, first: \n" + fails.take(40).joinToString("\n"))
        assertEquals(8648, patterns); assertEquals(5267, compiled); assertEquals(3206, safe); assertEquals(572525, matches)
    }
}
