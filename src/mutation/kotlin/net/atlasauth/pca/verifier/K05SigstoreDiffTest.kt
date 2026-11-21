package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for offline Sigstore bundle verification: test-data/k05-sigstore.json.gz from
 * tools/pca-audit/k05-oracles/sigstore-oracle.mts. fn -> Kotlin:
 *   parseTrustedRoot(json)               Sigstore.parseTrustedRoot     summary exact (keyId std base64, validity ms, end null =
 *                                                                       unbounded, v2 name, chain lengths); {$throws} -> must throw
 *   verifySigstoreBundleCore(b, {$root}) Sigstore.verifySigstoreBundleCore   ok + code exact, core JSON-equal (the detail text
 *                                                                       is informative: the reference's carries Node/OpenSSL wording)
 *   verifySigstoreBundle(b, {$root})     Sigstore.verifySigstoreBundle ok + code exact, facts JSON-equal
 *   verifyRfc3161(token, data, {$root})  Sigstore.verifyRfc3161(.., roots.tsas)  exact genTime ms; {$throws} -> must throw
 *   dssePae(type, payload)               Sigstore.dssePae              exact bytes
 * {$root: id} names the root of the `parseTrustedRoot/<id>` case (parsed here from the same JSON).
 */
class K05SigstoreDiffTest {
    companion object {
        const val FILE = "k05-sigstore.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn, false).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun throws(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        fun report(bad: List<String>, n: Int) = assertTrue("${bad.size}/$n divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())

        /** id -> parsed roots (null = this SDK refused the root). */
        val roots: Map<String, Sigstore.PinnedRoots?> by lazy {
            val r = HashMap<String, Sigstore.PinnedRoots?>()
            for (c in of("parseTrustedRoot")) r[(c["name"] as String).removePrefix("parseTrustedRoot/")] = try { Sigstore.parseTrustedRoot(args(c)[0]) } catch (e: Exception) { null }
            r
        }
        fun rootOf(ref: Any?): Sigstore.PinnedRoots? = roots[IntentJs.get(ref, "\$root") as String]
        fun std(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
        fun summary(r: Sigstore.PinnedRoots): Map<String, Any?> {
            fun end(e: Long): Any? = if (e == Long.MAX_VALUE) null else e
            fun lg(l: Sigstore.PinnedLog) = mapOf("keyId" to std(l.keyId), "start" to l.start, "end" to end(l.end), "v2" to l.v2Name)
            fun ca(c: Sigstore.PinnedCa) = mapOf("chain" to c.chain.size.toLong(), "start" to c.start, "end" to end(c.end))
            return mapOf("tlogs" to r.tlogs.map(::lg), "ctlogs" to r.ctlogs.map(::lg), "cas" to r.cas.map(::ca), "tsas" to r.tsas.map(::ca))
        }
    }

    @Test fun parseTrustedRoot() {
        val bad = ArrayList<String>()
        val cs = of("parseTrustedRoot")
        for (c in cs) {
            val want = c["out"]
            val got: Any? = try { summary(Sigstore.parseTrustedRoot(args(c)[0])) } catch (e: Exception) { mapOf("\$throws" to e.toString()) }
            val same = if (throws(want)) throws(got) else !throws(got) && IntentJs.jsonEquals(want, got)
            if (!same) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad, cs.size)
    }

    private fun core(fn: String): List<String> {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val a = args(c)
            val o = c["out"] as Map<*, *>
            val r = try { Sigstore.verifySigstoreBundleCore(a[0], rootOf(a[1])) } catch (t: Throwable) { bad.add("${c["name"]}: THROWS $t"); continue }
            val same = r.ok == (o["ok"] == true) && (if (r.ok) IntentJs.jsonEquals(o["core"], r.core) else r.code == o["code"])
            if (!same) bad.add("${c["name"]}\n  want: ${o["ok"]}|${o["code"]}|${o["detail"]}\n  got:  ${r.ok}|${r.code}|${r.detail}")
        }
        return bad
    }

    @Test fun verifySigstoreBundleCore() = report(core("verifySigstoreBundleCore"), of("verifySigstoreBundleCore").size)

    @Test fun verifySigstoreBundle() {
        val bad = ArrayList<String>()
        val cs = of("verifySigstoreBundle")
        for (c in cs) {
            val a = args(c)
            val o = c["out"] as Map<*, *>
            val r = try { Sigstore.verifySigstoreBundle(a[0], rootOf(a[1])) } catch (t: Throwable) { bad.add("${c["name"]}: THROWS $t"); continue }
            val same = r.ok == (o["ok"] == true) && (if (r.ok) IntentJs.jsonEquals(o["facts"], r.facts) else r.code == o["code"])
            if (!same) bad.add("${c["name"]}\n  want: $o\n  got:  ${r.ok}|${r.code}|${r.detail}|${r.facts}")
        }
        report(bad, cs.size)
    }

    private fun rfc3161(fn: String): List<String> {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val a = args(c)
            val want = c["out"]
            val got: Any? = try {
                val tsas = rootOf(a[2])?.tsas ?: throw IllegalArgumentException("root refused")
                Sigstore.verifyRfc3161(Base64.getDecoder().decode(a[0] as String), Base64.getDecoder().decode(a[1] as String), tsas)
            } catch (e: Exception) { mapOf("\$throws" to e.toString()) }
            val same = if (throws(want)) throws(got) else got is Long && IntentJs.jsonEquals(want, got)
            if (!same) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        return bad
    }

    @Test fun verifyRfc3161() = report(rfc3161("verifyRfc3161"), of("verifyRfc3161").size)

    @Test fun dssePae() {
        val bad = ArrayList<String>()
        val cs = of("dssePae")
        for (c in cs) {
            val a = args(c)
            val want = IntentJs.get(c["out"], "\$bytes")
            val got = try { Base64.getUrlEncoder().withoutPadding().encodeToString(Sigstore.dssePae(a[0] as String, Base64.getDecoder().decode(a[1] as String))) } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad, cs.size)
    }
}
