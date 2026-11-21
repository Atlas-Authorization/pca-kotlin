package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for provenance by default (ArgProvenance): test-data/k05-argprov.json.gz from
 * tools/pca-audit/k05-oracles/argprov-oracle.mts. Validators compare the exact reason, the decision every field (an
 * "evaluation error (fail closed)" reason compares by that prefix: the natives name the exception class, TS its message), the
 * recorder canonical JSON of every receipt / bundle (a throw only requires a refusal), the request reader canonical JSON or a
 * refusal. Skipped: a decide input that is not an object (the typed Kotlin API has no such state).
 */
class K05ArgProvDiffTest {
    companion object {
        private const val EVAL = "evaluation error (fail closed)"

        const val FILE = "k05-argprov.json.gz"

        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }

        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.take(60).joinToString("\n"), bad.isEmpty())
        fun throws(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        fun canon(v: Any?): String = Json.canonicalize(v)

        @Suppress("UNCHECKED_CAST") fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    }

    private fun exact(fn: String, f: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val want = c["out"]
            val got = try { f(args(c)) } catch (t: Throwable) { "THROWS $t" }
            val w = if (want is Json.Num) want.raw else want
            if (w != got) bad.add("${c["name"]}\n  want: $w\n  got:  $got")
        }
        report(bad)
    }

    @Test fun receiptWire() = exact("provReceiptWireError") { ArgProvenance.receiptWireError(it[0]) }
    @Test fun mediatorPin() = exact("isProvMediatorPin") { ArgProvenance.isMediatorPin(it[0]) }
    @Test fun actionInfo() = exact("provActionInfoError") { ArgProvenance.actionInfoError(it[0]) }
    @Test fun readOnly() = exact("isReadOnlyAction") { ArgProvenance.isReadOnlyAction(it[0]) }
    @Test fun envelope() = exact("provEnvelopeError") { ArgProvenance.envelopeError(it[0]) }
    @Test fun tokens() = exact("occursAsToken") { ArgProvenance.occursAsToken(it[0] as String, it[1] as String) }
    @Test fun receiptRef() = exact("provReceiptRef") { ArgProvenance.receiptRef(mp(it[0])) }
    @Test fun actionDigest() = exact("provActionDigest") { val op = mp(it[0]); ArgProvenance.actionDigest(op["verb"] as String, op["resource"] as String, mp(op["params"])) }

    @Test fun leaves() {
        val bad = ArrayList<String>()
        for (c in of("provLeaves")) {
            val want = c["out"]?.let { canon(it) }
            val got = try { ArgProvenance.provLeaves(args(c)[0])?.let { canon(it) } } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }

    private fun renderDecision(d: ArgProvenance.Decision): String {
        val reason = d.reason?.let { if (it.startsWith(EVAL)) EVAL else it }
        return "${d.outcome}|${d.code}|$reason|${d.sensitive}|${d.verified}|${d.control}|${canon(d.labels)}|${canon(d.tainted)}|${canon(d.path)}"
    }

    private fun renderWant(o: Map<String, Any?>): String {
        val reason = (o["reason"] as String?)?.let { if (it.startsWith(EVAL)) EVAL else it }
        return "${o["outcome"]}|${o["code"]}|$reason|${o["sensitive"]}|${o["verified"]}|${o["control"]}|${canon(o["labels"])}|${canon(o["tainted"])}|${canon(o["path"])}"
    }

    @Test fun decision() {
        val bad = ArrayList<String>()
        var ran = 0
        for (c in of("decideArgProvenance")) {
            val inp = args(c)[0] as? Map<*, *> ?: continue // typed API: a non-object input has no Kotlin state
            ran++
            val want = renderWant(mp(c["out"]))
            val got = try {
                renderDecision(
                    ArgProvenance.decide(
                        inp["bundle"], inp["operation"], inp["mediators"], inp["action"],
                        inp["principalPlan"] == true, inp["principalControl"] == true, inp["observed"],
                    ),
                )
            } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        assertTrue(ran > 7000)
        report(bad)
    }

    /** One recorder session: {pin, outs} with every throw (constructor or step) replaced by the token THROWS. */
    private fun record(spec: Map<String, Any?>): String {
        val clock = ArrayDeque((spec["clock"] as List<*>).map { IntentJs.num(it)!!.toLong() })
        var last = 0L
        val rec = try {
            ArgProvenance.Recorder(
                spec["mediator"] as String, spec["kid"] as String,
                Keys.ed25519(Keys.edFromSeed(Pca.decodeB64uStrict(spec["sk"], 32)!!)), spec["session"] as String,
            ) { if (clock.isEmpty()) last else clock.removeFirst().also { last = it } }
        } catch (t: Throwable) { return "THROWS" }
        val outs = ArrayList<String>()
        for (s in spec["steps"] as List<*>) {
            val st = s as List<*>
            outs.add(
                try {
                    canon(
                        when (st[0]) {
                            "principal" -> rec.principal(st[1] as String)
                            "tool" -> rec.tool(st[1] as String, st[2])
                            "retrieval" -> rec.retrieval(st[1] as String, st[2])
                            "web" -> rec.web(st[1] as String, st[2])
                            "action" -> { val op = mp(st[1]); rec.forAction(op["verb"] as String, op["resource"] as String, mp(op["params"])) }
                            "direct" -> { val op = mp(st[1]); ArgProvenance.principalDirect(rec, op["verb"] as String, op["resource"] as String, mp(op["params"])) }
                            else -> throw IllegalStateException("unknown step ${st[0]}")
                        },
                    )
                } catch (t: RuntimeException) { "THROWS" },
            )
        }
        return "${canon(rec.pin)} ${outs.joinToString(" ")}"
    }

    @Test fun recorder() {
        val bad = ArrayList<String>()
        for (c in of("recorder")) {
            val o = mp(c["out"])
            val want = if (throws(o)) "THROWS" else "${canon(o["pin"])} ${(o["outs"] as List<*>).joinToString(" ") { if (throws(it)) "THROWS" else canon(it) }}"
            val got = try { record(mp(args(c)[0])) } catch (t: Throwable) { "ERROR $t" }
            if (want != got) bad.add("${c["name"]}\n  want: ${want.take(400)}\n  got:  ${got.take(400)}")
        }
        report(bad)
    }

    @Test fun requestReader() {
        val bad = ArrayList<String>()
        for (c in of("defaultProvenanceBundle")) {
            val a = mp(args(c)[0])
            val header = a["header"] as String?
            val body = a["body"] as String?
            val got = try {
                val b = if (header != null && header != "") ArgProvenance.bundleFromHeader(header) else ArgProvenance.bundleFromBody(body?.toByteArray(Charsets.UTF_8))
                canon(b)
            } catch (t: RuntimeException) { "THROWS" }
            val want = if (throws(c["out"])) "THROWS" else canon(c["out"])
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }
}
