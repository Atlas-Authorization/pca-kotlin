package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `prohibition-vectors.json` (clause validation and decision, certificate recomputation, constitution + veto-polarity monitor, stateful
 * monitor sequences, signed safety evidence) and `forbid-certificate-vectors.json` (every decide row with the evaluators, every table row
 * with the consistency rule). A missing file FAILS.
 */
@Suppress("UNCHECKED_CAST")
class ForbidAndProhibitionVectorsTest {
    private val prohibition = ParityVectors.load("prohibition-vectors.json")
    private val forbid = ParityVectors.load("forbid-certificate-vectors.json")

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun strs(o: Any?): List<String>? = (o as List<Any?>?)?.map { it as String }
    private fun action(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    @Test fun everyClausesRow() {
        val rows = l(prohibition["clauses"])
        assertTrue("clauses rows: ${rows.size}", rows.size >= 20)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val exp = m(r["expect"])
            assertEquals("$name: error", exp["error"], ForbidWins.clausesError(r["clauses"]))
            val d = ForbidWins.decide(r["clauses"], action(r["action"]), null, null)
            assertEquals("$name: decision", exp["decision"], d.decision)
            assertEquals("$name: winner kind", m(exp["winner"])["kind"], d.winnerKind)
            assertEquals("$name: winner id", m(exp["winner"])["id"], d.winnerId)
            assertEquals("$name: shadowed", l(exp["shadowed"]), d.shadowed)
            assertEquals("$name: values", Json.canonicalize(exp["values"]), Json.canonicalize(d.values))
        }
    }

    @Test fun everyCheckRow() {
        val rows = l(prohibition["check"])
        assertTrue("check rows: ${rows.size}", rows.size >= 11)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val opts = (r["options"] as? Map<String, Any?>) ?: emptyMap()
            val why = ForbidWins.check(r["certificate"], r["clauses"], action(r["action"]), strs(opts["precedence"]), strs(opts["permitSigners"]))
            val exp = m(r["expect"])
            assertEquals("$name: ok ($why)", exp["ok"], why == null)
            if (exp["ok"] != true) assertEquals("$name: reason", exp["reason"], why)
        }
    }

    @Test fun everyConstitutionRow() {
        val rows = l(prohibition["constitution"])
        assertTrue("constitution rows: ${rows.size}", rows.size >= 33)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val exp = m(r["expect"])
            assertEquals("$name: problems", l(exp["problems"]), Prohibitions.validateConstitution(r["constitution"]))
            val got = Prohibitions.checkProhibitions(r["action"], r["constitution"], r["state"])
            assertEquals("$name: result", Json.canonicalize(exp["result"]), Json.canonicalize(got))
        }
    }

    @Test fun everyMonitorSequence() {
        val rows = l(prohibition["monitor"])
        assertTrue("monitor rows: ${rows.size}", rows.size >= 5)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val constitution = r["constitution"]
            var st: Any? = Prohibitions.emptyState(r["genesis_now"])
            var i = 0
            for (sx in l(r["steps"])) {
                val step = m(sx)
                val exp = m(step["expect"])
                val label = "$name step ${i++}"
                if (step.containsKey("now")) {
                    val tick = Prohibitions.tickState(st, step["now"])
                    if (tick["ok"] != true) {
                        assertEquals(label, false, exp["allow"])
                        assertEquals(label, "clock", exp["decidedBy"])
                        assertEquals(label, exp["reason"], tick["reason"])
                        continue
                    }
                    st = tick["state"]
                }
                val res = Prohibitions.checkAndAdvance(true, step["action"], constitution, st, null, null)
                assertEquals("$label: allow", exp["allow"], res["allow"])
                assertEquals("$label: decidedBy", exp["decidedBy"], res["decidedBy"])
                assertEquals("$label: violated", l(exp["violated"]), l(m(res["prohibition"])["violated"]))
                if (res["allow"] == true) st = res["next"]
                if (exp.containsKey("seq")) assertEquals("$label: seq", Prohibitions.dv(exp["seq"]), Prohibitions.dv(m(st)["seq"]), 0.0)
            }
        }
    }

    @Test fun everyEvidenceRow() {
        val rows = l(prohibition["evidence"])
        assertTrue("evidence rows: ${rows.size}", rows.size >= 13)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val exp = m(r["expect"])
            val why = Prohibitions.verifySignedSafetyEvidence(r["signed"], r["expected"])
            assertEquals("$name: ok ($why)", exp["ok"], why == null)
            if (exp["ok"] != true) assertEquals("$name: reason", exp["reason"], why)
        }
    }

    @Test fun everyDecideRowWithTheEvaluators() {
        val rows = l(forbid["decide"])
        assertTrue("decide rows: ${rows.size}", rows.size >= 11)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val opts = (r["options"] as? Map<String, Any?>) ?: emptyMap()
            val prec = strs(opts["precedence"])
            val ps = strs(opts["permitSigners"])
            val d = ForbidWins.decide(r["clauses"], m(r["action"]), prec, ps)
            val exp = m(r["expect"])
            assertEquals("$name: decision", exp["decision"], d.decision)
            assertEquals("$name: winner kind", m(exp["winner"])["kind"], d.winnerKind)
            assertEquals("$name: winner id", m(exp["winner"])["id"], d.winnerId)
            assertEquals("$name: shadowed", l(exp["shadowed"]), d.shadowed)
            assertEquals("$name: values", Json.canonicalize(exp["values"]), Json.canonicalize(d.values))
            val cert = ForbidWins.certify(r["clauses"], m(r["action"]), prec, ps)
            assertEquals("$name: certificate digest", exp["certificate_digest"], Pca.hashCanonical(cert))
            assertNull("$name: a recomputed certificate is accepted", ForbidWins.check(cert, r["clauses"], m(r["action"]), prec, ps))
        }
    }

    @Test fun everyTableRow() {
        val rows = l(forbid["table"])
        assertTrue("table rows: ${rows.size}", rows.size >= 19)
        for (x in rows) {
            val r = m(x)
            val opts = (r["options"] as? Map<String, Any?>) ?: emptyMap()
            assertEquals(r["name"] as String, m(r["expect"])["consistent"], ForbidWins.consistent(r["certificate"], strs(opts["precedence"])))
        }
    }

    @Test fun aTamperedCertificateOrMalformedClausesAreRefused() {
        val r = m(l(forbid["decide"])[0])
        val act = m(r["action"])
        val cert = ForbidWins.certify(r["clauses"], act, null, null)
        val inner = LinkedHashMap(m(act["action"]))
        inner["resource"] = "/acct/2"
        val other = LinkedHashMap(act)
        other["action"] = inner
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(cert, r["clauses"], other, null, null))
        assertEquals("malformed clauses", ForbidWins.check(cert, "x", act, null, null))
        assertEquals("malformed", ForbidWins.decide(listOf("x"), act, null, null).winnerKind)
        assertEquals("malformed", ForbidWins.decide(r["clauses"], LinkedHashMap(), null, null).winnerKind)
        assertEquals("clauses must be an array", ForbidWins.clausesError(null))
    }
}
