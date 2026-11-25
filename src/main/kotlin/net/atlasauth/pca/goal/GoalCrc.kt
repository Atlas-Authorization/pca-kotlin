package net.atlasauth.pca.goal

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.intent.IntentStats

/**
 * Conformal risk control: the choice rule and its finite-sample guarantee. Integer arithmetic matches the proved statement
 * ((sum of losses + 1) * b <= a * (n + 1), alpha = a / b, B = 1). Losses are rows of 0/1 values, nonincreasing in the level.
 */
object GoalCrc {
    /** {a, b} with b = 100000. */
    @JvmStatic
    fun alphaOf(x: Double): Map<String, Any?> {
        val b = 100_000L
        return G.map("a" to G.num(Math.round(x * b)), "b" to G.num(b))
    }

    /** Throws unless every loss is 0 or 1 and nonincreasing in the threshold level. */
    @JvmStatic
    fun assertMonotone(losses: List<Any?>) {
        for (i in losses.indices) {
            val row = G.arr(losses[i], "row")
            for (v in row) {
                val d = G.strictNum(v)
                if (d == null || (d != 0.0 && d != 1.0)) throw IrError("loss must be 0 or 1 (case $i)")
            }
            for (l in 1 until row.size) {
                if (G.strictNum(row[l])!! > G.strictNum(row[l - 1])!!) throw IrError("loss is not nonincreasing in the threshold (case $i, level $l)")
            }
        }
    }

    /** Smallest threshold whose corrected empirical risk is <= alpha; if none is feasible the top level is used. {level, n, feasible, correctedRisk, minN}. */
    @JvmStatic
    @JvmOverloads
    fun calibrate(losses: List<Any?>, alpha: Map<String, Any?>, gate: ((Long, Long) -> Boolean)? = null): Map<String, Any?> {
        assertMonotone(losses)
        val n = losses.size
        val kLevels = if (n == 0) 0 else G.arr(losses[0], "row").size
        if (kLevels == 0) throw IrError("calibrate: no levels")
        val a = G.toNum(alpha["a"])
        val b = G.toNum(alpha["b"])
        val minN = Math.ceil(b / a) - 1
        for (l in 0 until kLevels) {
            var k = 0L
            for (r in losses) k += G.strictNum(G.arr(r, "row")[l])!!.toLong()
            if ((k + 1) * b <= a * (n + 1) && (gate == null || gate(k, n.toLong()))) {
                return G.map("level" to G.num(l), "n" to G.num(n), "feasible" to true, "correctedRisk" to (k + 1).toDouble() / (n + 1), "minN" to num(minN))
            }
        }
        return G.map("level" to G.num(kLevels - 1), "n" to G.num(n), "feasible" to false, "correctedRisk" to 1.0 / (n + 1), "minN" to num(minN))
    }

    private fun num(d: Double): Any = if (d == Math.rint(d) && Math.abs(d) <= G.MAX_SAFE) G.num(d.toLong()) else d

    @JvmStatic
    fun cpUpper95(k: Long, n: Long): Double = if (n == 0L) 1.0 else IntentStats.clopperPearsonUpper(k.toDouble(), n.toDouble(), 0.05)

    /** JavaScript Number.prototype.toFixed for finite numbers (exact decimal expansion, ties away from zero). */
    internal fun toFixed(x: Double, digits: Int): String {
        if (x.isNaN()) return "NaN"
        if (x.isInfinite()) return if (x > 0) "Infinity" else "-Infinity"
        val s = BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString()
        return if (x < 0 && BigDecimal(s).signum() != 0) "-$s" else s
    }

    @JvmField
    val ASSUMPTIONS: List<String> = listOf(
        "Exchangeability: calibration and deployment goals are exchangeable within the domain. Distribution shift, a new ontology version, a new model or a new prompt breaks it: recalibrate and re-run the gate.",
        "Label quality: probe labels are the intended policy of the benchmark author; inter-annotator agreement is reported where human labels exist and is not claimed for synthetic goals.",
        "Probe coverage: the guarantee is about the published probe set (boundary examples of the intended policy, extreme amounts, other resources, other verbs), not about every possible action.",
        "Non-adaptive deployment: an adaptive attacker is handled by the hostile corpus and its widening-rate gate, not by this bound.",
        "Independence is not assumed for safety (the meet is within every reading); it affects only how often disagreement is detected.",
        "Recorded outputs: offline runs replay recorded model outputs. Rates measured on fixture recordings describe the pipeline, not any live model; live rates come from the scheduled evaluation.",
    )

    private fun d(o: Any?): Double = G.toNum(o)

    /** The Markdown report; [rs] are domain reports, [source] is "fixture" or "live". */
    @JvmStatic
    fun renderReportMarkdown(rs: List<Any?>, source: String, modelSet: String): String {
        val lines = ArrayList<String>()
        lines.add("# Intent fidelity report (" + (if (source == "live") "live models" else "recorded fixtures") + ")")
        lines.add("")
        lines.add("Model set: $modelSet")
        lines.add("")
        lines.add("| Domain | alpha | n (test) | widening k | rate | 95% upper (Clopper-Pearson) | escalation | false restriction | mean questions | gate |")
        lines.add("|---|---|---|---|---|---|---|---|---|---|")
        for (ro in rs) {
            val r = G.m(ro)!!
            val t = G.m(r["test"])!!
            val w = G.m(t["widening"])!!
            lines.add(
                "| " + G.jsStr(r["domain"]) + " | " + G.jsStr(r["alpha"]) + " | " + G.jsStr(t["n"]) + " | " + G.jsStr(w["k"]) + " | " + toFixed(d(w["rate"]), 4) +
                    " | " + toFixed(d(w["cpUpper95"]), 4) + " | " + toFixed(d(t["escalationRate"]), 3) + " | " + toFixed(d(t["falseRestrictionRate"]), 3) +
                    " | " + toFixed(d(t["meanQuestions"]), 2) + " | " + (if (G.truthy(r["gatePassed"])) "pass" else "FAIL") + " |",
            )
        }
        lines.add("")
        lines.add("## Calibrated threshold per domain")
        lines.add("")
        for (ro in rs) {
            val r = G.m(ro)!!
            val c = G.m(r["calibration"])!!
            lines.add(
                "- " + G.jsStr(r["domain"]) + ": level \"" + G.jsStr(c["levelName"]) + "\" (feasible: " + G.jsStr(c["feasible"]) + "; calibration n = " + G.jsStr(c["n"]) +
                    "; corrected risk " + toFixed(d(c["correctedRisk"]), 4) + "; minimum n for alpha: " + G.jsStr(c["minN"]) + ")",
            )
        }
        lines.add("")
        lines.add("## Per level (all cases)")
        lines.add("")
        for (ro in rs) {
            val r = G.m(ro)!!
            lines.add("### " + G.jsStr(r["domain"]))
            lines.add("")
            lines.add("| Level | widening k/n | 95% upper | escalation rate |")
            lines.add("|---|---|---|---|")
            for (po in G.arr(r["perLevel"], "perLevel")) {
                val p = G.m(po)!!
                val w = G.m(p["widening"])!!
                lines.add("| " + G.jsStr(p["level"]) + " | " + G.jsStr(w["k"]) + "/" + G.jsStr(w["n"]) + " | " + toFixed(d(w["cpUpper95"]), 4) + " | " + toFixed(d(p["escalationRate"]), 3) + " |")
            }
            lines.add("")
        }
        lines.add("## Compile-widening (IR to policy)")
        lines.add("")
        lines.add("Must be exactly zero; any nonzero value blocks the release.")
        lines.add("")
        for (ro in rs) {
            val r = G.m(ro)!!
            val cw = G.m(r["compileWidening"])!!
            lines.add("- " + G.jsStr(r["domain"]) + ": " + G.jsStr(cw["k"]) + " of " + G.jsStr(cw["n"]))
        }
        lines.add("")
        lines.add("## Guarantee and assumptions")
        lines.add("")
        lines.add("Under the assumptions below, E[loss] <= alpha (finite-sample corrected, proved in Crc.lean), where loss = 1 when the auto-accepted policy permits a probe the principal rejects.")
        lines.add("")
        for (a in ASSUMPTIONS) lines.add("- $a")
        return lines.joinToString("\n") + "\n"
    }
}
