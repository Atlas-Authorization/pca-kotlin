package net.atlasauth.pca.policyci

import java.io.File
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference oracle for the policy-safety CI gate (input normalization, lint rules, summaries, authoring commands, the CLI). */
class PolicyCiDiffTest {
    private val module = "ref-policy-ci"

    @Suppress("UNCHECKED_CAST") private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun opts(a: List<Any?>, i: Int): Map<String, Any?>? = if (a.size > i) m(a[i]) else null

    @Test fun normalizePolicyInput() = OracleCases.each(module, "normalizePolicyInput") { a -> Normalize.normalizePolicyInput(a[0]) }
    @Test fun normalizeChain() = OracleCases.each(module, "normalizeChain") { a -> Normalize.normalizeChain(a[0] as List<*>) }
    @Test fun isCapability() = OracleCases.each(module, "isCapability") { a -> Normalize.isCapability(a[0]) }
    @Test fun isEnvelope() = OracleCases.each(module, "isEnvelope") { a -> Normalize.isEnvelope(a[0]) }

    @Test fun lintPolicy() = OracleCases.each(module, "lintPolicy") { a -> PolicyCi.lintPolicy(a[0], opts(a, 1)) }
    @Test fun lintChain() = OracleCases.each(module, "lintChain") { a -> PolicyCi.lintChain(a[0] as List<*>, opts(a, 1)) }
    @Test fun lint() = OracleCases.each(module, "lint") { a -> PolicyCi.lint(a[0], opts(a, 1)) }

    @Test fun lintPolicies() = OracleCases.each(module, "lintPolicies") { a -> PolicyCi.lintPolicies(l(a[0]).map { m(it) }, opts(a, 1)) }

    @Test fun summarize() = OracleCases.each(module, "summarize") { a -> PolicyCi.summarize(l(a[0]), opts(a, 1)) }

    @Test fun checkLintRulesPin() = OracleCases.each(module, "checkLintRulesPin") { a ->
        if (a.size > 1) PolicyCi.checkLintRulesPin(a[0] as String, a[1] as String) else PolicyCi.checkLintRulesPin(a[0] as String)
    }

    @Test fun toAnalyzerPolicy() = OracleCases.each(module, "toAnalyzerPolicy") { a -> Authoring.toAnalyzerPolicy(a[0]) }

    @Test fun diffCommand() = OracleCases.each(module, "diffCommand") { a -> Authoring.diffCommand(a[0], a[1], if (a.size > 2) m(a[2]) else LinkedHashMap()) }

    /** Only the input refusals are recorded: they never reach the analyzer's test runner or coverage engine. */
    @Test fun testCommand() = OracleCases.each(module, "testCommand") { a -> Authoring.testCommand(a[0], a[1], LinkedHashMap(), null) }

    @Test fun coverageCommand() = OracleCases.each(module, "coverageCommand") { a -> Authoring.coverageCommand(a[0], a[1], LinkedHashMap(), null) }

    private fun strings(o: Any?): List<String> = l(o).map { it as String }

    @Test fun parseArgs() = OracleCases.each(module, "parseArgs") { a -> Cli.parseArgs(strings(a[0])) }

    @Test fun run() = OracleCases.each(module, "run") { a ->
        val input = m(a[0])
        val files = m(input["files"])
        val dir = File.createTempFile("pcaci", "").also { it.delete(); it.mkdirs() }
        val prefix = dir.path + "/"
        try {
            for ((k, v) in files) File(dir, k).writeBytes((v as String).toByteArray(Charsets.UTF_8))
            val argv = strings(input["argv"]).map { if (files.containsKey(it)) prefix + it else it }
            val lines = ArrayList<Any?>()
            // an annotation prints its file name as a workflow-command property (% : , escaped), so the temp directory shows in that form too
            val escaped = prefix.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
            val code = Cli.run(argv, { s -> lines.add(s.replace(prefix, "").replace(escaped, "")) })
            linkedMapOf<String, Any?>("code" to code, "lines" to lines)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun digestOfTheRuleList() {
        assertEquals(24, ActionLintRules.LINT_RULES.size)
        assertEquals(43, ActionLintRules.lintRulesDigest().length)
        assertTrue(PolicyCi.checkLintRulesPin(" " + ActionLintRules.lintRulesDigest() + "\n")["ok"] == true)
    }
}
