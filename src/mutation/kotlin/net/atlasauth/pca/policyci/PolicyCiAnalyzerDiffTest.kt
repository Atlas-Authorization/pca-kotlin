package net.atlasauth.pca.policyci

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** The policy-ci parts that run on the analyzer: the schema rule, the test command and the coverage command. */
class PolicyCiAnalyzerDiffTest {
    private val module = "ref-policy-ci-java-extra"

    @Suppress("UNCHECKED_CAST") private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Test fun lintPolicy() = OracleCases.each(module, "lintPolicy") { a -> PolicyCi.lintPolicy(a[0], if (a.size > 1) m(a[1]) else null) }

    @Test fun testCommand() = OracleCases.each(module, "testCommand") { a ->
        Authoring.testCommand(a[0], a[1], if (a.size > 2) m(a[2]) else LinkedHashMap(), Authoring.ANALYZER_BACKEND)
    }

    @Test fun coverageCommand() = OracleCases.each(module, "coverageCommand") { a ->
        Authoring.coverageCommand(a[0], a[1], if (a.size > 2) m(a[2]) else LinkedHashMap(), Authoring.ANALYZER_BACKEND)
    }
}
