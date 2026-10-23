package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** r9 mutation kills for IntentV2.run: both handlers (RuntimeException and StackOverflowError) fail the check closed, naming the exception class. */
class K042R9FailClosedTest {
    private fun run(name: String, clockOk: Boolean, f: () -> String?): List<String> {
        val m = IntentV2::class.java.declaredMethods.first { it.name == "run" && it.parameterCount == 4 }
        m.isAccessible = true
        val out = IntentV2.Decision()
        m.invoke(IntentV2, out, name, clockOk, f)
        return out.checks.map { "${it.name}|${it.ok}|${it.reason}" }
    }

    @Test
    fun aStepThatOverflowsTheStackFailsClosedWithTheErrorClass() {
        assertEquals(listOf("intent_session|false|intent_session error (fail closed): StackOverflowError"), run("intent_session", true) { throw StackOverflowError() })
    }

    @Test
    fun aStepThatThrowsFailsClosedWithTheExceptionClass() {
        assertEquals(listOf("schema|false|schema error (fail closed): IllegalStateException"), run("schema", true) { throw IllegalStateException("x") })
        assertEquals(listOf("schema|true|null"), run("schema", true) { null })
        assertEquals(listOf("schema|false|why"), run("schema", true) { "why" })
        assertEquals(listOf("schema|false|the verifier clock is not a safe integer (fail closed)"), run("schema", false) { null })
    }
}
