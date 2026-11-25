package net.atlasauth.pca.actions

import org.junit.Assert.assertEquals
import org.junit.Test

/** The YAML 1.2 double-quoted escapes L and P (U+2028, U+2029) are accepted only where they are escapes; anywhere else the text is untouched. */
@Suppress("UNCHECKED_CAST")
class ActionsYamlEscapeTest {
    private fun description(value: String): String {
        val text = "ns: acme\nactions:\n  - verb: acme.note.read\n    effects: [read]\n    resource: acme.note\n    description: $value\n"
        val r = ActionsText.loadActionsText(text, "yaml")
        assertEquals(r.toString(), 0, (r["errors"] as List<Any?>).size)
        return (r["defs"] as List<Map<String, Any?>>)[0]["description"] as String
    }

    @Test fun aSingleQuotedScalarKeepsTwoCharacters() = assertEquals("\\L", description("'\\L'"))

    @Test fun anEscapedBackslashThenLStaysABackslashAndL() = assertEquals("\\L", description("\"\\\\L\""))

    @Test fun aCommentIsLeftAlone() = assertEquals("x", description("x # \\L \\P"))

    @Test fun aPlainScalarKeepsTwoCharacters() = assertEquals("a\\Lb", description("a\\Lb"))

    @Test fun anEscapeInADoubleQuotedScalarIsTheLineSeparator() {
        assertEquals("\u2028", description("\"\\L\""))
        assertEquals("\u2029", description("\"\\P\""))
        assertEquals("\\\u2028", description("\"\\\\\\L\""))
        assertEquals("a\u2028b\u2029c", description("\"a\\Lb\\Pc\""))
    }
}
