package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * Kill tests for the IntentSession.kt survivors of the 0.4.2 Kotlin mutation run: the `intent_session` wire, the grant
 * caveat and its lookup, the session root shape and its signature. DIFFERENTIAL against the TS reference
 * (intent-session.ts, intent-session-caveat.ts): the golden test-data/killSession.json is written by
 * tools/pca-audit/kotlin-mutate/killSession-oracle-gen.mjs, and every case asserts the reference's EXACT reason (null =
 * accepted). Where the two refuse with different text (`kt_verify`, see the generator), the Kotlin text is pinned.
 */
class KillSessionTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val data: Map<String, Any?> by lazy {
            Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killSession.json")), Charsets.UTF_8)) as Map<String, Any?>
        }

        @Suppress("UNCHECKED_CAST")
        fun cases(sec: String): List<Map<String, Any?>> = data[sec] as List<Map<String, Any?>>
    }

    /** [want] = the reference's reason member; a `kt_<want>` member (when present) pins Kotlin's text instead. */
    private fun check(sec: String, want: String, got: (Any?) -> String?) {
        val bad = ArrayList<String>()
        val cs = cases(sec)
        for (c in cs) {
            val w = (if (c.containsKey("kt_$want")) c["kt_$want"] else c[want]) as String?
            val g = got(c["arg"])
            if (w != g) bad.add("${c["name"]}: want <$w> got <$g>")
        }
        assertEquals("$sec ($want) mismatches:\n" + bad.joinToString("\n"), 0, bad.size)
    }

    @Test fun wire() = check("wire", "ts") { IntentSession.validateWire(it) }

    @Test fun caveat() = check("caveat", "ts") { IntentSession.caveatError(it) }

    // The session root is verifier-held state: the pipeline normalizes it on entry (IntentV2.Context.fromJson).
    @Test fun rootShape() = check("root", "shape") { IntentSession.rootShapeError(IntentJs.normalize(it)) }

    // R3-01: a PQ root verifies only under the verifier's pins (`pins`, when the case passes any), never its own principals.
    @Test fun rootVerify() {
        val bad = ArrayList<String>()
        for (c in cases("root")) {
            val w = (if (c.containsKey("kt_verify")) c["kt_verify"] else c["verify"]) as String?
            val g = IntentSession.verifyRoot(IntentJs.normalize(c["arg"]), if (c.containsKey("pins")) IntentJs.normalize(c["pins"]) else null)
            if (w != g) bad.add("${c["name"]}: want <$w> got <$g>")
        }
        assertEquals("root (verify) mismatches:\n" + bad.joinToString("\n"), 0, bad.size)
    }

    @Test fun grantCaveat() {
        for (c in cases("grant")) {
            val idx = c["want_index"]
            val got = IntentSession.grantSessionCaveat(c["arg"])
            if (idx == null) assertNull(c["name"] as String, got)
            else {
                val list = (c["arg"] as Map<*, *>)["caveats"] as List<*>
                assertSame(c["name"] as String, list[IntentJs.num(idx)!!.toInt()], got)
            }
        }
    }

    @Test fun fieldsAndGoals() {
        assertEquals(listOf("session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form"), IntentSession.INTENT_SESSION_FIELDS)
        assertEquals("pca-intent:v2:S:M", IntentSession.intentGoalV2("S", "M"))
        assertEquals("pca-intent:v2c:S:M", IntentSession.intentGoalV2c("S", "M"))
    }
}
