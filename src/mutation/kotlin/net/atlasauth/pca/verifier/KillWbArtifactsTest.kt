package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Differential kills for IntentArtifacts.kt: the `art` cases of test-data/killWb.json were computed by the TS reference
 * (packages/pca/src/intent-artifacts.ts; generator tools/pca-audit/kotlin-mutate/killWb-oracle-gen.mjs). `iterable` and
 * `actionParams` have no TS counterpart (TS reads the members inline and throws a TypeError on the malformed ones):
 * they are pinned by hand below.
 */
class KillWbArtifactsTest {
    private fun canon(v: Any?): String = Json.canonicalize(v)
    private fun mutableCopy(v: Any?): Any? = Json.parseLenient(Json.canonicalize(v))

    @Suppress("UNCHECKED_CAST")
    @Test fun helpers() {
        val arts = KillWbTest.of("art")
        assertTrue(arts.size > 130)
        for (c in arts) {
            val name = c["name"] as String
            val a = c["args"] as List<Any?>
            val e = c["expect"]
            when (c["fn"]) {
                "isPathSegment" -> assertEquals(name, e, IntentArtifacts.isPathSegment(a[0] as String))
                "isName" -> assertEquals(name, e, IntentArtifacts.isName(a[0]))
                "isBoundedString" -> assertEquals(name, e, IntentArtifacts.isBoundedString(a[0], IntentJs.lng(a[1]).toInt()))
                "scalarEq" -> assertEquals(name, e, IntentArtifacts.scalarEq(a[0], a[1]))
                "closedMembers" -> assertEquals(name, e, IntentArtifacts.closedMembers(a[0] as Map<String, Any?>, a[1] as List<String>, a[2] as List<String>, a[3] as String))
                "pinPqOk" -> assertEquals(name, e, IntentArtifacts.pinPqOk(a[0]))
                "artifactSuiteError" -> assertEquals(name, e, IntentArtifacts.artifactSuiteError(a[0] as Map<String, Any?>))
                "verifyArtifactSig" -> assertEquals(name, e, IntentArtifacts.verifyArtifactSig(a[0] as String, a[1] as Map<String, Any?>, a[2], a[3]))
                "resolveParamPath" -> {
                    val r = IntentArtifacts.resolveParamPath(a[0], a[1])
                    val m = e as Map<String, Any?>
                    assertEquals("$name found", m["found"], r.found)
                    assertEquals("$name value", canon(m["value"]), canon(r.value))
                }
                "isParamPath" -> assertEquals(name, e, IntentArtifacts.isParamPath(a[0]))
                "setNested" -> {
                    val root = mutableCopy(a[0]) as MutableMap<String, Any?>
                    val ok = IntentArtifacts.setNested(root, a[1] as String, a[2])
                    val m = e as Map<String, Any?>
                    assertEquals("$name ok", m["ok"], ok)
                    assertEquals("$name root", canon(m["root"]), canon(root))
                }
                else -> fail("unknown fn ${c["fn"]}")
            }
        }
    }

    @Test fun iterableAndActionParams() {
        val l = arrayListOf<Any?>(1L)
        assertSame(l, IntentArtifacts.iterable(l))
        for (bad in listOf<Any?>(null, "x", linkedMapOf<String, Any?>(), 1L)) {
            try { IntentArtifacts.iterable(bad); fail("iterable($bad)") } catch (e: IllegalArgumentException) { assertEquals("not a list", e.message) }
        }
        assertEquals(canon(linkedMapOf<String, Any?>()), canon(IntentArtifacts.actionParams(linkedMapOf<String, Any?>())))
        assertEquals(canon(linkedMapOf<String, Any?>()), canon(IntentArtifacts.actionParams(null)))
        val p = linkedMapOf<String, Any?>("a" to 1L)
        assertSame(p, IntentArtifacts.actionParams(linkedMapOf<String, Any?>("params" to p)))
        for (bad in listOf<Any?>(null, 1L, "x", arrayListOf<Any?>())) {
            try { IntentArtifacts.actionParams(linkedMapOf<String, Any?>("params" to bad)); fail("actionParams($bad)") } catch (e: IllegalArgumentException) {
                assertEquals("action.params is not an object", e.message)
            }
        }
    }
}
