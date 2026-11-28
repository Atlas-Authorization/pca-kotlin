package net.atlasauth.pca.revoke

import java.io.File
import java.nio.file.Files
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference vectors of the realtime-revocation and kill-switch package. */
@Suppress("UNCHECKED_CAST")
class RevokeDiffTest {
    private val m = "ref-revoke"

    /** A store whose get (or all) throws, as the reference's failing stores do. */
    private class Failing(private val failGet: Boolean) : RevocationStore {
        val base = InMemoryRevocationStore()
        override fun add(entry: RevocationEntry) = base.add(entry)
        override fun remove(kind: String, value: String) = base.remove(kind, value)
        override fun get(kind: String, value: String): RevocationEntry? = if (failGet) throw IllegalStateException("boom") else base.get(kind, value)
        override fun all(): List<RevocationEntry> = if (!failGet) throw IllegalStateException("boom") else base.all()
        override fun clear() = base.clear()
    }

    private fun map(o: Any?): Map<String, Any?>? = when (o) {
        null -> null
        is Map<*, *> -> o as Map<String, Any?>
        else -> throw JsTypeError("not an object")
    }

    private fun entries(es: List<RevocationEntry>) = es.map { it.toMap() }

    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private val REGEN_NOW = BaseOracle.clockMs("$m.json.gz")

    /** An entry whose revokedAt is within two minutes of the wall clock (live, or the regeneration's) prints as "<now>" (the reference does the same). */
    private fun norm(v: Any?): Any? = when (v) {
        is List<*> -> v.map { norm(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o ->
            for ((k, x) in v) {
                val d = Js.num(x)
                o[k as String] = if (k == "revokedAt" && d != null && (Math.abs(d - System.currentTimeMillis()) < 120_000 || Math.abs(d - REGEN_NOW) < 120_000)) "<now>" else norm(x)
            }
        }
        else -> v
    }

    private fun scenario(spec: Map<String, Any?>): List<Any?> {
        val store: RevocationStore = when (spec["store"]) {
            "failGet" -> Failing(true)
            "failAll" -> Failing(false)
            else -> InMemoryRevocationStore()
        }
        val reg = RevocationRegistry(store)
        return (spec["ops"] as List<Map<String, Any?>>).map { s ->
            try {
                norm(
                    when (s["op"]) {
                        "revoke" -> reg.revoke(map(s["input"])).toMap()
                        "revokeSubtree" -> reg.revokeSubtree(s["target"], map(s["opts"])).toMap()
                        "unrevoke" -> reg.unrevoke(map(s["key"]))
                        "list" -> entries(reg.list())
                        "lookup" -> reg.lookup(s["kind"] as String, s["value"] as String)?.toMap()
                        "prefixes" -> entries(reg.prefixes())
                        "clear" -> { reg.clear(); null }
                        "killAgent" -> reg.killAgent(s["holder"], map(s["opts"])).toMap()
                        "killSubtree" -> reg.killSubtree(s["root"], map(s["opts"])).toMap()
                        "check" -> Revoke.checkRevocation(s["p"], reg, map(s["opts"])).toMap()
                        "verify" -> Revoke.verifyWithRevocation(s["p"], s["core"], reg, map(s["opts"])).toMap()
                        "ingest" -> entries(Revoke.ingestCaepEvent(s["event"], reg))
                        else -> throw IllegalArgumentException("bad op")
                    },
                )
            } catch (e: RuntimeException) {
                linkedMapOf<String, Any?>("\$err" to true)
            }
        }
    }

    /** The reference stores a revocation with no kind (an entry no lookup can match); this SDK refuses a kind that is not a string, so that case must be refused. */
    private val kindless = "scenario/revoke/34#34"

    @Test fun scenarios() {
        val cases = OracleCases.of(m, "scenario")
        val refused = cases.first { it["name"] == kindless }
        assertEquals(listOf<Any?>(linkedMapOf<String, Any?>("\$err" to true), emptyList<Any?>()), scenario((refused["args"] as List<Any?>)[0] as Map<String, Any?>))
        val bad = cases.filter { it["name"] != kindless }.mapNotNull { c -> OracleCases.diff(c, c["out"]) { a -> scenario(a[0] as Map<String, Any?>) } }
        assertTrue("${bad.size} divergent case(s) of scenario:\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun isActiveAt() = OracleCases.each(m, "isActiveAt") { a ->
        val e = map(a[0])!!
        val nb = if (e.containsKey("notBefore")) Js.num(e["notBefore"]) ?: Double.NaN else null
        Revoke.isActiveAt(RevocationEntry("cap", "v", null, "", 1.0, nb), Js.num(a[1]) ?: Double.NaN)
    }

    @Test fun caepEventTypes() = OracleCases.each(m, "caepEventTypes") {
        linkedMapOf("sessionRevoked" to Revoke.SESSION_REVOKED, "grantRevoked" to Revoke.GRANT_REVOKED, "killSwitch" to Revoke.KILL_SWITCH)
    }

    @Test fun inMemoryStoreConformance() = RevocationStoreConformance.cases({ InMemoryRevocationStore() }).forEach { it.run() }

    @Test fun fileStoreConformanceAndDurability() {
        val dir = Files.createTempDirectory("rev").toFile()
        var n = 0
        lateinit var last: File
        RevocationStoreConformance.cases(
            { last = File(dir, "rev${n++}.json"); FileRevocationStore(last) },
            { FileRevocationStore(last) },
        ).forEach { it.run() }
        dir.deleteRecursively()
    }

    @Test fun fileStoreRefusesACorruptFile() {
        val dir = Files.createTempDirectory("rev").toFile()
        val p = File(dir, "rev.json")
        for (bad in listOf(
            "not json", "{}", "{\"entries\":{}}", "{\"entries\":[{\"kind\":\"cap\"}]}",
            "{\"entries\":[{\"kind\":\"prefix\",\"value\":\"a,b\",\"prefix\":[\"a\"],\"reason\":\"\",\"revokedAt\":1}]}",
            "{\"entries\":[{\"kind\":\"cap\",\"value\":\"c\",\"reason\":\"\",\"revokedAt\":1,\"notBefore\":null}]}",
        )) {
            p.writeText(bad)
            try {
                FileRevocationStore(p)
                fail("accepted: $bad")
            } catch (expected: IllegalStateException) {
            }
        }
        p.writeText("{\"v\":1,\"entries\":[{\"kind\":\"cap\",\"value\":\"c\",\"reason\":\"r\",\"revokedAt\":1,\"notBefore\":2}]}")
        val ok = FileRevocationStore(p)
        assertEquals(1, ok.all().size)
        assertTrue(ok.get("cap", "c")!!.notBefore == 2.0)
        dir.deleteRecursively()
    }
}
