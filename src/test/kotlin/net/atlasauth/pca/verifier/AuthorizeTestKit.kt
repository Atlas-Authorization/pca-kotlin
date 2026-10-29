package net.atlasauth.pca.verifier

import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.util.Properties

/**
 * Shared data for the authorize tests: the TypeScript-signed fixtures (`test-data/authorize-fixtures.json`, a byte copy of
 * the Python SDK's), the `primitives.caveat_eval` conformance vectors, and a SQLite connection factory for the JDBC store.
 */
@Suppress("UNCHECKED_CAST")
object AuthorizeTestKit {
    const val FIXTURES = "test-data/authorize-fixtures.json"

    val fix: Map<String, Any?> by lazy { Json.parseLenient(File(FIXTURES).readText(Charsets.UTF_8)) as Map<String, Any?> }
    val cases: List<Map<String, Any?>> get() = fix["cases"] as List<Map<String, Any?>>
    val NOW: Long get() = Json.asLong(fix["now"])
    val AUD: String get() = fix["audience"] as String

    fun findUp(rel: String): File? {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val c = File(dir, rel)
            if (c.exists()) return c
            dir = dir.parentFile
        }
        return null
    }

    val caveatEval: List<Map<String, Any?>> by lazy {
        val f = findUp("packages/pca/conformance/vectors.json") ?: throw IllegalStateException("vectors.json not found")
        ((Json.parseLenient(f.readText(Charsets.UTF_8)) as Map<String, Any?>)["primitives"] as Map<String, Any?>)["caveat_eval"] as List<Map<String, Any?>>
    }

    fun case(name: String): Map<String, Any?> = cases.first { it["name"] == name }
    fun steps(c: Map<String, Any?>): List<Map<String, Any?>> = c["steps"] as List<Map<String, Any?>>
    fun grant(c: Map<String, Any?>): Map<String, Any?> = c["grant"] as Map<String, Any?>
    fun pcactn(c: Map<String, Any?>, step: Int = 0): Map<String, Any?> = steps(c)[step]["pcactn"] as Map<String, Any?>
    fun op(c: Map<String, Any?>, step: Int = 0): Authorize.Operation = Authorize.Operation.fromJson(steps(c)[step]["operation"])!!

    /** `{allow, status, sorted failing checks}` of a result, in the fixtures' `expect` shape. */
    fun settle(r: Authorize.Result): Map<String, Any?> =
        linkedMapOf("allow" to r.allow, "status" to r.status, "failed" to r.checks.filterValues { it == "fail" }.keys.sorted())

    fun expectOf(step: Map<String, Any?>): Map<String, Any?> {
        val e = step["expect"] as Map<String, Any?>
        return linkedMapOf("allow" to e["allow"], "status" to Json.asLong(e["status"]).toInt(), "failed" to (e["failed"] as List<*>).map { it as String })
    }

    fun tsOf(step: Map<String, Any?>): Map<String, Any?> {
        val t = step["ts"] as Map<String, Any?>
        return linkedMapOf("allow" to t["allow"], "status" to Json.asLong(t["status"]).toInt())
    }

    /** The input of step 0 of a case, with every component present; `edit` overrides fields. */
    fun input(
        c: Map<String, Any?>,
        step: Int = 0,
        operation: Authorize.Operation? = op(c, step),
        audience: String? = AUD,
        resolveGrant: ((String) -> Map<String, Any?>?)? = { grant(c) },
        stateStore: Authorize.StateStore? = Authorize.MemoryStateStore(),
        isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)? = { _, _ -> false },
        plan: String? = Authorize.SINGLE_STEP,
        context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
        intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null,
        require: List<String> = emptyList(),
        provenance: Any? = ProvHarness.bundle(operation),
    ) = Authorize.Input(
        operation = operation, audience = audience, resolveGrant = resolveGrant, stateStore = stateStore, isRevoked = isRevoked,
        now = NOW, plan = plan, context = context, intentV2 = intentV2, require = require,
        provenanceOptions = ProvHarness.options, provenance = provenance,
    )

    fun run(c: Map<String, Any?>, step: Int = 0, input: Authorize.Input = input(c, step)): Authorize.Result =
        Authorize.authorize(pcactn(c, step), input)

    /** Every step of a case against ONE store, in order (the revocation flag per step). */
    fun runCase(c: Map<String, Any?>, store: Authorize.StateStore): List<Map<String, Any?>> {
        var revoked = false
        val g = grant(c)
        return steps(c).mapIndexed { i, s ->
            revoked = s["revoked"] == true
            val r = Authorize.authorize(
                s["pcactn"],
                input(c, i, resolveGrant = { ref -> if (ref == g["id"]) g else null }, stateStore = store, isRevoked = { _, _ -> revoked }),
            )
            // a step that records a reason substring must carry it in the result's reasons
            val why = (s["expect"] as Map<String, Any?>)["reason"] as? String
            if (why != null) check(r.reasons.joinToString("\n").contains(why)) { "${c["name"]} step $i: reasons ${r.reasons} lack '$why'" }
            settle(r)
        }
    }

    // ---- SQLite (org.xerial:sqlite-jdbc, test scope) ----

    fun sqlite(path: String): Connection {
        val props = Properties()
        props.setProperty("busy_timeout", "30000")
        return DriverManager.getConnection("jdbc:sqlite:$path", props)
    }

    fun tempDb(): String {
        val f = File.createTempFile("pca-replay", ".db")
        f.delete()
        f.deleteOnExit()
        return f.absolutePath
    }

    fun jdbcStore(path: String = tempDb()): PcaJdbcStateStore = PcaJdbcStateStore({ sqlite(path) })
}
