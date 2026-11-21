package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The action schema beyond its shape checks against the reference (ref-action-schema, 173 cases; ref-action-schema-draft, 104): the vocabulary
 * constants, value-dependent reversibility, the wallet floor test, the verb lookup, signing under Ed25519, ML-DSA-65 and the hybrid suite (the
 * signature bytes compare), the key entry, the content address, verification with every refusal reason, and the v1 drafting importers.
 */
@Suppress("UNCHECKED_CAST")
class RefActionSchemaDiffTest {
    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun site(a: List<Any?>, secretAt: Int, suiteAt: Int): Keys.SuiteKey {
        val suite = arg(a, suiteAt) as Map<String, Any?>?
        val alg = if (suite != null && suite.containsKey("alg")) suite["alg"] as String else "ed25519"
        val pq = suite?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(a[secretAt])), pq)
    }

    private fun rx(r: Regex) = linkedMapOf<String, Any?>("\$regex" to "^" + r.pattern + "$")

    private fun constants(): Map<String, Any?> = linkedMapOf(
        "ACTION_SCHEMA_DOMAIN" to ActionSchema.ACTION_SCHEMA_DOMAIN, "ACTION_SCHEMA_REF_DOMAIN" to ActionSchema.ACTION_SCHEMA_REF_DOMAIN,
        "ACTION_SCHEMA_KIND" to ActionSchema.ACTION_SCHEMA_KIND, "WELL_KNOWN_PCA_ACTIONS_PATH" to ActionSchema.WELL_KNOWN_PCA_ACTIONS_PATH,
        "SENSITIVITIES" to ActionSchema.SENSITIVITIES, "SCHEMA_REVERSIBILITY" to ActionSchema.SCHEMA_REVERSIBILITY,
        "PARAM_TYPES" to ActionSchema.PARAM_TYPES, "PARAM_TYPES_V2" to ActionSchema.PARAM_TYPES_V2,
        "SCHEMA_V2_EFFECTS" to ActionSchema.SCHEMA_V2_EFFECTS, "SCHEMA_V2_CAVEATS" to ActionSchema.SCHEMA_V2_CAVEATS,
        "SCHEMA_V2_PRULES" to ActionSchema.SCHEMA_V2_PRULES, "SCHEMA_V2_CONTEXT" to ActionSchema.SCHEMA_V2_CONTEXT,
        "SCHEMA_V2_TAGS" to ActionSchema.SCHEMA_V2_TAGS, "SCHEMA_V2_PROVENANCE" to ActionSchema.SCHEMA_V2_PROVENANCE,
        "MAX_SCHEMA_VERBS" to ActionSchema.MAX_SCHEMA_VERBS, "MAX_SCHEMA_PARAMS" to ActionSchema.MAX_SCHEMA_PARAMS,
        "MAX_SCHEMA_VALUES" to ActionSchema.MAX_SCHEMA_VALUES, "DEFAULT_MAX_LEN" to ActionSchema.DEFAULT_MAX_LEN,
        "DEFAULT_MAX_ITEMS" to ActionSchema.DEFAULT_MAX_ITEMS,
        "PARAM_PATH_RE" to rx(ActionSchema.PARAM_PATH_RE), "PARAM_PATH_RE_V2" to rx(ActionSchema.PARAM_PATH_RE_V2), "UNIT_ID_RE" to rx(ActionSchema.UNIT_ID_RE),
        "WALLET_FLOOR_PREFIXES" to net.atlasauth.pca.intent.IntentSchema.WALLET_FLOOR_PREFIXES,
        "WALLET_FLOOR_EXACT" to net.atlasauth.pca.intent.IntentSchema.WALLET_FLOOR_EXACT,
    )

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> constants()
        "reversibilityOf" -> ActionSchema.reversibilityOf(map(a[0]), map(a[1]))
        "floorApplies" -> net.atlasauth.pca.intent.IntentSchema.floorApplies(a[0] as String, arg(a, 1) as Map<String, Any?>?)
        "schemaVerb" -> ActionSchema.schemaVerb(a[0], a[1] as String)
        "signActionSchema" -> SignersMore.signActionSchema(map(a[0]), a[1] as String, site(a, 2, 3))
        "actionSchemaKeyOf" -> SignersMore.actionSchemaKeyOf(a[0] as String, site(a, 1, 2))
        "actionSchemaDigest" -> ActionSchema.digest(a[0])
        "verifyActionSchema" -> ActionSchema.verify(a[0], a[1]).let { r -> if (r == null) linkedMapOf<String, Any?>("ok" to true) else linkedMapOf("ok" to false, "reason" to r) }
        "reversibilityFromMcpHints" -> ActionSchemaDraft.reversibilityFromMcpHints(arg(a, 0))
        "draftSchemaFromMcpTools" -> ActionSchemaDraft.draftSchemaFromMcpTools(a[0] as List<Any?>, a[1])
        "draftSchemaFromOpenApi" -> ActionSchemaDraft.draftSchemaFromOpenApi(a[0], a[1])
        else -> throw AssertionError("unhandled fn $fn")
    }

    private fun replay(mod: String, fns: Set<String>, total: Int) {
        var n = 0
        for (fn in fns) {
            OracleCases.each(mod, fn) { a -> call(fn, a) }
            n += OracleCases.of(mod, fn).size
        }
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(total, n)
    }

    @Test fun actionSchemaCorpus() = replay(
        "ref-action-schema",
        setOf("constants", "reversibilityOf", "floorApplies", "schemaVerb", "signActionSchema", "actionSchemaKeyOf", "actionSchemaDigest", "verifyActionSchema",
            "reversibilityFromMcpHints", "draftSchemaFromMcpTools", "draftSchemaFromOpenApi"),
        173,
    )

    @Test fun draftCorpus() = replay("ref-action-schema-draft", setOf("reversibilityOf", "schemaVerb", "reversibilityFromMcpHints", "draftSchemaFromOpenApi"), 104)
}
