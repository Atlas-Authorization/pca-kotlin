package net.atlasauth.pca.actions.importers

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json

/** The shipped suggestion rules: DATA, versioned. Every rule only ADDS. These are heuristics measured against a labeled corpus; none is a safety guarantee. */
@Suppress("UNCHECKED_CAST")
object ImportRules {
    const val DEFAULT_RULES_VERSION: String = "1.1.0"

    @JvmField val DEFAULT_RULES: Map<String, Any?> = IntentJs.normalize(Json.parseLenient(ImportRulesData.json())) as Map<String, Any?>

    /** The default rule set with its digest. */
    @JvmField val DEFAULT_RULES_SEALED: Map<String, Any?> = ImportSuggest.sealRules(DEFAULT_RULES)

    /** The digest recorded when the rule set was published. */
    fun publishedDigest(): String = ImportRulesData.SEALED_DIGEST
}
