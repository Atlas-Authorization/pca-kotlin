package net.atlasauth.pca.verifier

import java.io.File

/**
 * Locates the shared conformance files for the 0.5 parity tests. In the monorepo they live under `packages/pca/conformance`
 * and `packages/pca-conformance/vectors/goal`; a standalone checkout vendors them as `conformance/` and `conformance/goal/`.
 * A missing file FAILS the test (never skipped): the corpus is part of the contract.
 */
@Suppress("UNCHECKED_CAST")
object ParityVectors {
    private fun findUp(vararg rels: String): File? {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            for (rel in rels) {
                val c = File(dir, rel)
                if (c.exists()) return c
            }
            dir = dir.parentFile
        }
        return null
    }

    fun file(name: String): File =
        findUp("packages/pca/conformance/$name", "conformance/$name") ?: throw IllegalStateException("conformance/$name is missing: the shared corpus must be present (never skipped)")

    fun load(name: String): Map<String, Any?> = Json.parseLenient(file(name).readText(Charsets.UTF_8)) as Map<String, Any?>

    /** The goal vector directory (`index.json` plus one file per vector). */
    fun goalDir(): File =
        findUp("packages/pca-conformance/vectors/goal", "conformance/goal") ?: throw IllegalStateException("conformance/goal is missing: the goal vectors must be present (never skipped)")

    /** The action-kit vector directory (one JSON file per case). */
    fun actionsDir(): File =
        findUp("packages/pca-conformance/vectors/actions", "conformance/actions") ?: throw IllegalStateException("conformance/actions is missing: the action-kit vectors must be present (never skipped)")

    /** The approval profile vector directory (PSD2 linking, batch; K7). */
    fun approvalProfilesDir(): File =
        findUp("packages/pca-conformance/vectors/approval-profiles", "conformance/approval-profiles") ?: throw IllegalStateException("conformance/approval-profiles is missing: the approval profile vectors must be present (never skipped)")

    fun table(file: String, key: String, name: String): List<Map<String, Any?>> =
        ((load(file)[key] as Map<String, Any?>)[name]) as List<Map<String, Any?>>

    fun decisionTable(name: String): List<Map<String, Any?>> = table("decision-vectors.json", "primitives", name)

    fun parse(text: String): Any? = Json.parseLenient(text)

    @Suppress("UNCHECKED_CAST")
    fun obj(text: String): Map<String, Any?> = Json.parseLenient(text) as Map<String, Any?>
}
