package net.atlasauth.pca.connectors

/** Base class for every runtime refusal the connector catalog raises. */
open class ConnectorError internal constructor(
    /** The reference's error class name (ConnectorError, ManifestValidationError, UnknownProviderError). */
    val errorName: String,
    message: String,
) : RuntimeException(message) {
    constructor(message: String) : this("ConnectorError", message)

    /** A manifest failed structural validation; [issues] lists every problem found. */
    class ManifestValidationError(issues: List<String>) : ConnectorError(
        "ManifestValidationError", "invalid provider manifest: " + issues.joinToString("; "),
    ) {
        val issues: List<String> = ArrayList(issues)
    }

    /** No manifest is registered for the requested provider id. */
    class UnknownProviderError(val providerId: String) : ConnectorError(
        "UnknownProviderError", "no connector registered for provider '$providerId'",
    )
}
