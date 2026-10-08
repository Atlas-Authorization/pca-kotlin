package net.atlasauth.pca.stepup

/** A t=3 action waiting for the principal's device signature. */
data class PendingStepUp(
    val id: String,
    val grantRef: String,
    val actionVerb: String,
    val actionResource: String,
    val requiredT: Int,
    /** base64url of the exact bytes the principal key must sign. */
    val thresholdMessageB64u: String,
    /** Expiry as epoch milliseconds. */
    val expiresAt: Long,
) {
    /** Human summary for a confirmation sheet, e.g. "payments.refund on order/1234". */
    val summary: String get() = "$actionVerb on $actionResource"
}

/** Result of an approval. [anchored] is true once enough roles signed and the action was released. */
data class ApproveResult(val status: String, val anchored: Boolean, val httpStatus: Int)
