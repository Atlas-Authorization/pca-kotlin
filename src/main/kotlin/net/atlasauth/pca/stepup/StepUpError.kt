package net.atlasauth.pca.stepup

/** Everything the step-up module can throw. */
sealed class StepUpError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** No principal key is stored yet; call [PrincipalDeviceKey.generate] or [PrincipalDeviceKey.importSecret]. */
    class NoDeviceKey : StepUpError("No principal device key is stored on this device.")

    /** The principal secret is not a base64url 32-byte Ed25519 seed. */
    class InvalidSecret : StepUpError("The principal secret must be a base64url-encoded 32-byte Ed25519 seed.")

    /** The server's `threshold_message` is not valid base64url. */
    class InvalidThresholdMessage : StepUpError("The step-up's threshold message is not valid base64url.")

    /** HTTP 403: this device key is not the grant's principal key. [message] is the server's guidance. */
    class PrincipalMismatch(message: String) : StepUpError(message)

    /** Any other non-2xx answer (409 already approved/denied/expired, 401, 404, 422 ...). */
    class Api(val status: Int, message: String) : StepUpError("HTTP $status: $message")

    /** Network failure or an unreadable body. */
    class Transport(message: String, cause: Throwable? = null) : StepUpError(message, cause)
}
