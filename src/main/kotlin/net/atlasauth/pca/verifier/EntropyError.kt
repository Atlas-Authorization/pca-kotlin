package net.atlasauth.pca.verifier

/** Typed entropy failure: only thrown where a caller demanded quantum entropy or the transport is unsafe. Codes: quantum_required, health_test_failed, insecure_transport. */
class EntropyError(val code: String, message: String) : RuntimeException(message)
