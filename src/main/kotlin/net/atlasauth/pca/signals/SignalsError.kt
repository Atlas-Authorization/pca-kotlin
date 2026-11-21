package net.atlasauth.pca.signals

/** A misconfiguration or malformed input to the signals package. [code] names the check (misconfigured, bad_snapshot, unmapped_subject). */
class SignalsError(@JvmField val code: String, message: String) : RuntimeException(message)
