package net.atlasauth.pca.goal

/** A value that is not exactly a Goal IR value, or a malformed compiler tape. */
class IrError(m: String) : RuntimeException("pca-goal: $m")
