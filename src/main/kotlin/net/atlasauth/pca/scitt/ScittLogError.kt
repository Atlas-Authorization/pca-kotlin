package net.atlasauth.pca.scitt

/** A transparency-log failure with a stable code: store_required, store_corrupt, append_contention, out_of_range, bad_statement. */
class ScittLogError(val code: String, message: String) : RuntimeException(message)
