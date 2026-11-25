package net.atlasauth.pca.ratchet

/** A refused ratchet operation. [code]: invalid_depth, invalid_seed, leaf_out_of_range or leaf_punctured. */
class RatchetError(val code: String, message: String) : RuntimeException(message)

/** A refused accumulator input. [code]: invalid_value, length_mismatch or invalid_proof_shape. */
class AccumulatorError(val code: String, message: String) : RuntimeException(message)
