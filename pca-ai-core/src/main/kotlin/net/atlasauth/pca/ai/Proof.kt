package net.atlasauth.pca.ai

/** A built proof-carrying action: the PCActn, its encoded form (the `PCA-Action` header value) and the request headers to forward. */
class Proof(val pcactn: Map<String, Any?>, val encoded: String, val headers: Map<String, String>)
