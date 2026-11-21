package net.atlasauth.pca.ai

/** A tool call was refused before it ran: no proof could be built, the local pre-check denied it, or the tool is not mapped. Fail closed. */
class PcaDenied @JvmOverloads constructor(reason: String, val verb: String?, val resource: String?, cause: Throwable? = null) : RuntimeException(reason, cause)
