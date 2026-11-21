package net.atlasauth.pca.gnap

import net.atlasauth.pca.verifier.Issue

/** The Agent-GNAP profile as a machine-readable spec object. */
internal object GnapProfile {
    private fun obj(vararg kv: Pair<String, Any?>) = Issue.obj(*kv)
    private fun lst(vararg xs: Any?): MutableList<Any?> = arrayListOf(*xs)
    private fun row(gnap: String, pca: String, note: String) = obj("gnap" to gnap, "pca" to pca, "note" to note)

    fun profile(): Map<String, Any?> = obj(
        "name" to "agent-gnap",
        "version" to "1.0",
        "rfc" to "RFC 9635",
        "summary" to "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
        "mapping" to lst(
            row("access[].type", "predicate resource namespace gnap:<type>:<location>", "the resource family the rights live in"),
            row("access[].actions", "predicate.verb (list, or * for any)", "the operations permitted"),
            row("access[].locations", "predicate.resource (exact or trailing-* prefix)", "the resource targets"),
            row("access[].datatypes / identifier", "predicate.where on action.params.*", "value-level constraints"),
            row("client.key.jwk (OKP/Ed25519)", "capability.holder (cnf-bound key)", "the proof-of-possession key"),
            row("grant request (no prior grant)", "mintGrant → root capability", "envelope predicates = requested access"),
            row("grant request (delegated hop)", "delegate → child capability + gnap_access caveat", "append-only attenuation"),
            row("access_token (§3.2)", "a verifiable PCA capability chain (encodeBoundToken)", "bound, self-verifying token"),
            row("continue (§3.1) + interact (§3.3)", "PCA step-up: FROST/threshold co-signature folded into a PCActn", "tier-2/3 escalation"),
            row("jwsd detached JWS (§7.3.4)", "request proof binding the body to capability.holder", "verified with jose"),
        ),
        "proofMethods" to lst("jwsd"),
        "multiHop" to "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA caveats are conjunctive and append-only, so no hop can widen — \"never wider than the issuer\" holds across any depth.",
        "stepUp" to "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or multi-signature) before the action is admitted.",
        "security" to lst(
            "Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
            "Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
            "All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
            "Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
            "Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.",
        ),
    )
}
