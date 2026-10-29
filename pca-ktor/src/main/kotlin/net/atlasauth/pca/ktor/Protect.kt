package net.atlasauth.pca.ktor

import io.ktor.server.application.ApplicationCall
import java.util.concurrent.ConcurrentHashMap
import net.atlasauth.pca.verifier.Authorize

/**
 * What [protect] returns: [configure] is the plugin configuration (`install(PcaGuardPlugin, p.configure)`), [revoke] refuses every
 * further action under a grant id.
 */
class Protected internal constructor(val configure: PcaKtorConfig.() -> Unit, private val revoked: MutableSet<String>) {
    /** Refuse every further action under this grant id. */
    fun revoke(grantId: String) {
        revoked.add(grantId)
    }
}

/**
 * `protect()`: the secure defaults for a resource server, in one call.
 *
 *     val p = protect("ins_acme", listOf(grant)) { _, body -> Authorize.Operation("stripe.refund", "charge:...", paramsOf(body)) }
 *     routing { route("/refunds") { install(PcaGuardPlugin, p.configure); post { ... } } }
 *     p.revoke(grantId)   // later: every action under that grant is refused
 *
 * It fills in the parts every server otherwise wires by hand, and nothing else: the grant lookup (your own list or function,
 * never the request), an in-memory replay store, a revocation source, `plan = "single-step"` (the grant alone limits what runs).
 * Provenance by default stays on: pass [provenance] (`Authorize.ProvenanceOptions` with the pinned mediator keys of your agent
 * harness and your action facts) so a sensitive operation whose choice and arguments derive from the principal is allowed; the agent
 * presents its bundle in the `PCA-Provenance` header (or the body member `pca_provenance`).
 * Everything is still [Authorize.authorize]: bound to the operation your route executes, default-deny. [customize] runs last, so
 * any option you set there wins over the default (including a durable `authorize` with your own state store).
 *
 * Not carried over from the TypeScript helper: server-side risk from the connector catalog. This library has no catalog and its
 * authorize does not price risk, so none is configured; the grant's own predicates and limits still apply.
 *
 * The in-memory replay store is per process: use a shared store (set `authorize` in [customize]) when you run more than one instance.
 */
fun protect(
    audience: String,
    grants: List<Map<String, Any?>>,
    isRevoked: ((Map<String, Any?>) -> Boolean)? = null,
    customize: PcaKtorConfig.() -> Unit = {},
    provenance: Authorize.ProvenanceOptions? = null,
    operation: suspend (ApplicationCall, ByteArray) -> Authorize.Operation?,
): Protected {
    val byId = HashMap<String, Map<String, Any?>>()
    for (g in grants) (g["id"] as? String)?.let { byId[it] = g }
    return protect(audience, { ref -> byId[ref] }, isRevoked, customize, provenance, operation)
}

/** [protect] with a grant lookup function (`grant_ref` to grant, null = unknown) instead of a list. */
fun protect(
    audience: String,
    resolveGrant: (String) -> Map<String, Any?>?,
    isRevoked: ((Map<String, Any?>) -> Boolean)? = null,
    customize: PcaKtorConfig.() -> Unit = {},
    provenance: Authorize.ProvenanceOptions? = null,
    operation: suspend (ApplicationCall, ByteArray) -> Authorize.Operation?,
): Protected {
    val revoked: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val configure: PcaKtorConfig.() -> Unit = {
        this.audience = audience
        this.resolveGrant = resolveGrant
        this.operation = operation
        // the replay store is created per install, so two installs never share a counter
        this.authorize = Authorize.AuthorizeOptions(
            Authorize.MemoryStateStore(),
            { _, grant ->
                // anything but a clean "no" denies (see Authorize): a throwing extra source is a revoked grant
                (grant["id"] as? String)?.let { it in revoked } == true || (isRevoked != null && isRevoked(grant))
            },
            Authorize.SINGLE_STEP,
            provenance = provenance,
        )
        customize()
    }
    return Protected(configure, revoked)
}
