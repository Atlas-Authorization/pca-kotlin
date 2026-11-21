package example

import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import java.io.File
import net.atlasauth.pca.ktor.PcaGuardPlugin
import net.atlasauth.pca.ktor.Protected
import net.atlasauth.pca.ktor.pca
import net.atlasauth.pca.ktor.protect
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json

/** The audience this server is: a proof signed for another audience is refused. */
const val AUDIENCE = "payments-rs"

/**
 * The guard's configuration. The operation is what THIS route executes: the verb and resource come from the route, the params from
 * the request body. A proof is accepted only if it authorizes exactly this operation, so it cannot be replayed for another one.
 * Provenance is required by default: [provenance] pins your agent harness's recorder key, and the agent sends its bundle in the
 * `PCA-Provenance` header. Without a pinned key every payment is held for the principal.
 */
fun newProtection(
    grants: List<Map<String, Any?>>,
    provenance: Authorize.ProvenanceOptions? = null,
    nowMs: () -> Long = { System.currentTimeMillis() },
): Protected =
    protect(AUDIENCE, grants, provenance = provenance, customize = { clock = nowMs }) { _, body ->
        @Suppress("UNCHECKED_CAST")
        val params = try { Json.parse(String(body, Charsets.UTF_8)) as? Map<String, Any?> } catch (e: RuntimeException) { null }
        if (params == null) null else Authorize.Operation("payments.send", "payments/acme", params)
    }

/** POST /refunds, guarded. Call `revoke(grantId)` on the protection to refuse every further action under a grant. */
fun Application.refundsModule(p: Protected) {
    routing {
        route("/refunds") {
            install(PcaGuardPlugin, p.configure)
            post {
                val allowed = call.pca!! // only reached on an allow: the verdict, the PCActn and the bound operation
                call.respondText("{\"refunded\":true,\"operation\":\"${allowed.operation?.id}\"}", ContentType.Application.Json)
            }
        }
    }
}

/**
 * Run with `gradle run`. PCA_GRANTS names a JSON file holding a list of grants (your store, in a real server); PCA_MEDIATORS a JSON
 * file holding the list of pinned recorder keys `{mediator, kid, pk, pq_pk?}` of your agent harness.
 */
fun main() {
    val file = System.getenv("PCA_GRANTS") ?: error("set PCA_GRANTS to a JSON file with a list of grants")
    @Suppress("UNCHECKED_CAST")
    val grants = Json.parse(File(file).readText()) as List<Map<String, Any?>>
    @Suppress("UNCHECKED_CAST")
    val mediators = System.getenv("PCA_MEDIATORS")?.let { Json.parse(File(it).readText()) as List<Map<String, Any?>> } ?: emptyList()
    embeddedServer(Netty, port = 8080) { refundsModule(newProtection(grants, Authorize.ProvenanceOptions(mediators))) }.start(wait = true)
}
