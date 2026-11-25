package net.atlasauth.pca.verifier

import net.atlasauth.pca.connectors.Manifest
import net.atlasauth.pca.connectors.ProviderRegistry
import net.atlasauth.pca.connectors.Providers
import org.junit.Assert.assertEquals
import org.junit.Test

/** The seeded connector catalog against the reference corpus (ref-connectors-providers, 40 cases): every manifest, its digest, the catalog digest and the unknown-id lookups. */
class ConnectorsProvidersRefDiffTest {
    private val mod = "ref-connectors-providers"

    @Test fun everyFunction() {
        OracleCases.each(mod, "provider") { x ->
            val p = Providers.byId(x[0] as String)!!
            linkedMapOf("manifest" to p.toMap(), "digest" to Manifest.manifestDigest(p), "valid" to Manifest.validateManifest(p.toMap()).ok)
        }
        OracleCases.each(mod, "invariants") { x ->
            val id = x[0] as String
            val p = Providers.byId(id)!!
            linkedMapOf(
                "defaultScopesSubset" to p.defaultScopes.all { p.scopesAvailable.contains(it) }, "scopesUnique" to (p.scopesAvailable.toSet().size == p.scopesAvailable.size),
                "idMatchesKey" to (p.id == id), "httpsEndpoints" to (p.authorizeUrl.startsWith("https://") && p.tokenUrl.startsWith("https://")),
            )
        }
        OracleCases.each(mod, "builtinManifests") { _ ->
            linkedMapOf(
                "ids" to Providers.BUILTIN_MANIFESTS.map { it.id }, "digests" to Providers.BUILTIN_MANIFESTS.map { Manifest.manifestDigest(it) },
                "catalogDigest" to ProviderRegistry.catalogDigest(),
            )
        }
        OracleCases.each(mod, "unknownProvider") { x -> linkedMapOf("found" to (Providers.byId(x[0] as String) != null)) }
        val fns = setOf("provider", "invariants", "builtinManifests", "unknownProvider")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(40, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
