package net.atlasauth.pca.connectors

import org.junit.Assert.assertEquals
import org.junit.Test

/** The seeded manifests are reachable by name, as the reference exports them. */
class ProvidersNamedTest {
    @Test fun everySeededManifestHasItsName() {
        val named = listOf(
            Providers.google, Providers.github, Providers.slack, Providers.notion, Providers.hubspot, Providers.atlassian, Providers.salesforce, Providers.microsoft,
            Providers.shopify, Providers.snowflake, Providers.linear, Providers.zoom, Providers.stripe, Providers.dropbox, Providers.airtable,
        )
        assertEquals(Providers.BUILTIN_MANIFESTS.map { it.id }.toSet(), named.map { it.id }.toSet())
        assertEquals("google", Providers.google.id)
    }
}
