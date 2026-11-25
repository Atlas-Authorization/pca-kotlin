package net.atlasauth.pca.connectors

import net.atlasauth.pca.verifier.Pca

/**
 * The connector registry: an in-memory map of provider id to [ProviderManifest]. A manifest is validated on the way in, so nothing
 * malformed can ever be looked up. [defaultRegistry] is the process-wide registry seeded with the built-in catalog; callers who want
 * isolation build their own with [createDefaultRegistry].
 */
class ProviderRegistry {
    private val byId = HashMap<String, ProviderManifest>()

    /** Options of [register]: replace on purpose, and/or pin the digest of the manifest you reviewed. */
    class RegisterOptions @JvmOverloads constructor(
        var replace: Boolean = false,
        /** Null = no pin. */
        var expectedDigest: String? = null,
    )

    /**
     * Validate and register a manifest (a [ProviderManifest] or an untrusted parsed-JSON tree). Throws `ManifestValidationError` on a
     * malformed input, and refuses to replace a provider that is already registered: silently swapping the manifest of `google` would send its
     * tokens to a different endpoint.
     */
    @Synchronized @JvmOverloads fun register(manifest: Any?, opts: RegisterOptions? = null): ProviderManifest {
        val valid = Manifest.assertManifest(if (manifest is ProviderManifest) manifest.toMap() else manifest)
        if (opts != null && opts.expectedDigest != null && Manifest.manifestDigest(valid) != opts.expectedDigest) {
            throw ConnectorError("manifest '${valid.id}' does not match the pinned digest")
        }
        if (byId.containsKey(valid.id) && !(opts != null && opts.replace)) {
            throw ConnectorError("provider '${valid.id}' is already registered; pass { replace: true } to replace it deliberately")
        }
        byId[valid.id] = valid
        return valid
    }

    /** The manifest for [id], or null when none is registered. */
    @Synchronized fun get(id: String): ProviderManifest? = byId[id]

    /** The manifest for [id], or throw [ConnectorError.UnknownProviderError]. */
    @Synchronized fun require(id: String): ProviderManifest = byId[id] ?: throw ConnectorError.UnknownProviderError(id)

    @Synchronized fun has(id: String): Boolean = byId.containsKey(id)

    /** Every registered manifest, in ascending id order. */
    @Synchronized fun list(): List<ProviderManifest> = byId.values.sortedWith { a, b -> a.id.compareTo(b.id) }

    /** The registered provider ids, in ascending order. */
    fun ids(): List<String> = list().map { it.id }

    companion object {
        /** A fresh registry seeded with the full built-in connector catalog. */
        @JvmStatic fun createDefaultRegistry(): ProviderRegistry {
            val r = ProviderRegistry()
            for (m in Providers.BUILTIN_MANIFESTS) r.register(m)
            return r
        }

        private val DEFAULT: ProviderRegistry by lazy { createDefaultRegistry() }

        /** The process-wide registry the top-level [registerProvider] / [getProvider] / [listProviders] operate on. */
        @JvmStatic fun defaultRegistry(): ProviderRegistry = DEFAULT

        /** Validate and register a custom manifest onto the default registry. */
        @JvmStatic @JvmOverloads fun registerProvider(manifest: Any?, opts: RegisterOptions? = null): ProviderManifest = defaultRegistry().register(manifest, opts)

        /** A digest of the whole registry (every manifest, by id). Pin it to detect any change to the catalog. */
        @JvmStatic @JvmOverloads fun catalogDigest(registry: ProviderRegistry = defaultRegistry()): String {
            val rows = ArrayList<Any?>()
            for (m in registry.list()) rows.add(arrayListOf<Any?>(m.id, Manifest.manifestDigest(m)))
            return Pca.hashCanonical(rows)
        }

        /** The manifest for [id] in the default registry, or null. */
        @JvmStatic fun getProvider(id: String): ProviderManifest? = defaultRegistry().get(id)

        /** Every manifest in the default registry, in ascending id order. */
        @JvmStatic fun listProviders(): List<ProviderManifest> = java.util.Collections.unmodifiableList(defaultRegistry().list())
    }
}
