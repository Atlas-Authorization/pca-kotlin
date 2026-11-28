package net.atlasauth.pca.actions

import net.atlasauth.pca.actions.importers.GraphqlImporter
import net.atlasauth.pca.actions.importers.GrpcImporter
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the GraphQL and gRPC importers (SDL / proto parsing, introspection, descriptor sets). */
@Suppress("UNCHECKED_CAST")
class ActionsImportSdlDiffTest {
    private val MOD = "ref-actions-import-sdl"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    /** A {"$bytes": b64url} argument is the byte string itself. */
    private fun bytesOf(x: Any?): Any? {
        if (x !is Map<*, *> || x["\$bytes"] !is String) return x
        val s = x["\$bytes"] as String
        return if (s.isEmpty()) ByteArray(0) else Keys.unb64u(s)
    }

    @Test fun parseGraphqlSdl() = OracleCases.each(MOD, "parseGraphqlSdl") { a -> GraphqlImporter.parseGraphqlSdl(a[0] as String).toJson() }

    @Test fun fromIntrospection() = OracleCases.each(MOD, "fromIntrospection") { a -> GraphqlImporter.fromIntrospection(a[0]).toJson() }

    @Test fun importGraphql() = OracleCases.each(MOD, "importGraphql") { a -> GraphqlImporter.importGraphql(a[0], m(a[1])) }

    @Test fun parseProto() = OracleCases.each(MOD, "parseProto") { a -> GrpcImporter.parseProto(a[0] as String).toJson() }

    @Test fun parseDescriptorSet() = OracleCases.each(MOD, "parseDescriptorSet") { a -> GrpcImporter.parseDescriptorSet(bytesOf(a[0]) as ByteArray).toJson() }

    @Test fun importGrpc() = OracleCases.each(MOD, "importGrpc") { a -> GrpcImporter.importGrpc(bytesOf(a[0]), m(a[1])) }
}
