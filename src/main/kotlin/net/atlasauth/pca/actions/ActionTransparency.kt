package net.atlasauth.pca.actions

import net.atlasauth.pca.scitt.Scitt
import net.atlasauth.pca.scitt.ScittPrivateKey
import net.atlasauth.pca.scitt.ScittPublicKey
import net.atlasauth.pca.scitt.TransparencyService
import net.atlasauth.pca.verifier.ActionsRegistry
import net.atlasauth.pca.verifier.Json

/**
 * Append a signed pack to a SCITT transparency log (RFC 9943) and verify the receipt. The statement is a COSE Signed Statement over
 * `{ns, version, digest, root, prev}`; a verifier holding the pinned log key and tree root can show that this exact pack version was published.
 */
object ActionTransparency {
    const val PACK_STATEMENT_CONTENT_TYPE: String = "application/pca-action-pack+json"

    /** The payload the registry signs into the log (small: the digest, not the pack). */
    fun packStatementPayload(p: Map<String, Any?>): Map<String, Any?> =
        J.obj("v", J.n(1), "kind", "pca-action-pack-statement", "ns", p["ns"], "version", p["version"], "digest", ActionsRegistry.packDigest(p), "root", p["root"], "prev", p["prev"])

    /** What [appendPackToLog] returns. */
    class PackLogEntry(@JvmField val statement: ByteArray, @JvmField val receipt: ByteArray, @JvmField val index: Long, @JvmField val root: String)

    /** Sign the pack's statement with the registry's COSE key and register it. */
    fun appendPackToLog(pack: Map<String, Any?>, service: TransparencyService, alg: Scitt.CoseAlg, key: ScittPrivateKey, issuer: String?): PackLogEntry {
        val statement = Scitt.signStatement(
            packStatementPayload(pack),
            Scitt.SignStatementOpts(alg, key, issuer).subject("${pack["ns"]}@${pack["version"]}").contentType(PACK_STATEMENT_CONTENT_TYPE),
        )
        val r = TransparencyService.registerStatement(statement, service)
        return PackLogEntry(statement, r.receipt, r.index, r.root)
    }

    /** Does the entry prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never throws. */
    fun verifyPackLogEntry(pack: Map<String, Any?>, statement: ByteArray, receipt: ByteArray, registry: ScittPublicKey, log: ScittPublicKey, treeRoot: String?): Boolean = try {
        val o = Scitt.VerifyReceiptOpts()
        o.verificationKey = log
        o.statementKey = registry
        o.treeRoot = treeRoot
        Scitt.verifyReceipt(receipt, statement, o) && statementIsFor(pack, statement)
    } catch (e: RuntimeException) {
        false
    }

    private fun statementIsFor(pack: Map<String, Any?>, statement: ByteArray): Boolean {
        val got = Scitt.statementPayload(statement)
        val want = Json.canonicalize(packStatementPayload(pack)).toByteArray(Charsets.UTF_8)
        return got.contentEquals(want)
    }
}
