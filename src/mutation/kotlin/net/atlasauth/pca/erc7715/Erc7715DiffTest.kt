package net.atlasauth.pca.erc7715

import java.math.BigInteger
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the ERC-7715 permission mapping and verification through the native port. */
@Suppress("UNCHECKED_CAST")
class Erc7715DiffTest {
    private val m = "ref-erc7715"

    private fun mm(o: Any?) = o as Map<String, Any?>

    /** The reference takes the chain as a bigint: it crosses as a decimal string and becomes a BigInteger. */
    private fun withChain(o: Any?): Map<String, Any?> = LinkedHashMap(mm(o)).also { x -> (x["chainId"] as? String)?.let { x["chainId"] = BigInteger(it) } }

    @Test fun grantToPermissionRequest() = OracleCases.each(m, "grantToPermissionRequest") { Erc7715.grantToPermissionRequest(mm(it[0]), withChain(it[1])) }
    @Test fun supportsRequest() = OracleCases.each(m, "supportsRequest") { Erc7715.supportsRequest(it[0], it[1]) }
    @Test fun revokeParams() = OracleCases.each(m, "revokeParams") { if (it.isEmpty()) LinkedHashMap<String, Any?>() else Erc7715.revokeParams(it[0]) }
    @Test fun verifyGrantedPermission() = OracleCases.each(m, "verifyGrantedPermission") { a ->
        val x = mm(a[3])
        val owners = x["owners"] as? Map<String, Any?>
        Erc7715.verifyGrantedPermission(a[0], a[1], a[2], Erc7715.Options(x["allowedManagers"], owners?.let { o -> { ctx: String -> o[ctx] } }))
    }
    @Test fun grantDigestOf() = OracleCases.each(m, "grantDigestOf") { Erc7715.grantDigestOf(it[0]) }
}
