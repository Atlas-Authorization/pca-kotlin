package net.atlasauth.pca.erc7715

import java.math.BigDecimal
import java.math.BigInteger
import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * ERC-7715 (`wallet_requestExecutionPermissions`) for PCA grants: pure mapping and verification, no chain access and no redemption
 * through a delegation manager. The mapping covers the two permission names the draft ERC shows (`native-token-allowance` with
 * `data.allowance`, and `erc20-token-allowance`, whose `{tokenAddress, allowance}` data is a PCA profile, not from the ERC). A wallet may
 * narrow a permission (`isAdjustmentAllowed`) but never widen it: amount, a later expiry, another token, chain, recipient or manager are
 * all refused. There is no price oracle: the caller states an exact integer ratio `baseUnitsPerMinor`. Values are parsed JSON.
 */
object Erc7715 {
    const val NATIVE = "native-token-allowance"
    const val ERC20 = "erc20-token-allowance"
    private val HEX_ADDR = Regex("0x[0-9a-fA-F]{40}")
    private val HEX_QTY = Regex("0x(0|[1-9a-fA-F][0-9a-fA-F]*)")
    private val HEX_CTX = Regex("0x[0-9a-fA-F]+")
    private val DEC = Regex("0|[1-9][0-9]*")

    /** JavaScript `undefined` (an absent member), told apart from JSON null. */
    private object Undef

    // ---- JavaScript value helpers ----

    /** `o[k]`: [Undef] when absent; a null or undefined o throws (TypeError); a primitive or an array has no such member. */
    private fun at(o: Any?, k: String): Any? {
        if (o == null || o === Undef) throw IllegalStateException("TypeError: cannot read properties of null (reading '$k')")
        return if (o is Map<*, *> && o.containsKey(k)) o[k] else Undef
    }

    private fun jsNumString(d: Double): String = when {
        d.isNaN() -> "NaN"
        d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
        d == 0.0 -> "0"
        else -> Json.esNumber(d)
    }

    /** JavaScript `String(v)`. */
    private fun str(v: Any?): String = when {
        v === Undef -> "undefined"
        v == null -> "null"
        v is String -> v
        v is Boolean -> v.toString()
        Js.num(v) != null -> jsNumString(Js.num(v)!!)
        v is List<*> -> v.joinToString(",") { if (it == null || it === Undef) "" else str(it) }
        else -> "[object Object]"
    }

    /** `s.toLowerCase()`: a non-string has no such method (TypeError). */
    private fun lower(s: Any?): String = (s as? String ?: throw IllegalStateException("TypeError: toLowerCase is not a function")).lowercase(Locale.ROOT)

    /** `Number.isSafeInteger` (-0 counts, as in the reference). */
    private fun safeInteger(o: Any?): Boolean = Js.num(o)?.let { !it.isNaN() && !it.isInfinite() && it == Math.floor(it) && Math.abs(it) <= 9007199254740991.0 } ?: false

    private fun test(p: Regex, v: Any?): Boolean = p.matches(str(v))

    private val BIG_HEX = Regex("0[xX][0-9a-fA-F]+")
    private val BIG_OCT = Regex("0[oO][0-7]+")
    private val BIG_BIN = Regex("0[bB][01]+")
    private val BIG_DEC = Regex("[+-]?[0-9]+")

    /** `BigInt(v)`: a string (trimmed; empty is 0; 0x / 0o / 0b literals; a signed decimal), an integral number or a boolean; anything else throws. */
    private fun bigInt(v: Any?): BigInteger {
        if (v is Boolean) return if (v) BigInteger.ONE else BigInteger.ZERO
        if (v is String) {
            var a = 0
            var b = v.length
            while (a < b && AttestUtil.isJsSpace(v[a].code)) a++
            while (b > a && AttestUtil.isJsSpace(v[b - 1].code)) b--
            val s = v.substring(a, b)
            return when {
                s.isEmpty() -> BigInteger.ZERO
                BIG_HEX.matches(s) -> BigInteger(s.substring(2), 16)
                BIG_OCT.matches(s) -> BigInteger(s.substring(2), 8)
                BIG_BIN.matches(s) -> BigInteger(s.substring(2), 2)
                BIG_DEC.matches(s) -> BigInteger(s.removePrefix("+"))
                else -> throw IllegalArgumentException("SyntaxError: cannot convert $s to a BigInt")
            }
        }
        // an array or an object goes through its string form, as BigInt's ToPrimitive does ([7] is 7n, [] is 0n, {} is a SyntaxError)
        if (v is List<*> || v is Map<*, *>) return bigInt(str(v))
        val d = Js.num(v)
        if (d != null && !d.isNaN() && !d.isInfinite() && d == Math.floor(d)) return BigDecimal(d).toBigInteger()
        throw IllegalArgumentException("TypeError: cannot convert to a BigInt")
    }

    private fun hexOf(n: BigInteger) = "0x" + n.toString(16)

    // ---- request ----

    /**
     * Map a grant's money envelope to a permission request. [g]: `grantDigest`, `capMinor` (cumulative cap, integer minor units),
     * `expiresAtSec`. [o]: `chainId` (a [BigInteger]), `sessionAccount`, optional `tokenAddress` (absent: native token),
     * `baseUnitsPerMinor` (exact decimal-integer ratio), optional `from`, optional `isAdjustmentAllowed` (default true).
     * Throws IllegalArgumentException on a bad envelope, address, ratio or chain.
     */
    fun grantToPermissionRequest(g: Map<String, Any?>, o: Map<String, Any?>): Map<String, Any?> {
        val cap = at(g, "capMinor")
        val exp = at(g, "expiresAtSec")
        require(safeInteger(cap) && Js.num(cap)!! > 0 && safeInteger(exp) && Js.num(exp)!! > 0) { "grantToPermissionRequest: bad envelope" }
        val session = at(o, "sessionAccount")
        val from = at(o, "from")
        val token = at(o, "tokenAddress")
        require(test(HEX_ADDR, session) && (from === Undef || test(HEX_ADDR, from)) && (token === Undef || test(HEX_ADDR, token))) { "grantToPermissionRequest: bad address" }
        val ratio = at(o, "baseUnitsPerMinor")
        require(test(DEC, ratio) && ratio != "0") { "grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string" }
        val chain = o["chainId"]
        require(chain is BigInteger && chain.signum() > 0) { "grantToPermissionRequest: bad chain" }
        val allowance = hexOf(BigDecimal(Js.num(cap)!!).toBigInteger().multiply(bigInt(ratio)))
        val out = Js.obj("chainId" to hexOf(chain as BigInteger))
        if (from !== Undef) out["from"] = from
        out["to"] = session
        val data = Js.obj()
        if (token !== Undef) data["tokenAddress"] = token
        data["allowance"] = allowance
        out["permission"] = Js.obj("type" to (if (token !== Undef) ERC20 else NATIVE), "isAdjustmentAllowed" to (o["isAdjustmentAllowed"] ?: true), "data" to data)
        out["rules"] = listOf(Js.obj("type" to "expiry", "data" to Js.obj("timestamp" to exp)))
        return out
    }

    /**
     * Does the wallet's `wallet_getSupportedExecutionPermissions` result (keyed by permission type, with `chainIds` and `ruleTypes` or the
     * draft's other spelling `rulesTypes`) cover this request: its permission type, its chain, and every rule type. Pure; never throws.
     */
    fun supportsRequest(supported: Any?, req: Any?): Boolean = try {
        supportsOrThrow(supported, req)
    } catch (e: RuntimeException) {
        false
    }

    private fun supportsOrThrow(supported: Any?, req: Any?): Boolean {
        val type = str(at(at(req, "permission"), "type"))
        val s = at(supported, type)
        if (s === Undef) return false
        val chainIds = at(s, "chainIds") as? List<*> ?: return false
        val want = lower(at(req, "chainId"))
        if (chainIds.map { lower(it) }.none { it == want }) return false // every element is lowered first: a non-string element throws
        var rt = at(s, "ruleTypes")
        if (rt === Undef || rt == null) rt = at(s, "rulesTypes")
        val rules = at(req, "rules")
        if (rules === Undef || rules == null) return true
        if (rules !is List<*>) return false // no every() on anything else
        for (r in rules) {
            if (rt !is List<*>) return false
            val t = at(r, "type")
            if (t === Undef || rt.none { it != null && it == t }) return false
        }
        return true
    }

    /** The params of `wallet_revokeExecutionPermission`. */
    fun revokeParams(context: Any?): Map<String, Any?> = Js.obj("permissionContext" to context)

    // ---- verification ----

    /** [allowedManagers]: the delegation managers the operator trusts for the chain (strings, compared lower-case); [contextOwner]: the grant digest a context handle is already bound to (null: unbound). */
    class Options(val allowedManagers: Any?, val contextOwner: ((String) -> Any?)? = null)

    private fun strictEq(a: Any?, b: Any?): Boolean {
        if (a === Undef || b === Undef) return a === b
        if (a == null || b == null) return a == b
        if (a is String && b is String) return a == b
        if (a is Boolean && b is Boolean) return a == b
        val x = Js.num(a)
        val y = Js.num(b)
        return x != null && y != null && x == y
    }

    /**
     * Verify what the wallet actually granted against the request sent and the grant. Returns null when the permission is within the
     * grant, else a reason (response_malformed, context_malformed, context_bound_to_other_grant, delegation_manager_not_allowed,
     * chain_mismatch, recipient_mismatch, from_mismatch, permission_type_mismatch, token_mismatch, amount_malformed, amount_widened,
     * adjustment_widened, expiry_missing, unknown_rule_type, duplicate_expiry, expiry_malformed, expiry_extended). A wallet may NARROW
     * (isAdjustmentAllowed); it may never widen. Any exception while reading a hostile response is response_malformed. Never throws.
     */
    fun verifyGrantedPermission(g: Any?, sent: Any?, got: Any?, o: Options): String? = try {
        verifyOrThrow(g, sent, got, o)
    } catch (e: RuntimeException) {
        "response_malformed"
    }

    private fun verifyOrThrow(g: Any?, sent: Any?, got: Any?, o: Options): String? {
        if (!(got is Map<*, *> || got is List<*>)) return "response_malformed"
        val perm = at(got, "permission")
        if (!(perm is Map<*, *> || perm is List<*>)) return "response_malformed"
        val ctx = at(got, "context")
        if (ctx !is String || !HEX_CTX.matches(ctx)) return "context_malformed"
        val owner = o.contextOwner?.invoke(ctx)
        if (owner != null && !strictEq(owner, at(g, "grantDigest"))) return "context_bound_to_other_grant"
        val dm = at(got, "delegationManager")
        if (dm !is String || !HEX_ADDR.matches(dm)) return "delegation_manager_not_allowed"
        val managers = o.allowedManagers as? List<*> ?: throw IllegalStateException("TypeError: allowedManagers.map is not a function")
        val lowDm = lower(dm)
        if (managers.map { lower(it) }.none { it == lowDm }) return "delegation_manager_not_allowed"
        if (lower(str(at(got, "chainId"))) != lower(at(sent, "chainId"))) return "chain_mismatch"
        if (lower(str(at(got, "to"))) != lower(at(sent, "to"))) return "recipient_mismatch"
        val sentFrom = at(sent, "from")
        if (sentFrom !== Undef && lower(str(at(got, "from"))) != lower(sentFrom)) return "from_mismatch"
        val sentPerm = at(sent, "permission")
        val type = at(perm, "type")
        if (!strictEq(type, at(sentPerm, "type")) || (type != NATIVE && type != ERC20)) return "permission_type_mismatch"
        val d = at(perm, "data")
        val sd = at(sentPerm, "data")
        val dTok = at(d, "tokenAddress")
        val sdTok = at(sd, "tokenAddress")
        if (lower(str(if (dTok === Undef || dTok == null) "" else dTok)) != lower(str(if (sdTok === Undef || sdTok == null) "" else sdTok))) return "token_mismatch"
        val allowance = at(d, "allowance")
        if (allowance !is String || !HEX_QTY.matches(allowance)) return "amount_malformed"
        if (bigInt(allowance) > bigInt(at(sd, "allowance"))) return "amount_widened"
        val radj = at(perm, "isAdjustmentAllowed")
        if (!strictEq(radj, at(sentPerm, "isAdjustmentAllowed")) && radj == true) return "adjustment_widened"
        val rules = at(got, "rules") as? List<*> ?: return "expiry_missing"
        var expiry: Any? = Undef
        for (rule in rules) {
            val rt = if (rule == null) Undef else at(rule, "type")
            if (rt != "expiry") return "unknown_rule_type"
            if (expiry !== Undef) return "duplicate_expiry"
            expiry = at(at(rule, "data"), "timestamp")
            if (!safeInteger(expiry) || Js.isNegZero(expiry)) return "expiry_malformed"
        }
        if (expiry === Undef) return "expiry_missing"
        val gExp = at(g, "expiresAtSec")
        val lim = Js.num(if (gExp === Undef) null else gExp)
        // a grant expiry that is not a safe integer bounds nothing: the wallet's expiry cannot be shown within it
        if (!(safeInteger(gExp) && lim != null && Js.num(expiry)!! <= lim)) return "expiry_extended"
        return null
    }

    /** `hashCanonical(grant)`: the digest a context is bound to. Throws for a value with no strict canonical form. */
    fun grantDigestOf(grant: Any?): String = Pca.hashCanonical(grant)
}
