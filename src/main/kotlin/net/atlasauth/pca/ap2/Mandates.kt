package net.atlasauth.pca.ap2

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.ap2.Ap2Js.def
import net.atlasauth.pca.ap2.Ap2Js.get
import net.atlasauth.pca.ap2.Ap2Js.isArr
import net.atlasauth.pca.ap2.Ap2Js.isInt
import net.atlasauth.pca.ap2.Ap2Js.isNonEmptyStr
import net.atlasauth.pca.ap2.Ap2Js.isNonNegInt
import net.atlasauth.pca.ap2.Ap2Js.isObj
import net.atlasauth.pca.ap2.Ap2Js.isStr

/**
 * AP2 mandate claim shapes (Intent/Cart/Payment, closed and open) and their validators.
 *
 * The shapes follow the official AP2 JSON Schemas. The validators are hand-written over parsed JSON (Map, List, String, Boolean,
 * Json.Num, null), check at least what those schemas check, and are stricter in places where a lax reading would be unsafe
 * (non-negative safe-integer amounts, well-formed JWKs). Each returns the list of problems (empty = valid).
 */
object Mandates {
    const val VCT_CHECKOUT = "mandate.checkout.1"
    const val VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
    const val VCT_PAYMENT = "mandate.payment.1"
    const val VCT_PAYMENT_OPEN = "mandate.payment.open.1"

    /** Namespaced claim carrying PCA's own proof inside a mandate object. */
    const val PCA_CLAIM = "x_pca"

    @JvmField
    val FREQUENCIES: List<String> = java.util.Collections.unmodifiableList(listOf("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"))

    // ---------------------------------------------------------------------------------------------
    // currencies and minor units
    // ---------------------------------------------------------------------------------------------

    private val ZERO_DECIMAL = setOf("BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF")
    private val THREE_DECIMAL = setOf("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND")
    private val FOUR_DECIMAL = setOf("CLF", "UYW")

    internal fun isAlpha3(v: Any?): Boolean {
        if (v !is String || v.length != 3) return false
        for (c in v) if (c < 'A' || c > 'Z') return false
        return true
    }

    /** ISO 4217 minor-unit exponent for [currency] (2 for any code not in the 0/3/4-digit tables). */
    @JvmStatic
    fun currencyExponent(currency: Any?): Int {
        if (!isAlpha3(currency)) throw Ap2Error("currency must be an ISO 4217 alpha-3 code, got " + (if (currency === Ap2Js.UNDEF) "undefined" else Ap2Js.stringify(currency)))
        return when (currency as String) {
            in ZERO_DECIMAL -> 0
            in THREE_DECIMAL -> 3
            in FOUR_DECIMAL -> 4
            else -> 2
        }
    }

    /**
     * Convert a major-unit amount (e.g. `120.5` USD) to integer minor units (`12050`). Throws unless the amount is exactly
     * representable with the currency's exponent: float drift (`0.1 + 0.2`) is refused rather than rounded away.
     */
    @JvmStatic
    fun toMinorUnits(major: Any?, currency: Any?): Double {
        val e = currencyExponent(currency)
        if (!Ap2Js.isFinite(major) || Ap2Js.num(major)!! < 0) throw Ap2Error("amount must be a finite non-negative number, got " + Ap2Js.str(major))
        val m = Ap2Js.num(major)!!
        if (m >= 1e21) throw Ap2Error("amount " + Ap2Js.str(major) + " is outside the safe integer range in minor units") // toFixed answers in exponent form there
        val fixed = BigDecimal(m).setScale(e, RoundingMode.HALF_UP).toPlainString()
        if (fixed.toDouble() != m) throw Ap2Error("amount " + Ap2Js.str(major) + " is not exactly representable in " + currency + " minor units")
        val minor = fixed.replace(".", "").toDouble()
        if (!Ap2Js.isSafeInteger(minor)) throw Ap2Error("amount " + Ap2Js.str(major) + " is outside the safe integer range in minor units")
        return minor
    }

    /** Integer minor units to the major-unit number PCA budgets use (exact for any safe integer). */
    @JvmStatic
    fun fromMinorUnits(minor: Any?, currency: Any?): Double {
        val e = currencyExponent(currency)
        if (!Ap2Js.isSafeInteger(minor) || Ap2Js.num(minor)!! < 0 || Ap2Js.isNegZero(Ap2Js.num(minor)!!)) throw Ap2Error("minor-unit amount must be a non-negative safe integer, got " + Ap2Js.str(minor))
        return Ap2Js.num(minor)!! / Math.pow(10.0, e.toDouble())
    }

    // ---------------------------------------------------------------------------------------------
    // validators
    // ---------------------------------------------------------------------------------------------

    private fun problems(vararg ps: String): MutableList<String> = ArrayList<String>().also { it.addAll(ps) }

    private fun merchantProblems(v: Any?, at: String): MutableList<String> {
        if (!isObj(v)) return problems("$at: not an object")
        val p = ArrayList<String>()
        if (!isNonEmptyStr(get(v, "id"))) p.add("$at.id: required string")
        if (!isNonEmptyStr(get(v, "name"))) p.add("$at.name: required string")
        if (def(v, "website") && !isStr(get(v, "website"))) p.add("$at.website: must be a string")
        return p
    }

    private fun amountProblems(v: Any?, at: String): MutableList<String> {
        if (!isObj(v)) return problems("$at: not an object")
        val p = ArrayList<String>()
        if (!isNonNegInt(get(v, "amount"))) p.add("$at.amount: must be a non-negative integer (minor units)")
        if (!isAlpha3(get(v, "currency"))) p.add("$at.currency: must be an ISO 4217 alpha-3 code")
        return p
    }

    private fun instrumentProblems(v: Any?, at: String): MutableList<String> {
        if (!isObj(v)) return problems("$at: not an object")
        val p = ArrayList<String>()
        if (!isNonEmptyStr(get(v, "id"))) p.add("$at.id: required string")
        if (!isNonEmptyStr(get(v, "type"))) p.add("$at.type: required string")
        if (def(v, "description") && !isStr(get(v, "description"))) p.add("$at.description: must be a string")
        return p
    }

    private fun pispProblems(v: Any?, at: String): MutableList<String> {
        if (!isObj(v)) return problems("$at: not an object")
        val p = ArrayList<String>()
        for (k in arrayOf("legal_name", "brand_name", "domain_name")) if (!isNonEmptyStr(get(v, k))) p.add("$at.$k: required string")
        return p
    }

    private fun timeProblems(v: Map<String, Any?>): MutableList<String> {
        val p = ArrayList<String>()
        for (k in arrayOf("iat", "exp")) if (v.containsKey(k) && !isNonNegInt(v[k])) p.add("$k: must be an integer epoch-seconds")
        return p
    }

    private fun cnfProblems(v: Any?): MutableList<String> {
        if (!isObj(v) || !isObj(get(v, "jwk"))) return problems("cnf: must be { jwk }")
        return try {
            Sdjwt.assertP256Jwk(get(v, "jwk"), "cnf.jwk")
            ArrayList()
        } catch (e: Ap2Error) {
            problems(e.message.toString())
        }
    }

    private fun pcaClaimProblems(v: Map<String, Any?>): MutableList<String> =
        if (v.containsKey(PCA_CLAIM) && !isObj(v[PCA_CLAIM])) problems("$PCA_CLAIM: must be an object") else ArrayList()

    private fun listProblems(v: Any?, at: String, each: (Any?, String) -> List<String>): MutableList<String> {
        if (!isArr(v)) return problems("$at: must be an array")
        val out = ArrayList<String>()
        val l = Ap2Js.arr(v)
        for (i in l.indices) out.addAll(each(l[i], "$at[$i]"))
        return out
    }

    private fun paymentConstraintProblems(c: Any?, at: String): List<String> {
        if (!isObj(c) || !isStr(get(c, "type"))) return problems("$at: constraint must be an object with a string type")
        val m = Ap2Js.obj(c)
        val type = m["type"] as String
        val p = ArrayList<String>()
        when (type) {
            "payment.agent_recurrence" -> {
                val f = m["frequency"]
                if (f !is String || !FREQUENCIES.contains(f)) p.add("$at.frequency: not a known frequency")
                if (m.containsKey("max_occurrences") && !(isInt(m["max_occurrences"]) && Ap2Js.num(m["max_occurrences"])!! > 0)) p.add("$at.max_occurrences: must be a positive integer")
                return p
            }
            "payment.allowed_payees" -> return listProblems(m["allowed"], "$at.allowed", ::merchantProblems)
            "payment.allowed_payment_instruments" -> return listProblems(m["allowed"], "$at.allowed", ::instrumentProblems)
            "payment.allowed_pisps" -> return listProblems(m["allowed"], "$at.allowed", ::pispProblems)
            "payment.amount_range" -> {
                if (!isAlpha3(m["currency"])) p.add("$at.currency: must be an ISO 4217 alpha-3 code")
                if (!isNonNegInt(m["max"])) p.add("$at.max: must be a non-negative integer (minor units)")
                if (m.containsKey("min") && !isNonNegInt(m["min"])) p.add("$at.min: must be a non-negative integer (minor units)")
                if (isInt(m["max"]) && isInt(m["min"]) && Ap2Js.num(m["min"])!! > Ap2Js.num(m["max"])!!) p.add("$at: min exceeds max")
                return p
            }
            "payment.budget" -> {
                if (!isAlpha3(m["currency"])) p.add("$at.currency: must be an ISO 4217 alpha-3 code")
                if (!Ap2Js.isFinite(m["max"]) || Ap2Js.num(m["max"])!! < 0) p.add("$at.max: must be a non-negative number (major units)")
                return p
            }
            "payment.execution_date" -> {
                for (k in arrayOf("not_before", "not_after")) if (m.containsKey(k) && !isStr(m[k])) p.add("$at.$k: must be a string")
                return p
            }
            "payment.reference" -> return if (isNonEmptyStr(m["conditional_transaction_id"])) p else problems("$at.conditional_transaction_id: required string")
            else -> return problems("$at: unknown constraint type $type")
        }
    }

    private fun acceptableItemProblems(x: Any?, ax: String): List<String> {
        if (!isObj(x)) return problems("$ax: not an object")
        val p = ArrayList<String>()
        for (k in arrayOf("id", "title")) if (!isNonEmptyStr(get(x, k))) p.add("$ax.$k: required string")
        return p
    }

    private fun checkoutConstraintProblems(c: Any?, at: String): List<String> {
        if (!isObj(c) || !isStr(get(c, "type"))) return problems("$at: constraint must be an object with a string type")
        val m = Ap2Js.obj(c)
        val type = m["type"] as String
        if (type == "checkout.allowed_merchants") return listProblems(m["allowed"], "$at.allowed", ::merchantProblems)
        if (type == "checkout.line_items") {
            val items = m["items"]
            if (!isArr(items) || Ap2Js.arr(items).isEmpty()) return problems("$at.items: must be a non-empty array")
            val out = ArrayList<String>()
            val l = Ap2Js.arr(items)
            for (i in l.indices) {
                val it = l[i]
                val a = "$at.items[$i]"
                if (!isObj(it)) {
                    out.add("$a: not an object")
                    continue
                }
                if (!isNonEmptyStr(get(it, "id"))) out.add("$a.id: required string")
                if (!isInt(get(it, "quantity")) || Ap2Js.num(get(it, "quantity"))!! <= 0) out.add("$a.quantity: must be a positive integer")
                out.addAll(listProblems(get(it, "acceptable_items"), "$a.acceptable_items", ::acceptableItemProblems))
            }
            return out
        }
        return problems("$at: unknown constraint type $type")
    }

    private fun vctProblem(v: Map<String, Any?>, want: String): MutableList<String> =
        if (want == v["vct"]) ArrayList() else problems("vct: must be $want")

    private fun anyConstraintOfType(constraints: Any?, type: String): Boolean {
        for (c in Ap2Js.arr(constraints)) if (isObj(c) && type == get(c, "type")) return true
        return false
    }

    @JvmStatic
    fun openPaymentMandateProblems(v: Any?): List<String> {
        if (!isObj(v)) return problems("mandate: not an object")
        val m = Ap2Js.obj(v)
        val p = vctProblem(m, VCT_PAYMENT_OPEN)
        p.addAll(timeProblems(m))
        p.addAll(cnfProblems(m["cnf"]))
        p.addAll(pcaClaimProblems(m))
        p.addAll(listProblems(m["constraints"], "constraints", ::paymentConstraintProblems))
        if (isArr(m["constraints"]) && !anyConstraintOfType(m["constraints"], "payment.reference")) p.add("constraints: must contain a payment.reference constraint")
        if (m.containsKey("payee")) p.addAll(merchantProblems(m["payee"], "payee"))
        if (m.containsKey("payment_amount")) p.addAll(amountProblems(m["payment_amount"], "payment_amount"))
        if (m.containsKey("payment_instrument")) p.addAll(instrumentProblems(m["payment_instrument"], "payment_instrument"))
        if (m.containsKey("pisp")) p.addAll(pispProblems(m["pisp"], "pisp"))
        if (m.containsKey("execution_date") && !isStr(m["execution_date"])) p.add("execution_date: must be a string")
        if (m.containsKey("risk_data") && !isObj(m["risk_data"])) p.add("risk_data: must be an object")
        return p
    }

    @JvmStatic
    fun paymentMandateProblems(v: Any?): List<String> {
        if (!isObj(v)) return problems("mandate: not an object")
        val m = Ap2Js.obj(v)
        val p = vctProblem(m, VCT_PAYMENT)
        p.addAll(timeProblems(m))
        p.addAll(pcaClaimProblems(m))
        if (!isNonEmptyStr(m["transaction_id"])) p.add("transaction_id: required string")
        p.addAll(merchantProblems(m["payee"], "payee"))
        p.addAll(amountProblems(m["payment_amount"], "payment_amount"))
        p.addAll(instrumentProblems(m["payment_instrument"], "payment_instrument"))
        if (m.containsKey("pisp")) p.addAll(pispProblems(m["pisp"], "pisp"))
        if (m.containsKey("execution_date") && !isStr(m["execution_date"])) p.add("execution_date: must be a string")
        if (m.containsKey("risk_data") && !isObj(m["risk_data"])) p.add("risk_data: must be an object")
        return p
    }

    @JvmStatic
    fun openCheckoutMandateProblems(v: Any?): List<String> {
        if (!isObj(v)) return problems("mandate: not an object")
        val m = Ap2Js.obj(v)
        val p = vctProblem(m, VCT_CHECKOUT_OPEN)
        p.addAll(timeProblems(m))
        p.addAll(cnfProblems(m["cnf"]))
        p.addAll(pcaClaimProblems(m))
        p.addAll(listProblems(m["constraints"], "constraints", ::checkoutConstraintProblems))
        if (isArr(m["constraints"]) && !anyConstraintOfType(m["constraints"], "checkout.line_items")) p.add("constraints: must contain a checkout.line_items constraint")
        return p
    }

    @JvmStatic
    fun checkoutMandateProblems(v: Any?): List<String> {
        if (!isObj(v)) return problems("mandate: not an object")
        val m = Ap2Js.obj(v)
        val p = vctProblem(m, VCT_CHECKOUT)
        p.addAll(timeProblems(m))
        p.addAll(pcaClaimProblems(m))
        if (!isNonEmptyStr(m["checkout_jwt"])) p.add("checkout_jwt: required string")
        if (!isNonEmptyStr(m["checkout_hash"])) p.add("checkout_hash: required string")
        return p
    }

    /** Returns [v] when `problems(v)` is empty, else throws [Ap2Error] listing them. */
    @JvmStatic
    fun assertValid(v: Any?, problems: (Any?) -> List<String>, what: String): Any? {
        val p = problems(v)
        if (p.isNotEmpty()) throw Ap2Error(what + ": " + p.joinToString("; "))
        return v
    }
}
