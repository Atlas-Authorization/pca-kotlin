package net.atlasauth.pca.jose

import com.ibm.icu.text.IDNA

/**
 * `domainToASCII` of the WHATWG URL standard: UTS 46 ToASCII with CheckBidi and CheckJoiners on, non-transitional processing, STD3 rules off,
 * and neither hyphen nor DNS-length checks (`beStrict` false). ICU4J implements UTS 46 (java.net.IDN is IDNA 2003 and maps differently).
 */
object Uts46 {
    /** The errors a lenient WHATWG host parse does not raise: label shape and length checks. */
    private val LENIENT = setOf(
        IDNA.Error.EMPTY_LABEL, IDNA.Error.LABEL_TOO_LONG, IDNA.Error.DOMAIN_NAME_TOO_LONG,
        IDNA.Error.LEADING_HYPHEN, IDNA.Error.TRAILING_HYPHEN, IDNA.Error.HYPHEN_3_4,
    )

    private val idna: IDNA by lazy { IDNA.getUTS46Instance(IDNA.CHECK_BIDI or IDNA.CHECK_CONTEXTJ or IDNA.NONTRANSITIONAL_TO_ASCII) }

    /** True when [domain] needs UTS 46: a non-ASCII character. A pure-ASCII host is only lower-cased (the reference does not validate its `xn--` labels). */
    fun needed(domain: String): Boolean = domain.any { it.code > 0x7f }

    /** The ASCII form of [domain], or null when UTS 46 refuses it (a disallowed character, bad punycode, a Bidi or joiner violation). */
    fun toAscii(domain: String): String? {
        val out = StringBuilder()
        val info = IDNA.Info()
        idna.nameToASCII(domain, out, info)
        if (info.errors.any { it !in LENIENT }) return null
        return out.toString()
    }
}
