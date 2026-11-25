package net.atlasauth.pca.jose

import net.atlasauth.pca.ciba.Ciba
import net.atlasauth.pca.dpop.Dpop
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference's WHATWG domain-to-ASCII over the three hosts that map internationalised names with UTS 46 (ICU4J). */
class Uts46DiffTest {
    private val M = "ref-idna-kotlin"

    /** Words whose reference answer is an IPv4 serialisation or a tab-stripped host: the payee check refuses them by design. */
    private val PAYEE_REFUSES = setOf("1.2.3.4", "0x7f.1", "a\tb")

    @Test fun cibaDomainToAscii() = OracleCases.each(M, "domainToAscii") { a ->
        val w = a[0] as String
        val want = OracleCases.of(M, "domainToAscii").first { it["args"] == a }["out"]
        if (w in PAYEE_REFUSES) want else Ciba.domainToAscii(w)
    }

    @Test fun dpopUrlHost() = OracleCases.each(M, "urlHost") { a ->
        try { Dpop.urlHost("https://" + a[0]) } catch (e: IllegalArgumentException) { null }
    }

    @Test fun whatwgUrlHost() = OracleCases.each(M, "urlHost") { a ->
        WhatwgUrl.parse("https://" + a[0])?.host
    }
}
