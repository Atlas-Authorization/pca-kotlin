package net.atlasauth.pca.oauth

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the OAuth / MCP-authorization bridge through the native port. */
class OauthDiffTest {
    private val m = "ref-oauth"

    @Suppress("UNCHECKED_CAST")
    private fun mm(o: Any?) = o as Map<String, Any?>
    private fun opt(a: List<Any?>, i: Int) = if (a.size > i) a[i] as Map<String, Any?>? else null

    @Test fun resourceIdentifierProblem() = OracleCases.each(m, "resourceIdentifierProblem") { Oauth.resourceIdentifierProblem(it[0]) }
    @Test fun prmPathForResource() = OracleCases.each(m, "prmPathForResource") { Oauth.prmPathForResource(it[0] as String) }
    @Test fun prmUrlForResource() = OracleCases.each(m, "prmUrlForResource") { Oauth.prmUrlForResource(it[0] as String) }
    @Test fun protectedResourceMetadata() = OracleCases.each(m, "protectedResourceMetadata") { Oauth.protectedResourceMetadata(mm(it[0])) }
    @Test fun oauthDiscoveryHandler() = OracleCases.each(m, "oauthDiscoveryHandler") { Oauth.oauthDiscoveryHandler(mm(it[0])) }
    @Test fun parseProtectedResourceMetadata() = OracleCases.each(m, "parseProtectedResourceMetadata") { Oauth.parseProtectedResourceMetadata(it[0], opt(it, 1)) }
    @Test fun wwwAuthenticate() = OracleCases.each(m, "wwwAuthenticate") { Oauth.wwwAuthenticate(it[0] as String?, opt(it, 1)) }
    @Test fun mcpUnauthorized() = OracleCases.each(m, "mcpUnauthorized") { Oauth.mcpUnauthorized(it[0] as String?, opt(it, 1)) }
    @Test fun upgradeUnauthorizedChallenge() = OracleCases.each(m, "upgradeUnauthorizedChallenge") { Oauth.upgradeUnauthorizedChallenge(mm(it[0]), it[1] as String?, opt(it, 2)) }
    @Test fun checkResourceIndicator() = OracleCases.each(m, "checkResourceIndicator") { Oauth.checkResourceIndicator(it[0], it[1] as String?) }
    @Test fun checkTokenAudience() = OracleCases.each(m, "checkTokenAudience") { Oauth.checkTokenAudience(it[0], it[1] as String?) }
    @Test fun buildPcaGrantDetail() = OracleCases.each(m, "buildPcaGrantDetail") { Oauth.buildPcaGrantDetail(mm(it[0])) }
    @Suppress("UNCHECKED_CAST")
    @Test fun pcaGrantRequestParam() = OracleCases.each(m, "pcaGrantRequestParam") { Oauth.pcaGrantRequestParam(it[0] as List<Any?>) }
    @Test fun authorizePcaGrantToken() = OracleCases.each(m, "authorizePcaGrantToken") { Oauth.authorizePcaGrantToken(mm(it[0])) }
    @Test fun oauthScopeForAction() = OracleCases.each(m, "oauthScopeForAction") { Oauth.oauthScopeForAction(it[0], mm(it[1])) }
}
