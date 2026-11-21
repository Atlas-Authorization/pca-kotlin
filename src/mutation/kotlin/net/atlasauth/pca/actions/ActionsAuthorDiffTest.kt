package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the action authoring forms (shorthands, expansion, loader, typed builders). */
@Suppress("UNCHECKED_CAST")
class ActionsAuthorDiffTest {
    private val M = "ref-actions-author"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun lng(o: Any?): Long? = if (o == null) null else (o as Json.Num).raw.toLong()
    private fun strs(o: Any?): List<String> = (o as List<Any?>).map { it as String }
    private fun xs(a: List<Any?>, i: Int): Map<String, Any?>? = if (i < a.size && a[i] != null) m(a[i]) else null

    @Test fun paramShorthand() = OracleCases.each(M, "parseParamShorthand") { a -> ActionAuthor.parseParamShorthand(a[0] as String) }
    @Test fun resourceShorthand() = OracleCases.each(M, "parseResourceShorthand") { a -> ActionAuthor.parseResourceShorthand(a[0] as String) }
    @Test fun defaultTitle() = OracleCases.each(M, "defaultTitle") { a -> ActionAuthor.defaultTitle(a[0] as String) }
    @Test fun expand() = OracleCases.each(M, "expandAction") { a -> ActionAuthor.expandAction(a[0], a[1] as String?) }
    @Test fun load() = OracleCases.each(M, "loadActionsValue") { a -> ActionAuthor.loadActionsValue(a[0]) }
    @Test fun action() = OracleCases.each(M, "action") { a -> ActionAuthor.action(a[0] as String, m(a[1])) }

    @Test fun builder() = OracleCases.each(M, "builder") { a ->
        when (a[0] as String) {
            "email" -> ActionAuthor.P.email(xs(a, 1))
            "phone" -> ActionAuthor.P.phone(xs(a, 1))
            "url" -> ActionAuthor.P.url(xs(a, 1))
            "uuid" -> ActionAuthor.P.uuid(xs(a, 1))
            "ccy" -> ActionAuthor.P.ccy(xs(a, 1))
            "country" -> ActionAuthor.P.country(xs(a, 1))
            "secret" -> ActionAuthor.P.secret(xs(a, 1))
            "bool" -> ActionAuthor.P.bool(xs(a, 1))
            "date" -> ActionAuthor.P.date(xs(a, 1))
            "datetime" -> ActionAuthor.P.datetime(xs(a, 1))
            "duration" -> ActionAuthor.P.duration(lng(a[1]), xs(a, 2))
            "message" -> ActionAuthor.P.message(lng(a[1]), xs(a, 2))
            "text" -> ActionAuthor.P.text(lng(a[1]), xs(a, 2))
            "int" -> ActionAuthor.P.intRange(lng(a[1]), lng(a[2]), xs(a, 3))
            "count" -> ActionAuthor.P.count(lng(a[1]), xs(a, 2))
            "money" -> ActionAuthor.P.money(a[1], if (a[2] == null) null else m(a[2]), xs(a, 3))
            "id" -> ActionAuthor.P.id(a[1] as String, xs(a, 2))
            "enum" -> ActionAuthor.P.enumOf(strs(a[1]), xs(a, 2))
            "set" -> ActionAuthor.P.setOf(strs(a[1]), xs(a, 2))
            "array" -> ActionAuthor.P.array(a[1] as String, lng(a[2]), xs(a, 3))
            "optional" -> ActionAuthor.P.optional(m(a[1]))
            else -> throw IllegalArgumentException("unknown builder " + a[0])
        }
    }
}
