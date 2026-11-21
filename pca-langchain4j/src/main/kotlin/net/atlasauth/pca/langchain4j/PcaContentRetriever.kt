package net.atlasauth.pca.langchain4j

import dev.langchain4j.rag.content.Content
import dev.langchain4j.rag.content.retriever.ContentRetriever
import dev.langchain4j.rag.query.Query
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.rag.Rag

/**
 * PCA-scoped RAG: a [ContentRetriever] whose results are filtered to what the principal may see BEFORE they reach the model (fail closed;
 * see [Rag]). LangChain4j metadata holds scalars only, so by default the ACL is read from the segment metadata keys `acl` and
 * `tags`: `relation:object` strings, comma separated (the split at the first colon, so an object id may contain colons). The id is
 * metadata `id`, else `source`, else positional. Pass [getAcls] / [getId] for another layout.
 */
class PcaContentRetriever @JvmOverloads constructor(
    private val delegate: ContentRetriever,
    private val principal: Any?,
    policy: Any?,
    private val prover: Prover? = null,
    private val getAcls: (Content) -> Any? = PcaContentRetriever.Companion::defaultAcls,
    private val getId: (Content) -> String? = PcaContentRetriever.Companion::defaultId,
) : ContentRetriever {
    private val compiled: Map<String, Any?> = Rag.compilePolicy(policy)

    @Volatile private var last: Map<String, Any?>? = null

    override fun retrieve(query: Query): List<Content> {
        val found: List<Content> = delegate.retrieve(query) ?: emptyList()
        val r = Rag.filter(principal, found, compiled, { c, _ -> getId(c) }, getAcls)
        last = r.decision
        if (prover != null) for (c in r.documents) prover.retrieval(getId(c).toString(), c.textSegment().text())
        return r.documents
    }

    /** The decision of the most recent retrieval (the proof trace), or null. */
    fun lastDecision(): Map<String, Any?>? = last

    companion object {
        @JvmStatic
        fun defaultAcls(c: Content): Any? {
            val m = c.textSegment().metadata()
            val tags = ArrayList<Any?>()
            for (key in listOf("acl", "tags")) {
                val v = m.getString(key) ?: continue
                for (t in v.split(",")) tags.add(t.trim())
            }
            return Rag.aclsFromMetadata(null, tags)
        }

        @JvmStatic
        fun defaultId(c: Content): String? {
            val m = c.textSegment().metadata()
            return m.getString("id") ?: m.getString("source")
        }
    }
}
