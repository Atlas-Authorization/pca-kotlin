package net.atlasauth.pca.rag

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the reference vectors of the retrieval filter through the native port. */
@Suppress("UNCHECKED_CAST")
class RagDiffTest {
    private val M = "ref-rag"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun aclsFromMetadata() = OracleCases.each(M, "aclsFromMetadata") { a -> Rag.aclsFromMetadata(a[0], a[1]) }
    @Test fun compilePolicy() = OracleCases.each(M, "compilePolicy") { a -> Rag.compilePolicy(a[0]) }
    @Test fun principalFromPCActn() = OracleCases.each(M, "principalFromPCActn") { a -> Rag.principalFromPCActn(a[0], a[1] as Map<String, Any?>?) }

    @Test fun filterDocuments() = OracleCases.each(M, "filterDocuments") { a ->
        val r = Rag.filterDocuments(a[0], if (a[1] is List<*>) l(a[1]) else null, a[2])
        linkedMapOf("documents" to r.documents, "decision" to r.decision)
    }

    @Test fun adminGroupClosureAdmitsAndOthersDrop() {
        val pred = mapOf("verb" to "can_view", "where" to listOf(mapOf("field" to "subject.group", "op" to "eq", "value" to "g1")))
        val doc = mapOf("id" to "d", "acl" to mapOf("relation" to "can_view", "object" to "document:d"))
        val ok = mapOf("id" to "u", "attributes" to mapOf("group" to "g1"))
        assertEquals(listOf("d"), Rag.filterDocuments(ok, listOf(doc), listOf(pred)).decision["allowedIds"])
        assertEquals(listOf("d"), Rag.filterDocuments(mapOf("id" to "u", "attributes" to mapOf("group" to "g2")), listOf(doc), listOf(pred)).decision["droppedIds"])
    }
}
