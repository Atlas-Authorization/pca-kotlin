package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `val c = r["class"]; if (c !is String || c !in EVOLUTION_CLASSES) return "bad class"`: the ledger's proof that the `c !is String` test is
 * redundant says the membership test needs no String cast. This pins what the proof relies on: a class that is not a string (a number, null,
 * a list that CONTAINS a valid class name, a boxed Long) is refused with the same message, and never throws.
 */
class Kill12RegistryClassTypeTest {
    private fun rec(cls: Any?): Map<String, Any?> = linkedMapOf(
        "v" to Json.Num("1"), "kind" to "pca-evolution-record", "ns" to "a", "verb" to "a.b", "from" to null, "to" to null, "class" to cls,
        "reasons" to ArrayList<Any?>(),
    )

    @Test fun aNonStringClassIsRefusedWithoutAnException() {
        for (c in listOf<Any?>(Json.Num("5"), null, 7L, ArrayList<Any?>(listOf("equal")), linkedMapOf<String, Any?>("equal" to true)))
            assertEquals("class=$c", "evolution record: bad class", ActionsRegistry.evolutionRecordError(rec(c), false))
        assertEquals("evolution record: bad class", ActionsRegistry.evolutionRecordError(rec("nope"), false))
    }
}
