package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the intent ontology: verb resolution, IR projection, checker, template instantiation, slot typing, amounts. */
@Suppress("UNCHECKED_CAST")
class GoalOntologyDiffTest {
    private val M = "ref-goal-ontology"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    private fun l(o: Any?): List<Any?> = o as List<Any?>

    /** A shipped ontology travels by name; the hand-written one inline. */
    private fun ont(o: Any?): Map<String, Any?> = if (o is String) GoalOntologies.ontology(o)!! else m(o)!!

    private fun i(o: Any?): Int = (if (o is Json.Num) o.raw else o.toString()).toDouble().toInt()

    @Test fun shippedOntology() = OracleCases.each(M, "shippedOntology") { a -> GoalOntologies.ontology(a[0] as String) }

    @Test fun shippedCatalog() = OracleCases.each(M, "shippedCatalog") { a -> GoalOntologies.selCatalog(a[0] as String) }

    @Test fun ontologyDigest() = OracleCases.each(M, "ontologyDigest") { a -> GoalOntology.ontologyDigest(ont(a[0])) }

    @Test fun resolveVerb() = OracleCases.each(M, "resolveVerb") { a -> GoalOntology.resolveVerb(ont(a[0]), a[1] as String) }

    @Test fun goalCcy() = OracleCases.each(M, "goalCcy") { a -> GoalOntology.goalCcy(m(a[0])!!) }

    @Test fun goalAnchors() = OracleCases.each(M, "goalAnchors") { a -> GoalOntology.goalAnchors(m(a[0])!!) }

    @Test fun toIrOntology() = OracleCases.each(M, "toIrOntology") { a ->
        val opts = m(a[1])
        GoalOntology.toIrOntology(ont(a[0]), if (opts == null) null else opts["ccy"] as String?, if (opts == null) null else opts["rels"] as List<Any?>?)
    }

    @Test fun ontologyForGoal() = OracleCases.each(M, "ontologyForGoal") { a ->
        GoalOntology.ontologyForGoal(ont(a[0]), m(a[1])!!, if (a.size > 2 && a[2] != null) l(a[2]) else null)
    }

    @Test fun checkOntology() = OracleCases.each(M, "checkOntology") { a -> GoalOntology.checkOntology(ont(a[0])) }

    @Test fun instantiateTemplate() = OracleCases.each(M, "instantiateTemplate") { a ->
        val opts = m(a[3])!!
        var src: List<String>? = null
        if (opts["sources"] != null) src = l(opts["sources"]).map { it as String }
        GoalOntology.instantiateTemplate(ont(a[0]), a[1] as String, m(a[2]), opts["principal"] as String, opts["nl"] as String, src)
    }

    @Test fun slotLits() = OracleCases.each(M, "slotLits") { a -> GoalOntology.slotLits(ont(a[0]), m(a[1])!!, a[2]) }

    @Test fun parseHumanAmount() = OracleCases.each(M, "parseHumanAmount") { a -> GoalOntology.parseHumanAmount(a[0] as String, i(a[1]), a[2] as String?) }

    @Test fun parseMoney() = OracleCases.each(M, "parseMoney") { a -> GoalOntology.parseMoney(a[0] as String, i(a[1]), a[2] as String?) }
}
