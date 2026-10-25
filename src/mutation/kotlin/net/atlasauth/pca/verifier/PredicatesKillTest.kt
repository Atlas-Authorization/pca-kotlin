package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mutation kills for the predicate evaluator (`layers` ceilings) and the linear-time regex engine and guard. */
class PredicatesKillTest {
    private fun jm(vararg kv: Any?): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); var i = 0; while (i < kv.size) { r[kv[i] as String] = kv[i + 1]; i += 2 }; return r }
    private fun jl(vararg xs: Any?): ArrayList<Any?> = ArrayList(xs.toList())
    private fun n(s: String) = Json.Num(s)

    private fun ctx(): LinkedHashMap<String, Any?> = jm(
        "action", jm("verb", "air.book", "resource", "skyair.example/bookings/7", "params",
            jm("total", n("38900"), "name", "Ana", "tags", jl("a", "b"), "nested", jm("x", n("1")), "astral", "😀")),
        "env", jm("canon", jm("add_ons", "[\"none\"]"), "groups", jm("ana", "staff", "staff", jl("emp")), "cur", "dev1"),
    )
    private fun leaf(field: String, op: String, value: Any?) = Predicates.evaluateConditionTri(jm("field", field, "op", op, "value", value), ctx())
    private val T = Predicates.Tri.TRUE
    private val F = Predicates.Tri.FALSE
    private val U = Predicates.Tri.UNKNOWN

    @Test fun comparisons() {
        assertEquals(T, leaf("action.params.total", "eq", n("38900")))
        assertEquals(T, leaf("action.params.total", "eq", n("38900.0")))
        assertEquals(F, leaf("action.params.total", "eq", "38900"))
        assertEquals(T, leaf("action.params.total", "ne", "38900"))
        assertEquals(T, leaf("action.params.total", "lte", n("38900")))
        assertEquals(F, leaf("action.params.total", "lt", n("38900")))
        assertEquals(T, leaf("action.params.total", "gte", n("38900")))
        assertEquals(F, leaf("action.params.total", "gt", n("38900")))
        assertEquals(U, leaf("action.params.total", "lt", "x"))
        assertEquals(T, leaf("action.params.name", "lt", "Bob"))
        // UTF-8 byte order: U+1F600 sorts after U+FFFF (UTF-16 order would put it before)
        assertEquals(T, leaf("action.params.astral", "gt", "￿"))
        assertEquals(T, leaf("action.params.tags", "eq", jl("a", "b")))
        assertEquals(F, leaf("action.params.tags", "eq", jl("b", "a")))
        assertEquals(T, leaf("action.params.nested", "eq", jm("x", n("1.0"))))
        assertEquals(T, leaf("action.params.name", "in", jl("x", "Ana")))
        assertEquals(F, leaf("action.params.name", "nin", jl("x", "Ana")))
        assertEquals(U, leaf("action.params.name", "in", "Ana"))
        assertEquals(T, leaf("action.params.name", "prefix", "An"))
        assertEquals(U, leaf("action.params.total", "prefix", "3"))
        assertEquals(U, leaf("action.params.name", "nope", "x"))
        assertEquals(T, leaf("env.canon.add_ons", "eq", "[\"none\"]"))
    }

    @Test fun existsRefsAndParams() {
        assertEquals(T, leaf("action.params.name", "exists", true))
        assertEquals(F, leaf("action.params.missing", "exists", true))
        assertEquals(T, leaf("action.params.missing", "exists", false))
        assertEquals(U, leaf("action.params.missing", "eq", "x"))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "exists"), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "eq"), ctx()))
        assertEquals(F, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "eq", "ref", "env.cur"), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "eq", "ref", "env.none"), ctx()))
        val noParams = jm("action", jm("verb", "v", "resource", "r"))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.x", "op", "exists", "value", false), noParams))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "action.verb", "op", "eq", "value", "v"), noParams))
        assertEquals(F, leaf("action.params.__proto__", "exists", true))
        assertEquals(T, leaf("action.params.tags.1", "eq", "b"))
        assertEquals(U, leaf("action.params.tags.2", "eq", "b"))
        assertEquals(U, leaf("action.params.tags.01", "eq", "b"))
        assertFalse(Predicates.resolvePath(ctx(), "subject.x").found)
        assertFalse(Predicates.resolvePath(ctx(), "other.x").found)
        assertFalse(Predicates.resolvePath(ctx(), "").found)
    }

    @Test fun groups() {
        val t = jm("field", "action.verb", "op", "eq", "value", "air.book")
        val f = jm("field", "action.verb", "op", "eq", "value", "x")
        val u = jm("field", "action.params.zz", "op", "eq", "value", "x")
        assertEquals(T, Predicates.evaluateConditionTri(jm("all_of", jl(t, t)), ctx()))
        assertEquals(F, Predicates.evaluateConditionTri(jm("all_of", jl(u, f)), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("all_of", jl(t, u)), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("all_of", jl()), ctx()))
        assertEquals(T, Predicates.evaluateConditionTri(jm("any_of", jl(u, t)), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("any_of", jl(u, f)), ctx()))
        assertEquals(F, Predicates.evaluateConditionTri(jm("any_of", jl(f, f)), ctx()))
        assertEquals(F, Predicates.evaluateConditionTri(jm("not", t), ctx()))
        assertEquals(T, Predicates.evaluateConditionTri(jm("not", f), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("not", u), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jl(t), ctx()))
        assertEquals(F, Predicates.evaluateConditionTri(jm("all_of", jl(f), "any_of", jl(t)), ctx()))
    }

    @Test fun likeIsATypeAndMembership() {
        assertEquals(T, leaf("action.params.name", "like", "A*"))
        assertEquals(T, leaf("action.params.name", "like", "A?a"))
        assertEquals(F, leaf("action.params.name", "like", "A?"))
        assertEquals(T, leaf("action.params.name", "like", "*n*"))
        assertEquals(T, leaf("action.params.name", "like", "A\\na"))
        assertEquals(U, leaf("action.params.name", "like", "A\\"))
        assertEquals(U, leaf("action.params.name", "like", "x".repeat(513)))
        assertEquals(T, leaf("action.params.name", "like", "*".repeat(512)))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "is_a", "value", "Ana"), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.total", "op", "is_a", "value", "x"), ctx()))
        val c = ctx()
        @Suppress("UNCHECKED_CAST")
        (c["env"] as MutableMap<String, Any?>)["obj"] = jm("type", "Doc::pdf", "tags", jl("x"))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "env.obj", "op", "is_a", "value", "Doc"), c))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "env.obj", "op", "is_a", "value", "x"), c))
        assertEquals(F, Predicates.evaluateConditionTri(jm("field", "env.obj", "op", "is_a", "value", "Do"), c))
        assertEquals(T, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "member_of", "value", "emp", "collection", "env.groups"),
            jm("action", jm("verb", "v", "resource", "r", "params", jm("name", "ana")), "env", jm("groups", jm("ana", "staff", "staff", jl("emp"))))))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "member_of", "value", "emp"), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "member_of", "value", jl(), "collection", "env.groups"), ctx()))
    }

    @Test fun predicatesAndResources() {
        val c = ctx()
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "air.book")), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*")), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", jl("x", "air.book"))), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "x")), c))
        assertFalse(Predicates.evaluatePredicates(jl(), c))
        assertFalse(Predicates.evaluatePredicates(jm("verb", "*"), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "skyair.example/*")), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "skyair.example/x*")), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "skyair.example/bookings/7")), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", null)), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "re:skyair\\.example/bookings/\\d+")), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "re:skyair")), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "resource", "re:(a+)+")), c))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "where", "x")), c))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "x"), jm("verb", "air.book", "where", jl())), c))
    }

    @Test fun regexGuard() {
        assertTrue(SafeRegex.isSafeSource("/acct/[^/]+/items/\\d+"))
        assertTrue(SafeRegex.isSafeSource("(?:GET|POST) /x"))
        assertFalse(SafeRegex.isSafeSource("(a+)+"))
        assertFalse(SafeRegex.isSafeSource("(a|aa)+"))
        assertFalse(SafeRegex.isSafeSource("(a)\\1"))
        assertFalse(SafeRegex.isSafeSource("(?=a)"))
        assertFalse(SafeRegex.isSafeSource("a{65}"))
        assertTrue(SafeRegex.isSafeSource("a{64}"))
        assertFalse(SafeRegex.isSafeSource("a{2,1}"))
        assertFalse(SafeRegex.isSafeSource("a{"))
        assertFalse(SafeRegex.isSafeSource("*a"))
        assertFalse(SafeRegex.isSafeSource("a**"))
        assertTrue(SafeRegex.isSafeSource("a*b*"))
        assertFalse(SafeRegex.isSafeSource("a*b*c*"))
        assertFalse(SafeRegex.isSafeSource("[^](a+)+]"))
        assertTrue(SafeRegex.isSafeSource("a?".repeat(22)))
        assertFalse(SafeRegex.isSafeSource("a?".repeat(23)))
        assertEquals(6, SafeRegex.ceilLog2(64))
        assertEquals(7, SafeRegex.ceilLog2(65))
        assertEquals(1, SafeRegex.ceilLog2(2))
        assertEquals(2, SafeRegex.ceilLog2(3))
        assertFalse(SafeRegex.isSafeSource("(a"))
        assertFalse(SafeRegex.isSafeSource("a)"))
        assertFalse(SafeRegex.isSafeSource("[a"))
        assertFalse(SafeRegex.isSafeSource("\\"))
        assertFalse(SafeRegex.isSafeSource("\\b"))
        assertFalse(SafeRegex.isSafeSource("\\q"))
    }

    @Test fun regexEngine() {
        assertEquals(true, SafeRegex.fullMatch("a|b", "b"))
        assertEquals(false, SafeRegex.fullMatch("a|b", "ab"))
        assertEquals(true, SafeRegex.fullMatch("[]|x", "x"))
        assertEquals(false, SafeRegex.fullMatch("[]", ""))
        assertEquals(true, SafeRegex.fullMatch("[^]", "\n"))
        assertEquals(false, SafeRegex.fullMatch(".", "\n"))
        assertEquals(true, SafeRegex.fullMatch(".", "\u0085"))
        assertEquals(true, SafeRegex.fullMatch("\\d{2,3}", "123"))
        assertEquals(false, SafeRegex.fullMatch("\\d{2,3}", "1234"))
        assertEquals(true, SafeRegex.fullMatch("[\\w-]+", "a-b_9"))
        assertEquals(true, SafeRegex.fullMatch("[a\\-z]+", "-az"))
        assertEquals(false, SafeRegex.fullMatch("[a-c]", "d"))
        assertNull(SafeRegex.fullMatch("[c-a]", "b"))
        assertEquals(true, SafeRegex.fullMatch("\\x41\\u0042\\cJ", "AB\n"))
        assertEquals(true, SafeRegex.fullMatch("[\\b]", "\b"))
        assertNull(SafeRegex.fullMatch("\\01", "x"))
        assertEquals(true, SafeRegex.fullMatch("\\0", "\u0000"))
        assertEquals(true, SafeRegex.fullMatch("^a$", "a"))
        assertNull(SafeRegex.fullMatch("^*", "a"))
        assertEquals(true, SafeRegex.fullMatch("a{0}b", "b"))
        assertEquals(true, SafeRegex.fullMatch("a+?", "aaa"))
        assertEquals(true, SafeRegex.fullMatch("\\s", "　"))
        assertEquals(false, SafeRegex.fullMatch("\\S", "　"))
        assertEquals(true, SafeRegex.fullMatch("\\.", "."))
        assertEquals(true, SafeRegex.fullMatch("..", "😀"))
        val c = SafeRegex.compile("a*")!!
        val n = (SafeRegex.MAX_MATCH_STEPS / c.size()).toInt()
        assertNotNull(SafeRegex.run(c, "a".repeat(n - 1)))
        assertNull(SafeRegex.run(c, "a".repeat(n)))
    }

    @Test fun documentBudget() {
        val where = ArrayList<Any?>()
        repeat(64) { where.add(jm("field", "action.params.name", "op", "matches", "value", "A.a")) }
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*", "where", where)), ctx()))
        where.add(jm("field", "action.params.name", "op", "matches", "value", "A.a"))
        assertFalse(Predicates.evaluatePredicates(jl(jm("verb", "*", "where", where)), ctx()))
        assertTrue(Predicates.evaluatePredicates(jl(jm("verb", "*", "where", jl(jm("field", "action.params.name", "op", "matches", "value", "A.a")))), ctx()))
        assertEquals(U, Predicates.evaluateConditionTri(jm("field", "action.params.name", "op", "matches", "value", "x".repeat(201)), ctx()))
    }
}
