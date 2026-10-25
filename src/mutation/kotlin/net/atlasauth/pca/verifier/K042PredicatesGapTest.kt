package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Exhaustive / boundary kills for Predicates internals (glob matching, path resolution, ref handling, budget) not reached by the TS corpus. */
@Suppress("UNCHECKED_CAST")
class K042PredicatesGapTest {
    /** Reference glob matcher: ? = one unit, * = any run, backslash escapes the next unit; null on a dangling backslash. */
    private fun ref(glob: String, s: String): Boolean? {
        val t = ArrayList<Pair<Char, Char>>()
        var i = 0
        while (i < glob.length) {
            val c = glob[i]
            when (c) {
                '\\' -> { if (i + 1 >= glob.length) return null; t.add('L' to glob[++i]) }
                '*' -> t.add('*' to ' ')
                '?' -> t.add('?' to ' ')
                else -> t.add('L' to c)
            }
            i++
        }
        val m = Array(t.size + 1) { BooleanArray(s.length + 1) }
        m[0][0] = true
        for (a in 1..t.size) {
            val k = t[a - 1]
            for (j in 0..s.length) {
                if (k.first == '*') m[a][j] = m[a - 1][j] || (j > 0 && m[a][j - 1])
                else if (j > 0 && (k.first == '?' || k.second == s[j - 1])) m[a][j] = m[a - 1][j - 1]
            }
        }
        return m[t.size][s.length]
    }

    private fun words(alpha: String, max: Int): List<String> {
        val out = ArrayList<String>(); out.add("")
        var prev = listOf("")
        for (n in 1..max) { val next = prev.flatMap { p -> alpha.map { p + it } }; out.addAll(next); prev = next }
        return out
    }

    @Test fun globMatchesTheReferenceExhaustively() {
        val pats = words("a\u0002*?\\", 4); val subs = words("a\u0002*?\\b", 4)
        var bad = 0; val sb = StringBuilder()
        for (p in pats) for (s in subs) {
            val want = ref(p, s); val got = Predicates.globMatch(p, s)
            if (want != got && bad++ < 20) sb.append(p.replace("\u0002", "^B")).append(" ~ ").append(s.replace("\u0002", "^B")).append(": want $want got $got\n")
        }
        assertEquals(sb.toString(), 0, bad)
    }

    @Test fun globStarRunsAndEscapes() {
        assertEquals(true, Predicates.globMatch("a**b", "axxb")); assertEquals(true, Predicates.globMatch("**", ""))
        assertEquals(true, Predicates.globMatch("*a*b*", "xxaxxbxx")); assertEquals(false, Predicates.globMatch("*a*b*", "xxbxxaxx"))
        assertEquals(true, Predicates.globMatch("\\*", "*")); assertEquals(false, Predicates.globMatch("\\*", "x"))
        assertEquals(true, Predicates.globMatch("\\?", "?")); assertEquals(false, Predicates.globMatch("\\?", "x"))
        assertEquals(true, Predicates.globMatch("\\\\", "\\")); assertNull(Predicates.globMatch("a\\", "a"))
        assertEquals(true, Predicates.globMatch("\u0002*", "\u0002abc")); assertEquals(false, Predicates.globMatch("\u0002", "x"))
        assertEquals(true, Predicates.globMatch("?*?", "ab")); assertEquals(false, Predicates.globMatch("?*?", "a"))
        assertEquals(true, Predicates.globMatch("a*", "a")); assertEquals(true, Predicates.globMatch("*a", "bba")); assertEquals(false, Predicates.globMatch("*a", "bbab"))
    }

    @Test fun resolvePathRejectsWhatIsNotAPathOrARoot() {
        val ctx = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to "v"), "other" to "x", "" to "empty")
        for (p in listOf(null, Json.Num("5"), listOf("action"), mapOf<String, Any?>(), true, "")) assertFalse(p.toString(), Predicates.resolvePath(ctx, p).found)
        assertFalse(Predicates.resolvePath(ctx, "other").found); assertFalse(Predicates.resolvePath(ctx, "other.x").found)
        assertFalse(Predicates.resolvePath(ctx, ".x").found); assertFalse(Predicates.resolvePath(ctx, "subject").found)
        assertFalse(Predicates.resolvePath(null, "action").found)
        assertTrue(Predicates.resolvePath(ctx, "action.verb").found); assertEquals("v", Predicates.resolvePath(ctx, "action.verb").value)
        assertFalse(Predicates.resolvePath(ctx, "action.verb.x").found); assertFalse(Predicates.resolvePath(ctx, "action..verb").found)
    }

    private val T = Predicates.Tri.TRUE; private val F = Predicates.Tri.FALSE; private val U = Predicates.Tri.UNKNOWN
    private fun ctx(json: String) = Json.parseLenient(json) as Map<String, Any?>
    private fun tri(cond: String, ctx: String) = Predicates.evaluateConditionTri(Json.parseLenient(cond), ctx(ctx))

    private val NOPARAMS = """{"action":{"verb":"v","resource":"r"},"subject":{"id":"s","name":"n"},"env":{}}"""
    private val PARAMS = """{"action":{"verb":"v","resource":"r","params":{"x":"s"}},"subject":{"id":"s","name":"n"},"env":{}}"""

    @Test fun refRootedAtUnavailableParamsIsUnknownBeforeAnyOp() {
        assertEquals(U, tri("""{"field":"subject.id","op":"exists","ref":"action.params.x"}""", NOPARAMS))
        assertEquals(U, tri("""{"field":"subject.id","op":"eq","ref":"action.params.x"}""", NOPARAMS))
        assertEquals(U, tri("""{"field":"subject.id","op":"exists","ref":"action.params"}""", NOPARAMS))
        assertEquals(T, tri("""{"field":"subject.id","op":"exists","ref":"subject.name"}""", NOPARAMS))
        assertEquals(F, tri("""{"field":"subject.id","op":"eq","ref":"subject.name"}""", NOPARAMS))
        assertEquals(T, tri("""{"field":"subject.id","op":"ne","ref":"subject.name"}""", NOPARAMS))
        assertEquals(T, tri("""{"field":"subject.id","op":"exists","ref":5}""", NOPARAMS))
        assertEquals(T, tri("""{"field":"subject.id","op":"eq","ref":"action.params.x"}""", PARAMS))
        assertEquals(T, tri("""{"field":"subject.id","op":"exists","ref":"action.params.x"}""", PARAMS))
        assertEquals(U, tri("""{"field":"action.params.x","op":"exists"}""", NOPARAMS))
        assertEquals(U, tri("""{"field":"action.params","op":"exists"}""", NOPARAMS))
        assertEquals(T, tri("""{"field":"action.paramsx","op":"exists","value":false}""", NOPARAMS))
        val q = """{"field":"action.params.0","op":"eq","value":"q"}"""
        assertEquals(T, tri(q, """{"action":{"verb":"v","resource":"r","params":["q"]}}"""))
        assertEquals(U, tri(q, """{"action":{"verb":"v","resource":"r","params":"q"}}"""))
        assertEquals(U, tri(q, """{"action":{"verb":"v","resource":"r","params":null}}"""))
        assertEquals(U, tri(q, """{"action":[1]}"""))
        assertEquals(U, tri(q, "{}"))
        assertEquals(U, Predicates.evaluateConditionTri(Json.parseLenient(q), null))
    }

    @Test fun emptyGroupsAndEmptyTypeTagsAreUnknown() {
        assertEquals(U, tri("""{"all_of":[]}""", PARAMS)); assertEquals(U, tri("""{"any_of":[]}""", PARAMS))
        assertEquals(U, tri("""{"all_of":{}}""", PARAMS)); assertEquals(U, tri("""{"any_of":"x"}""", PARAMS))
        assertEquals(U, tri("""{"field":"subject.name","op":"is_a","value":""}""", PARAMS))
        assertEquals(U, tri("""{"field":"subject.name","op":"is_a","value":5}""", PARAMS))
        assertEquals(T, tri("""{"field":"subject.name","op":"is_a","value":"n"}""", PARAMS))
        assertEquals(U, tri("""{"field":"subject.name","op":"member_of","collection":"","value":"n"}""", PARAMS))
        assertEquals(U, tri("""{"field":"subject.name","op":"member_of","collection":5,"value":"n"}""", PARAMS))
        assertEquals(U, tri("""{"field":"subject.name","op":"member_of","collection":"subject.id","value":"n"}""", PARAMS))
    }

    @Test fun memberClosureNeverFollowsPrototypeNames() {
        val c = """{"action":{"verb":"v","resource":"r"},"subject":{"id":"a","g":{"a":"__proto__","__proto__":"target","constructor":"t2","b":"constructor"}}}"""
        fun mo(v: String) = tri("""{"field":"subject.id","op":"member_of","collection":"subject.g","value":"$v"}""", c)
        assertEquals(T, mo("__proto__")); assertEquals(F, mo("target")); assertEquals(F, mo("t2")); assertEquals(F, mo("zzz"))
    }

    @Test fun predicateWithoutResourceOrWhere() {
        val cx = ctx(PARAMS)
        fun pm(p: String, c: Map<String, Any?>? = cx) = Predicates.predicateMatches(Json.parseLenient(p), c)
        assertTrue(pm("""{"verb":"v"}""")); assertTrue(pm("""{"verb":"v","resource":"*"}""")); assertTrue(pm("""{"verb":"v","resource":"r"}"""))
        assertTrue(pm("""{"verb":"v","resource":"r*"}"""))
        assertFalse(pm("""{"verb":"v","resource":null}""")); assertFalse(pm("""{"verb":"v","resource":5}""")); assertFalse(pm("""{"verb":"v","resource":"x"}"""))
        assertFalse(pm("""{"verb":"v","where":{}}""")); assertFalse(pm("""{"verb":"v","where":null}""")); assertFalse(pm("""{"verb":"x"}"""))
        assertFalse(pm("{}")); assertFalse(pm("[]")); assertFalse(pm("5")); assertFalse(Predicates.predicateMatches(null, cx))
        assertFalse(pm("""{"verb":"v"}""", null))
        assertFalse(pm("""{"verb":"v"}""", ctx("""{"action":5}""")))
        assertFalse(pm("""{"verb":"v"}""", ctx("""{"action":{"verb":5,"resource":"r"}}""")))
        assertFalse(pm("""{"verb":"v"}""", ctx("""{"action":{"verb":"v","resource":5}}""")))
        assertFalse(pm("""{"verb":"v"}""", ctx("""{"action":{"verb":"v"}}""")))
        assertTrue(pm("""{"verb":[null,5,"v"]}""")); assertTrue(pm("""{"verb":["x","*"]}""")); assertFalse(pm("""{"verb":[null,5]}"""))
        assertFalse(Predicates.evaluatePredicates(Json.parseLenient("[]"), cx)); assertFalse(Predicates.evaluatePredicates(Json.parseLenient("{}"), cx))
        assertFalse(Predicates.evaluatePredicates(null, cx)); assertTrue(Predicates.evaluatePredicates(Json.parseLenient("""[5,{"verb":"v"}]"""), cx))
    }

    @Test fun documentStepBudgetIsChargedBySubjectLength() {
        val pat = "a".repeat(130) + "b{64}"
        val c = SafeRegex.compile(pat)
        assertNotNull(c); assertTrue(SafeRegex.isSafeSource(pat))
        val subj = "a".repeat(512)
        val per = c!!.size() * 513
        val fit = (5_000_000L / per).toInt()
        assertTrue("fit $fit", fit in 11..59)
        val cond = Json.parseLenient("""{"field":"subject.s","op":"matches","value":"$pat"}""")
        val cx = ctx("""{"subject":{"s":"$subj"}}""")
        assertEquals(F, Predicates.evaluateConditionTri(mapOf("any_of" to List(fit) { cond }), cx))
        assertEquals(U, Predicates.evaluateConditionTri(mapOf("any_of" to List(fit + 1) { cond }), cx))
        val rcx = ctx("""{"action":{"verb":"v","resource":"$subj"}}""")
        val miss = Json.parseLenient("""{"verb":"v","resource":"re:$pat"}""")
        val allow = Json.parseLenient("""{"verb":"v","resource":"re:.*"}""")
        assertTrue(Predicates.evaluatePredicates(List(fit) { miss } + allow, rcx))
        assertFalse(Predicates.evaluatePredicates(List(fit + 1) { miss } + allow, rcx))
    }

    /** A condition tree nested far deeper than any thread stack is UNKNOWN (the StackOverflowError is caught), never an exception. */
    @Test fun aHugelyNestedConditionIsUnknownNotAnError() {
        var cond: Any? = linkedMapOf<String, Any?>("field" to "subject.id", "op" to "exists")
        repeat(400_000) { cond = linkedMapOf<String, Any?>("all_of" to arrayListOf(cond)) }
        assertEquals(U, Predicates.evaluateConditionTri(cond, ctx(PARAMS)))
        assertFalse(Predicates.evaluateCondition(cond, ctx(PARAMS)))
        var neg: Any? = linkedMapOf<String, Any?>("field" to "subject.id", "op" to "exists")
        repeat(400_000) { neg = linkedMapOf<String, Any?>("not" to neg) }
        assertEquals(U, Predicates.evaluateConditionTri(neg, ctx(PARAMS)))
        // the same inside a predicate's where clause: the predicate does not match
        assertFalse(Predicates.predicateMatches(linkedMapOf<String, Any?>("verb" to "v", "where" to arrayListOf(cond)), ctx(PARAMS)))
    }
}
