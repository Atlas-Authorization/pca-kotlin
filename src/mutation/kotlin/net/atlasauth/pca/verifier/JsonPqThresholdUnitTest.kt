package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.mm
import net.atlasauth.pca.verifier.KUtil.n
import net.atlasauth.pca.verifier.KUtil.priv
import java.math.BigDecimal
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonPqThresholdUnitTest {
    private fun err(raw: String?) = Json.numberError(raw)

    @Test fun numberErrors() {
        assertEquals("malformed number", err(null))
        for (s in listOf("", "01", ".5", "1.", "+1", "1e", "--1", "-", "1.e1", "0x1", "1 ", " 1", "1e+", "abc", "-01", "00")) assertEquals(s, "malformed number", err(s))
        for (s in listOf("1e5", "1E5", "1.5e5", "-1E-5")) assertEquals("exponent form is not allowed", err(s))
        assertEquals("negative zero is not allowed", err("-0")); assertNull(err("0"))
        for (s in listOf("1.50", "0.0", "-0.0")) assertEquals("trailing fractional zero is not canonical", err(s))
        assertNull(err("0.5")); assertNull(err("-0.5")); assertNull(err("12345678901234.5")); assertNull(err("-12345678901234.5"))
        for (s in listOf("123456789012345.5", "-123456789012345.5", "1234567890123456.5")) assertEquals("more than 15 significant digits", err(s))
        assertNull(err("0.000001")); assertNull(err("-0.000001")); assertNull(err("0.000012345678901"))
        assertEquals("non-integer magnitude below 1e-6", err("0.0000001")); assertEquals("non-integer magnitude below 1e-6", err("-0.0000001"))
        assertNull(err("9007199254740991")); assertNull(err("-9007199254740991"))
        for (s in listOf("9007199254740992", "-9007199254740992", "10000000000000000", "99999999999999999999")) assertEquals("integer outside the safe range", err(s))
        assertNull(err("1000000000000000")); assertNull(err("-5")); assertNull(err("123"))
    }

    @Test fun numberKinds() {
        assertTrue(Json.isSafeInt(n("5"))); assertTrue(Json.isSafeInt(n("-5"))); assertFalse(Json.isSafeInt(n("5.5"))); assertFalse(Json.isSafeInt(n("1.0")))
        assertFalse(Json.isSafeInt(n("-0"))); assertFalse(Json.isSafeInt(n("9007199254740992"))); assertTrue(Json.isSafeInt(n("9007199254740991")))
        assertTrue(Json.isSafeInt(5)); assertTrue(Json.isSafeInt(-5)); assertTrue(Json.isSafeInt(9007199254740991L)); assertTrue(Json.isSafeInt(-9007199254740991L))
        assertFalse(Json.isSafeInt(9007199254740992L)); assertFalse(Json.isSafeInt(-9007199254740992L)); assertFalse(Json.isSafeInt(Long.MIN_VALUE)); assertFalse(Json.isSafeInt(Long.MAX_VALUE))
        assertFalse(Json.isSafeInt(5.0)); assertFalse(Json.isSafeInt("5")); assertFalse(Json.isSafeInt(null))
        assertTrue(Json.isStrictNumber(n("5"))); assertTrue(Json.isStrictNumber(n("5.5"))); assertFalse(Json.isStrictNumber(n("1e5"))); assertFalse(Json.isStrictNumber(n("1.0")))
        assertTrue(Json.isStrictNumber(5)); assertTrue(Json.isStrictNumber(7L)); assertFalse(Json.isStrictNumber(Long.MAX_VALUE)); assertFalse(Json.isStrictNumber("5")); assertFalse(Json.isStrictNumber(null)); assertFalse(Json.isStrictNumber(5.5))
        assertEquals(5L, Json.asLong(n("5"))); assertEquals(-7L, Json.asLong(n("-7"))); assertEquals(7L, Json.asLong(7)); assertEquals(9007199254740991L, Json.asLong(9007199254740991L))
        assertEquals(BigDecimal("1.5"), Json.asDecimal(n("1.5"))); assertEquals(BigDecimal("-0.000001"), Json.asDecimal(n("-0.000001")))
        assertEquals(BigDecimal("7"), Json.asDecimal(7)); assertEquals(BigDecimal("9007199254740991"), Json.asDecimal(9007199254740991L))
        assertEquals("1.50", n("1.50").toString()); assertEquals("12", n("12").raw)
        assertTrue(n("1") == n("1")); assertFalse(n("1") == n("2")); assertFalse(n("1").equals("1")); assertEquals(n("12").hashCode(), "12".hashCode())
    }

    @Test fun surrogates() {
        assertFalse(Json.hasLoneSurrogate("")); assertFalse(Json.hasLoneSurrogate("abc")); assertFalse(Json.hasLoneSurrogate("\ud83d\ude00"))
        assertFalse(Json.hasLoneSurrogate("a\ud83d\ude00b")); assertFalse(Json.hasLoneSurrogate("\ud83d\ude00\ud83d\ude00"))
        for (s in listOf("\ud83d", "\ude00", "\ude00\ud83d", "\ud83dx", "a\ud83d", "\ud83d\ud83d\ude00", "\ud83d\ude00\ude00")) assertTrue(s, Json.hasLoneSurrogate(s))
    }

    @Test fun canonicalForms() {
        assertEquals("null", Json.canonicalize(null)); assertEquals("true", Json.canonicalize(true)); assertEquals("false", Json.canonicalize(false))
        assertEquals("5", Json.canonicalize(5)); assertEquals("-5", Json.canonicalize(-5L)); assertEquals("[]", Json.canonicalize(ArrayList<Any?>())); assertEquals("{}", Json.canonicalize(m()))
        assertEquals("[1,2,3]", Json.canonicalize(l(1, 2, 3))); assertEquals("{\"a\":1,\"b\":[true,null]}", Json.canonicalize(m("b" to l(true, null), "a" to 1)))
        assertEquals("{\"B\":1,\"a\":2,\"\u00e9\":3,\"\uff5e\":4,\"\ud83d\ude00\":5}", Json.canonicalize(m("\ud83d\ude00" to 5, "\uff5e" to 4, "\u00e9" to 3, "a" to 2, "B" to 1)))
        assertEquals("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f \u007f\"", Json.canonicalize("\"\\\b\u000c\n\r\t\u0001\u001f \u007f"))
        assertEquals("\"\u00e9\ud83d\ude00\"", Json.canonicalize("\u00e9\ud83d\ude00"))
        assertEquals("\"\ufffd\"", Json.canonicalize("\ud83d")); assertEquals("\"\ufffdx\"", Json.canonicalize("\ud83dx")); assertEquals("\"\ufffd\"", Json.canonicalize("\ude00"))
        assertEquals("\"a\ufffd\"", Json.canonicalize("a\ud83d")); assertEquals("\"\ufffd\ud83d\ude00\"", Json.canonicalize("\ud83d\ud83d\ude00"))
        assertEquals("canonicalize: lone surrogate in string", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict("\ud83d") }.message)
        assertEquals("canonicalize: lone surrogate in string", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(m("\ude00" to 1)) }.message)
        assertEquals("100000", Json.canonicalize(n("1e5"))); assertEquals("1.5", Json.canonicalize(n("1.50"))); assertEquals("0", Json.canonicalize(n("-0"))); assertEquals("0", Json.canonicalize(n("0.0")))
        assertEquals("0", Json.canonicalize(n("1e-400"))); assertEquals("1", Json.canonicalize(n("1.0"))); assertEquals("123456789012345680", Json.canonicalize(n("123456789012345678")))
        assertEquals("12", Json.canonicalize(n("12"))); assertEquals("-12.5", Json.canonicalize(n("-12.5"))); assertEquals("0.1", Json.canonicalize(n("1e-1")))
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException::class.java) { Json.canonicalize(n("1e400")) }.message)
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException::class.java) { Json.canonicalize(n("-1e400")) }.message)
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException::class.java) { Json.fmtNumber("1e99999999999") }.message)
        assertEquals("1", Json.fmtNumber("1")); assertEquals("1.5", Json.fmtNumber("1.5")); assertEquals("1.5", Json.fmtNumber("1.50"))
        assertEquals("[1,1.5]", Json.canonicalizeStrict(l(n("1"), n("1.5"))))
        assertEquals("canonicalize: exponent form is not allowed", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(n("1e5")) }.message)
        assertEquals("canonicalize: integer outside the safe range", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(9007199254740992L) }.message)
        assertEquals("9007199254740991", Json.canonicalizeStrict(9007199254740991L)); assertEquals("5", Json.canonicalizeStrict(5)); assertEquals("9007199254740992", Json.canonicalize(9007199254740992L))
        assertTrue(assertThrows(IllegalArgumentException::class.java) { Json.canonicalize(1.5) }.message!!.startsWith("canonicalize: unsupported type"))
        assertTrue(assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(1.5) }.message!!.startsWith("canonicalize: unsupported type"))
        assertTrue(assertThrows(IllegalArgumentException::class.java) { Json.canonicalize(l(Any())) }.message!!.startsWith("canonicalize: unsupported type"))
        var a: Any? = 1; repeat(32) { a = l(a) }
        assertNotNull(Json.canonicalizeStrict(a)); val a33 = l(a)
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(a33) }.message); assertNotNull(Json.canonicalize(a33))
        var o: Any? = 1; repeat(32) { o = m("k" to o) }
        assertNotNull(Json.canonicalizeStrict(o)); val o33 = m("k" to o)
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(o33) }.message); assertNotNull(Json.canonicalize(o33))
        var mix: Any? = 1; repeat(16) { mix = m("k" to l(mix)) }
        assertNotNull(Json.canonicalizeStrict(mix)); val mix2 = m("k" to l(mix))
        assertThrows(IllegalArgumentException::class.java) { Json.canonicalizeStrict(mix2) }
        assertEquals(0, Json.compareUtf8("a", "a")); assertTrue(Json.compareUtf8("a", "b") < 0); assertTrue(Json.compareUtf8("\uff5e", "\ud83d\ude00") < 0)
        assertTrue(Json.compareUtf8("\u00e9", "z") > 0); assertTrue(Json.compareUtf8("a", "ab") < 0)
    }

    @Test fun parserEdges() {
        assertEquals("input is not a string", assertThrows(IllegalArgumentException::class.java) { Json.parse(null) }.message)
        assertEquals("input is not a string", assertThrows(IllegalArgumentException::class.java) { Json.parseLenient(null) }.message)
        assertEquals("input too large", assertThrows(IllegalArgumentException::class.java) { Json.parse("[" + " ".repeat(1048575) + "]") }.message)
        assertEquals(listOf<Any?>(), Json.parse("[" + " ".repeat(1048574) + "]")); assertEquals(listOf<Any?>(), Json.parseLenient("[" + " ".repeat(1048600) + "]"))
        val euro = "\"" + "\u20ac".repeat(349524)
        assertEquals("input too large", assertThrows(IllegalArgumentException::class.java) { Json.parse(euro + "aaa\"") }.message)
        assertEquals(349526, (Json.parse(euro + "aa\"") as String).length)
        assertEquals(true, Json.parse("true")); assertEquals(false, Json.parse(" false ")); assertNull(Json.parse("null")); assertEquals("a", Json.parse("\"a\""))
        assertEquals("x\u00e9\ud83d\ude00\n\t\"\\/\b\u000c\r", Json.parse("\"x\\u00e9\\ud83d\\ude00\\n\\t\\\"\\\\\\/\\b\\f\\r\""))
        assertEquals("\u00e9\u00E9", Json.parse("\"\\u00e9\\u00E9\"")); assertEquals("09afAF", Json.parse("\"\\u0030\\u0039\\u0061\\u0066\\u0041\\u0046\""))
        assertEquals("1", (Json.parse("[1]") as List<*>)[0].toString()); assertEquals("-12.5", (Json.parse("-12.5") as Json.Num).raw); assertEquals("0", (Json.parse("0") as Json.Num).raw)
        assertEquals("1e5", (Json.parseLenient("1e5") as Json.Num).raw); assertEquals("1E+5", (Json.parseLenient("1E+5") as Json.Num).raw); assertEquals("1e-5", (Json.parseLenient("1e-5") as Json.Num).raw)
        assertEquals("9", (Json.parse("9") as Json.Num).raw); assertEquals("1.5", (Json.parse("1.5") as Json.Num).raw); assertEquals("19", (Json.parse("19") as Json.Num).raw)
        assertEquals("1.0", (Json.parseLenient("1.0") as Json.Num).raw)
        assertEquals("\ud800", Json.parseLenient("\"\\ud800\""))
        for ((i, e) in listOf("" to "unexpected end at 0", "   " to "unexpected end at 3", "[" to "unexpected end at 1", "[1" to "unterminated array at 2", "[1," to "unexpected end at 3",
            "{" to "expected key at 1", "{\"a\"" to "expected ':' at 4", "{\"a\":1" to "unterminated object at 6", "{\"a\":1," to "expected key at 7",
            "\"abc" to "unterminated string at 4", "\"\\" to "bad escape at 2", "\"\\x\"" to "bad escape at 3", "\"\\u12" to "bad \\u escape at 3", "\"\\u12G4\"" to "bad \\u escape at 3",
            "\"\\u00:0\"" to "bad \\u escape at 3", "\"\\u00/0\"" to "bad \\u escape at 3", "\"\\u00@0\"" to "bad \\u escape at 3", "\"\\u00`0\"" to "bad \\u escape at 3", "\"\\u00g0\"" to "bad \\u escape at 3",
            "tru" to "bad literal at 0", "nul" to "bad literal at 0", "-" to "bad number at 1", "-x" to "bad number at 1", "1." to "bad number at 2", "1e" to "bad number at 2", "1e+" to "bad number at 3",
            "x" to "bad number at 0", "[1,]" to "bad number at 3", "[1 2]" to "expected ',' or ']' at 4", "{\"a\":1 \"b\":2}" to "expected ',' or '}' at 8",
            "1 2" to "trailing data at 2", "\"\u0001\"" to "control char in string at 2", "\"\ud800\"" to "lone surrogate in string at 3", "01" to "trailing data at 1",
            "{\"a\":1,\"a\":2}" to "duplicate key at 10", "1.0" to "trailing fractional zero is not canonical at 3", "1e5" to "exponent form is not allowed at 3"))
            assertEquals(i, e, assertThrows(IllegalArgumentException::class.java) { Json.parse(i) }.message)
        assertNotNull(Json.parse("[".repeat(32) + "]".repeat(32)))
        assertEquals("nesting too deep at 32", assertThrows(IllegalArgumentException::class.java) { Json.parse("[".repeat(33) + "]".repeat(33)) }.message)
        assertNotNull(Json.parseLenient("[".repeat(100) + "]".repeat(100))); assertNotNull(Json.parse("{\"a\":".repeat(32) + "1" + "}".repeat(32)))
        assertTrue(assertThrows(IllegalArgumentException::class.java) { Json.parse("{\"a\":".repeat(33) + "1" + "}".repeat(33)) }.message!!.startsWith("nesting too deep at "))
        assertEquals(listOf<Any?>(), Json.parse("[ ]")); assertEquals(mapOf<String, Any?>(), Json.parse("{ }")); assertEquals(1, (Json.parse("[ 1 ]") as List<*>).size)
        assertEquals(1, (Json.parse("{ \"a\" : 1 }") as Map<*, *>).size); assertEquals(2, (Json.parse("[\t1\r\n,\n2 ]") as List<*>).size); assertEquals(1, (Json.parse("\t{\n\"a\"\r:\n1\t}\n") as Map<*, *>).size)
        assertThrows(IllegalArgumentException::class.java) { Json.parse("\u00a0[]") }; assertEquals(listOf<Any?>(), Json.parse("\n[\n]\n"))
        for (digits in listOf("\uff10\uff10\uff10\uff11", "\u0660\u0660\u0660\u0661", "00\uff10\uff11", "\uff1000")) {
            val inp = "\"\\u$digits\""
            assertEquals("bad \\u escape at 3", assertThrows(IllegalArgumentException::class.java) { Json.parse(inp) }.message)
            assertThrows(IllegalArgumentException::class.java) { Json.parseLenient(inp) }
        }
        assertEquals("A", Json.parse("\"\\u0041\""))
        @Suppress("UNCHECKED_CAST") (Json.parse("{ }") as MutableMap<String, Any?>)["k"] = 1
        @Suppress("UNCHECKED_CAST") (Json.parse("[ ]") as MutableList<Any?>).add(1)
        @Suppress("UNCHECKED_CAST") (Json.parse("{}") as MutableMap<String, Any?>)["k"] = 1
        @Suppress("UNCHECKED_CAST") (Json.parse("[]") as MutableList<Any?>).add(1)
    }

    @Test fun suites() {
        val ed = Pq.resolveSigAlg(null, false)!!
        assertEquals(Pq.Suite("ed25519", 64, true, null, false, false), ed)
        assertEquals("ed25519", Pq.resolveSigAlg("ed25519", true)!!.alg)
        assertEquals(Pq.Suite("ml-dsa-65", 3309, false, Pq.Prim.ML_DSA_65, true, false), Pq.resolveSigAlg("ml-dsa-65", true))
        assertEquals(Pq.Suite("ml-dsa-87", 4627, false, Pq.Prim.ML_DSA_87, true, false), Pq.resolveSigAlg("ml-dsa-87", true))
        val hy = Pq.resolveSigAlg("hybrid-ed25519-ml-dsa-65", true)!!
        assertEquals(Pq.Suite("hybrid-ed25519-ml-dsa-65", 64, true, Pq.Prim.ML_DSA_65, true, true), hy)
        assertEquals(Pq.Suite("hybrid-nested-ed25519-ml-dsa-65", 64, true, Pq.Prim.ML_DSA_65, true, true, nested = true), Pq.resolveSigAlg("hybrid-nested-ed25519-ml-dsa-65", true))
        assertTrue(hy.hasEd25519); assertEquals(Pq.Prim.ML_DSA_65, hy.pq); assertTrue(hy.needsPqPk); assertTrue(hy.needsPqSig); assertFalse(hy.nested)
        assertNull(ed.pq); assertFalse(ed.needsPqSig)
        // a registered suite outside the dispatch (no FIPS 206 in BouncyCastle) and malformed algs resolve to nothing
        assertNull(Pq.resolveSigAlg("fn-dsa-512", true)); assertNull(Pq.resolveSigAlg(5, true)); assertNull(Pq.resolveSigAlg(null, true))
        assertEquals(1952, Pq.ML_DSA_65_PUBLIC_KEY_BYTES); assertEquals(3309, Pq.ML_DSA_65_SIGNATURE_BYTES); assertEquals(64, Pq.ED25519_SIGNATURE_BYTES); assertEquals("ed25519", Pq.DEFAULT_SIG_ALG)
    }

    @Test fun validateSigWire() {
        val pk = "A".repeat(2603); val sg = "A".repeat(4412); val ed = "A".repeat(86)
        assertNull(Pq.validateSignatureWire(m("sig" to ed)))
        assertEquals("'alg' must be a string", Pq.validateSignatureWire(m("alg" to 5, "sig" to ed)))
        assertEquals("'alg' must be a string", Pq.validateSignatureWire(m("alg" to null, "sig" to ed)))
        assertEquals("unknown signature alg 'zz'", Pq.validateSignatureWire(m("alg" to "zz", "sig" to ed)))
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pq.validateSignatureWire(m("sig" to "x")))
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pq.validateSignatureWire(m("alg" to "ed25519", "sig" to sg)))
        assertEquals("'pq_pk' must be absent for alg 'ed25519'", Pq.validateSignatureWire(m("sig" to ed, "pq_pk" to pk)))
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pq.validateSignatureWire(m("sig" to ed, "pq_sig" to sg)))
        assertNull(Pq.validateSignatureWire(m("alg" to "ml-dsa-65", "sig" to sg, "pq_pk" to pk)))
        assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pq.validateSignatureWire(m("alg" to "ml-dsa-65", "sig" to sg)))
        assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'", Pq.validateSignatureWire(m("alg" to "ml-dsa-65", "sig" to sg, "pq_pk" to pk, "pq_sig" to sg)))
        assertNull(Pq.validateSignatureWire(m("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to ed, "pq_pk" to pk, "pq_sig" to sg)))
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pq.validateSignatureWire(m("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to ed, "pq_pk" to pk)))
        assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pq.validateSignatureWire(m("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to ed, "pq_sig" to sg)))
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'hybrid-ed25519-ml-dsa-65'", Pq.validateSignatureWire(m("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to sg, "pq_pk" to pk, "pq_sig" to sg)))
    }

    @Test fun resolveKey() {
        val commit = Pca.holderPqCommitment("PK")
        fun r(id: String?, pk: Any?, hp: Any?, pins: Map<String, Any?>?, t: String?) = PinnedPq.resolve(id, pk, hp, pins, t)
        assertEquals("T", r("i", "PK", null, null, "T")!!.key); assertNull(r("i", "PK", null, null, "")); assertNull(r("i", "PK", null, null, null)); assertNull(r("i", "", null, null, null))
        assertNull(r("i", 5, commit, null, null)); assertNull(r("i", null, commit, null, null)); assertNull(r("i", "", Pca.holderPqCommitment(""), null, null))
        assertEquals("PK", r("i", "PK", commit, null, null)!!.key); assertNull(r("i", "PK", "wrong", null, null)); assertNull(r("i", "PK", 5, null, null)); assertNull(r("i", "PK", null, null, null))
        assertEquals("pin", r("i", "PK", null, m("i" to "PK"), null)!!.source); assertNull(r("i", "PK", commit, m("i" to "OTHER"), null)); assertNull(r("i", "PK", commit, m("i" to 5), null))
        assertEquals("holder-commitment", r("i", "PK", commit, m("j" to "PK2"), null)!!.source); assertNull(r("i", "PK", null, m("j" to "PK"), null))
        assertEquals("PK", r(null, "PK", commit, m("i" to "PK2"), null)!!.key); assertEquals("PK", r("i", "PK", commit, m(), null)!!.key)
        assertEquals("trusted", r("i", null, null, m("i" to "X"), "T")!!.source)
    }

    @Test fun leafSuiteSeam() {
        @Suppress("UNCHECKED_CAST")
        for (nm in listOf("pq-leaf-ml-dsa-65-valid", "pq-leaf-hybrid-ed25519-ml-dsa-65-valid")) {
            val p = mm(KUtil.vec(nm)["pcactn"]); val chain = KUtil.ll(p["cap_chain"])
            val holder = mm(chain[chain.size - 1])["holder"] as String
            val msg = Pca.thresholdMessage(p); val alg = p["alg"]
            assertTrue(nm, Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, p["sig"], p["pq_sig"]))
            assertTrue(nm, Pq.verifyArtifactSignature(alg as String, holder, p["pq_pk"], msg, p["sig"], p["pq_sig"]))
            assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, 5, p["pq_sig"]))
            assertFalse(Pq.verifyLeafSuite("bogus", true, holder, p["pq_pk"], msg, p["sig"], p["pq_sig"]))
            assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], byteArrayOf(1), p["sig"], p["pq_sig"]))
            assertFalse(Pq.verifyLeafSuite(alg, true, holder, 5, msg, p["sig"], p["pq_sig"]))
            assertFalse(Pq.verifySuite(alg, true, holder, null, msg, p["sig"], p["pq_sig"]))
            if (alg == "hybrid-ed25519-ml-dsa-65") {
                assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, p["sig"], null)); assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, p["sig"], 5))
                assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, p["sig"], "A".repeat(4412))); assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, "A".repeat(86), p["pq_sig"]))
                assertFalse(Pq.verifyLeafSuite(alg, true, "A".repeat(43), p["pq_pk"], msg, p["sig"], p["pq_sig"])); assertFalse(Pq.verifyLeafSuite(alg, true, holder, "A".repeat(2603), msg, p["sig"], p["pq_sig"]))
                assertTrue(Pca.verifyB64u(holder, msg, p["sig"] as String)); assertTrue(Pq.mlDsa65VerifyB64u(p["pq_pk"], msg, p["pq_sig"]))
            } else {
                assertFalse(Pq.verifyLeafSuite(alg, true, holder, "A".repeat(2603), msg, p["sig"], null)); assertFalse(Pq.verifyLeafSuite(alg, true, holder, p["pq_pk"], msg, "A".repeat(4412), null))
                assertTrue(Pq.mlDsa65VerifyB64u(p["pq_pk"], msg, p["sig"])); assertFalse(Pq.mlDsa65VerifyB64u(p["pq_pk"], msg, "A".repeat(4412))); assertFalse(Pq.mlDsa65VerifyB64u("A".repeat(2603), msg, p["sig"]))
                assertFalse(Pq.mlDsa65VerifyB64u(null, msg, p["sig"])); assertFalse(Pq.mlDsa65VerifyB64u(p["pq_pk"], msg, null))
                val pkb = Pca.decodeB64uStrict(p["pq_pk"], 1952)!!; val sgb = Pca.decodeB64uStrict(p["sig"], 3309)!!
                assertTrue(Pq.mlDsa65Verify(pkb, msg, sgb)); assertFalse(Pq.mlDsa65Verify(null, msg, sgb)); assertFalse(Pq.mlDsa65Verify(pkb, msg, null))
                assertFalse(Pq.mlDsa65Verify(ByteArray(1951), msg, sgb)); assertFalse(Pq.mlDsa65Verify(ByteArray(1953), msg, sgb)); assertFalse(Pq.mlDsa65Verify(pkb, msg, ByteArray(3308))); assertFalse(Pq.mlDsa65Verify(pkb, msg, ByteArray(3310)))
                assertFalse(Pq.mlDsa65Verify(pkb, byteArrayOf(1), sgb)); val bad = sgb.clone(); bad[10] = (bad[10].toInt() xor 1).toByte(); assertFalse(Pq.mlDsa65Verify(pkb, msg, bad))
            }
        }
        assertFalse(Pq.verifyLeafSuite(null, false, "x", null, ByteArray(0), null, null)); assertFalse(Pq.verifyLeafSuite("ed25519", true, "x", null, ByteArray(0), "A".repeat(86), null))
    }

    @Test fun thresholdBinding() {
        assertEquals("2.1", Threshold.AGENT_LEAF_SHARE_BINDING_VERSION)
        fun tag(alg: Any?, present: Boolean): ByteArray = priv(Threshold, "shareSuiteTag", alg, present)
        assertArrayEquals(ByteArray(0), tag(null, false)); assertArrayEquals(ByteArray(0), tag("ed25519", true)); assertArrayEquals(ByteArray(0), tag("bogus", true)); assertArrayEquals(ByteArray(0), tag(5, true))
        assertArrayEquals("\u0000atlas-pca/share-suite/v1\u0000ml-dsa-65".toByteArray(), tag("ml-dsa-65", true))
        assertArrayEquals("\u0000atlas-pca/share-suite/v1\u0000hybrid-ed25519-ml-dsa-65".toByteArray(), tag("hybrid-ed25519-ml-dsa-65", true))
        val set = l(m("publicKey" to "b", "role" to "guardian"), m("publicKey" to "a", "role" to "guardian"), m("publicKey" to "z", "role" to "agent"))
        val sorted = l(m("publicKey" to "z", "role" to "agent"), m("publicKey" to "a", "role" to "guardian"), m("publicKey" to "b", "role" to "guardian"))
        assertArrayEquals(Threshold.signerSetHash(sorted), Threshold.signerSetHash(set))
        assertArrayEquals(Threshold.signerSetHash(sorted), Threshold.signerSetHash(l(m("publicKey" to "z", "role" to "agent"), m("publicKey" to "b", "role" to "guardian"), m("publicKey" to "a", "role" to "guardian"))))
        val dom = "atlas-pca/signerset/v1\u0000".toByteArray()
        assertArrayEquals(Pca.sha(dom, "[{\"publicKey\":\"z\",\"role\":\"agent\"},{\"publicKey\":\"a\",\"role\":\"guardian\"},{\"publicKey\":\"b\",\"role\":\"guardian\"}]".toByteArray()), Threshold.signerSetHash(set))
        val pq = l(m("publicKey" to "a", "role" to "r", "pq_pk" to "PQ"), m("publicKey" to "a", "role" to "q", "pq_pk" to 5), m("role" to "q"))
        assertArrayEquals(Pca.sha(dom, "[{\"publicKey\":\"a\",\"role\":\"q\"},{\"publicKey\":\"null\",\"role\":\"q\"},{\"pq_pk\":\"PQ\",\"publicKey\":\"a\",\"role\":\"r\"}]".toByteArray()), Threshold.signerSetHash(pq))
        assertEquals(32, Threshold.signerSetHash(ArrayList()).size); assertFalse(Threshold.signerSetHash(sorted).contentEquals(Threshold.signerSetHash(ArrayList())))
        val tm = byteArrayOf(1, 2, 3)
        for (t in listOf(0, 4, -1)) assertEquals("shareMessage: t must be 1, 2 or 3", assertThrows(IllegalArgumentException::class.java) { Threshold.shareMessage("agent", tm, sorted, t, null, false) }.message)
        for (t in 1..3) assertArrayEquals(Pca.concat("atlas-pca/share/agent\u0000".toByteArray(), Pca.sha(tm), Threshold.signerSetHash(sorted), byteArrayOf(t.toByte())), Threshold.shareMessage("agent", tm, sorted, t, null, false))
        assertArrayEquals(Pca.concat("atlas-pca/share/agent\u0000".toByteArray(), Pca.sha(tm), Threshold.signerSetHash(sorted), byteArrayOf(2), tag("ml-dsa-65", true)), Threshold.shareMessage("agent", tm, sorted, 2, "ml-dsa-65", true))
        @Suppress("UNCHECKED_CAST") val shares = (mm(SnapshotTest.core["primitives"])["threshold_share"]) as List<Any?>
        var seen = 0
        for (x in shares) {
            val e = mm(x); if (e.containsKey("valid") && e["valid"] == false) continue
            val share = mm(e["share"]); val ealg = share["alg"]
            if (ealg is String && ealg !in listOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) continue
            val tmsg = Pca.decodeB64uStrict(e["threshold_message"], -1)!!; val ss = KUtil.ll(e["signer_set"]); val t = Json.asLong(e["t"]).toInt(); val role = e["role"] as String
            assertTrue(e["name"].toString(), Threshold.verifyShare(role, tmsg, ss, t, share))
            assertFalse(Threshold.verifyShare(role + "x", tmsg, ss, t, share)); assertFalse(Threshold.verifyShare(role, byteArrayOf(9), ss, t, share))
            assertFalse(Threshold.verifyShare(role, tmsg, ss, if (t == 1) 2 else 1, share)); assertFalse(Threshold.verifyShare(role, tmsg, ss, 0, share)); assertFalse(Threshold.verifyShare(role, tmsg, ArrayList(), t, share))
            assertFalse(Threshold.verifyShare(role, tmsg, ss, t, LinkedHashMap(share).also { it.remove("sig") }))
            if (ealg == null || ealg == "ed25519") assertFalse(Threshold.verifyShare(role, tmsg, ss, t, LinkedHashMap(share).also { it.remove("publicKey") }))
            assertFalse(Threshold.verifyShare(role, tmsg, ss, t, LinkedHashMap(share).also { it["alg"] = "bogus" }))
            if (ealg != null && ealg != "ed25519") {
                assertFalse(Threshold.verifyShare(role, tmsg, ss, t, LinkedHashMap(share).also { it.remove("alg") }))
                assertTrue(Threshold.verifyShare(role, tmsg, ss, t, LinkedHashMap(share).also { it.remove("pq_pk") })) // R5-A1: key from the signer set
            }
            seen++
        }
        assertTrue("valid shares $seen", seen > 3)
        assertFalse(Threshold.verifyShare("agent", tm, l("x"), 1, m()))
    }
}
