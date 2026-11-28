package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests (BRIEF-deadline): Json, V8Json and AttestXml loops/cursors that a mutant could stop advancing. */
class Kill06DeadlineAJsonXmlTest {
    private fun <T> dl(b: () -> T): T = Deadline.within { b() }

    @Test fun jsonLoneSurrogate() = dl {
        assertFalse(Json.hasLoneSurrogate("a\uD83D\uDE00b\uD83D\uDE01c"))
        assertTrue(Json.hasLoneSurrogate("a\uD83D\uDE00b\uD83D"))
        assertTrue(Json.hasLoneSurrogate("\uDE00"))
        assertTrue(Json.hasLoneSurrogate("\uD83Dx"))
        assertFalse(Json.hasLoneSurrogate("abc"))
    }

    @Test fun jsonParserNumbersAndWs() = dl {
        val v = Json.parseLenient(" \t\r\n[ -12.5e+3 ,\n 0 , 7 , 3.25E-2 , 1e5 ] \n") as List<*>
        assertEquals(listOf("-12.5e+3", "0", "7", "3.25E-2", "1e5"), v.map { (it as Json.Num).raw })
        val s = Json.parse("{ \"a\" : [ 12 , -3 , 4.5 ] , \"b\" : 0 }") as Map<*, *>
        assertEquals(listOf("12", "-3", "4.5"), (s["a"] as List<*>).map { (it as Json.Num).raw })
        assertEquals("0", (s["b"] as Json.Num).raw)
        assertEquals(1234567L, Json.asLong(Json.parse("1234567")))
        assertEquals("-0.5", (Json.parse("-0.5") as Json.Num).raw)
        assertTrue(Json.parse("[]") is List<*>)
        assertTrue(Json.parse("{ }") is Map<*, *>)
    }

    @Test fun v8JsonValidDocuments() = dl {
        assertEquals("", V8Json.error("[1, 2.5e+3, -0.5E-2, 10, [true, false, null], {\"a\": \"x\\u00e9\\n\\\"\"}]"))
        assertEquals("", V8Json.error("  \t\r\n{\"k\" : [ 1 , 2 ,3 ] , \"z\":\"\\uABcd\"}  \n"))
        assertEquals("", V8Json.error("\"plain string\""))
        assertEquals("", V8Json.error("[ \"a\" , \"b\" , \"c\" ]"))
        assertEquals("", V8Json.error("12345.678e10"))
        assertEquals("", V8Json.error("[[],[[]],[[],[]]]"))
        assertTrue(V8Json.error("[1,2").isNotEmpty())
        assertTrue(V8Json.error("\"\\u12g4\"").startsWith("Bad Unicode escape"))
        assertTrue(V8Json.error("[1 2]").startsWith("Expected ',' or ']'"))
        assertTrue(V8Json.error("1.").startsWith("Unterminated fractional number"))
        assertTrue(V8Json.error("1e").startsWith("Exponent part is missing a number"))
        assertTrue(V8Json.error("-").startsWith("No number after minus sign"))
    }

    @Test fun xmlParseAllConstructs() = dl {
        val xml = "<!-- c1 --><?pi x?><!DOCTYPE d [<!ENTITY e \"v\">]>" +
            "<r xmlns=\"urn:d\" xmlns:a=\"urn:a\"  id = \"1&amp;2\"  q='x'  ><a:b  a:k = \"v\" z='&#65;&#x42;' />" +
            "t<![CDATA[<raw>]]>&lt;<c>x</c ></r>"
        val d = AttestXml.parse(xml)
        assertEquals("XML comments are not permitted", d.violation)
        val r = d.root
        assertEquals("r", r.local)
        assertEquals("urn:d", r.ns)
        assertEquals("1&2", r.attr("id"))
        assertEquals("x", r.attr("q"))
        val kids = r.elementChildren()
        assertEquals(2, kids.size)
        assertEquals("urn:a", kids[0].ns)
        assertEquals("b", kids[0].local)
        assertEquals("AB", kids[0].attr("z"))
        assertEquals("v", kids[0].attr("a:k"))
        assertEquals("urn:d", kids[1].ns)
        assertEquals("t<raw><x", r.textContent().substring(0, 8))
        assertEquals("x", kids[1].textContent())
    }

    @Test fun xmlViolationsFirstWins() = dl {
        assertEquals("XML processing instructions are not permitted", AttestXml.parse("<?pi?><a/><!--c-->").violation)
        assertEquals("DTD / DOCTYPE is not permitted", AttestXml.parse("<!DOCTYPE a [x[y]z]><a></a>").violation)
        assertEquals("", AttestXml.parse("<a b=\"1\"></a>").violation)
        val s = AttestXml.parse("<a   b = '1'   c=\"2\"   />").root
        assertEquals("1", s.attr("b"))
        assertEquals("2", s.attr("c"))
    }
}
