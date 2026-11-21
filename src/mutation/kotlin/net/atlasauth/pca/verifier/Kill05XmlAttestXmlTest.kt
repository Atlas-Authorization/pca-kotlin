package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The RIM XML reader and canonicaliser: every refusal text, the profile violations, namespaces, references and the C14N escapes. */
class Kill05XmlAttestXmlTest {
    private fun err(s: String): String = try {
        AttestXml.parse(s)
        "OK"
    } catch (e: AttErr) {
        e.message ?: ""
    }

    private fun dec(s: String): String = try {
        AttestXml.decode(s)
    } catch (e: AttErr) {
        "ERR " + e.message
    }

    @Test
    fun refusals() {
        val cases = listOf(
            "" to "no document element",
            " \t\r\n" to "no document element",
            "x<a/>" to "text outside the document element",
            " y <a/>" to "text outside the document element",
            "<a/>x" to "text outside the document element",
            "<a/><b/>" to "more than one document element",
            "<a>" to "element <a> is not closed",
            "<a><b></a>" to "end tag </a> does not match <b>",
            "</a>" to "unexpected end tag",
            "<a></a" to "unexpected end tag",
            "<a><!-- x</a>" to "unterminated comment",
            "<a><!--></a>" to "unterminated comment",
            "<a><? x</a>" to "unterminated processing instruction",
            "<a><![CDATA[x</a>" to "misplaced or unterminated CDATA section",
            "<![CDATA[x]]><a/>" to "misplaced or unterminated CDATA section",
            "<!DOCTYPE a [<x>" to "unterminated DOCTYPE",
            "<a/><!DOCTYPE a" to "unterminated DOCTYPE",
            "<a>&amp</a>" to "unterminated entity reference",
            "<a>&foo;</a>" to "undefined entity &foo;",
            "<a>&#xD800;</a>" to "invalid character reference &#xD800;",
            "< a/>" to "malformed start tag",
            "<>" to "malformed start tag",
            "<a" to "unterminated start tag",
            "<a " to "unterminated start tag",
            "<a/" to "malformed start tag",
            "<a/x>" to "malformed start tag",
            "<a b/>" to "malformed attribute",
            "<a b>=\"x\"/>" to "malformed attribute",
            "<a b/=\"x\"/>" to "malformed attribute",
            "<a =\"x\"/>" to "malformed attribute",
            "<a b" to "malformed attribute",
            "<a b " to "malformed attribute",
            "<a b=" to "unquoted attribute value",
            "<a b= " to "unquoted attribute value",
            "<a b=x/>" to "unquoted attribute value",
            "<a b=\"x/>" to "unterminated attribute value",
            "<a b='x\"/>" to "unterminated attribute value",
            "<a b=\"<\"/>" to "'<' in an attribute value",
            "<a b=\"1\" b=\"2\"/>" to "attribute b is repeated",
            "<a b=\"&x;\"/>" to "undefined entity &x;",
            "<q:a/>" to "namespace prefix q is not bound",
            "<a q:x=\"1\"/>" to "namespace prefix q is not bound",
            "<a xmlns:p=\"u\"><b q:x=\"1\"/></a>" to "namespace prefix q is not bound",
        )
        for ((xml, want) in cases) assertEquals(xml, want, err(xml))
    }

    @Test
    fun violationsFirstOneWinsAndTheDocumentStillParses() {
        fun v(s: String) = AttestXml.parse(s).violation
        assertEquals("", v("<a/>"))
        assertEquals("", v("\n <a/>\r\n\t"))
        assertEquals("XML processing instructions are not permitted", v("<?xml version=\"1.0\"?><a><!--c--></a>"))
        assertEquals("XML comments are not permitted", v("<a><!--c--><?p?></a>"))
        assertEquals("DTD / DOCTYPE is not permitted", v("<!DOCTYPE a [<!ENTITY e \"x\">]><a/>"))
        assertEquals("DTD / DOCTYPE is not permitted", v("<!DOCTYPE a><a/>"))
        assertEquals("DTD / DOCTYPE is not permitted", v("<!DOCTYPE a [ [ ] ] ><a/>"))
        assertEquals("DTD / DOCTYPE is not permitted", v("<!DOCTYPE a ]><a/>"))
        assertEquals(
            "xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)",
            v("<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" xml:lang=\"en\"/>"),
        )
        // what follows each skipped construct is read from the right offset
        assertEquals("t", AttestXml.parse("<a><!--x-->t</a>").root.textContent())
        assertEquals("t", AttestXml.parse("<a><!---->t</a>").root.textContent())
        assertEquals("t", AttestXml.parse("<a><?p x?>t</a>").root.textContent())
        assertEquals("t", AttestXml.parse("<a><?>t</a>").root.textContent())
        assertEquals("<b>&amp;t", AttestXml.parse("<a><![CDATA[<b>&amp;]]>t</a>").root.textContent())
        assertEquals("a", AttestXml.parse("<!DOCTYPE a><a/>").root.name)
        assertEquals("a", AttestXml.parse("<?p?><a/>").root.name)
        assertEquals("a", AttestXml.parse("<!--c--><a/>").root.name)
    }

    @Test
    fun treeShapeTextAndHelpers() {
        val d = AttestXml.parse("<r xmlns:p=\"u\"><p:x/>t<x/><p:y><p:x/></p:y></r>")
        val r = d.root
        assertNull(r.parent)
        assertEquals(4, r.children.size)
        val text = r.children[1]
        assertTrue(!text.elem)
        assertEquals("t", text.text)
        assertSame(r, text.parent)
        assertEquals("", text.name)
        assertEquals("", text.prefix)
        assertEquals("", text.local)
        assertEquals("", text.ns)
        assertEquals(listOf("p:x", "x", "p:y"), r.elementChildren().map { it.name })
        assertEquals(listOf("p:x"), r.elementChildrenNs("u", "x").map { it.name })
        assertEquals(listOf("x"), r.elementChildrenNs("", "x").map { it.name })
        assertEquals(0, r.elementChildrenNs("", "").size)
        assertEquals(0, r.elementChildrenNs("u", "z").size)
        assertEquals(2, r.descendantsNs("u", "x"))
        assertEquals(1, r.descendantsNs("u", "y"))
        assertEquals(1, r.descendantsNs("", "x"))
        assertEquals(0, r.descendantsNs("v", "x"))
        val px = r.children[0]
        assertEquals("p", px.prefix)
        assertEquals("x", px.local)
        assertEquals("u", px.ns)
        assertSame(r, px.parent)
        assertEquals("u", px.lookupNs("p"))
        assertNull(px.lookupNs("zz"))
        assertNull(px.lookupNs(""))

        val a = AttestXml.parse("<a b=\"1\" c=\"2\"/>").root
        assertEquals("1", a.attr("b"))
        assertEquals("2", a.attr("c"))
        assertEquals("", a.attr("z"))

        // text accumulates into one node across CDATA; an element splits it
        val m = AttestXml.parse("<a>x<![CDATA[y]]>z</a>").root
        assertEquals(1, m.children.size)
        assertEquals("xyz", m.children[0].text)
        val s = AttestXml.parse("<a>x<b>y</b>z</a>").root
        assertEquals(3, s.children.size)
        assertEquals("xyz", s.textContent())
        assertEquals("y", s.children[1].textContent())
        assertEquals("", AttestXml.parse("<a></a>").root.textContent())
        // end tags may carry trailing white space
        assertEquals("a", AttestXml.parse("<a></a \t\r\n>").root.name)
    }

    @Test
    fun nodeProperties() {
        val t = AttestXml.Node(false)
        assertEquals("", t.text)
        assertEquals("", t.prefix)
        assertEquals("", t.local)
        assertEquals("", t.ns)
        val e = AttestXml.Node(true, "n", "x")
        assertEquals("x", e.text)
        assertEquals("", e.prefix)
        e.prefix = "p"
        e.local = "l"
        e.ns = "s"
        e.text = "w"
        assertEquals("p", e.prefix)
        assertEquals("l", e.local)
        assertEquals("s", e.ns)
        assertEquals("w", e.text)
        val at = AttestXml.Attr("q:a", "q", "a", "", "v")
        at.ns = "u"
        assertEquals("u", at.ns)
    }

    @Test
    fun namespacesAndAttributes() {
        val r = AttestXml.parse("<a xmlns=\"d\" xmlns:q=\"u\" q:x=\"1\" y=\"2\"><b/></a>").root
        assertEquals("d", r.ns)
        assertEquals("", r.prefix)
        assertEquals("a", r.local)
        assertEquals("d", r.children[0].ns)
        assertEquals(2, r.attrs.size)
        val qx = r.attrs[0]
        assertEquals("q:x", qx.name)
        assertEquals("q", qx.prefix)
        assertEquals("x", qx.local)
        assertEquals("u", qx.ns)
        val y = r.attrs[1]
        assertEquals("", y.prefix)
        assertEquals("y", y.local)
        assertEquals("", y.ns)
        assertEquals(2, r.decls.size)
        assertEquals("", r.decls[0].prefix)
        assertEquals("d", r.decls[0].uri)
        assertEquals("q", r.decls[1].prefix)
        assertEquals("u", r.decls[1].uri)
        assertEquals(mapOf("" to "d", "q" to "u"), r.children[0].scope())
        // the xml prefix is bound by definition (xmldom, as the TS RIM verifier uses); declaring nothing, xml:lang still resolves
        val xl = AttestXml.parse("<a xml:lang=\"en\"><xml:b/></a>").root
        assertEquals("http://www.w3.org/XML/1998/namespace", xl.attrs[0].ns)
        assertEquals("http://www.w3.org/XML/1998/namespace", xl.children[0].ns)
        // and so an undeclared xml:lang is the profile violation, as a declared one is (it was a parse error before)
        assertEquals("xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)", AttestXml.parse("<a xml:lang=\"en\"/>").violation)
        // every XML white-space character separates; quotes of either kind; references decoded in values
        val w = AttestXml.parse("<a\tb\n=\r'x&amp;y'\nc = \"\" />").root
        assertEquals("a", w.name)
        assertEquals("x&y", w.attr("b"))
        assertEquals("", w.attr("c"))
        assertEquals(2, w.attrs.size)
        assertEquals("a=b", AttestXml.parse("<a v=\"a=b\"/>").root.attr("v"))
        assertEquals("'", AttestXml.parse("<a v=\"'\"/>").root.attr("v"))
        assertEquals(">", AttestXml.parse("<a v='>'/>").root.attr("v"))
        // a vertical tab is not XML white space: it stays in the name
        assertEquals("a\u000bb", AttestXml.parse("<a\u000bb/>").root.name)
    }

    @Test
    fun references() {
        assertEquals("plain", dec("plain"))
        assertEquals("", dec(""))
        assertEquals("<>&\"'", dec("&lt;&gt;&amp;&quot;&apos;"))
        assertEquals("xAyBz", dec("x&#65;y&#x42;z"))
        assertEquals("a;b", dec("a;b"))
        assertEquals("&", dec("&#38;"))
        val ok = listOf(0x9, 0xa, 0xd, 0x20, 0x41, 0xd7ff, 0xe000, 0xfffd, 0x10000, 0x10ffff)
        for (c in ok) {
            val want = String(Character.toChars(c))
            assertEquals("#x$c", want, dec("&#x" + Integer.toHexString(c) + ";"))
            assertEquals("#$c", want, dec("&#$c;"))
        }
        val bad = listOf(0x0, 0x1, 0x8, 0xb, 0xc, 0xe, 0x1f, 0xd800, 0xdfff, 0xfffe, 0xffff, 0x110000)
        for (c in bad) {
            val ent = "#x" + Integer.toHexString(c)
            assertEquals(ent, "ERR invalid character reference &$ent;", dec("&$ent;"))
        }
        // out of the Int range (would wrap to TAB / 'A'), negative, empty, not a number, upper-case X
        for (ent in listOf("#4294967305", "#4294967361", "#-4294967287", "#-4294967231", "#2147483648", "#-2147483648", "#-1", "#x", "#", "#xZZ", "#X41", "#99999999999999999999"))
            assertEquals(ent, "ERR invalid character reference &$ent;", dec("&$ent;"))
        // BRIEF cross-language check: a sign, a space or an overflow is no character reference; leading zeros are legal XML 1.0 (TS accepts)
        for (ent in listOf("#+65", "#-65", "#x+41", "# 65", "#99999999999"))
            assertEquals(ent, "ERR invalid character reference &$ent;", dec("&$ent;"))
        assertEquals("A", dec("&#000065;"))
        assertEquals("A", dec("&#x0041;"))
        assertEquals("ERR undefined entity &foo;", dec("&foo;"))
        assertEquals("ERR undefined entity &;", dec("&;"))
        assertEquals("ERR undefined entity &LT;", dec("&LT;"))
        assertEquals("ERR unterminated entity reference", dec("x&amp"))
        // the text path decodes, CDATA does not
        assertEquals("<A", AttestXml.parse("<a>&lt;&#65;</a>").root.textContent())
    }

    @Test
    fun canonicalForm() {
        val d = AttestXml.parse(
            "<r xmlns=\"urn:d\" xmlns:p=\"urn:p&amp;x\" b=\"2\" p:a=\"v&quot;&#9;&#10;&#13;&lt;&gt;&amp;'\" a=\"1\">" +
                "<p:c>t&amp;&lt;&gt;&#13;\"'\t\n</p:c><e/></r>",
        )
        val r = d.root
        val head = "<r xmlns=\"urn:d\" xmlns:p=\"urn:p&amp;x\" a=\"1\" b=\"2\" p:a=\"v&quot;&#x9;&#xA;&#xD;&lt;>&amp;'\">"
        val c = "<p:c>t&amp;&lt;&gt;&#xD;\"'\t\n</p:c>"
        assertEquals("$head$c<e></e></r>", AttestXml.canonicalize(r, emptyMap(), null))
        // the enveloped-signature transform drops the skipped subtree
        assertEquals("$head$c</r>", AttestXml.canonicalize(r, emptyMap(), r.children[1]))
        // an apex below the root renders every in-scope namespace
        assertEquals("<p:c xmlns=\"urn:d\" xmlns:p=\"urn:p&amp;x\">t&amp;&lt;&gt;&#xD;\"'\t\n</p:c>", AttestXml.canonicalize(r.children[0], r.scope(), null))
        // an inherited binding is not repeated on a child; an undeclared default (xmlns="") is not rendered at the apex
        assertEquals("<a><b></b></a>", AttestXml.canonicalize(AttestXml.parse("<a xmlns=\"\"><b/></a>").root, emptyMap(), null))
    }
}
