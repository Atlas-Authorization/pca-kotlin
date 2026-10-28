package net.atlasauth.pca.verifier

/**
 * A small XML reader and a canonicaliser (inclusive C14N; identical to C14N 1.1 for documents without `xml:*` attributes, which
 * the RIM profile refuses) for the NVIDIA RIM XMLDSig check. Only the subset the profile needs is supported: elements, attributes,
 * namespaces, text, CDATA and the predefined and numeric character references. A comment, processing instruction or DOCTYPE is not
 * interpreted: the first of them (in document order) is recorded as a profile violation, and the verifier refuses the document
 * before any cryptography.
 */
internal object AttestXml {
    class Attr(val name: String, val prefix: String, val local: String, var ns: String, val value: String)

    class Decl(val prefix: String, val uri: String)

    class Node(val elem: Boolean, val name: String = "", var text: String = "") {
        var prefix = ""
        var local = ""
        var ns = ""
        val attrs = ArrayList<Attr>()
        val decls = ArrayList<Decl>()
        val children = ArrayList<Node>()
        var parent: Node? = null

        /** Resolves a prefix (`""` is the default namespace) through the element's ancestors; null when unbound. */
        fun lookupNs(prefix: String): String? {
            var e: Node? = this
            while (e != null) {
                for (d in e.decls) if (d.prefix == prefix) return d.uri
                e = e.parent
            }
            return null
        }

        fun attr(name: String): String = attrs.firstOrNull { it.name == name }?.value ?: ""

        fun textContent(): String {
            if (!elem) return text
            val sb = StringBuilder()
            for (c in children) sb.append(c.textContent())
            return sb.toString()
        }

        fun elementChildren(): List<Node> = children.filter { it.elem }

        fun elementChildrenNs(ns: String, local: String): List<Node> = elementChildren().filter { it.ns == ns && it.local == local }

        /** Counts the descendant elements with the given namespace and local name. */
        fun descendantsNs(ns: String, local: String): Int {
            var total = 0
            for (c in elementChildren()) {
                if (c.ns == ns && c.local == local) total++
                total += c.descendantsNs(ns, local)
            }
            return total
        }

        /** The in-scope namespace bindings of the element (its own declarations included). */
        fun scope(): Map<String, String> {
            val chain = ArrayList<Node>()
            var e: Node? = this
            while (e != null) {
                chain.add(e)
                e = e.parent
            }
            val out = LinkedHashMap<String, String>()
            for (i in chain.size - 1 downTo 0) for (d in chain[i].decls) out[d.prefix] = d.uri
            return out
        }

        fun appendText(t: String) {
            val k = children.size
            if (k > 0 && !children[k - 1].elem) {
                children[k - 1].text += t
                return
            }
            val n = Node(false, "", t)
            n.parent = this
            children.add(n)
        }

        fun resolveNames() {
            val i = name.indexOf(':')
            prefix = if (i >= 0) name.substring(0, i) else ""
            local = if (i >= 0) name.substring(i + 1) else name
            val uri = lookupNs(prefix)
            if (prefix != "" && uri == null) throw AttErr("namespace prefix $prefix is not bound")
            ns = uri ?: ""
            for (a in attrs) {
                if (a.prefix == "") continue
                a.ns = lookupNs(a.prefix) ?: throw AttErr("namespace prefix ${a.prefix} is not bound")
            }
        }
    }

    class Doc(val root: Node, val violation: String)

    private fun isXmlSpace(c: Char): Boolean = c == ' ' || c == '\t' || c == '\n' || c == '\r'

    private fun decode(s: String): String {
        if (!s.contains('&')) return s
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            if (s[i] != '&') {
                sb.append(s[i])
                i++
                continue
            }
            val j = s.indexOf(';', i)
            if (j < 0) throw AttErr("unterminated entity reference")
            val ent = s.substring(i + 1, j)
            i = j + 1
            when (ent) {
                "lt" -> sb.append('<')
                "gt" -> sb.append('>')
                "amp" -> sb.append('&')
                "quot" -> sb.append('"')
                "apos" -> sb.append('\'')
                else -> {
                    if (!ent.startsWith("#")) throw AttErr("undefined entity &$ent;")
                    val n: Long? = if (ent.startsWith("#x")) ent.substring(2).toLongOrNull(16) else ent.substring(1).toLongOrNull(10)
                    val r = if (n != null && n >= Int.MIN_VALUE && n <= Int.MAX_VALUE) n.toInt() else -1
                    if (n == null || !(r == 0x9 || r == 0xa || r == 0xd || (r in 0x20..0xd7ff) || (r in 0xe000..0xfffd) || (r in 0x10000..0x10ffff)))
                        throw AttErr("invalid character reference &$ent;")
                    sb.appendCodePoint(r)
                }
            }
        }
        return sb.toString()
    }

    fun parse(s: String): Doc {
        var violation = ""
        fun note(v: String) {
            if (violation == "") violation = v
        }
        var root: Node? = null
        var cur: Node? = null
        var i = 0
        while (i < s.length) {
            if (s[i] != '<') {
                var end = s.indexOf('<', i)
                if (end < 0) end = s.length
                val txt = s.substring(i, end)
                i = end
                if (cur == null) {
                    if (txt.any { !(it.code < 0x80 && isXmlSpace(it)) }) throw AttErr("text outside the document element")
                    continue
                }
                cur.appendText(decode(txt))
                continue
            }
            val rest = s.substring(i)
            when {
                rest.startsWith("<!--") -> {
                    val j = rest.indexOf("-->", 4)
                    if (j < 0) throw AttErr("unterminated comment")
                    note("XML comments are not permitted")
                    i += j + 3
                }
                rest.startsWith("<?") -> {
                    val j = rest.indexOf("?>")
                    if (j < 0) throw AttErr("unterminated processing instruction")
                    note("XML processing instructions are not permitted")
                    i += j + 2
                }
                rest.startsWith("<![CDATA[") -> {
                    val j = rest.indexOf("]]>")
                    if (j < 0 || cur == null) throw AttErr("misplaced or unterminated CDATA section")
                    cur.appendText(rest.substring(9, j))
                    i += j + 3
                }
                rest.startsWith("<!DOCTYPE") -> {
                    var depth = 0
                    var j = 0
                    while (j < rest.length) {
                        val ch = rest[j]
                        if (ch == '[') depth++
                        else if (ch == ']') depth--
                        else if (ch == '>' && depth <= 0) break
                        j++
                    }
                    if (j >= rest.length) throw AttErr("unterminated DOCTYPE")
                    note("DTD / DOCTYPE is not permitted")
                    i += j + 1
                }
                rest.startsWith("</") -> {
                    val j = rest.indexOf('>')
                    if (j < 0 || cur == null) throw AttErr("unexpected end tag")
                    val name = rest.substring(2, j).trimEnd(' ', '\t', '\r', '\n')
                    if (name != cur.name) throw AttErr("end tag </$name> does not match <${cur.name}>")
                    cur = cur.parent
                    i += j + 1
                }
                else -> {
                    val st = parseStartTag(rest, ::note)
                    i += st.consumed
                    val node = st.node
                    node.parent = cur
                    if (cur == null) {
                        if (root != null) throw AttErr("more than one document element")
                        root = node
                    } else cur.children.add(node)
                    node.resolveNames()
                    if (!st.selfClose) cur = node
                }
            }
        }
        if (cur != null) throw AttErr("element <${cur.name}> is not closed")
        if (root == null) throw AttErr("no document element")
        return Doc(root, violation)
    }

    private class StartTag(val node: Node, val selfClose: Boolean, val consumed: Int)

    /** Reads one start tag at the beginning of `rest`. */
    private fun parseStartTag(rest: String, note: (String) -> Unit): StartTag {
        var i = 1
        var j = i
        while (j < rest.length && !isXmlSpace(rest[j]) && rest[j] != '/' && rest[j] != '>') j++
        val name = rest.substring(i, j)
        if (name.isEmpty()) throw AttErr("malformed start tag")
        val node = Node(true, name)
        val seen = HashSet<String>()
        i = j
        while (true) {
            while (i < rest.length && isXmlSpace(rest[i])) i++
            if (i >= rest.length) throw AttErr("unterminated start tag")
            if (rest[i] == '>') return StartTag(node, false, i + 1)
            if (rest[i] == '/') {
                if (i + 1 < rest.length && rest[i + 1] == '>') return StartTag(node, true, i + 2)
                throw AttErr("malformed start tag")
            }
            var k = i
            while (k < rest.length && !isXmlSpace(rest[k]) && rest[k] != '=' && rest[k] != '>' && rest[k] != '/') k++
            val aname = rest.substring(i, k)
            while (k < rest.length && isXmlSpace(rest[k])) k++
            if (aname.isEmpty() || k >= rest.length || rest[k] != '=') throw AttErr("malformed attribute")
            k++
            while (k < rest.length && isXmlSpace(rest[k])) k++
            if (k >= rest.length || (rest[k] != '"' && rest[k] != '\'')) throw AttErr("unquoted attribute value")
            val q = rest[k]
            val e = rest.indexOf(q, k + 1)
            if (e < 0) throw AttErr("unterminated attribute value")
            val raw = rest.substring(k + 1, e)
            if (raw.contains('<')) throw AttErr("'<' in an attribute value")
            val value = decode(raw)
            i = e + 1
            if (!seen.add(aname)) throw AttErr("attribute $aname is repeated")
            if (aname.lowercase().startsWith("xml:")) note("xml:* attribute '$aname' is not permitted (C14N 1.1 profile)")
            if (aname == "xmlns") node.decls.add(Decl("", value))
            else if (aname.startsWith("xmlns:")) node.decls.add(Decl(aname.substring(6), value))
            else {
                val c = aname.indexOf(':')
                node.attrs.add(Attr(aname, if (c >= 0) aname.substring(0, c) else "", if (c >= 0) aname.substring(c + 1) else aname, "", value))
            }
        }
    }

    private fun escapeText(s: String): String {
        val sb = StringBuilder()
        for (r in s) when (r) {
            '&' -> sb.append("&amp;")
            '<' -> sb.append("&lt;")
            '>' -> sb.append("&gt;")
            '\r' -> sb.append("&#xD;")
            else -> sb.append(r)
        }
        return sb.toString()
    }

    private fun escapeAttr(s: String): String {
        val sb = StringBuilder()
        for (r in s) when (r) {
            '&' -> sb.append("&amp;")
            '<' -> sb.append("&lt;")
            '"' -> sb.append("&quot;")
            '\t' -> sb.append("&#x9;")
            '\n' -> sb.append("&#xA;")
            '\r' -> sb.append("&#xD;")
            else -> sb.append(r)
        }
        return sb.toString()
    }

    /**
     * The inclusive canonical form of the subtree at `n`, omitting the subtree `skip` (the enveloped-signature transform).
     * `parentScope` is the in-scope bindings of n's ancestors: an apex element renders every in-scope namespace.
     */
    fun canonicalize(n: Node, parentScope: Map<String, String>, skip: Node?): String {
        val sb = StringBuilder()
        c14nElement(sb, n, parentScope, HashMap(), skip)
        return sb.toString()
    }

    private fun c14nElement(sb: StringBuilder, n: Node, parentScope: Map<String, String>, rendered: Map<String, String>, skip: Node?) {
        val scope = HashMap<String, String>(parentScope)
        for (d in n.decls) scope[d.prefix] = d.uri
        val emit = ArrayList<String>()
        for ((p, uri) in scope) {
            if (p == "xml" || (uri == "" && p != "")) continue
            if ((rendered[p] ?: "") == uri) continue
            emit.add(p)
        }
        emit.sort()
        val newRendered = HashMap<String, String>(rendered)
        sb.append("<").append(n.name)
        for (p in emit) {
            val uri = scope.getValue(p)
            if (p == "") sb.append(" xmlns=\"").append(escapeAttr(uri)).append("\"")
            else sb.append(" xmlns:").append(p).append("=\"").append(escapeAttr(uri)).append("\"")
            newRendered[p] = uri
        }
        val attrs = n.attrs.sortedWith { a, b ->
            if ((a.ns == "") != (b.ns == "")) (if (a.ns == "") -1 else 1)
            else Json.compareUtf8(a.ns + a.local, b.ns + b.local)
        }
        for (a in attrs) sb.append(" ").append(a.name).append("=\"").append(escapeAttr(a.value)).append("\"")
        sb.append(">")
        for (c in n.children) {
            if (c === skip) continue
            if (c.elem) c14nElement(sb, c, scope, newRendered, skip) else sb.append(escapeText(c.text))
        }
        sb.append("</").append(n.name).append(">")
    }
}
