package net.atlasauth.pca.actions

/** The restricted resource id grammar: matching and (decidable) containment between two patterns. A pattern is `"*"`, `{exact}` or `{prefix, class, len}`. */
object ActionIdPattern {
    private const val DIGITS = "0123456789"
    private const val HEXLC = DIGITS + "abcdef"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val ALNUM = DIGITS + LOWER + UPPER
    private val UUID_RE = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private const val MAX_ID_LEN = 128

    /** The character set of an id class (digits, hex, alnum, slug, uuid, any_safe). */
    fun idClassChars(c: String): String = when (c) {
        "digits" -> DIGITS
        "hex" -> HEXLC
        "alnum" -> ALNUM
        "slug" -> DIGITS + LOWER + "-_"
        "uuid" -> "$HEXLC-"
        "any_safe" -> "$ALNUM._-:/"
        else -> throw IllegalArgumentException("unknown id class $c")
    }

    private fun inClass(s: String, c: String): Boolean {
        val set = idClassChars(c)
        for (ch in s) if (set.indexOf(ch) < 0) return false
        return true
    }

    private fun isExact(p: Any?): Boolean = p is Map<*, *> && p.containsKey("exact")

    /** Does `id` (the id part of a resource, without the type) match the pattern? */
    fun idMatches(p: Any?, id: String): Boolean {
        if ("*" == p) return id.isNotEmpty() && id.length <= MAX_ID_LEN && inClass(id, "any_safe")
        if (isExact(p)) return id == J.get(p, "exact")
        val prefix = J.get(p, "prefix") as String
        if (!id.startsWith(prefix)) return false
        val rest = id.substring(prefix.length)
        val len = J.a(J.get(p, "len"))
        if (rest.length < J.num(len[0])!! || rest.length > J.num(len[1])!!) return false
        val cls = J.get(p, "class") as String
        if (cls == "uuid") return UUID_RE.matches(rest)
        return inClass(rest, cls)
    }

    private fun classSubset(a: String, b: String): Boolean {
        val sa = idClassChars(a)
        val sb = idClassChars(b)
        for (ch in sa) if (sb.indexOf(ch) < 0) return false
        return true
    }

    /** Is every id matched by `inner` also matched by `outer`? */
    fun idPatternContains(outer: Any?, inner: Any?): Boolean {
        if ("*" == outer) return true
        if ("*" == inner) return false
        if (isExact(outer)) return isExact(inner) && J.get(inner, "exact") == J.get(outer, "exact")
        if (isExact(inner)) return idMatches(outer, J.get(inner, "exact") as String)
        val ip = J.get(inner, "prefix") as String
        val op = J.get(outer, "prefix") as String
        if (!ip.startsWith(op)) return false
        val r = ip.substring(op.length)
        val oc = J.get(outer, "class") as String
        val ic = J.get(inner, "class") as String
        if (!inClass(r, oc)) return false
        if (oc == "uuid") return ic == "uuid" && r.isEmpty()
        if (!classSubset(ic, oc)) return false
        val ol = J.a(J.get(outer, "len"))
        val il = J.a(J.get(inner, "len"))
        return r.length + J.num(il[0])!! >= J.num(ol[0])!! && r.length + J.num(il[1])!! <= J.num(ol[1])!!
    }
}
