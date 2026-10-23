package net.atlasauth.pca.verifier

/**
 * The linear-time, budgeted regular-expression matcher of the predicate DSL (`re:` resources and the `matches`
 * operator), a port of packages/pca/src/safe-regex.ts and regex-budget.ts.
 *
 * A pattern is parsed ONCE by this parser into a Thompson NFA and run by a Pike-style simulation: O(|subject| x |NFA|),
 * no backtracking. SUBSET (anything else is refused, fail closed): literals; `.` (not a line terminator); classes `[...]`
 * / `[^...]` incl. `[]` (nothing) and `[^]` (any code unit), ranges and `\d \D \w \W \s \S` inside them; escapes
 * `\d \D \w \W \s \S \t \n \v \f \r \0 \xHH \uHHHH \cX` and escaped punctuation; groups `( )` and `(?: )`; alternation;
 * quantifiers `* + ? {n} {n,} {n,m}` with an optional lazy `?`; anchors `^ $`. Matching is over UTF-16 code units,
 * exactly like a flagless JS RegExp.
 *
 * The per-document work budget ([withBudget], [charge]) caps regex evaluations, source characters and NFA steps for one
 * predicate evaluation (64 / 8192 / 5,000,000), poisoning itself on the first refusal.
 */
object SafeRegex {
    const val MAX_NFA_INSTRUCTIONS = 4096
    const val MAX_REPEAT = 64
    const val MAX_MATCH_STEPS = 2_000_000L
    const val MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64
    const val MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192
    const val MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000L

    private const val SET = 0
    private const val SPLIT = 1
    private const val JMP = 2
    private const val BOL = 3
    private const val EOL = 4
    private const val MATCH = 5

    /** A set of UTF-16 code units: sorted, merged ranges, optionally negated. */
    internal class CharSet(val ranges: Array<IntArray>, val negated: Boolean) {
        fun has(c: Int): Boolean {
            var lo = 0
            var hi = ranges.size - 1
            var inside = false
            while (lo <= hi) {
                val mid = (lo + hi) shr 1
                val r = ranges[mid]
                if (c < r[0]) hi = mid - 1
                else if (c > r[1]) lo = mid + 1
                else { inside = true; break }
            }
            return inside != negated
        }
    }

    private fun r(a: Int, b: Int) = intArrayOf(a, b)
    private val DIGIT = arrayOf(r(0x30, 0x39))
    private val WORD = arrayOf(r(0x30, 0x39), r(0x41, 0x5a), r(0x5f, 0x5f), r(0x61, 0x7a))
    private val SPACE = arrayOf(
        r(0x09, 0x0d), r(0x20, 0x20), r(0xa0, 0xa0), r(0x1680, 0x1680), r(0x2000, 0x200a),
        r(0x2028, 0x2029), r(0x202f, 0x202f), r(0x205f, 0x205f), r(0x3000, 0x3000), r(0xfeff, 0xfeff),
    )
    private val LINE_TERMINATORS = arrayOf(r(0x0a, 0x0a), r(0x0d, 0x0d), r(0x2028, 0x2029))

    internal fun normalize(input: List<IntArray>): Array<IntArray> {
        val s = input.map { intArrayOf(it[0], it[1]) }.sortedBy { it[0] }
        val out = ArrayList<IntArray>()
        for (x in s) {
            val last = out.lastOrNull()
            if (last != null && x[0] <= last[1] + 1) last[1] = maxOf(last[1], x[1])
            else out.add(intArrayOf(x[0], x[1]))
        }
        return out.toTypedArray()
    }

    internal fun complement(rs: Array<IntArray>): Array<IntArray> {
        val out = ArrayList<IntArray>()
        var next = 0
        for (ab in normalize(rs.toList())) {
            if (ab[0] > next) out.add(intArrayOf(next, ab[0] - 1))
            next = ab[1] + 1
        }
        if (next <= 0xffff) out.add(intArrayOf(next, 0xffff))
        return out.toTypedArray()
    }

    // ---- AST ----
    private class Node(val k: Char) { // 's' set, '^' bol, '$' eol, 'c' cat, 'a' alt, 'r' rep
        var set: CharSet? = null
        var items: List<Node> = emptyList()
        var node: Node? = null
        var min = 0
        var max = 0.0 // Infinity for unbounded
    }

    private class Refuse(m: String) : RuntimeException(m, null, false, false)

    private val QUANT = Regex("^\\{(\\d{1,4})(?:(,)(\\d{0,4}))?\\}")

    /** After a backslash: the set, whether it is a class escape, and its single code unit (or -1). */
    private class Esc(val set: CharSet, val cls: Boolean, val ch: Int)

    private class Parser(val s: String) {
        var i = 0

        /** `s[i]` as a code unit, or -1 past the end (JS undefined). */
        fun at(k: Int): Int = if (k < s.length) s[k].code else -1

        fun parse(): Node {
            val n = alt()
            if (i < s.length) throw Refuse("unbalanced )")
            return n
        }

        fun alt(): Node {
            val items = ArrayList<Node>()
            items.add(cat())
            while (at(i) == '|'.code) { i++; items.add(cat()) }
            if (items.size == 1) return items[0]
            return Node('a').also { it.items = items }
        }

        fun cat(): Node {
            val items = ArrayList<Node>()
            while (i < s.length && s[i] != '|' && s[i] != ')') items.add(quantified())
            return Node('c').also { it.items = items }
        }

        fun quantified(): Node {
            val atom = atom()
            val c = at(i)
            val min: Int
            val max: Double
            when (c) {
                '*'.code -> { min = 0; max = Double.POSITIVE_INFINITY; i++ }
                '+'.code -> { min = 1; max = Double.POSITIVE_INFINITY; i++ }
                '?'.code -> { min = 0; max = 1.0; i++ }
                '{'.code -> {
                    val m = QUANT.find(s.substring(i, minOf(s.length, i + 16))) ?: throw Refuse("{ is not a well-formed quantifier")
                    min = m.groupValues[1].toInt()
                    max = if (m.groups[2] == null) min.toDouble()
                    else if (m.groupValues[3].isEmpty()) Double.POSITIVE_INFINITY else m.groupValues[3].toInt().toDouble()
                    if (max < min) throw Refuse("quantifier range out of order")
                    i += m.value.length
                }
                else -> return atom
            }
            if (atom.k == '^' || atom.k == '$') throw Refuse("nothing to repeat (assertion)")
            if ((max != Double.POSITIVE_INFINITY && max > MAX_REPEAT) || min > MAX_REPEAT) throw Refuse("repeat bound too large")
            if (at(i) == '?'.code) i++
            return Node('r').also { it.node = atom; it.min = min; it.max = max }
        }

        fun set(cs: CharSet): Node = Node('s').also { it.set = cs }

        fun atom(): Node {
            val c = s[i]
            when (c) {
                '(' -> {
                    i++
                    if (at(i) == '?'.code) {
                        if (at(i + 1) != ':'.code) throw Refuse("lookaround / named groups are not supported")
                        i += 2
                    }
                    val n = alt()
                    if (at(i) != ')'.code) throw Refuse("unterminated group")
                    i++
                    return n
                }
                '[' -> return cls()
                '.' -> { i++; return set(CharSet(LINE_TERMINATORS, true)) }
                '^' -> { i++; return Node('^') }
                '$' -> { i++; return Node('$') }
                '\\' -> return set(escapeInner(false).set)
                '*', '+', '?' -> throw Refuse("nothing to repeat")
                '{' -> throw Refuse("{ is not a well-formed quantifier")
                else -> {
                    i++
                    return set(CharSet(arrayOf(intArrayOf(c.code, c.code)), false))
                }
            }
        }

        fun single(code: Int): Esc = Esc(CharSet(arrayOf(intArrayOf(code, code)), false), false, code)

        fun escapeInner(inClass: Boolean): Esc {
            i++
            val c = at(i)
            if (c < 0) throw Refuse("trailing backslash")
            i++
            when (c.toChar()) {
                'd' -> return Esc(CharSet(DIGIT, false), true, -1)
                'D' -> return Esc(CharSet(DIGIT, true), true, -1)
                'w' -> return Esc(CharSet(WORD, false), true, -1)
                'W' -> return Esc(CharSet(WORD, true), true, -1)
                's' -> return Esc(CharSet(SPACE, false), true, -1)
                'S' -> return Esc(CharSet(SPACE, true), true, -1)
                't' -> return single(9)
                'n' -> return single(10)
                'v' -> return single(11)
                'f' -> return single(12)
                'r' -> return single(13)
                '0' -> {
                    val n = at(i)
                    if (n >= '0'.code && n <= '9'.code) throw Refuse("octal escape")
                    return single(0)
                }
                'x' -> {
                    if (i + 2 > s.length || !isHex(s, i, 2)) throw Refuse("bad \\x escape")
                    val v = s.substring(i, i + 2).toInt(16)
                    i += 2
                    return single(v)
                }
                'u' -> {
                    if (i + 4 > s.length || !isHex(s, i, 4)) throw Refuse("bad \\u escape")
                    val v = s.substring(i, i + 4).toInt(16)
                    i += 4
                    return single(v)
                }
                'c' -> {
                    val l = at(i)
                    if (!((l >= 'A'.code && l <= 'Z'.code) || (l >= 'a'.code && l <= 'z'.code))) throw Refuse("bad \\c escape")
                    i++
                    return single(l % 32)
                }
                'b' -> {
                    if (inClass) return single(8)
                    throw Refuse("word-boundary assertions are not supported")
                }
                else -> {
                    if ((c >= 'A'.code && c <= 'Z'.code) || (c >= 'a'.code && c <= 'z'.code) || (c >= '0'.code && c <= '9'.code) || c == '_'.code)
                        throw Refuse("escape \\" + c.toChar() + " is not supported")
                    return single(c)
                }
            }
        }

        fun cls(): Node {
            i++
            var negated = false
            if (at(i) == '^'.code) { negated = true; i++ }
            val ranges = ArrayList<IntArray>()
            while (true) {
                val c = at(i)
                if (c < 0) throw Refuse("unterminated class")
                if (c == ']'.code) { i++; break }
                val a = readAtom()
                if (at(i) == '-'.code && at(i + 1) >= 0 && at(i + 1) != ']'.code) {
                    i++
                    val b = readAtom()
                    if (a.cls || b.cls) {
                        for (x in a.set.ranges) ranges.add(intArrayOf(x[0], x[1]))
                        ranges.add(intArrayOf(0x2d, 0x2d))
                        for (x in b.set.ranges) ranges.add(intArrayOf(x[0], x[1]))
                    } else {
                        if (a.ch > b.ch) throw Refuse("class range out of order")
                        ranges.add(intArrayOf(a.ch, b.ch))
                    }
                } else {
                    for (x in a.set.ranges) ranges.add(intArrayOf(x[0], x[1]))
                }
            }
            return Node('s').also { it.set = CharSet(normalize(ranges), negated) }
        }

        /** A class atom; its `set` holds plain (already complemented) ranges. */
        fun readAtom(): Esc {
            val c = s[i].code
            if (c == '\\'.code) {
                val e = escapeInner(true)
                val rs = if (e.set.negated) complement(e.set.ranges) else e.set.ranges
                return Esc(CharSet(rs, false), e.cls, e.ch)
            }
            i++
            return Esc(CharSet(arrayOf(intArrayOf(c, c)), false), false, c)
        }
    }

    private fun isHex(s: String, from: Int, n: Int): Boolean {
        for (k in from until from + n) {
            val ch = s[k]
            if (!((ch in '0'..'9') || (ch in 'a'..'f') || (ch in 'A'..'F'))) return false
        }
        return true
    }

    // ---- compile ----
    internal class Inst(val op: Int, var x: Int, var y: Int, val set: CharSet?)

    /** A compiled NFA program. */
    class Compiled internal constructor(internal val program: Array<Inst>) {
        fun size(): Int = program.size
    }

    private fun emit(node: Node, prog: MutableList<Inst>) {
        if (prog.size > MAX_NFA_INSTRUCTIONS) throw Refuse("pattern too large")
        when (node.k) {
            's' -> prog.add(Inst(SET, 0, 0, node.set))
            '^' -> prog.add(Inst(BOL, 0, 0, null))
            '$' -> prog.add(Inst(EOL, 0, 0, null))
            'c' -> for (it in node.items) emit(it, prog)
            'a' -> {
                val jmps = ArrayList<Int>()
                for (i in node.items.indices) {
                    if (i < node.items.size - 1) {
                        val split = prog.size
                        prog.add(Inst(SPLIT, split + 1, -1, null))
                        emit(node.items[i], prog)
                        jmps.add(prog.size)
                        prog.add(Inst(JMP, -1, 0, null))
                        prog[split].y = prog.size
                    } else emit(node.items[i], prog)
                }
                for (j in jmps) prog[j].x = prog.size
            }
            else -> { // rep
                val sub = node.node!!
                for (i in 0 until node.min) emit(sub, prog)
                if (node.max == Double.POSITIVE_INFINITY) {
                    val split = prog.size
                    prog.add(Inst(SPLIT, split + 1, -1, null))
                    emit(sub, prog)
                    prog.add(Inst(JMP, split, 0, null))
                    prog[split].y = prog.size
                } else {
                    val splits = ArrayList<Int>()
                    var i = node.min
                    while (i < node.max) {
                        splits.add(prog.size)
                        prog.add(Inst(SPLIT, prog.size + 1, -1, null))
                        emit(sub, prog)
                        i++
                    }
                    for (sp in splits) prog[sp].y = prog.size
                }
                if (prog.size > MAX_NFA_INSTRUCTIONS) throw Refuse("pattern too large")
            }
        }
    }

    /** Compile `src`, or null when it is outside the subset or too large. Never throws. */
    fun compile(src: String?): Compiled? {
        if (src == null) return null
        return try {
            val ast = Parser(src).parse()
            val prog = ArrayList<Inst>()
            emit(ast, prog)
            prog.add(Inst(MATCH, 0, 0, null))
            if (prog.size > MAX_NFA_INSTRUCTIONS) null else Compiled(prog.toTypedArray())
        } catch (e: RuntimeException) {
            null
        } catch (e: StackOverflowError) {
            null
        }
    }

    /** Full-match `subject`: true / false, or null when the work budget would be exceeded. */
    fun run(re: Compiled, subject: String): Boolean? {
        val prog = re.program
        val n = subject.length
        if (prog.size.toLong() * (n + 1) > MAX_MATCH_STEPS) return null
        var clist = IntArray(prog.size)
        var nlist = IntArray(prog.size)
        val mark = IntArray(prog.size) { -1 }
        val stack = IntArray(prog.size * 2 + 2)
        val matched = booleanArrayOf(false)
        var gen = 1
        var cn = add(prog, stack, mark, gen, matched, clist, 0, 0, 0, n)
        for (pos in 0 until n) {
            val c = subject[pos].code
            gen++
            var nn = 0
            for (k in 0 until cn) {
                val pc = clist[k]
                if (prog[pc].set!!.has(c)) nn = add(prog, stack, mark, gen, matched, nlist, nn, pc + 1, pos + 1, n)
            }
            val t = clist; clist = nlist; nlist = t
            cn = nn
            if (cn == 0 && !matched[0]) return false
        }
        return matched[0]
    }

    private fun add(prog: Array<Inst>, stack: IntArray, mark: IntArray, gen: Int, matched: BooleanArray, list: IntArray, count0: Int, pc0: Int, pos: Int, n: Int): Int {
        var count = count0
        var sp = 0
        stack[sp++] = pc0
        while (sp > 0) {
            val pc = stack[--sp]
            if (mark[pc] == gen) continue
            mark[pc] = gen
            val ins = prog[pc]
            when (ins.op) {
                JMP -> stack[sp++] = ins.x
                SPLIT -> { stack[sp++] = ins.y; stack[sp++] = ins.x }
                BOL -> if (pos == 0) stack[sp++] = pc + 1
                EOL -> if (pos == n) stack[sp++] = pc + 1
                MATCH -> if (pos == n) matched[0] = true
                else -> list[count++] = pc
            }
        }
        return count
    }

    /** `new RegExp('^(?:' + src + ')$').test(subject)` over the subset; null when refused or over budget. */
    fun fullMatch(src: String?, subject: String): Boolean? {
        val re = compile(src) ?: return null
        return run(re, subject)
    }

    // ---- the safe-source guard (predicates.ts isSafeRegexSource) ----
    private const val MAX_REGEX_COST_BITS = 22
    private const val UNBOUNDED_QUANTIFIER_BITS = 8
    private const val MAX_BOUNDED_REPEAT = 64
    private val GUARD_QUANT = Regex("^\\{(\\d+)(?:(,)(\\d*))?\\}")

    private class Frame { var hasQuant = false; var hasAlt = false }

    /**
     * The linear-time-safe subset guard: no quantified group containing a quantifier or an alternation, no
     * backreferences / lookaround / named groups, bounded repeats at most 64, a 22-bit backtracking-cost budget, and the
     * source must compile in [compile].
     */
    fun isSafeSource(src: String?): Boolean {
        if (src == null) return false
        val stack = ArrayList<Frame>()
        stack.add(Frame())
        var prev: Any? = null // null = none, true = atom, Frame = a closed group
        var bits = 0
        var i = 0
        while (i < src.length) {
            val ch = src[i]
            if (ch == '\\') {
                if (i + 1 >= src.length) return false
                val n = src[i + 1]
                if ((n in '1'..'9') || n == 'k') return false
                i += 2
                prev = true
                continue
            }
            if (ch == '[') {
                var j = i + 1
                if (j < src.length && src[j] == '^') j++
                while (j < src.length && src[j] != ']') { if (src[j] == '\\') j++; j++ }
                if (j >= src.length) return false
                i = j + 1
                prev = true
                continue
            }
            if (ch == '(') {
                if (i + 1 < src.length && src[i + 1] == '?') {
                    if (!(i + 2 < src.length && src[i + 2] == ':')) return false
                    i += 3
                } else i += 1
                stack.add(Frame())
                prev = null
                continue
            }
            if (ch == ')') {
                if (stack.size < 2) return false
                val f = stack.removeAt(stack.size - 1)
                val parent = stack[stack.size - 1]
                parent.hasQuant = parent.hasQuant or f.hasQuant
                parent.hasAlt = parent.hasAlt or f.hasAlt
                prev = f
                i++
                continue
            }
            if (ch == '|') {
                if (++bits > MAX_REGEX_COST_BITS) return false
                stack[stack.size - 1].hasAlt = true
                prev = null
                i++
                continue
            }
            var isQ = false
            var unbounded = false
            var len = 0
            var max = 0.0
            var options = 0.0
            if (ch == '*' || ch == '+') { isQ = true; len = 1; unbounded = true; max = Double.POSITIVE_INFINITY; options = Double.POSITIVE_INFINITY }
            else if (ch == '?') { isQ = true; len = 1; max = 1.0; options = 2.0 }
            else if (ch == '{') {
                val m = GUARD_QUANT.find(src.substring(i)) ?: return false
                val lo = m.groupValues[1].toDouble()
                val hasComma = m.groups[2] != null
                val hi = if (!hasComma) lo else if (m.groupValues[3].isEmpty()) Double.POSITIVE_INFINITY else m.groupValues[3].toDouble()
                if (hi < lo) return false
                isQ = true
                len = m.value.length
                unbounded = hi == Double.POSITIVE_INFINITY
                max = hi
                options = if (hi == Double.POSITIVE_INFINITY) Double.POSITIVE_INFINITY else hi - lo + 1
            }
            if (isQ) {
                if (prev == null) return false
                if (prev is Frame && (prev.hasQuant || prev.hasAlt)) return false
                if (!unbounded && max != Double.POSITIVE_INFINITY && max > MAX_BOUNDED_REPEAT) return false
                bits += if (unbounded) UNBOUNDED_QUANTIFIER_BITS else if (options > 1) ceilLog2(options.toLong()) else 0
                if (bits > MAX_REGEX_COST_BITS) return false
                stack[stack.size - 1].hasQuant = true
                i += len
                if (i < src.length && src[i] == '?') i++
                prev = null
                continue
            }
            i++
            prev = true
        }
        return stack.size == 1 && compile(src) != null
    }

    /** `Math.ceil(Math.log2(n))` for an integer n >= 2, computed exactly. */
    internal fun ceilLog2(n: Long): Int = 64 - java.lang.Long.numberOfLeadingZeros(n - 1)

    // ---- per-document budget (regex-budget.ts) ----
    /** One document's regex work budget. */
    internal class Budget {
        var evaluations = 0
        var chars = 0
        var steps = 0L
        var refusals = 0

        fun charge(src: String, subjectLen: Int): Boolean {
            val c = compile(src)
            if (c == null) { refusals++; return false }
            val ev = evaluations + 1
            val ch = chars + src.length
            val st = steps + c.size().toLong() * (subjectLen + 1)
            if (ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT || ch > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT || st > MAX_REGEX_STEPS_PER_DOCUMENT) {
                evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1 // poison: order-independent refusal
                refusals++
                return false
            }
            evaluations = ev
            chars = ch
            steps = st
            return true
        }
    }

    private val CURRENT = ThreadLocal<Budget?>()

    /** Run `fn` inside the open document budget, or a fresh one when none is open (withRegexBudget). */
    internal fun <T> withBudget(fn: () -> T): T {
        if (CURRENT.get() != null) return fn()
        CURRENT.set(Budget())
        try {
            return fn()
        } finally {
            CURRENT.remove()
        }
    }

    /** Charge one evaluation of `src` against a subject of `subjectLen` code units (chargeRegex). */
    internal fun charge(src: String, subjectLen: Int): Boolean = (CURRENT.get() ?: Budget()).charge(src, subjectLen)
}
