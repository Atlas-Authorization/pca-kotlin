package net.atlasauth.pca.goal

import net.atlasauth.pca.goal.kernel.KCompile
import net.atlasauth.pca.goal.kernel.KDecide
import net.atlasauth.pca.goal.kernel.KDec
import net.atlasauth.pca.goal.kernel.KEnc
import net.atlasauth.pca.goal.kernel.KTypes
import net.atlasauth.pca.goal.kernel.Tok

/**
 * The goal compiler: typecheck, compileGoal, decideGoal, decidePolicy and renderTape over token tapes, hand-ported from the proved
 * model (the package `kernel` next to this file holds the IR, the tape decoders and encoders, the typing judgement, the lowering
 * and the decision functions). Token tapes are lists of `["k", n]`, `["i", n]` and `["s", text]`; the first output token is `i0`
 * ok, `i1` rejected with reasons, `i9` malformed input. All integers are exact (no floating point); anything that does not parse
 * is refused, never repaired.
 */
object GoalKernel {
    /** The kernel is part of the library; there is nothing to load. */
    @JvmStatic
    fun available(): Boolean = true

    private fun safe(v: Any?): Long = G.safeInt(v) ?: throw IrError("goal tape: " + G.jsStr(v) + " is not a safe integer")

    private fun toToks(tape: List<Any?>?): List<Tok> {
        val out = ArrayList<Tok>(tape?.size ?: 0)
        if (tape != null) for (o in tape) {
            val t = G.l(o)
            if (t == null || t.size != 2) throw IrError("goal tape: token expected")
            val v = t[1]
            when (t[0]) {
                "k" -> out.add(Tok.Kw(safe(v)))
                "i" -> out.add(Tok.I(safe(v)))
                "s" -> out.add(Tok.S(v as? String ?: throw IrError("goal tape: string token expected")))
                else -> throw IrError("goal tape: unknown token tag " + t[0])
            }
        }
        return out
    }

    private fun tok(tag: String, v: Any?): List<Any?> {
        val x = ArrayList<Any?>(2)
        x.add(tag)
        x.add(v)
        return x
    }

    private fun fromToks(ts: List<Tok>): List<Any?> = ts.map {
        when (it) {
            is Tok.Kw -> tok("k", G.num(it.k))
            is Tok.I -> tok("i", G.num(it.i))
            is Tok.S -> tok("s", it.s)
        }
    }

    private fun bad(): List<Tok> = listOf(Tok.I(9))

    private fun reasonsTape(rs: List<String>): MutableList<Tok> {
        val o = ArrayList<Tok>()
        o.add(Tok.I(1))
        KEnc.strs(o, rs)
        return o
    }

    private fun exec(op: String, goal: List<Any?>?, ont: List<Any?>?, act: List<Any?>?, hist: List<Any?>?): List<Tok> {
        when (op) {
            "typecheck", "compile", "render", "decideg", "decidep" -> {}
            else -> throw IllegalArgumentException("goal kernel: unknown op $op")
        }
        val gt = toToks(goal)
        val g = KDec.goal(gt)
        if (op == "render") return if (g == null) bad() else listOf<Tok>(Tok.I(0)) + KEnc.goal(g)
        val o = KDec.ontology(toToks(ont))
        if (op == "typecheck" || op == "compile") {
            if (g == null || o == null) return bad()
            if (op == "typecheck") {
                val rs = KTypes.reasons(o, g)
                return if (rs.isEmpty()) listOf(Tok.I(0)) else reasonsTape(rs)
            }
            val c = KCompile.compile(o, g)
            val p = c.policy ?: return reasonsTape(c.reasons)
            return listOf<Tok>(Tok.I(0)) + KCompile.encPol(p)
        }
        val a = KDec.act(toToks(act))
        val h = KDec.hist(toToks(hist))
        if (g == null || o == null || a == null || h == null) return bad()
        if (op == "decideg") return listOf(Tok.I(0), Tok.I(KDecide.dg(o, g, a, h).toLong()))
        val c = KCompile.compile(o, g)
        val p = c.policy ?: return reasonsTape(c.reasons)
        val w = KDecide.decideW(p, a, h)
        val out = ArrayList<Tok>()
        out.add(Tok.I(0)); out.add(Tok.I(w.decision.toLong())); out.add(Tok.S(w.gid))
        KEnc.strs(out, w.bids)
        out.add(Tok.I(if (w.decision == 2 && KDecide.verifyWitness(p, a, h, w)) 1L else 0L))
        return out
    }

    /**
     * One entry point over token tapes: op in typecheck, compile, decideg, decidep, render (act and hist are read by the decide ops).
     * First output token: i0 ok, i1 rejected with reasons, i9 malformed input.
     */
    @JvmStatic
    fun call(op: String, goal: List<Any?>?, ont: List<Any?>?, act: List<Any?>?, hist: List<Any?>?): List<Any?> =
        onBigStack {
            try {
                fromToks(exec(op, goal, ont, act, hist))
            } catch (e: StackOverflowError) {
                throw IrError("goal tape: nesting too deep")
            }
        }

    /** Runs [body] on a thread with a large stack, so a huge string or deep tape does not overflow the caller's (same guard as the Java kernel). */
    private fun <T> onBigStack(body: () -> T): T {
        var result: Any? = null
        var error: Throwable? = null
        val t = Thread(null, { try { result = body() } catch (e: Throwable) { error = e } }, "pca-goal-kernel", 1L shl 29)
        t.start()
        t.join()
        error?.let { throw it }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    // ---- the typed front door (compiler.ts) ----

    private fun first(t: List<Any?>): Long {
        val x = if (t.isEmpty()) null else G.l(t[0])
        if (x == null || x[0] != "i") throw IrError("malformed compiler output")
        return safe(x[1])
    }

    private fun at(t: List<Any?>, i: Int): Long = safe(G.l(t[i])!![1])

    private fun str(tok: Any?): String { val x = G.l(tok)!!; return if (x[0] == "s") x[1] as String else "" }

    private fun reasons(t: List<Any?>): List<String> {
        val n = if (t.size > 1) at(t, 1).toInt() else 0
        return t.subList(2, 2 + n).map { str(it) }
    }

    private fun decision(n: Long): String = if (n == 2L) "allow" else if (n == 1L) "escalate" else "deny"

    /** Type reasons of a goal against an ontology; empty = well typed. */
    @JvmStatic
    fun typecheck(goal: Map<String, Any?>, ont: Map<String, Any?>): List<String> {
        val out = call("typecheck", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), null, null)
        val s = first(out)
        if (s == 0L) return ArrayList()
        if (s == 1L) return reasons(out)
        throw IrError("compiler rejected the input tape")
    }

    /** C: Goal -> {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced. */
    @JvmStatic
    fun compileGoal(goal: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?> {
        val out = call("compile", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), null, null)
        val s = first(out)
        val r = LinkedHashMap<String, Any?>()
        if (s == 0L) { r["ok"] = true; r["policy"] = GoalCodec.decodePolicy(ArrayList(out.subList(1, out.size))); return r }
        if (s == 1L) { r["ok"] = false; r["reasons"] = ArrayList<Any?>(reasons(out)); return r }
        throw IrError("compiler rejected the input tape")
    }

    /** The reference semantics D_G(a, H): "allow" | "escalate" | "deny". */
    @JvmStatic
    fun decideGoal(goal: Map<String, Any?>, ont: Map<String, Any?>, act: Map<String, Any?>, hist: Map<String, Any?>): String {
        val out = call("decideg", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), GoalCodec.encodeAct(act), GoalCodec.encodeHist(hist))
        if (first(out) != 0L) throw IrError("compiler rejected the input tape")
        return decision(at(out, 1))
    }

    /** The compiled policy's decision: {ok: false, reasons} | {ok: true, decision, witness (null unless allow), witnessChecked}. */
    @JvmStatic
    fun decidePolicy(goal: Map<String, Any?>, ont: Map<String, Any?>, act: Map<String, Any?>, hist: Map<String, Any?>): Map<String, Any?> {
        val out = call("decidep", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), GoalCodec.encodeAct(act), GoalCodec.encodeHist(hist))
        val s = first(out)
        val r = LinkedHashMap<String, Any?>()
        if (s == 1L) { r["ok"] = false; r["reasons"] = ArrayList<Any?>(reasons(out)); return r }
        if (s != 0L) throw IrError("compiler rejected the input tape")
        val d = decision(at(out, 1))
        val n = at(out, 3).toInt()
        val bids = ArrayList<Any?>()
        for (x in out.subList(4, 4 + n)) bids.add(str(x))
        var w: Map<String, Any?>? = null
        if (d == "allow") { val m = LinkedHashMap<String, Any?>(); m["gid"] = str(out[2]); m["bids"] = bids; w = m }
        r["ok"] = true; r["decision"] = d; r["witness"] = w; r["witnessChecked"] = at(out, 4 + n) == 1L
        return r
    }

    /** The card as a token tape: `GoalCodec.decodeGoal(renderTape(g))` equals g. */
    @JvmStatic
    fun renderTape(goal: Map<String, Any?>): List<Any?> {
        val out = call("render", GoalCodec.encodeGoal(goal), null, null, null)
        if (first(out) != 0L) throw IrError("goal tape rejected")
        return ArrayList(out.subList(1, out.size))
    }

    /** The review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision. */
    @JvmStatic
    fun provedKernel(): GoalReview.ReviewKernel = object : GoalReview.ReviewKernel {
        override fun compile(goal: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?> = compileGoal(goal, ont)
        override fun policyDigest(policy: Map<String, Any?>): String = GoalCompiler.policyDigest(policy)
        override fun canDecide(): Boolean = true
        override fun decide(goal: Map<String, Any?>, ont: Map<String, Any?>, act: Map<String, Any?>, hist: Map<String, Any?>): String =
            decideGoal(goal, ont, act, hist)
    }

    // ---- harness text syntax (kN, iN, s<hex>.<hex>...) ----

    /** A tape in the differential-harness syntax. */
    @JvmStatic
    fun tapeToText(tape: List<Any?>): String {
        val sb = StringBuilder()
        for (o in tape) {
            val t = G.l(o)!!
            if (sb.isNotEmpty()) sb.append(' ')
            if (t[0] == "s") {
                sb.append('s')
                val s = t[1] as String
                var i = 0
                var firstCp = true
                while (i < s.length) {
                    val cp = s.codePointAt(i)
                    if (!firstCp) sb.append('.')
                    sb.append(Integer.toHexString(cp))
                    firstCp = false
                    i += Character.charCount(cp)
                }
            } else sb.append(t[0]).append(safe(t[1]))
        }
        return sb.toString()
    }

    /** Parse the differential-harness syntax. */
    @JvmStatic
    fun tapeFromText(s: String): List<Any?> {
        val out = ArrayList<Any?>()
        for (x in s.split(" ")) {
            if (x.isEmpty()) continue
            val b = x.substring(1)
            val c = x[0]
            if (c == 'k' || c == 'i') out.add(tok(c.toString(), G.num(b.toLong())))
            else if (c == 's') {
                val sb = StringBuilder()
                if (b.isNotEmpty()) for (h in b.split(".")) sb.appendCodePoint(h.toInt(16))
                out.add(tok("s", sb.toString()))
            } else throw IrError("goal tape text: bad token $x")
        }
        return out
    }
}
