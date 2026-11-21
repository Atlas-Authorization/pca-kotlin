package net.atlasauth.pca.signals

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json

/** JavaScript value semantics used by the signals port (member reads that throw on null, `??`, typeof checks, number printing). */
internal object JsV {
    fun num(o: Any?): Double? = Js.num(o)

    fun isFinite(o: Any?): Boolean = Js.isFinite(o)

    fun isNumber(o: Any?): Boolean = Js.isNumber(o)

    fun truthy(o: Any?): Boolean = Js.truthy(o)

    fun isSafeInteger(o: Any?): Boolean {
        val d = num(o)
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    fun nonEmpty(o: Any?): Boolean = o is String && o.isNotEmpty()

    /** `o[k]` that throws on null, as JavaScript does. */
    fun member(o: Any?, k: String): Any? = Js.member(o, k)

    /** `o?.[k]`. */
    fun opt(o: Any?, k: String): Any? = Js.get(o, k)

    /** The object carries the member (a JSON null counts as present). */
    fun has(o: Any?, k: String): Boolean = Js.own(o, k)

    fun or(a: Any?, b: Any?): Any? = a ?: b

    fun numOf(d: Double): Json.Num = if (d.isNaN() || d.isInfinite()) Json.Num(d.toString()) else Js.jsNum(d)

    fun str(v: Any?): String = Js.template(v)

    fun isSpace(c: Char): Boolean = c == ' ' || (c in '\t'..'\r') || c == ' ' || c == ' ' || (c in ' '..' ') ||
        c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿'
}
