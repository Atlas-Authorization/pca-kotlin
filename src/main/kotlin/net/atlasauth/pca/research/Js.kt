package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentJs

/** JavaScript value semantics the research modules lean on (`String()`), over parsed JSON values. */
internal object Js {
    /** JavaScript `String(v)` for a JSON value. */
    fun str(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = IntentJs.num(v)
        if (d != null) return AttestUtil.jsNumString(d)
        if (v is List<*>) return v.joinToString(",") { if (it == null) "" else str(it) }
        return "[object Object]"
    }
}
