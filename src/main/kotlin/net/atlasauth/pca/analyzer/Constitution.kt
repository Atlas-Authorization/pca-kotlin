package net.atlasauth.pca.analyzer

/** A constitution's stateless invariants in analyzable (veto) form. */
object Constitution {
    /**
     * Turn a constitution into analyzer vetoes: `{vetoes, unmodeled}`. `never` / `never_unless` / `require_approval_over` become
     * vetoes; `cap` / `rate` are bounded by maxExposure instead, and every other kind needs history, so both are listed in `unmodeled`.
     */
    fun vetoesFromConstitution(c: Any?): Map<String, Any?> {
        val vetoes = ArrayList<Any?>()
        val unmodeled = ArrayList<Any?>()
        val invs = AJs.get(c, "invariants")
        if (invs is List<*>) {
            for (inv in invs) {
                if (inv == null) throw IllegalArgumentException("invariant is null")
                val kind = AJs.get(inv, "kind")
                val k = if (kind is String) kind else ""
                when (k) {
                    "never" -> {
                        val v = AJs.obj()
                        AJs.putIf(v, "id", inv, "id")
                        v["kind"] = "deny"
                        AJs.putIf(v, "when", inv, "when")
                        vetoes.add(v)
                    }
                    "never_unless" -> {
                        val v = AJs.obj()
                        AJs.putIf(v, "id", inv, "id")
                        v["kind"] = "deny"
                        AJs.putIf(v, "when", inv, "when")
                        AJs.putIf(v, "unless", inv, "unless")
                        vetoes.add(v)
                    }
                    "require_approval_over" -> {
                        val v = AJs.obj()
                        AJs.putIf(v, "id", inv, "id")
                        v["kind"] = "approval"
                        AJs.putIf(v, "when", inv, "when")
                        val over = AJs.obj()
                        AJs.putIf(over, "path", inv, "amount")
                        AJs.putIf(over, "threshold", inv, "threshold")
                        v["over"] = over
                        AJs.putIf(v, "unless", inv, "approved")
                        vetoes.add(v)
                    }
                    "cap", "rate" -> {
                        val u = AJs.obj()
                        AJs.putIf(u, "id", inv, "id")
                        u["kind"] = k
                        u["reason"] = "windowed total: bounded by maxExposure, not by a per-action veto"
                        unmodeled.add(u)
                    }
                    else -> {
                        val u = AJs.obj()
                        AJs.putIf(u, "id", inv, "id")
                        AJs.putIf(u, "kind", inv, "kind")
                        u["reason"] = "needs action history"
                        unmodeled.add(u)
                    }
                }
            }
        }
        return AJs.obj("vetoes", vetoes, "unmodeled", unmodeled)
    }
}
