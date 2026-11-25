package net.atlasauth.pca.actions

/** The plain-language profile of one def: its policy card, the effective profile, and what a grant must carry before the action is auto-allowed. Deterministic text. */
object ActionExplain {
    private fun blastText(ppm: Long): String = if (ppm % 1000 == 0L) (ppm / 1000).toString() + "k" else ppm.toString() + "ppm"

    private fun join(xs: Any?): String = J.a(xs).joinToString(", ") { it as String }

    fun explainDef(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): String {
        val eff = ActionEffective.effective(d, reg, attestationVerified)
        val card = ActionDerive.cardOf(d, eff, reg)
        val e = J.m(eff["eff"])
        val confirmed = eff["confirmed"] == true
        val rev = e["rev"] as String
        val lines = ArrayList<String>()
        lines.add("" + card["text"])
        lines.add("effective: risk " + J.num(e["risk"])!!.toLong() + ", " + (if (rev == "irreversible") "irreversible" else if (rev == "rate_limited") "rate limited" else "reversible") +
            ", blast " + blastText(J.num(e["blast_ppm"])!!.toLong()) + ", escalation: " + card["escalation"])
        val needs = J.a(card["needs"])
        lines.add("grant must carry: " + (if (needs.isNotEmpty()) join(needs) else "nothing"))
        val ctx = J.a(card["context"])
        if (ctx.isNotEmpty()) lines.add("call must carry: " + join(ctx))
        val closure = join(eff["closure"])
        val state = J.get(d["review"], "state") as String?
        lines.add("traits: " + (if (closure.isEmpty()) "none" else closure))
        lines.add("review: " + (if (confirmed) state else state.toString() + ", not confirmed by a signed review"))
        if (!confirmed) {
            val h = J.m(eff["hint"])
            val hc = join(h["closure"])
            val he = J.m(h["eff"])
            lines.add("until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk " + J.num(he["risk"])!!.toLong() +
                ", escalation tier " + J.num(he["esc"])!!.toLong() + ", traits: " + (if (hc.isEmpty()) "none" else hc))
        }
        return lines.joinToString("\n")
    }
}
