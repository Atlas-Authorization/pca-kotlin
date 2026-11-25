package net.atlasauth.pca.actions

/**
 * Trait selectors and the registry-growth semantics. A selector is a positive predicate over the trait closure of an action.
 * Prohibit selectors float (they cover every present and future action that matches); allow selectors are pinned to a set of
 * verbs and may not use negation (the absence of a trait is never a safety claim). A selector is `{k: 'trait', id}`,
 * `{k: 'all_of'|'any_of', ids}`, `{k: 'not', s}` or `{k: 'and', a, b}`.
 */
object ActionSelectors {
    /** Does the selector match an action whose trait closure is `closure`? */
    fun selectorMatches(s: Any?, closure: Collection<Any?>): Boolean {
        val k = J.get(s, "k")
        if ("trait" == k) return closure.contains(J.get(s, "id"))
        if ("all_of" == k) { for (i in J.a(J.get(s, "ids"))) if (!closure.contains(i)) return false; return true }
        if ("any_of" == k) { for (i in J.a(J.get(s, "ids"))) if (closure.contains(i)) return true; return false }
        if ("not" == k) return !selectorMatches(J.get(s, "s"), closure)
        if ("and" == k) return selectorMatches(J.get(s, "a"), closure) && selectorMatches(J.get(s, "b"), closure)
        throw IllegalArgumentException("unknown selector kind")
    }

    /**
     * Does a selector of the given mode (`allow` or `prohibit`) match an action? An UNCONFIRMED action is maximally
     * dangerous: every prohibit selector matches it whatever it says, and no allow selector ever does.
     */
    fun selectorMatchesFor(s: Any?, mode: String, closure: Collection<Any?>, confirmed: Boolean): Boolean {
        if (!confirmed) return "prohibit" == mode
        return selectorMatches(s, closure)
    }

    fun selectorHasNot(s: Any?): Boolean {
        val k = J.get(s, "k")
        return "not" == k || ("and" == k && (selectorHasNot(J.get(s, "a")) || selectorHasNot(J.get(s, "b"))))
    }

    private fun anyOf(s: Any?): Boolean {
        val k = J.get(s, "k")
        return "any_of" == k || ("and" == k && (anyOf(J.get(s, "a")) || anyOf(J.get(s, "b"))))
    }

    /** The typing rule for an ALLOW selector: no negation anywhere, and any_of only inside a pinned allow. Null = allowed. */
    fun allowSelectorError(s: Any?, pinned: Boolean): String? {
        if (selectorHasNot(s)) return "an allow selector must not use negation: the absence of a trait is never a safety claim"
        if (!pinned && anyOf(s)) return "any_of in an allow selector requires the grant to be pinned to a pack digest"
        return null
    }

    /**
     * The policy component of the decision for one action: a matching prohibit denies; otherwise a pinned verb with a matching allow
     * is allowed; an unpinned verb is deny/escalate; a pinned verb with no allow is deny. `p` is
     * `{pinned, allow, prohibit, on_new_action?}`.
     */
    fun policyDecision(p: Map<String, Any?>, verb: String, closure: Collection<Any?>, confirmed: Boolean): String {
        for (s in J.a(p["prohibit"])) if (selectorMatchesFor(s, "prohibit", closure, confirmed)) return "deny"
        if (!J.a(p["pinned"]).contains(verb)) return if ("escalate" == p["on_new_action"]) "escalate" else "deny"
        for (s in J.a(p["allow"])) if (selectorMatchesFor(s, "allow", closure, confirmed)) return "allow"
        return "deny"
    }
}
