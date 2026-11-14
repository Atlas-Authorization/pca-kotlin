package net.atlasauth.pca.verifier

/**
 * The connector catalog the facade compiles `permissions` against: each action's PCA verb, reversibility class, blast radius and
 * (for money-moving actions) the params field that carries the amount, plus the other names it answers to. This is data, not
 * enforcement: the resource server's verifier stays authoritative.
 *
 * [BUILTIN] is the reference's 21 built-in actions with their EFFECTIVE reversibility and blast radius. Generated data: do not edit
 * by hand (a test compares it with the reference catalog).
 */
class Catalog(specs: List<Spec>) {
    /** One catalogued action. [amountField] is null for an action that moves no money. */
    class Spec(
        val connector: String,
        val action: String,
        val verb: String,
        val reversibility: String,
        val blastRadius: Double,
        val amountField: String?,
        val description: String,
        val aliases: List<String> = emptyList(),
        val traits: List<String> = emptyList(),
    )

    private val byVerb = LinkedHashMap<String, Spec>().also { m -> for (s in specs) m[s.verb] = s } // a later spec with the same verb wins

    /** The spec of a verb (`connector.action`), or null. */
    fun get(verb: String): Spec? = byVerb[verb]

    fun all(): List<Spec> = ArrayList(byVerb.values)

    /** The exact verb, else the one action of [connector] that lists [action] as an alias (never a guess: two hits are none). */
    fun resolve(connector: String, action: String): Spec? {
        byVerb["$connector.$action"]?.let { return it }
        val hits = byVerb.values.filter { it.connector == connector && action in it.aliases }
        return if (hits.size == 1) hits[0] else null
    }

    companion object {
        // BEGIN GENERATED (the reference's built-in catalog)
        val BUILTIN: List<Spec> = listOf(
            Spec("stripe", "charge", "stripe.charge", "irreversible", 0.9, "amount", "Charge a customer. Refundable in practice, but a charge is treated as final.", listOf("bill", "charge_customer"), listOf("pca.irreversible", "pca.money_moving")),
            Spec("stripe", "refund", "stripe.refund", "irreversible", 0.9, "amount", "Returns money for a charge to the customer.", listOf("issue_refund", "refund", "refund_charge", "reimburse"), listOf("pca.irreversible", "pca.money_moving")),
            Spec("stripe", "payout", "stripe.payout", "irreversible", 0.9, "amount", "Moves funds from a Stripe balance to a bank account.", listOf("pay_out", "payout"), listOf("pca.irreversible", "pca.money_moving")),
            Spec("stripe", "create_customer", "stripe.create_customer", "rate_limited", 0.2, null, "Creates a customer record.", listOf(), listOf("pca.pii_access")),
            Spec("gmail", "send", "gmail.send", "irreversible", 0.8, null, "Sends an email to people outside your organisation.", listOf("send_email"), listOf("pca.external_communication", "pca.irreversible", "pca.pii_access")),
            Spec("gmail", "draft", "gmail.draft", "reversible", 0.2, null, "Saves an email draft without sending it.", listOf(), listOf("pca.pii_access")),
            Spec("gmail", "delete", "gmail.delete", "irreversible", 0.8, null, "Permanently deletes a message.", listOf(), listOf("pca.destructive", "pca.irreversible")),
            Spec("github", "read", "github.read", "reversible", 0.05, null, "Reads files from a repository.", listOf(), listOf()),
            Spec("github", "create_pr", "github.create_pr", "irreversible", 0.2, null, "Opens a pull request, which is visible to everyone with access to the repository.", listOf(), listOf("pca.external_communication", "pca.irreversible")),
            Spec("github", "comment", "github.comment", "irreversible", 0.2, null, "Posts a comment, visible to everyone with access to the repository.", listOf(), listOf("pca.external_communication", "pca.irreversible")),
            Spec("github", "merge_pr", "github.merge_pr", "irreversible", 0.5, null, "Merges a pull request, which can trigger deploys and other downstream effects.", listOf(), listOf("pca.irreversible")),
            Spec("github", "delete_repo", "github.delete_repo", "irreversible", 0.8, null, "Deletes a repository and everything in it.", listOf(), listOf("pca.destructive", "pca.irreversible")),
            Spec("slack", "post_message", "slack.post_message", "irreversible", 0.5, null, "Posts a message that members of the channel can read.", listOf(), listOf("pca.bulk", "pca.external_communication", "pca.irreversible")),
            Spec("slack", "read", "slack.read", "reversible", 0.05, null, "Reads the message history of a channel.", listOf(), listOf()),
            Spec("calendar", "create_event", "calendar.create_event", "irreversible", 0.2, null, "Creates an event and sends invitations to its attendees.", listOf(), listOf("pca.external_communication", "pca.irreversible", "pca.pii_access")),
            Spec("calendar", "delete_event", "calendar.delete_event", "rate_limited", 0.5, null, "Deletes a calendar event.", listOf(), listOf("pca.destructive")),
            Spec("files", "read", "files.read", "reversible", 0.05, null, "Reads files.", listOf(), listOf("pca.bulk")),
            Spec("files", "write", "files.write", "rate_limited", 0.5, null, "Writes or overwrites files.", listOf(), listOf("pca.bulk")),
            Spec("files", "delete", "files.delete", "irreversible", 0.8, null, "Deletes files.", listOf(), listOf("pca.bulk", "pca.destructive", "pca.irreversible")),
            Spec("http", "get", "http.get", "reversible", 0.05, null, "Fetches a URL.", listOf(), listOf("pca.bulk", "pca.network_egress")),
            Spec("http", "post", "http.post", "rate_limited", 0.5, null, "Posts a body to a URL.", listOf(), listOf("pca.bulk", "pca.network_egress"))
        )
        // END GENERATED

        /** The catalog of the built-in actions. */
        val DEFAULT = Catalog(BUILTIN)
    }
}
