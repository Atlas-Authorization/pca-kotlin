package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The prohibitions and contracts names the shared vectors and the base prohibitions corpus do not reach, against the reference corpora
 * (ref-prohibitions 1637 cases, ref-contracts 1269): every function, every case. Where the reference tells an absent option from a null
 * one, the replay calls the entry point that keeps the difference.
 */
@Suppress("UNCHECKED_CAST")
class ProhibitionsContractsRefDiffTest {
    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    /** The loader has replaced each {"$seed": label} by the base64url seed; anything else is not a key and the reference refuses it. */
    private fun seed(s: Any?): ByteArray = Pca.decodeB64uStrict(s, 32) ?: throw IllegalArgumentException("not a signing key")

    private fun need(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    /** JavaScript object spread of a value: a string or a list contributes its indices. */
    private fun spread(o: Any?): Map<String, Any?> {
        if (o == null) throw IllegalArgumentException("null")
        if (o is Map<*, *>) return o as Map<String, Any?>
        val out = LinkedHashMap<String, Any?>()
        if (o is List<*>) for ((i, x) in o.withIndex()) out[i.toString()] = x
        if (o is String) for ((i, ch) in o.withIndex()) out[i.toString()] = ch.toString()
        return out
    }

    private fun replay(module: String, total: Int, table: Map<String, (List<Any?>) -> Any?>) {
        assertEquals(table.keys, BaseOracle.fns("$module.json.gz"))
        assertEquals(total, table.keys.sumOf { OracleCases.of(module, it).size })
        for ((fn, f) in table) OracleCases.each(module, fn, f)
    }

    @Test fun prohibitions() {
        val f = LinkedHashMap<String, (List<Any?>) -> Any?>()
        f["constants"] = { _ ->
            Prohibitions.map(
                "CONSTITUTION_VERSION", Prohibitions.CONSTITUTION_VERSION, "CONSTITUTION_SIG_DOMAIN", Prohibitions.CONSTITUTION_SIG_DOMAIN,
                "EVIDENCE_VERSION", Prohibitions.EVIDENCE_VERSION, "SAFETY_EVIDENCE_SIG_DOMAIN", Prohibitions.SAFETY_EVIDENCE_SIG_DOMAIN,
                "STATE_DIGEST_DOMAIN", Prohibitions.STATE_DIGEST_DOMAIN, "STATE_CHAIN_DOMAIN", Prohibitions.STATE_CHAIN_DOMAIN,
                "MAX_LEDGER", Prohibitions.MAX_LEDGER, "MAX_INVARIANTS", Prohibitions.MAX_INVARIANTS, "MAX_DEADLINE", Prohibitions.MAX_DEADLINE,
            )
        }
        f["validateWhen"] = { a ->
            val label = arg(a, 1)
            Prohibitions.validateWhen(arg(a, 0), if (label is String) label else IntentRevocation.jsText(label, a.size > 1))
        }
        f["whenMatches"] = { a -> Prohibitions.whenMatches(arg(a, 0), arg(a, 1)) }
        f["signConstitution"] = { a -> SignersMore.signConstitution(need(arg(a, 0)), Keys.edFromSeed(seed(arg(a, 1)))) }
        f["advanceState"] = { a -> Prohibitions.advanceState(arg(a, 0), arg(a, 1), arg(a, 2), if (a.size > 3) a[3] else Prohibitions.ABSENT) }
        f["evidenceDigest"] = { a -> Prohibitions.evidenceDigest(arg(a, 0)) }
        f["composeAuthority"] = { a -> Prohibitions.composeAuthority(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3)) }
        replay("ref-prohibitions", 1637, f)
    }

    /** The options of a contract advance as the reference reads them: a member that is present, even null, is a check. */
    private fun opts(a: List<Any?>, i: Int): List<Any?> {
        val o = arg(a, i)
        if (a.size > i && o == null) return listOf(Contracts.NULL_OPTIONS, Prohibitions.ABSENT, Prohibitions.ABSENT) // the reference reads a member of null inside its guard: the advance fails closed
        val om = o as? Map<String, Any?>
        return listOf(
            om?.get("now"),
            if (om != null && om.containsKey("expectedSeq")) om["expectedSeq"] else Prohibitions.ABSENT,
            if (om != null && om.containsKey("expectedStateDigest")) om["expectedStateDigest"] else Prohibitions.ABSENT,
        )
    }

    @Test fun contracts() {
        val f = LinkedHashMap<String, (List<Any?>) -> Any?>()
        f["constants"] = { _ ->
            Prohibitions.map(
                "CONTRACT_VERSION", Contracts.CONTRACT_VERSION, "CONTRACT_SIG_DOMAIN", Contracts.CONTRACT_SIG_DOMAIN, "MAX_CLAUSES", Contracts.MAX_CLAUSES,
                "MAX_CLAUSE_DEPTH", Contracts.MAX_CLAUSE_DEPTH,
            )
        }
        f["validateClause"] = { a ->
            val seen = HashSet<String>()
            for (s in arg(a, 1) as List<Any?>) seen.add(s as String)
            Contracts.validateClause(arg(a, 0), seen, Math.ceil(IntentJs.num(arg(a, 2))!!).toInt())
        }
        f["contractId"] = { a -> Contracts.contractId(spread(arg(a, 0))) }
        f["signContract"] = { a -> Contracts.signContract(need(arg(a, 0)), seed(arg(a, 1))) }
        f["embeddedConstitution"] = { a -> Contracts.embeddedConstitutionOf(arg(a, 0)) }
        f["contractFromConstitution"] = { a -> Contracts.contractFromConstitution(arg(a, 0)) }
        f["checkContract"] = { a -> Contracts.checkContract(arg(a, 0), arg(a, 1), arg(a, 2)) }
        f["advanceContract"] = { a ->
            val o = opts(a, 3)
            Contracts.advanceContractRef(arg(a, 0), arg(a, 1), arg(a, 2), o[0], o[1], o[2])
        }
        f["checkAndAdvanceContract"] = { a ->
            val o = opts(a, 4)
            Contracts.checkAndAdvanceContractRef(arg(a, 0) == true, arg(a, 1), arg(a, 2), arg(a, 3), o[0], o[1], o[2])
        }
        replay("ref-contracts", 1269, f)
    }

    @Test fun thePublicEntryPointsReadNullAsNotGiven() {
        val state = Prohibitions.emptyState(IntentJs.ofLong(1_700_000_000_000L))
        val action = linkedMapOf<String, Any?>("action" to linkedMapOf<String, Any?>("verb" to "read", "resource" to "/r"))
        val c = Contracts.fromConstitution(linkedMapOf<String, Any?>("version" to IntentJs.ofLong(1), "principal" to Pca.b64(ByteArray(32)), "invariants" to ArrayList<Any?>()))
        assertEquals(
            Json.canonicalize(Contracts.advanceContractRef(state, action, c, null, Prohibitions.ABSENT, Prohibitions.ABSENT)),
            Json.canonicalize(Contracts.advanceContract(state, action, c, null, null, null)),
        )
        assertEquals(
            Json.canonicalize(Prohibitions.advanceState(action, Contracts.embeddedConstitutionOf(c), state)),
            Json.canonicalize(Prohibitions.advanceStateStrict(action, Contracts.embeddedConstitutionOf(c), state)["state"]),
        )
    }
}
