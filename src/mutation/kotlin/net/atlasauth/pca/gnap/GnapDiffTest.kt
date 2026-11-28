package net.atlasauth.pca.gnap

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference oracle of the GNAP bridge (access rights, grant requests, chains, jwsd proofs, step-up, interaction). */
@Suppress("UNCHECKED_CAST")
class GnapDiffTest {
    private val mod = "ref-gnap"

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun n(o: Any?): Long = (o as Json.Num).raw.toDouble().toLong()
    private fun opt(a: List<Any?>, i: Int): Map<String, Any?>? = if (a.size > i) m(a[i]) else null

    /** {"$bytes": b64url} to bytes; anything else unchanged. */
    private fun unbytes(x: Any?): Any? =
        if (x is Map<*, *> && x.size == 1 && x["\$bytes"] is String) Keys.unb64u(x["\$bytes"] as String) else x

    private fun each(fn: String, f: (List<Any?>) -> Any?) = OracleCases.each(mod, fn, f)

    // ---- access rights ----
    @Test fun constants() = each("constants") {
        linkedMapOf<String, Any?>(
            "GNAP_GRANT_CAVEAT" to Gnap.GNAP_GRANT_CAVEAT,
            "GNAP_ACCESS_CAVEAT" to Gnap.GNAP_ACCESS_CAVEAT,
            "MAX_DETACHED_JWS_CHARS" to Gnap.MAX_DETACHED_JWS_CHARS,
            "START_MODES" to ArrayList<Any?>(Interaction.START_MODES),
            "FINISH_METHODS" to ArrayList<Any?>(Interaction.FINISH_METHODS),
            "HASH_METHODS" to ArrayList<Any?>(Interaction.HASH_METHODS.keys),
        )
    }

    @Test fun agentGnapProfile() = each("AGENT_GNAP_PROFILE") { Gnap.agentGnapProfile() }
    @Test fun gnapActionResource() = each("gnapActionResource") { Gnap.gnapActionResource(it[0] as String, it[1] as String) }
    @Test fun normalizeAccess() = each("normalizeAccess") { Gnap.normalizeAccess(it[0]) }
    @Test fun accessToPredicates() = each("accessToPredicates") { Gnap.accessToPredicates(m(it[0])) }
    @Test fun accessContains() = each("accessContains") { Gnap.accessContains(m(it[0]), m(it[1])) }
    @Test fun accessWithin() = each("accessWithin") { Gnap.accessWithin(l(it[0]), m(it[1])) }
    @Test fun clampAccess() = each("clampAccess") { Gnap.clampAccess(l(it[0]), l(it[1])) }
    @Test fun grantedAccessOf() = each("grantedAccessOf") { Gnap.grantedAccessOf(it[0]) }
    @Test fun resolveHolder() = each("resolveHolder") { Gnap.resolveHolder(it[0], if (it.size > 1) it[1] else Gnap.ABSENT) }
    @Test fun holderJwk() = each("holderJwk") { Gnap.holderJwk(it[0] as String) }

    // ---- grant request -> capability, authorization, tokens ----
    @Test fun grantRequestToCapability() = each("grantRequestToCapability") { Gnap.grantRequestToCapability(it[0], m(it[1])) }
    @Test fun authorizeGnapAction() = each("authorizeGnapAction") { Gnap.authorizeGnapAction(it[0], m(it[1]), opt(it, 2)) }
    @Test fun encodeBoundToken() = each("encodeBoundToken") { Gnap.encodeBoundToken(it[0]) }
    @Test fun capabilityToGrantResponse() = each("capabilityToGrantResponse") { Gnap.capabilityToGrantResponse(it[0], opt(it, 1)) }
    @Test fun verifyGnapToken() = each("verifyGnapToken") { Gnap.verifyGnapToken(it[0], opt(it, 1)) }

    // ---- jwsd ----
    @Test fun gnapContentDigest() = each("gnapContentDigest") { Gnap.gnapContentDigest(unbytes(it[0])) }
    @Test fun gnapContentDigestAbsent() = each("gnapContentDigestAbsent") { Gnap.gnapContentDigest(Gnap.ABSENT) }

    @Test fun signGnapRequest() = each("signGnapRequest") { a ->
        val args = LinkedHashMap(m(a[0]))
        if (args.containsKey("body")) args["body"] = unbytes(args["body"])
        Gnap.signGnapRequest(args)
    }

    @Test fun verifyGnapRequest() = each("verifyGnapRequest") { a ->
        val args = LinkedHashMap(m(a[0]))
        val mode = args.remove("seenProofMode")
        if (args.containsKey("body")) args["body"] = unbytes(args["body"])
        val seen = ArrayList<Any?>()
        if (mode != null) {
            args["seenProof"] = Gnap.SeenProof { id, exp ->
                seen.add(arrayListOf<Any?>(id, exp))
                when (mode as String) {
                    "fresh" -> false
                    "replayed" -> true
                    "throws" -> throw IllegalStateException("store down")
                    else -> null // returns nothing: replayed
                }
            }
        }
        linkedMapOf<String, Any?>("result" to Gnap.verifyGnapRequest(args), "seen" to seen)
    }

    // ---- step-up ----
    @Test fun gnapRequestRequiresStepUp() = each("gnapRequestRequiresStepUp") { Gnap.gnapRequestRequiresStepUp(it[0], opt(it, 1)) }
    @Test fun beginGnapContinuation() = each("beginGnapContinuation") { Gnap.beginGnapContinuation(m(it[0])) }
    @Test fun gnapStepUpShare() = each("gnapStepUpShare") { Gnap.gnapStepUpShare(m(it[0]), it[1] as String, it[2], it[3], it[4]) }
    @Test fun completeGnapContinuation() = each("completeGnapContinuation") { Gnap.completeGnapContinuation(m(it[0])) }

    // ---- interaction (an InteractionError exposes its code to the oracle comparison) ----
    @Test fun callbackUriOk() = each("callbackUriOk") { Interaction.callbackUriOk(it[0]) }
    @Test fun validateInteractRequest() = each("validateInteractRequest") { Interaction.validateInteractRequest(it[0]) }
    @Test fun interactionHash() = each("interactionHash") { Interaction.interactionHash(m(it[0])) }
    @Test fun verifyInteractionHash() = each("verifyInteractionHash") { Interaction.verifyInteractionHash(it[0], m(it[1])) }
    @Test fun acceptFinish() = each("acceptFinish") { Interaction.acceptFinish(m(it[0]), m(it[1])) }
    @Test fun accessToNeeds() = each("accessToNeeds") { Interaction.accessToNeeds(l(it[0])) }
    @Test fun newUserCodeRefusals() = each("newUserCode") { Interaction.newUserCode(n(it[0]).toInt()) }

    @Test fun newUserCodeShape() {
        val p = Regex("[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}")
        repeat(200) { assertTrue(p.matches(Interaction.newUserCode())) }
        for (len in 6..12) assertEquals(len, Interaction.newUserCode(len).length)
        assertThrows(IllegalArgumentException::class.java) { Interaction.newUserCode(5) }
        assertThrows(IllegalArgumentException::class.java) { Interaction.newUserCode(13) }
    }

    // ---- the AS state machine as scripted scenarios (random values replaced by tokens) ----
    private fun redact(v: Any?, tokens: List<Pair<String?, String>>): Any? = when (v) {
        is String -> tokens.fold(v) { s, (k, t) -> if (k.isNullOrEmpty()) s else s.replace(k, t) }
        is List<*> -> v.map { redact(it, tokens) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = redact(x, tokens) }
        else -> v
    }

    private fun stateMap(s: Interaction.State?): Any? = s?.toMap()

    private fun scenario(s: Map<String, Any?>): Any? {
        var clock = 1000L
        val opts = m(s["opts"])
        val ge = if (opts.containsKey("grantEndpoint")) opts["grantEndpoint"] as String else "https://as.example/tx"
        val supports = l(opts["supports"]).map { it as String }
        val app: ((String) -> String)? = if (opts["app"] == true) ({ id: String -> "app://as/$id" }) else null
        val ttl = if (opts.containsKey("ttlSec")) n(opts["ttlSec"]) else null
        val srv = Interaction.Server(ge, supports, { id -> "https://as.example/i/$id" }, app, opts["userCodeUri"] as String?, ttl, { clock })
        val v = HashMap<String, String>()
        var lastReq: Map<String, Any?>? = null
        val trace = ArrayList<Any?>()
        // every started interaction is redacted, not only the latest: the latest keeps <ID>/<CODE>/<ASNONCE>, start number n (from 0) is <ID:n>...
        val started = ArrayList<Triple<String, String, String>>()
        fun sub(x: Any?): Any? {
            if (x !is String || !x.startsWith("$")) return x
            val k = x.substring(1)
            val code = v["code"] ?: ""
            if (k == "code:lower") return code.lowercase()
            if (k == "code:spaced") return code.substring(0, minOf(4, code.length)) + " - " + code.substring(minOf(4, code.length))
            return v[k] ?: x
        }
        for (so in l(s["steps"])) {
            val st = m(so)
            val op = st["op"] as String
            val entry = linkedMapOf<String, Any?>("op" to op)
            try {
                var value: Any? = null
                when (op) {
                    "start" -> {
                        lastReq = m(st["req"])
                        val r = srv.start(lastReq!!)
                        val it = r["interaction"] as Interaction.State
                        v["id"] = it.id
                        v["code"] = it.userCode ?: ""
                        v["asnonce"] = it.finish?.get("asNonce") as String? ?: ""
                        started.add(Triple(v["id"]!!, v["code"]!!, v["asnonce"]!!))
                        value = linkedMapOf<String, Any?>("interaction" to it.toMap(), "response" to r["response"])
                    }
                    "lookup" -> value = stateMap(srv.lookupUserCode(sub(st["code"]) as String))
                    "approve" -> {
                        val r = srv.approve(sub(st["id"]) as String)
                        v["ref"] = r["interactRef"] as String
                        val held = srv.get(v["id"]!!)
                        val fin = r["finish"] as Map<String, Any?>?
                        val h: String? = when {
                            fin != null && fin["method"] == "push" -> m(fin["body"])["hash"] as String?
                            fin != null && fin["url"] != null -> Regex("[?&]hash=([^&]+)").find(fin["url"] as String)?.groupValues?.get(1)
                            else -> null
                        }
                        v["hash"] = h ?: ""
                        val f = held?.finish
                        val expected = if (held == null || f == null) null else Interaction.interactionHash(linkedMapOf("clientNonce" to f["clientNonce"],
                            "asNonce" to f["asNonce"], "interactRef" to r["interactRef"], "grantEndpoint" to held.grantEndpoint, "hashMethod" to f["hashMethod"]))
                        value = linkedMapOf<String, Any?>("result" to r, "hashOk" to (h == expected))
                    }
                    "consume" -> value = stateMap(srv.consume(sub(st["ref"]) as String))
                    "finalize" -> srv.finalizeInteraction(sub(st["id"]) as String)
                    "get" -> value = stateMap(srv.get(sub(st["id"]) as String))
                    "advance" -> { clock += n(st["sec"]); value = clock }
                    "accept" -> {
                        val fin = m(lastReq!!["finish"])
                        val ctx = linkedMapOf<String, Any?>("clientNonce" to fin["nonce"], "asNonce" to v["asnonce"], "grantEndpoint" to ge)
                        if (fin["hash_method"] != null) ctx["hashMethod"] = fin["hash_method"]
                        val cb = linkedMapOf<String, Any?>("hash" to sub(st["hash"]), "interact_ref" to sub(st["ref"]))
                        value = Interaction.acceptFinish(cb, ctx)
                    }
                    else -> throw IllegalStateException("unknown step $op")
                }
                val tokens = listOf(v["ref"] to "<REF>", v["hash"] to "<HASH>", v["asnonce"] to "<ASNONCE>", v["id"] to "<ID>", v["code"] to "<CODE>") +
                    started.dropLast(1).withIndex().flatMap { (n, a) -> listOf<Pair<String?, String>>(a.first to "<ID:$n>", a.second to "<CODE:$n>", a.third to "<ASNONCE:$n>") }
                entry["ok"] = true
                entry["value"] = redact(OracleCases.toJson(value), tokens)
            } catch (e: InteractionError) {
                entry["ok"] = false
                entry["code"] = e.code
            } catch (e: RuntimeException) {
                entry["ok"] = false
                entry["code"] = "other"
            }
            trace.add(entry)
        }
        return trace
    }

    @Test fun interactionScenario() = each("interactionScenario") { scenario(m(it[0])) }
}
