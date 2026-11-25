package net.atlasauth.pca.attesteat

import java.security.SecureRandom
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.ProvenanceGate
import net.atlasauth.pca.verifier.Sigstore

/**
 * THE ARTIFACT ATTESTATION VERIFIER: Sigstore provenance joined to runtime attestation, issued as a discharge. The verifier that holds
 * the `artifact`-class key runs, for one request: the Sigstore bundle against the pinned roots (offline); the digest of the image that is
 * actually running, from an EAT it already accepted (never a digest the caller states); the provenance gate (its own pins and the join);
 * and signs the discharge the request asks for, with the gate's claims. Any failure returns no discharge: provenance can only remove
 * authority.
 */
object AttestEatProvenance {
    /**
     * The running image's digest from an ACCEPTED EAT verdict: exactly one `measurements` entry labelled `slot` (default `image`),
     * lowercase hex of the algorithm's length (64 for sha256, else 128). Null when the verdict is not ok, the slot is missing or
     * repeated, or the value is malformed. [o]: slot?, alg?. Result {alg, digest} or null.
     */
    fun runtimeDigestFromEat(verdict: Any?, o: Map<String, Any?>? = null): Map<String, Any?>? {
        val v = AttestEat.rec(verdict)
        if (v == null || v["ok"] != true || v["claims"] !is Map<*, *>) return null
        val opts = o ?: emptyMap()
        val slot: Any? = opts["slot"] ?: "image"
        val alg: Any? = opts["alg"] ?: "sha256"
        val ms = AttestEat.rec(v["claims"])!!["measurements"]
        var hit: Any? = null
        var hits = 0
        if (ms != null) {
            val l = AttestEat.arr(ms) ?: throw IllegalArgumentException("(claims.measurements ?? []).filter is not a function")
            for (e in l) {
                val m = AttestEat.rec(e)
                if (m != null && slot == m["type"]) { hits++; hit = m["value"] }
            }
        }
        if (hits != 1) return null
        val re = if ("sha256" == alg) Regex("[0-9a-f]{64}") else Regex("[0-9a-f]{128}")
        if (hit !is String || !re.matches(hit)) return null
        return linkedMapOf("alg" to alg, "digest" to hit)
    }

    /**
     * The discharge body for a passed provenance gate and a discharge request (`provenanceDischargeBody`): v 1, kind pca-discharge, the
     * request's caveat id / issuer / cap_hash / bind (and action_digest), the gate's claims, iat, not_after = iat + ttl_ms and the nonce.
     * Throws when the gate refused or `ttl_ms` exceeds what the caveat accepts.
     */
    fun provenanceDischargeBody(request: Map<String, Any?>, gate: ProvenanceGate.GateResult, iat: Any?, ttlMs: Any?, nonce: String): Map<String, Any?> {
        if (!gate.ok) throw IllegalArgumentException("provenanceDischargeBody: the provenance gate refused (${gate.code})")
        val ttl = Js.num(ttlMs)
        val reqTtl = Js.num(request["ttl_ms"])
        val at = Js.num(iat)
        if (ttl != null && reqTtl != null && ttl > reqTtl) throw IllegalArgumentException("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts")
        val b = LinkedHashMap<String, Any?>()
        b["v"] = 1L
        b["kind"] = "pca-discharge"
        b["caveat_id"] = request["caveat_id"]
        b["issuer"] = request["issuer"]
        b["cap_hash"] = request["cap_hash"]
        b["bind"] = request["bind"]
        if (request.containsKey("action_digest")) b["action_digest"] = request["action_digest"]
        b["claims"] = gate.claims
        b["iat"] = iat
        val notAfter = (at ?: Double.NaN) + (ttl ?: Double.NaN)
        b["not_after"] = if (notAfter == Math.rint(notAfter) && Math.abs(notAfter) < 9007199254740992.0) notAfter.toLong() as Any else notAfter as Any
        b["nonce"] = nonce
        return b
    }

    /**
     * Issue an artifact discharge. [i]: bundle (a parsed Sigstore bundle), roots ([Sigstore.PinnedRoots]), policy (`provenanceGate`
     * policy), runtime? ({alg, digest} from [runtimeDigestFromEat]; omit only when the policy does not require the join; an explicit
     * null is a failed join), request (the discharge request), now (verifier clock, epoch ms), issuerKey ([Keys.SuiteKey], the
     * `artifact`-class issuer), ttl_ms? (default the request's). Result {ok: true, discharge, facts, level} or {ok: false, stage:
     * "sigstore", code, detail} or {ok: false, stage: "gate", code}. The 16-byte nonce comes from [nonce] (default SecureRandom).
     */
    fun issueArtifactDischarge(i: Map<String, Any?>, nonce: (() -> ByteArray)? = null): Map<String, Any?> {
        val v = Sigstore.verifySigstoreBundle(i["bundle"], i["roots"] as Sigstore.PinnedRoots?)
        val out = LinkedHashMap<String, Any?>()
        if (!v.ok) {
            out["ok"] = false
            out["stage"] = "sigstore"
            out["code"] = v.code
            out["detail"] = v.detail
            return out
        }
        if (i.containsKey("runtime") && i["runtime"] == null) return gateFail("no_runtime")
        val inp = LinkedHashMap<String, Any?>()
        inp["facts"] = v.facts
        inp["policy"] = i["policy"]
        if (i.containsKey("runtime")) inp["runtime"] = i["runtime"]
        val now = Js.num(i["now"])
        inp["now"] = if (now == null) null else Math.floor(now / 1000).toLong()
        val gate = ProvenanceGate.provenanceGate(inp)
        if (!gate.ok) return gateFail(gate.code ?: "")
        val request = AttestEat.rec(i["request"]) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'ttl_ms')")
        val ttl = i["ttl_ms"] ?: request["ttl_ms"]
        val n = if (nonce != null) nonce() else ByteArray(16).also { SecureRandom().nextBytes(it) }
        val body = provenanceDischargeBody(request, gate, i["now"], ttl, Pca.b64(n))
        out["ok"] = true
        out["discharge"] = Issue.signDischarge(body, i["issuerKey"] as Keys.SuiteKey)
        out["facts"] = v.facts
        out["level"] = gate.level
        return out
    }

    private fun gateFail(code: String): Map<String, Any?> = linkedMapOf("ok" to false, "stage" to "gate", "code" to code)
}
