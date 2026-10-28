# pca-kotlin — Proof-Carrying Authority for Kotlin (JVM, Android)

An **offline verifier for Proof-Carrying Actions (PCActns)** in Kotlin, plus the principal's phone-side
**step-up** client. A PCActn is the credential an autonomous agent presents with *every* action it takes:
a self-contained, cryptographically-checkable object proving the action is a faithful execution of
authority its principal actually granted. Your resource server verifies it locally — no token
introspection, no network call on the hot path.

This package is the Kotlin member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

Two things ship from the package:

- the native offline verifier (`net.atlasauth.pca.verifier`) for the eight core PCActn checks, and
- the principal-device **step-up** client (`net.atlasauth.pca.stepup`) for the threshold co-sign flow.

## Install

Add the module with Gradle (from source; no package-registry release yet):

```kotlin
// settings.gradle.kts — e.g. a git submodule or a local checkout
include(":pca-kotlin")
```

Cryptography uses **BouncyCastle (`bcprov-jdk18on`, >= 1.80)**: the lightweight Ed25519 API for the
classical suite and the FIPS-204 ML-DSA-65 implementation for the post-quantum suites. Strict RFC 8032
checks (S < L, small-/mixed-order rejection) are applied on top so a forged small-order signature cannot
pass. The verifier itself has no other runtime dependency.

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (raw JSON via `Pca.verifyPcactnJson(…)`, or a parsed
value via `Pca.verifyPcactn(…)`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check results.

```kotlin
import net.atlasauth.pca.verifier.Pca

// `raw` is the PCActn as received (strict canonical JSON, wire version 2).
// `grant` is the Root Intent Grant the action's capability chain roots in.
val now = System.currentTimeMillis()
val verdict = Pca.verifyPcactnJson(raw, grant, now, Pca.Audience.Of("https://api.example.com"))

if (verdict.allow) {
    // every core check passed — execute the action
} else {
    println("denied: ${verdict.reason} ${verdict.checks}")   // verdict.checks: Map<String, Boolean>
}
```

`verdict.checks` reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## authorize (0.5)

`Authorize.authorize` is the full decision for one operation. It runs the verifier checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, the caveats placed on the root
  grant and the caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an
  unknown type is refused);
- checks revocation with your `isRevoked`;
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without `audience`, `resolveGrant`, `stateStore`, `isRevoked` or the operation, the call
is refused and `result.missing` names what is absent. `authorize` never throws: an internal error is a denial.

```kotlin
import java.sql.DriverManager
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.PcaJdbcStateStore

// One row per (grant, agent), safe across processes. Any JDBC connection works: SQLite 3.24+ or PostgreSQL 9.5+.
val store = PcaJdbcStateStore({ DriverManager.getConnection("jdbc:sqlite:pca-replay.db") })

val operation = Authorize.Operation("payments.send", "payments/acme", body) // what you will execute
val result = Authorize.authorize(
    pcactn, // the PCActn as JSON text, UTF-8 bytes or a parsed object
    Authorize.Input(
        operation = operation,
        audience = "payments-rs",
        resolveGrant = { grantRef -> grants[grantRef] }, // from your own store
        stateStore = store,
        isRevoked = { _, grant -> grant["id"] as? String in revokedGrantIds }, // your revocation list
        plan = Authorize.SINGLE_STEP,
        now = System.currentTimeMillis(), // epoch ms; the default is the wall clock
    ),
)
if (!result.allow) throw SecurityException(result.reason) // e.g. "policy: caveat(s) not satisfied: max_spend"
sendPayment(body)
```

- `body` is the request's parsed JSON object (`Json.parse`); params hold JSON values (`Json.Num`, `Int`, `Long`,
  `String`, `Boolean`, `null`, maps and lists).
- `plan = Authorize.SINGLE_STEP` accepts a proof whose plan is this one operation. For a multi-step plan, pass
  `context = { pcactn -> mapOf("plan" to nodes, "plan_authorized" to true) }` with the plan the principal authorized.
  The context can also carry `subject`, `env`, `blast_radius`, `recent_action_times` and the server's authoritative
  `reversibility_class`.
- `result.status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.checks` lists every check
  (`pass`, `fail` or `not-enforced`) and `result.reason` the decisive failure. On success `result.operation` is the
  bound operation, and `Authorize.isAuthorizedFor(result, operation)` re-checks it where the side effect runs.
- `Authorize.MemoryStateStore` is for a single process. Your own store implements `Authorize.StateStore.claim(key,
  counter)` as one atomic operation (for example a conditional `UPDATE ... WHERE last_counter < ?`), returning
  `ClaimResult(ok, lastCounter)`.
- `Authorize.AuthorizeOptions(stateStore, isRevoked)` holds the components a request handler reuses (`plan` defaults
  to single-step); `options.run(pcactn, operation, audience, resolveGrant)` authorizes one operation.
- `Authorize.evaluateAgentCaveats`, `Authorize.evaluateToolSchema`, `Authorize.readEnvelope` and
  `Authorize.rootCaveats` expose the policy steps on their own.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`.


## Step-up co-sign (principal device, Android)

`net.atlasauth.pca.stepup` is the principal's phone side of PCA: approve or deny a high-risk (t=3) agent
action. Additional deps for this client only: OkHttp, kotlinx.serialization, `androidx.security:security-crypto`.

```kotlin
import net.atlasauth.pca.stepup.*

val key = PrincipalDeviceKey(context)                // Keystore-wrapped EncryptedSharedPreferences
key.importSecret(principalSecretB64u)                // or key.generate() -> register this public key as the grant's principal
val client = StepUpClient(
    dashboardUrl = "https://api.atlasauth.net", instanceUrl = "https://auth.example.com",
    accountId = "acc_...", instanceId = "ins_...", key = key, token = { myDashboardToken() },
)
val pending: List<PendingStepUp> = client.pending()
pending.firstOrNull()?.let { /* show it.summary, require BiometricPrompt */ client.approve(it) }  // or client.deny(it, "not me")
```

`approve` signs the decoded `threshold_message` and POSTs `{ role: "principal", publicKey, sig }` to the
public `POST /v1/pca/stepups/:id/cosign` (the signature is the credential, no token needed); `pending` /
`deny` use the dashboard API with a bearer token.

**Security note (honest):** Android Keystore does not provide a usable Ed25519 key, and PCA principal keys
are Ed25519. The key is therefore a **software key**: the seed is encrypted at rest by an AES-256 master
key in the Android Keystore (hardware-backed where available) but is **not hardware-bound** and sits in
process memory when used. Gate `approve` behind a BiometricPrompt for user presence.

## One call: protect, and explaining a refusal

`protect()` fills in the parts every server wires by hand: the grant lookup (your list or function, never the request), an
in-memory replay store, a revocation source and `plan = "single-step"`. Anything you set in the `customize` block wins.

```kotlin
val p = protect("payments-rs", listOf(grant)) { call, body -> Authorize.Operation("payments.send", "payments/acme", paramsOf(body)) }
routing { route("/refunds") { install(PcaGuardPlugin, p.configure); post { /* call.pca!! */ } } }
p.revoke(grant["id"] as String) // later: every action under that grant is refused
```

The in-memory store is per process; set `authorize` in `customize` with a shared store when you run more than one instance. Unlike
the TypeScript helper, `protect()` does not price risk from a connector catalog (this library has none). A complete runnable
server is in `examples/ktor-server`.

Every refusal body also carries a `doc` member, the page that explains the refusal. `explainRefusal(reason)` returns the same
guidance in code (`check`, `meaning`, `fix`, `docs`); the reason strings themselves are never reworded.

## What a passing result does not cover

`counter: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
Verification is stateless and this package has no replay store, so the resource server must persist, per grant and
agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its processes.

The verifier is the core verifier only (this package has no HTTP middleware). It does not check replay, revocation, caveats, envelope predicates, plan authorization, risk or
thresholds, and it does not compare the request body with the signed `params_digest`. Do those checks in your
handler (the caveat helpers, the params digest of the body you will execute, your replay and revocation stores), or
delegate the decision to a full verifier such as `requirePCA` from `@atlasauth/pca`.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): over a hundred golden and adversarial PCActns with their expected verdicts, plus
canonical-JSON, strict-base64url, and Merkle primitive vectors. `gradle test` runs the verifier against
every vector; it must reproduce `allow` and every listed check exactly. The suite is green across the
classical and post-quantum corpora.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and the post-quantum key are part of the signed body, so a downgrade is a signature failure;
a hybrid PCActn requires **both** signatures to verify.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered, and this
package implements all of them — including the post-quantum suites — green against the shared corpus. The
broader framework surface is implemented and tested in the reference implementation: threshold/step-up
co-signing (a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM
allow — the step-up client here is the principal's side of that flow), TEE/hardware and model-weights
attestation, zero-knowledge proof-of-compliance (a real Groth16 proof), optimistic bonds and the
contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs with abort). A few rungs
carry a remaining production requirement, stated plainly rather than hidden behind a label: a live
TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested against real-crypto mock
reports); unforgeable FROST guardian custody needs each share in a separate trust domain / HSM with a
network signing protocol (the reference runs the signing round in-process); the MPC Policy VM's offline
triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and the zero-knowledge
circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller policy coverage ongoing.
See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the full model.

## License

See `LICENSE`.
