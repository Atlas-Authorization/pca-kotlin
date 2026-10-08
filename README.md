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
