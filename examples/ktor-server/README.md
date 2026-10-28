# PCA Ktor server example

A minimal Ktor server guarded by Proof-Carrying Authority. `POST /refunds` runs only when the request carries a proof that authorizes
exactly that operation; everything else is refused, and each refusal body has a `doc` member linking the page that explains it.

The guard comes from one call:

```kotlin
val p = protect("payments-rs", grants) { _, body -> Authorize.Operation("payments.send", "payments/acme", paramsOf(body)) }
routing { route("/refunds") { install(PcaGuardPlugin, p.configure); post { /* call.pca!! */ } } }
p.revoke(grantId) // later: every action under that grant is refused
```

The operation is built from the route and the request body, never from the proof. The grant comes from your own list, never from
the request. Replay protection is an in-memory store (one process); pass your own `authorize` options to share a store.

## Run the test

```
gradle test
```

This needs JDK 17, Gradle 8.9 and an Android SDK on `ANDROID_HOME` (the library build configures its Android module; the Ktor
module itself is plain JVM). The test sends a valid proof (allowed), a validly signed proof over the grant's limit (refused with a
`doc` link), a request with no proof, and a request under a revoked grant.

## Run the server

```
PCA_GRANTS=grants.json gradle run
```

`grants.json` is a JSON list of grants you issued. Clients send the proof in the `PCA-Action` header.
