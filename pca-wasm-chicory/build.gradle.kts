plugins {
    alias(libs.plugins.kotlin.jvm)
}

// In-process WebAssembly core-module host for sandboxed tools on Chicory (pure JVM): instruction fuel, wall-clock deadline, memory cap,
// no WASI. A separate module so the core library gains no engine dependency. Compiles the sandbox package (and what it needs) from the core sources.
group = "net.atlasauth"
version = "0.5.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

kotlin {
    for (p in listOf("analyzer", "compliance", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "sandbox", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.icu4j)
    implementation(libs.okhttp)
    // pinned: the interpreter machine and its ExecutionListener hook are what the fuel meter relies on
    api("com.dylibso.chicory:runtime:1.7.5")
    testImplementation(libs.junit)
}
