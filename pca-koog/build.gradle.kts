plugins {
    alias(libs.plugins.kotlin.jvm)
}

// JetBrains Koog adapter for PCA: run a Koog tool under a built proof. A pure-JVM module; the coroutine entry points of the shared
// guard are used so cancellation propagates.
group = "net.atlasauth"
version = "0.6.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

kotlin {
    for (p in listOf("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
    sourceSets["main"].kotlin.srcDir("../pca-ai-core/src/main/kotlin")
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    implementation(libs.kotlinx.coroutines.core)
    api("ai.koog:koog-agents:0.5.0")
    testImplementation(libs.junit)
}
