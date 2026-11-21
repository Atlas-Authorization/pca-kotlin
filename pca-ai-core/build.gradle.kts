plugins {
    alias(libs.plugins.kotlin.jvm)
}

// The shared guard behind the AI-stack adapters (LangChain4j, OpenAI, Koog): map a tool call to a PCA action, build the proof, run the
// tool under it. A pure-JVM module: the core verifier is compiled in from the shared source directory.
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
    for (p in listOf("analyzer", "compliance", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    testImplementation(libs.junit)
}
