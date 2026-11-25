plugins {
    alias(libs.plugins.kotlin.jvm)
}

// OpenAI (openai-kotlin) adapter for PCA: dispatch a model's function tool calls under a built proof. A pure-JVM module.
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
    for (p in listOf("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
    sourceSets["main"].kotlin.srcDir("../pca-ai-core/src/main/kotlin")
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    api("com.aallam.openai:openai-client:3.8.2")
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.core)
}
