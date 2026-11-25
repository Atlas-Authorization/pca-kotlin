plugins {
    alias(libs.plugins.kotlin.jvm)
}

// LangChain4j adapter for PCA: a guarded ToolExecutor (every tool execution runs under a built proof) and a PCA-scoped ContentRetriever
// (retrieval is filtered to what the principal may see before it reaches the model). A pure-JVM module.
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
    // the core verifier and the retrieval filter (with the policy bridge it evaluates) are compiled in from the shared source directory
    for (p in listOf("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/jose")
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/policybridge")
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/rag")
    sourceSets["main"].kotlin.srcDir("../pca-ai-core/src/main/kotlin")
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    api("dev.langchain4j:langchain4j:1.0.0")
    testImplementation(libs.junit)
}
