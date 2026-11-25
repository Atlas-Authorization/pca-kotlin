plugins {
    alias(libs.plugins.kotlin.jvm)
}

// The Kotlin face on the Java FN-DSA adapter (libfndsa through JNA). A pure-JVM module so the core library gains no native dependency. The adapter's Java
// sources are compiled in (vendored at adapter/ in the public mirror, else the monorepo's java-pca adapter); the Java FnDsa framing it builds on comes from
// the Java core library, installed into mavenLocal first (net.atlasauth:pca-mutation:0) or given as -Ppca.java.core=/path/to/jar. The Kotlin core verifier is
// compiled in from ../src, as pca-pairing does. Run the tests with -Ppca.fndsa.lib=/path/to/libfndsa.so [-Ppca.fndsa.required=true].
group = "net.atlasauth"
version = "0.6.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

val adapter = listOf("adapter", "../../java-pca/adapters/pca-fndsa").map { file("$it/src/main/java") }.firstOrNull { it.isDirectory }
    ?: throw GradleException("the Java pca-fndsa adapter sources were not found (adapter/ or ../../java-pca/adapters/pca-fndsa)")

sourceSets["main"].java.srcDir(adapter)

// per-platform libraries (natives/<os>-<arch>/) staged by the release workflow: -Ppca.natives=/path/to/stage
sourceSets["main"].resources.srcDir(providers.gradleProperty("pca.natives").getOrElse("build/natives-in"))

kotlin {
    for (p in listOf("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
}

repositories { mavenLocal() }

tasks.withType<Test>().configureEach {
    // the library path doubles as the env var the Maven tests read; the Kotlin test reads the property and the environment alike
    providers.gradleProperty("pca.fndsa.lib").orNull?.let { systemProperty("pca.fndsa.lib", it); environment("ATLAS_PCA_LIBFNDSA", it) }
    providers.gradleProperty("pca.fndsa.required").orNull?.let { if (it == "true") environment("ATLAS_PCA_LIBFNDSA_REQUIRED", "1") }
}

dependencies {
    val javaCore = providers.gradleProperty("pca.java.core").orNull
    if (javaCore != null) implementation(files(javaCore)) else implementation("net.atlasauth:pca-mutation:0")
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    implementation(libs.jna)
    testImplementation(libs.junit)
    testImplementation("com.google.code.gson:gson:2.11.0")
}
