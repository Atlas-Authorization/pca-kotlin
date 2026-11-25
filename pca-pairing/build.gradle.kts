plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Pairing-based PCA packages (BLS signature aggregation, BBS, ABE) on BLS12-381, over supranational blst through its JVM binding.
// A pure-JVM module so the core library gains no native dependency.
group = "net.atlasauth"
version = "0.6.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

// per-platform libraries (natives/<os>-<arch>/) staged by the release workflow: -Ppca.natives=/path/to/stage
sourceSets["main"].resources.srcDir(providers.gradleProperty("pca.natives").getOrElse("build/natives-in"))

kotlin {
    for (p in listOf("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")) sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/$p")
}

// ABE's GT operations are a small JNI shim over blst (src/main/c, built into libpcagt.so by the CI pairing job); tests load it by path
tasks.withType<Test>().configureEach {
    val lib = providers.gradleProperty("pca.gt.lib").orElse(layout.buildDirectory.file("native/libpcagt.so").map { it.asFile.path })
    systemProperty("pca.gt.lib", lib.get())
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.okhttp)
    implementation(libs.icu4j)
    // supranational blst (audited, constant-time) via its JVM binding, natives bundled; the only pairing implementation used
    api("tech.pegasys:jblst:0.3.18")
    testImplementation(libs.junit)
}
