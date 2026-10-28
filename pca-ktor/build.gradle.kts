plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Ktor server plugin for PCA. A pure-JVM module: the core verifier (a pure-JVM package) is compiled in from the shared source
// directory, so the core library itself keeps no Ktor dependency. Not part of the Android artifact.
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
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/verifier")
    sourceSets["main"].kotlin.srcDir("../guard-common")
    sourceSets["test"].kotlin.srcDir("../guard-common-test")
}

dependencies {
    api(libs.ktor.server.core)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.bouncycastle)

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit)
}

tasks.test {
    maxHeapSize = "2g"
    jvmArgs("-Xss16m")
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}
