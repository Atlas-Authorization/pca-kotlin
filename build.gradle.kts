plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.jvm) apply false // the JVM-only integration modules (Ktor, Spring) below
}

// Principal-device step-up module for PCA. Deliberately NOT part of the atlas-android
// auth SDK: it is a separate artifact with its own tiny dependency set.
group = "net.atlasauth"
version = "0.6.0"

android {
    namespace = "net.atlasauth.pca.stepup"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = "1.8" }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
            // the attestation vector file (real vendor evidence) is large
            all {
                it.maxHeapSize = "3g"
                it.jvmArgs("-Xss16m", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=/tmp")
                it.testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL; showStandardStreams = true }
            }
        }
    }
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.androidx.security.crypto)
    // Ed25519 (lightweight API only; no JCA provider registration, so it does not collide
    // with Android's platform-bundled, stripped BouncyCastle).
    implementation(libs.bouncycastle)
    // libsodium behind the ristretto255 / Ed25519 group (ratchet/Libsodium.kt): on a device the lazysodium-android AAR (libsodium for the four ABIs) and the JNA AAR;
    // the desktop lazysodium-java is compile-only here and test-only at runtime, the host JVM unit tests use it (Libsodium.kt picks by Build.VERSION.SDK_INT)
    implementation(variantOf(libs.lazysodium.android) { artifactType("aar") })
    implementation(variantOf(libs.jna) { artifactType("aar") })
    compileOnly(libs.lazysodium.java)
    testImplementation(libs.lazysodium.java)
    testImplementation(libs.jna)
    implementation(libs.icu4j)
    implementation(libs.snakeyaml.engine)

    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc) // the JDBC replay store's tests only
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.kotlinx.coroutines.test)
}

// The networked FROST HTTP transport uses com.sun.net.httpserver and java.net.http, neither of which Android has: it is JVM-only (the Maven build compiles it with its test).
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach { exclude("**/frost/FrostNetHttp*.kt") }
