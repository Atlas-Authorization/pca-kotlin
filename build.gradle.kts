plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.jvm) apply false // the JVM-only integration modules (Ktor, Spring) below
}

// Principal-device step-up module for PCA. Deliberately NOT part of the atlas-android
// auth SDK: it is a separate artifact with its own tiny dependency set.
group = "net.atlasauth"
version = "0.5.0"

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
            all { it.maxHeapSize = "2g" }
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

    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc) // the JDBC replay store's tests only
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.kotlinx.coroutines.test)
}
