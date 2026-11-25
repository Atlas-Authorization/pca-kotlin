plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    testImplementation(libs.junit)
}

// Native tools for the JVM: the LESS library and the reference WebAssembly host, as jar resources (natives/<os>-<arch>/) staged by the release workflow
// (-Ppca.natives=/path/to/stage). A separate module so the core library (also an Android library) carries no desktop binaries.
group = "net.atlasauth"
version = "0.6.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

sourceSets["main"].resources.srcDir(providers.gradleProperty("pca.natives").getOrElse("build/natives-in"))
