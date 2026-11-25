plugins {
    alias(libs.plugins.kotlin.jvm)
}

// The Kotlin face on the Java SEAL adapter (BFV risk gate over Microsoft SEAL's C export API through JNA). A pure-JVM module so the core library
// gains no native dependency. The adapter's Java sources are compiled in: vendored at adapter/ in the public mirror (same ref), else the
// monorepo's java-pca adapter. libsealc is built by CI from the pinned SEAL tag: pass -Ppca.sealc.lib=/path/to/libsealc.so
// -Ppca.fhe.corpus=/path/to/fhe-seal.json.gz [-Ppca.fhe.required=true] to run the tests.
group = "net.atlasauth"
version = "0.5.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

val adapter = listOf("adapter", "../../java-pca/adapters/pca-fhe-seal").map { file("$it/src/main/java") }.firstOrNull { it.isDirectory }
    ?: throw GradleException("the Java pca-fhe-seal adapter sources were not found (adapter/ or ../../java-pca/adapters/pca-fhe-seal)")

sourceSets["main"].java.srcDir(adapter)

// per-platform libraries (natives/<os>-<arch>/) staged by the release workflow: -Ppca.natives=/path/to/stage
sourceSets["main"].resources.srcDir(providers.gradleProperty("pca.natives").getOrElse("build/natives-in"))

repositories { mavenLocal() }

tasks.withType<Test>().configureEach {
    for (p in listOf("pca.sealc.lib", "pca.fhe.corpus", "pca.fhe.required")) {
        providers.gradleProperty(p).orNull?.let { systemProperty(p, it) }
    }
}

dependencies {
    // the adapter finds its packaged library through the Java core's NativeLibs (installed into mavenLocal, as pca-fndsa does)
    implementation("net.atlasauth:pca-mutation:0")
    implementation(libs.jna)
    testImplementation(libs.junit)
    testImplementation("com.google.code.gson:gson:2.11.0")
}
