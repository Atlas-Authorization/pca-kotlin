pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "atlas-pca-stepup"

// Framework integrations: pure-JVM modules, so the core library keeps no Ktor / Spring dependency.
include(":pca-ktor", ":pca-spring", ":pca-ai-core", ":pca-langchain4j", ":pca-openai", ":pca-koog", ":pca-pairing", ":pca-wasm-chicory", ":pca-natives")
// The SEAL module compiles the Java adapter's sources; skip it (instead of failing the whole build) when they are not present.
if (file("pca-fhe-seal/adapter").isDirectory || file("../java-pca/adapters/pca-fhe-seal").isDirectory) include(":pca-fhe-seal")
// Likewise the FN-DSA module (Java adapter + the Java core's FnDsa framing, see its build file).
if (file("pca-fndsa/adapter").isDirectory || file("../java-pca/adapters/pca-fndsa").isDirectory) include(":pca-fndsa")
// And the Groth16 module (Java adapter over the shared Groth16 library + the Java core's Zk seam).
if (file("pca-zk/adapter").isDirectory || file("../java-pca/adapters/pca-zk").isDirectory) include(":pca-zk")
