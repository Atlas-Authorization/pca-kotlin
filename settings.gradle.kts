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
include(":pca-ktor", ":pca-spring")
