pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "pca-ktor-server-example"

// The PCA library is built from the repository root and substituted for net.atlasauth:pca-ktor.
includeBuild("../..")
