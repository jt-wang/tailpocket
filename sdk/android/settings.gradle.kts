pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.namespace == "com.android") useModule("com.android.tools.build:gradle:${requested.version}")
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // The gomobile library built by scripts/build-mobile.sh android.
        maven { url = uri("../../build/android/m2") }
    }
}

rootProject.name = "tailpocket-android"
include(":tailpocket", ":tailpocket-ui", ":tailpocket-nsh")
