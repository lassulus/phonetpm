pluginManagement {
    repositories {
        google()
        mavenCentral()
        // Only plugin marker POMs may come from the portal (which proxies
        // arbitrary repositories); implementation artifacts must resolve from
        // google() or mavenCentral().
        gradlePluginPortal {
            content {
                includeModuleByRegex(".*", ".*\\.gradle\\.plugin")
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "phonetpm"
include(":app")
