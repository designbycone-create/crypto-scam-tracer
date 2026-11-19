pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "ScamHunter"
include(":app")       // ScamHunter Guard (calls and messages)
include(":desk")      // ScamHunter Threat Desk (your PC's Desk, on your phone)
