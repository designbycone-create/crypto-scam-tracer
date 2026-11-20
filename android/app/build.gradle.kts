plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.scamhunter.guard"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.scamhunter.guard"
        minSdk = 29            // Android 10: call screening role
        targetSdk = 35
        versionCode = 3
        versionName = "0.3.0"
    }
    // Signed with the project's permanent key when CI has it (GitHub secrets), so each new version installs
    // as an update over the last and keeps the person's settings. Without it (forks, local builds) the build
    // falls back to Android's throwaway debug key.
    val ks = System.getenv("SHG_KEYSTORE")
    signingConfigs {
        if (ks != null) create("scamhunter") {
            storeFile = file(ks)
            storeType = "pkcs12"
            storePassword = System.getenv("SHG_KEYSTORE_PASSWORD")?.trim()
            keyAlias = "scamhunterguard"
            keyPassword = System.getenv("SHG_KEYSTORE_PASSWORD")?.trim()
        }
    }
    buildTypes {
        release { isMinifyEnabled = false }
        if (ks != null) getByName("debug") { signingConfig = signingConfigs.getByName("scamhunter") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")     // real org.json for JVM unit tests (Android's is a stub there)
}
