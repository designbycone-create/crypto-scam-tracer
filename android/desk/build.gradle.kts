plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.scamhunter.desk"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.scamhunter.desk"     // separate from ScamHunter Guard (org.scamhunter.guard)
        minSdk = 29
        targetSdk = 35
        versionCode = 3
        versionName = "0.1.2"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    // QR scanning for pairing: ZXing Android Embedded (Apache-2.0) and ZXing core (Apache-2.0). See NOTICE.md.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // The scanner calls androidx.core (ContextCompat, ActivityCompat) when it opens the camera, but its published
    // package doesn't bring it along, so the app must (Apache-2.0). Without it: NoClassDefFoundError on "Scan the code".
    implementation("androidx.core:core:1.13.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
