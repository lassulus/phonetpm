plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Release signing from the environment (CI secrets). Without a keystore the
// release build falls back to the debug key so local `assembleRelease` still
// yields an installable APK.
val releaseKeystore = System.getenv("ANDROID_KEYSTORE_PATH")?.takeIf { file(it).exists() }
// Version from the git tag in CI (v1.2.3 -> 1.2.3 / code 10203), else the default.
val versionFromTag = System.getenv("PHONETPM_VERSION")?.removePrefix("v")

android {
    namespace = "dev.phonetpm.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.phonetpm.app"
        minSdk = 31
        targetSdk = 35
        versionName = versionFromTag ?: "0.1.0"
        versionCode = versionName!!.split(".").take(3).map { it.toIntOrNull() ?: 0 }
            .fold(0) { acc, n -> acc * 100 + n }.coerceAtLeast(1)
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (releaseKeystore != null) signingConfigs.getByName("release")
                            else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        jvmToolchain(17)
    }

    buildFeatures {
        compose = true
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment.ktx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation("${libs.jna.get()}@aar")
    implementation(libs.zxing.core)
    implementation(libs.unifiedpush.connector)
}
