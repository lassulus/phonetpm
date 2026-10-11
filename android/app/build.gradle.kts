plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Release signing for local builds, from the environment. Without
// ANDROID_KEYSTORE_PATH the release APK is left unsigned (never debug-signed);
// CI always builds it unsigned and signs it in a separate job with apksigner.
val releaseKeystore = System.getenv("ANDROID_KEYSTORE_PATH")?.takeIf { it.isNotEmpty() }
fun requireEnv(name: String): String = System.getenv(name)?.takeIf { it.isNotEmpty() }
    ?: throw GradleException("ANDROID_KEYSTORE_PATH is set but $name is not")

// Version from the release tag in CI (v1.2.3 -> 1.2.3 / code 10203), else the
// default. Every component must stay below 100 so versionCode stays monotonic.
val tagVersion = System.getenv("PHONETPM_VERSION")?.takeIf { it.isNotEmpty() }?.let { tag ->
    val match = Regex("""v(\d{1,2})\.(\d{1,2})\.(\d{1,2})""").matchEntire(tag)
        ?: throw GradleException(
            "PHONETPM_VERSION '$tag' must be vMAJOR.MINOR.PATCH with numeric components below 100"
        )
    val (major, minor, patch) = match.destructured.toList().map { it.toInt() }
    tag.removePrefix("v") to major * 10000 + minor * 100 + patch
}

android {
    namespace = "dev.phonetpm.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.phonetpm.app"
        minSdk = 31
        targetSdk = 35
        versionName = tagVersion?.first ?: "0.1.0"
        versionCode = tagVersion?.second ?: 100
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (releaseKeystore != null) {
            if (!file(releaseKeystore).isFile) {
                throw GradleException("ANDROID_KEYSTORE_PATH '$releaseKeystore' does not exist")
            }
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = requireEnv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = requireEnv("ANDROID_KEY_ALIAS")
                keyPassword = requireEnv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = releaseKeystore?.let { signingConfigs.getByName("release") }
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
