plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.browser"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.browser"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "1.0-alpha"
        resourceConfigurations += listOf("en")
        base.archivesName = "browser"
    }

    buildTypes {
        debug {
            // Same hardened posture as the rest of the suite — even the
            // debug variant is a sideload-installable browsing tool, and
            // browsing tools are exactly what you DON'T want
            // jdwp-attachable. WebView page state would be readable via
            // run-as if debuggable.
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // BuildConfig.FLAVOR drives the eng-vs-prod gate for the developer
        // Diagnostics / proxy surfaces (see MainActivity `isEngBuild`). AGP 8
        // disables app-module BuildConfig generation by default, so it must be
        // opted back in for the generated FLAVOR field to exist.
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    flavorDimensions += "channel"
    productFlavors {
        create("prod") {
            dimension = "channel"
        }
        create("eng") {
            dimension = "channel"
            applicationIdSuffix = ".eng"
            versionNameSuffix = "-eng"
        }
    }
}

dependencies {
    implementation(project(":common-security"))
    // I2P is the only doctrine-compatible overlay (userspace SOCKS/HTTP,
    // never the VpnService slot). The Lokinet + Yggdrasil modules are
    // VpnService/TUN designs and are no longer a browser dependency —
    // v2 dropped their cards from the (eng-only) proxy surface. The
    // proxy surface itself is eng-gated; a prod build shows nothing.
    implementation(project(":overlay-i2p"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-viewbinding")
    implementation("androidx.compose.material3:material3")

    // androidx.webkit gives us the modern, Android-version-independent
    // WebView API surface — WebSettingsCompat, WebViewFeature checks,
    // safe-browsing toggles. Pure-Android, no Chromium fork yet (that's
    // phase 2 Cromite alignment). Plain WebView with locked-down defaults
    // is the MVP.
    implementation("androidx.webkit:webkit:1.12.1")
}
