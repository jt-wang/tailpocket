plugins {
    `maven-publish`
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "io.jingtao.tailpocket.ui"
    compileSdk = 36
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    publishing { singleVariant("release") }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }
    testOptions { unitTests.isIncludeAndroidResources = true }
}

// The screenshot baselines and the record switch are test inputs: a changed baseline, or going back from
// recording to comparing, runs the tests again instead of reporting them up to date.
tasks.withType<Test>().configureEach {
    inputs.dir("src/test/snapshots").withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("snapshots")
    inputs.property("recordSnapshots", providers.environmentVariable("TAILPOCKET_RECORD_SNAPSHOTS").orElse(""))
}

dependencies {
    api(project(":tailpocket"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
    // Lifts the version activity-compose asks for to the one the core library already uses.
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    // The keyboard and layout checks (nightly, on an emulator).
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}

// ./gradlew publish puts io.jingtao.tailpocket:tailpocket-ui:0.4.0 next to the gomobile library in
// build/android/m2 (React Native's module and any app can depend on it from there).
publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "io.jingtao.tailpocket"
            artifactId = "tailpocket-ui"
            version = "0.4.0"
            afterEvaluate { from(components["release"]) }
        }
    }
    repositories { maven { url = uri(rootDir.resolve("../../build/android/m2")) } }
}
