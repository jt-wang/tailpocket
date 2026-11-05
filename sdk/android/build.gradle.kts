plugins {
    alias(libs.plugins.android.library) apply false
    // AGP 9 supplies built-in Kotlin; org.jetbrains.kotlin.android is not applied.
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
