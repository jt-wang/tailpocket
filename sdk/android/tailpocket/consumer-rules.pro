# gomobile's generated Java classes are called from native code.
-keep class go.** { *; }
-keep class io.jingtao.tailpocket.connectmobile.** { *; }
# TailPocketPlayIntegrity is compiled against Play Integrity (compileOnly): an app that uses it adds the
# dependency itself, and an app that does not must still shrink with R8 (WANG-77, v0.4.0 audit).
-dontwarn com.google.android.play.core.integrity.**
-dontwarn com.google.android.gms.tasks.**
