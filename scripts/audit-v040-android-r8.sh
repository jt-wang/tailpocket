#!/bin/sh
# Audit of v0.4.0 (91b6d1b), item 2: an Android app that shrinks its release build with R8 (minifyEnabled,
# what every store build does) no longer builds once it moves from io.jingtao.tailpocket:tailpocket 0.3.6
# to 0.4.0, even when it uses no push at all:
#   ERROR: R8: Missing class com.google.android.play.core.integrity.IntegrityManager (referenced from: …
#   io.jingtao.tailpocket.TailPocketPlayIntegrity …) and 15 more (com.google.android.gms.tasks.Task, …)
# TailPocketPlayIntegrity is compiled against Play Integrity (compileOnly), the AAR carries the class, and
# its consumer rules (sdk/android/tailpocket/consumer-rules.pro) say nothing about the classes an app
# without that dependency does not have. docs/PUSH.md and the class's own comment say such an app needs
# nothing ("an app that uses this class adds the dependency itself").
#
# This builds three small apps against a Maven folder with the Android libraries and runs R8 on each:
#   nopush     TailPocket as in v0.3.6, no push
#   push       TailPocketPushPhone with TailPocketKeystorePushStore, no attester, no Play Integrity
#   integrity  TailPocketPlayIntegrity, with com.google.android.play:integrity added (the control)
# All three must pass. With the v0.3.6 Maven folder, nopush passes (the other two need v0.4.0's classes).
#
# usage: scripts/audit-v040-android-r8.sh [m2 dir] [version] [case...]
#   m2 dir   default build/android/m2 (after scripts/build-mobile.sh android and, in sdk/android,
#            ./gradlew publish), or the m2 folder unzipped from a release's tailpocket-android-m2.zip
#   version  default: the version sdk/android/tailpocket/build.gradle.kts publishes
#   TAILPOCKET_GRADLE_ARGS, e.g. --offline
set -eu
cd "$(dirname "$0")/.."
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
m2=${1:-build/android/m2}
[ -d "$m2/io/jingtao/tailpocket/tailpocket" ] || { echo "no io.jingtao.tailpocket:tailpocket in $m2" >&2; exit 2; }
m2=$(cd "$m2" && pwd)
version=${2:-$(awk -F'"' '$1 ~ /^ *version = $/ {print $2}' sdk/android/tailpocket/build.gradle.kts)}
[ -n "$version" ] || { echo "no version" >&2; exit 2; }
if [ $# -gt 2 ]; then shift 2; else set --; fi
cases=${*:-nopush push integrity}
agp=$(awk -F'"' '$1 == "agp = " {print $2}' sdk/android/gradle/libs.versions.toml)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R sdk/android/gradlew sdk/android/gradle sdk/android/gradle.properties "$tmp/"
cat > "$tmp/settings.gradle.kts" <<EOF
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    resolutionStrategy { eachPlugin { if (requested.id.namespace == "com.android") useModule("com.android.tools.build:gradle:\${requested.version}") } }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral(); maven { url = uri("$m2") } }
}
rootProject.name = "audit-r8"
include(":nopush", ":push", ":integrity")
EOF
echo "plugins { id(\"com.android.application\") version \"$agp\" apply false }" > "$tmp/build.gradle.kts"

# app <name> <extra dependency line> <onCreate body>, imports on stdin
app() {
  dir="$tmp/$1/src/main/java/audit/r8/$1"
  mkdir -p "$dir"
  cat > "$tmp/$1/build.gradle.kts" <<EOF
plugins { id("com.android.application") }
android {
    namespace = "audit.r8.$1"
    compileSdk = 36
    defaultConfig { applicationId = "audit.r8.$1"; minSdk = 26; targetSdk = 36; versionCode = 1; versionName = "1" }
    buildTypes { release { isMinifyEnabled = true; proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt")) } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies {
    implementation("io.jingtao.tailpocket:tailpocket:$version")
    $2
}
EOF
  cat > "$tmp/$1/src/main/AndroidManifest.xml" <<EOF
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="$1">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
        </activity>
    </application>
</manifest>
EOF
  {
    echo "package audit.r8.$1"
    echo "import android.app.Activity"
    echo "import android.os.Bundle"
    cat
    echo "class MainActivity : Activity() {"
    echo "    override fun onCreate(savedInstanceState: Bundle?) {"
    echo "        super.onCreate(savedInstanceState)"
    echo "        $3"
    echo "    }"
    echo "}"
  } > "$dir/MainActivity.kt"
}

app nopush "" 'title = TailPocket.default.newKey()' <<'EOF'
import io.jingtao.tailpocket.TailPocket
EOF
app push "" 'title = TailPocketPushPhone(TailPocket.default, TailPocketKeystorePushStore(this)).toString()' <<'EOF'
import io.jingtao.tailpocket.TailPocket
import io.jingtao.tailpocket.TailPocketKeystorePushStore
import io.jingtao.tailpocket.TailPocketPushPhone
EOF
app integrity 'implementation("com.google.android.play:integrity:1.4.0")' \
  'title = TailPocketPushPhone(TailPocket.default, TailPocketKeystorePushStore(this), TailPocketPlayIntegrity.standard(this, 1L)).toString()' <<'EOF'
import io.jingtao.tailpocket.TailPocket
import io.jingtao.tailpocket.TailPocketKeystorePushStore
import io.jingtao.tailpocket.TailPocketPlayIntegrity
import io.jingtao.tailpocket.TailPocketPushPhone
EOF

status=0
for c in $cases; do
  # shellcheck disable=SC2086
  if (cd "$tmp" && ./gradlew -q ${TAILPOCKET_GRADLE_ARGS:-} ":$c:minifyReleaseWithR8") > "$tmp/$c.log" 2>&1; then
    echo "PASS: $c (tailpocket $version): R8 shrinks the app"
  else
    grep -E '^e: |Missing class|What went wrong|^> ' "$tmp/$c.log" | cut -c1-240 | head -3 >&2
    echo "FAIL: $c (tailpocket $version): $(grep -c 'Missing class' "$tmp/$c.log" || true) missing classes" >&2
    status=1
  fi
done
exit $status
