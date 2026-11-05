#!/bin/sh
# Renders docs/illustrations/*.html into looping GIFs for the README, light and dark:
# docs/images/<name>-light.gif and <name>-dark.gif. Each page draws one exact moment for ?t=<ms>, so
# every frame is a screenshot by headless Chrome. Needs ffmpeg and a Chrome: CHROME=<binary>, or
# Playwright's headless shell, or Google Chrome in /Applications.
set -eu
cd "$(dirname "$0")/.."
FPS="${FPS:-15}"
CHROME="${CHROME:-$(ls -d "$HOME"/Library/Caches/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell 2>/dev/null | tail -1)}"
[ -n "$CHROME" ] || CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
[ -x "$CHROME" ] || { echo "no Chrome found; set CHROME"; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p docs/images

for page in docs/illustrations/*.html; do
  name=$(basename "$page" .html)
  [ "$name" = launch ] && continue  # an MP4, made by scripts/render-launch-video.sh
  duration=$(sed -n 's/.*var DURATION = \([0-9]*\);.*/\1/p' "$page")
  [ -n "$duration" ] || { echo "$page has no DURATION"; exit 1; }
  frames=$((duration * FPS / 1000))
  for theme in light dark; do
    dir="$work/$name-$theme"
    mkdir -p "$dir"
    i=0
    while [ "$i" -lt "$frames" ]; do
      printf '%s %s\n' "$i" "$((i * 1000 / FPS))"
      i=$((i + 1))
    done | xargs -P 6 -n 2 sh -c '
      # $0 Chrome, $1 frame folder, $2 page, $3 theme, then the frame number and its time (ms).
      "$0" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 --window-size=1200,675 \
        --virtual-time-budget=300 --screenshot="$1/$(printf %04d "$4").png" "file://$2?t=$5&theme=$3" >/dev/null 2>&1
    ' "$CHROME" "$dir" "$PWD/$page" "$theme"
    count=$(ls "$dir" | wc -l | tr -d ' ')
    [ "$count" -eq "$frames" ] || { echo "$name $theme: $count of $frames frames"; exit 1; }
    ffmpeg -loglevel error -y -framerate "$FPS" -i "$dir/%04d.png" \
      -vf "split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
      -loop 0 "docs/images/$name-$theme.gif"
    echo "docs/images/$name-$theme.gif ($frames frames, $(du -h "docs/images/$name-$theme.gif" | cut -f1))"
  done
done
