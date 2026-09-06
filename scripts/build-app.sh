#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="Gofing.app"
APP_PATH="$DIR/$APP_NAME"
CONTENTS="$APP_PATH/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES_DIR="$CONTENTS/Resources"

echo "Stopping any existing Gofing processes..."
make -C "$DIR" kill 2>/dev/null || true

echo "Building Gofing binary with go-webui..."
make -C "$DIR" build

echo "Creating native macOS application bundle..."
rm -rf "$APP_PATH"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Mach-O binary as CFBundleExecutable (shell launchers are unreliable in Dock/Finder).
cp "$DIR/gofing" "$MACOS_DIR/Gofing"
chmod +x "$MACOS_DIR/Gofing"

if [ -f "$DIR/build/gofing-notify" ]; then
  echo "Bundling notification helper..."
  cp "$DIR/build/gofing-notify" "$MACOS_DIR/gofing-notify"
  chmod +x "$MACOS_DIR/gofing-notify"
fi

ICON_KEYS=""
if [ -f "$DIR/build/Gofing.icns" ]; then
  echo "Applying custom application icon..."
  cp "$DIR/build/Gofing.icns" "$RESOURCES_DIR/Gofing.icns"
  ICON_KEYS=$'    <key>CFBundleIconFile</key>\n    <string>Gofing</string>'
fi

if [ -f "$DIR/build/Gofing.png" ]; then
  cp "$DIR/build/Gofing.png" "$RESOURCES_DIR/Gofing.png"
fi

cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleName</key>
    <string>Gofing</string>
    <key>CFBundleDisplayName</key>
    <string>Gofing</string>
    <key>CFBundleIdentifier</key>
    <string>com.jaredwarren.gofing</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleExecutable</key>
    <string>Gofing</string>
${ICON_KEYS}
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

echo "Code-signing application bundle (ad-hoc)..."
codesign --force --deep --sign - "$APP_PATH" 2>/dev/null || true

if [ -d "/Applications/$APP_NAME" ]; then
  echo "Syncing updated app bundle to /Applications/$APP_NAME..."
  rm -rf "/Applications/$APP_NAME"
  cp -R "$APP_PATH" "/Applications/$APP_NAME"
fi

echo "Done! Native desktop application created at: $APP_PATH"
echo ""
echo "Launch:  open \"$APP_PATH\""
echo "Install: cp -R \"$APP_PATH\" /Applications/ && open -a Gofing"
echo "Logs:    ~/Library/Logs/Gofing/gofing.log"
echo "Then right-click the Dock icon → Options → Keep in Dock"
