#!/bin/sh
# Builds an Apple silicon, ad-hoc signed WireGuard.app into ./build.
# Set SIGN_IDENTITY to sign with a certificate instead.
set -eu
cd "$(dirname "$0")/.."

APP_ID="${APP_ID:-dev.whyredfire.wireguard}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
HELPER_LABEL="$APP_ID.helper"
APP="build/WireGuard.app"
HELPER="$APP/Contents/Library/LaunchServices/$HELPER_LABEL"
VERSION="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" Sources/WireGuardApp/UI/macOS/Info.plist)"
BUILD="$(git rev-list --count HEAD)"
GO_VERSION="$(cd Sources/WireGuardHelper && go list -m -f '{{.Version}}' golang.zx2c4.com/wireguard | sed 's/.*-//' | cut -c1-8)"

swift build -c release --arch arm64 --product WireGuard
BIN="$(swift build -c release --arch arm64 --show-bin-path)"

rm -rf build
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$(dirname "$HELPER")"

(cd Sources/WireGuardHelper && CGO_ENABLED=1 GOARCH=arm64 CGO_CFLAGS=-mmacosx-version-min=26.0 \
    CGO_LDFLAGS=-mmacosx-version-min=26.0 go build -trimpath -ldflags=-w -o "$OLDPWD/$HELPER" .)

sed -e "s/\$(APP_ID_MACOS)/$APP_ID/g" -e "s/\$(VERSION_ID)/$BUILD/g" -e "s/\$(WIREGUARD_GO_VERSION)/$GO_VERSION/g" \
    Sources/WireGuardApp/UI/macOS/Info.plist > "$APP/Contents/Info.plist"
cp "$BIN/WireGuard" "$APP/Contents/MacOS/"
cp -R Sources/WireGuardApp/UI/macOS/Resources/ Sources/WireGuardApp/*.lproj "$APP/Contents/Resources/"

# Sign inside-out: the helper, then the app.
codesign --force --options runtime --sign "$SIGN_IDENTITY" --identifier "$HELPER_LABEL" "$HELPER"
codesign --force --options runtime --sign "$SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict "$APP"

echo "Built $APP $VERSION ($BUILD)"
