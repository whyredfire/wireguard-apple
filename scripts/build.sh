#!/bin/sh
# Builds an Apple silicon WireGuard.app into ./build.
#
# Ad-hoc signed by default: the app launches, but tunnels can't start, as the network extension
# entitlement requires a provisioning profile. For a working build, pass a signing identity, your
# team ID and the provisioning profiles of the app and the extension:
#   SIGN_IDENTITY="Apple Development: …" TEAM_ID=… APP_PROFILE=… EXTENSION_PROFILE=… scripts/build.sh
set -eu
cd "$(dirname "$0")/.."

APP_ID="${APP_ID:-dev.whyredfire.wireguard}"
TEAM_ID="${TEAM_ID:-}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
ARCH="arm64"
APP="build/WireGuard.app"
EXTENSION="$APP/Contents/PlugIns/WireGuardNetworkExtension.appex"
HELPER="$APP/Contents/Library/LoginItems/WireGuardLoginItemHelper.app"
GO_BUILD=".build/wireguard-go"
VERSION="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" Sources/WireGuardApp/UI/macOS/Info.plist)"
BUILD="$(git rev-list --count HEAD)"

if [ "$SIGN_IDENTITY" != - ]; then
    : "${TEAM_ID:?TEAM_ID is required for a signed build}"
    : "${APP_PROFILE:?APP_PROFILE is required for a signed build}"
    : "${EXTENSION_PROFILE:?EXTENSION_PROFILE is required for a signed build}"
fi

make -C Sources/WireGuardKitGo build version-header ARCHS="$ARCH" \
    CONFIGURATION_BUILD_DIR="$PWD/$GO_BUILD" CONFIGURATION_TEMP_DIR="$PWD/$GO_BUILD/tmp" \
    MACOSX_DEPLOYMENT_TARGET=13.0 DEPLOYMENT_TARGET_CLANG_FLAG_NAME=mmacosx-version-min \
    DEPLOYMENT_TARGET_CLANG_ENV_NAME=MACOSX_DEPLOYMENT_TARGET
GO_VERSION="$(sed -n 's/.*"\(.*\)"/\1/p' "$GO_BUILD/wireguard-go-version.h")"

swift build -c release --arch "$ARCH" -Xlinker -L"$GO_BUILD"
BIN="$(swift build -c release --arch "$ARCH" --show-bin-path)"

# Fills in the $(…) variables of the Info.plists and entitlements.
fill() {
    sed -e "s/\$(APP_ID_MACOS)/$APP_ID/g" -e "s/\$(DEVELOPMENT_TEAM)/$TEAM_ID/g" \
        -e "s/\$(VERSION_NAME)/$VERSION/g" -e "s/\$(VERSION_ID)/$BUILD/g" \
        -e "s/\$(WIREGUARD_GO_VERSION)/$GO_VERSION/g" "$1" > "$2"
}

rm -rf build
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$EXTENSION/Contents/MacOS" "$HELPER/Contents/MacOS" build/entitlements

fill Sources/WireGuardApp/UI/macOS/Info.plist "$APP/Contents/Info.plist"
fill Sources/WireGuardNetworkExtension/Info.plist "$EXTENSION/Contents/Info.plist"
fill Sources/WireGuardLoginItemHelper/Info.plist "$HELPER/Contents/Info.plist"
cp "$BIN/WireGuard" "$APP/Contents/MacOS/"
cp "$BIN/WireGuardNetworkExtension" "$EXTENSION/Contents/MacOS/"
cp "$BIN/WireGuardLoginItemHelper" "$HELPER/Contents/MacOS/"
cp -R Sources/WireGuardApp/UI/macOS/Resources/ Sources/WireGuardApp/*.lproj "$APP/Contents/Resources/"

# sign <bundle> <entitlements> [<provisioning profile>]
sign() {
    entitlements="build/entitlements/$(basename "$2")"
    fill "$2" "$entitlements"
    if [ "$SIGN_IDENTITY" = - ]; then
        # Ad-hoc signatures can't carry restricted entitlements or a team's app group.
        for key in com.apple.developer.networking.networkextension com.apple.security.application-groups; do
            /usr/libexec/PlistBuddy -c "Delete :$key" "$entitlements" >/dev/null 2>&1 || true
        done
    elif [ $# -eq 3 ]; then
        cp "$3" "$1/Contents/embedded.provisionprofile"
    fi
    codesign --force --options runtime --sign "$SIGN_IDENTITY" --entitlements "$entitlements" "$1"
}

# Sign inside-out: the login item helper and the extension, then the app.
sign "$HELPER" Sources/WireGuardLoginItemHelper/LoginItemHelper.entitlements
sign "$EXTENSION" Sources/WireGuardNetworkExtension/WireGuardNetworkExtension_macOS.entitlements "${EXTENSION_PROFILE:-}"
sign "$APP" Sources/WireGuardApp/UI/macOS/WireGuard.entitlements "${APP_PROFILE:-}"
codesign --verify --deep --strict "$APP"

echo "Built $APP $VERSION ($BUILD)"
