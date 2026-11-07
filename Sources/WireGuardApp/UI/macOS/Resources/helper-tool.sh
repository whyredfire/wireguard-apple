#!/bin/sh
# Installs or removes the WireGuard helper LaunchDaemon. Must run as root.
set -eu

LABEL="dev.whyredfire.wireguard.helper"
TOOL="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

unload() {
    launchctl bootout "system/$LABEL" 2>/dev/null || true
}

case "${1:-}" in
    install)
        tool="$2" uid="$3" requirement="$4"
        case "$uid" in '' | *[!0-9]*) echo "invalid uid" >&2; exit 64 ;; esac
        case "$requirement" in *[\<\>\&]*) echo "invalid requirement" >&2; exit 64 ;; esac
        unload
        mkdir -p /Library/PrivilegedHelperTools
        install -m 755 -o root -g wheel "$tool" "$TOOL"
        cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$TOOL</string>
        <string>-uid</string>
        <string>$uid</string>
        <string>-requirement</string>
        <string>$requirement</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
PLIST
        chown root:wheel "$PLIST"
        chmod 644 "$PLIST"
        # bootout is asynchronous; retry until the old job is gone.
        for _ in 1 2 3 4 5; do
            launchctl bootstrap system "$PLIST" 2>/dev/null && exit 0
            sleep 1
        done
        launchctl bootstrap system "$PLIST"
        ;;
    uninstall)
        unload
        rm -f "$TOOL" "$PLIST"
        ;;
    *)
        echo "usage: $0 install <tool> <uid> <code requirement> | uninstall" >&2
        exit 64
        ;;
esac
