#!/bin/bash
# Re-sign and reinstall MacRemoteClient (iPhone, over Wi-Fi) and MacRemoteServer (/Applications)
# when the free-account provisioning profile is about to expire (7-day lifetime).
#
#   scripts/refresh-signing.sh           # only if the profile expires within THRESHOLD_HOURS
#   scripts/refresh-signing.sh --force   # always rebuild and reinstall
#   scripts/refresh-signing.sh --client-only | --server-only
#
# Needs: iPhone paired, "Connect via network" enabled in Xcode, same Wi-Fi, phone unlocked.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="$HOME/.macremote-refresh"
DERIVED="$STATE_DIR/DerivedData"
EXPIRY_FILE="$STATE_DIR/client-profile-expiry"
THRESHOLD_HOURS="${THRESHOLD_HOURS:-36}"
DEVICE="${MACREMOTE_DEVICE:-00008160-001A225234800036}"
CLIENT_BUNDLE_ID="com.naduda.pr.MacRemoteClient"

force=0; do_client=1; do_server=1
for a in "$@"; do
  case "$a" in
    --force) force=1 ;;
    --client-only) do_server=0 ;;
    --server-only) do_client=0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR"
log() { echo "[refresh $(date '+%F %T')] $*"; }

profile_expiry_epoch() {
  security cms -D -i "$1" 2>/dev/null > "$STATE_DIR/profile.plist" || return 1
  local d; d=$(/usr/libexec/PlistBuddy -c "Print :ExpirationDate" "$STATE_DIR/profile.plist" 2>/dev/null) || return 1
  date -j -f "%a %b %d %T %Z %Y" "$d" +%s 2>/dev/null
}

needs_refresh() {
  [ "$force" = 1 ] && return 0
  [ -f "$EXPIRY_FILE" ] || return 0
  local exp now; exp=$(cat "$EXPIRY_FILE"); now=$(date +%s)
  [ $(( (exp - now) / 3600 )) -lt "$THRESHOLD_HOURS" ]
}

if ! needs_refresh; then
  log "profile still valid until $(date -r "$(cat "$EXPIRY_FILE")" '+%F %H:%M'); nothing to do"
  exit 0
fi

# Xcode reuses a cached profile until ~1h before expiry, so a refresh 36h early would reinstall the
# same soon-to-die profile. Drop the cached MacRemote profiles to force a freshly issued one.
for p in "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"/*.mobileprovision \
         "$HOME/Library/MobileDevice/Provisioning Profiles"/*.mobileprovision; do
  [ -f "$p" ] || continue
  if security cms -D -i "$p" 2>/dev/null | grep -q "com.naduda.pr.MacRemote"; then
    log "removing cached profile $(basename "$p")"
    rm -f "$p"
  fi
done

cd "$ROOT" || exit 1
[ -d MacRemote.xcworkspace ] || tuist generate --no-open || exit 1

rc=0

if [ "$do_client" = 1 ]; then
  log "building MacRemoteClient"
  if xcodebuild -workspace MacRemote.xcworkspace -scheme MacRemoteClient -configuration Debug \
       -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" -allowProvisioningUpdates build -quiet; then
    app="$DERIVED/Build/Products/Debug-iphoneos/MacRemoteClient.app"
    log "installing on device $DEVICE"
    if xcrun devicectl device install app --device "$DEVICE" "$app"; then
      exp=$(profile_expiry_epoch "$app/embedded.mobileprovision") && echo "$exp" > "$EXPIRY_FILE"
      log "client installed; profile valid until $(date -r "${exp:-0}" '+%F %H:%M')"
      [ $(( (${exp:-0} - $(date +%s)) / 3600 )) -ge "$THRESHOLD_HOURS" ] || { log "WARNING: profile was not renewed"; rc=1; }
    else
      log "client install FAILED (phone unlocked, on the same Wi-Fi?)"; rc=1
    fi
  else
    log "client build FAILED"; rc=1
  fi
fi

if [ "$do_server" = 1 ]; then
  log "building MacRemoteServer"
  if xcodebuild -workspace MacRemote.xcworkspace -scheme MacRemoteServer -configuration Debug \
       -derivedDataPath "$DERIVED" -allowProvisioningUpdates build -quiet; then
    pkill -x MacRemoteServer 2>/dev/null; sleep 1
    rm -rf /Applications/MacRemoteServer.app
    cp -R "$DERIVED/Build/Products/Debug/MacRemoteServer.app" /Applications/ && open /Applications/MacRemoteServer.app
    log "server reinstalled and launched"
  else
    log "server build FAILED"; rc=1
  fi
fi

exit $rc
