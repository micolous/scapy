#!/bin/bash
# Install Tunnelblick's signed tuntaposx kexts
# https://sourceforge.net/p/tuntaposx/bugs/28/

# Note: This only works on macOS 10.12 and earlier, and is broken on 10.13:
# https://github.com/travis-ci/travis-ci/issues/9377

TB_URL="https://tunnelblick.net/release/Tunnelblick_3.8.0_build_5370.dmg"
TB_DMG="Tunnelblick_3.8.0_build_5370.dmg"
TB_SHA256="4131ef7ab1b328e0efd62867cb4a35796fa22aaaa160ab478215f56197669925"
TB_VOL="/Volumes/Tunnelblick"
TB_KEXT_PATH="${TB_VOL}/Tunnelblick.app/Contents/Resources/"

pushd /tmp
rm -f $TB_DMG
curl -L -o $TB_DMG $TB_URL

# Check SHA256, die if incorrect
echo "${TB_SHA256} *${TB_DMG}" | shasum -ba 256 -c - || exit 1

# Mount DMG
hdiutil mount $TB_DMG
pushd ${TB_KEXT_PATH}

# Note: kexts are directories
sudo cp -r tap-notarized.kext tun-notarized.kext /Library/Extensions/

# Unmount DMG
popd
hdiutil detach ${TB_VOL}

chown -R root:wheel /Library/Extensions/tap-notarized.kext /Library/Extensions/tun-notarized.kext

# Load the kexts
sudo kextload -v 1 /Library/Extensions/tap-notarized.kext
sudo kextload -v 1 /Library/Extensions/tun-notarized.kext

ls -la /dev/tap* /dev/tun*
