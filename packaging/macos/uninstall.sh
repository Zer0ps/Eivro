#!/bin/sh
set -eu
if [ "$(/usr/bin/id -u)" != 0 ]; then
    echo 'Run this uninstaller with sudo after quitting Eivro.' >&2
    exit 1
fi
if /bin/launchctl print system/io.eivro.tun >/dev/null 2>&1; then
    /bin/launchctl bootout system/io.eivro.tun
fi
/Library/PrivilegedHelperTools/io.eivro/eivro-tun --release
/bin/rm -f /Library/LaunchDaemons/io.eivro.tun.plist
/bin/rm -rf /Library/PrivilegedHelperTools/io.eivro
/bin/rm -rf /Applications/Eivro.app
/usr/sbin/pkgutil --forget io.eivro.pkg >/dev/null
# User settings and keys are deliberately retained.
