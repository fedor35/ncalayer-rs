#!/bin/bash
# Собирает AppImage из target/release/ncalayerd с помощью linuxdeploy + qt-плагина.
# Использование: packaging/appimage.sh <version>   (нужны: wget, file, patchelf; Qt6 в системе)
set -euo pipefail
VER=${1:?version}
cd "$(dirname "$0")/.."
W=target/appimage; rm -rf "$W"; mkdir -p "$W/AppDir/usr/bin" "$W/AppDir/usr/share/applications" "$W/AppDir/usr/share/icons/hicolor/scalable/apps" "$W/AppDir/usr/share/icons/hicolor/128x128/apps"
cp target/release/ncalayerd "$W/AppDir/usr/bin/"
cp packaging/ncalayerd.desktop "$W/AppDir/usr/share/applications/"
cp packaging/ncalayer-rs.svg "$W/AppDir/usr/share/icons/hicolor/scalable/apps/"
cp packaging/ncalayer-rs.png "$W/AppDir/usr/share/icons/hicolor/128x128/apps/"
cd "$W"
for t in linuxdeploy-x86_64.AppImage linuxdeploy-plugin-qt-x86_64.AppImage; do
  [ -f "$t" ] || wget -q "https://github.com/linuxdeploy/${t%%-x86_64*}/releases/download/continuous/$t"; chmod +x "$t"
done
export APPIMAGE_EXTRACT_AND_RUN=1 QMAKE=${QMAKE:-$(command -v qmake6 || command -v qmake)} VERSION="$VER"
export EXTRA_QT_MODULES="" QML_SOURCES_PATHS=""
./linuxdeploy-x86_64.AppImage --appdir AppDir --plugin qt --output appimage
ls -la *.AppImage
