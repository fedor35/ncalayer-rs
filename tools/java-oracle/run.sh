#!/bin/bash
# Компилирует и запускает оракул против Kalkan из кэша NCALayer. Требует JDK 8 и установленный NCALayer.
set -e
cd "$(dirname "$0")"
K=${KALKAN_JAR:-$HOME/.config/NCALayer/ncalayer-cache/bundle10/version0.0/bundle.jar}
[ -f Oracle.class ] || javac -cp "$K" Oracle.java
exec java -cp "$K:." Oracle "$@"
