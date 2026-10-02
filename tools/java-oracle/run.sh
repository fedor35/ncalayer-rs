#!/bin/bash
# Компилирует и запускает оракул против Kalkan из кэша NCALayer. Требует JDK 8 и установленный NCALayer.
# Бандлы: 10 = Kalkan JCE, 15 = provider-utils (CMS/XML/TSP), 17 = xmldsig (Santuario), main jar = slf4j/logback.
set -e
cd "$(dirname "$0")"
C=${NCALAYER_CACHE:-$HOME/.config/NCALayer/ncalayer-cache}
CP="$C/bundle10/version0.0/bundle.jar:$C/bundle15/version0.0/bundle.jar:$C/bundle17/version0.0/bundle.jar:/usr/share/ncalayer/ncalayer.jar"
[ -f Oracle.class ] || javac -cp "$CP" Oracle.java
exec java -cp "$CP:." Oracle "$@"
