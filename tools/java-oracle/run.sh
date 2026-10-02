#!/bin/bash
# Компилирует и запускает оракул против Kalkan из кэша NCALayer. Требует JDK 8 и установленный NCALayer.
# Бандлы ищутся по Bundle-SymbolicName (их номера меняются при обновлении NCALayer):
#   knca_provider_jce_kalkan = Kalkan JCE, knca_provider_util = CMS/XML/TSP, xmldsig = Santuario с ГОСТ; main jar = slf4j/logback.
set -e
cd "$(dirname "$0")"
C=${NCALAYER_CACHE:-$HOME/.config/NCALayer/ncalayer-cache}
find_bundle() {
  for j in "$C"/bundle*/version*/bundle.jar; do
    if unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | tr -d '\r' | grep -q "^Bundle-SymbolicName: $1\$"; then echo "$j"; return; fi
  done
  echo "bundle $1 not found in $C" >&2; exit 1
}
KALKAN=$(find_bundle kz.gov.pki.kalkan.knca_provider_jce_kalkan)
UTIL=$(find_bundle kz.gov.pki.provider.knca_provider_util)
XMLDSIG=$(find_bundle kz.gov.pki.kalkan.xmldsig)
CP="$KALKAN:$UTIL:$XMLDSIG:/usr/share/ncalayer/ncalayer.jar"
[ -f Oracle.class ] || javac -cp "$CP" Oracle.java
exec java -cp "$CP:." Oracle "$@"
