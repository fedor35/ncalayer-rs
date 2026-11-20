#!/bin/bash
# CsrOracle на бандлах из установщика NCALayer (NCA_DIR — распакованный ncalayer.zip с ncalayer.sh и kncabundles/).
set -e
cd "$(dirname "$0")"
D=${NCA_DIR:?NCA_DIR=каталог с ncalayer.sh и kncabundles/}
CP="$(ls $D/kncabundles/kalkancrypt-*.jar):$(ls $D/kncabundles/knca_provider_util-*.jar):$(ls $D/kncabundles/knca_applet-*.jar):$D/ncalayer.sh"
J=/usr/lib/jvm/java-8-openjdk/bin
[ CsrOracle.class -nt CsrOracle.java ] || $J/javac -cp "$CP" CsrOracle.java
exec $J/java -cp "$CP:." CsrOracle "$@"
