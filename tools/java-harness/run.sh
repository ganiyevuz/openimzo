#!/bin/bash
# Compiles and runs the harness against the jars shipped inside the installed original E-IMZO.
set -euo pipefail
HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
APP=/Applications/E-IMZO.app/Contents/app
CP="$APP/E-IMZO.jar:$(ls "$APP"/lib/*.jar | tr '\n' ':')"
JAVA_HOME="$(/usr/libexec/java_home -v 17)"
"$JAVA_HOME/bin/javac" -cp "$CP" -d "$HARNESS_DIR" "$HARNESS_DIRthe original"
"$JAVA_HOME/bin/java" -cp "$CP:$HARNESS_DIR" Harness "$@"
