#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf .m2 target
mvn -s settings.xml -Dmaven.repo.local=.m2 -q package
mvn -s settings.xml -Dmaven.repo.local=.m2 -q exec:java
