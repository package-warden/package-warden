#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf obj bin .packages
export NUGET_PACKAGES="$PWD/.packages"
dotnet nuget locals all --clear
dotnet restore HelloWorld.csproj
dotnet run --project HelloWorld.csproj
