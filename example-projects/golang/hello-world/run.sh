#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf .gopath go.sum
export GOPATH="$PWD/.gopath"
export GOPROXY="http://localhost:5050/v1/proxy/golang"
export GONOSUMDB="*"
go mod tidy
go run main.go
