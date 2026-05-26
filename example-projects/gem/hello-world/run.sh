#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -f Gemfile.lock
rm -rf vendor/bundle .bundle
bundle config set --local path vendor/bundle
bundle install --full-index
bundle exec ruby hello.rb
