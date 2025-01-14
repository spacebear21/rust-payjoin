#!/usr/bin/env bash
set -e

cargo clippy --all-targets --keep-going --features=send,receive,_test_utils -- -D warnings
cargo clippy --all-targets --keep-going --features=v2,_danger-local-https,io,_test_utils -- -D warnings
