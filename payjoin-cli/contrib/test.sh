#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --no-default-features --features=_danger-local-https,v2,_test_utils --test e2e
cargo test --locked --package payjoin-cli --verbose --features=_danger-local-https,_test_utils
