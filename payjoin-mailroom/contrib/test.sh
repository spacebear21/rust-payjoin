#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-mailroom --all-features --lib
cargo test --locked --package payjoin-mailroom --all-features --test integration
