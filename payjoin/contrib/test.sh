#!/usr/bin/env bash
set -e

features=("v1" "v2")

cargo test --locked --package payjoin --all-features --lib
cargo test --locked --package payjoin --all-features --test integration

for feature in "${features[@]}"; do
    cargo test --locked --package payjoin --no-default-features --features "$feature" --lib --no-run
    cargo test --locked --package payjoin --no-default-features --features "$feature" --test integration --no-run
done
