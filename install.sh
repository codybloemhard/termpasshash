#!/bin/bash
doas mkdir -p /usr/local/bin
cargo build --release
doas cp -f target/release/termpasshash /usr/local/bin
doas chmod 755 /usr/local/bin/termpasshash
