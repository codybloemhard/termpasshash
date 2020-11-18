#!/bin/bash
sudo mkdir -p /usr/local/bin
cargo build --release
sudo cp -f target/release/termpasshash /usr/local/bin
sudo chmod 755 /usr/local/bin/termpasshash
