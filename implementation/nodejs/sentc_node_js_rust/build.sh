#!/bin/bash

for TARGET in \
        x86_64-apple-darwin aarch64-apple-darwin \
        x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu #\
        #x86_64-unknown-linux-musl aarch64-unknown-linux-musl
do
    #rustup target add $TARGET
    yarn exec napi build --platform --release --target=$TARGET
done

yarn exec napi artifacts -d .