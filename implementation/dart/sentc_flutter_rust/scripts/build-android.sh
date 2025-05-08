#!/bin/bash

# Set up cargo-ndk
#cargo install cargo-ndk
#rustup target add \
#        aarch64-linux-android \
#        armv7-linux-androideabi \
#        x86_64-linux-android \
#        i686-linux-android

cd ..

# Build the android libraries in the jniLibs directory
cargo ndk --manifest-path Cargo.toml \
        -t armeabi-v7a \
        -t arm64-v8a \
        -t x86 \
        -t x86_64 \
        -o ../sentc_flutter/sentc/android/src/main/jniLibs \
        build --release --package sentc_flutter

