#!/bin/bash

cd ..

zig_build () {
    local TARGET="$1"
    local PLATFORM_NAME="$2"
    local LIBNAME="$3"
    #rustup target add "$TARGET"
    cargo zigbuild --target "$TARGET" -r --package sentc_flutter
    mkdir -p "../sentc_flutter/sentc/linux/$PLATFORM_NAME/"
    cp "../../../target/$TARGET/release/$LIBNAME" "../sentc_flutter/sentc/linux/$PLATFORM_NAME/"
}

win_build () {
    local TARGET="$1"
    local PLATFORM_NAME="$2"
    local LIBNAME="$3"
    #rustup target add "$TARGET"
    cargo xwin build --target "$TARGET" -r --package sentc_flutter
    mkdir -p "../sentc_flutter/sentc/windows/$PLATFORM_NAME/"
    cp "../../../target/$TARGET/release/$LIBNAME" "../sentc_flutter/sentc/windows/$PLATFORM_NAME/"
}

# Build all the dynamic libraries
LINUX_LIBNAME=libsentc_flutter.so
zig_build aarch64-unknown-linux-gnu linux-arm64 $LINUX_LIBNAME
zig_build x86_64-unknown-linux-gnu linux-x64 $LINUX_LIBNAME

WINDOWS_LIBNAME=sentc_flutter.dll
#win_build aarch64-pc-windows-msvc windows-arm64 $WINDOWS_LIBNAME # windows arm is not supported by ring atm
win_build x86_64-pc-windows-msvc windows-x64 $WINDOWS_LIBNAME