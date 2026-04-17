#!/bin/bash

cd ..

# Build static libs
for TARGET in \
        aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim \
        x86_64-apple-darwin aarch64-apple-darwin
do
    #rustup target add $TARGET
    cargo build -r --target=$TARGET --package sentc_flutter
done

# Create XCFramework zip
FRAMEWORK="Sentc.xcframework"
LIBNAME=libsentc_flutter.a
mkdir mac-lipo ios-sim-lipo
IOS_SIM_LIPO=ios-sim-lipo/$LIBNAME
MAC_LIPO=mac-lipo/$LIBNAME
lipo -create -output $IOS_SIM_LIPO \
        ../../../target/aarch64-apple-ios-sim/release/$LIBNAME \
        ../../../target/x86_64-apple-ios/release/$LIBNAME
lipo -create -output $MAC_LIPO \
        ../../../target/aarch64-apple-darwin/release/$LIBNAME \
        ../../../target/x86_64-apple-darwin/release/$LIBNAME
xcodebuild -create-xcframework \
        -library $IOS_SIM_LIPO \
        -library $MAC_LIPO \
        -library ../../../target/aarch64-apple-ios/release/$LIBNAME \
        -output $FRAMEWORK

zip -r $FRAMEWORK.zip $FRAMEWORK

cp $FRAMEWORK.zip ../sentc_flutter/sentc/ios/Frameworks

# Cleanup
rm -rf ios-sim-lipo mac-lipo $FRAMEWORK $FRAMEWORK.zip
