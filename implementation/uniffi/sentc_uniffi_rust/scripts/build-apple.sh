cd ..

BASENAME=sentc_uniffi_rust

 # Build static libs
export IPHONEOS_DEPLOYMENT_TARGET=13.0
 for TARGET in \
         aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim \
         x86_64-apple-darwin aarch64-apple-darwin
 do
     #rustup target add $TARGET
      cargo build -r --target=$TARGET --package $BASENAME
 done

generate_ffi() {
  echo "Generating framework module mapping and FFI bindings"
  # NOTE: Convention requires the modulemap be named module.modulemap
  # Choose any compiled lib
  cargo run \
                -p sentc_uniffi_bindgen --bin swift \
                -- ../../../target/aarch64-apple-ios/release/lib$1.a generated/swift/resources --swift-sources \
                --headers \
                --modulemap --module-name $1FFI --modulemap-filename module.modulemap

  mv generated/swift/resources/*.swift generated/swift/source/
  mv generated/swift/resources/module.modulemap generated/swift/resources/module.modulemap
}

generate_ffi $BASENAME

FRAMEWORK="Sentc.xcframework"
LIBNAME=lib$BASENAME.a
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
    -library $IOS_SIM_LIPO -headers generated/swift/resources \
    -library $MAC_LIPO -headers generated/swift/resources \
    -library ../../../target/aarch64-apple-ios/release/$LIBNAME -headers generated/swift/resources \
    -output $FRAMEWORK

zip -r generated/swift/$FRAMEWORK.zip $FRAMEWORK

# Cleanup
rm -rf ios-sim-lipo mac-lipo $FRAMEWORK