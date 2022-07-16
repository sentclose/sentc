# Sentc 
from Sentclose

An end-to-end encryption sdk for developer with user management.

Available in:
- Javascript 
- Dart with flutter

## Contains

- User management: Register, login, authentication, authorisation
- Group management: Invite or add member, role management, group encryption
- Handling large files in browser and native


## Build from source

#### Requirements:
- Rust MRV 1.6.0
- For flutter:
  - cargo-ndk
  - llvm
- For Javascript:
  - wasm-pack
  - node js min. version 14 lts

### Build for rust

Build rust in the current workspace.

````shell
cargo build --release
````

### Build javascript (wasm)

1. Build with wasm pack in `implementation/js/sentc_wasm`

````shell
cd ./implementation/js/sentc_wasm

wasm-pack build --target web 
````

2. Build typescript code in `implementation/js/sentc_wasm`

````shell
cd ./implementation/js/sentc_wasm

npm run build
````

### Build flutter

Build with flutter rust bridge and cargo-ndk.

1. In the current workspace, generate the flutter code

````shell
flutter_rust_bridge_codegen --rust-input implementation/dart/sentc/rust/src/sentc.rs --dart-output implementation/dart/sentc/lib/generated.dart --llvm-path <path-to-your-llvm>
````

2. build the android code with cargo-ndk in `implementation/dart/sentc/rust`

````shell
cd ./implementation/dart/sentc/rust

cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ../android/src/main/jniLibs build --release
````