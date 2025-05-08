#!/bin/bash

# go to the main dir
#cd ../../../../
cd ..

flutter_rust_bridge_codegen generate \
                   --config-file flutter_rust_bridge.yaml
