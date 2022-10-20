To (attempt) to build to a wasm binary for WASI (`wasm32-wasi`, not `wasm32-unknown-unknown`, which is the default for wasm-pack. Used for rngs):
1. install cargo wasi: `cargo install cargo-wasi`
2. build: `cargo wasi build --features "npm"`

This doesn't work yet.
