![crates.io](https://img.shields.io/crates/v/wapc.svg)&nbsp;
![travis](https://travis-ci.org/wapc/wapc-rust.svg?branch=master)&nbsp;
![license](https://img.shields.io/crates/l/wapc.svg)

# waPC

This is the Rust implementation of the **waPC** standard for WebAssembly host runtimes. It allows any WebAssembly module to be loaded as a guest and receive requests for invocation as well as to make its own function requests of the host. This library allows for both "pure" (completely isolated) wasm modules as well as WASI modules

## Example

The following is a simple example of synchronous, bi-directional procedure calls between a WebAssembly host runtime and the guest module.

```rust
extern crate wapc;
use wapc::prelude::*;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = load_file();
    let mut host = WapcHost::new(host_callback, &module, None)?;

    let res = host.call("wapc:sample!Hello", b"this is a test")?;
    assert_eq!(res, b"hello world!");
    Ok(())
}

fn host_callback(op: &str, payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Guest invoked '{}' with payload of {} bytes", op, payload.len());
    Ok(vec![])
}
```

To see a similar demo in action, enter the following in your shell:
```
$ cargo run --example demo
```

waPC utilizes the [Bytecode Alliance](https://bytecodealliance.org/) runtime [wasmtime](https://github.com/bytecodealliance/wasmtime) for low-level WebAssembly compilation and execution.

**NOTE** - The current version of waPC does not support loading WASI modules. That is only a temporary limitation expected to go away in the next version.
