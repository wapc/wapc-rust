![crates.io](https://img.shields.io/crates/v/wapc.svg)&nbsp;
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
    let mut host = WapcHost::new(|id: u64, bd: &str, ns: &str, op: &str, payload: &str|{
        println!("Guest {} invoked '{}->{}:{}' with payload of {} bytes", id, bd, ns, op, payload.len());
        Ok(vec![])
    }, &module, None)?;

    let res = host.call("wapc:sample!Hello", b"this is a test")?;
    assert_eq!(res, b"hello world!");
    Ok(())
}
```

To see a similar demo in action, enter the following in your shell:
```
$ cargo run --example demo
```

waPC utilizes the [Bytecode Alliance](https://bytecodealliance.org/) runtime [wasmtime](https://github.com/bytecodealliance/wasmtime) for low-level WebAssembly compilation and execution.
