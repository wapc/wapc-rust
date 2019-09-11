//! # wapc
//!
//! The `wapc` crate provides a WebAssembly host runtime that conforms to an RPC mechanism
//! called **waPC**. waPC is designed specifically to prevent either side of the call from having
//! to know anything about _how_ or _when_ memory is allocated or freed. The interface may at first appear more
//! "chatty" than other protocols, but the cleanliness, ease of use, and simplified developer experience
//! is worth the few extra nanoseconds of latency.
//! 
//! To use `wapc`, first you'll need a waPC-compliant WebAssembly module (referred to as the _guest_) to load
//! and interpret. You can find a number of these samples available in the GitHub repository,
//! and anything compiled with the [waxosuit](https://waxosuit.io) guest SDK can also be invoked
//! via waPC as it is 100% waPC compliant.
//! 
//! To make function calls, first set your `host_callback` function, a function invoked by the _guest_. 
//! Then execute `call` on the `WapcHost` instance. 
//! # Example
//! ```
//! extern crate wapc;
//! use wapc::prelude::*;
//! 
//! # fn load_file() -> Vec<u8> {
//! #    include_bytes!("../.assets/hello.wasm").to_vec()
//! # }
//! pub fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let module = load_file();
//!     let mut host = WapcHost::new(&module)?;
//! 
//!     wapc::set_host_callback(host_callback);
//!     let res = host.call("wapc:sample!Hello", b"this is a test")?;
//!     assert_eq!(res, b"hello world!");
//!     Ok(())
//! }
//! 
//! fn host_callback(op: &str, payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//!     println!("Guest invoked '{}' with payload of {} bytes", op, payload.len());
//!     Ok(vec![])
//! }
//! ```
//! 
//! # Notes
//! waPC is _reactive_. Guest modules cannot initiate host calls without first handling a call
//! initiated by the host. waPC will not automatically invoke any start functions--that decision
//! is up to the waPC library consumer. Guest modules can synchronously make as many host calls
//! as they like, but keep in mind that if a host call takes too long or fails, it'll cause the original
//! guest call to also fail.
//! 
//! In summary, keep `host_callback` functions fast and resilient, and do not spawn new threads 
//! within `host_callback` unless you must (and can synchronize memory access) because waPC 
//! assumes a single-threaded execution environment. The `host_callback` function intentionally 
//! has no references to the WebAssembly module bytes or the running instance.


#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

pub mod errors;
pub mod prelude;

/// A result type for errors that occur within the wapc library
pub type Result<T> = std::result::Result<T, errors::Error>;

use std::sync::RwLock;
use wasmer_runtime::ImportObject;
use wasmer_runtime::{func, imports, instantiate, Ctx, Func, Instance, Memory};

const HOST_NAMESPACE: &str = "wapc";
const HOST_ENV_NAMESPACE: &str = "env"; // default namespace for multiple interface specs

// -- Functions called by guest, exported by host
const HOST_CONSOLE_LOG: &str = "__console_log";
const HOST_CALL: &str = "__host_call";
const GUEST_REQUEST_FN: &str = "__guest_request";
const HOST_RESPONSE_FN: &str = "__host_response";
const HOST_RESPONSE_LEN_FN: &str = "__host_response_len";
const GUEST_RESPONSE_FN: &str = "__guest_response";
const GUEST_ERROR_FN: &str = "__guest_error";
const HOST_ERROR_FN: &str = "__host_error";
const HOST_ERROR_LEN_FN: &str = "__host_error_len";

// CommonWA support (subset)
const HOST_IO_GET_STDOUT: &str = "io_get_stdout";
const HOST_RESOURCE_WRITE: &str = "resource_write";

// -- Functions called by host, exported by guest
const GUEST_CALL: &str = "__guest_call";

type HostCallback = dyn Fn(&str, &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> + Sync + Send + 'static;

lazy_static! {
    static ref GUEST_REQUEST: RwLock<Option<Invocation>> = RwLock::new(None);
    static ref GUEST_RESPONSE: RwLock<Option<Vec<u8>>> = RwLock::new(None);
    static ref HOST_RESPONSE: RwLock<Option<Vec<u8>>> = RwLock::new(None);
    static ref GUEST_ERROR: RwLock<Option<String>> = RwLock::new(None);
    static ref HOST_ERROR: RwLock<Option<String>> = RwLock::new(None);
    static ref HOST_CALLBACK: RwLock<Option<Box<HostCallback>>> = RwLock::new(None);
}

#[derive(Debug, Clone)]
struct Invocation {
    operation: String,
    msg: Vec<u8>,
}

impl Invocation {
    fn new(op: &str, msg: Vec<u8>) -> Invocation {
        Invocation {
            operation: op.to_string(),
            msg,
        }
    }
}

/// Sets the callback function to be invoked when the guest module makes a host call.
/// 
/// Callback functions should be single-threaded wherever possible
/// and execute quickly and be diligent about returning appropriate error results.
pub fn set_host_callback<F>(callback: F) where F: Fn(&str, &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> + Sync + Send + 'static {
    *HOST_CALLBACK.write().unwrap() = Some(Box::new(callback))
}

/// A WebAssembly host runtime for waPC-compliant WebAssembly modules
/// 
/// Use an instance of this struct to provide a means of invoking procedure calls by 
/// specifying an operation name and a set of bytes representing the opaque operation payload. 
/// `WapcHost` makes no assumptions about the contents or format of either the payload or the 
/// operation name.
pub struct WapcHost {
    instance: Instance,
}

impl WapcHost {
    /// Creates a new instance of a waPC-compliant WebAssembly host runtime
    pub fn new(buf: &[u8]) -> Result<WapcHost> {
        let import_object = generate_imports();

        let mh = WapcHost {
            instance: instantiate(&buf, &import_object)?,
        };
        Ok(mh)
    }

    /// Invokes the `__guest_call` function within the guest module as per the waPC specification.
    /// Provide an operation name and an opaque payload of bytes and the function returns a `Result`
    /// containing either an error or an opaque reply of bytes.    
    /// 
    /// It is worth noting that the _first_ time `call` is invoked, the WebAssembly module
    /// will be JIT-compiled. This can take up to a few seconds on debug .wasm files, but
    /// all subsequent calls will be "hot" and run at near-native speeds.    
    pub fn call(&mut self, op: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let inv = Invocation::new(op, payload.to_vec());

        {
            *GUEST_RESPONSE.write().unwrap() = None;
            *GUEST_REQUEST.write().unwrap() = Some((inv).clone());
            *GUEST_ERROR.write().unwrap() = None;
        }

        let callresult = self
            .guest_call_fn()?
            .call(inv.operation.len() as _, inv.msg.len() as _)?;

        if callresult == 0 {
            // invocation failed
            match *GUEST_ERROR.read().unwrap() {
                Some(ref s) => Err(errors::new(errors::ErrorKind::GuestCallFailure(s.clone()))),
                None => Err(errors::new(errors::ErrorKind::GuestCallFailure(
                    "No error message set for call failure".to_string(),
                ))),
            }
        } else {
            // invocation succeeded
            let resp = GUEST_RESPONSE.read().unwrap();
            match *resp {
                Some(ref e) => Ok(e.clone()),
                None => match *GUEST_ERROR.read().unwrap() {
                    Some(ref s) => Err(errors::new(errors::ErrorKind::GuestCallFailure(s.clone()))),
                    None => Err(errors::new(errors::ErrorKind::GuestCallFailure(
                        "No error message OR response set for call success".to_string(),
                    ))),
                },
            }
        }
    }

    /// Performs a live "hot swap" of the WebAssembly module. Since execution is assumed to be
    /// single-threaded within the environment of the `WapcHost`, this will not cause any pending function
    /// calls to be lost. This will replace the currently executing WebAssembly module with the new
    /// bytes.
    /// 
    /// **Note**: you will lose all JITted functions for this module, so the first `call` after a 
    /// hot swap will be "cold" and take longer than regular calls. There are an enormous number of
    /// ways in which a hot swap could go horribly wrong, so please ensure you have the proper guards
    /// in place before invoking it. For example, [Waxosuit](https://waxosuit.io) implements JWT-based
    /// security that consults [Open Policy Agent](https://openpolicyagent.org) before allowing a hot wap.
    pub fn replace_module(&mut self, module: &[u8]) -> Result<()> {
        info!(
            "HOT SWAP - Replacing existing WebAssembly module with new buffer, {} bytes",
            module.len()
        );
        self.instance = create_instance_from_buf(module)?;
        info!("HOT SWAP - Success");
        Ok(())
    }

    fn guest_call_fn(&self) -> Result<Func<(i32, i32), i32>> {
        let f: Func<(i32, i32), i32> = self.instance.func(GUEST_CALL)?;
        Ok(f)
    }
}

fn create_instance_from_buf(buf: &[u8]) -> Result<Instance> {
    let import_object = generate_imports();

    match instantiate(&buf, &import_object) {
        Ok(instance) => Ok(instance),
        Err(e) => Err(errors::new(errors::ErrorKind::WasmMisc(e))),
    }
}

fn generate_imports() -> ImportObject {
    imports! {
            HOST_NAMESPACE => {
                HOST_CONSOLE_LOG => func!(console_log),
                HOST_CALL => func!(host_call),
                GUEST_REQUEST_FN => func!(guest_request),
                GUEST_RESPONSE_FN => func!(guest_response),
                GUEST_ERROR_FN => func!(guest_error),
                HOST_RESPONSE_FN => func!(host_response),
                HOST_RESPONSE_LEN_FN => func!(host_response_len),
                HOST_ERROR_FN => func!(host_error),
                HOST_ERROR_LEN_FN => func!(host_error_len),
            },
            // These are here to attempt to make Go's wasm binaries happy
            HOST_ENV_NAMESPACE => {
                HOST_IO_GET_STDOUT => func!(io_get_stdout),
                HOST_RESOURCE_WRITE => func!(resource_write),
            },
    }
}

// -- Host Functions Follow --

/// Invoked by the guest to populate the request and operation name at the given pointer locations
fn guest_request(ctx: &mut Ctx, op_ptr: i32, ptr: i32) {
    let invocation = GUEST_REQUEST.read().unwrap();
    if let Some(ref inv) = *invocation {
        write_bytes_to_memory(&ctx.memory(0), ptr, &inv.msg);
        write_bytes_to_memory(&ctx.memory(0), op_ptr, &inv.operation.as_bytes());
    }
}

/// Invoked by the guest to set a string describing a failure that occurred during `__guest_call`
fn guest_error(ctx: &mut Ctx, ptr: i32, len: i32) {
    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);
    *GUEST_ERROR.write().unwrap() = Some(String::from_utf8(vec).unwrap());
}

/// Invoked by the guest to set a response. The existence of a response is an assertion that `__guest_call` finished successfully
fn guest_response(ctx: &mut Ctx, ptr: i32, len: i32) {
    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);
    *GUEST_RESPONSE.write().unwrap() = Some(vec);
}

/// Invoked by the guest to query the response from the host after `__host_call`
fn host_response(ctx: &mut Ctx, ptr: i32) {
    let resp = HOST_RESPONSE.write().unwrap();
    if let Some(ref e) = *resp {
        write_bytes_to_memory(&ctx.memory(0), ptr, &e);
    }
}

/// Invoked by the guest to obtain the length of the response from the host after `__host_call`
fn host_response_len(_ctx: &mut Ctx) -> i32 {
    let resp = HOST_RESPONSE.read().unwrap();
    match *resp {
        Some(ref e) => e.len() as _,
        None => 0,
    }
}

/// Invoked by the guest to determine the size (if any) of a host failure that occurred during RPC
fn host_error_len(_ctx: &mut Ctx) -> i32 {
    let err = HOST_ERROR.read().unwrap();
    match *err {
        Some(ref e) => e.len() as _,
        None => 0,
    }
}

/// If an error occurred during `__host_call`, the guest module invokes this function to fill a pointer
/// with the string corresponding to that error
fn host_error(ctx: &mut Ctx, ptr: i32) {
    let err = HOST_ERROR.read().unwrap();
    if let Some(ref e) = *err {
        write_bytes_to_memory(&ctx.memory(0), ptr, e.as_bytes());
    }
}

/// Invoked by the guest module when it wants to make a call to a capability
/// The flow of function calls is as follows:
/// 1. Guest invokes `__host_call` with ptr+len pairs for the operation name and the binary payload
/// 2. Host performs requested operation, sets state accordingly
/// 3. Host returns
/// 4. Guest calls `__host_error_len()`, if this is greater than zero, guest invokes `__host_error(ptr)` to obtain the error string
/// 5. Guest calls `__host_response_len()` if no error occurred, then calls `__host_response(ptr)` to obtain the host reply data
fn host_call(ctx: &mut Ctx, op_ptr: i32, op_len: i32, ptr: i32, len: i32) -> i32 {
    {
        *HOST_RESPONSE.write().unwrap() = None;
        *HOST_ERROR.write().unwrap() = None;
    }

    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);
    let op_vec = get_vec_from_memory(&ctx.memory(0), op_ptr, op_len);
    let op = std::str::from_utf8(&op_vec).unwrap();
    info!("Guest module invoking host call for operation {}", op);

    let result = {
        let lock = HOST_CALLBACK.read().unwrap();
        match *lock {
            Some(ref f) => f(op, &vec),
            None => Err("missing host callback function".into()),         
        }
    };
    match result {
        Ok(invresp) => {
            *HOST_RESPONSE.write().unwrap() = Some(invresp);
            1
        }
        Err(e) => {
            *HOST_ERROR.write().unwrap() = Some(format!("{}", e));
            0
        }
    }
}

/// A CWA-subset function provided in case some languages compile with a CWA subset requirement
/// This function writes a pointer (String) to a resource. waPC only supports the STDOUT resource
/// as resource 0
fn resource_write(ctx: &mut Ctx, resource: i32, ptr: i32, len: i32) -> i32 {
    if resource != 0 {
        warn!("Ignoring non-zero resource write (STDOUT is the only Waxosuit-supported resource)");
        return 0;
    }
    console_log(ctx, ptr, len);
    0
}

/// CWA-subset function that returns the resource identifier for the STDOUT resource. We do not
/// need to do any unique handle acquisition, so the ID of the STDOUT resource will always be
/// 0.
fn io_get_stdout(_ctx: &mut Ctx) -> i32 {
    0
}

/// Emits a UTF-8 encoded string to the stdout device
fn console_log(ctx: &mut Ctx, ptr: i32, len: i32) {
    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);

    info!("Wasm Guest: {}", std::str::from_utf8(&vec).unwrap());
}

fn get_vec_from_memory(mem: &Memory, ptr: i32, len: i32) -> Vec<u8> {
    mem.view()[ptr as usize..(ptr + len) as usize]
        .iter()
        .map(|cell| cell.get())
        .collect()
}

fn write_bytes_to_memory(memory: &Memory, ptr: i32, slice: &[u8]) {
    let start: usize = ptr as usize;
    let finish: usize = start + slice.len();
    for (&byte, cell) in slice
        .to_vec()
        .iter()
        .zip(memory.view()[start..finish].iter())
    {
        cell.set(byte);
    }
}
