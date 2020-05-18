#![doc(html_logo_url = "https://avatars0.githubusercontent.com/u/54989751?s=200&v=4")]

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
//! and anything compiled with the [wascc](https://github.com/wascc) actor SDK can also be invoked
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
//! # fn load_wasi_file() -> Vec<u8> {
//! #    include_bytes!("../.assets/hello_wasi.wasm").to_vec()
//! # }
//! pub fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let module_bytes = load_file();
//!     let mut host = WapcHost::new(|id: u64, bd: &str, ns: &str, op: &str, payload: &[u8]| {
//!         println!("Guest {} invoked '{}->{}:{}' with payload of {} bytes", id, bd, ns, op, payload.len());
//!         Ok(vec![])
//!     }, &module_bytes, None)?;
//!
//!     let res = host.call("wapc:sample!Hello", b"this is a test")?;
//!     assert_eq!(res, b"hello world!");
//!
//!     Ok(())
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

mod callbacks;
pub mod errors;
mod modreg;
pub mod prelude;

/// A result type for errors that occur within the wapc library
pub type Result<T> = std::result::Result<T, errors::Error>;

use crate::modreg::ModuleRegistry;
use std::sync::atomic::{AtomicU64, Ordering};
use wasmtime::Func;
use wasmtime::Instance;

use std::cell::RefCell;

use crate::callbacks::ModuleState;
use std::rc::Rc;
use wasmtime::*;

macro_rules!  call {
    ($func:expr, $($p:expr),*) => {
      match $func.borrow().call(&[$($p.into()),*]) {
        Ok(result) => {
          let result: i32 = result[0].i32().unwrap();
          result
        }
        Err(e) => {
            error!("Failure invoking guest module handler: {:?}", e);
            0
        }
      }
    }
  }

static GLOBAL_MODULE_COUNT: AtomicU64 = AtomicU64::new(1);

const HOST_NAMESPACE: &str = "wapc";

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

// -- Functions called by host, exported by guest
const GUEST_CALL: &str = "__guest_call";

// namespace needed for some language support
const WASI_UNSTABLE_NAMESPACE: &str = "wasi_unstable";
const WASI_SNAPSHOT_PREVIEW1_NAMESPACE: &str = "wasi_snapshot_preview1";

type HostCallback = dyn Fn(u64, &str, &str, &str, &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>
    + Sync
    + Send
    + 'static;

type LogCallback = dyn Fn(u64, &str) -> std::result::Result<(), Box<dyn std::error::Error>>
    + Sync
    + Send
    + 'static;

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

/// Stores the parameters required to create a WASI instance
#[derive(Debug, Default)]
pub struct WasiParams {
    argv: Vec<String>,
    map_dirs: Vec<(String, String)>,
    env_vars: Vec<(String, String)>,
    preopened_dirs: Vec<String>,
}

impl WasiParams {
    pub fn new(
        argv: Vec<String>,
        map_dirs: Vec<(String, String)>,
        env_vars: Vec<(String, String)>,
        preopened_dirs: Vec<String>,
    ) -> Self {
        WasiParams {
            argv,
            map_dirs,
            preopened_dirs,
            env_vars,
        }
    }
}

/// A WebAssembly host runtime for waPC-compliant WebAssembly modules
///
/// Use an instance of this struct to provide a means of invoking procedure calls by
/// specifying an operation name and a set of bytes representing the opaque operation payload.
/// `WapcHost` makes no assumptions about the contents or format of either the payload or the
/// operation name.
pub struct WapcHost {
    state: Rc<RefCell<ModuleState>>,
    instance: Rc<RefCell<Option<Instance>>>,
    wasidata: Option<WasiParams>,
    guest_call_fn: HostRef<Func>,
}

impl WapcHost {
    /// Creates a new instance of a waPC-compliant WebAssembly host runtime.
    pub fn new(
        host_callback: impl Fn(
                u64,
                &str,
                &str,
                &str,
                &[u8],
            ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>
            + 'static
            + Sync
            + Send,
        buf: &[u8],
        wasi: Option<WasiParams>,
    ) -> Result<Self> {
        let id = GLOBAL_MODULE_COUNT.fetch_add(1, Ordering::SeqCst);
        let state = Rc::new(RefCell::new(ModuleState::new(id, Box::new(host_callback))));
        let instance_ref = Rc::new(RefCell::new(None));
        let instance = WapcHost::instance_from_buffer(buf, &wasi, state.clone())?;
        instance_ref.replace(Some(instance));
        let gc = guest_call_fn(instance_ref.clone())?;
        let mh = WapcHost {
            state,
            instance: instance_ref,
            wasidata: wasi,
            guest_call_fn: gc,
        };

        mh.initialize()?;

        Ok(mh)
    }

    /// Creates a new instance of a waPC-compliant WebAssembly host runtime with a callback handler
    /// for logging
    pub fn new_with_logger(
        host_callback: impl Fn(
                u64,
                &str,
                &str,
                &str,
                &[u8],
            ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>
            + 'static
            + Sync
            + Send,
        buf: &[u8],
        logger: impl Fn(u64, &str) -> std::result::Result<(), Box<dyn std::error::Error>>
            + Sync
            + Send
            + 'static,
        wasi: Option<WasiParams>,
    ) -> Result<Self> {
        let id = GLOBAL_MODULE_COUNT.fetch_add(1, Ordering::SeqCst);
        let state = Rc::new(RefCell::new(ModuleState::new_with_logger(
            id,
            Box::new(host_callback),
            Box::new(logger),
        )));
        let instance_ref = Rc::new(RefCell::new(None));
        let instance = WapcHost::instance_from_buffer(buf, &wasi, state.clone())?;
        instance_ref.replace(Some(instance));
        let gc = guest_call_fn(instance_ref.clone())?;
        let mh = WapcHost {
            state,
            instance: instance_ref,
            wasidata: wasi,
            guest_call_fn: gc,
        };

        mh.initialize()?;

        Ok(mh)
    }

    /// Returns a reference to the unique identifier of this module. If a parent process
    /// has instantiated multiple `WapcHost`s, then the single static host call function
    /// may be used to differentiate between modules.
    pub fn id(&self) -> u64 {
        self.state.borrow().id
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
            let mut state = self.state.borrow_mut();
            state.guest_response = None;
            state.guest_request = Some((inv).clone());
            state.guest_error = None;
        }

        let callresult: i32 = call!(
            self.guest_call_fn,
            inv.operation.len() as i32,
            inv.msg.len() as i32
        );

        if callresult == 0 {
            // invocation failed
            match self.state.borrow().guest_error {
                Some(ref s) => Err(errors::new(errors::ErrorKind::GuestCallFailure(s.clone()))),
                None => Err(errors::new(errors::ErrorKind::GuestCallFailure(
                    "No error message set for call failure".to_string(),
                ))),
            }
        } else {
            // invocation succeeded
            match self.state.borrow().guest_response {
                Some(ref e) => Ok(e.clone()),
                None => match self.state.borrow().guest_error {
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
    /// in place before invoking it. Libraries that build upon this one can (and likely should) implement
    /// some form of security to protect against malicious swaps.
    ///
    /// If you perform a hot swap of a WASI module, you cannot alter the parameters used to create the WASI module
    /// like the environment variables, mapped directories, pre-opened files, etc. Not abiding by this could lead
    /// to privilege escalation attacks or non-deterministic behavior after the swap.
    pub fn replace_module(&self, module: &[u8]) -> Result<()> {
        info!(
            "HOT SWAP - Replacing existing WebAssembly module with new buffer, {} bytes",
            module.len()
        );
        let state = self.state.clone();
        let new_instance = WapcHost::instance_from_buffer(module, &self.wasidata, state)?;
        self.instance.borrow_mut().replace(new_instance);

        self.initialize()
    }

    fn instance_from_buffer(
        buf: &[u8],
        wasi: &Option<WasiParams>,
        state: Rc<RefCell<ModuleState>>,
    ) -> Result<Instance> {
        let engine = Engine::default();
        let store = Store::new(&engine);
        let module = Module::new(&store, buf).unwrap();

        let d = WasiParams::default();
        let wasi = match wasi {
            Some(w) => w,
            None => &d,
        };

        // Make wasi available by default.
        let preopen_dirs =
            modreg::compute_preopen_dirs(&wasi.preopened_dirs, &wasi.map_dirs).unwrap();
        let argv = vec![]; // TODO: add support for argv (if applicable)

        let module_registry =
            ModuleRegistry::new(&store, &preopen_dirs, &argv, &wasi.env_vars).unwrap();

        let imports = arrange_imports(&module, state.clone(), store.clone(), &module_registry);

        Ok(wasmtime::Instance::new(&module, imports?.as_slice()).unwrap())
    }

    fn initialize(&self) -> Result<()> {
        if let Some(ext) = self
            .instance
            .borrow()
            .as_ref()
            .unwrap()
            .get_export("_start")
        {
            ext.into_func().unwrap().call(&[]).map(|_| ()).map_err(|_err| {
                errors::new(errors::ErrorKind::GuestCallFailure(
                    "Error invoking _start function!".to_string(),
                ))
            })
        } else {
            Ok(())
        }
    }
}

// Called once, then the result is cached. This returns a `Func` that corresponds
// to the `__guest_call` export
fn guest_call_fn(instance: Rc<RefCell<Option<Instance>>>) -> Result<HostRef<Func>> {
    if let Some(ext) = instance.borrow().as_ref().unwrap().get_export(GUEST_CALL) {
        Ok(HostRef::new(ext.into_func().unwrap().clone()))
    } else {
        Err(errors::new(errors::ErrorKind::GuestCallFailure(
            "Guest module did not export __guest_call function!".to_string(),
        )))
    }
}

/// wasmtime requires that the list of callbacks be "zippable" with the list
/// of module imports. In order to ensure that both lists are in the same
/// order, we have to loop through the module imports and instantiate the
/// corresponding callback. We **cannot** rely on a predictable import order
/// in the wasm module
fn arrange_imports(
    module: &Module,
    state: Rc<RefCell<ModuleState>>,
    store: Store,
    mod_registry: &ModuleRegistry,
) -> Result<Vec<Extern>> {
    Ok(module
        .imports()        
        .filter_map(|imp| {
            if let ExternType::Func(_) = imp.ty() {
                match imp.module() {
                    HOST_NAMESPACE => Some(callback_for_import(
                        imp.name(),
                        state.clone(),
                        store.clone(),
                    )),
                    // TODO: to forcibly block the use of WASI, these should error
                    // rather than looking up WASI modules.
                    WASI_UNSTABLE_NAMESPACE => {
                        let f = Extern::from(
                            mod_registry
                                .wasi_unstable
                                .get_export(imp.name())
                                .unwrap()
                                .clone(),
                        );
                        Some(f)
                    }
                    WASI_SNAPSHOT_PREVIEW1_NAMESPACE => {
                        let f: Extern = Extern::from(
                            mod_registry
                                .wasi_snapshot_preview1
                                .get_export(imp.name())
                                .unwrap()
                                .clone(),
                        );
                        Some(f)
                    }
                    other => panic!("import module `{}` was not found", other), //TODO: get rid of panic
                }
            } else {
                None
            }
        })
        .collect())
}

fn callback_for_import(import: &str, state: Rc<RefCell<ModuleState>>, store: Store) -> Extern {
    match import {
        HOST_CONSOLE_LOG => callbacks::console_log_func(&store, state.clone()).into(),
        HOST_CALL => callbacks::host_call_func(&store, state.clone()).into(),
        GUEST_REQUEST_FN => callbacks::guest_request_func(&store, state.clone()).into(),
        HOST_RESPONSE_FN => callbacks::host_response_func(&store, state.clone()).into(),
        HOST_RESPONSE_LEN_FN => callbacks::host_response_len_func(&store, state.clone()).into(),
        GUEST_RESPONSE_FN => callbacks::guest_response_func(&store, state.clone()).into(),
        GUEST_ERROR_FN => callbacks::guest_error_func(&store, state.clone()).into(),
        HOST_ERROR_FN => callbacks::host_error_func(&store, state.clone()).into(),
        HOST_ERROR_LEN_FN => callbacks::host_error_len_func(&store, state.clone()).into(),
        _ => unreachable!(),
    }
}
