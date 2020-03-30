use crate::Invocation;
use crate::{HostCallback, LogCallback};
use anyhow::Context as _;
use std::cell::RefCell;
use std::rc::Rc;
use wasmtime::Instance;
use wasmtime::Memory;
use wasmtime::{Callable, Extern, Func, FuncType, HostRef, Store, Trap, Val, ValType};

#[derive(Default)]
pub(crate) struct ModuleState {
    pub guest_request: Option<Invocation>,
    pub guest_response: Option<Vec<u8>>,
    pub host_response: Option<Vec<u8>>,
    pub guest_error: Option<String>,
    pub host_error: Option<String>,
    pub host_callback: Option<Box<HostCallback>>,
    pub log_callback: Option<Box<LogCallback>>,
    pub id: u64,
}

impl ModuleState {
    pub fn new(id: u64, host_callback: Box<HostCallback>) -> Self {
        ModuleState {
            id,
            host_callback: Some(host_callback),
            log_callback: None,
            ..ModuleState::default()
        }
    }

    pub fn new_with_logger(
        id: u64,
        host_callback: Box<HostCallback>,
        log_callback: Box<LogCallback>,
    ) -> Self {
        ModuleState {
            id,
            host_callback: Some(host_callback),
            log_callback: Some(log_callback),
            ..ModuleState::default()
        }
    }
}

pub(crate) trait Callback<T> {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func;
}

pub(crate) struct GuestRequest {
    state: Rc<RefCell<ModuleState>>,
    instance: Rc<RefCell<Option<Instance>>>,
}

impl GuestRequest {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        GuestRequest { state, instance }
    }
}

/// Invoked by the guest to set a response. The existence of a response is an assertion that `__guest_call` finished successfully
pub(crate) struct GuestResponse {
    state: Rc<RefCell<ModuleState>>,
    instance: Rc<RefCell<Option<Instance>>>,
}

impl GuestResponse {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        GuestResponse { state, instance }
    }
}

/// Invoked by the guest to set a string describing a failure that occurred during `__guest_call`
pub(crate) struct GuestError {
    instance: Rc<RefCell<Option<Instance>>>,
    state: Rc<RefCell<ModuleState>>,
}

impl GuestError {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        GuestError { instance, state }
    }
}

/// Invoked by the guest module when it wants to make a host call
/// The flow of function calls is as follows:
/// 1. Guest invokes `__host_call` with ptr+len pairs for the operation name and the binary payload
/// 2. Host performs requested operation, sets state accordingly
/// 3. Host returns
/// 4. Guest calls `__host_error_len()`, if this is greater than zero, guest invokes `__host_error(ptr)` to obtain the error string
/// 5. Guest calls `__host_response_len()` if no error occurred, then calls `__host_response(ptr)` to obtain the host reply data
pub(crate) struct HostCall {
    instance: Rc<RefCell<Option<Instance>>>,
    state: Rc<RefCell<ModuleState>>,
}

impl HostCall {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        HostCall { instance, state }
    }
}

/// Invoked by the guest to obtain the length of the response from the host after `__host_call`
pub(crate) struct HostResponseLen {
    state: Rc<RefCell<ModuleState>>,
}

impl HostResponseLen {
    pub fn new(state: Rc<RefCell<ModuleState>>, _instance: Rc<RefCell<Option<Instance>>>) -> Self {
        HostResponseLen { state }
    }
}

/// Invoked by the guest to query the response from the host after `__host_call`
pub(crate) struct HostResponse {
    instance: Rc<RefCell<Option<Instance>>>,
    state: Rc<RefCell<ModuleState>>,
}
impl HostResponse {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        HostResponse { instance, state }
    }
}

/// Invoked by the guest to determine the size (if any) of a host failure that occurred during RPC
pub(crate) struct HostErrorLen {
    state: Rc<RefCell<ModuleState>>,
}
impl HostErrorLen {
    pub fn new(state: Rc<RefCell<ModuleState>>, _instance: Rc<RefCell<Option<Instance>>>) -> Self {
        HostErrorLen { state }
    }
}

/// If an error occurred during `__host_call`, the guest module invokes this function to fill a pointer
/// with the string corresponding to that error
pub(crate) struct HostError {
    instance: Rc<RefCell<Option<Instance>>>,
    state: Rc<RefCell<ModuleState>>,
}
impl HostError {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        HostError { instance, state }
    }
}
pub(crate) struct ConsoleLog {
    instance: Rc<RefCell<Option<Instance>>>,
    state: Rc<RefCell<ModuleState>>,
}

impl ConsoleLog {
    pub fn new(state: Rc<RefCell<ModuleState>>, instance: Rc<RefCell<Option<Instance>>>) -> Self {
        ConsoleLog { state, instance }
    }
}

pub(crate) struct FdWrite {}

impl FdWrite {
    pub fn new(_state: Rc<RefCell<ModuleState>>, _instance: Rc<RefCell<Option<Instance>>>) -> Self {
        FdWrite {}
    }
}

impl Callable for GuestRequest {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        let ptr = params[1].i32();
        let op_ptr = params[0].i32();

        let invocation = &self.state.borrow().guest_request;
        let memory = get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
        if let Some(inv) = invocation {
            write_bytes_to_memory(memory.clone(), ptr.unwrap(), &inv.msg);
            write_bytes_to_memory(memory, op_ptr.unwrap(), &inv.operation.as_bytes());
        }
        Ok(())
    }
}

impl Callable for GuestResponse {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        let ptr = params[0].i32();
        let len = params[1].i32();
        let memory = get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
        let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());
        self.state.borrow_mut().guest_response = Some(vec);
        Ok(())
    }
}

impl Callable for GuestError {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        let memory = get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
        let ptr = params[0].i32();
        let len = params[1].i32();

        let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());
        self.state.borrow_mut().guest_error = Some(String::from_utf8(vec).unwrap());

        Ok(())
    }
}

impl Callable for HostCall {
    fn call(&self, params: &[Val], results: &mut [Val]) -> std::result::Result<(), Trap> {
        let id = {
            let mut state = self.state.borrow_mut();
            state.host_response = None;
            state.host_error = None;
            state.id
        };
        let memory = get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();

        let bd_ptr = params[0].i32();
        let bd_len = params[1].i32();
        let ns_ptr = params[2].i32();
        let ns_len = params[3].i32();
        let op_ptr = params[4].i32();
        let op_len = params[5].i32();
        let ptr = params[6].i32();
        let len = params[7].i32();

        let vec = get_vec_from_memory(memory.clone(), ptr.unwrap(), len.unwrap());
        let bd_vec = get_vec_from_memory(memory.clone(), bd_ptr.unwrap(), bd_len.unwrap());
        let bd = std::str::from_utf8(&bd_vec).unwrap();
        let ns_vec = get_vec_from_memory(memory.clone(), ns_ptr.unwrap(), ns_len.unwrap());
        let ns = std::str::from_utf8(&ns_vec).unwrap();
        let op_vec = get_vec_from_memory(memory, op_ptr.unwrap(), op_len.unwrap());
        let op = std::str::from_utf8(&op_vec).unwrap();
        trace!("Guest {} invoking host operation {}", id, op);
        let result = {
            match self.state.borrow().host_callback {
                Some(ref f) => f(id, bd, ns, op, &vec),
                None => Err("missing host callback function".into()),
            }
        };
        results[0] = Val::I32(match result {
            Ok(invresp) => {
                self.state.borrow_mut().host_response = Some(invresp);
                1
            }
            Err(e) => {
                self.state.borrow_mut().host_error = Some(format!("{}", e));
                0
            }
        });

        Ok(())
    }
}

impl Callable for HostResponseLen {
    fn call(&self, _params: &[Val], results: &mut [Val]) -> std::result::Result<(), Trap> {
        results[0] = Val::I32(match self.state.borrow().host_response {
            Some(ref r) => r.len() as _,
            None => 0,
        });
        Ok(())
    }
}

impl Callable for HostResponse {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        if let Some(ref e) = self.state.borrow().host_response {
            let memory =
                get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
            let ptr = params[0].i32();
            write_bytes_to_memory(memory, ptr.unwrap(), &e);
        }
        Ok(())
    }
}

impl Callable for HostErrorLen {
    fn call(&self, _params: &[Val], results: &mut [Val]) -> std::result::Result<(), Trap> {
        results[0] = Val::I32(match self.state.borrow().host_error {
            Some(ref e) => e.len() as _,
            None => 0,
        });
        Ok(())
    }
}
impl Callable for HostError {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        if let Some(ref e) = self.state.borrow().host_error {
            let ptr = params[0].i32();
            let memory =
                get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
            write_bytes_to_memory(memory, ptr.unwrap(), e.as_bytes());
        }
        Ok(())
    }
}

impl Callable for ConsoleLog {
    fn call(&self, params: &[Val], _results: &mut [Val]) -> std::result::Result<(), Trap> {
        let ptr = params[0].i32();
        let len = params[1].i32();
        let memory = get_export_memory(self.instance.borrow().as_ref().unwrap().exports()).unwrap();
        let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());

        let id = self.state.borrow().id;
        let msg = std::str::from_utf8(&vec).unwrap();

        match self.state.borrow().log_callback {
            Some(ref f) => {
                f(id, msg).unwrap();
            }
            None => {
                info!("[Guest {}]: {}", id, msg);
            }
        }
        Ok(())
    }
}

impl Callable for FdWrite {
    fn call(&self, _params: &[Val], results: &mut [Val]) -> std::result::Result<(), Trap> {
        results[0] = Val::I32(0);
        Ok(())
    }
}

impl Callback<GuestRequest> for GuestRequest {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
        Func::new(
            &store,
            callback_type,
            Rc::new(GuestRequest::new(state, instance)),
        )
    }
}

impl Callback<GuestError> for GuestError {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
        Func::new(
            &store,
            callback_type,
            Rc::new(GuestError::new(state, instance)),
        )
    }
}

impl Callback<GuestResponse> for GuestResponse {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
        Func::new(
            &store,
            callback_type,
            Rc::new(GuestResponse::new(state, instance)),
        )
    }
}

impl Callback<HostResponse> for HostResponse {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32]), Box::new([]));
        Func::new(
            &store,
            callback_type,
            Rc::new(HostResponse::new(state, instance)),
        )
    }
}

impl Callback<HostResponseLen> for HostResponseLen {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([]), Box::new([ValType::I32]));
        Func::new(
            &store,
            callback_type,
            Rc::new(HostResponseLen::new(state, instance)),
        )
    }
}

impl Callback<HostErrorLen> for HostErrorLen {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([]), Box::new([ValType::I32]));
        Func::new(
            &store,
            callback_type,
            Rc::new(HostErrorLen::new(state, instance)),
        )
    }
}

impl Callback<HostError> for HostError {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32]), Box::new([]));
        Func::new(
            &store,
            callback_type,
            Rc::new(HostError::new(state, instance)),
        )
    }
}

impl Callback<HostCall> for HostCall {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(
            Box::new([
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
            ]),
            Box::new([ValType::I32]),
        );
        Func::new(
            &store,
            callback_type,
            Rc::new(HostCall::new(state, instance)),
        )
    }
}

impl Callback<ConsoleLog> for ConsoleLog {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));

        Func::new(
            &store,
            callback_type,
            Rc::new(ConsoleLog::new(state, instance)),
        )
    }
}

impl Callback<FdWrite> for FdWrite {
    fn as_func(
        state: Rc<RefCell<ModuleState>>,
        instance: Rc<RefCell<Option<Instance>>>,
        store: Store,
    ) -> Func {
        let callback_type = FuncType::new(
            Box::new([ValType::I32, ValType::I32, ValType::I32, ValType::I32]),
            Box::new([ValType::I32]),
        );
        Func::new(
            &store,
            callback_type,
            Rc::new(FdWrite::new(state, instance)),
        )
    }
}

fn get_export_memory(exports: &[Extern]) -> Result<HostRef<Memory>, anyhow::Error> {
    let memory = exports.iter().find_map(|e| e.memory());

    Ok(HostRef::new(
        memory
            .with_context(|| "> Error accessing memory export!")?
            .clone(),
    ))
}

fn get_vec_from_memory(mem: HostRef<Memory>, ptr: i32, len: i32) -> Vec<u8> {
    let mem = mem.borrow_mut();
    let data = unsafe { mem.data_unchecked_mut() };
    data[ptr as usize..(ptr + len) as usize]
        .iter()
        .copied()
        .collect()
}

fn write_bytes_to_memory(memory: HostRef<Memory>, ptr: i32, slice: &[u8]) {
    let memory = memory.borrow_mut();
    let data = unsafe { memory.data_unchecked_mut() };
    // TODO: upgrade this to a faster memory write
    for idx in 0..slice.len() {
        data[idx + ptr as usize] = slice[idx];
    }
}
