use crate::Invocation;
use crate::{HostCallback, LogCallback};
use std::cell::RefCell;
use std::rc::Rc;
use wasmtime::Memory;
use wasmtime::{Caller, Func, FuncType, HostRef, Store, Val, ValType};

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

pub(crate) fn guest_request_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params, _results| {
            let ptr = params[1].i32();
            let op_ptr = params[0].i32();

            let invocation = &state.borrow().guest_request;
            let memory = get_caller_memory(&caller).unwrap();
            if let Some(inv) = invocation {
                write_bytes_to_memory(memory.clone(), ptr.unwrap(), &inv.msg);
                write_bytes_to_memory(memory, op_ptr.unwrap(), &inv.operation.as_bytes());
            }
            Ok(())
        },
    )
}

pub(crate) fn console_log_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller, params: &[Val], _results: &mut [Val]| {
            let ptr = params[0].i32();
            let len = params[1].i32();
            let memory = get_caller_memory(&caller).unwrap();
            let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());

            let id = state.borrow().id;
            let msg = std::str::from_utf8(&vec).unwrap();

            match state.borrow().log_callback {
                Some(ref f) => {
                    f(id, msg).unwrap();
                }
                None => {
                    info!("[Guest {}]: {}", id, msg);
                }
            }
            Ok(())
        },
    )
}

pub(crate) fn host_call_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
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
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params: &[Val], results: &mut [Val]| {
            let id = {
                let mut state = state.borrow_mut();
                state.host_response = None;
                state.host_error = None;
                state.id
            };
            let memory = get_caller_memory(&caller).unwrap();

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
                match state.borrow().host_callback {
                    Some(ref f) => f(id, bd, ns, op, &vec),
                    None => Err("missing host callback function".into()),
                }
            };
            results[0] = Val::I32(match result {
                Ok(invresp) => {
                    state.borrow_mut().host_response = Some(invresp);
                    1
                }
                Err(e) => {
                    state.borrow_mut().host_error = Some(format!("{}", e));
                    0
                }
            });

            Ok(())
        },
    )
}

pub(crate) fn host_response_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32]), Box::new([]));
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params: &[Val], _results: &mut [Val]| {
            if let Some(ref e) = state.borrow().host_response {
                let memory = get_caller_memory(&caller).unwrap();
                let ptr = params[0].i32();
                write_bytes_to_memory(memory, ptr.unwrap(), &e);
            }
            Ok(())
        },
    )
}

pub(crate) fn host_response_len_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([]), Box::new([ValType::I32]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |_caller: Caller, _params: &[Val], results: &mut [Val]| {
            results[0] = Val::I32(match state.borrow().host_response {
                Some(ref r) => r.len() as _,
                None => 0,
            });
            Ok(())
        },
    )
}

pub(crate) fn guest_response_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params: &[Val], _results: &mut [Val]| {
            let ptr = params[0].i32();
            let len = params[1].i32();
            let memory = get_caller_memory(&caller).unwrap();
            let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());
            state.borrow_mut().guest_response = Some(vec);
            Ok(())
        },
    )
}

pub(crate) fn guest_error_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32, ValType::I32]), Box::new([]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params: &[Val], _results: &mut [Val]| {
            let memory = get_caller_memory(&caller).unwrap();
            let ptr = params[0].i32();
            let len = params[1].i32();

            let vec = get_vec_from_memory(memory, ptr.unwrap(), len.unwrap());
            state.borrow_mut().guest_error = Some(String::from_utf8(vec).unwrap());

            Ok(())
        },
    )
}

pub(crate) fn host_error_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([ValType::I32]), Box::new([]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |caller: Caller, params: &[Val], _results: &mut [Val]| {
            if let Some(ref e) = state.borrow().host_error {
                let ptr = params[0].i32();
                let memory = get_caller_memory(&caller).unwrap();
                write_bytes_to_memory(memory, ptr.unwrap(), e.as_bytes());
            }
            Ok(())
        },
    )
}

pub(crate) fn host_error_len_func(store: &Store, state: Rc<RefCell<ModuleState>>) -> Func {
    let callback_type = FuncType::new(Box::new([]), Box::new([ValType::I32]));
    let state = state.clone();
    Func::new(
        store,
        callback_type,
        move |_caller: Caller, _params: &[Val], results: &mut [Val]| {
            results[0] = Val::I32(match state.borrow().host_error {
                Some(ref e) => e.len() as _,
                None => 0,
            });
            Ok(())
        },
    )
}

fn get_caller_memory(caller: &Caller) -> Result<HostRef<Memory>, anyhow::Error> {
    let memory = caller
        .get_export("memory")
        .map(|e| e.memory().cloned().unwrap());
    Ok(HostRef::new(memory.unwrap()))
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
