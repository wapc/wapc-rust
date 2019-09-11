// Copyright 2015-2019 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Library-specific error types and utility functions

use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

pub fn new(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

#[derive(Debug)]
pub enum ErrorKind {
    NoSuchFunction(String),
    IO(std::io::Error),
    WasmRuntime(wasmer_runtime_core::error::RuntimeError),
    WasmMisc(wasmer_runtime_core::error::Error),
    WasmEntityResolution(wasmer_runtime_core::error::ResolveError),
    HostCallFailure(Box<dyn StdError>),
    GuestCallFailure(String),
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    pub fn into_kind(self) -> ErrorKind {
        *self.0
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self.0 {
            ErrorKind::NoSuchFunction(_) => "No such function in Wasm module",
            ErrorKind::IO(_) => "I/O error",
            ErrorKind::WasmRuntime(_) => "WebAssembly runtime error",
            ErrorKind::WasmEntityResolution(_) => "WebAssembly entity resolution failure",
            ErrorKind::WasmMisc(_) => "WebAssembly failure",
            ErrorKind::HostCallFailure(_) => "Error occurred during host call",
            ErrorKind::GuestCallFailure(_) => "Guest call failure",
        }
    }

    fn cause(&self) -> Option<&dyn StdError> {
        match *self.0 {
            ErrorKind::NoSuchFunction(_) => None,
            ErrorKind::IO(ref err) => Some(err),
            ErrorKind::WasmRuntime(ref err) => Some(err),
            ErrorKind::WasmEntityResolution(ref err) => Some(err),
            ErrorKind::WasmMisc(ref err) => Some(err),
            ErrorKind::HostCallFailure(_) => None,
            ErrorKind::GuestCallFailure(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::NoSuchFunction(ref fname) => {
                write!(f, "No such function in Wasm module: {}", fname)
            }
            ErrorKind::IO(ref err) => write!(f, "I/O error: {}", err),
            ErrorKind::WasmRuntime(ref err) => write!(f, "WebAssembly runtime error: {}", err),
            ErrorKind::WasmEntityResolution(ref err) => {
                write!(f, "WebAssembly entity resolution error: {}", err)
            }
            ErrorKind::WasmMisc(ref err) => write!(f, "WebAssembly error: {}", err),
            ErrorKind::HostCallFailure(ref err) => {
                write!(f, "Error occurred during host call: {}", err)
            }
            ErrorKind::GuestCallFailure(ref reason) => write!(f, "Guest call failure: {}", reason),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Error {
        Error(Box::new(ErrorKind::IO(source)))
    }
}

impl From<wasmer_runtime_core::error::RuntimeError> for Error {
    fn from(source: wasmer_runtime_core::error::RuntimeError) -> Error {
        Error(Box::new(ErrorKind::WasmRuntime(source)))
    }
}

impl From<wasmer_runtime_core::error::Error> for Error {
    fn from(source: wasmer_runtime_core::error::Error) -> Error {
        Error(Box::new(ErrorKind::WasmMisc(source)))
    }
}

impl From<wasmer_runtime_core::error::ResolveError> for Error {
    fn from(source: wasmer_runtime_core::error::ResolveError) -> Error {
        Error(Box::new(ErrorKind::WasmEntityResolution(source)))
    }
}
