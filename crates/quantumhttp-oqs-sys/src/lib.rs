#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// In feature `oqs`, expose the generated bindings. Otherwise, expose a stub.
#[cfg(feature = "oqs")]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(feature = "oqs")]
pub use bindings::*;

#[cfg(feature = "oqs")]
pub const OQS_AVAILABLE: bool = true;

#[cfg(not(feature = "oqs"))]
pub const OQS_AVAILABLE: bool = false;

#[cfg(not(feature = "oqs"))]
pub mod stub {
    #[derive(Debug, Clone)]
    pub struct OqsUnavailable;
}
