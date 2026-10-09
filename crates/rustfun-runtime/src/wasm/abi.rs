//! The RustFun WebAssembly guest ABI.
//!
//! A RustFun Wasm function is a **core module** (not a component) that exports exactly two
//! functions and one linear memory:
//!
//! ```wat
//! (module
//!   ;; The host writes the framed invocation into linear memory and returns its offset.
//!   (import "rustfun" "payload" (func $payload (param i32 i32) (result i32)))
//!
//!   ;; The guest handler. Writes the framed response and returns its length.
//!   (func (export "rustfun_handler") (result i32) ...)
//!
//!   ;; Mandatory: the guest must export its memory.
//!   (memory (export "memory") 1))
//! ```
//!
//! # Why this shape
//!
//! - **One request per call.** The instance is warm and reusable, so `rustfun_handler` is
//!   stateless with respect to the host: the host pushes the request into the guest on every
//!   invocation.
//! - **`memory` must be exported.** Wasmtime refuses to expose linear memory to the host
//!   otherwise, and a Wasm function cannot allocate host memory for the guest.
//! - **Zero imports are still valid.** A module that only exports `rustfun_handler` and
//!   `memory` runs fine; the host simply cannot offer host functions it does not import.
//!
//! # Response envelope
//!
//! The frame the guest writes is `RFN1 | version | codec | length | body`, and the body is one
//! status byte followed by the guest's own bytes:
//!
//! ```text
//! +---------+--------------------------+
//! | status  | payload                  |
//! +---------+--------------------------+
//! ```
//!
//! | status | meaning | payload |
//! | --- | --- | --- |
//! | `0x00` | success | the response body, verbatim: JSON or binary |
//! | `0x01` | failure | a UTF-8 message for the caller |
//!
//! The guest does **not** get to choose the invocation identity, the duration, the instance id,
//! or the status vocabulary: the host owns all of those and fills them in. A guest that returns
//! a whole `InvocationResponse` instead would be able to forge another invocation's id, so the
//! envelope deliberately does not have that shape.
//!
//! # Framing
//!
//! Both directions use the standard RustFun frame, which is **not** a bare length prefix:
//!
//! ```text
//! +--------+--------+--------+----------------+
//! | "RFN1" | ver=1  | codec  | u32 length (BE) |
//! +--------+--------+--------+----------------+
//! | body ...                                              |
//! +------------------------------------------------------+
//! ```
//!
//! `request` and `response` are therefore complete frames produced by the protocol codec, and a
//! guest that writes anything else is reported as `RUSTFUN_WASM_BAD_RESPONSE`. A guest can
//! precompute the ten header bytes as a data segment instead of assembling them at runtime.
//!
//! # Limits
//!
//! The host never trusts guest arithmetic. Offsets and lengths returned by the guest are
//! bounds-checked against the actual memory size, and a guest frame larger than
//! [`MAX_FRAME_BYTES`] is rejected rather than allocated.

/// Import module name for RustFun host functions.
pub const HOST_MODULE: &str = "rustfun";

/// Name of the host call that tells the guest where its request frame landed.
///
/// Signature: `(param ptr: i32 len: i32) (result i32)`. Both parameters are reserved; the host
/// returns the offset of the request frame, which starts with a header carrying the body
/// length, or a negative value when there is no request (a guest that calls it outside an
/// invocation). The host has already written the frame, so the guest only needs to know where
/// it is.
pub const HOST_FN_PAYLOAD: &str = "payload";

/// Name of the guest export that handles one invocation.
///
/// Signature: `() -> i32` — returns the length of the framed response written into linear
/// memory, or a negative value when the guest failed to write one.
pub const EXPORT_HANDLER: &str = "rustfun_handler";

/// Name of the mandatory memory export.
pub const EXPORT_MEMORY: &str = "memory";

/// Response status byte: the invocation succeeded and the rest is the body.
pub const STATUS_SUCCESS: u8 = 0x00;

/// Response status byte: the invocation failed and the rest is a UTF-8 message.
pub const STATUS_ERROR: u8 = 0x01;

/// Largest single frame accepted in either direction (16 MiB).
///
/// The guest controls the number it returns; without a ceiling a buggy handler could ask the
/// host to copy a gigabyte out of its own memory on every call.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Largest linear memory a guest may request, unless the function policy lowers it.
///
/// Wasmtime's default 4 GiB ceiling exists because memory *limits* cost address space on some
/// hosts; RustFun additionally refuses anything above this so a hostile module cannot reserve
/// more than a function platform would ever allow.
pub const DEFAULT_MAX_MEMORY_PAGES: u64 = 512;

/// The host-side view of a guest export that was not present or had the wrong signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportError {
    /// Export name that was missing or invalid.
    pub name: &'static str,
    /// Human-readable reason.
    pub reason: String,
}

impl ExportError {
    /// Build an export error.
    pub fn new(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "export `{}` is unusable: {}", self.name, self.reason)
    }
}

impl std::error::Error for ExportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_error_explains_the_missing_symbol() {
        let error = ExportError::new(EXPORT_HANDLER, "the module does not export it");
        assert!(error.to_string().contains(EXPORT_HANDLER));
        assert!(error.to_string().contains("does not export it"));
    }

    #[test]
    fn status_bytes_are_distinct() {
        assert_ne!(STATUS_SUCCESS, STATUS_ERROR);
        assert_eq!(STATUS_SUCCESS, 0);
        assert_eq!(STATUS_ERROR, 1);
    }

    #[test]
    fn default_page_ceiling_matches_the_documented_mib() {
        // 512 pages is 32 MiB: enough for real handlers, small enough to bound host memory.
        const _: () = assert!(DEFAULT_MAX_MEMORY_PAGES * 64 * 1024 == 32 * 1024 * 1024);
    }

    #[test]
    fn frame_ceiling_is_a_usable_const() {
        const _: () = assert!(MAX_FRAME_BYTES == 16 * 1024 * 1024);
    }
}
