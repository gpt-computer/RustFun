;; RustFun Wasm template.
;;
;; The guest ABI (see crates/rustfun-runtime/src/wasm/abi.rs):
;;   * export `memory` - the host writes the request frame there,
;;   * export `rustfun_handler() -> i32` - handle one invocation, return the frame length,
;;   * optionally import `rustfun.payload` to learn where the request frame landed.
;;
;; This template returns a fixed body so it runs with no build step. A real handler would decode
;; the request frame at 65536 and build its answer from it.
(module
  ;; The response frame, header included: "RFN1", version 1, JSON codec, body length.
  ;; The body is one status byte (0x00 = success) followed by the payload.
  (data (i32.const 70000) "RFN1\01\01\00\00\00\1e\00{\"message\":\"hello from wasm\"}")

  ;; Linear memory starts at 65536: the host owns that page as the mailbox.
  (memory (export "memory") 2)

  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 40))
    (i32.const 40)))
