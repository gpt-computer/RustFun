;; Conformance fixture: answers with a success envelope.
(module
  ;; "RFN1", version 1, JSON codec, body length, then the body: one status byte plus the payload.
  (data (i32.const 70000) "RFN1\01\01\00\00\00\1a\00{\"ok\":true,\"lang\":\"wasm\"}")
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 36))
    (i32.const 36)))
