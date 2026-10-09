;; Conformance fixture: answers with the error envelope.
(module
  ;; "RFN1", version 1, JSON codec, body length, then the body: one status byte plus the payload.
  (data (i32.const 70000) "RFN1\01\01\00\00\00\14\01conformance failure")
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 30))
    (i32.const 30)))
