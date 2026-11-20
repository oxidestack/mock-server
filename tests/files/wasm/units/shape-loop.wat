;; shape-loop: a shaper that never returns: it runs out of wasmExecutionTimeoutMillis and
;; WasmResponseShaper.warnOnce logs the budget failure once
(module
  (memory (export "memory") 1)
  (func (export "match_request") (param i32 i32) (result i32) (i32.const 1))
  (func (export "shape_response") (param i32 i32) (result i64) (loop $forever (br $forever)) (i64.const 0)))
