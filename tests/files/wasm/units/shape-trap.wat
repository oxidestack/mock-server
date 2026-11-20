;; shape-trap: a shaper that traps: WasmResponseShaper.warnOnce logs "WASM shape_response trapped" once
(module
  (memory (export "memory") 1)
  (func (export "match_request") (param i32 i32) (result i32) (i32.const 1))
  (func (export "shape_response") (param i32 i32) (result i64) (unreachable)))
