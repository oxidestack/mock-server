;; start-loop: a start function that never returns; match would match. Instantiation runs out of the
;; wasmExecutionTimeoutMillis budget, so the module fails closed.
(module
  (memory (export "memory") 1)
  (func $start (loop $forever (br $forever)))
  (start $start)
  (func (export "match") (param i32 i32) (result i32) (i32.const 1))
  (func (export "shape_response") (param i32 i32) (result i64) (i64.const 0)))
