;; match-loop: a matcher that never returns: it holds a request for the whole
;; wasmExecutionTimeoutMillis budget, then fails closed
(module
  (memory (export "memory") 1)
  (func (export "match") (param i32 i32) (result i32) (loop $forever (br $forever)) (i32.const 1)))
