;; start-trap: a start function that traps fails the instantiation, so match is never reached.
(module
  (memory (export "memory") 1)
  (func $start unreachable)
  (start $start)
  (func (export "match") (param i32 i32) (result i32) (i32.const 1)))
