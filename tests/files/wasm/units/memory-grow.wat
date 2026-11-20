;; memory-grow: the wasmMaxMemoryPages cap as a module: matches when memory.grow by 10 pages succeeds
(module
  (memory (export "memory") 1)
  (func (export "match") (param i32 i32) (result i32)
    (i32.ne (memory.grow (i32.const 10)) (i32.const -1))))
