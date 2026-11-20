;; start-bounded: a start function that counts 200 000 iterations and stores the count at 60000 (above
;; the input the runtime writes at offset 0); match matches when the start function finished.
(module
  (memory (export "memory") 1)
  (func $start
    (local $n i32)
    (block $done
      (loop $count
        (br_if $done (i32.eq (local.get $n) (i32.const 200000)))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $count)))
    (i32.store (i32.const 60000) (local.get $n)))
  (start $start)
  (func (export "match") (param i32 i32) (result i32)
    (i32.eq (i32.load (i32.const 60000)) (i32.const 200000))))
