;; shape-out-of-bounds: WasmRuntimeShapeAbiTest readShapedResult / WasmResponseShaperTest applyShaped as modules
(module
  (memory (export "memory") 1 1)
  (func (export "match_request") (param i32 i32) (result i32) (i32.const 1))
  (func (export "shape_response") (param i32 i32) (result i64) (i64.or (i64.shl (i64.const 60000) (i64.const 32)) (i64.const 20000))))
