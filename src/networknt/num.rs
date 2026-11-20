//! JSON numbers as Jackson's default `JsonMapper` reads them for networknt: an integral literal is an `IntNode`,
//! `LongNode` or `BigIntegerNode`, anything with a fraction or an exponent a `DoubleNode`. Text and comparisons follow
//! those node types (`Double.toString`, `decimalValue()`, `BigDecimal.valueOf(double)`).

use jackson::bigdecimal::BigDecimal;
use num_bigint::BigInt;
use serde_json::{Number, Value};

/// A number node: integral, or a double (possibly infinite when the literal overflows).
#[derive(Clone, Debug)]
pub enum Num {
    Int(BigInt),
    Double(f64),
}

pub fn num(n: &Number) -> Num {
    let text = n.to_string();
    if text.contains(['.', 'e', 'E']) {
        Num::Double(text.parse::<f64>().unwrap_or(f64::NAN))
    } else {
        Num::Int(text.parse::<BigInt>().unwrap_or_default())
    }
}

impl Num {
    /// `JsonNodeTypes.isNonFiniteNumber`.
    pub fn non_finite(&self) -> bool {
        matches!(self, Num::Double(d) if !d.is_finite())
    }

    /// `canConvertToExactIntegral`.
    pub fn exact_integral(&self) -> bool {
        match self {
            Num::Int(_) => true,
            Num::Double(d) => d.is_finite() && d.fract() == 0.0,
        }
    }

    /// `asString()` / `toString()` of the node.
    pub fn text(&self) -> String {
        match self {
            Num::Int(i) => i.to_string(),
            Num::Double(d) => java_compat::double_to_string(*d),
        }
    }

    /// `decimalValue()`: exact for integers, `BigDecimal.valueOf(double)` for doubles. `None` when non-finite.
    pub fn decimal(&self) -> Option<BigDecimal> {
        match self {
            Num::Int(i) => Some(BigDecimal::from_bigint(i.clone())),
            Num::Double(d) => BigDecimal::try_value_of_f64(*d).ok(),
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            Num::Int(i) => i.to_string().parse().unwrap_or(f64::NAN),
            Num::Double(d) => *d,
        }
    }

    /// `asLong()`: doubles truncate toward zero (saturating), big integers wrap.
    pub fn as_long(&self) -> i64 {
        match self {
            Num::Int(i) => jackson::bigdecimal::wrap_i64(i),
            Num::Double(d) => *d as i64,
        }
    }

    /// `isLong() || isInt()`: an integral literal that fits a `long`.
    pub fn is_long(&self) -> bool {
        matches!(self, Num::Int(i) if i64::try_from(i.clone()).is_ok())
    }
}

/// Numeric equality (`compareTo == 0`).
pub fn same_value(a: &Num, b: &Num) -> bool {
    match (a.decimal(), b.decimal()) {
        (Some(x), Some(y)) => x.compare_to(&y) == std::cmp::Ordering::Equal,
        _ => a.as_f64() == b.as_f64(),
    }
}

/// `JsonNode.equals`: number nodes are equal only within the same kind (an `IntNode` never equals a `DoubleNode`).
pub fn node_equals(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (num(x), num(y)) {
            (Num::Int(p), Num::Int(q)) => p == q,
            (Num::Double(p), Num::Double(q)) => p == q || (p.is_nan() && q.is_nan()),
            _ => false,
        },
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| node_equals(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| node_equals(v, w))),
        _ => a == b,
    }
}

/// `node.toString()`: compact JSON with Jackson's number text.
pub fn node_text(v: &Value) -> String {
    let mut out = String::new();
    write_node(v, &mut out);
    out
}

fn write_node(v: &Value, out: &mut String) {
    match v {
        Value::Number(n) => out.push_str(&num(n).text()),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_node(item, out);
            }
            out.push(']');
        }
        Value::Object(fields) => {
            out.push('{');
            for (i, (k, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_node(item, out);
            }
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// `node.asString()` for a scalar (`""` for null, as Jackson 3 answers), `toString()` for containers and strings
/// when `quoted_strings`.
pub fn as_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => num(n).text(),
        other => node_text(other),
    }
}

/// `dividend % divisor == 0` for two decimals (`divideAndRemainder(...)[1]` is zero).
pub fn is_multiple(dividend: &BigDecimal, divisor: &BigDecimal) -> bool {
    let scale = dividend.scale.max(divisor.scale);
    let widen = |d: &BigDecimal| -> BigInt { &d.unscaled * BigInt::from(10u32).pow((scale - d.scale) as u32) };
    let (a, b) = (widen(dividend), widen(divisor));
    if b == BigInt::from(0) {
        return true;
    }
    (a % b) == BigInt::from(0)
}
