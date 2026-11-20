//! `org.mockserver.openapi.examples.SampleDataGenerator` and `GenerationOptions`: realistic, schema-aware example
//! values from a Datafaker `Faker` over a `java.util.Random` (datafaker-rs), seeded 42 unless the caller's
//! `__generationOptions__` give a seed, so the same calls in the same order give the oracle's values.

use std::sync::LazyLock;

use datafaker::{Faker, RandomService};
use serde_json::{Map, Value as Json};

const FIXED_SEED: i64 = 42;

pub struct SampleDataGenerator {
    faker: Faker,
    /// The faker's own `java.util.Random` (`new Faker(random)` shares it).
    random: RandomService,
}

/// `ExampleBuilder.STATIC_GENERATOR`: one seed-42 generator for the whole process (upstream: the JVM), used for
/// `pattern` and `format: time` strings when realistic values are off, so its draws depend on every such string
/// generated since the process started.
pub static STATIC_GENERATOR: LazyLock<SampleDataGenerator> = LazyLock::new(SampleDataGenerator::default);

impl Default for SampleDataGenerator {
    fn default() -> Self {
        SampleDataGenerator::new(FIXED_SEED)
    }
}

impl SampleDataGenerator {
    /// `new SampleDataGenerator(seed)`: `faker = new Faker(random = new Random(seed))`.
    pub fn new(seed: i64) -> Self {
        let faker = Faker::with_seed(seed);
        let random = faker.random();
        SampleDataGenerator { faker, random }
    }

    fn next_int(&self, bound: i32) -> i32 {
        self.random.random().next_int_bounded(bound).unwrap_or(0)
    }

    pub fn email(&self) -> String {
        self.faker.internet().email_address().unwrap_or_default()
    }

    /// Two `nextLong`s with the version-4 and IETF variant bits set, as `java.util.UUID.toString()`.
    pub fn uuid(&self) -> String {
        let r = self.random.random();
        let most = (r.next_long() as u64 & 0xFFFF_FFFF_FFFF_0FFF) | 0x0000_0000_0000_4000;
        let least = (r.next_long() as u64 & 0x3FFF_FFFF_FFFF_FFFF) | 0x8000_0000_0000_0000;
        uuid::Uuid::from_u64_pair(most, least).to_string()
    }

    fn date(&self) -> String {
        let year = 2020 + self.next_int(5);
        let month = 1 + self.next_int(12);
        let day = 1 + self.next_int(28);
        format!("{year:04}-{month:02}-{day:02}")
    }

    /// `LocalDate` in 2020–2024, days 1–28, `ISO_LOCAL_DATE`.
    pub fn date_string(&self) -> String {
        self.date()
    }

    /// That date at a random time in UTC, `ISO_OFFSET_DATE_TIME` (`…T20:30:25Z`).
    pub fn date_time_string(&self) -> String {
        let date = self.date();
        let (h, m, s) = (self.next_int(24), self.next_int(60), self.next_int(60));
        format!("{date}T{h:02}:{m:02}:{s:02}Z")
    }

    /// `HH:mm:ss` for the `time` string format.
    pub fn time_string(&self) -> String {
        let (h, m, s) = (self.next_int(24), self.next_int(60), self.next_int(60));
        format!("{h:02}:{m:02}:{s:02}")
    }

    /// `faker.regexify(pattern)`, `None` for a blank pattern or one RgxGen rejects.
    pub fn regexify(&self, pattern: &str) -> Option<String> {
        if pattern.is_empty() {
            return None;
        }
        self.faker.regexify(pattern).ok()
    }

    pub fn uri(&self) -> String {
        self.faker.internet().url().unwrap_or_default()
    }

    pub fn hostname(&self) -> String {
        self.faker.internet().domain_name().unwrap_or_default()
    }

    pub fn ipv4(&self) -> String {
        self.faker.internet().ip_v4_address()
    }

    pub fn ipv6(&self) -> String {
        self.faker.internet().ip_v6_address()
    }

    /// Twelve `nextBytes`, Base64.
    pub fn byte_string(&self) -> String {
        use base64::Engine;
        let mut bytes = [0i8; 12];
        self.random.random().next_bytes(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(bytes.map(|b| b as u8))
    }

    pub fn password(&self) -> String {
        self.faker.internet().password_with(8, 16, true, true, true).unwrap_or_default()
    }

    /// Lorem words joined by spaces up to a random length in `[minLength, maxLength]` (default 1–20), cut at the
    /// maximum and padded with `a` to the minimum.
    pub fn string_with_constraints(&self, min_length: Option<i32>, max_length: Option<i32>) -> String {
        let min = min_length.unwrap_or(1);
        let mut max = max_length.unwrap_or(min.max(20));
        if max < min {
            max = min;
        }
        let target = min + if max > min { self.next_int(max - min + 1) } else { 0 };
        let mut out: Vec<u16> = Vec::new();
        while (out.len() as i64) < target as i64 {
            if !out.is_empty() {
                out.push(' ' as u16);
            }
            out.extend(self.faker.lorem().word().unwrap_or_default().encode_utf16());
        }
        if out.len() as i64 > max as i64 {
            out.truncate(max.max(0) as usize);
        }
        let mut result = String::from_utf16_lossy(&out);
        while (result.encode_utf16().count() as i64) < min as i64 {
            result.push('a');
        }
        result
    }

    /// `integer(minimum, maximum)`: `min + nextInt(max - min + 1)`, defaults 0 and 1000.
    pub fn integer(&self, minimum: Option<f64>, maximum: Option<f64>) -> i32 {
        let min = minimum.map(int_value).unwrap_or(0);
        let max = maximum.map(int_value).unwrap_or(1000);
        if max <= min {
            return min;
        }
        min.wrapping_add(self.next_int(max.wrapping_sub(min).wrapping_add(1)))
    }

    /// `longValue(minimum, maximum)`: `min + (long) (nextDouble() * (max - min + 1))`, defaults 0 and 10000.
    pub fn long_value(&self, minimum: Option<f64>, maximum: Option<f64>) -> i64 {
        let min = minimum.map(|v| v as i64).unwrap_or(0);
        let max = maximum.map(|v| v as i64).unwrap_or(10_000);
        if max <= min {
            return min;
        }
        let span = max.wrapping_sub(min).wrapping_add(1) as f64;
        min.wrapping_add((self.random.random().next_double() * span) as i64)
    }

    /// `floatValue(minimum, maximum)`: a float in `[min, max)` rounded half-up to two places, defaults 0 and 100.
    pub fn float_value(&self, minimum: Option<f64>, maximum: Option<f64>) -> f32 {
        let min = minimum.map(|v| v as f32).unwrap_or(0.0);
        let max = maximum.map(|v| v as f32).unwrap_or(100.0);
        if max <= min {
            return min;
        }
        let value = min + self.random.random().next_float() * (max - min);
        scale2(value as f64).parse().unwrap_or(value)
    }

    /// `doubleValue(minimum, maximum)`: like [`Self::float_value`] in doubles, defaults 0 and 1000.
    pub fn double_value(&self, minimum: Option<f64>, maximum: Option<f64>) -> f64 {
        let min = minimum.unwrap_or(0.0);
        let max = maximum.unwrap_or(1000.0);
        if max <= min {
            return min;
        }
        let value = min + self.random.random().next_double() * (max - min);
        scale2(value).parse().unwrap_or(value)
    }

    /// `decimal(minimum, maximum)`: a `BigDecimal` with scale 2, defaults 0 and 1000.
    pub fn decimal(&self, minimum: Option<f64>, maximum: Option<f64>) -> jackson::BigDecimal {
        let min = minimum.unwrap_or(0.0);
        let max = maximum.unwrap_or(1000.0);
        let value = if max <= min { min } else { min + self.random.random().next_double() * (max - min) };
        jackson::BigDecimal::parse(&scale2(value)).expect("a plain decimal")
    }

    pub fn boolean(&self) -> bool {
        self.random.random().next_boolean()
    }
}

/// `BigDecimal.intValue()` of a bound (low 32 bits of the integer part).
fn int_value(v: f64) -> i32 {
    v as i64 as i32
}

/// `BigDecimal.valueOf(d).setScale(2, RoundingMode.HALF_UP).toPlainString()`.
fn scale2(d: f64) -> String {
    let plain = jackson::BigDecimal::value_of_f64(d).to_plain_string();
    let (negative, digits) = match plain.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, plain.as_str()),
    };
    let (int_part, frac_part) = digits.split_once('.').unwrap_or((digits, ""));
    let mut frac: Vec<u8> = frac_part.bytes().collect();
    let round_up = frac.get(2).is_some_and(|d| *d >= b'5');
    frac.resize(2, b'0');
    let mut all: Vec<u8> = int_part.bytes().chain(frac).collect();
    if round_up {
        let mut i = all.len();
        loop {
            if i == 0 {
                all.insert(0, b'1');
                break;
            }
            i -= 1;
            if all[i] == b'9' {
                all[i] = b'0';
            } else {
                all[i] += 1;
                break;
            }
        }
    }
    let split = all.len() - 2;
    let text = format!("{}.{}", String::from_utf8_lossy(&all[..split]), String::from_utf8_lossy(&all[split..]));
    if negative && all.iter().any(|d| *d != b'0') { format!("-{text}") } else { text }
}

/// `GenerationOptions`: per-run example-generation options from the reserved `__generationOptions__` entry of an
/// OpenAPI import's `operationsAndResponses`.
#[derive(Clone, Debug, Default)]
pub struct GenerationOptions {
    pub seed: Option<i64>,
    pub field_overrides: Map<String, Json>,
    pub realistic_values: Option<bool>,
}

pub const OPERATIONS_KEY: &str = "__generationOptions__";

impl GenerationOptions {
    /// `GenerationOptions.fromOperationsMap`: `None` when the entry is missing, not an object, or sets nothing.
    pub fn from_operations_map(operations_and_responses: Option<&Map<String, Json>>) -> Option<GenerationOptions> {
        let options = operations_and_responses?.get(OPERATIONS_KEY)?.as_object()?;
        let seed = match options.get("seed") {
            Some(Json::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
            Some(Json::String(s)) if !s.trim().is_empty() => s.trim().parse::<i64>().ok().filter(|_| is_java_long(s.trim())),
            _ => None,
        };
        let field_overrides = options.get("fieldOverrides").and_then(Json::as_object).cloned().unwrap_or_default();
        let realistic_values = match options.get("realisticValues") {
            Some(Json::Bool(b)) => Some(*b),
            Some(Json::String(s)) if !s.trim().is_empty() => Some(s.trim().eq_ignore_ascii_case("true")),
            _ => None,
        };
        if seed.is_none() && field_overrides.is_empty() && realistic_values.is_none() {
            return None;
        }
        Some(GenerationOptions { seed, field_overrides, realistic_values })
    }

    /// `getOverride(name)` when `hasOverrideFor(name)`.
    pub fn override_for(&self, name: Option<&str>) -> Option<&Json> {
        self.field_overrides.get(name?)
    }
}

/// `Long.parseLong`: an optional sign and decimal digits only.
fn is_java_long(s: &str) -> bool {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale2_rounds_half_up() {
        assert_eq!(scale2(374.545), "374.55");
        assert_eq!(scale2(0.004), "0.00");
        assert_eq!(scale2(-0.004), "0.00");
        assert_eq!(scale2(9.995), "10.00");
        assert_eq!(scale2(1.0E-5), "0.00");
        assert_eq!(scale2(12.0), "12.00");
    }

    #[test]
    fn seed_42_matches_the_oracle() {
        // `ExampleBuilderRealisticValuesTest` goldens: a fresh generator per example.
        assert_eq!(SampleDataGenerator::default().date_time_string(), "2020-04-21T20:30:25Z");
        assert_eq!(SampleDataGenerator::default().byte_string(), "NZ1BuveK/g3hu+eu");
        assert_eq!(SampleDataGenerator::default().regexify("SKU-[0-9]{6}").unwrap(), "SKU-038405");
        assert_eq!(SampleDataGenerator::default().email(), "lamar.lehner@hotmail.com");
    }
}
