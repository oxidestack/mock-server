//! `jdk.internal.util.regex.Grapheme` as JDK 26 has it: `\X`, `\b{g}` and `NFCCharProperty` take
//! their clusters from `nextBoundary`, which types code points with its own `getType` (from `Character.getType` and
//! `Character.isExtendedPictographic`, not from Grapheme_Cluster_Break), applies the `rules` table with the gb11 and
//! regional-indicator state, and GB9c through `IndicConjunctBreak` (DerivedCoreProperties' Indic_Conjunct_Break).

use super::tables;
use std::sync::OnceLock;

const OTHER: usize = 0;
const CR: usize = 1;
const LF: usize = 2;
const CONTROL: usize = 3;
const EXTEND: usize = 4;
const ZWJ: usize = 5;
const RI: usize = 6;
const PREPEND: usize = 7;
const SPACINGMARK: usize = 8;
const L: usize = 9;
const V: usize = 10;
const T: usize = 11;
const LV: usize = 12;
const LVT: usize = 13;
const EXTENDED_PICTOGRAPHIC: usize = 14;
const TYPES: usize = 15;

/// `Grapheme.rules`: whether there is a boundary between a code point of the first type and one of the second.
const RULES: [[bool; TYPES]; TYPES] = rules();

const fn rules() -> [[bool; TYPES]; TYPES] {
    // GB 999 Any + Any -> default
    let mut rules = [[true; TYPES]; TYPES];
    // GB 6 L x (L | V | LV | VT)
    rules[L][L] = false;
    rules[L][V] = false;
    rules[L][LV] = false;
    rules[L][LVT] = false;
    // GB 7 (LV | V) x (V | T)
    rules[LV][V] = false;
    rules[LV][T] = false;
    rules[V][V] = false;
    rules[V][T] = false;
    // GB 8 (LVT | T) x T
    rules[LVT][T] = false;
    rules[T][T] = false;
    // GB 9 x (Extend|ZWJ), GB 9a x SpacingMark, GB 9b Prepend x
    let mut i = 0;
    while i < TYPES {
        rules[i][EXTEND] = false;
        rules[i][ZWJ] = false;
        rules[i][SPACINGMARK] = false;
        rules[PREPEND][i] = false;
        i += 1;
    }
    // GB 4 (Control | CR | LF) +, GB 5 + (Control | CR | LF)
    let mut i = 0;
    while i < TYPES {
        let mut j = CR;
        while j <= CONTROL {
            rules[i][j] = true;
            rules[j][i] = true;
            j += 1;
        }
        i += 1;
    }
    // GB 3 CR x LF
    rules[CR][LF] = false;
    // GB 11 Extended_Pictographic x (Extend|ZWJ)
    rules[EXTENDED_PICTOGRAPHIC][EXTEND] = false;
    rules[EXTENDED_PICTOGRAPHIC][ZWJ] = false;
    rules
}

/// `Grapheme.nextBoundary(src, off, limit)` over byte offsets: where the cluster starting at `off` ends. `off` must
/// be before `limit`.
pub(super) fn next_boundary(src: &str, off: usize, limit: usize) -> usize {
    let at = |i: usize| src[i..].chars().next().expect("a code point before the limit");
    let mut ch0 = at(off);
    let mut ret = off + ch0.len_utf8();
    let mut t0 = get_type(ch0 as u32);
    // whether gb11 or gb12 is underway
    let mut ri_count = usize::from(t0 == RI);
    let mut gb11 = t0 == EXTENDED_PICTOGRAPHIC;
    while ret < limit {
        let ch1 = at(ret);
        let t1 = get_type(ch1 as u32);
        // GB9c; `ch0` and `t0` stay as they were across the conjunct.
        if is_conjunct(CONSONANT, ch0 as u32) && let Some(advance) = check_indic_conjunct_break(src, ret, limit) {
            ret += advance;
            continue;
        }
        if gb11 && t0 == ZWJ && t1 == EXTENDED_PICTOGRAPHIC {
            // continue for gb11
        } else if ri_count % 2 == 1 && t0 == RI && t1 == RI {
            // continue for gb12
        } else if RULES[t0][t1] {
            if ret > off {
                break;
            }
            gb11 = t1 == EXTENDED_PICTOGRAPHIC;
            ri_count = 0;
        }
        ri_count += usize::from(t1 == RI);
        ch0 = ch1;
        t0 = t1;
        ret += ch1.len_utf8();
    }
    ret
}

/// `Grapheme.checkIndicConjunctBreak`: the length of `[Extend Linker]* Linker [Extend Linker]* Consonant` at
/// `index`, if it is there (only the first consonant of a longer chain).
fn check_indic_conjunct_break(src: &str, index: usize, limit: usize) -> Option<usize> {
    let mut linker_found = false;
    let mut advance = 0;
    while index + advance < limit {
        let ch1 = src[index + advance..].chars().next().expect("a code point before the limit");
        advance += ch1.len_utf8();
        let cp = ch1 as u32;
        if is_conjunct(LINKER, cp) {
            linker_found = true;
        } else if is_conjunct(CONSONANT, cp) {
            if linker_found {
                return Some(advance);
            }
            break;
        } else if !is_conjunct(INCB_EXTEND, cp) {
            break;
        }
    }
    None
}

/// `Grapheme.isExcludedSpacingMark`.
fn is_excluded_spacing_mark(cp: u32) -> bool {
    matches!(cp, 0x102B | 0x102C | 0x1038 | 0x1062..=0x1064 | 0x1067..=0x106D | 0x1083 | 0x1087..=0x108C | 0x108F
        | 0x109A..=0x109C | 0x1A61 | 0x1A63 | 0x1A64 | 0xAA7B | 0xAA7D)
}

// Hangul syllables
const SYLLABLE_BASE: u32 = 0xAC00;
const TCOUNT: u32 = 28;
const SCOUNT: u32 = 19 * 21 * TCOUNT;

/// `Grapheme.getType`.
fn get_type(cp: u32) -> usize {
    if cp < 0x7F {
        if cp < 32 {
            return match cp {
                0x0D => CR,
                0x0A => LF,
                _ => CONTROL,
            };
        }
        return OTHER;
    }
    if in_ranges(property("Extended_Pictographic"), cp) {
        return EXTENDED_PICTOGRAPHIC;
    }
    match general_category(cp) {
        // #tr29 lists unassigned code points as Control, but GraphemeBreakTest.txt has U+0378 as Other.
        "Cn" if cp == 0x0378 => OTHER,
        "Cn" | "Cc" | "Zl" | "Zp" | "Cs" => CONTROL,
        "Cf" => {
            if cp == 0x200C || (0xE0020..=0xE007F).contains(&cp) {
                EXTEND
            } else if cp == 0x200D {
                ZWJ
            } else if matches!(cp, 0x0600..=0x0605 | 0x06DD | 0x070F | 0x0890 | 0x0891 | 0x08E2 | 0x110BD | 0x110CD) {
                PREPEND
            } else {
                CONTROL
            }
        }
        "Mn" | "Me" => EXTEND,
        "Mc" if is_excluded_spacing_mark(cp) => OTHER,
        "Mc" => SPACINGMARK,
        "So" if (0x1F1E6..=0x1F1FF).contains(&cp) => RI,
        "Lm" | "Sk" if matches!(cp, 0xFF9E | 0xFF9F | 0x1F3FB..=0x1F3FF) => EXTEND,
        "Lo" => {
            if cp == 0x0E33 || cp == 0x0EB3 {
                return SPACINGMARK;
            }
            // hangul jamo
            if (0x1100..=0x11FF).contains(&cp) {
                return if cp <= 0x115F {
                    L
                } else if cp <= 0x11A7 {
                    V
                } else {
                    T
                };
            }
            // hangul syllables
            if (SYLLABLE_BASE..SYLLABLE_BASE + SCOUNT).contains(&cp) {
                return if (cp - SYLLABLE_BASE).is_multiple_of(TCOUNT) { LV } else { LVT };
            }
            // hangul jamo extended A
            if (0xA960..=0xA97C).contains(&cp) {
                return L;
            }
            // hangul jamo extended B, Kirat Rai vowel signs
            if (0xD7B0..=0xD7C6).contains(&cp) || cp == 0x16D63 || (0x16D67..=0x16D6A).contains(&cp) {
                return V;
            }
            if (0xD7CB..=0xD7FB).contains(&cp) {
                return T;
            }
            match cp {
                0x0D4E | 0x111C2 | 0x111C3 | 0x113D1 | 0x1193F | 0x11941 | 0x11A84..=0x11A89 | 0x11D46 | 0x11F02 => PREPEND,
                _ => OTHER,
            }
        }
        _ => OTHER,
    }
}

const CONSONANT: usize = 0;
const INCB_EXTEND: usize = 1;
const LINKER: usize = 2;

/// `IndicConjunctBreak.isConsonant` / `isExtend` / `isLinker`.
fn is_conjunct(value: usize, cp: u32) -> bool {
    static VALUES: OnceLock<[&'static [(u32, u32)]; 3]> = OnceLock::new();
    let values = VALUES.get_or_init(|| {
        let find = |name: &str| tables::INDIC_CONJUNCT_BREAK.iter().find(|(n, _)| *n == name).map_or(&[][..], |(_, r)| *r);
        [find("Consonant"), find("Extend"), find("Linker")]
    });
    in_ranges(values[value], cp)
}

fn property(name: &str) -> &'static [(u32, u32)] {
    tables::PROPERTIES.iter().find(|(n, _)| *n == name).map_or(&[], |(_, r)| r)
}

/// `Character.getType` as its two-letter name (`Cn` for a code point no category lists).
fn general_category(cp: u32) -> &'static str {
    static RANGES: OnceLock<Vec<(u32, u32, &'static str)>> = OnceLock::new();
    let ranges = RANGES.get_or_init(|| {
        let mut all: Vec<_> = tables::GENERAL_CATEGORIES.iter().flat_map(|(gc, r)| r.iter().map(move |&(lo, hi)| (lo, hi, *gc))).collect();
        all.sort_unstable();
        all
    });
    match ranges.binary_search_by(|&(lo, hi, _)| if hi < cp { std::cmp::Ordering::Less } else if lo > cp { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal }) {
        Ok(i) => ranges[i].2,
        Err(_) => "Cn",
    }
}

fn in_ranges(ranges: &[(u32, u32)], cp: u32) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| if hi < cp { std::cmp::Ordering::Less } else if lo > cp { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal })
        .is_ok()
}
