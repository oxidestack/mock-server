//! Derivation by restriction of complex types (`derivation-ok-restriction.5`), as Xerces' `XSConstraints` checks it
//! under full schema checking: the restriction's particle against its base's (`particleValidRestriction`, the
//! `rcase-*` cases), and the type derivation and wildcard subset rules those cases use.

use super::types::Variety;
use super::{ComplexType, Content, ElemId, Expr, Process, Schema, Type, TypeId, Wildcard};

/// Derivation methods (`XSConstants.DERIVATION_*`), as `block` and `final` sets hold them.
pub const EXTENSION: u8 = 1;
pub const RESTRICTION: u8 = 2;
pub const SUBSTITUTION: u8 = 4;
pub const LIST: u8 = 8;
pub const UNION: u8 = 16;

/// A `block`, `final` or `*Default` value as a set of derivation methods.
pub fn derivation_set(value: &str) -> u8 {
    value
        .split_whitespace()
        .map(|w| match w {
            "#all" => EXTENSION | RESTRICTION | SUBSTITUTION | LIST | UNION,
            "extension" => EXTENSION,
            "restriction" => RESTRICTION,
            "substitution" => SUBSTITUTION,
            "list" => LIST,
            "union" => UNION,
            _ => 0,
        })
        .fold(0, |a, b| a | b)
}

/// What a type definition keeps of its derivation beyond the base: the method and its `block` and `final` sets.
#[derive(Debug, Clone, Copy, Default)]
pub struct TypeFlags {
    pub by_extension: bool,
    pub block: u8,
    pub final_: u8,
}

impl Wildcard {
    /// `XSWildcardDecl.isSubsetOf`.
    pub(super) fn is_subset_of(&self, sup: &Wildcard) -> bool {
        let Some(theirs) = &sup.namespaces else { return true };
        let Some(ours) = &self.namespaces else { return false };
        match (self.negated, sup.negated) {
            (true, true) => ours == theirs,
            (false, false) => ours.iter().all(|n| theirs.contains(n)),
            // `##other` also excludes absent, which is in its list.
            (false, true) => !ours.iter().any(|n| theirs.contains(n)),
            (true, false) => false,
        }
    }

    /// `XSWildcardDecl.weakerProcessContents`.
    pub(super) fn weaker_than(&self, sup: &Wildcard) -> bool {
        (self.process == Process::Lax && sup.process == Process::Strict) || (self.process == Process::Skip && sup.process != Process::Skip)
    }

    pub(super) fn process_name(&self) -> &'static str {
        match self.process {
            Process::Strict => "strict",
            Process::Lax => "lax",
            Process::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Compositor {
    Sequence,
    Choice,
    All,
}

#[derive(Debug, Clone)]
enum Term {
    Element(ElemId),
    Any(Wildcard),
    Group(Compositor, Vec<Particle>),
    /// `PARTICLE_EMPTY`: a content particle with `minOccurs="0" maxOccurs="0"`.
    Empty,
}

/// A particle as Xerces builds it: occurrence and term (`max` `None` is unbounded).
#[derive(Debug, Clone)]
struct Particle {
    min: u64,
    max: Option<u64>,
    term: Term,
}

/// The shape a particle takes once pointless groups are removed and substitution groups expanded.
enum Kind<'p> {
    Element(ElemId),
    Any(&'p Wildcard),
    Group(Compositor),
    Empty,
}

/// Why a particle is not a valid restriction: a rule, past which an enclosing mapping may try the next base
/// particle, or a crash of Xerces' check itself, which fails the schema outright.
enum Failure {
    Rule(String),
    Crash(String),
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure::Rule(message)
    }
}

type Checked<T> = Result<T, Failure>;

fn rule<T>(message: String) -> Checked<T> {
    Err(Failure::Rule(message))
}

fn once(term: Term) -> Particle {
    Particle { min: 1, max: Some(1), term }
}

/// The particle of a content model.
fn particle(e: &Expr) -> Option<Particle> {
    // A particle with `maxOccurs="0"` (or a dropped reference) is not in its group: `traverseLocalElements`
    // removes such element particles, and the other traversers never add theirs.
    let group = |c, items: &[Expr]| Some(once(Term::Group(c, items.iter().filter(|i| !matches!(i, Expr::Empty)).filter_map(particle).collect())));
    match e {
        Expr::Empty => Some(Particle { min: 0, max: Some(0), term: Term::Empty }),
        Expr::Fail => Some(once(Term::Group(Compositor::Choice, Vec::new()))),
        Expr::Element(id) => Some(once(Term::Element(*id))),
        Expr::Any(w) => Some(once(Term::Any((**w).clone()))),
        Expr::Sequence(items) => group(Compositor::Sequence, items),
        Expr::Choice(items) => group(Compositor::Choice, items),
        Expr::All(members) => Some(once(Term::Group(
            Compositor::All,
            members.iter().map(|(id, required)| Particle { min: u64::from(*required), max: Some(1), term: Term::Element(*id) }).collect(),
        ))),
        Expr::Repeat(inner, min, max) => {
            let p = particle(inner)?;
            let (min, max) = (u64::from(*min), max.map(u64::from));
            Some(if p.min == 1 && p.max == Some(1) { Particle { min, max, ..p } } else { Particle { min, max, term: Term::Group(Compositor::Sequence, vec![p]) } })
        }
    }
}

fn empty_sequence() -> Particle {
    once(Term::Group(Compositor::Sequence, Vec::new()))
}

fn is_empty(p: &Particle) -> bool {
    match &p.term {
        Term::Element(_) | Term::Any(_) => false,
        Term::Group(_, items) => items.iter().all(is_empty),
        Term::Empty => true,
    }
}

fn min_total(p: &Particle) -> u64 {
    match &p.term {
        Term::Element(_) | Term::Any(_) => p.min,
        Term::Empty => 0,
        Term::Group(Compositor::Choice, items) => items.iter().map(min_total).min().unwrap_or(0) * p.min,
        Term::Group(_, items) => items.iter().map(min_total).sum::<u64>() * p.min,
    }
}

fn max_total(p: &Particle) -> Option<u64> {
    let group = match &p.term {
        Term::Element(_) | Term::Any(_) => return p.max,
        Term::Empty => return Some(0),
        Term::Group(Compositor::Choice, items) => items.iter().map(max_total).try_fold(0, |a, m| m.map(|m| a.max(m))),
        Term::Group(_, items) => items.iter().map(max_total).try_fold(0u64, |a, m| m.map(|m| a.saturating_add(m))),
    };
    match (group, p.max) {
        (None, _) => None,
        (Some(0), _) => Some(0),
        (Some(_), None) => None,
        (Some(g), Some(m)) => Some(g.saturating_mul(m)),
    }
}

fn emptiable(p: &Particle) -> bool {
    min_total(p) == 0
}

/// `getNonUnaryGroup`: a `(1,1)` group with one particle stands for that particle.
fn non_unary(p: &Particle) -> &Particle {
    match &p.term {
        Term::Group(_, items) if p.min == 1 && p.max == Some(1) && items.len() == 1 => non_unary(&items[0]),
        _ => p,
    }
}

/// `removePointlessChildren` / `gatherChildren`.
fn gather(parent: Compositor, p: &Particle, out: &mut Vec<Particle>) {
    match &p.term {
        Term::Element(_) | Term::Any(_) | Term::Empty => out.push(p.clone()),
        Term::Group(c, items) => {
            if !(p.min == 1 && p.max == Some(1)) {
                out.push(p.clone());
            } else if *c == parent {
                for item in items {
                    gather(*c, item, out);
                }
            } else if !is_empty(p) {
                out.push(p.clone());
            }
        }
    }
}

fn range_ok(min1: u64, max1: Option<u64>, min2: u64, max2: Option<u64>) -> bool {
    min1 >= min2 && match (max1, max2) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a <= b,
    }
}

/// A namespace as Java prints a `null` one.
fn or_null(namespace: &str) -> &str {
    if namespace.is_empty() { "null" } else { namespace }
}

fn bound(max: Option<u64>) -> String {
    max.map(|m| m.to_string()).unwrap_or_else(|| "unbounded".into())
}

const NO_MAPPING: &str = "There is not a complete functional mapping between the particles.";

fn group_range(key: &str, min1: u64, max1: Option<u64>, min2: u64, max2: Option<u64>) -> String {
    format!("{key}: Group's occurrence range, ({min1},{}), is not a valid restriction of base group's occurrence range, ({min2},{}).", bound(max1), bound(max2))
}

impl Schema {
    fn flags(&self, id: TypeId) -> TypeFlags {
        self.type_flags.get(&id).copied().unwrap_or_default()
    }

    fn any_simple_type(&self) -> TypeId {
        self.builtin("anySimpleType")
    }

    /// `XSConstraints.checkTypeDerivationOk`: whether `d` is validly derived from `b` with the methods in `block`
    /// disallowed.
    pub(super) fn derivation_ok(&self, d: TypeId, b: TypeId, block: u8) -> bool {
        let any_simple = self.any_simple_type();
        if d == self.any_type {
            return d == b;
        }
        if d == any_simple {
            return b == self.any_type || b == any_simple;
        }
        match &self.types[d] {
            Type::Simple(_) => match self.simple_base(b) {
                Some(b) => self.simple_derivation_ok(d, b, block, 0),
                None => false,
            },
            Type::Complex(_) => self.complex_derivation_ok(d, b, block, 0),
        }
    }

    /// `b` as a simple type to derive from: `anyType` stands for `anySimpleType`, another complex type for none.
    fn simple_base(&self, b: TypeId) -> Option<TypeId> {
        match &self.types[b] {
            Type::Simple(_) => Some(b),
            Type::Complex(_) if b == self.any_type => Some(self.any_simple_type()),
            Type::Complex(_) => None,
        }
    }

    /// `checkSimpleDerivation`.
    pub(super) fn simple_derivation_ok(&self, d: TypeId, b: TypeId, block: u8, depth: usize) -> bool {
        if d == b {
            return true;
        }
        if depth > 200 {
            return false;
        }
        let Type::Simple(st) = &self.types[d] else { return false };
        let Some(base) = st.base else { return false };
        if block & RESTRICTION != 0 || self.flags(base).final_ & RESTRICTION != 0 {
            return false;
        }
        if base == b {
            return true;
        }
        let any_simple = self.any_simple_type();
        if base != any_simple && self.simple_derivation_ok(base, b, block, depth + 1) {
            return true;
        }
        if matches!(st.variety, Variety::List(_) | Variety::Union(_)) && b == any_simple {
            return true;
        }
        if let Type::Simple(bt) = &self.types[b] && let Variety::Union(members) = &bt.variety {
            return members.iter().any(|m| self.simple_derivation_ok(d, *m, block, depth + 1));
        }
        false
    }

    /// `checkComplexDerivation`.
    fn complex_derivation_ok(&self, d: TypeId, b: TypeId, block: u8, depth: usize) -> bool {
        if d == b {
            return true;
        }
        if depth > 200 {
            return false;
        }
        let Type::Complex(ct) = &self.types[d] else { return false };
        let method = if self.flags(d).by_extension { EXTENSION } else { RESTRICTION };
        if method & block != 0 {
            return false;
        }
        let base = ct.base.unwrap_or(self.any_type);
        if base == b {
            return true;
        }
        if base == self.any_type || base == self.any_simple_type() {
            return false;
        }
        match &self.types[base] {
            Type::Complex(_) => self.complex_derivation_ok(base, b, block, depth + 1),
            Type::Simple(_) => match self.simple_base(b) {
                Some(b) => self.simple_derivation_ok(base, b, block, depth + 1),
                None => false,
            },
        }
    }

    /// `getDBMethods`: the derivation methods from `d` up to `b` and the blocks of the complex types passed, or
    /// `None` when `d` does not derive from `b` or a step is blocked.
    fn derivation_methods(&self, mut d: TypeId, b: TypeId) -> Option<u8> {
        let (mut methods, mut blocked) = (0u8, 0u8);
        let mut guard = 0;
        while d != b && d != self.any_type {
            guard += 1;
            if guard > 1000 {
                return None;
            }
            let base = match &self.types[d] {
                Type::Complex(ct) => {
                    methods |= if self.flags(d).by_extension { EXTENSION } else { RESTRICTION };
                    ct.base
                }
                Type::Simple(st) => {
                    methods |= RESTRICTION;
                    st.base
                }
            };
            d = base.unwrap_or(self.any_type);
            if matches!(self.types[d], Type::Complex(_)) {
                blocked |= self.flags(d).block;
            }
        }
        (d == b && methods & blocked == 0).then_some(methods)
    }

    /// `SubstitutionGroupHandler.getSubstitutionGroup`: the members that may substitute for `head`.
    fn substitution_group(&self, head: ElemId) -> Vec<ElemId> {
        let decl = &self.elements[head];
        if decl.block & SUBSTITUTION != 0 {
            return Vec::new();
        }
        let Some(members) = self.substitutes.get(&head) else { return Vec::new() };
        members
            .iter()
            .copied()
            .filter(|m| self.derivation_methods(self.elements[*m].ty, decl.ty).is_some_and(|methods| decl.block & methods == 0))
            .collect()
    }

    /// The content particle of a complex type: `None` for empty or simple content.
    fn content_particle(&self, ct: &ComplexType) -> Option<Particle> {
        match &ct.content {
            Content::Empty | Content::Simple(_) => None,
            Content::Any => Some(once(Term::Group(
                Compositor::Sequence,
                vec![Particle { min: 0, max: None, term: Term::Any(Wildcard { namespaces: None, negated: false, process: Process::Lax }) }],
            ))),
            Content::Elements(Expr::Empty) if ct.mixed => Some(empty_sequence()),
            Content::Elements(Expr::Empty) => None,
            Content::Elements(e) => particle(e),
        }
    }

    /// `derivation-ok-restriction.5.3.2` and `.5.4.2` for every complex type derived by restriction from a complex
    /// type other than `anyType`.
    pub(super) fn check_particle_restrictions(&self) -> Result<(), (TypeId, String)> {
        for (id, ty) in self.types.iter().enumerate() {
            let Type::Complex(ct) = ty else { continue };
            let Some(base) = ct.base else { continue };
            if base == self.any_type || self.flags(id).by_extension {
                continue;
            }
            let Type::Complex(base_ct) = &self.types[base] else { continue };
            let derived = self.content_particle(ct);
            let theirs = self.content_particle(base_ct);
            match (derived, theirs) {
                (None, Some(b)) if !emptiable(&b) => {
                    return Err((id, format!(
                        "derivation-ok-restriction.5.3.2: Error for type '{}'.  The content type of this type is empty, but the content type of the base, '{}', is not empty or emptiable.",
                        ct.name, base_ct.name
                    )));
                }
                (Some(_), None) => {
                    return Err((id, format!("derivation-ok-restriction.5.4.2: Error for type '{}'.  The particle of the type is not a valid restriction of the particle of the base.", ct.name)));
                }
                (Some(d), Some(b)) => {
                    if let Err(Failure::Rule(message) | Failure::Crash(message)) = self.valid_restriction(&d, true, &b, true, true) {
                        return Err((id, message));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Normalises a particle for `particleValidRestriction`: pointless groups removed, a substitution group head
    /// expanded into a choice of its members (when `sg`). Returns the particle that stands, its kind and children,
    /// and whether a substitution group was expanded.
    fn normalise<'p>(&self, original: &'p Particle, sg: bool) -> Checked<(&'p Particle, Kind<'p>, Vec<Particle>, bool)> {
        let p = non_unary(original);
        if matches!(original.term, Term::Group(..)) && matches!(p.term, Term::Empty) {
            // `removePointlessChildren` casts the empty particle's term to a model group.
            return Err(Failure::Crash(
                "java.lang.ClassCastException: class com.sun.org.apache.xerces.internal.impl.xs.XSElementDecl cannot be cast to class com.sun.org.apache.xerces.internal.impl.xs.XSModelGroupImpl".into(),
            ));
        }
        Ok(match &p.term {
            Term::Empty => (p, Kind::Empty, Vec::new(), false),
            Term::Element(id) => {
                let mut members = if sg { self.substitution_group(*id) } else { Vec::new() };
                if members.is_empty() {
                    return Ok((p, Kind::Element(*id), Vec::new(), false));
                }
                members.push(*id);
                members.sort_by(|a, b| {
                    let (na, nb) = (&self.elements[*a].name, &self.elements[*b].name);
                    na.0.cmp(&nb.0).then_with(|| na.1.cmp(&nb.1))
                });
                (p, Kind::Group(Compositor::Choice), members.into_iter().map(|m| once(Term::Element(m))).collect(), true)
            }
            Term::Any(w) => (p, Kind::Any(w), Vec::new(), false),
            Term::Group(c, items) => {
                let mut children = Vec::new();
                for item in items {
                    gather(*c, item, &mut children);
                }
                (p, Kind::Group(*c), children, false)
            }
        })
    }

    /// [`Schema::valid_restriction`] where a rule failure is `None`, for the mappings that try base particles.
    fn try_restriction(&self, d: &Particle, d_sg: bool, b: &Particle, b_sg: bool) -> Checked<Option<bool>> {
        match self.valid_restriction(d, d_sg, b, b_sg, true) {
            Ok(expanded) => Ok(Some(expanded)),
            Err(Failure::Rule(_)) => Ok(None),
            Err(crash) => Err(crash),
        }
    }

    /// `particleValidRestriction`; `Ok(true)` when the base was an expanded substitution group.
    fn valid_restriction(&self, d: &Particle, d_sg: bool, b: &Particle, b_sg: bool, check_wc: bool) -> Checked<bool> {
        if is_empty(d) && !emptiable(b) {
            return rule("cos-particle-restrict.a: Derived particle is empty, and base is not emptiable.".into());
        }
        if !is_empty(d) && is_empty(b) {
            return rule("cos-particle-restrict.b: Base particle is empty, but derived particle is not.".into());
        }
        let (dp, dk, dch, d_expanded) = self.normalise(d, d_sg)?;
        let (bp, bk, bch, b_expanded) = self.normalise(b, b_sg)?;
        let (d_sg, b_sg) = (d_sg && !d_expanded, b_sg && !b_expanded);
        let (dmin, dmax, bmin, bmax) = (dp.min, dp.max, bp.min, bp.max);
        // The effective total range of a group (an expanded substitution group keeps the particle's occurrence).
        let (dmin_total, dmax_total) = if d_expanded { (dmin, dmax) } else { (min_total(dp), max_total(dp)) };
        let forbidden = |what: &str| rule(format!("cos-particle-restrict.2: Forbidden particle restriction: '{what}'."));
        use Compositor::*;
        match (dk, bk) {
            // No case of Xerces' switch takes an empty particle: it passes.
            (Kind::Empty, _) => {}
            (_, Kind::Empty) => return rule("Internal-Error: in particleValidRestriction".into()),
            (Kind::Element(de), Kind::Element(be)) => self.name_and_type_ok(de, dmin, dmax, be, bmin, bmax)?,
            (Kind::Element(de), Kind::Any(w)) => self.ns_compat(de, dmin, dmax, w, bmin, bmax, check_wc)?,
            (Kind::Element(_), Kind::Group(Choice)) => self.recurse_lax(std::slice::from_ref(dp), 1, Some(1), d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Element(_), Kind::Group(_)) => self.recurse(std::slice::from_ref(dp), 1, Some(1), d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Any(dw), Kind::Any(bw)) => {
                if !range_ok(dmin, dmax, bmin, bmax) {
                    return rule(format!("rcase-NSSubset.2: Wildcard's occurrence range, ({dmin},{}), is not a valid restriction of that in the base, ({bmin},{}),.", bound(dmax), bound(bmax)));
                }
                if !dw.is_subset_of(bw) {
                    return rule("rcase-NSSubset.1: Wildcard is not a subset of corresponding wildcard in base.".into());
                }
                if dw.weaker_than(bw) {
                    return rule(format!("rcase-NSSubset.3: Wildcard's process contents, '{}', is weaker than that in the base, '{}'.", dw.process_name(), bw.process_name()));
                }
            }
            (Kind::Any(_), _) => return forbidden("any:choice,sequence,all,elt"),
            (Kind::Group(_), Kind::Any(_)) => {
                if check_wc && !range_ok(dmin_total, dmax_total, bmin, bmax) {
                    return rule(format!(
                        "rcase-NSRecurseCheckCardinality.2: Group's occurrence range, ({dmin_total},{}), is not a valid restriction of base wildcard's range, ({bmin},{}).",
                        bound(dmax_total),
                        bound(bmax)
                    ));
                }
                for child in &dch {
                    self.valid_restriction(child, d_sg, bp, false, false)?;
                }
            }
            (Kind::Group(All), Kind::Group(All)) => self.recurse(&dch, dmin, dmax, d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Group(All), _) => return forbidden("all:choice,sequence,elt"),
            (Kind::Group(Choice), Kind::Group(Choice)) => self.recurse_lax(&dch, dmin, dmax, d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Group(Choice), _) => return forbidden("choice:all,sequence,elt"),
            (Kind::Group(Sequence), Kind::Group(All)) => self.recurse_unordered(&dch, dmin, dmax, d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Group(Sequence), Kind::Group(Sequence)) => self.recurse(&dch, dmin, dmax, d_sg, &bch, bmin, bmax, b_sg)?,
            (Kind::Group(Sequence), Kind::Group(Choice)) => {
                let n = dch.len() as u64;
                self.map_and_sum(&dch, dmin * n, dmax.map(|m| m * n), d_sg, &bch, bmin, bmax, b_sg)?
            }
            (Kind::Group(Sequence), Kind::Element(_)) => return forbidden("seq:elt"),
        }
        Ok(b_expanded)
    }

    /// `checkNameAndTypeOK`.
    fn name_and_type_ok(&self, d: ElemId, dmin: u64, dmax: Option<u64>, b: ElemId, bmin: u64, bmax: Option<u64>) -> Result<(), String> {
        let (de, be) = (&self.elements[d], &self.elements[b]);
        let name = &de.name.1;
        if de.name != be.name {
            return Err(format!(
                "rcase-NameAndTypeOK.1: Elements have names and target namespaces which are not the same:  Element '{}' in namespace '{}' and element '{}' in namespace '{}'.",
                de.name.1,
                or_null(&de.name.0),
                be.name.1,
                or_null(&be.name.0)
            ));
        }
        if de.nillable && !be.nillable {
            return Err(format!("rcase-NameAndTypeOK.2: Error for the particle whose {{term}} is the element declaration '{name}'. The element declaration's {{nillable}} is true, but the corresponding particle in the base type has an element declaration whose {{nillable}} is false."));
        }
        if !range_ok(dmin, dmax, bmin, bmax) {
            return Err(format!(
                "rcase-NameAndTypeOK.3: Error for the particle whose {{term}} is the element declaration '{name}'. Its occurrence range, ({dmin},{}), is not a valid restriction of the range, ({bmin},{}), of the corresponding particle in the base type.",
                bound(dmax),
                bound(bmax)
            ));
        }
        if let Some(base_fixed) = &be.fixed {
            let Some(fixed) = &de.fixed else {
                return Err(format!("rcase-NameAndTypeOK.4.a: Element '{name}' is not fixed, but the corresponding element in the base type is fixed with value '{base_fixed}'."));
            };
            if !self.same_fixed(de.ty, fixed, be.ty, base_fixed) {
                return Err(format!("rcase-NameAndTypeOK.4.b: Element '{name}' is fixed with value '{fixed}', but the corresponding element in the base type is fixed with value '{base_fixed}'."));
            }
        }
        if de.block & be.block != be.block {
            return Err(format!("rcase-NameAndTypeOK.6: The disallowed substitutions for element '{name}' are not a superset of those in the base."));
        }
        if !self.derivation_ok(de.ty, be.ty, EXTENSION | LIST | UNION) {
            return Err(format!(
                "rcase-NameAndTypeOK.7: The type of element '{name}', '{}', is not derived from the type of the base element, '{}'.",
                self.type_label(de.ty),
                self.type_label(be.ty)
            ));
        }
        Ok(())
    }

    /// A type's `getName()`: `null` for an anonymous type.
    fn type_label(&self, id: TypeId) -> &str {
        let name = match &self.types[id] {
            Type::Simple(s) => &s.name,
            Type::Complex(c) => &c.name,
        };
        if name.is_empty() || name.starts_with("#AnonType_") { "null" } else { name }
    }

    /// Two fixed values compared as actual values of a simple (content) type, or else as strings.
    fn same_fixed(&self, dt: TypeId, d: &str, bt: TypeId, b: &str) -> bool {
        let simple = |t: TypeId| match &self.types[t] {
            Type::Simple(_) => Some(t),
            Type::Complex(ct) => match ct.content {
                Content::Simple(s) => Some(s),
                _ => None,
            },
        };
        let (Some(ds), Some(bs)) = (simple(dt), simple(bt)) else { return d == b };
        let bound = |_: &str| true;
        let resolve = |_: Option<&str>| Some(String::new());
        let value = |t: TypeId, v: &str| self.validate_simple(t, v, &bound).ok().map(|n| self.ic_value(t, &n, &resolve));
        match (value(ds, d), value(bs, b)) {
            (Some(x), Some(y)) => x.kind == y.kind && x.key == y.key,
            _ => d == b,
        }
    }

    /// `checkNSCompat`.
    #[allow(clippy::too_many_arguments)]
    fn ns_compat(&self, d: ElemId, dmin: u64, dmax: Option<u64>, w: &Wildcard, bmin: u64, bmax: Option<u64>, check_wc: bool) -> Result<(), String> {
        let de = &self.elements[d];
        if check_wc && !range_ok(dmin, dmax, bmin, bmax) {
            return Err(format!(
                "rcase-NSCompat.2: Error for the particle whose {{term}} is the element declaration '{}'. Its occurrence range, ({dmin},{}), is not a valid restriction of the range, ({bmin},{}), of the corresponding particle in the base type.",
                de.name.1,
                bound(dmax),
                bound(bmax)
            ));
        }
        if !w.allows(&de.name.0) {
            return Err(format!("rcase-NSCompat.1: Element '{}' has a namespace '{}' which is not allowed by the wildcard in the base.", de.name.1, or_null(&de.name.0)));
        }
        Ok(())
    }

    /// `checkRecurse`: an order-preserving mapping where every unmapped base particle is emptiable.
    #[allow(clippy::too_many_arguments)]
    fn recurse(&self, dch: &[Particle], min1: u64, max1: Option<u64>, d_sg: bool, bch: &[Particle], min2: u64, max2: Option<u64>, b_sg: bool) -> Checked<()> {
        if !range_ok(min1, max1, min2, max2) {
            return rule(group_range("rcase-Recurse.1", min1, max1, min2, max2));
        }
        let mut current = 0;
        'derived: for p1 in dch {
            while current < bch.len() {
                let p2 = &bch[current];
                current += 1;
                if self.try_restriction(p1, d_sg, p2, b_sg)?.is_some() {
                    continue 'derived;
                }
                if !emptiable(p2) {
                    return rule(format!("rcase-Recurse.2: {NO_MAPPING}"));
                }
            }
            return rule(format!("rcase-Recurse.2: {NO_MAPPING}"));
        }
        if bch[current..].iter().any(|p2| !emptiable(p2)) {
            return rule(format!("rcase-Recurse.2: {NO_MAPPING}"));
        }
        Ok(())
    }

    /// `checkRecurseLax`: an order-preserving mapping; an expanded substitution group may take several.
    #[allow(clippy::too_many_arguments)]
    fn recurse_lax(&self, dch: &[Particle], min1: u64, max1: Option<u64>, d_sg: bool, bch: &[Particle], min2: u64, max2: Option<u64>, b_sg: bool) -> Checked<()> {
        if !range_ok(min1, max1, min2, max2) {
            return rule(group_range("rcase-RecurseLax.1", min1, max1, min2, max2));
        }
        let mut current = 0;
        'derived: for p1 in dch {
            let mut j = current;
            while j < bch.len() {
                current += 1;
                if let Some(expanded) = self.try_restriction(p1, d_sg, &bch[j], b_sg)? {
                    if expanded {
                        current -= 1;
                    }
                    continue 'derived;
                }
                j += 1;
            }
            return rule(format!("rcase-RecurseLax.2: {NO_MAPPING}"));
        }
        Ok(())
    }

    /// `checkRecurseUnordered`: a sequence restricting an `all`.
    #[allow(clippy::too_many_arguments)]
    fn recurse_unordered(&self, dch: &[Particle], min1: u64, max1: Option<u64>, d_sg: bool, bch: &[Particle], min2: u64, max2: Option<u64>, b_sg: bool) -> Checked<()> {
        if !range_ok(min1, max1, min2, max2) {
            return rule(group_range("rcase-RecurseUnordered.1", min1, max1, min2, max2));
        }
        let mut found = vec![false; bch.len()];
        'derived: for p1 in dch {
            for (j, p2) in bch.iter().enumerate() {
                // A base particle already mapped is skipped (Xerces' exception for it is caught by its own loop).
                if self.try_restriction(p1, d_sg, p2, b_sg)?.is_some() && !found[j] {
                    found[j] = true;
                    continue 'derived;
                }
            }
            return rule(format!("rcase-RecurseUnordered.2: {NO_MAPPING}"));
        }
        if bch.iter().zip(&found).any(|(p2, f)| !f && !emptiable(p2)) {
            return rule(format!("rcase-RecurseUnordered.2: {NO_MAPPING}"));
        }
        Ok(())
    }

    /// `checkMapAndSum`: a sequence restricting a choice.
    #[allow(clippy::too_many_arguments)]
    fn map_and_sum(&self, dch: &[Particle], min1: u64, max1: Option<u64>, d_sg: bool, bch: &[Particle], min2: u64, max2: Option<u64>, b_sg: bool) -> Checked<()> {
        if !range_ok(min1, max1, min2, max2) {
            return rule(group_range("rcase-MapAndSum.2", min1, max1, min2, max2));
        }
        'derived: for p1 in dch {
            for p2 in bch {
                if self.try_restriction(p1, d_sg, p2, b_sg)?.is_some() {
                    continue 'derived;
                }
            }
            return rule(format!("rcase-MapAndSum.1: {NO_MAPPING}"));
        }
        Ok(())
    }
}
