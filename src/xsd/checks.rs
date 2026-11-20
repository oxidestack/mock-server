//! Schema component constraints Xerces checks once the components are built: value constraints, ID attributes,
//! attribute restrictions, substitution groups, consistent element declarations and Unique Particle Attribution.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{AttributeUse, Builder, ComplexType, Content, ElemId, Expr, Schema, Type, TypeId, Wildcard};

impl Schema {
    /// Whether `t` is `b` or derived from it (`checkCOSDerivationOK`, without the blocking sets): through bases, and
    /// for a simple type also as a member of union `b`.
    pub(super) fn type_derives(&self, t: TypeId, b: TypeId) -> bool {
        if b == self.any_type {
            return true;
        }
        let mut current = Some(t);
        let mut guard = 0;
        while let Some(c) = current {
            if c == b {
                return true;
            }
            if let Type::Simple(union) = &self.types[b] && let super::types::Variety::Union(members) = &union.variety && members.iter().any(|m| self.type_derives(c, *m)) {
                return true;
            }
            guard += 1;
            if guard > 1000 {
                return false;
            }
            current = match &self.types[c] {
                Type::Simple(s) => s.base,
                Type::Complex(ct) => ct.base,
            };
        }
        false
    }

    fn type_name(&self, id: TypeId) -> &str {
        match &self.types[id] {
            Type::Simple(s) => &s.name,
            Type::Complex(c) => &c.name,
        }
    }

    fn is_id(&self, id: TypeId) -> bool {
        matches!(self.types[id], Type::Simple(_)) && self.derives_from(id, "ID")
    }

    /// Values whose validity needs the declaration's namespace context, which is not kept.
    fn context_dependent(&self, id: TypeId) -> bool {
        self.derives_from(id, "QName") || self.derives_from(id, "NOTATION")
    }
}

impl<'a, 'input> Builder<'a, 'input> {
    /// `derivation-ok-restriction.2` to `.4` for the attribute uses of complex restriction `ct` (its own uses only,
    /// before the base's are merged in) of `base` (`XSAttributeGroupDecl.validRestrictionOf`), reported at `at`
    /// (where Xerces' traverser stands: `None` for no element).
    pub(super) fn check_attribute_restriction(&mut self, ct: &ComplexType, base: &ComplexType, at: Option<(usize, usize)>) -> Result<(), String> {
        let fail = |builder: &Self, message: String| match at {
            Some(place) => builder.fail_at(place, message),
            None => message,
        };
        for own in ct.attributes.iter().filter(|a| !a.prohibited) {
            match base.attributes.iter().find(|b| b.name == own.name && !b.prohibited) {
                Some(theirs) => {
                    self.ensure_built(own.ty)?;
                    self.ensure_built(theirs.ty)?;
                    if theirs.required && !own.required {
                        return Err(fail(self, format!(
                            "derivation-ok-restriction.2.1.1: Error for type '{}'.  The attribute use '{}' in this type has a 'use' value of 'optional', which is inconsistent with the value of 'required' in a matching attribute use in the base type.",
                            ct.name, own.name.1
                        )));
                    }
                    if !self.schema.type_derives(own.ty, theirs.ty) {
                        return Err(fail(self, format!(
                            "derivation-ok-restriction.2.1.2: Error for type '{}'.  The attribute use '{}' in this type has type '{}', which is not validly derived from '{}', the type of the matching attribute use in the base type.",
                            ct.name,
                            own.name.1,
                            self.schema.type_name(own.ty),
                            self.schema.type_name(theirs.ty)
                        )));
                    }
                    if let Some(base_fixed) = &theirs.fixed {
                        let Some(fixed) = &own.fixed else {
                            return Err(fail(self, format!(
                                "derivation-ok-restriction.2.1.3.a: Error for type '{}'.  The attribute use '{}' in this type has an effective value constraint which is not fixed, and the effective value constraint of the matching attribute use in the base type is fixed.",
                                ct.name, own.name.1
                            )));
                        };
                        let bound = |_: &str| true;
                        let resolve = |_: Option<&str>| Some(String::new());
                        let actual = |t: TypeId, v: &str| self.schema.validate_simple(t, v, &bound).ok().map(|n| self.schema.ic_value(t, &n, &resolve)).map(|v| (v.kind, v.key));
                        let same = match (actual(own.ty, fixed), actual(theirs.ty, base_fixed)) {
                            (Some(a), Some(b)) => a == b,
                            _ => fixed == base_fixed,
                        };
                        if !same {
                            return Err(fail(self, format!(
                                "derivation-ok-restriction.2.1.3.b: Error for type '{}'.  The attribute use '{}' in this type has an effective value constraint fixed with a value of '{fixed}', which is not consistent with the value of '{base_fixed}' for the fixed effective value constraint of the matching attribute use in the base type.",
                                ct.name, own.name.1
                            )));
                        }
                    }
                }
                None => match &base.attribute_wildcard {
                    Some(w) if w.allows(&own.name.0) => {}
                    Some(_) => {
                        return Err(fail(self, format!(
                            "derivation-ok-restriction.2.2.b: Error for type '{}'.  The attribute use '{}' in this type does not have a matching attribute use in the base, and the wildcard in the base type does not allow the namespace '{}' of this attribute use.",
                            ct.name, own.name.1, own.name.0
                        )));
                    }
                    None => {
                        return Err(fail(self, format!(
                            "derivation-ok-restriction.2.2.a: Error for type '{}'.  The attribute use '{}' in this type does not have a matching attribute use in the base, and the base type does not have a wildcard attribute.",
                            ct.name, own.name.1
                        )));
                    }
                },
            }
        }
        // A required use of the base that a prohibited use here keeps out of the merged uses.
        if let Some(theirs) = base.attributes.iter().find(|b| b.required && !b.prohibited && ct.attributes.iter().any(|o| o.name == b.name && o.prohibited)) {
            return Err(fail(self, format!(
                "derivation-ok-restriction.3: Error for type '{}'.  The attribute use '{}' in the base type has REQUIRED as true, but there is no matching attribute use in the derived type.",
                ct.name, theirs.name.1
            )));
        }
        if let Some(ours) = &ct.attribute_wildcard {
            let Some(theirs) = &base.attribute_wildcard else {
                return Err(fail(self, format!("derivation-ok-restriction.4.1: Error for type '{}'.  The derivation has an attribute wildcard, but the base does not have one.", ct.name)));
            };
            if !ours.is_subset_of(theirs) {
                return Err(fail(self, format!("derivation-ok-restriction.4.2: Error for type '{}'.  The wildcard in the derivation is not a valid wildcard subset of the one in the base.", ct.name)));
            }
            if ours.weaker_than(theirs) {
                return Err(fail(self, format!(
                    "derivation-ok-restriction.4.3: Error for type '{}'.  The process contents of the wildcard in the derivation ({}) is weaker than that in the base ({}).",
                    ct.name,
                    ours.process_name(),
                    theirs.process_name()
                )));
            }
        }
        Ok(())
    }

    /// The checks over the built schema, each component once.
    pub(super) fn check_components(&mut self) -> Result<(), String> {
        let schema = &self.schema;
        let unbound_values = &self.unbound_values;
        let bound = |_: &str| true;
        // Element value constraints (`e-props-correct.2`, `.5`): `ElementDefaultValidImmediate`.
        for decl in &schema.elements {
            if let Some(ty) = schema.notation_without_enumeration(decl.ty) {
                return Err(self.fail_at(decl.source, format!(
                    "enumeration-required-notation: The NOTATION type, '{ty}' used by element '{}', must have an enumeration facet value which specifies the notation elements used by this type.",
                    decl.name.1
                )));
            }
            let Some(value) = decl.fixed.as_ref().or(decl.default.as_ref()) else { continue };
            let invalid = || self.fail_at(decl.source, format!("e-props-correct.2: Invalid value constraint value '{value}' in element '{}'.", decl.name.1));
            let simple = match &schema.types[decl.ty] {
                Type::Simple(_) => Some(decl.ty),
                Type::Complex(ct) => match &ct.content {
                    Content::Simple(s) => Some(*s),
                    Content::Any => None,
                    Content::Elements(e) if ct.mixed && schema.nullable(e) => None,
                    _ => return Err(invalid()),
                },
            };
            if let Some(simple) = simple {
                let unbound = schema.context_dependent(simple) && self.unbound_values.contains(&decl.source);
                if unbound || (!schema.context_dependent(simple) && schema.validate_simple(simple, value, &bound).is_err()) {
                    return Err(invalid());
                }
                if schema.is_id(simple) {
                    return Err(self.fail_at(decl.source, format!(
                        "e-props-correct.5: A {{value constraint}} must not be present on element '{}', because the element's {{type definition}} or {{type definition}}'s {{content type}} is ID, or is derived from ID.",
                        decl.name.1
                    )));
                }
            }
        }
        // Attribute value constraints (`a-props-correct.2`, `.3`) and ID attributes (`ct-props-correct.5`).
        let check_use = |a: &AttributeUse| -> Result<(), String> {
            if let Some(ty) = schema.notation_without_enumeration(a.ty) {
                return Err(self.fail_at(a.source, format!(
                    "enumeration-required-notation: The NOTATION type, '{ty}' used by attribute '{}', must have an enumeration facet value which specifies the notation elements used by this type.",
                    a.name.1
                )));
            }
            let Some(value) = a.fixed.as_ref().or(a.default.as_ref()) else { return Ok(()) };
            if !schema.context_dependent(a.ty) {
                schema.validate_simple(a.ty, value, &bound).map_err(|m| self.fail_at(a.source, m))?;
            } else if unbound_values.contains(&a.source) {
                // The QName value's own error, which Xerces reports before `a-props-correct.2`.
                let prefix = value.trim().split_once(':').map_or("", |(p, _)| p);
                return Err(self.fail_at(a.source, format!("UndeclaredPrefix: Cannot resolve '{}' as a QName: the prefix '{prefix}' is not declared.", value.trim())));
            }
            if schema.is_id(a.ty) {
                return Err(self.fail_at(a.source, format!("a-props-correct.3: Attribute '{}' cannot use 'fixed' or 'default', because the attribute's {{type definition}} is ID, or is derived from ID.", a.name.1)));
            }
            Ok(())
        };
        let mut globals: Vec<&AttributeUse> = schema.global_attributes.values().collect();
        globals.sort_by_key(|a| a.source);
        for a in globals {
            check_use(a)?;
        }
        for ty in &schema.types {
            let Type::Complex(ct) = ty else { continue };
            for a in &ct.attributes {
                check_use(a)?;
            }
            let ids: Vec<&AttributeUse> = ct.attributes.iter().filter(|a| !a.prohibited && schema.is_id(a.ty)).collect();
            if ids.len() > 1 {
                return Err(self.fail_at(ids[1].source, format!(
                    "ct-props-correct.5: Error for type '{}'. Two attribute declarations, '{}' and '{}' have types which are derived from ID.",
                    ct.name, ids[1].name.1, ids[0].name.1
                )));
            }
        }
        // Substitution groups (`e-props-correct.4`), the head named as the `substitutionGroup` attribute's prefix and
        // local name.
        let mut heads: Vec<(&ElemId, &Vec<ElemId>)> = schema.substitutes.iter().collect();
        heads.sort();
        for (head, members) in heads {
            for member in members {
                if !schema.derivation_ok(schema.elements[*member].ty, schema.elements[*head].ty, schema.elements[*head].final_) {
                    let source = schema.elements[*member].source;
                    let raw = self.node_at(source).and_then(|n| n.attribute("substitutionGroup")).unwrap_or_default();
                    let (prefix, local) = raw.trim().split_once(':').unwrap_or(("", raw.trim()));
                    return Err(self.fail_at(source, format!(
                        "e-props-correct.4: The {{type definition}} of element '{}' is not validly derived from the {{type definition}} of the substitutionHead '{prefix}:{local}', or the {{substitution group exclusions}} property of '{prefix}:{local}' does not allow this derivation.",
                        schema.elements[*member].name.1
                    )));
                }
            }
        }
        // Content models (`cos-element-consistent`, `cos-nonambig`), reported at the complex type.
        for (id, ty) in schema.types.iter().enumerate() {
            let Type::Complex(ct) = ty else { continue };
            let Content::Elements(model) = &ct.content else { continue };
            let at = |m: String| match self.type_nodes.get(&id) {
                Some(place) => self.fail_at(*place, m),
                None => m,
            };
            schema.element_consistent(&ct.name, model).map_err(at)?;
            schema.unique_particle_attribution(model).map_err(at)?;
        }
        Ok(())
    }
}

impl Schema {
    /// `checkNotationType`: the name (`null` when anonymous) of a NOTATION type `id` without an enumeration.
    fn notation_without_enumeration(&self, id: TypeId) -> Option<&str> {
        let Type::Simple(st) = &self.types[id] else { return None };
        if !matches!(st.variety, super::Variety::Atomic) || self.atomic_dv(id).0 != super::types::Dv::Notation || self.effective(id).0.enumeration.is_some() {
            return None;
        }
        Some(if st.name.is_empty() || st.name.starts_with("#AnonType_") { "null" } else { &st.name })
    }

    fn element_consistent(&self, owner: &str, model: &Expr) -> Result<(), String> {
        let mut leaves = Vec::new();
        collect_elements(model, &mut leaves);
        let mut seen: HashMap<&(String, String), ElemId> = HashMap::new();
        for id in leaves {
            let decl = &self.elements[id];
            match seen.get(&decl.name) {
                Some(other) => {
                    let first = &self.elements[*other];
                    if first.source != decl.source && first.ty != decl.ty {
                        return Err(format!(
                            "cos-element-consistent: Error for type '{owner}'. Multiple elements with name '{}', with different types, appear in the model group.",
                            decl.name.1
                        ));
                    }
                }
                None => {
                    seen.insert(&decl.name, id);
                }
            }
        }
        Ok(())
    }

    /// `XSConstraints.checkElementDeclsConsistent`'s sibling, `XSCMValidator.checkUniqueParticleAttribution`:
    /// explores the content model's states; two different particles that can take the same next element are an
    /// ambiguity.
    fn unique_particle_attribution(&self, model: &Expr) -> Result<(), String> {
        let mut leaves = Vec::new();
        let start = positions(model, &mut leaves);
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(state) = queue.pop_front() {
            if seen.len() > 2000 {
                break;
            }
            if !seen.insert(format!("{state:?}")) {
                continue;
            }
            let mut first = Vec::new();
            p_first(&state, &mut first);
            first.dedup();
            let mut distinct: Vec<usize> = Vec::new();
            for p in first {
                if !distinct.contains(&p) {
                    distinct.push(p);
                }
            }
            for (i, a) in distinct.iter().enumerate() {
                for b in &distinct[i + 1..] {
                    if self.overlap(&leaves[*a], &leaves[*b]) {
                        return Err(format!(
                            "cos-nonambig: {} and {} (or elements from their substitution group) violate \"Unique Particle Attribution\". During validation against this schema, ambiguity would be created for those two particles.",
                            self.leaf_text(&leaves[*a]),
                            self.leaf_text(&leaves[*b])
                        ));
                    }
                }
            }
            for p in distinct {
                let next = p_simplify(p_derive(&state, p));
                if !matches!(next, P::Fail) {
                    queue.push_back(next);
                }
            }
        }
        Ok(())
    }

    fn names_of(&self, id: ElemId) -> Vec<&(String, String)> {
        let mut out = vec![&self.elements[id].name];
        if let Some(members) = self.substitutes.get(&id) {
            out.extend(members.iter().map(|m| &self.elements[*m].name));
        }
        out
    }

    fn overlap(&self, a: &Leaf, b: &Leaf) -> bool {
        match (a, b) {
            (Leaf::Element(x), Leaf::Element(y)) => {
                let ys = self.names_of(*y);
                self.names_of(*x).iter().any(|n| ys.contains(n))
            }
            (Leaf::Element(x), Leaf::Any(w)) | (Leaf::Any(w), Leaf::Element(x)) => self.names_of(*x).iter().any(|n| w.allows(&n.0)),
            (Leaf::Any(v), Leaf::Any(w)) => wildcards_intersect(v, w),
        }
    }

    fn leaf_text(&self, leaf: &Leaf) -> String {
        match leaf {
            Leaf::Element(id) => self.elements[*id].name.1.clone(),
            Leaf::Any(w) => match &w.namespaces {
                None => "WC[##any]".into(),
                Some(list) if w.negated => format!("WC[##other:\"{}\"]", list.first().cloned().unwrap_or_default()),
                Some(list) => format!("WC[{}]", list.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(",")),
            },
        }
    }
}

fn wildcards_intersect(v: &Wildcard, w: &Wildcard) -> bool {
    match (&v.namespaces, &w.namespaces) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => match (v.negated, w.negated) {
            (false, false) => a.iter().any(|n| b.contains(n)),
            (false, true) => a.iter().any(|n| !b.contains(n)),
            (true, false) => b.iter().any(|n| !a.contains(n)),
            (true, true) => true,
        },
    }
}

fn collect_elements(e: &Expr, out: &mut Vec<ElemId>) {
    match e {
        Expr::Element(id) => out.push(*id),
        Expr::Sequence(items) | Expr::Choice(items) => items.iter().for_each(|i| collect_elements(i, out)),
        Expr::Repeat(inner, ..) => collect_elements(inner, out),
        Expr::All(members) => out.extend(members.iter().map(|(id, _)| *id)),
        Expr::Empty | Expr::Fail | Expr::Any(_) => {}
    }
}

#[derive(Debug, Clone)]
enum Leaf {
    Element(ElemId),
    Any(Wildcard),
}

/// A content model whose leaves are particle positions.
#[derive(Debug, Clone)]
enum P {
    Empty,
    Fail,
    Leaf(usize),
    Seq(Vec<P>),
    Choice(Vec<P>),
    Repeat(Box<P>, u32, Option<u32>),
    All(Vec<(usize, bool)>),
}

fn positions(e: &Expr, leaves: &mut Vec<Leaf>) -> P {
    let leaf = |l: Leaf, leaves: &mut Vec<Leaf>| {
        leaves.push(l);
        P::Leaf(leaves.len() - 1)
    };
    match e {
        Expr::Empty => P::Empty,
        Expr::Fail => P::Fail,
        Expr::Element(id) => leaf(Leaf::Element(*id), leaves),
        Expr::Any(w) => leaf(Leaf::Any((**w).clone()), leaves),
        Expr::Sequence(items) => P::Seq(items.iter().map(|i| positions(i, leaves)).collect()),
        Expr::Choice(items) => P::Choice(items.iter().map(|i| positions(i, leaves)).collect()),
        Expr::Repeat(inner, min, max) => P::Repeat(Box::new(positions(inner, leaves)), *min, *max),
        Expr::All(members) => P::All(
            members
                .iter()
                .map(|(id, required)| {
                    leaves.push(Leaf::Element(*id));
                    (leaves.len() - 1, *required)
                })
                .collect(),
        ),
    }
}

fn p_nullable(e: &P) -> bool {
    match e {
        P::Empty => true,
        P::Fail | P::Leaf(_) => false,
        P::Seq(items) => items.iter().all(p_nullable),
        P::Choice(items) => items.iter().any(p_nullable),
        P::Repeat(inner, min, _) => *min == 0 || p_nullable(inner),
        P::All(members) => members.iter().all(|(_, required)| !required),
    }
}

fn p_first(e: &P, out: &mut Vec<usize>) {
    match e {
        P::Empty | P::Fail => {}
        P::Leaf(p) => out.push(*p),
        P::Seq(items) => {
            for item in items {
                p_first(item, out);
                if !p_nullable(item) {
                    break;
                }
            }
        }
        P::Choice(items) => items.iter().for_each(|i| p_first(i, out)),
        P::Repeat(inner, _, max) => {
            if *max != Some(0) {
                p_first(inner, out);
            }
        }
        P::All(members) => out.extend(members.iter().map(|(p, _)| *p)),
    }
}

fn p_derive(e: &P, p: usize) -> P {
    match e {
        P::Empty | P::Fail => P::Fail,
        P::Leaf(q) => if *q == p { P::Empty } else { P::Fail },
        P::Seq(items) => {
            let Some((head, rest)) = items.split_first() else { return P::Fail };
            let mut through = vec![p_derive(head, p)];
            through.extend(rest.iter().cloned());
            let through = p_simplify(P::Seq(through));
            if p_nullable(head) { p_simplify(P::Choice(vec![through, p_derive(&P::Seq(rest.to_vec()), p)])) } else { through }
        }
        P::Choice(items) => p_simplify(P::Choice(items.iter().map(|i| p_derive(i, p)).collect())),
        P::Repeat(inner, min, max) => {
            if *max == Some(0) {
                return P::Fail;
            }
            let next = P::Repeat(inner.clone(), min.saturating_sub(1), max.map(|m| m - 1));
            p_simplify(P::Seq(vec![p_derive(inner, p), next]))
        }
        P::All(members) => match members.iter().position(|(q, _)| *q == p) {
            Some(i) => {
                let mut rest = members.clone();
                rest.remove(i);
                P::All(rest)
            }
            None => P::Fail,
        },
    }
}

fn p_simplify(e: P) -> P {
    match e {
        P::Seq(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    P::Fail => return P::Fail,
                    P::Empty => {}
                    P::Seq(inner) => out.extend(inner),
                    other => out.push(other),
                }
            }
            match out.len() {
                0 => P::Empty,
                1 => out.pop().expect("one"),
                _ => P::Seq(out),
            }
        }
        P::Choice(items) => {
            let mut out: Vec<P> = Vec::new();
            for item in items {
                if matches!(item, P::Fail) {
                    continue;
                }
                let text = format!("{item:?}");
                if !out.iter().any(|o| format!("{o:?}") == text) {
                    out.push(item);
                }
            }
            match out.len() {
                0 => P::Fail,
                1 => out.pop().expect("one"),
                _ => P::Choice(out),
            }
        }
        P::Repeat(_, _, Some(0)) => P::Empty,
        other => other,
    }
}
