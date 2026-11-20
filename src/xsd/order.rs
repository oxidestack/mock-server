//! Xerces' traversal order (`XSDHandler.traverseSchemas`), walked over the schema documents to find the first
//! reference into a namespace without a loaded grammar that has not been reported yet: the one `src-resolve`
//! names. Global components are traversed in document order, each one when first referenced; local element
//! declarations are deferred to the end (`traverseLocalElements`), keyref `refer`s after them (`resolveKeyRefs`).
//! The builder resolves references in an order of its own; only this one decides which unloaded namespace is
//! reported.

use std::collections::HashSet;

use roxmltree::Node;

use super::{Builder, Kind, Unloaded, Walk, XS, is_xs, xs_children};

struct Order<'a, 'input> {
    visited: HashSet<(usize, usize)>,
    deferred: Vec<(Node<'a, 'input>, usize)>,
    refers: Vec<(Node<'a, 'input>, usize)>,
}

/// Goes on with the walk unless `walk` ended it.
macro_rules! walk {
    ($e:expr) => {
        match $e {
            Walk::Next => {}
            other => return other,
        }
    };
}

impl<'a, 'input> Builder<'a, 'input> {
    /// The name messages give a component kind.
    pub(super) fn static_what(what: &str) -> &'static str {
        match what {
            "type definition" => "type definition",
            "element declaration" => "element declaration",
            "attribute declaration" => "attribute declaration",
            "attribute group" => "attribute group",
            "group" => "group",
            "notation" => "notation",
            _ => "identity constraint",
        }
    }

    /// The first reference Xerces' traversal meets into a namespace without a grammar, not reported yet; `None`
    /// when there is none, or when it meets another unresolvable reference first.
    pub(super) fn xerces_first_unloaded(&self) -> Option<Unloaded> {
        let mut order = Order { visited: HashSet::new(), deferred: Vec::new(), refers: Vec::new() };
        let walked = (|| {
            for (doc, (root, ..)) in self.roots.iter().enumerate() {
                for child in xs_children(*root) {
                    if is_xs(&child, "redefine") {
                        for component in xs_children(child) {
                            walk!(self.walk_global(&mut order, component, doc));
                        }
                    } else {
                        walk!(self.walk_global(&mut order, child, doc));
                    }
                }
            }
            let mut i = 0;
            while i < order.deferred.len() {
                let (element, doc) = order.deferred[i];
                walk!(self.walk_element(&mut order, element, doc, false));
                i += 1;
            }
            for (keyref, doc) in std::mem::take(&mut order.refers) {
                if let Some(refer) = keyref.attribute("refer") {
                    walk!(self.walk_reference(&mut order, keyref, doc, refer, None, "identity constraint"));
                }
            }
            Walk::Next
        })();
        match walked {
            Walk::Found(first) => Some(first),
            _ => None,
        }
    }

    fn walk_global(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        if !order.visited.insert((doc, node.range().start)) {
            return Walk::Next;
        }
        match node.tag_name().name() {
            "element" => self.walk_element(order, node, doc, true),
            "complexType" => self.walk_complex(order, node, doc),
            "simpleType" => self.walk_simple(order, node, doc),
            "attribute" => self.walk_attribute(order, node, doc),
            "group" => match xs_children(node).next() {
                Some(model) => self.walk_particle(order, model, doc),
                None => Walk::Next,
            },
            "attributeGroup" => self.walk_attributes(order, node, doc),
            _ => Walk::Next,
        }
    }

    /// A QName reference to a component of `kind` (`None`: an identity constraint, never traversed from here).
    fn walk_reference(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize, value: &str, kind: Option<Kind>, what: &str) -> Walk {
        let Ok(name) = self.resolve(node, doc, value) else { return Walk::Stop };
        if kind == Some(Kind::Type) && name.0 == XS && self.schema.global_types.contains_key(&name) {
            return Walk::Next;
        }
        if !self.allowed[doc].contains(&name.0) {
            return Walk::Stop;
        }
        if !self.grammars.contains(&name.0) {
            if self.reported.contains(&name.0) {
                return Walk::Next;
            }
            return Walk::Found(Unloaded { place: (doc, node.range().start), value: value.to_string(), what: Self::static_what(what), namespace: name.0 });
        }
        let Some(kind) = kind else { return Walk::Next };
        match self.components.get(&(kind, name)) {
            Some(&(decl, decl_doc)) => self.walk_global(order, decl, decl_doc),
            None => Walk::Stop,
        }
    }

    /// `XSDElementTraverser.traverseNamedElement` (or a reference): substitution group, type, identity constraints.
    fn walk_element(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize, global: bool) -> Walk {
        if let Some(reference) = node.attribute("ref").filter(|_| !global) {
            return self.walk_reference(order, node, doc, reference, Some(Kind::Element), "element declaration");
        }
        if let Some(head) = node.attribute("substitutionGroup").filter(|_| global) {
            walk!(self.walk_reference(order, node, doc, head, Some(Kind::Element), "element declaration"));
        }
        match xs_children(node).find(|c| matches!(c.tag_name().name(), "complexType" | "simpleType")) {
            Some(inline) if inline.tag_name().name() == "complexType" => walk!(self.walk_complex(order, inline, doc)),
            Some(inline) => walk!(self.walk_simple(order, inline, doc)),
            None => {
                if let Some(ty) = node.attribute("type") {
                    walk!(self.walk_reference(order, node, doc, ty, Some(Kind::Type), "type definition"));
                }
            }
        }
        order.refers.extend(xs_children(node).filter(|c| c.tag_name().name() == "keyref").map(|k| (k, doc)));
        Walk::Next
    }

    /// `XSDComplexTypeTraverser`: the derivation's base, then the particle, then the attributes.
    fn walk_complex(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        for child in xs_children(node) {
            match child.tag_name().name() {
                "simpleContent" | "complexContent" => {
                    let Some(def) = xs_children(child).next() else { continue };
                    if let Some(base) = def.attribute("base") {
                        walk!(self.walk_reference(order, def, doc, base, Some(Kind::Type), "type definition"));
                    }
                    for part in xs_children(def) {
                        match part.tag_name().name() {
                            "simpleType" => walk!(self.walk_simple(order, part, doc)),
                            "sequence" | "choice" | "all" | "group" => walk!(self.walk_particle(order, part, doc)),
                            _ => {}
                        }
                    }
                    walk!(self.walk_attributes(order, def, doc));
                }
                "sequence" | "choice" | "all" | "group" => walk!(self.walk_particle(order, child, doc)),
                _ => {}
            }
        }
        self.walk_attributes(order, node, doc)
    }

    /// A particle: local elements are deferred; a group reference traverses the group.
    fn walk_particle(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        match node.tag_name().name() {
            "element" => order.deferred.push((node, doc)),
            "group" => {
                if let Some(reference) = node.attribute("ref") {
                    return self.walk_reference(order, node, doc, reference, Some(Kind::Group), "group");
                }
            }
            "sequence" | "choice" | "all" => {
                for child in xs_children(node) {
                    walk!(self.walk_particle(order, child, doc));
                }
            }
            _ => {}
        }
        Walk::Next
    }

    /// `traverseAttrsAndAttrGrps` over `node`'s children.
    fn walk_attributes(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        for child in xs_children(node) {
            match child.tag_name().name() {
                "attribute" => walk!(self.walk_attribute(order, child, doc)),
                "attributeGroup" => {
                    if let Some(reference) = child.attribute("ref") {
                        walk!(self.walk_reference(order, child, doc, reference, Some(Kind::AttributeGroup), "attribute group"));
                    }
                }
                _ => {}
            }
        }
        Walk::Next
    }

    fn walk_attribute(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        if let Some(reference) = node.attribute("ref") {
            return self.walk_reference(order, node, doc, reference, Some(Kind::Attribute), "attribute declaration");
        }
        match xs_children(node).find(|c| c.tag_name().name() == "simpleType") {
            Some(inline) => self.walk_simple(order, inline, doc),
            None => match node.attribute("type") {
                Some(ty) => self.walk_reference(order, node, doc, ty, Some(Kind::Type), "type definition"),
                None => Walk::Next,
            },
        }
    }

    /// `XSDSimpleTypeTraverser`: base, item or member types, then a NOTATION restriction's enumerations.
    fn walk_simple(&self, order: &mut Order<'a, 'input>, node: Node<'a, 'input>, doc: usize) -> Walk {
        let Some(def) = xs_children(node).next() else { return Walk::Next };
        match def.tag_name().name() {
            "restriction" => {
                match def.attribute("base") {
                    Some(base) => walk!(self.walk_reference(order, def, doc, base, Some(Kind::Type), "type definition")),
                    None => {
                        if let Some(inline) = xs_children(def).find(|c| c.tag_name().name() == "simpleType") {
                            walk!(self.walk_simple(order, inline, doc));
                        }
                    }
                }
                if self.restricts_notation(def, doc, 0) {
                    for enumeration in xs_children(def).filter(|c| c.tag_name().name() == "enumeration") {
                        let value = enumeration.attribute("value").unwrap_or_default().trim();
                        walk!(self.walk_reference(order, enumeration, doc, value, Some(Kind::Notation), "notation"));
                    }
                }
            }
            "list" => match def.attribute("itemType") {
                Some(item) => walk!(self.walk_reference(order, def, doc, item, Some(Kind::Type), "type definition")),
                None => {
                    if let Some(inline) = xs_children(def).next() {
                        walk!(self.walk_simple(order, inline, doc));
                    }
                }
            },
            "union" => {
                for member in def.attribute("memberTypes").unwrap_or_default().split_whitespace() {
                    walk!(self.walk_reference(order, def, doc, member, Some(Kind::Type), "type definition"));
                }
                for inline in xs_children(def).filter(|c| c.tag_name().name() == "simpleType") {
                    walk!(self.walk_simple(order, inline, doc));
                }
            }
            _ => {}
        }
        Walk::Next
    }

    /// Whether the restriction `def` derives (through named simple types) from `xs:NOTATION`.
    pub(super) fn restricts_notation(&self, def: Node<'a, 'input>, doc: usize, depth: usize) -> bool {
        if depth > 64 {
            return false;
        }
        let base = match def.attribute("base") {
            Some(base) => base,
            None => {
                return xs_children(def)
                    .find(|c| c.tag_name().name() == "simpleType")
                    .and_then(|inline| xs_children(inline).next())
                    .is_some_and(|inner| inner.tag_name().name() == "restriction" && self.restricts_notation(inner, doc, depth + 1));
            }
        };
        let Ok(name) = self.resolve(def, doc, base) else { return false };
        if name.0 == XS {
            return name.1 == "NOTATION";
        }
        let Some(&(decl, decl_doc)) = self.components.get(&(Kind::Type, name)) else { return false };
        decl.tag_name().name() == "simpleType"
            && xs_children(decl).next().is_some_and(|inner| inner.tag_name().name() == "restriction" && self.restricts_notation(inner, decl_doc, depth + 1))
    }
}
