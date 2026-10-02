//! Canonical XML 1.0 (<https://www.w3.org/TR/2001/REC-xml-c14n-20010315>,
//! with and without comments) and Exclusive XML Canonicalization 1.0
//! (<https://www.w3.org/TR/xml-exc-c14n/>, without an `InclusiveNamespaces`
//! prefix list).
//!
//! The node-set is described as a subtree root (the document node or an
//! element), an optional excluded subtree (the enveloped-signature
//! transform) and whether comments are part of the set.

use crate::dom::{Attr, Document, NodeId, NodeKind, NsBinding, XML_NS};

/// Canonicalization algorithm URIs.
pub mod uri {
    /// Canonical XML 1.0 without comments.
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /// Canonical XML 1.0 with comments.
    pub const C14N_WITH_COMMENTS: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    /// Exclusive XML Canonicalization 1.0 without comments.
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    /// Exclusive XML Canonicalization 1.0 with comments.
    pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
}

/// A canonicalization method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    /// Exclusive (`xml-exc-c14n`) instead of inclusive Canonical XML 1.0.
    pub exclusive: bool,
    /// Keep comments.
    pub with_comments: bool,
}

impl Method {
    /// Inclusive Canonical XML 1.0 without comments.
    pub const INCLUSIVE: Method = Method {
        exclusive: false,
        with_comments: false,
    };
    /// Inclusive Canonical XML 1.0 with comments.
    pub const INCLUSIVE_WITH_COMMENTS: Method = Method {
        exclusive: false,
        with_comments: true,
    };
    /// Exclusive XML Canonicalization 1.0 without comments.
    pub const EXCLUSIVE: Method = Method {
        exclusive: true,
        with_comments: false,
    };
    /// Exclusive XML Canonicalization 1.0 with comments.
    pub const EXCLUSIVE_WITH_COMMENTS: Method = Method {
        exclusive: true,
        with_comments: true,
    };

    /// Method by its algorithm URI.
    pub fn from_uri(u: &str) -> Option<Method> {
        Some(match u {
            uri::C14N => Method::INCLUSIVE,
            uri::C14N_WITH_COMMENTS => Method::INCLUSIVE_WITH_COMMENTS,
            uri::EXC_C14N => Method::EXCLUSIVE,
            uri::EXC_C14N_WITH_COMMENTS => Method::EXCLUSIVE_WITH_COMMENTS,
            _ => return None,
        })
    }

    /// Algorithm URI of the method.
    pub fn uri(self) -> &'static str {
        match (self.exclusive, self.with_comments) {
            (false, false) => uri::C14N,
            (false, true) => uri::C14N_WITH_COMMENTS,
            (true, false) => uri::EXC_C14N,
            (true, true) => uri::EXC_C14N_WITH_COMMENTS,
        }
    }
}

/// Canonicalize the subtree rooted at `root` (the document node or an
/// element), leaving out the subtree rooted at `exclude` (if any) and,
/// unless the method keeps them, all comments.
pub fn canonicalize(
    doc: &Document,
    root: NodeId,
    exclude: Option<NodeId>,
    method: Method,
) -> Vec<u8> {
    let mut c = Canon {
        doc,
        exclude,
        method,
        out: String::new(),
    };
    match &doc.nodes[root].kind {
        NodeKind::Document => c.document(root),
        _ => c.node(root, &[], true),
    }
    c.out.into_bytes()
}

/// Canonicalize a whole document parsed from `xml`.
pub fn canonicalize_str(xml: &str, method: Method) -> crate::Result<Vec<u8>> {
    let doc = Document::parse(xml)?;
    Ok(canonicalize(&doc, 0, None, method))
}

struct Canon<'a> {
    doc: &'a Document,
    exclude: Option<NodeId>,
    method: Method,
    out: String,
}

impl Canon<'_> {
    fn document(&mut self, root: NodeId) {
        let children = &self.doc.nodes[root].children;
        let root_el = children.iter().position(|&c| self.doc.is_element(c));
        for (i, &c) in children.iter().enumerate() {
            let rendered = match &self.doc.nodes[c].kind {
                NodeKind::Comment(_) => self.method.with_comments,
                NodeKind::Pi { .. } => true,
                NodeKind::Element { .. } => true,
                _ => false, // whitespace outside the root element is not part of the data model
            };
            if !rendered || Some(c) == self.exclude {
                continue;
            }
            let after_root = root_el.is_some_and(|r| i > r);
            if after_root {
                self.out.push('\n');
            }
            self.node(c, &[], false);
            if root_el.is_some_and(|r| i < r) {
                self.out.push('\n');
            }
        }
    }

    /// `ancestor_ns`: for inclusive C14N, the namespace axis of the nearest
    /// output ancestor element (empty for the apex); for exclusive C14N, the
    /// namespaces rendered by output ancestors (later entries shadow
    /// earlier ones).  `apex` marks the subtree root when it is an element
    /// whose ancestors are outside the node-set.
    fn node(&mut self, id: NodeId, ancestor_ns: &[NsBinding], apex: bool) {
        if Some(id) == self.exclude {
            return;
        }
        match &self.doc.nodes[id].kind {
            NodeKind::Document => {}
            NodeKind::Text(t) => escape_text(t, &mut self.out),
            NodeKind::Comment(c) => {
                if self.method.with_comments {
                    self.out.push_str("<!--");
                    self.out.push_str(c);
                    self.out.push_str("-->");
                }
            }
            NodeKind::Pi { target, data } => {
                self.out.push_str("<?");
                self.out.push_str(target);
                if let Some(d) = data.as_deref().filter(|d| !d.is_empty()) {
                    self.out.push(' ');
                    self.out.push_str(d);
                }
                self.out.push_str("?>");
            }
            NodeKind::Element {
                prefix,
                local,
                attrs,
                in_scope,
                ..
            } => {
                let name = crate::dom::qname(prefix.as_deref(), local);

                // Namespace nodes to render.
                let mut ns_out: Vec<NsBinding> = Vec::new();
                if self.method.exclusive {
                    let mut used: Vec<Option<&str>> = vec![prefix.as_deref()];
                    for a in attrs {
                        if let Some(p) = a.prefix.as_deref() {
                            if p != "xml" && !used.contains(&Some(p)) {
                                used.push(Some(p));
                            }
                        }
                    }
                    for p in used {
                        let uri = lookup(in_scope, p).unwrap_or("");
                        if p.is_none() && uri.is_empty() {
                            // xmlns="" only if an output ancestor rendered a default namespace
                            if !lookup(ancestor_ns, None).unwrap_or("").is_empty() {
                                ns_out.push((None, String::new()));
                            }
                        } else if lookup(ancestor_ns, p) != Some(uri) {
                            ns_out.push((p.map(str::to_string), uri.to_string()));
                        }
                    }
                } else {
                    for (p, u) in in_scope {
                        if p.is_none() && u.is_empty() {
                            continue; // handled below
                        }
                        if lookup(ancestor_ns, p.as_deref()) != Some(u.as_str()) {
                            ns_out.push((p.clone(), u.clone()));
                        }
                    }
                    if lookup(in_scope, None).unwrap_or("").is_empty()
                        && !lookup(ancestor_ns, None).unwrap_or("").is_empty()
                    {
                        ns_out.push((None, String::new()));
                    }
                }
                ns_out.sort();

                // Attributes, plus inherited xml:* ones on an inclusive apex.
                let mut attr_out: Vec<&Attr> = attrs.iter().collect();
                let inherited;
                if apex && !self.method.exclusive {
                    inherited = self.inherited_xml_attrs(id);
                    attr_out.extend(inherited.iter());
                }
                attr_out.sort_by(|a, b| {
                    (a.uri.as_deref().unwrap_or(""), &a.local)
                        .cmp(&(b.uri.as_deref().unwrap_or(""), &b.local))
                });

                self.out.push('<');
                self.out.push_str(&name);
                for (p, u) in &ns_out {
                    self.out.push(' ');
                    match p {
                        Some(p) => {
                            self.out.push_str("xmlns:");
                            self.out.push_str(p);
                        }
                        None => self.out.push_str("xmlns"),
                    }
                    self.out.push_str("=\"");
                    escape_attr(u, &mut self.out);
                    self.out.push('"');
                }
                for a in &attr_out {
                    self.out.push(' ');
                    self.out.push_str(&a.qname());
                    self.out.push_str("=\"");
                    escape_attr(&a.value, &mut self.out);
                    self.out.push('"');
                }
                self.out.push('>');

                let child_ns: Vec<NsBinding> = if self.method.exclusive {
                    let mut v = ancestor_ns.to_vec();
                    v.extend(ns_out);
                    v
                } else {
                    in_scope.clone()
                };
                for &c in &self.doc.nodes[id].children {
                    self.node(c, &child_ns, false);
                }

                self.out.push_str("</");
                self.out.push_str(&name);
                self.out.push('>');
            }
        }
    }

    /// `xml:*` attributes of ancestors (nearest wins) that the element does
    /// not carry itself.
    fn inherited_xml_attrs(&self, id: NodeId) -> Vec<Attr> {
        let mut out: Vec<Attr> = Vec::new();
        let own = self.doc.attrs(id);
        let mut cur = self.doc.nodes[id].parent;
        while let Some(p) = cur {
            for a in self.doc.attrs(p) {
                if a.uri.as_deref() == Some(XML_NS)
                    && !own.iter().any(|o| o.local == a.local && o.uri == a.uri)
                    && !out.iter().any(|o| o.local == a.local)
                {
                    out.push(a.clone());
                }
            }
            cur = self.doc.nodes[p].parent;
        }
        out
    }
}

/// Value bound to `prefix` by the latest entry of `ns`.
fn lookup<'a>(ns: &'a [NsBinding], prefix: Option<&str>) -> Option<&'a str> {
    ns.iter()
        .rev()
        .find(|(p, _)| p.as_deref() == prefix)
        .map(|(_, u)| u.as_str())
}

/// Text node escaping of Canonical XML (§2.3): `&`, `<`, `>` and CR.
pub fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Attribute value escaping of Canonical XML (§2.3): `&`, `<`, `"`, TAB, LF, CR.
pub fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}
