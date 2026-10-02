//! A small mutable DOM that keeps everything canonicalization needs:
//! comments, processing instructions, whitespace text, the original
//! namespace prefixes and every in-scope namespace of every element.
//!
//! Documents are parsed with `roxmltree` and copied into an arena; the
//! source text is kept so that a signature can be spliced into it without
//! re-serializing (and thus altering) the caller's XML.

use std::ops::Range;

use crate::error::{Error, Result};

/// Index of a node in the arena.
pub type NodeId = usize;

/// The XML namespace (`xml:` prefix).
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A namespace binding: `(prefix, uri)`; `None` is the default namespace.
pub type NsBinding = (Option<String>, String);

/// An attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// Prefix as written in the document.
    pub prefix: Option<String>,
    /// Local name.
    pub local: String,
    /// Namespace URI (`None` for unprefixed attributes).
    pub uri: Option<String>,
    /// Normalized value.
    pub value: String,
}

impl Attr {
    /// Qualified name as written (`prefix:local` or `local`).
    pub fn qname(&self) -> String {
        qname(self.prefix.as_deref(), &self.local)
    }
}

/// Node payload.
#[derive(Debug, Clone)]
pub enum NodeKind {
    /// The document node (arena index 0).
    Document,
    /// An element.
    Element {
        /// Prefix as written in the document.
        prefix: Option<String>,
        /// Local name.
        local: String,
        /// Namespace URI of the element name.
        uri: Option<String>,
        /// Attributes in document order (namespace declarations excluded).
        attrs: Vec<Attr>,
        /// Namespace declarations made on this element (for serialization).
        decls: Vec<NsBinding>,
        /// Every namespace in scope on this element, `xml` excluded; an
        /// undeclared default namespace is `(None, "")`.
        in_scope: Vec<NsBinding>,
    },
    /// Character data (entity references already expanded).
    Text(String),
    /// A comment.
    Comment(String),
    /// A processing instruction.
    Pi {
        /// Target.
        target: String,
        /// Data, if any.
        data: Option<String>,
    },
}

/// An arena node.
#[derive(Debug, Clone)]
pub struct Node {
    /// Payload.
    pub kind: NodeKind,
    /// Parent (`None` for the document node).
    pub parent: Option<NodeId>,
    /// Children in document order.
    pub children: Vec<NodeId>,
    /// Byte range in the source text, when the node came from the parser.
    pub range: Option<Range<usize>>,
}

/// A parsed document plus its source text.
#[derive(Debug, Clone)]
pub struct Document {
    /// Arena; index 0 is the document node.
    pub nodes: Vec<Node>,
    /// Source text the document was parsed from.
    pub source: String,
}

/// Build `prefix:local`.
pub fn qname(prefix: Option<&str>, local: &str) -> String {
    match prefix {
        Some(p) => format!("{p}:{local}"),
        None => local.to_string(),
    }
}

impl Document {
    /// Parse a document.  Comments, PIs and whitespace are kept; the XML
    /// declaration and DOCTYPE are dropped (they never take part in C14N).
    pub fn parse(xml: &str) -> Result<Self> {
        let rox = roxmltree::Document::parse_with_options(
            xml,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )?;
        let mut doc = Document {
            nodes: vec![Node {
                kind: NodeKind::Document,
                parent: None,
                children: Vec::new(),
                range: None,
            }],
            source: xml.to_string(),
        };
        for child in rox.root().children() {
            doc.import(child, 0, &[])?;
        }
        Ok(doc)
    }

    fn import(
        &mut self,
        n: roxmltree::Node<'_, '_>,
        parent: NodeId,
        parent_scope: &[NsBinding],
    ) -> Result<()> {
        let range = Some(n.range());
        let kind = match n.node_type() {
            roxmltree::NodeType::Root => return Ok(()),
            roxmltree::NodeType::Text => NodeKind::Text(n.text().unwrap_or("").to_string()),
            roxmltree::NodeType::Comment => NodeKind::Comment(n.text().unwrap_or("").to_string()),
            roxmltree::NodeType::PI => {
                let pi = n
                    .pi()
                    .ok_or_else(|| Error::Structure("PI without payload".into()))?;
                NodeKind::Pi {
                    target: pi.target.to_string(),
                    data: pi.value.map(str::to_string),
                }
            }
            roxmltree::NodeType::Element => {
                let (prefix, local) = split_qname(tag_qname(&self.source, n.range().start));
                let uri = n.tag_name().namespace().map(str::to_string);
                let mut in_scope: Vec<NsBinding> = n
                    .namespaces()
                    .filter(|ns| ns.name() != Some("xml"))
                    .map(|ns| (ns.name().map(str::to_string), ns.uri().to_string()))
                    .collect();
                in_scope.sort();
                let decls = in_scope
                    .iter()
                    .filter(|b| !parent_scope.contains(b))
                    .filter(|b| {
                        !(b.0.is_none()
                            && b.1.is_empty()
                            && !parent_scope
                                .iter()
                                .any(|p| p.0.is_none() && !p.1.is_empty()))
                    })
                    .cloned()
                    .collect();
                let attrs = n
                    .attributes()
                    .map(|a| {
                        let (prefix, local) = split_qname(&self.source[a.range_qname()]);
                        Attr {
                            prefix,
                            local,
                            uri: a.namespace().map(str::to_string),
                            value: a.value().to_string(),
                        }
                    })
                    .collect();
                NodeKind::Element {
                    prefix,
                    local,
                    uri,
                    attrs,
                    decls,
                    in_scope,
                }
            }
        };
        let id = self.push(kind, parent, range);
        if n.is_element() {
            let scope = self.in_scope(id).to_vec();
            for c in n.children() {
                self.import(c, id, &scope)?;
            }
        }
        Ok(())
    }

    fn push(&mut self, kind: NodeKind, parent: NodeId, range: Option<Range<usize>>) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node {
            kind,
            parent: Some(parent),
            children: Vec::new(),
            range,
        });
        self.nodes[parent].children.push(id);
        id
    }

    /// The root element.
    pub fn root_element(&self) -> Result<NodeId> {
        self.nodes[0]
            .children
            .iter()
            .copied()
            .find(|&c| self.is_element(c))
            .ok_or_else(|| Error::Structure("no root element".into()))
    }

    /// Whether `id` is an element.
    pub fn is_element(&self, id: NodeId) -> bool {
        matches!(self.nodes[id].kind, NodeKind::Element { .. })
    }

    /// In-scope namespaces of an element (empty for other nodes).
    pub fn in_scope(&self, id: NodeId) -> &[NsBinding] {
        match &self.nodes[id].kind {
            NodeKind::Element { in_scope, .. } => in_scope,
            _ => &[],
        }
    }

    /// Element name as `(prefix, local, uri)`.
    pub fn name(&self, id: NodeId) -> Option<(Option<&str>, &str, Option<&str>)> {
        match &self.nodes[id].kind {
            NodeKind::Element {
                prefix, local, uri, ..
            } => Some((prefix.as_deref(), local, uri.as_deref())),
            _ => None,
        }
    }

    /// Attributes of an element (empty for other nodes).
    pub fn attrs(&self, id: NodeId) -> &[Attr] {
        match &self.nodes[id].kind {
            NodeKind::Element { attrs, .. } => attrs,
            _ => &[],
        }
    }

    /// Value of an unprefixed attribute.
    pub fn attr(&self, id: NodeId, local: &str) -> Option<&str> {
        self.attrs(id)
            .iter()
            .find(|a| a.uri.is_none() && a.local == local)
            .map(|a| a.value.as_str())
    }

    /// Concatenated text of the direct text children.
    pub fn text(&self, id: NodeId) -> String {
        let mut s = String::new();
        for &c in &self.nodes[id].children {
            if let NodeKind::Text(t) = &self.nodes[c].kind {
                s.push_str(t);
            }
        }
        s
    }

    /// Whether `ancestor` is `id` or one of its ancestors.
    pub fn is_descendant_or_self(&self, id: NodeId, ancestor: NodeId) -> bool {
        let mut cur = Some(id);
        while let Some(c) = cur {
            if c == ancestor {
                return true;
            }
            cur = self.nodes[c].parent;
        }
        false
    }

    /// Element children matching `(uri, local)`.
    pub fn elements(&self, id: NodeId, uri: Option<&str>, local: &str) -> Vec<NodeId> {
        self.nodes[id]
            .children
            .iter()
            .copied()
            .filter(|&c| self.name(c).is_some_and(|(_, l, u)| l == local && u == uri))
            .collect()
    }

    /// First element child matching `(uri, local)`.
    pub fn element(&self, id: NodeId, uri: Option<&str>, local: &str) -> Option<NodeId> {
        self.elements(id, uri, local).into_iter().next()
    }

    /// Every element of the document (document order) matching `(uri, local)`.
    pub fn descendants_named(&self, uri: Option<&str>, local: &str) -> Vec<NodeId> {
        let mut out = Vec::new();
        self.walk(0, &mut |d, id| {
            if d.name(id).is_some_and(|(_, l, u)| l == local && u == uri) {
                out.push(id);
            }
        });
        out
    }

    fn walk(&self, id: NodeId, f: &mut dyn FnMut(&Document, NodeId)) {
        f(self, id);
        for &c in &self.nodes[id].children {
            self.walk(c, f);
        }
    }

    /// Find the element whose attribute `Id` (also accepted: `ID`, `id`)
    /// equals `value`.
    pub fn element_by_id(&self, value: &str) -> Option<NodeId> {
        for name in ["Id", "ID", "id"] {
            let mut found = None;
            self.walk(0, &mut |d, id| {
                if found.is_none() && d.attr(id, name) == Some(value) {
                    found = Some(id);
                }
            });
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// Resolve a restricted absolute XPath: `/root/a` or `/root/a[2]`,
    /// matched by the qualified name as written.  Unindexed steps take the
    /// first matching child.
    pub fn select(&self, xpath: &str) -> Result<NodeId> {
        let path = xpath.trim();
        let rest = path
            .strip_prefix('/')
            .ok_or_else(|| Error::XPathUnsupported(xpath.into()))?;
        if rest.is_empty() || rest.starts_with('/') {
            return Err(Error::XPathUnsupported(xpath.into()));
        }
        let mut cur = 0;
        for step in rest.split('/') {
            let (name, index) = match step.split_once('[') {
                Some((n, i)) => {
                    let i = i
                        .strip_suffix(']')
                        .and_then(|i| i.trim().parse::<usize>().ok())
                        .filter(|&i| i >= 1)
                        .ok_or_else(|| Error::XPathUnsupported(xpath.into()))?;
                    (n.trim(), i)
                }
                None => (step.trim(), 1),
            };
            if name.is_empty()
                || name.contains(|c: char| {
                    !(c.is_alphanumeric() || matches!(c, ':' | '_' | '-' | '.'))
                })
            {
                return Err(Error::XPathUnsupported(xpath.into()));
            }
            cur = self.nodes[cur]
                .children
                .iter()
                .copied()
                .filter(|&c| self.name(c).is_some_and(|(p, l, _)| qname(p, l) == name))
                .nth(index - 1)
                .ok_or_else(|| Error::XPathNoMatch(xpath.into()))?;
        }
        Ok(cur)
    }

    /// Append a new element (not backed by the source text).
    pub fn append_element(
        &mut self,
        parent: NodeId,
        prefix: Option<&str>,
        local: &str,
        decls: &[NsBinding],
        attrs: Vec<Attr>,
    ) -> NodeId {
        let mut in_scope: Vec<NsBinding> = self
            .in_scope(parent)
            .iter()
            .filter(|b| !decls.iter().any(|d| d.0 == b.0))
            .cloned()
            .collect();
        in_scope.extend(decls.iter().cloned());
        in_scope.sort();
        let uri = prefix
            .and_then(|p| in_scope.iter().find(|b| b.0.as_deref() == Some(p)))
            .or_else(|| in_scope.iter().find(|b| b.0.is_none() && !b.1.is_empty()))
            .map(|b| b.1.clone());
        self.push(
            NodeKind::Element {
                prefix: prefix.map(str::to_string),
                local: local.to_string(),
                uri,
                attrs,
                decls: decls.to_vec(),
                in_scope,
            },
            parent,
            None,
        )
    }

    /// Append a text node.
    pub fn append_text(&mut self, parent: NodeId, text: &str) -> NodeId {
        self.push(NodeKind::Text(text.to_string()), parent, None)
    }

    /// Replace the text content of an element with a single text node.
    pub fn set_text(&mut self, id: NodeId, text: &str) {
        let old = std::mem::take(&mut self.nodes[id].children);
        for c in old {
            self.nodes[c].parent = None;
        }
        self.append_text(id, text);
    }

    /// Serialize a subtree (used for the signature element, which is built
    /// by this crate and therefore round-trips exactly).
    pub fn serialize(&self, id: NodeId, out: &mut String) {
        match &self.nodes[id].kind {
            NodeKind::Document => {
                for &c in &self.nodes[id].children {
                    self.serialize(c, out);
                }
            }
            NodeKind::Element {
                prefix,
                local,
                attrs,
                decls,
                ..
            } => {
                out.push('<');
                let name = qname(prefix.as_deref(), local);
                out.push_str(&name);
                for (p, u) in decls {
                    out.push(' ');
                    match p {
                        Some(p) => out.push_str(&format!("xmlns:{p}")),
                        None => out.push_str("xmlns"),
                    }
                    out.push_str("=\"");
                    escape_attr(u, out);
                    out.push('"');
                }
                for a in attrs {
                    out.push(' ');
                    out.push_str(&a.qname());
                    out.push_str("=\"");
                    escape_attr(&a.value, out);
                    out.push('"');
                }
                if self.nodes[id].children.is_empty() {
                    out.push_str("/>");
                } else {
                    out.push('>');
                    for &c in &self.nodes[id].children {
                        self.serialize(c, out);
                    }
                    out.push_str("</");
                    out.push_str(&name);
                    out.push('>');
                }
            }
            NodeKind::Text(t) => escape_text(t, out),
            NodeKind::Comment(c) => {
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->");
            }
            NodeKind::Pi { target, data } => {
                out.push_str("<?");
                out.push_str(target);
                if let Some(d) = data {
                    out.push(' ');
                    out.push_str(d);
                }
                out.push_str("?>");
            }
        }
    }

    /// Insert `text` into the source so that it becomes the last child of
    /// the source-backed element `parent`.
    pub fn splice_into(&self, parent: NodeId, text: &str) -> Result<String> {
        let range = self.nodes[parent]
            .range
            .clone()
            .ok_or_else(|| Error::Structure("parent element is not source-backed".into()))?;
        let src = &self.source;
        let elem = &src[range.clone()];
        let no_src_children = !self.nodes[parent]
            .children
            .iter()
            .any(|&c| self.nodes[c].range.is_some());
        // Like Santuario/DOM serialisation, the output starts at the first node after the
        // XML declaration: portals embed the signed document into their own XML, where a
        // declaration in the middle is a parse error ("ЭЦП недействительна" on egov.kz).
        let prolog_end = prolog_end(src);
        let mut out = String::with_capacity(src.len() + text.len() + 16);
        if no_src_children && elem.ends_with("/>") && !elem.contains("</") {
            // `<a .../>` → `<a ...>text</a>`
            out.push_str(&src[prolog_end..range.end - 2]);
            out.push('>');
            out.push_str(text);
            out.push_str("</");
            out.push_str(tag_qname(src, range.start));
            out.push('>');
        } else {
            let close = elem
                .rfind("</")
                .ok_or_else(|| Error::Structure("end tag not found".into()))?;
            out.push_str(&src[prolog_end..range.start + close]);
            out.push_str(text);
            out.push_str(&src[range.start + close..range.end]);
        }
        out.push_str(&src[range.end..]);
        Ok(out)
    }
}

/// Byte offset just past the XML declaration (and any BOM / whitespace around it), or 0.
fn prolog_end(src: &str) -> usize {
    let bom = if src.starts_with('\u{feff}') { 3 } else { 0 };
    let rest = &src[bom..];
    let ws = rest.len() - rest.trim_start().len();
    let after_ws = &rest[ws..];
    if let Some(stripped) = after_ws.strip_prefix("<?xml") {
        if let Some(end) = stripped.find("?>") {
            let decl_end = bom + ws + 5 + end + 2;
            let tail = &src[decl_end..];
            return decl_end + (tail.len() - tail.trim_start().len());
        }
    }
    bom
}

/// Qualified name of the start tag beginning at `start` in `src`.
fn tag_qname(src: &str, start: usize) -> &str {
    let s = &src[start + 1..];
    let end = s
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(s.len());
    &s[..end]
}

fn split_qname(q: &str) -> (Option<String>, String) {
    match q.split_once(':') {
        Some((p, l)) => (Some(p.to_string()), l.to_string()),
        None => (None, q.to_string()),
    }
}

/// Escape text content as a Java DOM serializer does (`&`, `<`, `>`, CR).
pub fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

/// Escape an attribute value for serialization.
pub fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod prolog_tests {
    use super::prolog_end;

    #[test]
    fn declaration_is_skipped() {
        let s = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a/>";
        assert_eq!(&s[prolog_end(s)..], "<a/>");
        assert_eq!(prolog_end("<a/>"), 0);
        assert_eq!(prolog_end("  <a/>"), 0);
        let bom = "\u{feff}<?xml version=\"1.0\"?><a/>";
        assert_eq!(&bom[prolog_end(bom)..], "<a/>");
    }
}
