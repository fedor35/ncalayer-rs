//! Canonical XML 1.0 examples from the W3C recommendation §3
//! (<https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Examples>) that are
//! reproducible without external entities or DTD-driven attribute typing,
//! plus the Exclusive C14N example (<https://www.w3.org/TR/xml-exc-c14n/#sec-Specification>).

use kz_xmldsig::dom::Document;
use kz_xmldsig::{canonicalize, canonicalize_str, Method};

fn c14n(xml: &str, m: Method) -> String {
    String::from_utf8(canonicalize_str(xml, m).unwrap()).unwrap()
}

fn subset(xml: &str, xpath: &str, m: Method) -> String {
    let doc = Document::parse(xml).unwrap();
    let el = doc.select(xpath).unwrap();
    String::from_utf8(canonicalize(&doc, el, None, m)).unwrap()
}

/// §3.1 PIs, Comments, and Outside of Document Element.
#[test]
fn spec_3_1_pis_comments_outside_document_element() {
    let input = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<!DOCTYPE doc SYSTEM \"doc.dtd\">\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n";
    assert_eq!(
        c14n(input, Method::INCLUSIVE),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
    );
    assert_eq!(
        c14n(input, Method::INCLUSIVE_WITH_COMMENTS),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
    );
}

/// §3.2 Whitespace in Document Content.
#[test]
fn spec_3_2_whitespace_in_document_content() {
    let input = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>\n";
    assert_eq!(c14n(input, Method::INCLUSIVE), input.trim_end());
}

/// §3.3 Start and End Tags (without the DTD-defaulted `attr="default"` on
/// `e9`, which needs attribute defaulting the parser does not do).
#[test]
fn spec_3_3_start_and_end_tags() {
    let input = "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>\n";
    let expected = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
    assert_eq!(c14n(input, Method::INCLUSIVE), expected);
}

/// §3.4 Character Modifications and Character References (without
/// `normNames` / `normId`, whose normalization is driven by DTD types).
#[test]
fn spec_3_4_character_modifications() {
    let input = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>\n";
    let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
    assert_eq!(c14n(input, Method::INCLUSIVE), expected);
}

/// §3.5 Entity References, reduced to the internal entity (the external
/// `ent2` and the `ENTITY`-typed attribute need a DTD processor).
#[test]
fn spec_3_5_internal_entity_reference() {
    let input =
        "<!DOCTYPE doc [\n<!ENTITY ent1 \"Hello\">\n]>\n<doc attr=\"&ent1;\">&ent1;, world!</doc>";
    assert_eq!(
        c14n(input, Method::INCLUSIVE),
        "<doc attr=\"Hello\">Hello, world!</doc>"
    );
}

/// §3.6 UTF-8 Encoding: no BOM, character references become the characters.
#[test]
fn spec_3_6_utf8_encoding() {
    let out = canonicalize_str(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc>&#169;</doc>",
        Method::INCLUSIVE,
    )
    .unwrap();
    assert_eq!(out, b"<doc>\xC2\xA9</doc>");
    let bom = "\u{FEFF}<doc>&#169;</doc>";
    assert_eq!(
        canonicalize_str(bom, Method::INCLUSIVE).unwrap(),
        b"<doc>\xC2\xA9</doc>"
    );
}

/// Exclusive C14N specification §2.2 example: the `elem2` subtree.
#[test]
fn exc_c14n_spec_example() {
    let input = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n0:local>";
    assert_eq!(
        subset(input, "/n0:local/n1:elem2", Method::INCLUSIVE),
        "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" xml:lang=\"en\">\n    <n3:stuff></n3:stuff>\n  </n1:elem2>"
    );
    assert_eq!(
        subset(input, "/n0:local/n1:elem2", Method::EXCLUSIVE),
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>"
    );
}

/// Inclusive C14N inherits `xml:*` attributes onto a subset apex; exclusive does not.
#[test]
fn xml_attributes_inheritance_on_apex() {
    let input = "<a xml:lang=\"en\" xml:space=\"preserve\"><b xml:lang=\"ru\"><c/></b></a>";
    assert_eq!(
        subset(input, "/a/b", Method::INCLUSIVE),
        "<b xml:lang=\"ru\" xml:space=\"preserve\"><c></c></b>"
    );
    assert_eq!(
        subset(input, "/a/b", Method::EXCLUSIVE),
        "<b xml:lang=\"ru\"><c></c></b>"
    );
    assert_eq!(
        subset(input, "/a/b/c", Method::INCLUSIVE),
        "<c xml:lang=\"ru\" xml:space=\"preserve\"></c>"
    );
}

/// Default namespace: undeclaration and visibility rules on a subset.
#[test]
fn default_namespace_rules() {
    let input = "<a xmlns=\"urn:x\" xmlns:p=\"urn:p\"><b xmlns=\"\"><c p:q=\"1\"/></b><d/></a>";
    assert_eq!(
        subset(input, "/a/b", Method::INCLUSIVE),
        "<b xmlns:p=\"urn:p\"><c p:q=\"1\"></c></b>"
    );
    assert_eq!(
        subset(input, "/a/b", Method::EXCLUSIVE),
        "<b><c xmlns:p=\"urn:p\" p:q=\"1\"></c></b>"
    );
    assert_eq!(
        subset(input, "/a/d", Method::INCLUSIVE),
        "<d xmlns=\"urn:x\" xmlns:p=\"urn:p\"></d>"
    );
    assert_eq!(
        subset(input, "/a/d", Method::EXCLUSIVE),
        "<d xmlns=\"urn:x\"></d>"
    );
    assert_eq!(
        c14n(input, Method::INCLUSIVE),
        "<a xmlns=\"urn:x\" xmlns:p=\"urn:p\"><b xmlns=\"\"><c p:q=\"1\"></c></b><d></d></a>"
    );
    assert_eq!(
        c14n(input, Method::EXCLUSIVE),
        "<a xmlns=\"urn:x\"><b xmlns=\"\"><c xmlns:p=\"urn:p\" p:q=\"1\"></c></b><d></d></a>"
    );
}

/// Attribute ordering: namespace declarations first (default, then by
/// prefix), then attributes by namespace URI and local name.
#[test]
fn attribute_ordering() {
    let input = "<r xmlns:z=\"urn:a\" xmlns:a=\"urn:z\" z:k=\"1\" a:k=\"2\" b=\"3\" a=\"4\" xmlns=\"urn:d\"/>";
    assert_eq!(
        c14n(input, Method::INCLUSIVE),
        "<r xmlns=\"urn:d\" xmlns:a=\"urn:z\" xmlns:z=\"urn:a\" a=\"4\" b=\"3\" z:k=\"1\" a:k=\"2\"></r>"
    );
}

/// The enveloped-signature transform: an excluded subtree disappears.
#[test]
fn excluded_subtree() {
    let doc = Document::parse("<r><a/><sig><x/></sig><b/></r>").unwrap();
    let sig = doc.select("/r/sig").unwrap();
    assert_eq!(
        canonicalize(&doc, 0, Some(sig), Method::INCLUSIVE),
        b"<r><a></a><b></b></r>"
    );
}

/// Comments inside the document element and CR / line-ending handling.
#[test]
fn comments_and_line_endings() {
    let input = "<r>a\r\nb<!--c-->\rd&#13;e</r>";
    assert_eq!(c14n(input, Method::INCLUSIVE), "<r>a\nb\nd&#xD;e</r>");
    assert_eq!(
        c14n(input, Method::INCLUSIVE_WITH_COMMENTS),
        "<r>a\nb<!--c-->\nd&#xD;e</r>"
    );
}
