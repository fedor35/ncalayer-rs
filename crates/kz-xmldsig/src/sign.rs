//! Building `ds:Signature` elements the way NCALayer's
//! `XMLUtil.createXmlSignature` (Apache Santuario) does.

use kz_cms::SignerAlgorithm;
use kz_pki::Entry;
use rand_core::CryptoRng;

use crate::algo::{base64_wrapped, sign_raw, XmlAlgorithm, DSIG_NS, ENVELOPED};
use crate::c14n::{canonicalize, Method};
use crate::dom::{Attr, Document, NodeId};
use crate::error::{Error, Result};

/// Sign a document with an enveloped signature: `Reference URI=""` with the
/// enveloped-signature and `c14n#WithComments` transforms, `SignedInfo`
/// canonicalized with inclusive Canonical XML 1.0, and the `ds:Signature`
/// appended as the last child of the root element.  The rest of the
/// caller's text is returned untouched.
pub fn sign_enveloped<R: CryptoRng + ?Sized>(
    entry: &Entry,
    xml: &str,
    rng: &mut R,
) -> Result<String> {
    let doc = Document::parse(xml)?;
    let root = doc.root_element()?;
    sign_document(
        entry,
        doc,
        Target {
            tbs: 0,
            parent: root,
            uri: String::new(),
            enveloped: true,
            method: Method::INCLUSIVE,
        },
        rng,
    )
}

/// Sign the element selected by `tbs_xpath` (it must carry an `Id`
/// attribute) with `Reference URI="#Id"` and the single transform
/// `c14n#WithComments`; `SignedInfo` is canonicalized with Exclusive C14N
/// and the `ds:Signature` is appended to the element selected by
/// `parent_xpath`.  Only absolute paths of the form `/root/a[1]` are
/// understood.
pub fn sign_by_id<R: CryptoRng + ?Sized>(
    entry: &Entry,
    xml: &str,
    tbs_xpath: &str,
    parent_xpath: &str,
    rng: &mut R,
) -> Result<String> {
    let doc = Document::parse(xml)?;
    let tbs = doc.select(tbs_xpath)?;
    let parent = doc.select(parent_xpath)?;
    let id = doc.attr(tbs, "Id").ok_or(Error::MissingId)?.to_string();
    if tbs == parent {
        return Err(Error::TbsIsParent);
    }
    if doc.is_descendant_or_self(parent, tbs) {
        return Err(Error::ParentInsideTbs);
    }
    sign_document(
        entry,
        doc,
        Target {
            tbs,
            parent,
            uri: format!("#{id}"),
            enveloped: false,
            method: Method::EXCLUSIVE,
        },
        rng,
    )
}

/// Sign several documents with enveloped signatures (`signXmls`).
pub fn sign_enveloped_many<R: CryptoRng + ?Sized>(
    entry: &Entry,
    xmls: &[String],
    rng: &mut R,
) -> Result<Vec<String>> {
    xmls.iter().map(|x| sign_enveloped(entry, x, rng)).collect()
}

struct Target {
    /// Node the `Reference` points at (the document node for `URI=""`).
    tbs: NodeId,
    /// Element the `ds:Signature` is appended to.
    parent: NodeId,
    /// `Reference/@URI`.
    uri: String,
    /// Add the enveloped-signature transform.
    enveloped: bool,
    /// `CanonicalizationMethod` of `SignedInfo`.
    method: Method,
}

fn sign_document<R: CryptoRng + ?Sized>(
    entry: &Entry,
    mut doc: Document,
    t: Target,
    rng: &mut R,
) -> Result<String> {
    let alg = SignerAlgorithm::for_private_key(&entry.key);
    let el = |doc: &mut Document, parent: NodeId, local: &str, attrs: &[(&str, &str)]| -> NodeId {
        let attrs = attrs
            .iter()
            .map(|(n, v)| Attr {
                prefix: None,
                local: n.to_string(),
                uri: None,
                value: v.to_string(),
            })
            .collect();
        doc.append_element(parent, Some("ds"), local, &[], attrs)
    };
    let nl = |doc: &mut Document, parent: NodeId| {
        doc.append_text(parent, "\n");
    };

    let sig = doc.append_element(
        t.parent,
        Some("ds"),
        "Signature",
        &[(Some("ds".into()), DSIG_NS.into())],
        vec![],
    );
    nl(&mut doc, sig);
    let signed_info = el(&mut doc, sig, "SignedInfo", &[]);
    nl(&mut doc, signed_info);
    el(
        &mut doc,
        signed_info,
        "CanonicalizationMethod",
        &[("Algorithm", t.method.uri())],
    );
    nl(&mut doc, signed_info);
    el(
        &mut doc,
        signed_info,
        "SignatureMethod",
        &[("Algorithm", alg.signature_uri())],
    );
    nl(&mut doc, signed_info);
    let reference = el(&mut doc, signed_info, "Reference", &[("URI", &t.uri)]);
    nl(&mut doc, reference);
    let transforms = el(&mut doc, reference, "Transforms", &[]);
    nl(&mut doc, transforms);
    if t.enveloped {
        el(
            &mut doc,
            transforms,
            "Transform",
            &[("Algorithm", ENVELOPED)],
        );
        nl(&mut doc, transforms);
    }
    el(
        &mut doc,
        transforms,
        "Transform",
        &[("Algorithm", Method::INCLUSIVE_WITH_COMMENTS.uri())],
    );
    nl(&mut doc, transforms);
    nl(&mut doc, reference);
    el(
        &mut doc,
        reference,
        "DigestMethod",
        &[("Algorithm", alg.digest_uri())],
    );
    nl(&mut doc, reference);
    let digest_value = el(&mut doc, reference, "DigestValue", &[]);
    nl(&mut doc, reference);
    nl(&mut doc, signed_info);
    nl(&mut doc, sig);
    let signature_value = el(&mut doc, sig, "SignatureValue", &[]);
    nl(&mut doc, sig);
    let key_info = el(&mut doc, sig, "KeyInfo", &[]);
    nl(&mut doc, key_info);
    let x509_data = el(&mut doc, key_info, "X509Data", &[]);
    nl(&mut doc, x509_data);
    let x509_cert = el(&mut doc, x509_data, "X509Certificate", &[]);
    let cert_b64 = base64_wrapped(entry.cert.as_der());
    doc.set_text(x509_cert, &format!("\n{cert_b64}\n"));
    nl(&mut doc, x509_data);
    nl(&mut doc, key_info);
    nl(&mut doc, sig);

    // Reference digest: the dereferenced node-set never contains comments
    // (XMLDSig §4.4.3.2), so `#WithComments` on the transform changes nothing.
    let exclude = if t.enveloped { Some(sig) } else { None };
    let canon = canonicalize(&doc, t.tbs, exclude, Method::INCLUSIVE);
    doc.set_text(digest_value, &base64_wrapped(&alg.digest(&canon)));

    let signed_info_canon = canonicalize(&doc, signed_info, None, t.method);
    let signature = sign_raw(&entry.key, &signed_info_canon, rng)?;
    doc.set_text(
        signature_value,
        &format!("\n{}\n", base64_wrapped(&signature)),
    );

    let mut text = String::new();
    doc.serialize(sig, &mut text);
    doc.splice_into(t.parent, &text)
}
