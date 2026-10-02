//! Print the contents of a PKCS#12 container: `cargo run -p kz-pki --example dump -- file.p12 password`.

use kz_pki::{KeyStore, PrivateKey};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: dump <file.p12> <password>");
    let password = args.next().unwrap_or_default();
    let ks = match KeyStore::open_file(&path, &password) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    for e in &ks.entries {
        println!("alias:       {}", e.alias);
        println!("algorithm:   {}", e.key.algorithm());
        if let PrivateKey::Rsa(k) = &e.key {
            use rsa::traits::PublicKeyParts;
            println!("rsa bits:    {}", k.n().bits());
        }
        println!("subjectDn:   {}", e.cert.subject_dn());
        println!("issuerDn:    {}", e.cert.issuer_dn());
        println!("serial:      {}", e.cert.serial_number());
        println!("notBefore:   {}", e.cert.not_before_str().unwrap_or_default());
        println!("notAfter:    {}", e.cert.not_after_str().unwrap_or_default());
        println!("keyUsage:    {}", e.cert.key_usage_type().as_str());
        println!("policies:    {:?}", e.cert.policies().unwrap_or_default().iter().map(|o| o.to_string()).collect::<Vec<_>>());
        println!("iin/bin:     {:?} / {:?}", e.cert.iin(), e.cert.bin());
        println!("authKeyId:   {:?}", e.cert.authority_key_identifier().unwrap_or_default());
        println!("chain:       {} cert(s)", e.chain.len());
        println!();
    }
}
