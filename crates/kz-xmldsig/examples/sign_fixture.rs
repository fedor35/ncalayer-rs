//! Sign the fixture inputs with the test key and write the results next to
//! the given output directory (used for manual comparison with the Kalkan
//! oracle): `cargo run -p kz-xmldsig --example sign_fixture -- <outdir>`.

use std::path::Path;

fn main() {
    let outdir = std::env::args().nth(1).expect("outdir");
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let entry = kz_pki::KeyStore::open_file(fx.join("test_gost512.p12"), "Test1234")
        .unwrap()
        .entries
        .remove(0);
    let mut rng = rand::rng();
    let read = |n: &str| std::fs::read_to_string(fx.join(n)).unwrap();
    let out = [
        (
            "simple",
            kz_xmldsig::sign_enveloped(
                &entry,
                &read("test_gost512.xml_simple.input.xml"),
                &mut rng,
            )
            .unwrap(),
        ),
        (
            "ns",
            kz_xmldsig::sign_enveloped(&entry, &read("test_gost512.xml_ns.input.xml"), &mut rng)
                .unwrap(),
        ),
        (
            "xpath",
            kz_xmldsig::sign_by_id(
                &entry,
                &read("test_gost512.xml_xpath.input.xml"),
                "/root/a",
                "/root",
                &mut rng,
            )
            .unwrap(),
        ),
    ];
    for (name, xml) in out {
        std::fs::write(Path::new(&outdir).join(format!("{name}.xml")), xml).unwrap();
    }
}
