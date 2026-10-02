// Тестовый оракул на проприетарном KalkanProvider из установленного NCALayer.
// Сам Kalkan в репозиторий не кладём: classpath указывает в ~/.config/NCALayer/ncalayer-cache.
// gen <dir> <password> — ключ ГОСТ-2015-512 (KZ ParamSetA), самоподписанный серт, p12, эталонная подпись.
// verify <cert.pem> <msg-utf8> <sig-hex> — проверить подпись Kalkan'ом (для подписи, сделанной Rust'ом).
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.interfaces.ECPrivateKey;
import kz.gov.pki.kalkan.jce.interfaces.ECPublicKey;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;
import kz.gov.pki.kalkan.jce.X509Principal;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.ess.ESSCertIDv2;
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Hashtable;
import java.util.Collections;

public class Oracle {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    static byte[] unhex(String h) { byte[] b = new byte[h.length()/2]; for (int i=0;i<b.length;i++) b[i]=(byte)Integer.parseInt(h.substring(2*i,2*i+2),16); return b; }
    static String pem(byte[] der) { return "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der) + "\n-----END CERTIFICATE-----\n"; }

    public static void main(String[] a) throws Exception {
        Security.addProvider(new KalkanProvider());
        kz.gov.pki.kalkan.xmldsig.KncaXS.loadXMLSecurity();
        switch (a[0]) {
            case "gen": gen(a[1], a[2]); break;
            case "verify": verify(a[1], a[2], a[3]); break;
            case "cms": cms(a[1], a[2], a[3]); break;          // cms <p12> <password> <outdir>
            case "verifycms": verifyCms(a[1], a.length > 2 ? a[2] : null); break; // verifycms <file.cms> [detached-data-file]
            case "xml": xml(a[1], a[2], a[3]); break;             // xml <p12> <password> <outdir>  (XMLUtil.createXmlSignature)
            case "verifyxml": verifyXml(a[1]); break;             // verifyxml <file.xml>
            default: throw new IllegalArgumentException(a[0]);
        }
    }

    static void gen(String dir, String pw) throws Exception {
        String msg = "ncalayer-rs test message";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2015", KalkanProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("Gost3410-2015-512-ParamSetA"));
        KeyPair kp = kpg.generateKeyPair();
        X509V3CertificateGenerator g = new X509V3CertificateGenerator();
        X509Principal dn = new X509Principal("CN=TEST GOST512,SERIALNUMBER=IIN000000000000,C=KZ");
        g.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        g.setIssuerDN(dn); g.setSubjectDN(dn);
        g.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
        g.setNotAfter(new Date(System.currentTimeMillis() + 365L*86400000L));
        g.setPublicKey(kp.getPublic());
        g.setSignatureAlgorithm("1.2.398.3.10.1.1.2.3.2");
        X509Certificate cert = g.generateX509Certificate(kp.getPrivate(), KalkanProvider.PROVIDER_NAME);
        cert.verify(kp.getPublic());

        KeyStore ks = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
        ks.load(null, null);
        ks.setKeyEntry("test", kp.getPrivate(), pw.toCharArray(), new java.security.cert.Certificate[]{cert});
        try (FileOutputStream f = new FileOutputStream(dir + "/test_gost512.p12")) { ks.store(f, pw.toCharArray()); }
        try (FileWriter f = new FileWriter(dir + "/test_gost512.cer.pem")) { f.write(pem(cert.getEncoded())); }

        Signature s = Signature.getInstance("ECGOST3410-2015-512", KalkanProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate()); s.update(msg.getBytes("UTF-8")); byte[] sig = s.sign();
        MessageDigest md = MessageDigest.getInstance("GOST3411-2015-512", KalkanProvider.PROVIDER_NAME);
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate(); ECPublicKey pub = (ECPublicKey) kp.getPublic();
        try (PrintWriter f = new PrintWriter(dir + "/test_gost512.vectors")) {
            f.println("msg=" + msg);
            f.println("digest=" + hex(md.digest(msg.getBytes("UTF-8"))));
            f.println("d=" + priv.getD().toString(16));
            f.println("qx=" + pub.getQ().getX().toBigInteger().toString(16));
            f.println("qy=" + pub.getQ().getY().toBigInteger().toString(16));
            f.println("sig=" + hex(sig));
            f.println("spki=" + hex(pub.getEncoded()));
            f.println("sigalg_oid=" + cert.getSigAlgOID());
            f.println("cert_tbs=" + hex(cert.getTBSCertificate()));
            f.println("cert_sig=" + hex(cert.getSignature()));
        }
        System.out.println("ok: " + dir + " sigalg=" + cert.getSigAlgOID() + " siglen=" + sig.length);
    }

    // Повторяет kz.gov.pki.provider.utils.CMSUtil.createCAdES из бандла NCALayer:
    // BC-атрибуты по умолчанию (contentType, signingTime, messageDigest) + signingCertificateV2 (SHA-256).
    static void cms(String p12, String pw, String outdir) throws Exception {
        String msg = "ncalayer-rs test message";
        KeyStore ks = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
        try (FileInputStream f = new FileInputStream(p12)) { ks.load(f, pw.toCharArray()); }
        String alias = ks.aliases().nextElement();
        PrivateKey key = (PrivateKey) ks.getKey(alias, pw.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        for (boolean attached : new boolean[]{true, false}) {
            Hashtable<DERObjectIdentifier, Attribute> attrs = new Hashtable<>();
            byte[] certHash = MessageDigest.getInstance("SHA-256", KalkanProvider.PROVIDER_NAME).digest(cert.getEncoded());
            ESSCertIDv2 essId = new ESSCertIDv2(new AlgorithmIdentifier(new DERObjectIdentifier("2.16.840.1.101.3.4.2.1")), certHash);
            Attribute sc2 = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(new SigningCertificateV2(new ESSCertIDv2[]{essId})));
            attrs.put(sc2.getAttrType(), sc2);
            CMSSignedDataGenerator g = new CMSSignedDataGenerator();
            g.addSigner(key, cert, CMSSignedDataGenerator.DIGEST_GOST3411_2015_512, new AttributeTable(attrs), null);
            g.addCertificatesAndCRLs(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singletonList(cert)), KalkanProvider.PROVIDER_NAME));
            CMSSignedData sd = g.generate(new CMSProcessableByteArray(msg.getBytes("UTF-8")), attached, KalkanProvider.PROVIDER_NAME);
            String name = outdir + "/test_gost512." + (attached ? "attached" : "detached") + ".cms";
            try (FileOutputStream f = new FileOutputStream(name)) { f.write(sd.getEncoded()); }
            System.out.println("ok: " + name + " " + sd.getEncoded().length + " bytes");
        }
        try (FileOutputStream f = new FileOutputStream(outdir + "/test_message.txt")) { f.write(msg.getBytes("UTF-8")); }
    }

    static void verifyCms(String file, String dataFile) throws Exception {
        byte[] der = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(file));
        CMSSignedData sd = dataFile == null ? new CMSSignedData(der)
            : new CMSSignedData(new CMSProcessableByteArray(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dataFile))), der);
        CertStore cs = sd.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
        boolean all = true;
        for (Object o : sd.getSignerInfos().getSigners()) {
            SignerInformation si = (SignerInformation) o;
            X509Certificate c = (X509Certificate) cs.getCertificates(si.getSID()).iterator().next();
            boolean ok = si.verify(c, KalkanProvider.PROVIDER_NAME);
            System.out.println("signer " + c.getSubjectDN() + " digest=" + si.getDigestAlgOID() + " enc=" + si.getEncryptionAlgOID() + " -> " + (ok ? "VALID" : "INVALID"));
            all &= ok;
        }
        System.out.println(all ? "VALID" : "INVALID");
    }

    // Как signXml в NCALayer: kz.gov.pki.provider.utils.XMLUtil.createXmlSignature(SigningEntity, xml, provider)
    static void xml(String p12, String pw, String outdir) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
        try (FileInputStream f = new FileInputStream(p12)) { ks.load(f, pw.toCharArray()); }
        String alias = ks.aliases().nextElement();
        PrivateKey key = (PrivateKey) ks.getKey(alias, pw.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        kz.gov.pki.provider.utils.model.SigningEntity se = new kz.gov.pki.provider.utils.model.SigningEntity(key, Collections.singletonList(cert));
        java.security.Provider prov = Security.getProvider(KalkanProvider.PROVIDER_NAME);
        String[][] cases = {
            {"simple", "<root><a>1</a><b attr=\"x\">текст</b></root>"},
            {"ns", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns1:doc xmlns:ns1=\"urn:test\" id=\"d1\"><ns1:item>  spaced  </ns1:item><empty/></ns1:doc>"},
        };
        for (String[] c : cases) {
            String signed = kz.gov.pki.provider.utils.XMLUtil.createXmlSignature(se, c[1], prov);
            try (FileWriter f = new FileWriter(outdir + "/test_gost512.xml_" + c[0] + ".xml")) { f.write(signed); }
            try (FileWriter f = new FileWriter(outdir + "/test_gost512.xml_" + c[0] + ".input.xml")) { f.write(c[1]); }
            System.out.println("ok: xml_" + c[0] + " " + signed.length() + " chars");
        }
        // signXml with explicit tbsElementXPath / signatureParentElementXPath, as commonUtils.signXml does
        String xml = "<root><a Id=\"part\"><x>1</x></a><b/></root>";
        String signed = kz.gov.pki.provider.utils.XMLUtil.createXmlSignature(se, xml, "/root/a", "/root", prov);
        try (FileWriter f = new FileWriter(outdir + "/test_gost512.xml_xpath.xml")) { f.write(signed); }
        try (FileWriter f = new FileWriter(outdir + "/test_gost512.xml_xpath.input.xml")) { f.write(xml); }
        System.out.println("ok: xml_xpath " + signed.length() + " chars");
    }

    static void verifyXml(String file) throws Exception {
        String xml = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(file)), "UTF-8");
        org.w3c.dom.Document doc = kz.gov.pki.provider.utils.XMLUtil.getDocument(xml);
        // Detached-by-Id signatures (signXml with tbsElementXPath) need the Id attribute registered as an XML ID.
        org.w3c.dom.NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            org.w3c.dom.Element el = (org.w3c.dom.Element) all.item(i);
            if (el.hasAttribute("Id")) el.setIdAttribute("Id", true);
        }
        try {
            kz.gov.pki.provider.utils.XMLUtil.verifyXmlSignature(doc, Security.getProvider(KalkanProvider.PROVIDER_NAME));
            System.out.println("VALID");
        } catch (Exception e) {
            System.out.println("INVALID: " + e);
        }
    }

    static void verify(String certPem, String msg, String sigHex) throws Exception {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certPem));
        Signature s = Signature.getInstance("ECGOST3410-2015-512", KalkanProvider.PROVIDER_NAME);
        s.initVerify(cert.getPublicKey()); s.update(msg.getBytes("UTF-8"));
        System.out.println(s.verify(unhex(sigHex)) ? "VALID" : "INVALID");
    }
}
